import init, {
  wallet_custody_ceremony_establish_v1,
  wallet_custody_ceremony_join_v1,
  wallet_custody_ceremony_recover_v1,
  type WasmCeremonyEvmActivationPendingV1,
  type WasmCeremonyManifestEstablishedV1,
  type WasmCeremonyProtocolPreparedV1,
  type WasmCeremonySeedHeldV1,
} from '../../../../../../../wasm/wallet_custody_ceremony/pkg/wallet_custody_ceremony.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import type {
  WalletCustodyCeremonyCommitPayload,
  WalletCustodyEvmFamilyActivationCompletion,
} from '@shared/passkey-custody';
import type { WalletCustodyCeremonyWorkerOperationMap } from '../workerTypes';

/**
 * One wallet custody ceremony run, driven from a dedicated worker.
 *
 * A run provisions one key set and spans one protocol round-trip — the Router
 * for NEAR Ed25519, the relayer for the EVM family. Its state must survive that
 * round without the seed, the owner root, or the ECDSA pending blob ever
 * existing as JavaScript values. So the wasm state handle stays here, in the
 * worker, keyed by a ceremony id; the main thread carries only the public
 * protocol messages across the round and the ciphertext at the end.
 *
 * Each wasm transition consumes its handle. This worker mirrors that: a step
 * takes the stored handle out of the map before advancing, and only a
 * successful transition puts the next one back. A failed step therefore ends
 * the run rather than leaving a half-advanced state a caller could retry
 * into — which is the same rule the Rust typestate enforces, made visible at
 * the message layer.
 */

const wasmUrl = resolveWasmUrl('wallet_custody_ceremony_bg.wasm', 'Wallet Custody Ceremony');
let initPromise: Promise<void> | null = null;

/**
 * Ceremonies in flight. Bounded because each holds custody material: a caller
 * that starts ceremonies without finishing them must fail rather than grow this
 * map, and abandoning one is a bug worth surfacing, not absorbing.
 */
const MAX_CONCURRENT_CEREMONIES = 4;

/**
 * The two steps a run can be *parked* at between messages. There is no
 * `completed` state here on purpose: completing the protocol and establishing
 * the manifest happen in one message, so a completed-but-unestablished handle
 * never sits in the map waiting for a caller.
 *
 * `prepared` carries its key set because the next transition differs by it —
 * and because the manifest must be recorded under the key set whose protocol
 * actually ran, not one the completing caller names.
 */
type CeremonyState =
  | {
      readonly step: 'near_prepared';
      readonly handle: WasmCeremonyProtocolPreparedV1;
    }
  | {
      readonly step: 'evm_activation_pending';
      readonly handle: WasmCeremonyEvmActivationPendingV1;
    }
  | { readonly step: 'near_established'; readonly handle: WasmCeremonyManifestEstablishedV1 };

const ceremonies = new Map<string, CeremonyState>();

type WorkerRequest<TType extends keyof WalletCustodyCeremonyWorkerOperationMap> = {
  readonly id: string;
  readonly type: TType;
  readonly payload: WalletCustodyCeremonyWorkerOperationMap[TType]['payload'];
};

type BeginRequest = WorkerRequest<'beginWalletCustodyKeySetRun'>;
type CompleteRequest = WorkerRequest<'completeWalletCustodyKeySetRun'>;
type FinishRequest = WorkerRequest<'finishWalletCustodyKeySetRun'>;
type DiscardRequest = WorkerRequest<'discardWalletCustodyCeremony'>;

type WalletCustodyCeremonyWorkerRequest =
  | BeginRequest
  | CompleteRequest
  | FinishRequest
  | DiscardRequest;

function postToMainThread(message: unknown): void {
  (self as unknown as { postMessage: (message: unknown) => void }).postMessage(message);
}

function postSucceeded(id: string, result: unknown): void {
  postToMainThread({ id, ok: true, result });
}

function postFailed(id: string, error: unknown): void {
  postToMainThread({ id, ok: false, error: safeErrorMessage(error) });
}

async function initializeWasm(): Promise<void> {
  if (!initPromise) {
    initPromise = init({ module_or_path: wasmUrl }).then(
      () => undefined,
      (error: unknown) => {
        initPromise = null;
        console.error(
          '[wallet-custody-ceremony-worker]: WASM initialization failed:',
          errorLogSummary(error),
        );
        throw new Error(
          `Wallet custody ceremony WASM initialization failed: ${safeErrorMessage(error)}`,
        );
      },
    );
  }
  return initPromise;
}

function toBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function requireCeremonyId(value: unknown): string {
  const ceremonyId = String(value || '').trim();
  if (!ceremonyId) throw new Error('ceremonyId is required');
  return ceremonyId;
}

type BeginCustody = BeginRequest['payload']['custody'];

function takeSeed(custody: BeginCustody): WasmCeremonySeedHeldV1 {
  switch (custody.origin) {
    case 'establish':
      return wallet_custody_ceremony_establish_v1(custody.walletId);
    case 'join': {
      const factorSecret = toBytes(custody.factorSecret);
      try {
        return wallet_custody_ceremony_join_v1(factorSecret, custody.custodyJson);
      } finally {
        factorSecret.fill(0);
      }
    }
    case 'recover': {
      const recoveryCode = toBytes(custody.recoveryCode);
      try {
        return wallet_custody_ceremony_recover_v1(recoveryCode, custody.custodyJson);
      } finally {
        recoveryCode.fill(0);
      }
    }
    case 'recover_and_reseal': {
      const recoveryCode = toBytes(custody.recoveryCode);
      try {
        return wallet_custody_ceremony_recover_v1(recoveryCode, custody.custodyJson);
      } finally {
        recoveryCode.fill(0);
      }
    }
    default:
      return assertNever(custody);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unsupported custody origin: ${String(value)}`);
}

/**
 * Removes and returns a ceremony's state at the expected step.
 *
 * Taking rather than reading is what makes a failed transition terminal: if the
 * step below throws, nothing puts the handle back, so the ceremony is gone and
 * the caller must start over from a fresh seed.
 */
function takeCeremony<TStep extends CeremonyState['step']>(
  ceremonyId: string,
  step: TStep,
): Extract<CeremonyState, { step: TStep }> {
  const state = ceremonies.get(ceremonyId);
  if (!state) throw new Error(`No wallet custody ceremony ${ceremonyId} is in flight`);
  ceremonies.delete(ceremonyId);
  if (state.step !== step) {
    // The handle is dropped rather than restored: a caller that stepped out of
    // order has lost track of the ceremony, and resuming it would be guesswork.
    throw new Error(
      `Wallet custody ceremony ${ceremonyId} is at step ${state.step}, not ${String(step)}`,
    );
  }
  return state as Extract<CeremonyState, { step: TStep }>;
}

/**
 * Starts a run: takes hold of the wallet's seed, then derives this key set's
 * root straight into its protocol.
 *
 * Establishing generates the seed here; joining opens the envelope custody
 * already has. The open is what authorises a joining run — its AAD binds the
 * seed to the wallet, so a successful open proves the seed is that wallet's own.
 */
function beginKeySetRun(request: BeginRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  if (ceremonies.has(ceremonyId)) {
    throw new Error(`Wallet custody ceremony ${ceremonyId} is already in flight`);
  }
  if (ceremonies.size >= MAX_CONCURRENT_CEREMONIES) {
    throw new Error('Too many wallet custody ceremonies are in flight');
  }
  // `prepare_*` consumes `seedHeld`; on failure the seed is dropped with it.
  if (request.payload.keySet === 'near_ed25519_v1') {
    const seedHeld = takeSeed(request.payload.custody);
    const prepared = seedHeld.prepare_near_ed25519(request.payload.protocolInputsJson);
    const yaoExecuteRequestJson = prepared.yao_execute_request_json();
    if (!yaoExecuteRequestJson) throw new Error('NEAR custody preparation returned no request');
    ceremonies.set(ceremonyId, { step: 'near_prepared', handle: prepared });
    return { ceremonyId, keySet: 'near_ed25519_v1', yaoExecuteRequestJson };
  }

  const custody = request.payload.custody;
  const seedHeld = takeSeed(custody);
  const prepared = seedHeld.prepare_evm_family(request.payload.protocolInputsJson);
  const contextBinding32B64u = prepared.ecdsa_context_binding32_b64u();
  const clientSharePublicKey33B64u = prepared.ecdsa_client_share_public_key33_b64u();
  const clientShareRetryCounter = prepared.ecdsa_client_share_retry_counter();
  if (
    !contextBinding32B64u ||
    !clientSharePublicKey33B64u ||
    clientShareRetryCounter === undefined
  ) {
    throw new Error('EVM custody preparation returned no bootstrap facts');
  }

  let pending: WasmCeremonyEvmActivationPendingV1;
  if (custody.origin === 'establish') {
    const factorSecret = toBytes(custody.factorSecret);
    try {
      pending = prepared.prepare_evm_activation_establishing_custody(
        request.payload.evmFamilySigningKeySlotId,
        custody.factorJson,
        factorSecret,
        custody.recoveryCodesJson,
      );
    } finally {
      factorSecret.fill(0);
    }
  } else if (custody.origin === 'recover_and_reseal') {
    const replacementFactorSecret = toBytes(custody.replacementFactorSecret);
    try {
      pending = prepared.prepare_evm_activation_recovering_custody(
        request.payload.evmFamilySigningKeySlotId,
        requireRecordedManifestDigest(request.payload.recordedKeyManifestDigestB64u),
        custody.replacementFactorJson,
        replacementFactorSecret,
      );
    } finally {
      replacementFactorSecret.fill(0);
    }
  } else {
    pending = prepared.prepare_evm_activation_joining_custody(
      request.payload.evmFamilySigningKeySlotId,
      request.payload.recordedKeyManifestDigestB64u,
    );
  }
  const preActivationCommitPayload = pending.commit_payload() as WalletCustodyCeremonyCommitPayload;
  ceremonies.set(ceremonyId, { step: 'evm_activation_pending', handle: pending });
  return {
    ceremonyId,
    keySet: 'evm_family_ecdsa_v1',
    ecdsaContextBinding32B64u: contextBinding32B64u,
    ecdsaClientSharePublicKey33B64u: clientSharePublicKey33B64u,
    ecdsaClientShareRetryCounter: clientShareRetryCounter,
    preActivationCommitPayload,
  };
}

function requireRecordedManifestDigest(value: unknown): string {
  const digest = String(value || '').trim();
  if (!digest) throw new Error('recovery requires a recorded key manifest digest');
  return digest;
}

/**
 * Completes this key set's protocol and establishes its manifest.
 *
 * These are one message because nothing external happens between them: the
 * manifest is built from what the protocol just returned, and leaving the
 * completed state addressable would only widen the window in which a seed sits
 * in the map.
 *
 * The key set comes from the stored state rather than the request, so the
 * manifest is recorded under the protocol that actually ran.
 */
function completeKeySetRun(request: CompleteRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  if (request.payload.keySet === 'evm_family_ecdsa_v1') {
    const { handle } = takeCeremony(ceremonyId, 'evm_activation_pending');
    const activation = handle.complete(
      request.payload.protocolResultJson,
    ) as WalletCustodyEvmFamilyActivationCompletion;
    return { ceremonyId, keySet: 'evm_family_ecdsa_v1', activation };
  }

  const { handle } = takeCeremony(ceremonyId, 'near_prepared');
  const completed = handle.complete_near_ed25519(request.payload.protocolResultJson);
  const established = completed.establish_manifest(
    'near_ed25519_v1',
    request.payload.nearEd25519SigningKeyId,
    request.payload.recordedKeyManifestDigestB64u,
  );
  ceremonies.set(ceremonyId, { step: 'near_established', handle: established });
  return { ceremonyId, keySet: 'near_ed25519_v1' };
}

/**
 * Finishes the run and returns what there is to commit.
 *
 * A run that established custody seals the seed under its factor and issues the
 * recovery set. A joining run writes neither — the wallet already has both —
 * and its whole output is this key set's manifest digest.
 */
function finishKeySetRun(request: FinishRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  const { handle } = takeCeremony(ceremonyId, 'near_established');
  switch (request.payload.finish.kind) {
    case 'existing':
      return handle.finish_joining_custody();
    case 'establish': {
      const factorSecret = toBytes(request.payload.finish.factorSecret);
      try {
        return handle.finish_establishing_custody(
          request.payload.finish.factorJson,
          factorSecret,
          request.payload.finish.recoveryCodesJson,
        );
      } finally {
        factorSecret.fill(0);
      }
    }
    case 'recover_reseal': {
      const factorSecret = toBytes(request.payload.finish.replacementFactorSecret);
      try {
        return handle.finish_recovering_custody(
          request.payload.finish.replacementFactorJson,
          factorSecret,
        );
      } finally {
        factorSecret.fill(0);
      }
    }
    default:
      return assertNever(request.payload.finish);
  }
}

/**
 * Ends a run without completing it. Dropping the handle zeroizes the seed and
 * any in-flight protocol state, so an abandoned run leaves nothing behind.
 */
function discardCeremony(request: DiscardRequest): unknown {
  const ceremonyId = requireCeremonyId(request.payload.ceremonyId);
  const existed = ceremonies.delete(ceremonyId);
  return { ceremonyId, discarded: existed };
}

async function handleRequest(request: WalletCustodyCeremonyWorkerRequest): Promise<void> {
  await initializeWasm();
  switch (request.type) {
    case 'beginWalletCustodyKeySetRun':
      postSucceeded(request.id, beginKeySetRun(request));
      return;
    case 'completeWalletCustodyKeySetRun':
      postSucceeded(request.id, completeKeySetRun(request));
      return;
    case 'finishWalletCustodyKeySetRun':
      postSucceeded(request.id, finishKeySetRun(request));
      return;
    case 'discardWalletCustodyCeremony':
      postSucceeded(request.id, discardCeremony(request));
      return;
    default:
      throw new Error(
        `Unsupported wallet custody ceremony operation: ${String(
          (request as { type?: unknown }).type,
        )}`,
      );
  }
}

let messageQueue: Promise<void> = Promise.resolve();

self.onmessage = async (event: MessageEvent<WalletCustodyCeremonyWorkerRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[wallet-custody-ceremony-worker]: Ignoring message without request id');
    return;
  }
  // Serialized: two steps of one ceremony must not interleave, and the map is
  // read-modify-write.
  messageQueue = messageQueue
    .catch(() => undefined)
    .then(async () => {
      try {
        await handleRequest(event.data);
      } catch (error: unknown) {
        postFailed(requestId, error);
      }
    });
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[wallet-custody-ceremony-worker]: error:', {
    message: safeErrorMessage(typeof message === 'string' ? message : 'Unknown error'),
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error: error ? errorLogSummary(error) : undefined,
  });
};
