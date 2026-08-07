import init, {
  wallet_custody_ceremony_establish_v1,
  wallet_custody_ceremony_join_v1,
  type WasmCeremonyManifestEstablishedV1,
  type WasmCeremonyProtocolPreparedV1,
  type WasmCeremonySeedHeldV1,
} from '../../../../../../../wasm/wallet_custody_ceremony/pkg/wallet_custody_ceremony.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import type { WalletCustodyKeySetKind } from '@shared/passkey-custody';

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
      readonly step: 'prepared';
      readonly keySet: WalletCustodyKeySetKind;
      readonly handle: WasmCeremonyProtocolPreparedV1;
    }
  | { readonly step: 'established'; readonly handle: WasmCeremonyManifestEstablishedV1 };

const ceremonies = new Map<string, CeremonyState>();

type BeginRequest = {
  readonly id: string;
  readonly type: 'beginWalletCustodyKeySetRun';
  readonly payload: {
    readonly ceremonyId: string;
    readonly keySet: WalletCustodyKeySetKind;
    readonly custody:
      | { readonly origin: 'establish'; readonly walletId: string }
      | {
          readonly origin: 'join';
          readonly custodyJson: string;
          /** Opens the existing seed envelope. */
          readonly factorSecret: ArrayBuffer | Uint8Array;
        };
    /** `NearEd25519ProtocolInputsWireV1` or `EvmFamilyProtocolInputsWireV1`. */
    readonly protocolInputsJson: string;
  };
};

type CompleteRequest = {
  readonly id: string;
  readonly type: 'completeWalletCustodyKeySetRun';
  readonly payload: {
    readonly ceremonyId: string;
    readonly protocolResultJson: string;
    readonly identityId: string;
    readonly recordedKeyManifestDigestB64u?: string;
  };
};

type FinishRequest = {
  readonly id: string;
  readonly type: 'finishWalletCustodyKeySetRun';
  readonly payload: {
    readonly ceremonyId: string;
    readonly establishWith?: {
      readonly factorJson: string;
      /** The factor secret: a passkey PRF result, or the Email OTP factor key. */
      readonly factorSecret: ArrayBuffer | Uint8Array;
      readonly recoveryCodesJson: string;
    };
  };
};

type DiscardRequest = {
  readonly id: string;
  readonly type: 'discardWalletCustodyCeremony';
  readonly payload: { readonly ceremonyId: string };
};

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

function requireKeySet(value: unknown): WalletCustodyKeySetKind {
  if (value === 'near_ed25519_v1' || value === 'evm_family_ecdsa_v1') return value;
  throw new Error(`Unknown wallet key set kind: ${String(value)}`);
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
  // Validated before the seed exists: `prepare_*` consumes the handle, so an
  // unknown key set must fail while there is still nothing to drop.
  const keySet = requireKeySet(request.payload.keySet);

  const custody = request.payload.custody;
  let seedHeld: WasmCeremonySeedHeldV1;
  if (custody?.origin === 'join') {
    const factorSecret = toBytes(custody.factorSecret);
    try {
      seedHeld = wallet_custody_ceremony_join_v1(factorSecret, String(custody.custodyJson || ''));
    } finally {
      factorSecret.fill(0);
    }
  } else if (custody?.origin === 'establish') {
    seedHeld = wallet_custody_ceremony_establish_v1(String(custody.walletId || ''));
  } else {
    throw new Error('A wallet custody run must either establish custody or join it');
  }

  // `prepare_*` consumes `seedHeld`; on failure the seed is dropped with it.
  const prepared =
    keySet === 'near_ed25519_v1'
      ? seedHeld.prepare_near_ed25519(String(request.payload.protocolInputsJson || ''))
      : seedHeld.prepare_evm_family(String(request.payload.protocolInputsJson || ''));
  ceremonies.set(ceremonyId, { step: 'prepared', keySet, handle: prepared });

  return {
    ceremonyId,
    yaoExecuteRequestJson: prepared.yao_execute_request_json(),
    ecdsaContextBinding32B64u: prepared.ecdsa_context_binding32_b64u(),
    ecdsaClientSharePublicKey33B64u: prepared.ecdsa_client_share_public_key33_b64u(),
  };
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
  const { keySet, handle } = takeCeremony(ceremonyId, 'prepared');
  const protocolResultJson = String(request.payload.protocolResultJson || '');
  const completed =
    keySet === 'near_ed25519_v1'
      ? handle.complete_near_ed25519(protocolResultJson)
      : handle.complete_evm_family(protocolResultJson);
  const established = completed.establish_manifest(
    keySet,
    String(request.payload.identityId || ''),
    request.payload.recordedKeyManifestDigestB64u,
  );
  ceremonies.set(ceremonyId, { step: 'established', handle: established });
  return { ceremonyId };
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
  const { handle } = takeCeremony(ceremonyId, 'established');
  const establishWith = request.payload.establishWith;
  if (!establishWith) return handle.finish_joining_custody();

  const factorSecret = toBytes(establishWith.factorSecret);
  try {
    return handle.finish_establishing_custody(
      String(establishWith.factorJson || ''),
      factorSecret,
      String(establishWith.recoveryCodesJson || ''),
    );
  } finally {
    // The factor secret was copied into wasm; this view is the worker's own and
    // is cleared whether or not the seal succeeded.
    factorSecret.fill(0);
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
