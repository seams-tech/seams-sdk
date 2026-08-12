import init, {
  wallet_custody_ceremony_establish_v1,
  wallet_custody_ceremony_join_v1,
  wallet_custody_ceremony_recover_v1,
  type WasmCeremonyEvmActivationPendingV1,
  type WasmCeremonyManifestEstablishedV1,
  type WasmCeremonyProtocolPreparedV1,
  type WasmCeremonySeedHeldV1,
} from '../../../../../../../wasm/wallet_custody_ceremony/pkg/wallet_custody_ceremony.js';
import initNearSigner, {
  passkey_custody_open_wallet_seed_v1,
  passkey_custody_reseal_wallet_seed_v1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import initEd25519YaoClient, {
  WasmEd25519YaoLaneClientV1,
  WasmEd25519YaoLaneSourceV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyCeremonyCommitPayload,
  WalletCustodyEvmFamilyActivationCompletion,
} from '@shared/passkey-custody';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { assertEd25519YaoLaneCeremonyBindingParityV1 } from '@/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
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
const nearSignerWasmUrl = resolveWasmUrl('wasm_signer_worker_bg.wasm', 'Signer Worker');
const ed25519YaoClientWasmUrl = resolveWasmUrl(
  'router_ab_ed25519_yao_client_bg.wasm',
  'Ed25519 Yao Client',
);
let initPromise: Promise<void> | null = null;
let nearSignerInitPromise: Promise<void> | null = null;
let ed25519YaoClientInitPromise: Promise<void> | null = null;

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
const MAX_ACTIVE_LANE_SOURCES = 8;
const ed25519YaoLaneSources = new Map<string, WasmEd25519YaoLaneSourceV1>();
const ed25519YaoLaneSessions = new Map<
  string,
  { readonly sourceHandle: string; readonly client: WasmEd25519YaoLaneClientV1 }
>();

type WorkerRequest<TType extends keyof WalletCustodyCeremonyWorkerOperationMap> = {
  readonly id: string;
  readonly type: TType;
  readonly payload: WalletCustodyCeremonyWorkerOperationMap[TType]['payload'];
};

type BeginRequest = WorkerRequest<'beginWalletCustodyKeySetRun'>;
type CompleteRequest = WorkerRequest<'completeWalletCustodyKeySetRun'>;
type FinishRequest = WorkerRequest<'finishWalletCustodyKeySetRun'>;
type DiscardRequest = WorkerRequest<'discardWalletCustodyCeremony'>;
type LinkPasskeyRequest = WorkerRequest<'linkWalletCustodyPasskey'>;
type RotateRecoverySetRequest = WorkerRequest<'rotateWalletRecoverySet'>;
type OpenEd25519YaoLaneSourceRequest = WorkerRequest<'openEd25519YaoLaneSource'>;
type PrepareEd25519YaoLaneRequest = WorkerRequest<'prepareEd25519YaoLane'>;
type CompleteEd25519YaoLaneRequest = WorkerRequest<'completeEd25519YaoLane'>;
type DiscardEd25519YaoLaneSourceRequest = WorkerRequest<'discardEd25519YaoLaneSource'>;

type WalletCustodyCeremonyWorkerRequest =
  | BeginRequest
  | CompleteRequest
  | FinishRequest
  | DiscardRequest
  | LinkPasskeyRequest
  | RotateRecoverySetRequest
  | OpenEd25519YaoLaneSourceRequest
  | PrepareEd25519YaoLaneRequest
  | CompleteEd25519YaoLaneRequest
  | DiscardEd25519YaoLaneSourceRequest;

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

async function initializeNearSignerWasm(): Promise<void> {
  if (!nearSignerInitPromise) {
    nearSignerInitPromise = initNearSigner({ module_or_path: nearSignerWasmUrl }).then(
      () => undefined,
      (error: unknown) => {
        nearSignerInitPromise = null;
        throw new Error(`Signer WASM initialization failed: ${safeErrorMessage(error)}`);
      },
    );
  }
  return nearSignerInitPromise;
}

async function initializeEd25519YaoClientWasm(): Promise<void> {
  if (!ed25519YaoClientInitPromise) {
    ed25519YaoClientInitPromise = initEd25519YaoClient({
      module_or_path: ed25519YaoClientWasmUrl,
    }).then(
      () => undefined,
      (error: unknown) => {
        ed25519YaoClientInitPromise = null;
        throw new Error(
          `Ed25519 Yao client WASM initialization failed: ${safeErrorMessage(error)}`,
        );
      },
    );
  }
  return ed25519YaoClientInitPromise;
}

function toBytes(value: ArrayBuffer | Uint8Array): Uint8Array {
  return value instanceof Uint8Array ? value : new Uint8Array(value);
}

function requireCeremonyId(value: unknown): string {
  const ceremonyId = String(value || '').trim();
  if (!ceremonyId) throw new Error('ceremonyId is required');
  return ceremonyId;
}

function requireOpaqueHandle(value: unknown, label: string): string {
  const handle = String(value || '').trim();
  if (!handle || handle.length > 256) throw new Error(`${label} is invalid`);
  return handle;
}

function secureOpaqueHandle(prefix: string): string {
  const random = new Uint8Array(24);
  crypto.getRandomValues(random);
  return `${prefix}.${base64UrlEncode(random)}`;
}

function randomNonzero32(): Uint8Array {
  const output = new Uint8Array(32);
  do {
    crypto.getRandomValues(output);
  } while (allZero(output));
  return output;
}

function allZero(value: Uint8Array): boolean {
  let aggregate = 0;
  for (const byte of value) aggregate |= byte;
  return aggregate === 0;
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function distinctLaneSealSeeds(): readonly [Uint8Array, Uint8Array] {
  const first = randomNonzero32();
  let second = randomNonzero32();
  while (bytesEqual(first, second)) {
    second.fill(0);
    second = randomNonzero32();
  }
  return [first, second];
}

async function openEd25519YaoLaneSource(
  request: OpenEd25519YaoLaneSourceRequest,
): Promise<{ sourceHandle: string }> {
  await initializeEd25519YaoClientWasm();
  if (ed25519YaoLaneSources.size >= MAX_ACTIVE_LANE_SOURCES) {
    throw new Error('Too many Ed25519 Yao lane sources are active');
  }
  const envelope = parsePasskeyCustodyEnvelopeRecord(request.payload.envelope);
  const factorSecret = toBytes(request.payload.factorSecret);
  try {
    const source = new WasmEd25519YaoLaneSourceV1(
      factorSecret,
      custodyEnvelopeBindingJson(envelope),
      base64UrlDecode(envelope.nonceB64u),
      base64UrlDecode(envelope.sealedCustodySecretB64u),
      base64UrlDecode(envelope.aadHashB64u),
      base64UrlDecode(envelope.ciphertextDigestB64u),
      base64UrlDecode(request.payload.applicationBindingDigestB64u),
    );
    const sourceHandle = secureOpaqueHandle('ed25519-yao-lane-source-v1');
    ed25519YaoLaneSources.set(sourceHandle, source);
    return { sourceHandle };
  } finally {
    factorSecret.fill(0);
  }
}

async function prepareEd25519YaoLane(
  request: PrepareEd25519YaoLaneRequest,
): Promise<{ sessionHandle: string; requestJson: string }> {
  await initializeEd25519YaoClientWasm();
  const sourceHandle = requireOpaqueHandle(request.payload.sourceHandle, 'sourceHandle');
  const source = ed25519YaoLaneSources.get(sourceHandle);
  if (!source) throw new Error('Ed25519 Yao lane source handle is unknown or discarded');
  const client = new WasmEd25519YaoLaneClientV1();
  const [deriverASealSeed, deriverBSealSeed] = distinctLaneSealSeeds();
  try {
    await assertEd25519YaoLaneCeremonyBindingParityV1({
      job: request.payload.job,
      ceremonyBinding: request.payload.ceremonyBinding,
      applicationBinding: request.payload.applicationBinding,
      participantIds: request.payload.participantIds,
    });
    const prepared = client.prepare(
      JSON.stringify(request.payload.job),
      JSON.stringify(request.payload.ceremonyBinding),
      JSON.stringify(request.payload.applicationBinding),
      request.payload.participantIds[0],
      request.payload.participantIds[1],
      source,
      base64UrlDecode(request.payload.deriverAInputPublicKeyB64u),
      base64UrlDecode(request.payload.deriverBInputPublicKeyB64u),
      deriverASealSeed,
      deriverBSealSeed,
    ) as { requestJson?: unknown };
    const requestJson = String(prepared.requestJson || '').trim();
    if (!requestJson) throw new Error('Ed25519 Yao lane preparation returned no request JSON');
    const sessionHandle = secureOpaqueHandle('ed25519-yao-lane-session-v1');
    ed25519YaoLaneSessions.set(sessionHandle, { sourceHandle, client });
    return { sessionHandle, requestJson };
  } catch (error) {
    client.free();
    throw error;
  } finally {
    deriverASealSeed.fill(0);
    deriverBSealSeed.fill(0);
  }
}

async function completeEd25519YaoLane(
  request: CompleteEd25519YaoLaneRequest,
): Promise<WalletCustodyCeremonyWorkerOperationMap['completeEd25519YaoLane']['result']> {
  const sessionHandle = requireOpaqueHandle(request.payload.sessionHandle, 'sessionHandle');
  const session = ed25519YaoLaneSessions.get(sessionHandle);
  if (!session) throw new Error('Ed25519 Yao lane session handle is unknown or consumed');
  ed25519YaoLaneSessions.delete(sessionHandle);
  try {
    return session.client.complete({ responseJson: request.payload.responseJson });
  } finally {
    session.client.free();
  }
}

function discardEd25519YaoLaneSource(request: DiscardEd25519YaoLaneSourceRequest): {
  discarded: boolean;
} {
  const sourceHandle = requireOpaqueHandle(request.payload.sourceHandle, 'sourceHandle');
  for (const [sessionHandle, session] of ed25519YaoLaneSessions) {
    if (session.sourceHandle !== sourceHandle) continue;
    session.client.free();
    ed25519YaoLaneSessions.delete(sessionHandle);
  }
  const source = ed25519YaoLaneSources.get(sourceHandle);
  if (!source) return { discarded: false };
  ed25519YaoLaneSources.delete(sourceHandle);
  source.free();
  return { discarded: true };
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

function custodyEnvelopeBindingJson(envelope: PasskeyCustodyEnvelopeRecord): string {
  return JSON.stringify({
    walletId: envelope.walletId,
    envelopeId: envelope.envelopeId,
    factor: envelope.factor,
    envelopeRevision: envelope.envelopeRevision,
    binding: envelope.binding,
  });
}

async function linkWalletCustodyPasskey(request: LinkPasskeyRequest): Promise<unknown> {
  await initializeNearSignerWasm();
  const envelope = request.payload.existingEnvelope;
  const existingFactorSecret = toBytes(request.payload.existingFactorSecret);
  const replacementFactorSecret = toBytes(request.payload.replacementFactorSecret);
  const nonce = base64UrlDecode(envelope.nonceB64u);
  let handle: ReturnType<typeof passkey_custody_open_wallet_seed_v1> | null = null;
  try {
    handle = passkey_custody_open_wallet_seed_v1(
      existingFactorSecret,
      custodyEnvelopeBindingJson(envelope),
      nonce,
      envelope.sealedCustodySecretB64u,
      envelope.aadHashB64u,
      envelope.ciphertextDigestB64u,
    );
    const resealed = passkey_custody_reseal_wallet_seed_v1(
      handle,
      replacementFactorSecret,
      request.payload.replacementEnvelopeBindingJson,
    ) as Record<string, unknown>;
    return {
      nonceB64u: String(resealed.nonceB64u || ''),
      sealedCustodySecretB64u: String(resealed.sealedCustodySecretB64u || ''),
      aadHashB64u: String(resealed.aadHashB64u || ''),
      ciphertextDigestB64u: String(resealed.ciphertextDigestB64u || ''),
    };
  } finally {
    handle?.free();
    existingFactorSecret.fill(0);
    replacementFactorSecret.fill(0);
  }
}

async function rotateWalletRecoverySet(request: RotateRecoverySetRequest): Promise<unknown> {
  const factorSecret = toBytes(request.payload.factorSecret);
  let handle: WasmCeremonySeedHeldV1 | null = null;
  try {
    handle = wallet_custody_ceremony_join_v1(factorSecret, request.payload.custodyJson);
    const resultJson = handle.rotate_recovery_codes(request.payload.recoveryCodesJson);
    handle = null;
    return JSON.parse(resultJson) as unknown;
  } finally {
    handle?.free();
    factorSecret.fill(0);
  }
}

async function handleRequest(request: WalletCustodyCeremonyWorkerRequest): Promise<void> {
  await initializeWasm();
  switch (request.type) {
    case 'openEd25519YaoLaneSource':
      postSucceeded(request.id, await openEd25519YaoLaneSource(request));
      return;
    case 'prepareEd25519YaoLane':
      postSucceeded(request.id, await prepareEd25519YaoLane(request));
      return;
    case 'completeEd25519YaoLane':
      postSucceeded(request.id, await completeEd25519YaoLane(request));
      return;
    case 'discardEd25519YaoLaneSource':
      postSucceeded(request.id, discardEd25519YaoLaneSource(request));
      return;
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
    case 'linkWalletCustodyPasskey':
      postSucceeded(request.id, await linkWalletCustodyPasskey(request));
      return;
    case 'rotateWalletRecoverySet':
      postSucceeded(request.id, await rotateWalletRecoverySet(request));
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
