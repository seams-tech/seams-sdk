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
  linked_device_custody_transfer_recipient_v1,
  passkey_custody_open_wallet_seed_from_linked_device_v1,
  passkey_custody_open_wallet_seed_v1,
  passkey_custody_reseal_transferred_wallet_seed_v1,
  passkey_custody_reseal_wallet_seed_v1,
  passkey_custody_seal_wallet_seed_for_linked_device_v1,
  type WasmLinkedDeviceCustodyTransferRecipientV1,
  type WasmPasskeyCustodyHandleV1,
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

/**
 * Device 2's custody-transfer recipient keys, held here for the same reason
 * ceremony handles are: the private half must never exist as a JavaScript
 * value. A linking attempt uses exactly one, and an abandoned attempt is a bug
 * worth surfacing rather than absorbing, so the map is bounded.
 */
const MAX_ACTIVE_TRANSFER_RECIPIENTS = 2;
const custodyTransferRecipients = new Map<string, WasmLinkedDeviceCustodyTransferRecipientV1>();

/**
 * Refactor 103 zero-prompt handoff — Device 1's unlocked custody transfer
 * capabilities.
 *
 * Each entry owns a custody-seed handle opened during registration or ordinary
 * unlock, when the owner factor was already being presented. The handle stays
 * in this map for the lifetime of the owner Wallet Session that authorized it,
 * so approving a linked device later seals from here without another factor
 * prompt. The reference JavaScript holds back is the map key plus the binding
 * facts below — never the seed, and never anything that survives this worker.
 *
 * Sealing re-verifies every stored fact against the presented reference, and a
 * mismatch fails before any ciphertext exists. One capability per wallet:
 * establishing a replacement destroys the previous handle first, and the map
 * is bounded like the recipient map because an abandoned handle is a bug worth
 * surfacing.
 */
const MAX_ACTIVE_UNLOCKED_CUSTODY_CAPABILITIES = 4;
type UnlockedCustodyCapabilityRecordV1 = {
  readonly handle: WasmPasskeyCustodyHandleV1;
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly walletSessionId: string;
  readonly expiresAtMs: number;
};
const unlockedCustodyCapabilities = new Map<string, UnlockedCustodyCapabilityRecordV1>();

function destroyUnlockedCustodyCapabilityEntry(capabilityHandleId: string): boolean {
  const record = unlockedCustodyCapabilities.get(capabilityHandleId);
  unlockedCustodyCapabilities.delete(capabilityHandleId);
  if (!record) return false;
  record.handle.destroy();
  record.handle.free();
  return true;
}

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
type CreateTransferRecipientRequest =
  WorkerRequest<'createLinkedDeviceCustodyTransferRecipient'>;
type EstablishUnlockedCustodyCapabilityRequest =
  WorkerRequest<'establishUnlockedWalletCustodyTransferCapability'>;
type DestroyUnlockedCustodyCapabilitiesRequest =
  WorkerRequest<'destroyUnlockedWalletCustodyTransferCapabilities'>;
type SealForLinkedDeviceRequest = WorkerRequest<'sealWalletCustodySeedForLinkedDevice'>;
type AcceptTransferRequest = WorkerRequest<'acceptLinkedDeviceCustodyTransfer'>;
type DiscardTransferRecipientRequest =
  WorkerRequest<'discardLinkedDeviceCustodyTransferRecipient'>;
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
  | CreateTransferRecipientRequest
  | EstablishUnlockedCustodyCapabilityRequest
  | DestroyUnlockedCustodyCapabilitiesRequest
  | SealForLinkedDeviceRequest
  | AcceptTransferRequest
  | DiscardTransferRecipientRequest
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

/**
 * Device 2: publishes the key Device 1 will seal the wallet custody seed to.
 *
 * Deliberately generated here rather than in the device-linking key worker.
 * That worker holds the QR's link key as a non-extractable `CryptoKey`, so
 * decapsulating there would require the opened seed to cross into JavaScript
 * before it could be resealed. Keeping the recipient key in the module that
 * performs the reseal means the seed only ever exists inside wasm.
 */
async function createLinkedDeviceCustodyTransferRecipient(
  _request: CreateTransferRecipientRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  if (custodyTransferRecipients.size >= MAX_ACTIVE_TRANSFER_RECIPIENTS) {
    throw new Error('too many linked-device custody transfer recipients are active');
  }
  const recipient = linked_device_custody_transfer_recipient_v1();
  const recipientHandleId = createTransferRecipientHandleId();
  custodyTransferRecipients.set(recipientHandleId, recipient);
  return {
    recipientHandleId,
    recipientPublicKeyB64u: recipient.public_key_b64u(),
  };
}

/**
 * Refactor 103 zero-prompt handoff: opens the wallet custody seed envelope
 * with the factor secret already in hand from registration or ordinary
 * unlock, and parks the opened handle for the owner Wallet Session that
 * authorized it. Only the public reference crosses back.
 */
async function establishUnlockedWalletCustodyTransferCapability(
  request: EstablishUnlockedCustodyCapabilityRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const envelope = request.payload.existingEnvelope;
  const existingFactorSecret = toBytes(request.payload.existingFactorSecret);
  try {
    const walletId = requireCapabilityFact(request.payload.walletId, 'walletId');
    const walletAuthMethodId = requireCapabilityFact(
      request.payload.walletAuthMethodId,
      'walletAuthMethodId',
    );
    const walletSessionId = requireCapabilityFact(
      request.payload.walletSessionId,
      'walletSessionId',
    );
    const expiresAtMs = request.payload.expiresAtMs;
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
      throw new Error('unlocked custody capability expiry must be in the future');
    }
    if (String(envelope.walletId) !== walletId) {
      throw new Error('unlocked custody capability envelope names another wallet');
    }
    // One capability per wallet: a replacement (new unlock, new session)
    // destroys the previous handle before the new one is admitted.
    for (const [existingId, record] of [...unlockedCustodyCapabilities]) {
      if (record.walletId === walletId) destroyUnlockedCustodyCapabilityEntry(existingId);
    }
    if (unlockedCustodyCapabilities.size >= MAX_ACTIVE_UNLOCKED_CUSTODY_CAPABILITIES) {
      throw new Error('too many unlocked custody capabilities are active');
    }
    const handle = passkey_custody_open_wallet_seed_v1(
      existingFactorSecret,
      custodyEnvelopeBindingJson(envelope),
      base64UrlDecode(envelope.nonceB64u),
      envelope.sealedCustodySecretB64u,
      envelope.aadHashB64u,
      envelope.ciphertextDigestB64u,
    );
    const capabilityHandleId = createUnlockedCustodyCapabilityHandleId();
    unlockedCustodyCapabilities.set(capabilityHandleId, {
      handle,
      walletId,
      walletAuthMethodId,
      walletSessionId,
      expiresAtMs,
    });
    return {
      kind: 'unlocked_wallet_custody_transfer_capability_v1',
      capabilityHandleId,
      walletId,
      walletAuthMethodId,
      walletSessionId,
      expiresAtMs,
    };
  } finally {
    existingFactorSecret.fill(0);
  }
}

/** Lock, logout, session retirement, expiry, failed activation, teardown. */
function destroyUnlockedWalletCustodyTransferCapabilities(
  request: DestroyUnlockedCustodyCapabilitiesRequest,
): unknown {
  const scope = request.payload.scope;
  let destroyedCount = 0;
  for (const [capabilityHandleId, record] of [...unlockedCustodyCapabilities]) {
    const matches =
      scope.kind === 'all' ||
      (scope.kind === 'capability' && scope.capabilityHandleId === capabilityHandleId) ||
      (scope.kind === 'wallet' && scope.walletId === record.walletId) ||
      (scope.kind === 'wallet_session' && scope.walletSessionId === record.walletSessionId);
    if (matches && destroyUnlockedCustodyCapabilityEntry(capabilityHandleId)) {
      destroyedCount += 1;
    }
  }
  return { destroyedCount };
}

/**
 * Device 1: seals the seed for one approved linked device from the unlocked
 * capability established at registration or unlock.
 *
 * Every fact in the presented reference is re-verified against the record this
 * worker stored, so a caller holding a stale or foreign reference fails before
 * any ciphertext exists. An expired capability is destroyed on sight. The
 * handle survives a successful seal: separately approved enrollments may seal
 * again while the owner Wallet Session remains active, each with fresh
 * ephemeral key material drawn inside wasm.
 */
async function sealWalletCustodySeedForLinkedDevice(
  request: SealForLinkedDeviceRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const capability = request.payload.capability;
  const capabilityHandleId = requireCapabilityFact(
    capability.capabilityHandleId,
    'capabilityHandleId',
  );
  const record = unlockedCustodyCapabilities.get(capabilityHandleId);
  if (!record) {
    throw new Error('unlocked custody capability is unknown or destroyed');
  }
  if (
    String(capability.walletId) !== record.walletId ||
    String(capability.walletAuthMethodId) !== record.walletAuthMethodId ||
    String(capability.walletSessionId) !== record.walletSessionId ||
    capability.expiresAtMs !== record.expiresAtMs
  ) {
    throw new Error('unlocked custody capability reference does not match the held handle');
  }
  if (record.expiresAtMs <= Date.now()) {
    destroyUnlockedCustodyCapabilityEntry(capabilityHandleId);
    throw new Error('unlocked custody capability has expired');
  }
  const sealed = passkey_custody_seal_wallet_seed_for_linked_device_v1(
    record.handle,
    request.payload.transferBindingJson,
  ) as Record<string, unknown>;
  return {
    ephemeralPublicKeyB64u: String(sealed.ephemeralPublicKeyB64u || ''),
    nonceB64u: String(sealed.nonceB64u || ''),
    sealedCustodySecretB64u: String(sealed.sealedCustodySecretB64u || ''),
    aadHashB64u: String(sealed.aadHashB64u || ''),
    ciphertextDigestB64u: String(sealed.ciphertextDigestB64u || ''),
  };
}

function requireCapabilityFact(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`unlocked custody capability ${label} is invalid`);
  }
  return value;
}

function createUnlockedCustodyCapabilityHandleId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `unlocked-custody-capability-${base64UrlEncode(bytes)}`;
}

/**
 * Device 2: opens the transfer and reseals under the passkey it just created.
 *
 * One message rather than two on purpose. Splitting them would leave an opened
 * seed sitting behind a handle between turns, reachable by any later message;
 * doing both here means the seed exists only for the span of this call. The
 * recipient key is consumed either way — a transfer is single-use, and keeping
 * it after an attempt would let a second package be opened against it.
 */
async function acceptLinkedDeviceCustodyTransfer(
  request: AcceptTransferRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const recipient = custodyTransferRecipients.get(request.payload.recipientHandleId);
  if (!recipient) {
    new Uint8Array(request.payload.replacementFactorSecret).fill(0);
    throw new Error('linked-device custody transfer recipient is unknown or discarded');
  }
  custodyTransferRecipients.delete(request.payload.recipientHandleId);
  const replacementFactorSecret = toBytes(request.payload.replacementFactorSecret);
  let handle: ReturnType<typeof passkey_custody_open_wallet_seed_from_linked_device_v1> | null =
    null;
  try {
    handle = passkey_custody_open_wallet_seed_from_linked_device_v1(
      recipient,
      request.payload.transferBindingJson,
      request.payload.ephemeralPublicKeyB64u,
      base64UrlDecode(request.payload.nonceB64u),
      request.payload.sealedCustodySecretB64u,
      request.payload.aadHashB64u,
      request.payload.ciphertextDigestB64u,
    );
    const resealed = passkey_custody_reseal_transferred_wallet_seed_v1(
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
    replacementFactorSecret.fill(0);
    recipient.free();
  }
}

/** Cancel, failure, and page teardown all land here. */
function discardLinkedDeviceCustodyTransferRecipient(
  request: DiscardTransferRecipientRequest,
): unknown {
  const recipient = custodyTransferRecipients.get(request.payload.recipientHandleId);
  custodyTransferRecipients.delete(request.payload.recipientHandleId);
  recipient?.free();
  return {
    recipientHandleId: request.payload.recipientHandleId,
    discarded: Boolean(recipient),
  };
}

function createTransferRecipientHandleId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `linked-device-custody-transfer-${base64UrlEncode(bytes)}`;
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
    case 'createLinkedDeviceCustodyTransferRecipient':
      postSucceeded(request.id, await createLinkedDeviceCustodyTransferRecipient(request));
      return;
    case 'establishUnlockedWalletCustodyTransferCapability':
      postSucceeded(request.id, await establishUnlockedWalletCustodyTransferCapability(request));
      return;
    case 'destroyUnlockedWalletCustodyTransferCapabilities':
      postSucceeded(request.id, destroyUnlockedWalletCustodyTransferCapabilities(request));
      return;
    case 'sealWalletCustodySeedForLinkedDevice':
      postSucceeded(request.id, await sealWalletCustodySeedForLinkedDevice(request));
      return;
    case 'acceptLinkedDeviceCustodyTransfer':
      postSucceeded(request.id, await acceptLinkedDeviceCustodyTransfer(request));
      return;
    case 'discardLinkedDeviceCustodyTransferRecipient':
      postSucceeded(request.id, discardLinkedDeviceCustodyTransferRecipient(request));
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
