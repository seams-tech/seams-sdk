import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
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
  ed25519_yao_client_root_transfer_recipient_v1,
  passkey_custody_open_wallet_seed_v1,
  passkey_custody_reseal_wallet_seed_v1,
  passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1,
  passkey_custody_seal_ed25519_yao_client_root_for_linked_device_v1,
  passkey_custody_seal_ed25519_yao_client_root_under_factor_v1,
  type WasmEd25519YaoClientRootTransferRecipientV1,
  type WasmPasskeyCustodyHandleV1,
} from '../../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import initEd25519YaoClient, {
  ed25519_yao_lane_source_from_wallet_seed_v1,
  WasmEd25519YaoLaneClientV1,
  WasmEd25519YaoLaneSourceV1,
  WasmEd25519YaoSourcePreservingRegistrationSessionV1,
} from '../../../../../../../crates/router-ab-ed25519-yao-client/pkg/router_ab_ed25519_yao_client.js';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorLogSummary, safeErrorMessage } from '@shared/utils/errors';
import type {
  PasskeyCustodyEnvelopeRecord,
  WalletCustodyCeremonyCommitPayload,
  WalletCustodyEvmFamilyActivationCompletion,
} from '@shared/passkey-custody';
import {
  buildMethodBoundEnvelopeOwnership,
  custodyEnvelopeBindingJsonV1,
  custodyEnvelopeOwnershipWireV1,
  parseEnvelopeRevision,
  parsePasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { assertEd25519YaoLaneCeremonyBindingParityV1 } from '@/core/signingEngine/threshold/crypto/ed25519YaoLaneWasm';
import type {
  UnlockedWalletEd25519ExportRootCapabilityV1,
  WalletCustodyCeremonyWorkerOperationMap,
} from '../workerTypes';

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
 * Device 2's export-root recipient keys, held here for the same reason
 * ceremony handles are: the private half must never exist as a JavaScript
 * value. A linking attempt uses exactly one, and an abandoned attempt is a bug
 * worth surfacing rather than absorbing, so the map is bounded.
 */
const MAX_ACTIVE_TRANSFER_RECIPIENTS = 2;
const ed25519ExportRootRecipients = new Map<string, WasmEd25519YaoClientRootTransferRecipientV1>();

/**
 * Device 1's unlocked export-root capabilities.
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
const MAX_ACTIVE_UNLOCKED_EXPORT_ROOT_CAPABILITIES = 4;
type UnlockedExportRootCapabilityRecordV1 = {
  readonly handle: WasmPasskeyCustodyHandleV1;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly factorSecret: Uint8Array;
  readonly walletId: string;
  readonly walletAuthMethodId: string;
  readonly walletSessionId: string;
  readonly expiresAtMs: number;
};
const unlockedExportRootCapabilities = new Map<string, UnlockedExportRootCapabilityRecordV1>();

function destroyUnlockedExportRootCapabilityEntry(capabilityHandleId: string): boolean {
  const record = unlockedExportRootCapabilities.get(capabilityHandleId);
  unlockedExportRootCapabilities.delete(capabilityHandleId);
  if (!record) return false;
  record.factorSecret.fill(0);
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
type CreateTransferRecipientRequest = WorkerRequest<'createLinkedDeviceEd25519ExportRootRecipient'>;
type EstablishUnlockedCustodyCapabilityRequest =
  WorkerRequest<'establishUnlockedWalletEd25519ExportRootCapability'>;
type DestroyUnlockedCustodyCapabilitiesRequest =
  WorkerRequest<'destroyUnlockedWalletEd25519ExportRootCapabilities'>;
type SealForLinkedDeviceRequest = WorkerRequest<'sealEd25519ExportRootForLinkedDevice'>;
type ResealFromUnlockedCapabilityRequest =
  WorkerRequest<'resealWalletCustodyFromUnlockedCapability'>;
type AcceptTransferRequest = WorkerRequest<'acceptLinkedDeviceEd25519ExportRoot'>;
type DiscardTransferRecipientRequest =
  WorkerRequest<'discardLinkedDeviceEd25519ExportRootRecipient'>;
type RotateRecoverySetRequest = WorkerRequest<'rotateWalletRecoverySet'>;
type OpenEd25519YaoLaneSourceRequest = WorkerRequest<'openEd25519YaoLaneSource'>;
type PrepareEd25519YaoLaneRequest = WorkerRequest<'prepareEd25519YaoLane'>;
type PrepareEd25519YaoSourcePreservingRegistrationRequest =
  WorkerRequest<'prepareEd25519YaoSourcePreservingRegistration'>;
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
  | ResealFromUnlockedCapabilityRequest
  | AcceptTransferRequest
  | DiscardTransferRecipientRequest
  | RotateRecoverySetRequest
  | OpenEd25519YaoLaneSourceRequest
  | PrepareEd25519YaoLaneRequest
  | PrepareEd25519YaoSourcePreservingRegistrationRequest
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

function requireUnlockedExportRootCapabilityRecord(
  capability: UnlockedWalletEd25519ExportRootCapabilityV1,
): UnlockedExportRootCapabilityRecordV1 {
  const capabilityHandleId = requireCapabilityFact(
    capability.capabilityHandleId,
    'capabilityHandleId',
  );
  const record = unlockedExportRootCapabilities.get(capabilityHandleId);
  if (!record) {
    throw new Error('unlocked Ed25519 export-root capability is unknown or destroyed');
  }
  if (
    String(capability.walletId) !== record.walletId ||
    String(capability.walletAuthMethodId) !== record.walletAuthMethodId ||
    String(capability.walletSessionId) !== record.walletSessionId ||
    capability.expiresAtMs !== record.expiresAtMs
  ) {
    throw new Error(
      'unlocked Ed25519 export-root capability reference does not match the held handle',
    );
  }
  if (record.expiresAtMs <= Date.now()) {
    destroyUnlockedExportRootCapabilityEntry(capabilityHandleId);
    throw new Error('unlocked Ed25519 export-root capability has expired');
  }
  return record;
}

function openedCustodyCapabilityLaneSourceInput(
  capability: UnlockedWalletEd25519ExportRootCapabilityV1,
): { readonly envelope: PasskeyCustodyEnvelopeRecord; readonly factorSecret: Uint8Array } {
  const record = requireUnlockedExportRootCapabilityRecord(capability);
  return {
    envelope: record.envelope,
    factorSecret: record.factorSecret.slice(),
  };
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
  const payload = request.payload;
  const opened =
    payload.kind === 'factor'
      ? {
          envelope: parsePasskeyCustodyEnvelopeRecord(payload.envelope),
          factorSecret: toBytes(payload.factorSecret),
        }
      : openedCustodyCapabilityLaneSourceInput(payload.capability);
  const factorSecret = opened.factorSecret;
  try {
    const envelopeArgs = [
      factorSecret,
      custodyEnvelopeBindingJson(opened.envelope),
      base64UrlDecode(opened.envelope.nonceB64u),
      base64UrlDecode(opened.envelope.sealedCustodySecretB64u),
      base64UrlDecode(opened.envelope.aadHashB64u),
      base64UrlDecode(opened.envelope.ciphertextDigestB64u),
    ] as const;
    const source =
      payload.kind === 'factor'
        ? new WasmEd25519YaoLaneSourceV1(...envelopeArgs)
        : ed25519_yao_lane_source_from_wallet_seed_v1(
            ...envelopeArgs,
            base64UrlDecode(payload.applicationBindingDigestB64u),
            payload.walletKeyId,
            payload.enrollmentId,
            BigInt(payload.revocationEpoch),
            base64UrlDecode(payload.registeredPublicKeyB64u),
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

async function prepareEd25519YaoSourcePreservingRegistration(
  request: PrepareEd25519YaoSourcePreservingRegistrationRequest,
): Promise<
  WalletCustodyCeremonyWorkerOperationMap['prepareEd25519YaoSourcePreservingRegistration']['result']
> {
  await initializeEd25519YaoClientWasm();
  const sourceHandle = requireOpaqueHandle(request.payload.sourceHandle, 'sourceHandle');
  const source = ed25519YaoLaneSources.get(sourceHandle);
  if (!source) throw new Error('Ed25519 Yao lane source handle is unknown or discarded');
  ed25519YaoLaneSources.delete(sourceHandle);
  const [deriverASealSeed, deriverBSealSeed] = distinctLaneSealSeeds();
  let session: WasmEd25519YaoSourcePreservingRegistrationSessionV1 | null = null;
  try {
    session = new WasmEd25519YaoSourcePreservingRegistrationSessionV1(
      JSON.stringify(request.payload.targetAdmission),
      JSON.stringify(request.payload.applicationBinding),
      request.payload.participantIds[0],
      request.payload.participantIds[1],
      source,
      base64UrlDecode(request.payload.expectedRegisteredPublicKeyB64u),
      base64UrlDecode(request.payload.targetClientRecipientPublicKeyB64u),
      deriverASealSeed,
      deriverBSealSeed,
    );
    return { requestJson: String(session.take_execute_request_json()).trim() };
  } finally {
    session?.free();
    source.free();
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

/**
 * The exact shape `signer_core::PasskeyCustodyEnvelopeBindingV1` deserialises,
 * including the ownership discriminator that selects the AAD generation. A V2
 * envelope must serialise as `unbound` or its AAD stops matching what it was
 * sealed under.
 */
function custodyEnvelopeBindingJson(envelope: PasskeyCustodyEnvelopeRecord): string {
  return custodyEnvelopeBindingJsonV1(envelope);
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
async function createLinkedDeviceEd25519ExportRootRecipient(
  _request: CreateTransferRecipientRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  if (ed25519ExportRootRecipients.size >= MAX_ACTIVE_TRANSFER_RECIPIENTS) {
    throw new Error('too many linked-device Ed25519 export-root recipients are active');
  }
  const recipient = ed25519_yao_client_root_transfer_recipient_v1();
  const recipientHandleId = createExportRootRecipientHandleId();
  ed25519ExportRootRecipients.set(recipientHandleId, recipient);
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
async function establishUnlockedWalletEd25519ExportRootCapability(
  request: EstablishUnlockedCustodyCapabilityRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const envelope = parsePasskeyCustodyEnvelopeRecord(request.payload.existingEnvelope);
  const existingFactorSecret = toBytes(request.payload.existingFactorSecret);
  let factorSecretStored = false;
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
      throw new Error('unlocked Ed25519 export-root capability expiry must be in the future');
    }
    if (String(envelope.walletId) !== walletId) {
      throw new Error('unlocked Ed25519 export-root capability envelope names another wallet');
    }
    /* A method-bound envelope belongs to exactly one method. Refusing a
       mismatch here is belt to the AAD's braces: the binding is built from the
       envelope's own owner, so a relabelled row already fails to open — but a
       sibling session must not reach a decrypt attempt at all. */
    if (
      envelope.ownership.kind === 'method_bound' &&
      String(envelope.ownership.walletAuthMethodId) !== walletAuthMethodId
    ) {
      throw new Error('wallet custody envelope belongs to another auth method');
    }
    // One capability per wallet: a replacement (new unlock, new session)
    // destroys the previous handle before the new one is admitted.
    for (const [existingId, record] of [...unlockedExportRootCapabilities]) {
      if (record.walletId === walletId) destroyUnlockedExportRootCapabilityEntry(existingId);
    }
    if (unlockedExportRootCapabilities.size >= MAX_ACTIVE_UNLOCKED_EXPORT_ROOT_CAPABILITIES) {
      throw new Error('too many unlocked Ed25519 export-root capabilities are active');
    }
    const handle = passkey_custody_open_wallet_seed_v1(
      existingFactorSecret,
      custodyEnvelopeBindingJson(envelope),
      base64UrlDecode(envelope.nonceB64u),
      envelope.sealedCustodySecretB64u,
      envelope.aadHashB64u,
      envelope.ciphertextDigestB64u,
    );
    const capabilityHandleId = createUnlockedExportRootCapabilityHandleId();
    unlockedExportRootCapabilities.set(capabilityHandleId, {
      handle,
      envelope,
      factorSecret: existingFactorSecret,
      walletId,
      walletAuthMethodId,
      walletSessionId,
      expiresAtMs,
    });
    factorSecretStored = true;
    /* R109C: a V2 envelope opened under its original AAD is immediately
       resealed as V3 under the method that just authenticated. This is the only
       place the upgrade can happen — it needs the factor secret and the exact
       selected method at the same instant, which is precisely what an unlock
       has and a migration never does. The caller persists what comes back;
       until it does, the V2 row stands and the next unlock retries. */
    const upgradedEnvelope =
      envelope.ownership.kind === 'unbound'
        ? resealUnboundEnvelopeAsMethodBound({
            handle,
            envelope,
            factorSecret: existingFactorSecret,
            walletAuthMethodId,
          })
        : null;
    return {
      kind: 'unlocked_wallet_ed25519_export_root_capability_v1',
      capabilityHandleId,
      walletId,
      walletAuthMethodId,
      walletSessionId,
      expiresAtMs,
      ...(upgradedEnvelope ? { upgradedEnvelope } : {}),
    };
  } finally {
    if (!factorSecretStored) existingFactorSecret.fill(0);
  }
}

/**
 * Reseals an opened pre-109C envelope under the method that just authenticated.
 *
 * The factor secret is unchanged — this is not a factor change — so the only
 * things that move are ownership, from `unbound` to the exact method, and the
 * revision that carries it into the AAD. The envelope keeps its identity, so
 * the upgrade replaces one row through the store's existing next-revision
 * rewrap rather than creating a second envelope for the same seed.
 */
function resealUnboundEnvelopeAsMethodBound(input: {
  readonly handle: ReturnType<typeof passkey_custody_open_wallet_seed_v1>;
  readonly envelope: PasskeyCustodyEnvelopeRecord;
  readonly factorSecret: Uint8Array;
  readonly walletAuthMethodId: string;
}): PasskeyCustodyEnvelopeRecord {
  const parsedMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
  if (!parsedMethodId.ok) {
    throw new Error(`custody envelope upgrade ${parsedMethodId.error.message}`);
  }
  /* Same envelope id, next revision. The upgrade replaces one row's ciphertext
     rather than creating a second envelope for the same seed, so it lands
     through the store's existing rewrap path: that path admits exactly
     `current + 1`, which makes a replayed upgrade a revision conflict instead
     of a duplicate, and leaves no old row to retire. */
  const upgradedRevision = parseEnvelopeRevision(Number(input.envelope.envelopeRevision) + 1);
  const ownership = buildMethodBoundEnvelopeOwnership(parsedMethodId.value);
  const upgradedBindingJson = JSON.stringify({
    walletId: input.envelope.walletId,
    envelopeId: input.envelope.envelopeId,
    factor: input.envelope.factor,
    envelopeRevision: upgradedRevision,
    binding: input.envelope.binding,
    ownership: custodyEnvelopeOwnershipWireV1(ownership),
  });
  const factorSecret = input.factorSecret.slice();
  let resealed: ReturnType<typeof requireResealedEnvelopeResult>;
  try {
    resealed = requireResealedEnvelopeResult(
      passkey_custody_reseal_wallet_seed_v1(input.handle, factorSecret, upgradedBindingJson),
    );
  } finally {
    factorSecret.fill(0);
  }
  const nowMs = Date.now();
  return parsePasskeyCustodyEnvelopeRecord({
    ...input.envelope,
    envelopeRevision: upgradedRevision,
    ownership,
    nonceB64u: resealed.nonceB64u,
    sealedCustodySecretB64u: resealed.sealedCustodySecretB64u,
    aadHashB64u: resealed.aadHashB64u,
    ciphertextDigestB64u: resealed.ciphertextDigestB64u,
    updatedAtMs: nowMs,
  });
}

function requireResealedEnvelopeResult(value: unknown): {
  readonly nonceB64u: string;
  readonly sealedCustodySecretB64u: string;
  readonly aadHashB64u: string;
  readonly ciphertextDigestB64u: string;
} {
  if (!value || typeof value !== 'object') {
    throw new Error('custody envelope upgrade returned no resealed envelope');
  }
  const record = value as Record<string, unknown>;
  return {
    nonceB64u: String(record.nonceB64u || ''),
    sealedCustodySecretB64u: String(record.sealedCustodySecretB64u || ''),
    aadHashB64u: String(record.aadHashB64u || ''),
    ciphertextDigestB64u: String(record.ciphertextDigestB64u || ''),
  };
}

/** Lock, logout, session retirement, expiry, failed activation, teardown. */
function destroyUnlockedWalletEd25519ExportRootCapabilities(
  request: DestroyUnlockedCustodyCapabilitiesRequest,
): unknown {
  const scope = request.payload.scope;
  let destroyedCount = 0;
  for (const [capabilityHandleId, record] of [...unlockedExportRootCapabilities]) {
    const matches =
      scope.kind === 'all' ||
      (scope.kind === 'capability' && scope.capabilityHandleId === capabilityHandleId) ||
      (scope.kind === 'wallet' && scope.walletId === record.walletId) ||
      (scope.kind === 'wallet_session' && scope.walletSessionId === record.walletSessionId);
    if (matches && destroyUnlockedExportRootCapabilityEntry(capabilityHandleId)) {
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
async function sealEd25519ExportRootForLinkedDevice(
  request: SealForLinkedDeviceRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const capability = request.payload.capability;
  const record = requireUnlockedExportRootCapabilityRecord(capability);
  const sealed = passkey_custody_seal_ed25519_yao_client_root_for_linked_device_v1(
    record.handle,
    request.payload.transferBindingJson,
  ) as Record<string, unknown>;
  return {
    ephemeralPublicKeyB64u: String(sealed.ephemeralPublicKeyB64u || ''),
    nonceB64u: String(sealed.nonceB64u || ''),
    sealedExportRootB64u: String(sealed.sealedExportRootB64u || ''),
    bindingDigestB64u: String(sealed.bindingDigestB64u || ''),
    ciphertextDigestB64u: String(sealed.ciphertextDigestB64u || ''),
  };
}

/**
 * Refactor 109C: reseals the wallet seed under a new factor from the unlocked
 * capability, for an addition whose source is Email OTP.
 *
 * The source factor secret is already parked here — an Email unlock left it
 * with the opened handle — so the addition needs no factor release and no
 * second one-time code. The user proves the source freshly to authorize the
 * ceremony; the seed itself comes from the handle that unlock already opened.
 *
 * The same reseal every other path uses. Nothing new is derived: the handle
 * carries the seed's proof that it reproduces this wallet's key set, and the
 * reseal carries that claim forward under the new factor.
 */
async function resealWalletCustodyFromUnlockedCapability(
  request: ResealFromUnlockedCapabilityRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const record = requireUnlockedExportRootCapabilityRecord(request.payload.capability);
  const replacementFactorSecret = toBytes(request.payload.replacementFactorSecret);
  try {
    const resealed = passkey_custody_reseal_wallet_seed_v1(
      record.handle,
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
    replacementFactorSecret.fill(0);
  }
}

function requireCapabilityFact(value: unknown, label: string): string {
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`unlocked Ed25519 export-root capability ${label} is invalid`);
  }
  return value;
}

function createUnlockedExportRootCapabilityHandleId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `unlocked-ed25519-export-root-${base64UrlEncode(bytes)}`;
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
async function acceptLinkedDeviceEd25519ExportRoot(
  request: AcceptTransferRequest,
): Promise<unknown> {
  await initializeNearSignerWasm();
  const recipient = ed25519ExportRootRecipients.get(request.payload.recipientHandleId);
  if (!recipient) {
    new Uint8Array(request.payload.replacementFactorSecret).fill(0);
    throw new Error('linked-device Ed25519 export-root recipient is unknown or discarded');
  }
  ed25519ExportRootRecipients.delete(request.payload.recipientHandleId);
  const replacementFactorSecret = toBytes(request.payload.replacementFactorSecret);
  let handle: WasmPasskeyCustodyHandleV1 | null = null;
  try {
    handle = passkey_custody_open_ed25519_yao_client_root_from_linked_device_v1(
      recipient,
      request.payload.transferBindingJson,
      request.payload.ephemeralPublicKeyB64u,
      base64UrlDecode(request.payload.nonceB64u),
      request.payload.sealedExportRootB64u,
      request.payload.bindingDigestB64u,
      request.payload.ciphertextDigestB64u,
    );
    const resealed = passkey_custody_seal_ed25519_yao_client_root_under_factor_v1(
      handle,
      replacementFactorSecret,
      request.payload.replacementEnvelopeBindingJson,
    ) as Record<string, unknown>;
    return {
      nonceB64u: String(resealed.nonceB64u || ''),
      sealedExportRootB64u: String(resealed.sealedExportRootB64u || ''),
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
function discardLinkedDeviceEd25519ExportRootRecipient(
  request: DiscardTransferRecipientRequest,
): unknown {
  const recipient = ed25519ExportRootRecipients.get(request.payload.recipientHandleId);
  ed25519ExportRootRecipients.delete(request.payload.recipientHandleId);
  recipient?.free();
  return {
    recipientHandleId: request.payload.recipientHandleId,
    discarded: Boolean(recipient),
  };
}

function createExportRootRecipientHandleId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return `linked-device-ed25519-export-root-${base64UrlEncode(bytes)}`;
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
    case 'prepareEd25519YaoSourcePreservingRegistration':
      postSucceeded(request.id, await prepareEd25519YaoSourcePreservingRegistration(request));
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
    case 'createLinkedDeviceEd25519ExportRootRecipient':
      postSucceeded(request.id, await createLinkedDeviceEd25519ExportRootRecipient(request));
      return;
    case 'establishUnlockedWalletEd25519ExportRootCapability':
      postSucceeded(request.id, await establishUnlockedWalletEd25519ExportRootCapability(request));
      return;
    case 'destroyUnlockedWalletEd25519ExportRootCapabilities':
      postSucceeded(request.id, destroyUnlockedWalletEd25519ExportRootCapabilities(request));
      return;
    case 'resealWalletCustodyFromUnlockedCapability':
      postSucceeded(request.id, await resealWalletCustodyFromUnlockedCapability(request));
      return;
    case 'sealEd25519ExportRootForLinkedDevice':
      postSucceeded(request.id, await sealEd25519ExportRootForLinkedDevice(request));
      return;
    case 'acceptLinkedDeviceEd25519ExportRoot':
      postSucceeded(request.id, await acceptLinkedDeviceEd25519ExportRoot(request));
      return;
    case 'discardLinkedDeviceEd25519ExportRootRecipient':
      postSucceeded(request.id, discardLinkedDeviceEd25519ExportRootRecipient(request));
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
