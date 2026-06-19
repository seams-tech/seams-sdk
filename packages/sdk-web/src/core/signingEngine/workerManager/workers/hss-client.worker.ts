import {
  type WorkerResponseDiagnostics,
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import initHssClientSigner, {
  build_ecdsa_role_local_export_artifact_v1,
  finalize_ecdsa_client_bootstrap_v1,
  open_ecdsa_role_local_signing_share_v1,
  prepare_ecdsa_client_bootstrap_v1,
  derive_threshold_ed25519_hss_client_inputs,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_open_client_output,
  threshold_ed25519_hss_open_seed_output,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
  threshold_ed25519_role_separated_client_verifying_share_from_base_share,
  threshold_ed25519_role_separated_normal_signing_create_client_share,
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import initEthSigner, {
  init_eth_signer,
  map_additive_share_to_threshold_signatures_share_2p,
  ThresholdEcdsaPresignSession,
  threshold_ecdsa_compute_signature_share,
} from '../../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import {
  HssClientCustomRequestType,
  HssClientCustomResponseType,
  WorkerControlMessage,
  type ThresholdEcdsaPresignProgressResult,
  type HssWorkerOperationType,
} from '../workerTypes';
import { buildRouterAbEd25519SigningMaterialPersistedHandle } from '../../threshold/ed25519/hssMaterialBinding';

const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'HSS Client Signer');
const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'HSS Client ECDSA Presign');

let hssClientSignerInitPromise: Promise<void> | null = null;
let ethSignerInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();
const DIAGNOSTIC_BREAKDOWN_MAX_DEPTH = 2;
const DIAGNOSTIC_BREAKDOWN_MAX_FIELDS = 64;

type StoredEd25519HssMaterial = {
  materialHandle: string;
  xClientBaseB64u: string;
  clientVerifyingShareB64u: string;
  bindingDigest: string;
};

const ed25519HssMaterialStore = new Map<string, StoredEd25519HssMaterial>();

type StoredEcdsaRoleLocalSigningMaterial = {
  materialHandle: string;
  stateBlobB64u: string;
  bindingDigest: string;
};

const ecdsaRoleLocalSigningMaterialStore = new Map<
  string,
  StoredEcdsaRoleLocalSigningMaterial
>();

type HssEcdsaStoredPresignature = {
  materialHandle: string;
  bigR33: Uint8Array;
  kShare32: Uint8Array;
  sigmaShare32: Uint8Array;
};

const ecdsaRoleLocalPresignSessions = new Map<string, ThresholdEcdsaPresignSession>();
const ecdsaRoleLocalPresignaturesByHandle = new Map<string, HssEcdsaStoredPresignature>();

type HssWorkerResponse = {
  type: WorkerResponseType | HssClientCustomResponseType;
  payload: unknown;
};

type HssWorkerCommandResult = HssWorkerResponse & {
  wasmInitWaitMs: number;
  wasmCallMs: number;
};

function nowMs(): number {
  return performance.now();
}

function roundMs(value: number): number {
  return Math.max(0, Math.round(value));
}

function collectSizeBreakdown(input: {
  value: unknown;
  out: Record<string, number>;
  path: string;
  depth: number;
}): void {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return;
  if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;

  for (const [key, entry] of Object.entries(input.value as Record<string, unknown>)) {
    if (Object.keys(input.out).length >= DIAGNOSTIC_BREAKDOWN_MAX_FIELDS) return;
    const fieldPath = input.path ? `${input.path}.${key}` : key;
    if (typeof entry === 'string') {
      input.out[`${fieldPath}Bytes`] = entry.length;
    } else if (Array.isArray(entry)) {
      input.out[`${fieldPath}Count`] = entry.length;
    } else if (input.depth > 0 && entry && typeof entry === 'object') {
      collectSizeBreakdown({
        value: entry,
        out: input.out,
        path: fieldPath,
        depth: input.depth - 1,
      });
    }
  }
}

function sizeBreakdown(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  collectSizeBreakdown({
    value,
    out,
    path: '',
    depth: DIAGNOSTIC_BREAKDOWN_MAX_DEPTH,
  });
  return out;
}

function totalBreakdownBytes(breakdown: Record<string, number>): number {
  return Object.entries(breakdown).reduce(
    (total, [key, value]) => (key.endsWith('Bytes') ? total + value : total),
    0,
  );
}

function readNonEmptyString(record: Record<string, unknown>, key: string): string {
  const parsed = String(record[key] || '').trim();
  if (!parsed) {
    throw new Error(`HSS client worker request is missing ${key}`);
  }
  return parsed;
}

function readPositiveInteger(record: Record<string, unknown>, key: string): number {
  const parsed = Math.floor(Number(record[key]));
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`HSS client worker request has invalid ${key}`);
  }
  return parsed;
}

function readParticipantIds(record: Record<string, unknown>, key: string): number[] {
  const value = record[key];
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`HSS client worker request is missing ${key}`);
  }
  return value.map((entry) => {
    const parsed = Number(entry);
    if (!Number.isInteger(parsed) || parsed <= 0) {
      throw new Error(`HSS client worker request has invalid ${key}`);
    }
    return parsed;
  });
}

function toU8(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (Array.isArray(value)) return new Uint8Array(value.map((entry) => Number(entry)));
  throw new Error('HSS client worker request expected bytes');
}

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

function normalizePresignStage(stageRaw: unknown): 'triples' | 'triples_done' | 'presign' | 'done' {
  if (stageRaw === 'triples') return 'triples';
  if (stageRaw === 'triples_done') return 'triples_done';
  if (stageRaw === 'presign') return 'presign';
  if (stageRaw === 'done') return 'done';
  return 'triples';
}

function normalizePresignEvent(eventRaw: unknown): 'none' | 'triples_done' | 'presign_done' {
  if (eventRaw === 'triples_done') return 'triples_done';
  if (eventRaw === 'presign_done') return 'presign_done';
  return 'none';
}

function parsePresignPollResult(raw: unknown): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoing: Uint8Array[];
} {
  const obj = (raw || {}) as { stage?: unknown; event?: unknown; outgoing?: unknown };
  const outgoingRaw = obj.outgoing;
  const outgoing = Array.isArray(outgoingRaw) ? outgoingRaw.map((entry) => toU8(entry)) : [];
  return {
    stage: normalizePresignStage(obj.stage),
    event: normalizePresignEvent(obj.event),
    outgoing,
  };
}

function freeEcdsaRoleLocalPresignSession(sessionId: string): void {
  const existing = ecdsaRoleLocalPresignSessions.get(sessionId);
  if (!existing) return;
  ecdsaRoleLocalPresignSessions.delete(sessionId);
  try {
    existing.free();
  } catch {}
}

function randomHandleId(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `${prefix}-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')}`;
}

function putEcdsaRoleLocalPresignatureMaterial(args: {
  sessionId: string;
  presignature97: Uint8Array;
}): { materialHandle: string; bigR33: Uint8Array } {
  if (args.presignature97.length !== 97) {
    throw new Error('threshold ECDSA presignature must be 97 bytes');
  }
  const materialHandle = randomHandleId(`hss-ecdsa-presign-material-${args.sessionId}`);
  const bigR33 = args.presignature97.slice(0, 33);
  ecdsaRoleLocalPresignaturesByHandle.set(materialHandle, {
    materialHandle,
    bigR33: bigR33.slice(),
    kShare32: args.presignature97.slice(33, 65),
    sigmaShare32: args.presignature97.slice(65, 97),
  });
  return { materialHandle, bigR33 };
}

function takeEcdsaRoleLocalPresignatureMaterial(
  materialHandleRaw: unknown,
): HssEcdsaStoredPresignature {
  const materialHandle = String(materialHandleRaw || '').trim();
  if (!materialHandle) throw new Error('Missing threshold ECDSA presignature materialHandle');
  const stored = ecdsaRoleLocalPresignaturesByHandle.get(materialHandle);
  if (!stored) throw new Error('Unknown threshold ECDSA presignature materialHandle');
  ecdsaRoleLocalPresignaturesByHandle.delete(materialHandle);
  return stored;
}

function pollEcdsaRoleLocalPresignSession(
  sessionId: string,
  session: ThresholdEcdsaPresignSession,
): ThresholdEcdsaPresignProgressResult {
  const parsed = parsePresignPollResult(session.poll());
  const outgoingMessages = parsed.outgoing.map((msg) => msg.slice().buffer);
  if (parsed.event !== 'presign_done') {
    return {
      stage: parsed.stage,
      event: parsed.event,
      outgoingMessages,
    };
  }

  const presignature97 = session.take_presignature_97();
  freeEcdsaRoleLocalPresignSession(sessionId);
  const stored = putEcdsaRoleLocalPresignatureMaterial({ sessionId, presignature97 });
  const presignatureBigR33 = stored.bigR33.slice().buffer;
  zeroizeBytes(presignature97);
  return {
    stage: 'done',
    event: 'presign_done',
    outgoingMessages,
    presignatureHandle: stored.materialHandle,
    presignatureBigR33,
  };
}

function requireRecordPayload(payload: unknown): Record<string, unknown> {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    throw new Error('HSS client worker request payload must be an object');
  }
  return payload as Record<string, unknown>;
}

async function storeRouterAbEd25519HssMaterialFromClientOutput(
  payload: unknown,
): Promise<StoredEd25519HssMaterial> {
  const record = requireRecordPayload(payload);
  const opened = threshold_ed25519_hss_open_client_output({
    evaluatorDriverStateB64u: readNonEmptyString(record, 'evaluatorDriverStateB64u'),
    clientOutputMessageB64u: readNonEmptyString(record, 'clientOutputMessageB64u'),
    clientOutputMaskB64u: readNonEmptyString(record, 'clientOutputMaskB64u'),
  }) as { contextBindingB64u?: unknown; xClientBaseB64u?: unknown };
  const contextBindingB64u = String(opened.contextBindingB64u || '').trim();
  const expectedContextBindingB64u = readNonEmptyString(record, 'expectedContextBindingB64u');
  if (contextBindingB64u !== expectedContextBindingB64u) {
    throw new Error('Ed25519 HSS client output context binding mismatch');
  }
  const xClientBaseB64u = String(opened.xClientBaseB64u || '').trim();
  if (!xClientBaseB64u) {
    throw new Error('Ed25519 HSS client output is missing client base material');
  }
  const derived = threshold_ed25519_role_separated_client_verifying_share_from_base_share({
    xClientBaseB64u,
  }) as { clientVerifyingShareB64u?: unknown };
  const clientVerifyingShareB64u = String(derived.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('HSS client worker failed to derive Ed25519 client verifying share');
  }
  const persistedHandle = await buildRouterAbEd25519SigningMaterialPersistedHandle({
    thresholdSessionId: readNonEmptyString(record, 'thresholdSessionId'),
    walletSigningSessionId: readNonEmptyString(record, 'walletSigningSessionId'),
    signingRootId: readNonEmptyString(record, 'signingRootId'),
    signingRootVersion: readNonEmptyString(record, 'signingRootVersion'),
    expiresAtMs: readPositiveInteger(record, 'expiresAtMs'),
    nearAccountId: readNonEmptyString(record, 'nearAccountId'),
    relayerKeyId: readNonEmptyString(record, 'relayerKeyId'),
    participantIds: readParticipantIds(record, 'participantIds'),
    signingWorkerId: readNonEmptyString(record, 'signingWorkerId'),
    clientVerifyingShareB64u,
  });
  const stored = {
    materialHandle: persistedHandle.materialHandle,
    xClientBaseB64u,
    clientVerifyingShareB64u: persistedHandle.clientVerifyingShareB64u,
    bindingDigest: persistedHandle.bindingDigest,
  };
  ed25519HssMaterialStore.set(stored.materialHandle, stored);
  return stored;
}

function storeEd25519HssMaterial(payload: unknown): StoredEd25519HssMaterial {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const xClientBaseB64u = readNonEmptyString(record, 'xClientBaseB64u');
  const expectedClientVerifyingShareB64u = readNonEmptyString(
    record,
    'expectedClientVerifyingShareB64u',
  );
  const bindingDigest = readNonEmptyString(record, 'bindingDigest');
  const derived = threshold_ed25519_role_separated_client_verifying_share_from_base_share({
    xClientBaseB64u,
  }) as { clientVerifyingShareB64u?: unknown };
  const clientVerifyingShareB64u = String(derived.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('HSS client worker failed to derive Ed25519 client verifying share');
  }
  if (clientVerifyingShareB64u !== expectedClientVerifyingShareB64u) {
    throw new Error('Ed25519 HSS material verifying-share binding mismatch');
  }
  const stored = {
    materialHandle,
    xClientBaseB64u,
    clientVerifyingShareB64u,
    bindingDigest,
  };
  ed25519HssMaterialStore.set(materialHandle, stored);
  return stored;
}

function createEd25519NormalSigningClientShareFromHandle(payload: unknown): unknown {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const expectedClientVerifyingShareB64u = readNonEmptyString(
    record,
    'expectedClientVerifyingShareB64u',
  );
  const stored = ed25519HssMaterialStore.get(materialHandle);
  if (!stored) {
    throw new Error('Ed25519 HSS material handle is not loaded in this worker');
  }
  if (stored.clientVerifyingShareB64u !== expectedClientVerifyingShareB64u) {
    throw new Error('Ed25519 HSS material handle verifying-share binding mismatch');
  }
  return threshold_ed25519_role_separated_normal_signing_create_client_share({
    ...record,
    xClientBaseB64u: stored.xClientBaseB64u,
  });
}

function validateEd25519HssMaterialHandle(payload: unknown): {
  materialHandle: string;
  clientVerifyingShareB64u: string;
  bindingDigest: string;
} {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const expectedClientVerifyingShareB64u = readNonEmptyString(
    record,
    'expectedClientVerifyingShareB64u',
  );
  const expectedBindingDigest = readNonEmptyString(record, 'expectedBindingDigest');
  const stored = ed25519HssMaterialStore.get(materialHandle);
  if (!stored) {
    throw new Error('Ed25519 HSS material handle is not loaded in this worker');
  }
  if (stored.clientVerifyingShareB64u !== expectedClientVerifyingShareB64u) {
    throw new Error('Ed25519 HSS material handle verifying-share binding mismatch');
  }
  if (stored.bindingDigest !== expectedBindingDigest) {
    throw new Error('Ed25519 HSS material handle binding digest mismatch');
  }
  return {
    materialHandle: stored.materialHandle,
    clientVerifyingShareB64u: stored.clientVerifyingShareB64u,
    bindingDigest: stored.bindingDigest,
  };
}

function storeEcdsaRoleLocalSigningMaterial(
  payload: unknown,
): StoredEcdsaRoleLocalSigningMaterial {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const bindingDigest = readNonEmptyString(record, 'bindingDigest');
  const stateBlobRecord = requireRecordPayload(record.stateBlob);
  const stateBlobB64u = readNonEmptyString(stateBlobRecord, 'stateBlobB64u');
  const stored = {
    materialHandle,
    stateBlobB64u,
    bindingDigest,
  };
  ecdsaRoleLocalSigningMaterialStore.set(materialHandle, stored);
  return stored;
}

function openEcdsaRoleLocalSigningShareFromHandle(payload: unknown): unknown {
  const record = requireRecordPayload(payload);
  const materialHandle = readNonEmptyString(record, 'materialHandle');
  const expectedBindingDigest = readNonEmptyString(record, 'expectedBindingDigest');
  const stored = ecdsaRoleLocalSigningMaterialStore.get(materialHandle);
  if (!stored) {
    throw new Error('ECDSA role-local signing material handle is not loaded in this worker');
  }
  if (stored.bindingDigest !== expectedBindingDigest) {
    throw new Error('ECDSA role-local signing material binding mismatch');
  }
  return open_ecdsa_role_local_signing_share_v1({
    stateBlobB64u: stored.stateBlobB64u,
  });
}

function openEcdsaRoleLocalSigningShare32FromHandle(payload: unknown): Uint8Array {
  const result = openEcdsaRoleLocalSigningShareFromHandle(payload) as {
    signingShare32B64u?: unknown;
  };
  const signingShare32 = base64UrlDecode(String(result.signingShare32B64u || '').trim());
  if (signingShare32.length !== 32) {
    zeroizeBytes(signingShare32);
    throw new Error('ECDSA role-local signing material must decode to 32 bytes');
  }
  return signingShare32;
}

async function initEcdsaRoleLocalPresignSessionFromMaterialHandle(
  payload: unknown,
): Promise<ThresholdEcdsaPresignProgressResult> {
  await initializeEthSignerWasmForEcdsaPresign();
  const record = requireRecordPayload(payload);
  const sessionId = readNonEmptyString(record, 'sessionId');
  freeEcdsaRoleLocalPresignSession(sessionId);

  const participantIds = readParticipantIds(record, 'participantIds');
  const clientParticipantId = readPositiveInteger(record, 'clientParticipantId');
  const threshold = readPositiveInteger(record, 'threshold');
  const groupPublicKey33 = toU8(record.groupPublicKey33);
  const additiveShare32 = openEcdsaRoleLocalSigningShare32FromHandle(record);
  let clientThresholdSigningShare32: Uint8Array | null = null;
  try {
    clientThresholdSigningShare32 = map_additive_share_to_threshold_signatures_share_2p(
      additiveShare32,
      clientParticipantId,
    ) as Uint8Array;
    if (clientThresholdSigningShare32.length !== 32) {
      throw new Error('ECDSA role-local threshold signing share must be 32 bytes');
    }
    const session = new ThresholdEcdsaPresignSession(
      new Uint32Array(participantIds),
      clientParticipantId,
      threshold,
      clientThresholdSigningShare32,
      groupPublicKey33,
    );
    ecdsaRoleLocalPresignSessions.set(sessionId, session);
    return pollEcdsaRoleLocalPresignSession(sessionId, session);
  } finally {
    zeroizeBytes(additiveShare32);
    zeroizeBytes(clientThresholdSigningShare32);
  }
}

async function stepEcdsaRoleLocalPresignSession(
  payload: unknown,
): Promise<ThresholdEcdsaPresignProgressResult> {
  await initializeEthSignerWasmForEcdsaPresign();
  const record = requireRecordPayload(payload);
  const sessionId = readNonEmptyString(record, 'sessionId');
  const session = ecdsaRoleLocalPresignSessions.get(sessionId);
  if (!session) throw new Error('Unknown threshold ECDSA role-local presign session');

  const stage = record.stage;
  if (stage !== 'triples' && stage !== 'presign') {
    throw new Error('Invalid stage (expected "triples" or "presign")');
  }
  const relayerParticipantId = readPositiveInteger(record, 'relayerParticipantId');
  const currentStage = session.stage();
  if (stage === 'presign') {
    if (currentStage === 'triples_done') {
      session.start_presign();
    } else if (currentStage === 'triples') {
      throw new Error('Client presign session is not ready for "presign" stage');
    }
  }

  const incomingRaw = record.incomingMessages;
  if (!Array.isArray(incomingRaw)) {
    throw new Error('threshold ECDSA role-local presign step requires incomingMessages');
  }
  const incomingMessages = incomingRaw.map((entry) => toU8(entry));
  for (const incoming of incomingMessages) {
    session.message(relayerParticipantId, incoming);
  }
  return pollEcdsaRoleLocalPresignSession(sessionId, session);
}

function abortEcdsaRoleLocalPresignSession(payload: unknown): {
  kind: 'threshold_ecdsa_presign_session_aborted';
  sessionId: string;
} {
  const record = requireRecordPayload(payload);
  const sessionId = readNonEmptyString(record, 'sessionId');
  freeEcdsaRoleLocalPresignSession(sessionId);
  return {
    kind: 'threshold_ecdsa_presign_session_aborted',
    sessionId,
  };
}

async function computeEcdsaRoleLocalSignatureShareFromPresignatureHandle(
  payload: unknown,
): Promise<ArrayBuffer> {
  await initializeEthSignerWasmForEcdsaPresign();
  const record = requireRecordPayload(payload);
  const material = takeEcdsaRoleLocalPresignatureMaterial(record.materialHandle);
  const groupPublicKey33 = toU8(record.groupPublicKey33);
  const expectedPresignBigR33 = toU8(record.expectedPresignBigR33);
  const digest32 = toU8(record.digest32);
  const entropy32 = toU8(record.entropy32);
  try {
    const bigRMatches =
      expectedPresignBigR33.length === material.bigR33.length &&
      expectedPresignBigR33.every((value, index) => value === material.bigR33[index]);
    if (!bigRMatches) {
      throw new Error('threshold ECDSA role-local presignature handle bigR mismatch');
    }
    const out = threshold_ecdsa_compute_signature_share(
      new Uint32Array(readParticipantIds(record, 'participantIds')),
      readPositiveInteger(record, 'clientParticipantId'),
      groupPublicKey33,
      material.bigR33,
      material.kShare32,
      material.sigmaShare32,
      digest32,
      entropy32,
    ) as Uint8Array;
    const ab = out.slice().buffer;
    zeroizeBytes(out);
    return ab;
  } finally {
    zeroizeBytes(material.bigR33);
    zeroizeBytes(material.kShare32);
    zeroizeBytes(material.sigmaShare32);
    zeroizeBytes(expectedPresignBigR33);
    zeroizeBytes(digest32);
    zeroizeBytes(entropy32);
  }
}

function operationTimingsFromPayload(payload: unknown): Record<string, number> | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const timings = (payload as { timings?: unknown }).timings;
  if (!timings || typeof timings !== 'object' || Array.isArray(timings)) return null;
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(timings)) {
    const numberValue = Number(value);
    if (Number.isFinite(numberValue)) out[key] = roundMs(numberValue);
  }
  return Object.keys(out).length ? out : null;
}

function workerDiagnostics(input: {
  requestType: number;
  queuedAt: number;
  startedAt: number;
  completedAt: number;
  command: HssWorkerCommandResult;
  requestPayload: unknown;
}): WorkerResponseDiagnostics {
  const requestPayloadBreakdown = sizeBreakdown(input.requestPayload);
  const responsePayloadBreakdown = sizeBreakdown(input.command.payload);
  const wasmOperationTimings = operationTimingsFromPayload(input.command.payload);
  return {
    kind: 'worker_response_diagnostics_v1',
    worker: 'hssClient',
    requestType: input.requestType,
    queueWaitMs: roundMs(input.startedAt - input.queuedAt),
    wasmInitWaitMs: input.command.wasmInitWaitMs,
    wasmCallMs: input.command.wasmCallMs,
    totalMs: roundMs(input.completedAt - input.queuedAt),
    requestPayloadBytes: totalBreakdownBytes(requestPayloadBreakdown),
    responsePayloadBytes: totalBreakdownBytes(responsePayloadBreakdown),
    requestPayloadBreakdown,
    responsePayloadBreakdown,
    ...(wasmOperationTimings ? { wasmOperationTimings } : {}),
  };
}

function isHssWasmInitFailureMessage(message: string): boolean {
  return /hss client wasm initialization failed|wasm initialization failed|failed to instantiate|module_or_path|webassembly/i.test(
    message,
  );
}

function classifyHssWorkerFailure(error: unknown): {
  message: string;
  code: string;
  coreCode?: string;
} {
  if (error && typeof error === 'object') {
    const message =
      typeof (error as { message?: unknown }).message === 'string'
        ? String((error as { message?: string }).message).trim()
        : '';
    const code =
      typeof (error as { code?: unknown }).code === 'string'
        ? String((error as { code?: string }).code).trim()
        : '';
    const coreCode =
      typeof (error as { coreCode?: unknown }).coreCode === 'string'
        ? String((error as { coreCode?: string }).coreCode).trim()
        : '';
    const resolvedMessage = message || errorMessage(error);
    if (isHssWasmInitFailureMessage(resolvedMessage)) {
      return {
        message: resolvedMessage,
        code: 'WORKER_RUNTIME_ERROR',
        coreCode: 'HSS_WASM_INIT_FAILURE',
      };
    }
    if (code) {
      return {
        message: resolvedMessage,
        code,
        ...(coreCode ? { coreCode } : {}),
      };
    }
    return {
      message: resolvedMessage,
      code: 'SIGNER_CRYPTO_ERROR',
      coreCode: 'HSS_COMMAND_FAILURE',
    };
  }
  const message = errorMessage(error);
  if (isHssWasmInitFailureMessage(message)) {
    return {
      message,
      code: 'WORKER_RUNTIME_ERROR',
      coreCode: 'HSS_WASM_INIT_FAILURE',
    };
  }
  return {
    message,
    code: 'SIGNER_CRYPTO_ERROR',
    coreCode: 'HSS_COMMAND_FAILURE',
  };
}

async function initializeHssClientSignerWasm(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    try {
      const startedAt = Date.now();
      await initHssClientSigner({ module_or_path: hssClientSignerWasmUrl });
      console.info('[hss-client-worker]: HSS client WASM initialized', {
        durationMs: Date.now() - startedAt,
        wasmUrl: String(hssClientSignerWasmUrl),
      });
    } catch (error: unknown) {
      hssClientSignerInitPromise = null;
      console.error('[hss-client-worker]: HSS client WASM initialization failed:', error);
      throw new Error(`HSS client WASM initialization failed: ${errorMessage(error)}`);
    }
  })();
  return hssClientSignerInitPromise;
}

async function initializeEthSignerWasmForEcdsaPresign(): Promise<void> {
  if (ethSignerInitPromise) return ethSignerInitPromise;
  ethSignerInitPromise = (async () => {
    await initializeWasm({
      workerName: 'HSS Client ECDSA Presign',
      wasmUrl: ethSignerWasmUrl,
      initFunction: initEthSigner as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_eth_signer(),
    });
  })();
  return ethSignerInitPromise;
}

async function handleHssClientMessage(data: unknown): Promise<HssWorkerCommandResult> {
  const request = data as { type?: unknown; payload?: unknown };
  const requestType = request?.type;
  const payload = request?.payload;
  const initStartedAt = nowMs();
  await initializeHssClientSignerWasm();
  const wasmInitWaitMs = roundMs(nowMs() - initStartedAt);
  const wasmCallStartedAt = nowMs();

  const response: HssWorkerResponse = await (async () => {
    switch (requestType) {
      case WorkerRequestType.DeriveThresholdEd25519HssClientInputs:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess,
          payload: derive_threshold_ed25519_hss_client_inputs(payload),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssSession:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess,
          payload: threshold_ed25519_hss_prepare_session(payload),
        };
      case WorkerRequestType.PrepareThresholdEd25519HssClientRequest:
        return {
          type: WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess,
          payload: threshold_ed25519_hss_prepare_client_request(payload),
        };
      case WorkerRequestType.DeriveThresholdEd25519HssClientOutputMask:
        return {
          type: WorkerResponseType.DeriveThresholdEd25519HssClientOutputMaskSuccess,
          payload: threshold_ed25519_hss_derive_client_output_mask(payload),
        };
      case WorkerRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactSuccess,
          payload: threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact(payload),
        };
      case WorkerRequestType.OpenThresholdEd25519HssClientOutput:
        return {
          type: WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess,
          payload: threshold_ed25519_hss_open_client_output(payload),
        };
      case WorkerRequestType.OpenThresholdEd25519HssSeedOutput:
        return {
          type: WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess,
          payload: threshold_ed25519_hss_open_seed_output(payload),
        };
      case WorkerRequestType.BuildThresholdEd25519SeedExportArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess,
          payload: threshold_ed25519_seed_export_artifact_from_seed(payload),
        };
      case WorkerRequestType.CreateThresholdEd25519RoleSeparatedNormalSigningClientShare:
        return {
          type: WorkerResponseType.CreateThresholdEd25519RoleSeparatedNormalSigningClientShareSuccess,
          payload: threshold_ed25519_role_separated_normal_signing_create_client_share(payload),
        };
      case HssClientCustomRequestType.ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShare:
        return {
          type: HssClientCustomResponseType.ThresholdEd25519RoleSeparatedClientVerifyingShareFromBaseShareSuccess,
          payload: threshold_ed25519_role_separated_client_verifying_share_from_base_share(payload),
        };
      case HssClientCustomRequestType.StoreThresholdEd25519HssMaterial:
        {
          const stored = storeEd25519HssMaterial(payload);
          return {
            type: HssClientCustomResponseType.StoreThresholdEd25519HssMaterialSuccess,
            payload: {
              materialHandle: stored.materialHandle,
              clientVerifyingShareB64u: stored.clientVerifyingShareB64u,
              bindingDigest: stored.bindingDigest,
            },
          };
        }
      case HssClientCustomRequestType.StoreRouterAbEd25519HssMaterialFromClientOutput:
        {
          const stored = await storeRouterAbEd25519HssMaterialFromClientOutput(payload);
          return {
            type: HssClientCustomResponseType.StoreRouterAbEd25519HssMaterialFromClientOutputSuccess,
            payload: {
              materialHandle: stored.materialHandle,
              clientVerifyingShareB64u: stored.clientVerifyingShareB64u,
              bindingDigest: stored.bindingDigest,
            },
          };
        }
      case HssClientCustomRequestType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle:
        return {
          type: HssClientCustomResponseType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleSuccess,
          payload: createEd25519NormalSigningClientShareFromHandle(payload),
        };
      case HssClientCustomRequestType.ValidateThresholdEd25519HssMaterial:
        return {
          type: HssClientCustomResponseType.ValidateThresholdEd25519HssMaterialSuccess,
          payload: validateEd25519HssMaterialHandle(payload),
        };
      case HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial:
        {
          const stored = storeEcdsaRoleLocalSigningMaterial(payload);
          return {
            type: HssClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess,
            payload: {
              materialHandle: stored.materialHandle,
              bindingDigest: stored.bindingDigest,
            },
          };
        }
      case HssClientCustomRequestType.OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandle:
        return {
          type: HssClientCustomResponseType.OpenThresholdEcdsaRoleLocalSigningShareFromMaterialHandleSuccess,
          payload: openEcdsaRoleLocalSigningShareFromHandle(payload),
        };
      case HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle:
        return {
          type: HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleSuccess,
          payload: await initEcdsaRoleLocalPresignSessionFromMaterialHandle(payload),
        };
      case HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep:
        return {
          type: HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionStepSuccess,
          payload: await stepEcdsaRoleLocalPresignSession(payload),
        };
      case HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionAbort:
        return {
          type: HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionAbortSuccess,
          payload: abortEcdsaRoleLocalPresignSession(payload),
        };
      case HssClientCustomRequestType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle:
        return {
          type: HssClientCustomResponseType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleSuccess,
          payload: await computeEcdsaRoleLocalSignatureShareFromPresignatureHandle(payload),
        };
      case WorkerRequestType.OpenThresholdEcdsaHssRoleLocalSigningShare:
        return {
          type: WorkerResponseType.OpenThresholdEcdsaHssRoleLocalSigningShareSuccess,
          payload: open_ecdsa_role_local_signing_share_v1(payload),
        };
      case WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap:
        return {
          type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: JSON.parse(prepare_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
        };
      case WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap:
        return {
          type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
          payload: JSON.parse(finalize_ecdsa_client_bootstrap_v1(JSON.stringify(payload))),
        };
      case WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact:
        return {
          type: WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess,
          payload: JSON.parse(build_ecdsa_role_local_export_artifact_v1(JSON.stringify(payload))),
        };
      default:
        throw new Error(`Unsupported HSS client request type: ${requestType}`);
    }
  })();
  return {
    ...response,
    wasmInitWaitMs,
    wasmCallMs: roundMs(nowMs() - wasmCallStartedAt),
  };
}

setTimeout(() => {
  self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

async function processWorkerMessage(event: MessageEvent): Promise<void> {
  const eventData = event.data as HssClientWorkerRpcRequest & { queuedAtMs?: unknown };
  const requestId = String(eventData.id || '').trim();
  if (!requestId) {
    throw new Error('HSS client worker request is missing RPC id');
  }
  const requestType = Number(eventData.type);

  try {
    const startedAt = nowMs();
    assertNoPrfSecretsInSignerPayload(eventData);
    const response = await handleHssClientMessage(eventData);
    const completedAt = nowMs();
    self.postMessage({
      id: requestId,
      ok: true,
      result: {
        type: response.type,
        payload: response.payload,
        diagnostics: workerDiagnostics({
          requestType,
          queuedAt: Number(eventData.queuedAtMs ?? startedAt),
          startedAt,
          completedAt,
          command: response,
          requestPayload: eventData.payload,
        }),
      },
    });
    console.info('[hss-client-worker]: request complete', {
      requestId,
      requestType,
      durationMs: roundMs(completedAt - startedAt),
    });
  } catch (error: unknown) {
    if (
      requestType === HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle ||
      requestType === HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep
    ) {
      const sessionId = String(
        (eventData.payload as { sessionId?: unknown } | undefined)?.sessionId || '',
      ).trim();
      if (sessionId) freeEcdsaRoleLocalPresignSession(sessionId);
    }
    console.error('[hss-client-worker]: Message processing failed:', error);
    const failure = classifyHssWorkerFailure(error);
    self.postMessage({
      id: requestId,
      ok: false,
      error: failure.message,
      code: failure.code,
      ...(failure.coreCode ? { coreCode: failure.coreCode } : {}),
    });
  }
}

type HssClientWorkerRpcRequest = {
  id: string;
  type: HssWorkerOperationType;
  payload: unknown;
};

self.onmessage = async (event: MessageEvent<HssClientWorkerRpcRequest>): Promise<void> => {
  const requestId = String((event.data as { id?: unknown })?.id || '').trim();
  if (!requestId) {
    console.warn('[hss-client-worker]: Ignoring message without request id');
    return;
  }

  const eventType = event.data?.type;
  if (typeof eventType !== 'number') {
    console.warn('[hss-client-worker]: Ignoring message with invalid non-numeric type:', eventType);
    return;
  }

  const queuedAtMs = nowMs();
  const queuedEvent = {
    ...event,
    data: {
      ...event.data,
      queuedAtMs,
    },
  } as MessageEvent<HssClientWorkerRpcRequest & { queuedAtMs: number }>;
  messageQueue = messageQueue.catch(() => undefined).then(() => processWorkerMessage(queuedEvent));
  await messageQueue;
};

self.onerror = (message, filename, lineno, colno, error) => {
  console.error('[hss-client-worker]: error:', {
    message: typeof message === 'string' ? message : 'Unknown error',
    filename: filename || 'unknown',
    lineno: lineno || 0,
    colno: colno || 0,
    error,
  });
};

self.onunhandledrejection = (event) => {
  console.error('[hss-client-worker]: Unhandled promise rejection:', event.reason);
  event.preventDefault();
};

function assertNoPrfSecretsInSignerPayload(data: unknown): void {
  const payload =
    data && typeof data === 'object' ? (data as { payload?: unknown }).payload : undefined;
  if (!payload || typeof payload !== 'object') return;
  const payloadRecord = payload as Record<string, unknown>;
  const forbiddenKeys = ['prfOutput', 'prf_output', 'prfFirst', 'prf_first', 'prf'];
  for (const key of forbiddenKeys) {
    if (payloadRecord[key] !== undefined) {
      throw new Error(`Forbidden secret field in signer payload: ${key}`);
    }
  }
}
