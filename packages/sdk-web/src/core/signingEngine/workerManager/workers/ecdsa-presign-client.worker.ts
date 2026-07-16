import initPresignClient, {
  ClientPresignSession,
  init_router_ab_ecdsa_presign_client,
} from '../../../../../../../wasm/router_ab_ecdsa_presign_client/pkg/router_ab_ecdsa_presign_client.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { safeErrorMessage } from '@shared/utils/errors';
import { WorkerDeferred } from '../workerDeferred';
import {
  EcdsaPresignClientRequestType,
  EcdsaPresignClientResponseType,
  WorkerControlMessage,
  type EcdsaPresignClientOperationMap,
  type ThresholdEcdsaPresignProgressResult,
} from '../workerTypes';
import {
  isAttachEcdsaDerivationToPresignPort,
  isAttachEmailOtpToPresignPort,
  isAttachEcdsaPresignToOnlinePort,
  isEcdsaPresignMaterialRequest,
  type EcdsaDerivationAdditiveShareResponse,
  type EcdsaPresignMaterialRequest,
  type EcdsaPresignMaterialResponse,
  type EmailOtpEcdsaSigningShareResponse,
} from '../ecdsaClientWorkerChannels';
import { IndexedDbClientPresignMaterialStore } from './ecdsaPresignMaterialStore';
import {
  parseEcdsaClientPresignPoolIdentity,
  type EcdsaClientPresignPoolIdentity,
} from '../ecdsaPresignPoolIdentity';

type PresignOperationType = keyof EcdsaPresignClientOperationMap;
type PresignRpcRequest = {
  [T in PresignOperationType]: {
    readonly id: string;
    readonly type: T;
    readonly payload: EcdsaPresignClientOperationMap[T]['payload'];
  };
}[PresignOperationType];

type SessionMaterialBinding = {
  readonly groupPublicKey33: Uint8Array;
  readonly expiresAtMs: number;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
};

type PendingAdditiveShare = {
  readonly resolve: (share: Uint8Array) => void;
  readonly reject: (error: Error) => void;
};

type EmailOtpSigningShare = {
  readonly additiveShare32: Uint8Array;
  readonly remainingUses: number;
  readonly expiresAtMs: number;
};

type PendingEmailOtpSigningShare = {
  readonly resolve: (share: EmailOtpSigningShare) => void;
  readonly reject: (error: Error) => void;
};

const presignWasmUrl = resolveWasmUrl(
  'router_ab_ecdsa_presign_client_bg.wasm',
  'ECDSA presign client',
);
const sessions = new Map<string, ClientPresignSession>();
const sessionMaterialBindings = new Map<string, SessionMaterialBinding>();
const materialStore = new IndexedDbClientPresignMaterialStore();
const pendingAdditiveShares = new Map<string, PendingAdditiveShare>();
const pendingEmailOtpSigningShares = new Map<string, PendingEmailOtpSigningShare>();
let derivationPort: MessagePort | null = null;
let emailOtpPort: MessagePort | null = null;
let onlinePort: MessagePort | null = null;
let wasmInitPromise: Promise<void> | null = null;
let messageQueue: Promise<void> = Promise.resolve();

function zeroize(bytes: Uint8Array): void {
  bytes.fill(0);
}

function randomHandle(prefix: string): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let suffix = '';
  for (const byte of bytes) suffix += byte.toString(16).padStart(2, '0');
  return `${prefix}-${suffix}`;
}

function toBytes(value: unknown, label: string): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be bytes`);
}

function requireString(value: unknown, label: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireFutureTimestamp(value: unknown, label: string): number {
  const timestamp = Number(value);
  if (!Number.isSafeInteger(timestamp) || timestamp <= Date.now()) {
    throw new Error(`${label} must be a future timestamp`);
  }
  return timestamp;
}

async function initializePresignWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = initializeWasm({
    workerName: 'ECDSA presign client',
    wasmUrl: presignWasmUrl,
    initFunction: initPresignClient as unknown as (wasmModule?: unknown) => Promise<void>,
    validateFunction: init_router_ab_ecdsa_presign_client,
  });
  return wasmInitPromise;
}

function freeSession(sessionId: string): void {
  const session = sessions.get(sessionId);
  sessions.delete(sessionId);
  sessionMaterialBindings.delete(sessionId);
  if (!session) return;
  try {
    session.free();
  } catch {}
}

function parsePollResult(raw: unknown): {
  stage: 'triples' | 'triples_done' | 'presign' | 'done';
  event: 'none' | 'triples_done' | 'presign_done';
  outgoing: Uint8Array[];
} {
  const record = (raw ?? {}) as Record<string, unknown>;
  const stage =
    record.stage === 'triples' ||
    record.stage === 'triples_done' ||
    record.stage === 'presign' ||
    record.stage === 'done'
      ? record.stage
      : 'triples';
  const event =
    record.event === 'triples_done' || record.event === 'presign_done' ? record.event : 'none';
  const outgoing = Array.isArray(record.outgoing)
    ? record.outgoing.map((entry) => toBytes(entry, 'outgoing presign message'))
    : [];
  return { stage, event, outgoing };
}

async function pollSession(
  sessionId: string,
  session: ClientPresignSession,
): Promise<ThresholdEcdsaPresignProgressResult> {
  const result = parsePollResult(session.poll());
  const outgoingMessages = result.outgoing.map((message) => message.slice().buffer);
  if (result.event !== 'presign_done') {
    return { stage: result.stage, event: result.event, outgoingMessages };
  }
  const binding = sessionMaterialBindings.get(sessionId);
  if (!binding) throw new Error('ECDSA Client presign session has no material binding');
  const presignature97 = session.take_presignature_97();
  freeSession(sessionId);
  if (presignature97.length !== 97) {
    zeroize(presignature97);
    throw new Error('Client presignature must be 97 bytes');
  }
  const materialHandle = randomHandle(`ecdsa-presign-${sessionId}`);
  const bigR33 = presignature97.slice(0, 33);
  const kShare32 = presignature97.slice(33, 65);
  const sigmaShare32 = presignature97.slice(65, 97);
  const presignatureBigR33 = bigR33.slice().buffer;
  try {
    await materialStore.putPendingAdmission({
      materialHandle,
      presignSessionId: sessionId,
      poolIdentity: binding.poolIdentity,
      groupPublicKey33: binding.groupPublicKey33,
      bigR33,
      kShare32,
      sigmaShare32,
      createdAtMs: Date.now(),
      expiresAtMs: binding.expiresAtMs,
    });
    return {
      stage: 'done',
      event: 'presign_done',
      outgoingMessages,
      presignatureHandle: materialHandle,
      presignatureBigR33,
    };
  } finally {
    zeroize(presignature97);
    zeroize(bigR33);
    zeroize(kShare32);
    zeroize(sigmaShare32);
  }
}

function handleDerivationResponse(event: MessageEvent<EcdsaDerivationAdditiveShareResponse>): void {
  const response = event.data;
  if (response.kind !== 'ecdsa_derivation_additive_share_result_v1') return;
  const pending = pendingAdditiveShares.get(response.requestId);
  if (!pending) return;
  pendingAdditiveShares.delete(response.requestId);
  if (!response.ok) {
    pending.reject(new Error(response.error));
    return;
  }
  pending.resolve(new Uint8Array(response.additiveShare32));
}

function handleEmailOtpResponse(event: MessageEvent<EmailOtpEcdsaSigningShareResponse>): void {
  const response = event.data;
  if (response.kind !== 'email_otp_ecdsa_signing_share_result_v1') return;
  const pending = pendingEmailOtpSigningShares.get(response.requestId);
  if (!pending) return;
  pendingEmailOtpSigningShares.delete(response.requestId);
  if (!response.ok) {
    pending.reject(new Error(response.error));
    return;
  }
  pending.resolve({
    additiveShare32: new Uint8Array(response.additiveShare32),
    remainingUses: response.remainingUses,
    expiresAtMs: response.expiresAtMs,
  });
}

function requestAdditiveShare(args: {
  materialHandle: string;
  expectedBindingDigest: string;
}): Promise<Uint8Array> {
  if (!derivationPort) {
    throw new Error('ECDSA presign client has no derivation material channel');
  }
  const requestId = randomHandle('ecdsa-derivation-share');
  const deferred = new WorkerDeferred<Uint8Array>();
  pendingAdditiveShares.set(requestId, deferred);
  derivationPort.postMessage({
    kind: 'ecdsa_derivation_additive_share_request_v1',
    requestId,
    materialHandle: args.materialHandle,
    expectedBindingDigest: args.expectedBindingDigest,
  });
  return deferred.promise;
}

function requestEmailOtpSigningShare(sessionId: string): Promise<EmailOtpSigningShare> {
  if (!emailOtpPort) {
    throw new Error('ECDSA presign client has no Email OTP material channel');
  }
  const requestId = randomHandle('email-otp-ecdsa-share');
  const deferred = new WorkerDeferred<EmailOtpSigningShare>();
  pendingEmailOtpSigningShares.set(requestId, deferred);
  emailOtpPort.postMessage({
    kind: 'email_otp_ecdsa_signing_share_request_v1',
    requestId,
    sessionId,
  });
  return deferred.promise;
}

async function initializeSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionInit]['payload'],
): Promise<
  EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionInit]['result']['payload']
> {
  await initializePresignWasm();
  const sessionId = requireString(payload.sessionId, 'sessionId');
  freeSession(sessionId);
  let additiveShare32: Uint8Array;
  let emailOtpAuthority: { remainingUses: number; expiresAtMs: number } | null = null;
  switch (payload.authority.kind) {
    case 'role_local_derivation_handle':
      additiveShare32 = await requestAdditiveShare({
        materialHandle: requireString(payload.authority.materialHandle, 'materialHandle'),
        expectedBindingDigest: requireString(
          payload.authority.expectedBindingDigest,
          'expectedBindingDigest',
        ),
      });
      break;
    case 'email_otp_worker_session': {
      const claimed = await requestEmailOtpSigningShare(
        requireString(payload.authority.emailOtpSessionId, 'emailOtpSessionId'),
      );
      additiveShare32 = claimed.additiveShare32;
      emailOtpAuthority = {
        remainingUses: claimed.remainingUses,
        expiresAtMs: claimed.expiresAtMs,
      };
      break;
    }
    default:
      payload.authority satisfies never;
      throw new Error('Unsupported ECDSA presign authority');
  }
  const groupPublicKey33 = toBytes(payload.groupPublicKey33, 'groupPublicKey33');
  if (groupPublicKey33.length !== 33) throw new Error('groupPublicKey33 must be 33 bytes');
  const materialExpiresAtMs = requireFutureTimestamp(
    payload.materialExpiresAtMs,
    'materialExpiresAtMs',
  );
  const poolIdentity = parseEcdsaClientPresignPoolIdentity(payload.poolIdentity);
  try {
    const session = new ClientPresignSession(additiveShare32, groupPublicKey33, sessionId);
    sessions.set(sessionId, session);
    sessionMaterialBindings.set(sessionId, {
      groupPublicKey33: groupPublicKey33.slice(),
      expiresAtMs: materialExpiresAtMs,
      poolIdentity,
    });
    const progress = await pollSession(sessionId, session);
    if (emailOtpAuthority) {
      return {
        authority: {
          kind: 'email_otp_worker_session',
          remainingUses: emailOtpAuthority.remainingUses,
          expiresAtMs: emailOtpAuthority.expiresAtMs,
        },
        progress,
      };
    }
    return {
      authority: { kind: 'role_local_derivation_handle' },
      progress,
    };
  } finally {
    zeroize(additiveShare32);
  }
}

async function stepSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionStep]['payload'],
): Promise<ThresholdEcdsaPresignProgressResult> {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  const session = sessions.get(sessionId);
  if (!session) throw new Error('Unknown ECDSA Client presign session');
  if (payload.stage === 'presign' && session.stage() === 'triples_done') {
    session.start_presign();
  }
  for (const incoming of payload.incomingMessages) {
    session.message(new Uint8Array(incoming));
  }
  return await pollSession(sessionId, session);
}

function abortSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionAbort]['payload'],
): { kind: 'threshold_ecdsa_presign_session_aborted'; sessionId: string } {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  freeSession(sessionId);
  return { kind: 'threshold_ecdsa_presign_session_aborted', sessionId };
}

async function admitPresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Admit]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_admitted_v1';
  materialHandle: string;
  presignatureId: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const expectedPresignatureId = requireString(
    payload.expectedPresignatureId,
    'expectedPresignatureId',
  );
  const admitted = await materialStore.admit({
    materialHandle,
    expectedPresignatureId,
    nowMs: Date.now(),
  });
  if (!admitted.ok) {
    throw new Error(`ECDSA Client presign admission failed: ${admitted.code}`);
  }
  return {
    kind: 'ecdsa_client_presignature_admitted_v1',
    materialHandle,
    presignatureId: admitted.presignatureId,
  };
}

async function destroyPresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Destroy]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_destroyed_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  if (!(await materialStore.destroy(materialHandle, Date.now()))) {
    throw new Error('ECDSA Client presignature destruction failed');
  }
  return { kind: 'ecdsa_client_presignature_destroyed_v1', materialHandle };
}

async function reservePresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Reserve]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_lifecycle_advanced_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const result = await materialStore.reserve({
    materialHandle,
    requestBinding: requireString(payload.requestBinding, 'requestBinding'),
    reservationId: requireString(payload.reservationId, 'reservationId'),
    leaseExpiresAtMs: requireFutureTimestamp(payload.leaseExpiresAtMs, 'leaseExpiresAtMs'),
    nowMs: Date.now(),
  });
  if (!result.ok) throw new Error(`ECDSA Client presign reservation failed: ${result.code}`);
  return { kind: 'ecdsa_client_presignature_lifecycle_advanced_v1', materialHandle };
}

async function commitPresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Commit]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_lifecycle_advanced_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const result = await materialStore.commit({
    materialHandle,
    requestBinding: requireString(payload.requestBinding, 'requestBinding'),
    reservationId: requireString(payload.reservationId, 'reservationId'),
    nowMs: Date.now(),
  });
  if (!result.ok) throw new Error(`ECDSA Client presign commit failed: ${result.code}`);
  return { kind: 'ecdsa_client_presignature_lifecycle_advanced_v1', materialHandle };
}

async function handleOnlineMaterialRequest(
  event: MessageEvent<EcdsaPresignMaterialRequest>,
): Promise<void> {
  if (!onlinePort) return;
  if (!isEcdsaPresignMaterialRequest(event.data)) return;
  const request = event.data;
  const taken = await materialStore.takeForOnline({
    materialHandle: request.materialHandle,
    requestBinding: request.requestBinding,
    reservationId: request.reservationId,
    groupPublicKey33: new Uint8Array(request.groupPublicKey33),
    expectedBigR33: new Uint8Array(request.expectedBigR33),
    nowMs: Date.now(),
  });
  if (!taken.ok) {
    const failure: EcdsaPresignMaterialResponse = {
      kind: 'ecdsa_presign_material_result_v1',
      requestId: request.requestId,
      ok: false,
      error: `ECDSA Client presign material unavailable: ${taken.code}`,
    };
    onlinePort.postMessage(failure);
    return;
  }
  const material = taken.material;
  const bigR33 = material.bigR33.buffer;
  const kShare32 = material.kShare32.buffer;
  const sigmaShare32 = material.sigmaShare32.buffer;
  try {
    const success: EcdsaPresignMaterialResponse = {
      kind: 'ecdsa_presign_material_result_v1',
      requestId: request.requestId,
      ok: true,
      bigR33,
      kShare32,
      sigmaShare32,
    };
    onlinePort.postMessage(success, [bigR33, kShare32, sigmaShare32]);
  } finally {
    zeroize(material.bigR33);
    zeroize(material.kShare32);
    zeroize(material.sigmaShare32);
  }
}

function attachControlChannel(value: unknown): boolean {
  if (isAttachEcdsaDerivationToPresignPort(value)) {
    derivationPort?.close();
    derivationPort = value.port;
    derivationPort.onmessage = handleDerivationResponse;
    derivationPort.start();
    return true;
  }
  if (isAttachEcdsaPresignToOnlinePort(value)) {
    onlinePort?.close();
    onlinePort = value.port;
    onlinePort.onmessage = handleOnlineMaterialRequest;
    onlinePort.start();
    return true;
  }
  if (isAttachEmailOtpToPresignPort(value)) {
    emailOtpPort?.close();
    emailOtpPort = value.port;
    emailOtpPort.onmessage = handleEmailOtpResponse;
    emailOtpPort.start();
    return true;
  }
  return false;
}

async function handleRpcRequest(request: PresignRpcRequest): Promise<void> {
  try {
    switch (request.type) {
      case EcdsaPresignClientRequestType.SessionInit:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.SessionInitSuccess,
            payload: await initializeSession(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.SessionStep:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.SessionStepSuccess,
            payload: await stepSession(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.SessionAbort:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.SessionAbortSuccess,
            payload: abortSession(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.Admit:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.AdmitSuccess,
            payload: await admitPresignature(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.Destroy:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.DestroySuccess,
            payload: await destroyPresignature(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.Reserve:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.ReserveSuccess,
            payload: await reservePresignature(request.payload),
          },
        });
        return;
      case EcdsaPresignClientRequestType.Commit:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.CommitSuccess,
            payload: await commitPresignature(request.payload),
          },
        });
        return;
    }
    request satisfies never;
  } catch (error: unknown) {
    self.postMessage({ id: request.id, ok: false, error: safeErrorMessage(error) });
  }
}

function processMessage(event: MessageEvent): void {
  if (attachControlChannel(event.data)) return;
  const request = event.data as PresignRpcRequest;
  messageQueue = messageQueue.then(() => handleRpcRequest(request));
}

self.addEventListener('message', processMessage);
self.postMessage({ type: WorkerControlMessage.WORKER_READY, ready: true });
