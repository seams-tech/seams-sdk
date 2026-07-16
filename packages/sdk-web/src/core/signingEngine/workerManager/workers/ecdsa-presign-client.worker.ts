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
  type EcdsaDerivationAdditiveShareResponse,
  type EcdsaPresignMaterialRequest,
  type EcdsaPresignMaterialResponse,
  type EmailOtpEcdsaSigningShareResponse,
} from '../ecdsaClientWorkerChannels';

type PresignOperationType = keyof EcdsaPresignClientOperationMap;
type PresignRpcRequest = {
  [T in PresignOperationType]: {
    readonly id: string;
    readonly type: T;
    readonly payload: EcdsaPresignClientOperationMap[T]['payload'];
  };
}[PresignOperationType];

type StoredPresignMaterial = {
  readonly materialHandle: string;
  readonly bigR33: Uint8Array;
  readonly kShare32: Uint8Array;
  readonly sigmaShare32: Uint8Array;
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
const materials = new Map<string, StoredPresignMaterial>();
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
  if (!session) return;
  sessions.delete(sessionId);
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

function pollSession(
  sessionId: string,
  session: ClientPresignSession,
): ThresholdEcdsaPresignProgressResult {
  const result = parsePollResult(session.poll());
  const outgoingMessages = result.outgoing.map((message) => message.slice().buffer);
  if (result.event !== 'presign_done') {
    return { stage: result.stage, event: result.event, outgoingMessages };
  }
  const presignature97 = session.take_presignature_97();
  freeSession(sessionId);
  if (presignature97.length !== 97) {
    zeroize(presignature97);
    throw new Error('Client presignature must be 97 bytes');
  }
  const materialHandle = randomHandle(`ecdsa-presign-${sessionId}`);
  const material: StoredPresignMaterial = {
    materialHandle,
    bigR33: presignature97.slice(0, 33),
    kShare32: presignature97.slice(33, 65),
    sigmaShare32: presignature97.slice(65, 97),
  };
  materials.set(materialHandle, material);
  zeroize(presignature97);
  return {
    stage: 'done',
    event: 'presign_done',
    outgoingMessages,
    presignatureHandle: materialHandle,
    presignatureBigR33: material.bigR33.slice().buffer,
  };
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
  try {
    const session = new ClientPresignSession(additiveShare32, groupPublicKey33, sessionId);
    sessions.set(sessionId, session);
    const progress = pollSession(sessionId, session);
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

function stepSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionStep]['payload'],
): ThresholdEcdsaPresignProgressResult {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  const session = sessions.get(sessionId);
  if (!session) throw new Error('Unknown ECDSA Client presign session');
  if (payload.stage === 'presign' && session.stage() === 'triples_done') {
    session.start_presign();
  }
  for (const incoming of payload.incomingMessages) {
    session.message(new Uint8Array(incoming));
  }
  return pollSession(sessionId, session);
}

function abortSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionAbort]['payload'],
): { kind: 'threshold_ecdsa_presign_session_aborted'; sessionId: string } {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  freeSession(sessionId);
  return { kind: 'threshold_ecdsa_presign_session_aborted', sessionId };
}

function handleOnlineMaterialRequest(event: MessageEvent<EcdsaPresignMaterialRequest>): void {
  if (!onlinePort) return;
  const request = event.data;
  if (request.kind !== 'ecdsa_presign_material_request_v1') return;
  const material = materials.get(request.materialHandle);
  if (!material) {
    const failure: EcdsaPresignMaterialResponse = {
      kind: 'ecdsa_presign_material_result_v1',
      requestId: request.requestId,
      ok: false,
      error: 'Unknown or already consumed ECDSA Client presign material handle',
    };
    onlinePort.postMessage(failure);
    return;
  }
  materials.delete(request.materialHandle);
  const bigR33 = material.bigR33.buffer;
  const kShare32 = material.kShare32.buffer;
  const sigmaShare32 = material.sigmaShare32.buffer;
  const success: EcdsaPresignMaterialResponse = {
    kind: 'ecdsa_presign_material_result_v1',
    requestId: request.requestId,
    ok: true,
    bigR33,
    kShare32,
    sigmaShare32,
  };
  onlinePort.postMessage(success, [bigR33, kShare32, sigmaShare32]);
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
            payload: stepSession(request.payload),
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
