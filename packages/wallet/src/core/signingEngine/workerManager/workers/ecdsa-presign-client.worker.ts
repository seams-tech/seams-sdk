import { safeErrorMessage } from '@shared/utils/errors';
import { WorkerDeferred } from '../workerDeferred';
import {
  EcdsaPresignClientRequestType,
  EcdsaPresignClientResponseType,
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  WorkerControlMessage,
  type EcdsaOnlineClientOperationMap,
  type EcdsaPresignClientOperationMap,
  type ThresholdEcdsaPresignProgressResult,
} from '../workerTypes';
import {
  isAttachEcdsaDerivationToPresignPort,
  isAttachLinkedHolderToPresignPort,
  isAttachPresignToOnlinePort,
  type OpaqueEcdsaPresignAuthorityRequestV1,
  type OpaqueEcdsaPresignAuthorityResponseV1,
} from '../ecdsaClientWorkerChannels';
import {
  equalEcdsaClientPresignPoolIdentity,
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

type WorkerClientPresignatureRef = {
  presignatureId: string;
  materialHandle: string;
  bigR33: ArrayBuffer;
  createdAtMs: number;
  expiresAtMs: number;
};

type OpaqueEcdsaPresignAuthorityResultV1 = Extract<
  OpaqueEcdsaPresignAuthorityResponseV1,
  { readonly ok: true }
>['result'];

type PendingOpaquePresignAuthority = {
  readonly port: MessagePort;
  readonly deferred: WorkerDeferred<OpaqueEcdsaPresignAuthorityResultV1>;
};

type OpaquePresignMaterialState =
  | { readonly kind: 'pending_admission' }
  | { readonly kind: 'available' }
  | {
      readonly kind: 'reserved';
      readonly requestBinding: string;
      readonly reservationId: string;
      readonly leaseExpiresAtMs: number;
    }
  | {
      readonly kind: 'committed';
      readonly requestBinding: string;
      readonly reservationId: string;
      readonly leaseExpiresAtMs: number;
    };

type OpaquePresignMaterialEntry = {
  readonly authorityPort: MessagePort;
  readonly poolIdentity: EcdsaClientPresignPoolIdentity;
  readonly groupPublicKey33: Uint8Array;
  readonly bigR33: ArrayBuffer;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  state: OpaquePresignMaterialState;
};

const opaqueMaterials = new Map<string, OpaquePresignMaterialEntry>();
const pendingOpaqueAuthorities = new Map<string, PendingOpaquePresignAuthority>();
const opaqueSessionPorts = new Map<string, MessagePort>();
const opaqueSessionBindings = new Map<
  string,
  {
    readonly poolIdentity: EcdsaClientPresignPoolIdentity;
    readonly groupPublicKey33: Uint8Array;
    readonly expiresAtMs: number;
  }
>();
let derivationPort: MessagePort | null = null;
let linkedHolderPort: MessagePort | null = null;
let onlinePort: MessagePort | null = null;
let messageQueue: Promise<void> = Promise.resolve();

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

function handleOpaqueAuthorityResponse(
  port: MessagePort,
  event: MessageEvent<OpaqueEcdsaPresignAuthorityResponseV1>,
): void {
  const response = event.data;
  if (response.kind !== 'opaque_ecdsa_presign_authority_result_v1') return;
  const pending = pendingOpaqueAuthorities.get(response.requestId);
  if (!pending || pending.port !== port) return;
  pendingOpaqueAuthorities.delete(response.requestId);
  if (!response.ok) {
    pending.deferred.reject(new Error(response.error));
    return;
  }
  pending.deferred.resolve(response.result);
}

function purgeAuthorityPort(port: MessagePort, message: string): void {
  rejectPendingOpaqueAuthorities(port, message);
  for (const [sessionId, sessionPort] of opaqueSessionPorts) {
    if (sessionPort !== port) continue;
    opaqueSessionPorts.delete(sessionId);
    opaqueSessionBindings.delete(sessionId);
  }
  for (const [materialHandle, entry] of opaqueMaterials) {
    if (entry.authorityPort === port) opaqueMaterials.delete(materialHandle);
  }
}

function rejectPendingOpaqueAuthorities(port: MessagePort, message: string): void {
  for (const [requestId, pending] of pendingOpaqueAuthorities) {
    if (pending.port !== port) continue;
    pendingOpaqueAuthorities.delete(requestId);
    pending.deferred.reject(new Error(message));
  }
}

function requestOpaqueAuthority(
  port: MessagePort,
  request: OpaqueEcdsaPresignAuthorityRequestV1,
  transfer: Transferable[] = [],
): Promise<OpaqueEcdsaPresignAuthorityResultV1> {
  const deferred = new WorkerDeferred<OpaqueEcdsaPresignAuthorityResultV1>();
  pendingOpaqueAuthorities.set(request.requestId, { port, deferred });
  try {
    port.postMessage(request, transfer);
  } catch (error) {
    pendingOpaqueAuthorities.delete(request.requestId);
    deferred.reject(error instanceof Error ? error : new Error(String(error)));
  }
  return deferred.promise;
}

async function initializeSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionInit]['payload'],
): Promise<
  EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionInit]['result']['payload']
> {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  if (opaqueSessionPorts.has(sessionId)) await abortSession({ sessionId });
  const poolIdentity = parseEcdsaClientPresignPoolIdentity(payload.poolIdentity);
  const groupPublicKey33 = toBytes(payload.groupPublicKey33, 'groupPublicKey33');
  if (groupPublicKey33.length !== 33) throw new Error('groupPublicKey33 must be 33 bytes');
  const materialExpiresAtMs = requireFutureTimestamp(
    payload.materialExpiresAtMs,
    'materialExpiresAtMs',
  );
  switch (payload.authority.kind) {
    case 'role_local_derivation_handle': {
      if (!derivationPort) {
        throw new Error('ECDSA presign client has no derivation material channel');
      }
      const requestId = randomHandle('ecdsa-role-local-presign');
      const groupPublicKeyBuffer = groupPublicKey33.slice().buffer;
      const result = await requestOpaqueAuthority(
        derivationPort,
        {
          kind: 'opaque_ecdsa_presign_session_init_v1',
          requestId,
          sessionId,
          authority: {
            kind: 'role_local_derivation_handle',
            materialHandle: requireString(payload.authority.materialHandle, 'materialHandle'),
            material: payload.authority.material,
          },
          poolIdentity,
          groupPublicKey33: groupPublicKeyBuffer,
          materialExpiresAtMs,
        },
        [groupPublicKeyBuffer],
      );
      const progress = requireOpaqueProgress(result);
      retainCompletedMaterial({
        progress,
        authorityPort: derivationPort,
        poolIdentity,
        groupPublicKey33,
        expiresAtMs: materialExpiresAtMs,
      });
      if (progress.event !== 'presign_done') {
        opaqueSessionPorts.set(sessionId, derivationPort);
        opaqueSessionBindings.set(sessionId, {
          poolIdentity,
          groupPublicKey33: groupPublicKey33.slice(),
          expiresAtMs: materialExpiresAtMs,
        });
      }
      return { authority: { kind: 'role_local_derivation_handle' }, progress };
    }
    case 'linked_holder_signing_material': {
      if (!linkedHolderPort) {
        throw new Error('ECDSA presign client has no linked holder material channel');
      }
      const requestId = randomHandle('linked-holder-ecdsa-presign');
      const groupPublicKeyBuffer = groupPublicKey33.slice().buffer;
      const result = await requestOpaqueAuthority(
        linkedHolderPort,
        {
          kind: 'opaque_ecdsa_presign_session_init_v1',
          requestId,
          sessionId,
          authority: {
            kind: 'linked_holder_signing_material',
            holderHandleId: requireString(payload.authority.holderHandleId, 'holderHandleId'),
          },
          poolIdentity,
          groupPublicKey33: groupPublicKeyBuffer,
          materialExpiresAtMs,
        },
        [groupPublicKeyBuffer],
      );
      const progress = requireOpaqueProgress(result);
      retainCompletedMaterial({
        progress,
        authorityPort: linkedHolderPort,
        poolIdentity,
        groupPublicKey33,
        expiresAtMs: materialExpiresAtMs,
      });
      if (progress.event !== 'presign_done') {
        opaqueSessionPorts.set(sessionId, linkedHolderPort);
        opaqueSessionBindings.set(sessionId, {
          poolIdentity,
          groupPublicKey33: groupPublicKey33.slice(),
          expiresAtMs: materialExpiresAtMs,
        });
      }
      return { authority: { kind: 'linked_holder_signing_material' }, progress };
    }
    default:
      payload.authority satisfies never;
      throw new Error('Unsupported ECDSA presign authority');
  }
}

async function stepSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionStep]['payload'],
): Promise<ThresholdEcdsaPresignProgressResult> {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  const opaquePort = opaqueSessionPorts.get(sessionId);
  if (opaquePort) {
    const activeBinding = opaqueSessionBindings.get(sessionId);
    if (!activeBinding || Date.now() >= activeBinding.expiresAtMs) {
      await abortSession({ sessionId });
      throw new Error('Opaque ECDSA presign session expired');
    }
    try {
      const requestId = randomHandle('opaque-ecdsa-presign-step');
      const incomingMessages = payload.incomingMessages.map(copyArrayBuffer);
      const result = await requestOpaqueAuthority(
        opaquePort,
        {
          kind: 'opaque_ecdsa_presign_session_step_v1',
          requestId,
          sessionId,
          stage: payload.stage,
          incomingMessages,
        },
        incomingMessages,
      );
      const progress = requireOpaqueProgress(result);
      if (progress.event === 'presign_done') {
        const binding = opaqueSessionBindings.get(sessionId);
        if (!binding) throw new Error('Opaque ECDSA presign session binding is unknown');
        retainCompletedMaterial({
          progress,
          authorityPort: opaquePort,
          poolIdentity: binding.poolIdentity,
          groupPublicKey33: binding.groupPublicKey33,
          expiresAtMs: binding.expiresAtMs,
        });
        opaqueSessionPorts.delete(sessionId);
        opaqueSessionBindings.delete(sessionId);
      }
      return progress;
    } catch (error) {
      opaqueSessionPorts.delete(sessionId);
      opaqueSessionBindings.delete(sessionId);
      throw error;
    }
  }
  throw new Error('Unknown ECDSA Client presign session');
}

async function abortSession(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.SessionAbort]['payload'],
): Promise<{ kind: 'threshold_ecdsa_presign_session_aborted'; sessionId: string }> {
  const sessionId = requireString(payload.sessionId, 'sessionId');
  const opaquePort = opaqueSessionPorts.get(sessionId);
  if (opaquePort) {
    opaqueSessionPorts.delete(sessionId);
    opaqueSessionBindings.delete(sessionId);
    const result = await requestOpaqueAuthority(opaquePort, {
      kind: 'opaque_ecdsa_presign_session_abort_v1',
      requestId: randomHandle('opaque-ecdsa-presign-abort'),
      sessionId,
    });
    if (result.kind !== 'aborted' || result.sessionId !== sessionId) {
      throw new Error('Opaque ECDSA presign authority returned an invalid abort result');
    }
    return { kind: 'threshold_ecdsa_presign_session_aborted', sessionId };
  }
  return { kind: 'threshold_ecdsa_presign_session_aborted', sessionId };
}

function requireOpaqueProgress(
  result: OpaqueEcdsaPresignAuthorityResultV1,
): ThresholdEcdsaPresignProgressResult {
  if (result.kind !== 'progress') {
    throw new Error('Opaque ECDSA presign authority returned an invalid progress result');
  }
  return result.progress;
}

function copyArrayBuffer(value: ArrayBuffer): ArrayBuffer {
  return value.slice(0);
}

async function presignatureId(bigR33: ArrayBuffer): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bigR33));
  let binary = '';
  for (const byte of digest) binary += String.fromCharCode(byte);
  return `presig-${btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')}`;
}

function retainCompletedMaterial(args: {
  progress: ThresholdEcdsaPresignProgressResult;
  authorityPort: MessagePort;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  groupPublicKey33: Uint8Array;
  expiresAtMs: number;
}): void {
  if (args.progress.event !== 'presign_done') return;
  const materialHandle = requireString(args.progress.presignatureHandle, 'presignatureHandle');
  const bigR33 = toBytes(args.progress.presignatureBigR33, 'presignatureBigR33');
  if (bigR33.length !== 33) throw new Error('presignatureBigR33 must be 33 bytes');
  opaqueMaterials.set(materialHandle, {
    authorityPort: args.authorityPort,
    poolIdentity: args.poolIdentity,
    groupPublicKey33: args.groupPublicKey33.slice(),
    bigR33: bigR33.slice().buffer,
    createdAtMs: Date.now(),
    expiresAtMs: args.expiresAtMs,
    state: { kind: 'pending_admission' },
  });
}

function requireOpaqueMaterial(
  materialHandle: string,
  poolIdentity: EcdsaClientPresignPoolIdentity,
): OpaquePresignMaterialEntry {
  const entry = opaqueMaterials.get(materialHandle);
  if (!entry) throw new Error('ECDSA Client presign material unavailable: not_found');
  if (!equalEcdsaClientPresignPoolIdentity(entry.poolIdentity, poolIdentity)) {
    opaqueMaterials.delete(materialHandle);
    void destroyOpaqueMaterial(materialHandle, entry);
    throw new Error('ECDSA Client presign material unavailable: binding_rejected');
  }
  if (Date.now() >= entry.expiresAtMs) {
    opaqueMaterials.delete(materialHandle);
    void destroyOpaqueMaterial(materialHandle, entry);
    throw new Error('ECDSA Client presign material unavailable: material_expired');
  }
  return entry;
}

async function destroyOpaqueMaterial(
  materialHandle: string,
  entry: OpaquePresignMaterialEntry,
): Promise<void> {
  await requestOpaqueAuthority(entry.authorityPort, {
    kind: 'opaque_ecdsa_presign_material_destroy_v1',
    requestId: randomHandle('opaque-ecdsa-presign-destroy'),
    materialHandle,
  }).catch(() => undefined);
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
  const entry = requireOpaqueMaterial(
    materialHandle,
    parseEcdsaClientPresignPoolIdentity(payload.poolIdentity),
  );
  const actualPresignatureId = await presignatureId(entry.bigR33);
  if (actualPresignatureId !== expectedPresignatureId) {
    opaqueMaterials.delete(materialHandle);
    await destroyOpaqueMaterial(materialHandle, entry);
    throw new Error('ECDSA Client presign admission failed: binding_rejected');
  }
  if (entry.state.kind !== 'pending_admission' && entry.state.kind !== 'available') {
    throw new Error('ECDSA Client presign admission failed: invalid_state');
  }
  entry.state = { kind: 'available' };
  return {
    kind: 'ecdsa_client_presignature_admitted_v1',
    materialHandle,
    presignatureId: actualPresignatureId,
  };
}

async function destroyPresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Destroy]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_destroyed_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const entry = requireOpaqueMaterial(
    materialHandle,
    parseEcdsaClientPresignPoolIdentity(payload.poolIdentity),
  );
  opaqueMaterials.delete(materialHandle);
  await destroyOpaqueMaterial(materialHandle, entry);
  return { kind: 'ecdsa_client_presignature_destroyed_v1', materialHandle };
}

async function reservePresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Reserve]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_lifecycle_advanced_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const entry = requireOpaqueMaterial(
    materialHandle,
    parseEcdsaClientPresignPoolIdentity(payload.poolIdentity),
  );
  if (entry.state.kind !== 'available') {
    throw new Error('ECDSA Client presign reservation failed: invalid_state');
  }
  const leaseExpiresAtMs = requireFutureTimestamp(payload.leaseExpiresAtMs, 'leaseExpiresAtMs');
  if (leaseExpiresAtMs > entry.expiresAtMs) {
    throw new Error('ECDSA Client presign reservation failed: material_expired');
  }
  entry.state = {
    kind: 'reserved',
    requestBinding: requireString(payload.requestBinding, 'requestBinding'),
    reservationId: requireString(payload.reservationId, 'reservationId'),
    leaseExpiresAtMs,
  };
  return { kind: 'ecdsa_client_presignature_lifecycle_advanced_v1', materialHandle };
}

async function commitPresignature(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.Commit]['payload'],
): Promise<{
  kind: 'ecdsa_client_presignature_lifecycle_advanced_v1';
  materialHandle: string;
}> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const entry = requireOpaqueMaterial(
    materialHandle,
    parseEcdsaClientPresignPoolIdentity(payload.poolIdentity),
  );
  const requestBinding = requireString(payload.requestBinding, 'requestBinding');
  const reservationId = requireString(payload.reservationId, 'reservationId');
  if (
    entry.state.kind !== 'reserved' ||
    entry.state.requestBinding !== requestBinding ||
    entry.state.reservationId !== reservationId ||
    Date.now() >= entry.state.leaseExpiresAtMs
  ) {
    throw new Error('ECDSA Client presign commit failed: binding_rejected');
  }
  entry.state = {
    kind: 'committed',
    requestBinding,
    reservationId,
    leaseExpiresAtMs: entry.state.leaseExpiresAtMs,
  };
  return { kind: 'ecdsa_client_presignature_lifecycle_advanced_v1', materialHandle };
}

async function listAvailablePresignatures(
  payload: EcdsaPresignClientOperationMap[typeof EcdsaPresignClientRequestType.ListAvailable]['payload'],
): Promise<WorkerClientPresignatureRef[]> {
  const poolIdentity = parseEcdsaClientPresignPoolIdentity(payload.poolIdentity);
  const refs: WorkerClientPresignatureRef[] = [];
  for (const [materialHandle, entry] of opaqueMaterials) {
    if (entry.state.kind !== 'available') continue;
    if (!equalEcdsaClientPresignPoolIdentity(entry.poolIdentity, poolIdentity)) continue;
    if (Date.now() >= entry.expiresAtMs) {
      opaqueMaterials.delete(materialHandle);
      await destroyOpaqueMaterial(materialHandle, entry);
      continue;
    }
    refs.push({
      presignatureId: await presignatureId(entry.bigR33),
      materialHandle,
      bigR33: entry.bigR33.slice(0),
      createdAtMs: entry.createdAtMs,
      expiresAtMs: entry.expiresAtMs,
    });
  }
  return refs.sort((left, right) => left.createdAtMs - right.createdAtMs);
}

function attachControlChannel(value: unknown): boolean {
  if (isAttachEcdsaDerivationToPresignPort(value)) {
    if (derivationPort) {
      purgeAuthorityPort(derivationPort, 'ECDSA derivation presign authority channel was replaced');
    }
    derivationPort?.close();
    derivationPort = value.port;
    derivationPort.onmessage = (event) => handleOpaqueAuthorityResponse(value.port, event);
    derivationPort.onmessageerror = () =>
      purgeAuthorityPort(value.port, 'ECDSA derivation presign authority channel failed');
    derivationPort.start();
    return true;
  }
  if (isAttachLinkedHolderToPresignPort(value)) {
    if (linkedHolderPort) {
      purgeAuthorityPort(
        linkedHolderPort,
        'Linked holder ECDSA presign authority channel was replaced',
      );
    }
    linkedHolderPort?.close();
    linkedHolderPort = value.port;
    linkedHolderPort.onmessage = (event) => handleOpaqueAuthorityResponse(value.port, event);
    linkedHolderPort.onmessageerror = () => {
      purgeAuthorityPort(value.port, 'Linked holder ECDSA presign authority channel failed');
    };
    linkedHolderPort.start();
    return true;
  }
  if (isAttachPresignToOnlinePort(value)) {
    onlinePort?.close();
    onlinePort = value.port;
    onlinePort.onmessage = (event) => enqueueOnlineRequest(value.port, event);
    onlinePort.start();
    return true;
  }
  return false;
}

type OnlineRpcRequest = {
  readonly id: string;
  readonly type: keyof EcdsaOnlineClientOperationMap;
  readonly payload: EcdsaOnlineClientOperationMap[keyof EcdsaOnlineClientOperationMap]['payload'];
};

async function computeOnlineShare(
  payload: EcdsaOnlineClientOperationMap[typeof EcdsaOnlineClientRequestType.ComputeSignatureShare]['payload'],
): Promise<ArrayBuffer> {
  const materialHandle = requireString(payload.materialHandle, 'materialHandle');
  const entry = requireOpaqueMaterial(
    materialHandle,
    parseEcdsaClientPresignPoolIdentity(payload.poolIdentity),
  );
  const requestBinding = requireString(payload.requestBinding, 'requestBinding');
  const reservationId = requireString(payload.reservationId, 'reservationId');
  if (
    entry.state.kind !== 'committed' ||
    entry.state.requestBinding !== requestBinding ||
    entry.state.reservationId !== reservationId ||
    Date.now() >= entry.state.leaseExpiresAtMs
  ) {
    throw new Error('ECDSA Client presign material unavailable: binding_rejected');
  }
  const suppliedGroupPublicKey33 = new Uint8Array(payload.groupPublicKey33);
  if (!equalPublicBytes(entry.groupPublicKey33, suppliedGroupPublicKey33)) {
    opaqueMaterials.delete(materialHandle);
    await destroyOpaqueMaterial(materialHandle, entry);
    throw new Error('ECDSA Client presign material unavailable: binding_rejected');
  }
  const buffers = [
    copyArrayBuffer(payload.groupPublicKey33),
    copyArrayBuffer(payload.expectedPresignBigR33),
    copyArrayBuffer(payload.digest32),
    copyArrayBuffer(payload.clientRerandomizationContribution32),
    copyArrayBuffer(payload.signingWorkerRerandomizationContribution32),
  ];
  try {
    const result = await requestOpaqueAuthority(
      entry.authorityPort,
      {
        kind: 'opaque_ecdsa_online_compute_v1',
        requestId: randomHandle('opaque-ecdsa-online'),
        materialHandle,
        groupPublicKey33: buffers[0]!,
        expectedPresignBigR33: buffers[1]!,
        digest32: buffers[2]!,
        clientRerandomizationContribution32: buffers[3]!,
        signingWorkerRerandomizationContribution32: buffers[4]!,
      },
      buffers,
    );
    if (result.kind !== 'online_share') {
      throw new Error('Opaque ECDSA authority returned an invalid online result');
    }
    opaqueMaterials.delete(materialHandle);
    return result.signatureShare32;
  } catch (error) {
    opaqueMaterials.delete(materialHandle);
    await destroyOpaqueMaterial(materialHandle, entry);
    throw error;
  }
}

function equalPublicBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

async function retireOpaquePool(
  payload: EcdsaOnlineClientOperationMap[typeof EcdsaOnlineClientRequestType.RetirePool]['payload'],
) {
  const poolIdentity = parseEcdsaClientPresignPoolIdentity(payload.poolIdentity);
  let retiredCount = 0;
  for (const [materialHandle, entry] of opaqueMaterials) {
    if (!equalEcdsaClientPresignPoolIdentity(entry.poolIdentity, poolIdentity)) continue;
    opaqueMaterials.delete(materialHandle);
    await destroyOpaqueMaterial(materialHandle, entry);
    retiredCount += 1;
  }
  return {
    kind: 'ecdsa_client_presignature_pool_retired_v1' as const,
    poolIdentity,
    reason: payload.reason,
    retiredCount,
  };
}

async function handleOnlineRequest(port: MessagePort, request: OnlineRpcRequest): Promise<void> {
  try {
    switch (request.type) {
      case EcdsaOnlineClientRequestType.ComputeSignatureShare: {
        const signatureShare32 = await computeOnlineShare(
          request.payload as EcdsaOnlineClientOperationMap[72000]['payload'],
        );
        port.postMessage(
          {
            id: request.id,
            ok: true,
            result: {
              type: EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess,
              payload: signatureShare32,
            },
          },
          [signatureShare32],
        );
        return;
      }
      case EcdsaOnlineClientRequestType.RetirePool:
        port.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaOnlineClientResponseType.RetirePoolSuccess,
            payload: await retireOpaquePool(
              request.payload as EcdsaOnlineClientOperationMap[72001]['payload'],
            ),
          },
        });
        return;
    }
  } catch (error) {
    try {
      port.postMessage({ id: request.id, ok: false, error: safeErrorMessage(error) });
    } catch {
      // The caller reset its channel; the opaque material was already burned.
    }
  }
}

function enqueueOnlineRequest(port: MessagePort, event: MessageEvent<OnlineRpcRequest>): void {
  void handleOnlineRequest(port, event.data);
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
            payload: await abortSession(request.payload),
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
      case EcdsaPresignClientRequestType.ListAvailable:
        self.postMessage({
          id: request.id,
          ok: true,
          result: {
            type: EcdsaPresignClientResponseType.ListAvailableSuccess,
            payload: await listAvailablePresignatures(request.payload),
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
