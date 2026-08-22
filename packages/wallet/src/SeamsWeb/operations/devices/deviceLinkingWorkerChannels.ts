import {
  parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
  type RouterAbEcdsaSigningWorkerExportShareBindingV1,
  type RouterAbEcdsaSigningWorkerExportShareEnvelopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  encodeLinkedDeviceRequestProofV1,
  parseLinkedDeviceProvisioningChildV1,
  parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  parseLinkDevicePublicKeyB64u,
  type LinkedDeviceProvisioningChildV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceRequestProofV1,
} from '@shared/device-linking';
import type {
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
  SealedLaneHolderMaterialV1,
} from '@shared/signing-lanes/rotation';
import {
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
} from '@shared/signing-lanes/rotationParsers';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  type LinkDeviceSessionId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
} from '@shared/signing-lanes/ids';
import {
  parseMpcMaterialActivationRef,
  parseWalletId,
  type MpcMaterialActivationRef,
  type WalletId,
} from '@shared/utils/domainIds';
import { resolveWorkerUrl } from '@/core/walletRuntimePaths';
import {
  parseLaneSealedHolderRecordV1,
  type LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import {
  createDeviceLinkingOrdinaryMaterialWorkerPortV1,
  type DeviceLinkingOrdinaryMaterialWorkerPortV1,
  type DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1,
  type DeviceLinkingOrdinaryMaterialWorkerRequestV1,
} from './deviceLinkingOrdinaryMaterialWorker';
import type {
  DeviceLinkingEd25519SigningShareV1,
  DeviceLinkingEcdsaExportArtifactV1,
  DeviceLinkingEcdsaExportPublicFactsV1,
  DeviceLinkingEcdsaExportRecipientV1,
  DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1,
  DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1,
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingKeyMaterialPortV1,
  DeviceLinkingKeyMaterialBundleV1,
} from './deviceLinkingPorts';
import { EcdsaClientWorkerControlKind } from '@/core/signingEngine/workerManager/ecdsaClientWorkerChannels';
import { getWorkerTransport } from '@/core/signingEngine/workerManager/workerTransport';

export type DeviceLinkingWorkerEndpointV1 = {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  addEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'error', listener: (event: ErrorEvent) => void): void;
  terminate(): void;
};

export type DeviceLinkingWorkerKeyMaterialPortV1 = DeviceLinkingKeyMaterialPortV1 &
  DeviceLinkingHolderSigningMaterialPortV1 & {
    close(): void;
  } & DeviceLinkingOrdinaryMaterialWorkerPortV1;

type DeviceLinkingWorkerRequestV1 =
  | DeviceLinkingOrdinaryMaterialWorkerRequestV1
  | DeviceLinkingOrdinaryMaterialWorkerPrivateRequestV1
  | { readonly kind: 'device_linking_key_material_create_v1' }
  | {
      readonly kind: 'device_linking_email_otp_export_root_recipient_create_v1';
      readonly handleId: string;
    }
  | {
      readonly kind: 'device_linking_target_holder_open_seal_v1';
      readonly handleId: string;
      readonly delivery: LinkedDeviceProvisioningChildV1;
    }
  | {
      readonly kind: 'device_linking_holder_signing_material_open_v1';
      readonly factorSecret: ArrayBuffer;
      readonly job: RotatableSigningLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly holderRecord: LaneSealedHolderRecordV1;
    }
  | {
      readonly kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1';
      readonly handleId: string;
      readonly walletId: WalletId;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly targetPreparationDigestB64u: DigestB64u;
      readonly orderedChildren: readonly [
        DeviceLinkingEmailOtpHolderSigningMaterialBatchChildV1,
        ...DeviceLinkingEmailOtpHolderSigningMaterialBatchChildV1[],
      ];
    }
  | {
      readonly kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1';
      readonly handleId: string;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly expectedChallengeId: string;
      readonly factorRelease: LinkedDeviceEmailOtpFactorReleaseEnvelopeV1;
      readonly orderedChildren: readonly [
        DeviceLinkingEmailOtpHolderSigningMaterialBatchChildV1,
        ...DeviceLinkingEmailOtpHolderSigningMaterialBatchChildV1[],
      ];
    }
  | {
      readonly kind: 'device_linking_holder_signing_material_discard_v1';
      readonly handleId: string;
    }
  | {
      readonly kind: 'device_linking_holder_ed25519_sign_v1';
      readonly handleId: string;
      readonly admittedDigestB64u: DigestB64u;
      readonly signingWorkerCommitments: {
        readonly hiding: string;
        readonly binding: string;
      };
      readonly signingWorkerVerifyingShareB64u: string;
    }
  | {
      readonly kind: 'device_linking_holder_ecdsa_export_recipient_prepare_v1';
      readonly handleId: string;
      readonly operationId: string;
    }
  | {
      readonly kind: 'device_linking_holder_ecdsa_export_finalize_v1';
      readonly handleId: string;
      readonly recipientHandleId: string;
      readonly signingWorkerExport: RouterAbEcdsaSigningWorkerExportShareEnvelopeV1;
      readonly expectedBinding: RouterAbEcdsaSigningWorkerExportShareBindingV1;
      readonly expectedPublicFacts: DeviceLinkingEcdsaExportPublicFactsV1;
    }
  | {
      readonly kind: 'device_linking_request_sign_v1';
      readonly handleId: string;
      readonly linkSessionId: LinkDeviceSessionId;
      readonly method: 'GET' | 'POST';
      readonly canonicalPath: string;
      readonly bodyDigestB64u: DigestB64u;
      readonly devicePublicKeyDigestB64u: DigestB64u;
      readonly challengeB64u: string;
      readonly issuedAtMs: number;
      readonly expiresAtMs: number;
    }
  | {
      readonly kind: 'device_linking_key_material_discard_v1';
      readonly handleId: string;
    };

type DeviceLinkingWorkerResponseFrameV1 =
  | { readonly id: string; readonly ok: true; readonly result: unknown }
  | { readonly id: string; readonly ok: false; readonly error: string };

type PendingRequestV1 = {
  readonly resolve: (value: unknown) => void;
  readonly reject: (error: Error) => void;
  readonly timeoutId: ReturnType<typeof setTimeout>;
};

type DeviceLinkingEmailOtpHolderSigningMaterialBatchChildV1 =
  DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1['orderedChildren'][number];

type DeviceLinkingHolderSigningMaterialBatchResultV1 = {
  readonly holderSigningMaterialHandles: readonly [
    DeviceLinkingHolderSigningMaterialHandleV1,
    ...DeviceLinkingHolderSigningMaterialHandleV1[],
  ];
};

type DeviceLinkingInitialHolderSigningMaterialBatchResultV1 =
  DeviceLinkingHolderSigningMaterialBatchResultV1 & {
    readonly warmSessionFactorSecret: ArrayBuffer;
  };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} must be an object`);
  return value;
}

function exactRecord(
  value: unknown,
  fields: readonly string[],
  label: string,
): Record<string, unknown> {
  const record = requireRecord(value, label);
  const expected = new Set(fields);
  for (const key of Object.keys(record)) {
    if (!expected.has(key)) throw new Error(`${label}.${key} is not supported`);
  }
  for (const key of fields) {
    if (!(key in record)) throw new Error(`${label}.${key} is required`);
  }
  return record;
}

function nonEmpty(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function parseDigest(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseFixedB64u(value: unknown, length: number, label: string): string {
  const encoded = nonEmpty(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(encoded);
  } catch {
    throw new Error(`${label} is invalid`);
  }
  if (bytes.length !== length || base64UrlEncode(bytes) !== encoded) {
    throw new Error(`${label} must be canonical base64url`);
  }
  bytes.fill(0);
  return encoded;
}

function parseHandle(value: unknown): DeviceLinkingKeyMaterialHandleV1 {
  const record = exactRecord(value, ['kind', 'handleId'], 'device-linking key handle');
  if (record.kind !== 'device_linking_key_material_handle_v1') {
    throw new Error('device-linking key handle kind is invalid');
  }
  return {
    kind: 'device_linking_key_material_handle_v1',
    handleId: nonEmpty(record.handleId, 'device-linking key handle.handleId'),
  };
}

function parseCreateResult(value: unknown): DeviceLinkingKeyMaterialBundleV1 {
  const record = exactRecord(
    value,
    ['handleId', 'linkPublicKeyB64u', 'devicePublicKeyB64u', 'emailOtpReleasePublicKey65B64u'],
    'device-linking key create response',
  );
  return {
    handle: {
      kind: 'device_linking_key_material_handle_v1',
      handleId: nonEmpty(record.handleId, 'device-linking key create handleId'),
    },
    linkPublicKeyB64u: parseLinkDevicePublicKeyB64u(record.linkPublicKeyB64u),
    devicePublicKeyB64u: parseLinkDevicePublicKeyB64u(record.devicePublicKeyB64u),
    emailOtpReleasePublicKey65B64u: parseFixedB64u(
      record.emailOtpReleasePublicKey65B64u,
      65,
      'emailOtpReleasePublicKey65B64u',
    ),
  };
}

function parseHolderSigningMaterialHandle(
  value: unknown,
): DeviceLinkingHolderSigningMaterialHandleV1 {
  const record = exactRecord(
    value,
    ['handleId', 'keyFamily'],
    'device-linking holder signing material response',
  );
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error('device-linking holder signing material keyFamily is invalid');
  }
  return {
    kind: 'device_linking_holder_signing_material_handle_v1',
    handleId: nonEmpty(record.handleId, 'device-linking holder signing material handleId'),
    keyFamily: record.keyFamily,
  };
}

function parseHolderSigningMaterialHandleInput(
  value: unknown,
): DeviceLinkingHolderSigningMaterialHandleV1 {
  const record = exactRecord(
    value,
    ['kind', 'handleId', 'keyFamily'],
    'device-linking holder signing material handle',
  );
  if (record.kind !== 'device_linking_holder_signing_material_handle_v1') {
    throw new Error('device-linking holder signing material handle kind is invalid');
  }
  return parseHolderSigningMaterialHandle({
    handleId: record.handleId,
    keyFamily: record.keyFamily,
  });
}

function parseHolderSigningMaterialBatchResult(
  value: unknown,
  children: DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1['orderedChildren'],
): DeviceLinkingHolderSigningMaterialBatchResultV1 {
  const record = exactRecord(
    value,
    ['holderSigningMaterialHandles'],
    'device-linking Email OTP holder signing material batch response',
  );
  if (!Array.isArray(record.holderSigningMaterialHandles)) {
    throw new Error('device-linking Email OTP holder signing material batch response is invalid');
  }
  if (record.holderSigningMaterialHandles.length !== children.length) {
    throw new Error('device-linking Email OTP holder signing material batch count changed');
  }
  const handles: DeviceLinkingHolderSigningMaterialHandleV1[] = [];
  const handleIds = new Set<string>();
  for (let index = 0; index < children.length; index += 1) {
    const rawHandle = record.holderSigningMaterialHandles[index];
    const handle = parseHolderSigningMaterialHandle(rawHandle);
    const child = children[index];
    if (!child || handle.keyFamily !== child.job.keyFamily || handleIds.has(handle.handleId)) {
      throw new Error('device-linking Email OTP holder signing material order changed');
    }
    handleIds.add(handle.handleId);
    handles.push(handle);
  }
  const first = handles[0];
  if (!first) throw new Error('device-linking Email OTP holder signing material batch is empty');
  return {
    holderSigningMaterialHandles: nonEmptyTupleV1(first, handles.slice(1)),
  };
}

function parseInitialHolderSigningMaterialBatchResult(
  value: unknown,
  children: DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1['orderedChildren'],
): DeviceLinkingInitialHolderSigningMaterialBatchResultV1 {
  const record = exactRecord(
    value,
    ['holderSigningMaterialHandles', 'warmSessionFactorSecret'],
    'device-linking initial Email OTP holder signing material batch response',
  );
  if (
    !(record.warmSessionFactorSecret instanceof ArrayBuffer) ||
    record.warmSessionFactorSecret.byteLength !== 32
  ) {
    throw new Error('device-linking Email OTP warm-session factor secret is invalid');
  }
  const parsed = parseHolderSigningMaterialBatchResult(
    { holderSigningMaterialHandles: record.holderSigningMaterialHandles },
    children,
  );
  return {
    ...parsed,
    warmSessionFactorSecret: record.warmSessionFactorSecret,
  };
}

function nonEmptyTupleV1<T>(first: T, rest: readonly T[]): readonly [T, ...T[]] {
  return [first, ...rest];
}

function parseCommitments(value: unknown): {
  readonly hiding: string;
  readonly binding: string;
} {
  const record = exactRecord(value, ['hiding', 'binding'], 'Ed25519 commitments');
  return {
    hiding: nonEmpty(record.hiding, 'Ed25519 commitments.hiding'),
    binding: nonEmpty(record.binding, 'Ed25519 commitments.binding'),
  };
}

function parseEd25519SigningShare(value: unknown): DeviceLinkingEd25519SigningShareV1 {
  const record = exactRecord(
    value,
    ['clientCommitments', 'clientVerifyingShareB64u', 'clientSignatureShareB64u'],
    'device-linking Ed25519 signing share',
  );
  return {
    clientCommitments: parseCommitments(record.clientCommitments),
    clientVerifyingShareB64u: parseFixedB64u(
      record.clientVerifyingShareB64u,
      32,
      'clientVerifyingShareB64u',
    ),
    clientSignatureShareB64u: parseFixedB64u(
      record.clientSignatureShareB64u,
      32,
      'clientSignatureShareB64u',
    ),
  };
}

function parseEcdsaExportRecipient(value: unknown): DeviceLinkingEcdsaExportRecipientV1 {
  const record = exactRecord(
    value,
    ['recipientHandleId', 'recipientIdentity', 'recipientPublicKeyB64u'],
    'device-linking ECDSA export recipient',
  );
  return {
    kind: 'device_linking_ecdsa_export_recipient_v1',
    recipientHandleId: nonEmpty(record.recipientHandleId, 'recipientHandleId'),
    recipientIdentity: nonEmpty(record.recipientIdentity, 'recipientIdentity'),
    recipientPublicKeyB64u: parseFixedB64u(
      record.recipientPublicKeyB64u,
      32,
      'recipientPublicKeyB64u',
    ),
  };
}

function parseEcdsaExportArtifact(value: unknown): DeviceLinkingEcdsaExportArtifactV1 {
  const record = exactRecord(
    value,
    ['publicKeyHex', 'privateKeyHex', 'ethereumAddress'],
    'device-linking ECDSA export artifact',
  );
  const publicKeyHex = nonEmpty(record.publicKeyHex, 'publicKeyHex');
  const privateKeyHex = nonEmpty(record.privateKeyHex, 'privateKeyHex');
  const ethereumAddress = nonEmpty(record.ethereumAddress, 'ethereumAddress');
  if (!/^0x[0-9a-f]{66}$/.test(publicKeyHex)) throw new Error('publicKeyHex is invalid');
  if (!/^0x[0-9a-f]{64}$/.test(privateKeyHex)) throw new Error('privateKeyHex is invalid');
  if (!/^0x[0-9a-f]{40}$/.test(ethereumAddress)) {
    throw new Error('ethereumAddress is invalid');
  }
  return { publicKeyHex, privateKeyHex, ethereumAddress };
}

function parseMaterialActivation(value: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(value);
  if (parsed.ok) return parsed.value;
  throw new Error(parsed.error.message);
}

function parseSignatureResult(value: unknown): { readonly signatureB64u: string } {
  const record = exactRecord(value, ['signatureB64u'], 'device-linking request signature response');
  return {
    signatureB64u: parseFixedB64u(record.signatureB64u, 64, 'signatureB64u'),
  };
}

function parseSealedHolderResult(value: unknown): SealedLaneHolderMaterialV1 {
  const record = exactRecord(
    value,
    [
      'sealedHolderMaterialB64u',
      'sealedHolderRecordDigestB64u',
      'verifiedHolderCiphertextDigestSetB64u',
    ],
    'device-linking sealed holder response',
  );
  return {
    sealedHolderMaterialB64u: nonEmpty(record.sealedHolderMaterialB64u, 'sealedHolderMaterialB64u'),
    sealedHolderRecordDigestB64u: parseDigest(
      record.sealedHolderRecordDigestB64u,
      'sealedHolderRecordDigestB64u',
    ),
    verifiedHolderCiphertextDigestSetB64u: parseDigest(
      record.verifiedHolderCiphertextDigestSetB64u,
      'verifiedHolderCiphertextDigestSetB64u',
    ),
  };
}

function parseResponseFrame(value: unknown): DeviceLinkingWorkerResponseFrameV1 | null {
  if (!isRecord(value)) return null;
  const id = value.id;
  if (typeof id !== 'string' || id.trim() !== id || id.length === 0) return null;
  if (value.ok === true && Object.keys(value).length === 3 && 'result' in value) {
    return { id, ok: true, result: value.result };
  }
  if (
    value.ok === false &&
    Object.keys(value).length === 3 &&
    typeof value.error === 'string' &&
    value.error.trim()
  ) {
    return { id, ok: false, error: value.error };
  }
  return null;
}

function requestId(): string {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('secure randomness is unavailable for device-linking worker');
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const id = `device-linking-${base64UrlEncode(bytes)}`;
  bytes.fill(0);
  return id;
}

function normalizeTimeout(value: number | undefined): number {
  if (value !== undefined && Number.isSafeInteger(value) && value > 0) return value;
  return 60_000;
}

function workerError(value: unknown): Error {
  if (value instanceof Error) return value;
  if (typeof value === 'string' && value.trim()) return new Error(value);
  return new Error('device-linking worker failed');
}

function createDefaultEndpoint(): DeviceLinkingWorkerEndpointV1 {
  if (typeof Worker === 'undefined') {
    throw new Error(
      'device-linking worker is unavailable; provide an authenticated worker endpoint',
    );
  }
  const url = resolveWorkerUrl(undefined, { worker: 'deviceLinking' });
  return new Worker(url, { type: 'module' });
}

function assertCanonicalPath(value: string): string {
  if (
    !value.startsWith('/') ||
    value.includes('?') ||
    value.includes('#') ||
    value.trim() !== value
  ) {
    throw new Error('canonicalPath is invalid');
  }
  return value;
}

function assertTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} is invalid`);
  return value;
}

function buildRequest(
  input: Parameters<DeviceLinkingKeyMaterialPortV1['signDeviceSessionRequestV1']>[0],
): DeviceLinkingWorkerRequestV1 {
  const parsedSession = parseLinkDeviceSessionId(input.linkSessionId);
  if (!parsedSession.ok) throw new Error(parsedSession.error.message);
  if (input.method !== 'GET' && input.method !== 'POST') throw new Error('method is invalid');
  const expiresAtMs = assertTimestamp(input.expiresAtMs, 'expiresAtMs');
  const issuedAtMs = assertTimestamp(input.issuedAtMs, 'issuedAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  return {
    kind: 'device_linking_request_sign_v1',
    handleId: nonEmpty(input.handle.handleId, 'handle.handleId'),
    linkSessionId: parsedSession.value,
    method: input.method,
    canonicalPath: assertCanonicalPath(input.canonicalPath),
    bodyDigestB64u: parseDigest(input.bodyDigestB64u, 'bodyDigestB64u'),
    devicePublicKeyDigestB64u: parseDigest(
      input.devicePublicKeyDigestB64u,
      'devicePublicKeyDigestB64u',
    ),
    challengeB64u: parseFixedB64u(input.challengeB64u, 32, 'challengeB64u'),
    issuedAtMs,
    expiresAtMs,
  };
}

/**
 * Creates the browser-side bridge to the device-linking worker. Frames only
 * contain public keys, opaque handles, canonical request fields, and opaque
 * signatures. Private CryptoKeys never leave the worker.
 */
export function createDeviceLinkingKeyMaterialPortV1(
  args: {
    readonly endpoint?: DeviceLinkingWorkerEndpointV1;
    readonly timeoutMs?: number;
  } = {},
): DeviceLinkingWorkerKeyMaterialPortV1 {
  const timeoutMs = normalizeTimeout(args.timeoutMs);
  const pending = new Map<string, PendingRequestV1>();
  let endpoint: DeviceLinkingWorkerEndpointV1 | null = args.endpoint ?? null;
  let closed = false;

  const onMessage = (event: MessageEvent): void => {
    const frame = parseResponseFrame(event.data);
    if (!frame) return;
    const request = pending.get(frame.id);
    if (!request) return;
    clearTimeout(request.timeoutId);
    pending.delete(frame.id);
    if (frame.ok) request.resolve(frame.result);
    else request.reject(new Error(frame.error));
  };
  const onError = (event: ErrorEvent): void => {
    const error = workerError(event.message);
    for (const [id, request] of pending) {
      clearTimeout(request.timeoutId);
      pending.delete(id);
      request.reject(error);
    }
  };
  const bindEndpoint = (nextEndpoint: DeviceLinkingWorkerEndpointV1): void => {
    nextEndpoint.addEventListener('message', onMessage);
    nextEndpoint.addEventListener('error', onError);
    if (args.endpoint) return;
    const presignPort = getWorkerTransport().createLinkedHolderPresignAuthorityPortV1();
    nextEndpoint.postMessage(
      {
        kind: EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign,
        port: presignPort,
      },
      [presignPort],
    );
  };

  if (args.endpoint) {
    bindEndpoint(args.endpoint);
    endpoint = args.endpoint;
  }

  const ensureEndpoint = (): DeviceLinkingWorkerEndpointV1 => {
    if (endpoint) return endpoint;
    const created = createDefaultEndpoint();
    try {
      bindEndpoint(created);
      endpoint = created;
      return created;
    } catch (error) {
      created.terminate();
      throw error;
    }
  };

  const close = (): void => {
    if (closed) return;
    closed = true;
    const currentEndpoint = endpoint;
    currentEndpoint?.removeEventListener('message', onMessage);
    currentEndpoint?.removeEventListener('error', onError);
    const error = new Error('device-linking worker transport is closed');
    for (const [id, request] of pending) {
      clearTimeout(request.timeoutId);
      pending.delete(id);
      request.reject(error);
    }
    currentEndpoint?.terminate();
    endpoint = null;
  };

  const request = (
    input: DeviceLinkingWorkerRequestV1,
    transfer?: Transferable[],
  ): Promise<unknown> => {
    if (closed) return Promise.reject(new Error('device-linking worker transport is closed'));
    let activeEndpoint: DeviceLinkingWorkerEndpointV1;
    try {
      activeEndpoint = ensureEndpoint();
    } catch (error) {
      return Promise.reject(workerError(error));
    }
    const id = requestId();
    return new Promise<unknown>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`device-linking worker request timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timeoutId });
      try {
        activeEndpoint.postMessage({ id, request: input }, transfer);
      } catch (error) {
        clearTimeout(timeoutId);
        pending.delete(id);
        reject(workerError(error));
      }
    });
  };

  const ordinaryMaterial = createDeviceLinkingOrdinaryMaterialWorkerPortV1(request);

  return {
    ...ordinaryMaterial,
    close,
    async createBootstrapKeyMaterialV1() {
      return parseCreateResult(await request({ kind: 'device_linking_key_material_create_v1' }));
    },
    async discardKeyMaterialV1(input) {
      const handle = parseHandle(input.handle);
      await request({ kind: 'device_linking_key_material_discard_v1', handleId: handle.handleId });
    },
    async openAndSealTargetHolderDeliveryV1(input) {
      const handle = parseHandle(input.handle);
      const delivery = parseLinkedDeviceProvisioningChildV1(input.delivery);
      const output = parseSealedHolderResult(
        await request({
          kind: 'device_linking_target_holder_open_seal_v1',
          handleId: handle.handleId,
          delivery,
        }),
      );
      if (
        output.verifiedHolderCiphertextDigestSetB64u !==
        delivery.protocolCommitReceipt.targetHolderCiphertextDigestSetB64u
      ) {
        throw new Error('device-linking worker returned the wrong holder ciphertext digest');
      }
      return output;
    },
    async openPersistedHolderSigningMaterialV1(input) {
      if (!(input.factorSecret instanceof ArrayBuffer) || input.factorSecret.byteLength !== 32) {
        throw new Error('device-linking holder signing factorSecret must be 32 bytes');
      }
      const job = parseRotatableSigningLaneJobV1(
        input.job,
        'device-linking holder signing material job',
      );
      const protocolCommitReceipt = parseLaneProtocolCommitReceiptV1(
        input.protocolCommitReceipt,
        'device-linking holder signing material protocol receipt',
      );
      return parseHolderSigningMaterialHandle(
        await request(
          {
            kind: 'device_linking_holder_signing_material_open_v1',
            factorSecret: input.factorSecret,
            job,
            protocolCommitReceipt,
            materialActivation: parseMaterialActivation(input.materialActivation),
            holderRecord: parseLaneSealedHolderRecordV1(input.holderRecord),
          },
          [input.factorSecret],
        ),
      );
    },
    async openPersistedEmailOtpHolderSigningMaterialsV1(input) {
      const handle = parseHandle(input.keyMaterial);
      const walletId = parseWalletId(input.walletId);
      if (!walletId.ok) throw new Error(walletId.error.message);
      const linkSessionId = parseLinkDeviceSessionId(input.linkSessionId);
      if (!linkSessionId.ok) throw new Error(linkSessionId.error.message);
      const enrollmentId = parseLinkedDeviceEnrollmentId(input.enrollmentId);
      if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
      const deviceId = parseLinkedDeviceId(input.deviceId);
      if (!deviceId.ok) throw new Error(deviceId.error.message);
      if (!Array.isArray(input.orderedChildren) || input.orderedChildren.length === 0) {
        throw new Error('device-linking Email OTP holder signing material batch is empty');
      }
      const orderedChildren: DeviceLinkingEmailOtpHolderSigningMaterialBatchInputV1['orderedChildren'][number][] =
        [];
      for (const child of input.orderedChildren) {
        orderedChildren.push({
          job: parseRotatableSigningLaneJobV1(
            child.job,
            'device-linking Email OTP holder signing material job',
          ),
          protocolCommitReceipt: parseLaneProtocolCommitReceiptV1(
            child.protocolCommitReceipt,
            'device-linking Email OTP holder signing material protocol receipt',
          ),
          materialActivation: parseMaterialActivation(child.materialActivation),
          holderRecord: parseLaneSealedHolderRecordV1(child.holderRecord),
        });
      }
      const first = orderedChildren[0];
      if (!first) {
        throw new Error('device-linking Email OTP holder signing material batch is empty');
      }
      const targetPreparationDigestB64u = parseDigest(
        input.targetPreparationDigestB64u,
        'targetPreparationDigestB64u',
      );
      const parsedChildren = nonEmptyTupleV1(first, orderedChildren.slice(1));
      const result = parseInitialHolderSigningMaterialBatchResult(
        await request({
          kind: 'device_linking_email_otp_holder_signing_material_batch_open_v1',
          handleId: handle.handleId,
          walletId: walletId.value,
          linkSessionId: linkSessionId.value,
          enrollmentId: enrollmentId.value,
          deviceId: deviceId.value,
          targetPreparationDigestB64u,
          orderedChildren: parsedChildren,
        }),
        parsedChildren,
      );
      return {
        handles: result.holderSigningMaterialHandles,
        warmSessionFactorSecret: result.warmSessionFactorSecret,
      };
    },
    async openPersistedEmailOtpHolderSigningMaterialsFromFactorReleaseV1(input) {
      const handle = parseHandle(input.keyMaterial);
      const walletId = parseWalletId(input.walletId);
      if (!walletId.ok) throw new Error(walletId.error.message);
      const enrollmentId = parseLinkedDeviceEnrollmentId(input.enrollmentId);
      if (!enrollmentId.ok) throw new Error(enrollmentId.error.message);
      const expectedChallengeId = nonEmpty(input.expectedChallengeId, 'expectedChallengeId');
      if (!Array.isArray(input.orderedChildren) || input.orderedChildren.length === 0) {
        throw new Error('device-linking Email OTP holder signing material batch is empty');
      }
      const orderedChildren: DeviceLinkingEmailOtpFactorReleaseHolderSigningMaterialBatchInputV1['orderedChildren'][number][] =
        [];
      for (const child of input.orderedChildren) {
        orderedChildren.push({
          job: parseRotatableSigningLaneJobV1(
            child.job,
            'device-linking Email OTP factor release holder signing material job',
          ),
          protocolCommitReceipt: parseLaneProtocolCommitReceiptV1(
            child.protocolCommitReceipt,
            'device-linking Email OTP factor release holder signing material protocol receipt',
          ),
          materialActivation: parseMaterialActivation(child.materialActivation),
          holderRecord: parseLaneSealedHolderRecordV1(child.holderRecord),
        });
      }
      const first = orderedChildren[0];
      if (!first) {
        throw new Error('device-linking Email OTP holder signing material batch is empty');
      }
      const parsedChildren = nonEmptyTupleV1(first, orderedChildren.slice(1));
      const factorRelease = parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(input.factorRelease);
      return parseHolderSigningMaterialBatchResult(
        await request({
          kind: 'device_linking_email_otp_factor_release_holder_signing_material_batch_open_v1',
          handleId: handle.handleId,
          walletId: walletId.value,
          enrollmentId: enrollmentId.value,
          expectedChallengeId,
          factorRelease,
          orderedChildren: parsedChildren,
        }),
        parsedChildren,
      ).holderSigningMaterialHandles;
    },
    async discardHolderSigningMaterialV1(input) {
      const handle = parseHolderSigningMaterialHandleInput(input.handle);
      await request({
        kind: 'device_linking_holder_signing_material_discard_v1',
        handleId: handle.handleId,
      });
    },
    async createEd25519HolderSigningShareV1(input) {
      const handle = parseHolderSigningMaterialHandleInput(input.handle);
      if (handle.keyFamily !== 'ed25519') {
        throw new Error('Ed25519 signing requires an Ed25519 holder handle');
      }
      return parseEd25519SigningShare(
        await request({
          kind: 'device_linking_holder_ed25519_sign_v1',
          handleId: handle.handleId,
          admittedDigestB64u: parseDigest(input.admittedDigestB64u, 'admittedDigestB64u'),
          signingWorkerCommitments: parseCommitments(input.signingWorkerCommitments),
          signingWorkerVerifyingShareB64u: parseFixedB64u(
            input.signingWorkerVerifyingShareB64u,
            32,
            'signingWorkerVerifyingShareB64u',
          ),
        }),
      );
    },
    async prepareEcdsaExportRecipientV1(input) {
      const handle = parseHolderSigningMaterialHandleInput(input.handle);
      if (handle.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('ECDSA export requires an ECDSA holder handle');
      }
      return parseEcdsaExportRecipient(
        await request({
          kind: 'device_linking_holder_ecdsa_export_recipient_prepare_v1',
          handleId: handle.handleId,
          operationId: nonEmpty(input.operationId, 'operationId'),
        }),
      );
    },
    async finalizeEcdsaExportV1(input) {
      const handle = parseHolderSigningMaterialHandleInput(input.handle);
      if (handle.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('ECDSA export requires an ECDSA holder handle');
      }
      const signingWorkerExport = parseRouterAbEcdsaSigningWorkerExportShareEnvelopeV1(
        input.signingWorkerExport,
      );
      return parseEcdsaExportArtifact(
        await request({
          kind: 'device_linking_holder_ecdsa_export_finalize_v1',
          handleId: handle.handleId,
          recipientHandleId: nonEmpty(input.recipientHandleId, 'recipientHandleId'),
          signingWorkerExport,
          expectedBinding: input.expectedBinding,
          expectedPublicFacts: input.expectedPublicFacts,
        }),
      );
    },
    async signDeviceSessionRequestV1(input) {
      const requestInput = buildRequest(input);
      return parseSignatureResult(await request(requestInput));
    },
  };
}

/** Builds the exact bytes used by the worker before Ed25519 signing. */
export function encodeDeviceLinkingRequestForWorkerV1(input: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly bodyDigestB64u: DigestB64u;
  readonly method: 'GET' | 'POST';
  readonly canonicalPath: string;
  readonly challengeB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Uint8Array {
  const zeroSignature = new Uint8Array(64);
  const proof: LinkedDeviceRequestProofV1 = {
    kind: 'linked_device_request_proof_v1',
    linkSessionId: input.linkSessionId,
    devicePublicKeyDigestB64u: input.devicePublicKeyDigestB64u,
    requestNonceB64u: input.challengeB64u,
    method: input.method,
    canonicalPath: input.canonicalPath,
    bodyDigestB64u: input.bodyDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    signatureB64u: base64UrlEncode(zeroSignature),
  };
  const encoded = encodeLinkedDeviceRequestProofV1(proof);
  zeroSignature.fill(0);
  return encoded;
}
