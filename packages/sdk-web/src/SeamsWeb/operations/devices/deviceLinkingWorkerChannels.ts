import {
  encodeLinkedDeviceRequestProofV1,
  parseLinkedDeviceProvisioningChildV1,
  parseLinkedDeviceTargetPreparationV1,
  parseLinkedDeviceTargetCredentialRegistrationV1,
  parseLinkDevicePublicKeyB64u,
  type LinkedDeviceTargetHolderRegistrationV1,
  type LinkedDeviceProvisioningChildV1,
  type LinkedDeviceTargetPreparationV1,
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
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import {
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import { resolveWorkerUrl } from '@/core/walletRuntimePaths';
import {
  parseLaneSealedHolderRecordV1,
  type LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  DeviceLinkingEd25519SigningShareV1,
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
  DeviceLinkingKeyMaterialHandleV1,
  DeviceLinkingKeyMaterialPortV1,
  DeviceLinkingKeyMaterialBundleV1,
} from './deviceLinkingPorts';
import { EcdsaClientWorkerControlKind } from '@/core/signingEngine/workerManager/ecdsaClientWorkerChannels';

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
  };

type DeviceLinkingWorkerRequestV1 =
  | { readonly kind: 'device_linking_key_material_create_v1' }
  | {
      readonly kind: 'device_linking_target_holder_open_seal_v1';
      readonly handleId: string;
      readonly delivery: LinkedDeviceProvisioningChildV1;
    }
  | {
      readonly kind: 'device_linking_target_holders_prepare_v1';
      readonly handleId: string;
      readonly preparation: LinkedDeviceTargetPreparationV1;
      readonly credentialIdB64u: string;
      readonly factorSecret: ArrayBuffer;
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
    ['handleId', 'linkPublicKeyB64u', 'devicePublicKeyB64u'],
    'device-linking key create response',
  );
  return {
    handle: {
      kind: 'device_linking_key_material_handle_v1',
      handleId: nonEmpty(record.handleId, 'device-linking key create handleId'),
    },
    linkPublicKeyB64u: parseLinkDevicePublicKeyB64u(record.linkPublicKeyB64u),
    devicePublicKeyB64u: parseLinkDevicePublicKeyB64u(record.devicePublicKeyB64u),
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

function parseTargetHolderResult(
  value: unknown,
  preparation: LinkedDeviceTargetPreparationV1,
  credentialIdB64u: string,
): {
  readonly orderedHolderRegistrations: readonly [
    LinkedDeviceTargetHolderRegistrationV1,
    ...LinkedDeviceTargetHolderRegistrationV1[],
  ];
} {
  const record = exactRecord(
    value,
    ['orderedHolderRegistrations'],
    'device-linking target holder response',
  );
  const registration = parseLinkedDeviceTargetCredentialRegistrationV1({
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId: preparation.linkSessionId,
    walletId: preparation.walletId,
    enrollmentId: preparation.enrollmentId,
    deviceId: preparation.deviceId,
    targetPreparationDigestB64u: base64UrlEncode(new Uint8Array(32)),
    webauthnRegistration: {
      kind: 'linked_device_webauthn_registration_v1',
      credentialIdB64u,
      authenticatorAttachment: null,
      clientDataJsonB64u: base64UrlEncode(new Uint8Array([1])),
      attestationObjectB64u: base64UrlEncode(new Uint8Array([1])),
      transports: [],
    },
    orderedHolderRegistrations: record.orderedHolderRegistrations,
    registeredAtMs: 1,
  });
  if (registration.orderedHolderRegistrations.length !== preparation.orderedChildren.length) {
    throw new Error('device-linking worker returned the wrong holder child count');
  }
  for (let index = 0; index < preparation.orderedChildren.length; index += 1) {
    const child = preparation.orderedChildren[index];
    const holder = registration.orderedHolderRegistrations[index];
    if (
      !child ||
      !holder ||
      holder.operationId !== child.operationId ||
      holder.walletKeyId !== child.walletKeyId ||
      holder.keyFamily !== child.keyFamily ||
      holder.targetLaneId !== child.targetLaneId ||
      holder.targetLaneShareEpoch !== child.targetLaneShareEpoch ||
      holder.targetMaterialActivationId !== child.targetMaterialActivationId ||
      holder.holderParticipant.participantId !== child.targetHolderParticipantId
    ) {
      throw new Error('device-linking worker changed an admitted holder child');
    }
  }
  return { orderedHolderRegistrations: registration.orderedHolderRegistrations };
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
  const endpoint = args.endpoint ?? createDefaultEndpoint();
  const timeoutMs = normalizeTimeout(args.timeoutMs);
  const pending = new Map<string, PendingRequestV1>();
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
  endpoint.addEventListener('message', onMessage);
  endpoint.addEventListener('error', onError);

  const close = (): void => {
    if (closed) return;
    closed = true;
    endpoint.removeEventListener('message', onMessage);
    endpoint.removeEventListener('error', onError);
    const error = new Error('device-linking worker transport is closed');
    for (const [id, request] of pending) {
      clearTimeout(request.timeoutId);
      pending.delete(id);
      request.reject(error);
    }
    endpoint.terminate();
  };

  const request = (
    input: DeviceLinkingWorkerRequestV1,
    transfer?: Transferable[],
  ): Promise<unknown> => {
    if (closed) return Promise.reject(new Error('device-linking worker transport is closed'));
    const id = requestId();
    return new Promise<unknown>((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`device-linking worker request timed out after ${timeoutMs}ms`));
      }, timeoutMs);
      pending.set(id, { resolve, reject, timeoutId });
      try {
        endpoint.postMessage({ id, request: input }, transfer);
      } catch (error) {
        clearTimeout(timeoutId);
        pending.delete(id);
        reject(workerError(error));
      }
    });
  };

  return {
    close,
    attachEcdsaPresignPortV1(port) {
      if (closed) throw new Error('device-linking worker transport is closed');
      endpoint.postMessage(
        {
          kind: EcdsaClientWorkerControlKind.AttachLinkedHolderToPresign,
          port,
        },
        [port],
      );
    },
    async createBootstrapKeyMaterialV1() {
      return parseCreateResult(await request({ kind: 'device_linking_key_material_create_v1' }));
    },
    async discardKeyMaterialV1(input) {
      const handle = parseHandle(input.handle);
      await request({ kind: 'device_linking_key_material_discard_v1', handleId: handle.handleId });
    },
    async prepareTargetHolderRegistrationsV1(input) {
      const handle = parseHandle(input.handle);
      const preparation = parseLinkedDeviceTargetPreparationV1(input.preparation);
      if (!(input.factorSecret instanceof ArrayBuffer) || input.factorSecret.byteLength !== 32) {
        throw new Error('device-linking target holder factorSecret must be 32 bytes');
      }
      return parseTargetHolderResult(
        await request(
          {
            kind: 'device_linking_target_holders_prepare_v1',
            handleId: handle.handleId,
            preparation,
            credentialIdB64u: input.credentialIdB64u,
            factorSecret: input.factorSecret,
          },
          [input.factorSecret],
        ),
        preparation,
        input.credentialIdB64u,
      );
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
