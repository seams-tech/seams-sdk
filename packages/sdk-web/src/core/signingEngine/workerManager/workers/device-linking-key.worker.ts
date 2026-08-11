import {
  encodeLinkedDeviceRequestProofV1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
  parseLinkDevicePublicKeyB64u,
  type LinkedDeviceRequestProofV1,
  type LinkDevicePublicKeyB64u,
} from '@shared/device-linking';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';

/**
 * The worker is the only owner of these key objects. The browser receives
 * public bytes and an opaque slot id; private CryptoKeys are non-extractable
 * and never appear in a structured-clone message.
 */
type DeviceLinkingKeySlotV1 = {
  readonly identityPrivateKey: CryptoKey;
  readonly linkPrivateKey: CryptoKey;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
};

type DeviceLinkingKeyWorkerRequestV1 =
  | { readonly kind: 'device_linking_key_material_create_v1' }
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

type DeviceLinkingKeyWorkerResponseV1 =
  | {
      readonly handleId: string;
      readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
      readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
    }
  | { readonly signatureB64u: string };

type DeviceLinkingKeyWorkerFrameV1 = {
  readonly id: string;
  readonly request: unknown;
};

export type DeviceLinkingKeyWorkerScopeV1 = {
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  removeEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
};

export type InstalledDeviceLinkingKeyWorkerV1 = {
  close(): void;
};

const keySlots = new Map<string, DeviceLinkingKeySlotV1>();

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

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function parseHandleId(value: unknown): string {
  const handleId = requireNonEmptyString(value, 'handleId');
  if (handleId.length > 256) throw new Error('handleId is too long');
  return handleId;
}

function createHandleId(): string {
  if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function') {
    throw new Error('secure randomness is unavailable for device-linking worker');
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(24));
  const handleId = `device-linking-key-${base64UrlEncode(bytes)}`;
  bytes.fill(0);
  return handleId;
}

function parseFixedBase64Url(value: unknown, length: number, label: string): string {
  const encoded = requireNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw new Error(`${label} is invalid`);
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(encoded);
  } catch {
    throw new Error(`${label} is invalid`);
  }
  if (bytes.length !== length || base64UrlEncode(bytes) !== encoded) {
    bytes.fill(0);
    throw new Error(`${label} must be canonical base64url`);
  }
  bytes.fill(0);
  return encoded;
}

function parseDigest(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parseSessionId(value: unknown): LinkDeviceSessionId {
  const parsed = parseLinkDeviceSessionId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseCanonicalPath(value: unknown): string {
  const path = requireNonEmptyString(value, 'canonicalPath');
  if (!path.startsWith('/') || path.includes('?') || path.includes('#')) {
    throw new Error('canonicalPath is invalid');
  }
  return path;
}

function parseTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} is invalid`);
  }
  return Number(value);
}

function parseSignRequest(value: unknown): {
  readonly handleId: string;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly method: 'GET' | 'POST';
  readonly canonicalPath: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly challengeB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
} {
  const record = exactRecord(
    value,
    [
      'kind',
      'handleId',
      'linkSessionId',
      'method',
      'canonicalPath',
      'bodyDigestB64u',
      'devicePublicKeyDigestB64u',
      'challengeB64u',
      'issuedAtMs',
      'expiresAtMs',
    ],
    'device-linking sign request',
  );
  if (record.kind !== 'device_linking_request_sign_v1') {
    throw new Error('device-linking sign request kind is invalid');
  }
  const issuedAtMs = parseTimestamp(record.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = parseTimestamp(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  if (expiresAtMs - issuedAtMs > LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1) {
    throw new Error('request proof lifetime exceeds the maximum');
  }
  if (record.method !== 'GET' && record.method !== 'POST') throw new Error('method is invalid');
  return {
    handleId: parseHandleId(record.handleId),
    linkSessionId: parseSessionId(record.linkSessionId),
    method: record.method,
    canonicalPath: parseCanonicalPath(record.canonicalPath),
    bodyDigestB64u: parseDigest(record.bodyDigestB64u, 'bodyDigestB64u'),
    devicePublicKeyDigestB64u: parseDigest(
      record.devicePublicKeyDigestB64u,
      'devicePublicKeyDigestB64u',
    ),
    challengeB64u: parseFixedBase64Url(
      record.challengeB64u,
      LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
      'challengeB64u',
    ),
    issuedAtMs,
    expiresAtMs,
  };
}

function requireCryptoKeyPair(value: CryptoKey | CryptoKeyPair, label: string): CryptoKeyPair {
  if (
    typeof value !== 'object' ||
    value === null ||
    !('publicKey' in value) ||
    !('privateKey' in value)
  ) {
    throw new Error(`${label} did not produce a key pair`);
  }
  return value;
}

function parseFrame(value: unknown): DeviceLinkingKeyWorkerFrameV1 {
  const frame = exactRecord(value, ['id', 'request'], 'device-linking worker frame');
  return {
    id: requireNonEmptyString(frame.id, 'device-linking worker frame.id'),
    request: frame.request,
  };
}

function parseRequest(value: unknown): DeviceLinkingKeyWorkerRequestV1 {
  const record = requireRecord(value, 'device-linking worker request');
  if (record.kind === 'device_linking_key_material_create_v1') {
    exactRecord(record, ['kind'], 'device-linking create request');
    return { kind: 'device_linking_key_material_create_v1' };
  }
  if (record.kind === 'device_linking_key_material_discard_v1') {
    const parsed = exactRecord(record, ['kind', 'handleId'], 'device-linking discard request');
    return {
      kind: 'device_linking_key_material_discard_v1',
      handleId: parseHandleId(parsed.handleId),
    };
  }
  if (record.kind === 'device_linking_request_sign_v1') {
    const parsed = parseSignRequest(record);
    return { kind: 'device_linking_request_sign_v1', ...parsed };
  }
  throw new Error('device-linking worker request kind is unsupported');
}

async function generateKeySlot(): Promise<{
  readonly slot: DeviceLinkingKeySlotV1;
  readonly result: Extract<DeviceLinkingKeyWorkerResponseV1, { readonly handleId: string }>;
}> {
  const identityPair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']),
    'Ed25519 identity',
  );
  const linkPair = requireCryptoKeyPair(
    await globalThis.crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']),
    'X25519 link',
  );
  const identityPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', identityPair.publicKey),
  );
  const linkPublicBytes = new Uint8Array(
    await globalThis.crypto.subtle.exportKey('raw', linkPair.publicKey),
  );
  try {
    if (identityPublicBytes.length !== 32 || linkPublicBytes.length !== 32) {
      throw new Error('device-linking worker returned an invalid public key length');
    }
    const devicePublicKeyB64u = parseLinkDevicePublicKeyB64u(
      base64UrlEncode(identityPublicBytes),
    );
    const linkPublicKeyB64u = parseLinkDevicePublicKeyB64u(base64UrlEncode(linkPublicBytes));
    const handleId = createHandleId();
    const slot: DeviceLinkingKeySlotV1 = {
      identityPrivateKey: identityPair.privateKey,
      linkPrivateKey: linkPair.privateKey,
      devicePublicKeyB64u,
      linkPublicKeyB64u,
    };
    return {
      slot,
      result: { handleId, linkPublicKeyB64u, devicePublicKeyB64u },
    };
  } finally {
    identityPublicBytes.fill(0);
    linkPublicBytes.fill(0);
  }
}

async function signRequest(
  request: Extract<DeviceLinkingKeyWorkerRequestV1, { readonly kind: 'device_linking_request_sign_v1' }>,
): Promise<{ readonly signatureB64u: string }> {
  const slot = keySlots.get(request.handleId);
  if (!slot) throw new Error('device-linking key handle is unknown or discarded');
  const zeroSignature = new Uint8Array(LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1);
  const proof: LinkedDeviceRequestProofV1 = {
    kind: 'linked_device_request_proof_v1',
    linkSessionId: request.linkSessionId,
    devicePublicKeyDigestB64u: request.devicePublicKeyDigestB64u,
    requestNonceB64u: request.challengeB64u,
    method: request.method,
    canonicalPath: request.canonicalPath,
    bodyDigestB64u: request.bodyDigestB64u,
    issuedAtMs: request.issuedAtMs,
    expiresAtMs: request.expiresAtMs,
    signatureB64u: base64UrlEncode(zeroSignature),
  };
  let canonicalBytes: Uint8Array | undefined;
  let signatureBytes: Uint8Array | undefined;
  try {
    canonicalBytes = encodeLinkedDeviceRequestProofV1(proof);
    signatureBytes = new Uint8Array(
      await globalThis.crypto.subtle.sign('Ed25519', slot.identityPrivateKey, canonicalBytes),
    );
    if (signatureBytes.length !== LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1) {
      throw new Error('device-linking worker returned an invalid signature length');
    }
    return { signatureB64u: base64UrlEncode(signatureBytes) };
  } finally {
    zeroSignature.fill(0);
    canonicalBytes?.fill(0);
    signatureBytes?.fill(0);
  }
}

async function handleRequest(
  rawRequest: unknown,
): Promise<DeviceLinkingKeyWorkerResponseV1 | undefined> {
  const request = parseRequest(rawRequest);
  switch (request.kind) {
    case 'device_linking_key_material_create_v1': {
      const generated = await generateKeySlot();
      keySlots.set(generated.result.handleId, generated.slot);
      return generated.result;
    }
    case 'device_linking_request_sign_v1':
      return await signRequest(request);
    case 'device_linking_key_material_discard_v1':
      keySlots.delete(request.handleId);
      return undefined;
    default:
      request satisfies never;
      throw new Error('device-linking worker request kind is unsupported');
  }
}

function workerError(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === 'string' && error.trim()) return error;
  return 'device-linking worker request failed';
}

export function installDeviceLinkingKeyWorkerV1(
  scope: DeviceLinkingKeyWorkerScopeV1,
): InstalledDeviceLinkingKeyWorkerV1 {
  let closed = false;
  let queue: Promise<void> = Promise.resolve();
  const onMessage = (event: MessageEvent): void => {
    queue = queue
      .catch(() => undefined)
      .then(async () => {
        if (closed) return;
        let id: string | undefined;
        try {
          const frame = parseFrame(event.data);
          id = frame.id;
          const result = await handleRequest(frame.request);
          scope.postMessage({ id, ok: true, result });
        } catch (error) {
          if (id) scope.postMessage({ id, ok: false, error: workerError(error) });
        }
      });
  };
  scope.addEventListener('message', onMessage);
  return {
    close(): void {
      if (closed) return;
      closed = true;
      scope.removeEventListener('message', onMessage);
      keySlots.clear();
    },
  };
}

if (typeof self !== 'undefined') {
  installDeviceLinkingKeyWorkerV1(self);
}
