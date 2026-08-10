import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '../signing-lanes/ids';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { sha256Bytes } from '../utils/digests';
import type { LinkDevicePublicKeyB64u } from './contracts';

export const LINKED_DEVICE_REQUEST_PROOF_DOMAIN_V1 = 'seams/linked-device/request-proof/v1';
export const LINKED_DEVICE_REQUEST_PROOF_HEADER_V1 = 'x-seams-linked-device-proof-v1';
export const LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1 = 60_000;
export const LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1 = 32;
export const LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1 = 64;
export const LINK_DEVICE_PUBLIC_KEY_BYTES_V1 = 32;

export type LinkedDeviceRequestProofV1 = {
  readonly kind: 'linked_device_request_proof_v1';
  readonly linkSessionId: LinkDeviceSessionId;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly requestNonceB64u: string;
  readonly method: 'GET' | 'POST';
  readonly canonicalPath: string;
  readonly bodyDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly signatureB64u: string;
};

export function encodeLinkedDeviceRequestProofV1(proof: LinkedDeviceRequestProofV1): Uint8Array {
  validateProofShapeV1(proof);
  return concat([
    text(LINKED_DEVICE_REQUEST_PROOF_DOMAIN_V1, 'domain'),
    text(proof.kind, 'kind'),
    text(proof.linkSessionId, 'linkSessionId'),
    rawDigest(proof.devicePublicKeyDigestB64u, 'devicePublicKeyDigestB64u'),
    lp32(
      parseFixedB64u(
        proof.requestNonceB64u,
        LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
        'requestNonceB64u',
      ),
      'requestNonceB64u',
    ),
    text(proof.method, 'method'),
    text(proof.canonicalPath, 'canonicalPath'),
    rawDigest(proof.bodyDigestB64u, 'bodyDigestB64u'),
    u64(proof.issuedAtMs, 'issuedAtMs'),
    u64(proof.expiresAtMs, 'expiresAtMs'),
  ]);
}

export async function computeLinkedDeviceRequestProofDigestV1(
  proof: LinkedDeviceRequestProofV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(await sha256Bytes(encodeLinkedDeviceRequestProofV1(proof))),
  );
}

export async function computeLinkedDevicePublicKeyDigestV1(
  publicKeyB64u: LinkDevicePublicKeyB64u | string,
): Promise<DigestB64u> {
  const publicKeyBytes = parseFixedB64u(
    publicKeyB64u,
    LINK_DEVICE_PUBLIC_KEY_BYTES_V1,
    'devicePublicKeyB64u',
  );
  return parseDigestB64u(base64UrlEncode(await sha256Bytes(publicKeyBytes)));
}

function validateProofShapeV1(proof: LinkedDeviceRequestProofV1): void {
  if (proof.kind !== 'linked_device_request_proof_v1') {
    throw new Error('request proof kind is invalid');
  }
  const parsedSessionId = parseLinkDeviceSessionId(proof.linkSessionId);
  if (!parsedSessionId.ok) throw new Error(parsedSessionId.error.message);
  parseDigestField(proof.devicePublicKeyDigestB64u, 'devicePublicKeyDigestB64u');
  parseFixedB64u(
    proof.requestNonceB64u,
    LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
    'requestNonceB64u',
  );
  if (proof.method !== 'GET' && proof.method !== 'POST') {
    throw new Error('request proof method is invalid');
  }
  parseCanonicalPath(proof.canonicalPath);
  parseDigestField(proof.bodyDigestB64u, 'bodyDigestB64u');
  parseTimestamp(proof.issuedAtMs, 'issuedAtMs');
  parseTimestamp(proof.expiresAtMs, 'expiresAtMs');
  if (proof.expiresAtMs <= proof.issuedAtMs) {
    throw new Error('expiresAtMs must be after issuedAtMs');
  }
  if (proof.expiresAtMs - proof.issuedAtMs > LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1) {
    throw new Error('request proof lifetime exceeds the maximum');
  }
  parseFixedB64u(
    proof.signatureB64u,
    LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
    'signatureB64u',
  );
}

function parseDigestField(value: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(value);
  } catch {
    throw new Error(`${label} is invalid`);
  }
}

function parseCanonicalPath(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error('canonicalPath is invalid');
  }
  if (!value.startsWith('/') || value.includes('?') || value.includes('#')) {
    throw new Error('canonicalPath is invalid');
  }
  return value;
}

function parseTimestamp(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} is invalid`);
  }
  return Number(value);
}

function parseFixedB64u(value: unknown, expectedBytes: number, label: string): Uint8Array {
  if (typeof value !== 'string' || value.length === 0 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error(`${label} is invalid`);
  }
  if (bytes.length !== expectedBytes || base64UrlEncode(bytes) !== value) {
    throw new Error(`${label} is invalid`);
  }
  return bytes;
}

function rawDigest(value: DigestB64u, label: string): Uint8Array {
  return lp32(base64UrlDecode(parseDigestField(value, label)), label);
}

function text(value: string, label: string): Uint8Array {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  return lp32(new TextEncoder().encode(value), label);
}

function u32(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`${label} must be a u32`);
  }
  return Uint8Array.from([
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ]);
}

function u64(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`${label} must be a u64`);
  let remaining = BigInt(value);
  const bytes = new Uint8Array(8);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

function lp32(value: Uint8Array, label: string): Uint8Array {
  return concat([u32(value.length, `${label}.length`), value]);
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((length, part) => length + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}
