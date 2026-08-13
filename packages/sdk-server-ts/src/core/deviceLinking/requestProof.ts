import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  computeLinkedDevicePublicKeyDigestV1,
  computeLinkedDeviceRequestProofDigestV1,
  encodeLinkedDeviceRequestProofV1,
  LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
  LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
  LINK_DEVICE_PUBLIC_KEY_BYTES_V1,
  type LinkedDeviceRequestProofV1,
} from '@shared/device-linking/requestProof';

export {
  computeLinkedDevicePublicKeyDigestV1,
  computeLinkedDeviceRequestProofDigestV1,
  encodeLinkedDeviceRequestProofV1,
  LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1,
  LINKED_DEVICE_REQUEST_PROOF_HEADER_V1,
  LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1,
  type LinkedDeviceRequestProofV1,
} from '@shared/device-linking/requestProof';

export type LinkedDeviceRequestProofVerificationInputV1 = {
  readonly proof: LinkedDeviceRequestProofV1;
  readonly expectedDevicePublicKeyB64u: string;
  readonly expectedDevicePublicKeyDigestB64u: DigestB64u;
  readonly expectedLinkSessionId: LinkDeviceSessionId;
  readonly expectedMethod: string;
  readonly expectedCanonicalPath: string;
  readonly expectedBodyDigestB64u: DigestB64u;
  readonly nowMs: number;
};

export type LinkedDeviceRequestProofNonceStoreV1 = {
  consumeRequestProofNonceV1(input: {
    readonly linkSessionId: LinkDeviceSessionId;
    readonly requestNonceB64u: string;
    readonly proofDigestB64u: DigestB64u;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly consumedAtMs: number;
  }): Promise<{ readonly outcome: 'consumed' } | { readonly outcome: 'already_used' }>;
};

export type LinkedDeviceRequestProofVerificationResultV1 =
  | {
      readonly kind: 'authorized';
      readonly proofDigestB64u: DigestB64u;
    }
  | {
      readonly kind: 'denied';
      readonly code: 'invalid' | 'expired' | 'replayed';
      readonly message: string;
    };

export class LinkedDeviceRequestProofVerifierV1 {
  private readonly nonceStore: LinkedDeviceRequestProofNonceStoreV1;

  constructor(input: { readonly nonceStore: LinkedDeviceRequestProofNonceStoreV1 }) {
    this.nonceStore = input.nonceStore;
  }

  async verifyV1(
    input: LinkedDeviceRequestProofVerificationInputV1,
  ): Promise<LinkedDeviceRequestProofVerificationResultV1> {
    try {
      validateRequestProofBindingV1(input);
      const expectedDevicePublicKeyDigestB64u = await computeLinkedDevicePublicKeyDigestV1(
        input.expectedDevicePublicKeyB64u,
      );
      if (
        !constantTimeEqualDigestV1(
          expectedDevicePublicKeyDigestB64u,
          input.expectedDevicePublicKeyDigestB64u,
        )
      ) {
        return {
          kind: 'denied',
          code: 'invalid',
          message: 'device request proof key digest is invalid',
        };
      }
      const canonicalPayload = encodeLinkedDeviceRequestProofV1(input.proof);
      const proofDigestB64u = await computeLinkedDeviceRequestProofDigestV1(input.proof);
      if (
        !(await verifyEd25519SignatureV1(
          input.expectedDevicePublicKeyB64u,
          input.proof.signatureB64u,
          canonicalPayload,
        ))
      ) {
        return {
          kind: 'denied',
          code: 'invalid',
          message: 'device request proof signature is invalid',
        };
      }
      const consumed = await this.nonceStore.consumeRequestProofNonceV1({
        linkSessionId: input.proof.linkSessionId,
        requestNonceB64u: input.proof.requestNonceB64u,
        proofDigestB64u,
        issuedAtMs: input.proof.issuedAtMs,
        expiresAtMs: input.proof.expiresAtMs,
        consumedAtMs: input.nowMs,
      });
      if (consumed.outcome === 'already_used') {
        return {
          kind: 'denied',
          code: 'replayed',
          message: 'device request proof was already used',
        };
      }
      return { kind: 'authorized', proofDigestB64u };
    } catch (error: unknown) {
      const message = errorMessage(error);
      return {
        kind: 'denied',
        code:
          message.includes('expired') ||
          message.includes('not yet valid') ||
          message.includes('lifetime exceeds')
            ? 'expired'
            : 'invalid',
        message,
      };
    }
  }

  async verifyPublicCreateV1(input: {
    readonly proof: LinkedDeviceRequestProofV1;
    readonly devicePublicKeyB64u: string;
    readonly devicePublicKeyDigestB64u: DigestB64u;
    readonly linkSessionId: LinkDeviceSessionId;
    readonly method: string;
    readonly canonicalPath: string;
    readonly bodyDigestB64u: DigestB64u;
    readonly nowMs: number;
  }): Promise<LinkedDeviceRequestProofVerificationResultV1> {
    return await this.verifyV1({
      proof: input.proof,
      expectedDevicePublicKeyB64u: input.devicePublicKeyB64u,
      expectedDevicePublicKeyDigestB64u: input.devicePublicKeyDigestB64u,
      expectedLinkSessionId: input.linkSessionId,
      expectedMethod: input.method,
      expectedCanonicalPath: input.canonicalPath,
      expectedBodyDigestB64u: input.bodyDigestB64u,
      nowMs: input.nowMs,
    });
  }
}

export function parseLinkedDeviceRequestProofV1(raw: unknown): LinkedDeviceRequestProofV1 {
  const record = requireRecord(raw, 'linked-device request proof');
  requireExactKeys(record, [
    'kind',
    'linkSessionId',
    'devicePublicKeyDigestB64u',
    'requestNonceB64u',
    'method',
    'canonicalPath',
    'bodyDigestB64u',
    'issuedAtMs',
    'expiresAtMs',
    'signatureB64u',
  ]);
  if (record.kind !== 'linked_device_request_proof_v1') {
    throw new Error('linked-device request proof kind is invalid');
  }
  const linkSessionId = parseSessionId(record.linkSessionId);
  const devicePublicKeyDigestB64u = parseDigestField(
    record.devicePublicKeyDigestB64u,
    'devicePublicKeyDigestB64u',
  );
  const requestNonceB64u = parseFixedB64u(
    record.requestNonceB64u,
    LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
    'requestNonceB64u',
  );
  const method = parseMethod(record.method);
  const canonicalPath = parseCanonicalPath(record.canonicalPath);
  const bodyDigestB64u = parseDigestField(record.bodyDigestB64u, 'bodyDigestB64u');
  const issuedAtMs = parseTimestamp(record.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = parseTimestamp(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  const signatureB64u = parseFixedB64u(
    record.signatureB64u,
    LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
    'signatureB64u',
  );
  return {
    kind: 'linked_device_request_proof_v1',
    linkSessionId,
    devicePublicKeyDigestB64u,
    requestNonceB64u,
    method,
    canonicalPath,
    bodyDigestB64u,
    issuedAtMs,
    expiresAtMs,
    signatureB64u,
  };
}

function validateRequestProofBindingV1(input: LinkedDeviceRequestProofVerificationInputV1): void {
  validateProofShapeV1(input.proof);
  if (input.proof.linkSessionId !== input.expectedLinkSessionId) {
    throw new Error('request proof link session does not match');
  }
  if (input.proof.method !== input.expectedMethod)
    throw new Error('request proof method does not match');
  if (input.proof.canonicalPath !== input.expectedCanonicalPath) {
    throw new Error('request proof canonical path does not match');
  }
  if (!constantTimeEqualDigestV1(input.proof.bodyDigestB64u, input.expectedBodyDigestB64u)) {
    throw new Error('request proof body digest does not match');
  }
  if (
    !constantTimeEqualDigestV1(
      input.proof.devicePublicKeyDigestB64u,
      input.expectedDevicePublicKeyDigestB64u,
    )
  ) {
    throw new Error('request proof device identity digest does not match');
  }
  if (
    !Number.isSafeInteger(input.nowMs) ||
    input.proof.issuedAtMs - input.nowMs > LINKED_DEVICE_CLOCK_SKEW_TOLERANCE_MS_V1
  ) {
    throw new Error('request proof is not yet valid');
  }
  if (input.nowMs >= input.proof.expiresAtMs) throw new Error('request proof is expired');
  if (
    input.proof.expiresAtMs - input.proof.issuedAtMs >
    LINKED_DEVICE_REQUEST_PROOF_MAX_TTL_MS_V1
  ) {
    throw new Error('request proof lifetime exceeds the maximum');
  }
}

async function verifyEd25519SignatureV1(
  publicKeyB64u: string,
  signatureB64u: string,
  canonicalPayload: Uint8Array,
): Promise<boolean> {
  const publicKey = parseFixedB64u(
    publicKeyB64u,
    LINK_DEVICE_PUBLIC_KEY_BYTES_V1,
    'devicePublicKeyB64u',
  );
  const signature = parseFixedB64u(
    signatureB64u,
    LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
    'signatureB64u',
  );
  const key = await crypto.subtle.importKey(
    'raw',
    toArrayBuffer(base64UrlDecode(publicKey)),
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  return await crypto.subtle.verify(
    { name: 'Ed25519' },
    key,
    toArrayBuffer(base64UrlDecode(signature)),
    toArrayBuffer(canonicalPayload),
  );
}

function validateProofShapeV1(proof: LinkedDeviceRequestProofV1): void {
  if (proof.kind !== 'linked_device_request_proof_v1')
    throw new Error('request proof kind is invalid');
  parseSessionId(proof.linkSessionId);
  parseDigestField(proof.devicePublicKeyDigestB64u, 'devicePublicKeyDigestB64u');
  parseFixedB64u(
    proof.requestNonceB64u,
    LINKED_DEVICE_REQUEST_PROOF_NONCE_BYTES_V1,
    'requestNonceB64u',
  );
  if (proof.method !== 'GET' && proof.method !== 'POST')
    throw new Error('request proof method is invalid');
  parseCanonicalPath(proof.canonicalPath);
  parseDigestField(proof.bodyDigestB64u, 'bodyDigestB64u');
  parseTimestamp(proof.issuedAtMs, 'issuedAtMs');
  parseTimestamp(proof.expiresAtMs, 'expiresAtMs');
  if (proof.expiresAtMs <= proof.issuedAtMs) {
    throw new Error('expiresAtMs must be after issuedAtMs');
  }
  parseFixedB64u(
    proof.signatureB64u,
    LINKED_DEVICE_REQUEST_PROOF_SIGNATURE_BYTES_V1,
    'signatureB64u',
  );
}

function parseSessionId(raw: unknown): LinkDeviceSessionId {
  if (typeof raw !== 'string') throw new Error('linkSessionId is invalid');
  const parsed = parseLinkDeviceSessionId(raw);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseMethod(raw: unknown): 'GET' | 'POST' {
  if (raw !== 'GET' && raw !== 'POST') throw new Error('method is invalid');
  return raw;
}

function parseCanonicalPath(raw: unknown): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw || !raw.startsWith('/')) {
    throw new Error('canonicalPath is invalid');
  }
  if (raw.includes('?') || raw.includes('#')) throw new Error('canonicalPath must be a pathname');
  return raw;
}

function parseTimestamp(raw: unknown, field: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0) throw new Error(`${field} is invalid`);
  return Number(raw);
}

function parseDigestField(raw: unknown, field: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch {
    throw new Error(`${field} is invalid`);
  }
}

function parseFixedB64u(raw: unknown, expectedBytes: number, field: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${field} is invalid`);
  }
  const bytes = base64UrlDecode(raw);
  if (bytes.length !== expectedBytes || base64UrlEncode(bytes) !== raw) {
    throw new Error(`${field} is invalid`);
  }
  return raw;
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function requireRecord(raw: unknown, field: string): Record<string, unknown> {
  if (!isRecord(raw)) throw new Error(`${field} must be an object`);
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return raw !== null && typeof raw === 'object' && !Array.isArray(raw);
}

function requireExactKeys(record: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error('record contains invalid fields');
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || 'invalid device request proof');
}

function constantTimeEqualDigestV1(left: DigestB64u, right: DigestB64u): boolean {
  const leftBytes = base64UrlDecode(left);
  const rightBytes = base64UrlDecode(right);
  if (leftBytes.length !== rightBytes.length) return false;
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}
