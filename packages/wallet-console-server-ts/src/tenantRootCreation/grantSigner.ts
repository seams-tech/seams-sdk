import { base64UrlDecode, base64UrlEncode } from '@seams/wallet-server/cloud-host';
import type { TenantRootIdentityV1 } from './types';

const IDENTITY_DOMAIN = new TextEncoder().encode('seams/tenant-root-identity/v1');
const GRANT_DOMAIN = new TextEncoder().encode('tenant_root_creation_grant_v1');
const GRANT_OPERATION = new TextEncoder().encode('tenant_root_authorize_create_v1');
const GRANT_AUTH_DOMAIN = new TextEncoder().encode('tenant_root_creation_grant_authentication_v1');
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const MAX_IDENTIFIER_BYTES = 256;
const MAX_GRANT_LIFETIME_MS = 300_000;

export interface TenantRootCreationGrantSigningInputV1 {
  readonly identity: TenantRootIdentityV1;
  readonly custodyLineage: Uint8Array;
  readonly grantNonce: Uint8Array;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly grantKeyId: string;
  readonly signingSeedB64u: string;
}

export interface SignedTenantRootCreationGrantV1 {
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
  readonly grantNonceB64u: string;
  readonly grantKeyId: string;
  readonly grantB64u: string;
  readonly grantDigestB64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function lengthPrefix(value: Uint8Array): Uint8Array {
  if (value.length === 0 || value.length > 0xffff_ffff) {
    throw new Error('Tenant-root grant canonical field length is invalid');
  }
  const output = new Uint8Array(4 + value.length);
  new DataView(output.buffer).setUint32(0, value.length, false);
  output.set(value, 4);
  return output;
}

function u64(value: number, label: string): Uint8Array {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value), false);
  return output;
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) return true;
  }
  return false;
}

function identifierBytes(value: string, label: string): Uint8Array {
  if (!value || value.trim() !== value || hasControlCharacters(value)) {
    throw new Error(`${label} is invalid`);
  }
  const bytes = new TextEncoder().encode(value);
  if (bytes.length > MAX_IDENTIFIER_BYTES) {
    throw new Error(`${label} exceeds ${MAX_IDENTIFIER_BYTES} UTF-8 bytes`);
  }
  return bytes;
}

export function encodeTenantRootIdentityV1(identity: TenantRootIdentityV1): Uint8Array {
  const fields = [
    identifierBytes(identity.orgId, 'identity.orgId'),
    identifierBytes(identity.projectId, 'identity.projectId'),
    identifierBytes(identity.envId, 'identity.envId'),
    identifierBytes(identity.signingRootId, 'identity.signingRootId'),
    identifierBytes(identity.signingRootVersion, 'identity.signingRootVersion'),
  ];
  return concatBytes([IDENTITY_DOMAIN, ...fields.map(lengthPrefix)]);
}

export async function tenantRootIdentityDigestB64uV1(
  identity: TenantRootIdentityV1,
): Promise<string> {
  return base64UrlEncode(await sha256(encodeTenantRootIdentityV1(identity)));
}

function exactBytes(value: Uint8Array, expectedLength: number, label: string): Uint8Array {
  if (value.length !== expectedLength || value.every((byte) => byte === 0)) {
    throw new Error(`${label} must be a nonzero ${expectedLength}-byte value`);
  }
  return new Uint8Array(value);
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const output = new ArrayBuffer(bytes.length);
  new Uint8Array(output).set(bytes);
  return output;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is required for tenant-root grant issuance');
  return new Uint8Array(await subtle.digest('SHA-256', copyToArrayBuffer(bytes)));
}

async function signEd25519(seed: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('WebCrypto is required for tenant-root grant issuance');
  const pkcs8 = concatBytes([ED25519_PKCS8_SEED_PREFIX, seed]);
  try {
    const key = await subtle.importKey('pkcs8', copyToArrayBuffer(pkcs8), 'Ed25519', false, [
      'sign',
    ]);
    return new Uint8Array(await subtle.sign('Ed25519', key, copyToArrayBuffer(message)));
  } finally {
    pkcs8.fill(0);
  }
}

export function randomTenantRootCreationGrantBytesV1(length: 16 | 32): Uint8Array {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('A cryptographic random source is required for tenant-root grant issuance');
  }
  const bytes = new Uint8Array(length);
  do {
    globalThis.crypto.getRandomValues(bytes);
  } while (bytes.every((byte) => byte === 0));
  return bytes;
}

export async function signTenantRootCreationGrantV1(
  input: TenantRootCreationGrantSigningInputV1,
): Promise<SignedTenantRootCreationGrantV1> {
  if (
    !Number.isSafeInteger(input.issuedAtMs) ||
    input.issuedAtMs <= 0 ||
    !Number.isSafeInteger(input.expiresAtMs) ||
    input.expiresAtMs <= input.issuedAtMs ||
    input.expiresAtMs - input.issuedAtMs > MAX_GRANT_LIFETIME_MS
  ) {
    throw new Error('Tenant-root creation grant time window is invalid');
  }
  const identityBytes = encodeTenantRootIdentityV1(input.identity);
  const custodyLineage = exactBytes(input.custodyLineage, 16, 'custodyLineage');
  const grantNonce = exactBytes(input.grantNonce, 32, 'grantNonce');
  const grantKeyId = identifierBytes(input.grantKeyId, 'grantKeyId');
  const seed = base64UrlDecode(input.signingSeedB64u);
  if (seed.length !== 32) {
    seed.fill(0);
    throw new Error('Tenant-root grant authority signing seed must be 32 bytes');
  }

  const unsigned = concatBytes([
    lengthPrefix(GRANT_DOMAIN),
    lengthPrefix(GRANT_OPERATION),
    lengthPrefix(identityBytes),
    lengthPrefix(custodyLineage),
    lengthPrefix(grantNonce),
    lengthPrefix(u64(input.issuedAtMs, 'issuedAtMs')),
    lengthPrefix(u64(input.expiresAtMs, 'expiresAtMs')),
    lengthPrefix(grantKeyId),
  ]);
  const authenticationInput = concatBytes([
    lengthPrefix(GRANT_AUTH_DOMAIN),
    lengthPrefix(grantKeyId),
    lengthPrefix(unsigned),
  ]);
  try {
    const signature = await signEd25519(seed, authenticationInput);
    if (signature.length !== 64) {
      throw new Error('Tenant-root grant authority produced an invalid Ed25519 signature');
    }
    const grant = concatBytes([unsigned, lengthPrefix(signature)]);
    const [identityDigest, grantDigest] = await Promise.all([sha256(identityBytes), sha256(grant)]);
    return {
      identityDigestB64u: base64UrlEncode(identityDigest),
      custodyLineageB64u: base64UrlEncode(custodyLineage),
      grantNonceB64u: base64UrlEncode(grantNonce),
      grantKeyId: input.grantKeyId,
      grantB64u: base64UrlEncode(grant),
      grantDigestB64u: base64UrlEncode(grantDigest),
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    };
  } finally {
    seed.fill(0);
  }
}
