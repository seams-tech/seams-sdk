import { base64UrlDecode, base64UrlEncode } from './encoders';
import {
  computeSdkEcdsaHssApplicationBindingDigestB64u,
  type SdkEcdsaHssBindingFacts,
} from '../threshold/ecdsaHssRoleLocalBootstrap';
import {
  decodeJwtPayloadRecord,
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
} from './sessionTokens';

export const ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1 = 'evm-family' as const;
export const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1 =
  'router_ab_ecdsa_hss_normal_signing_v1' as const;
export const ROUTER_AB_ECDSA_HSS_HEALTH_PATH = '/router-ab/ecdsa-hss/healthz' as const;
export const ROUTER_AB_ECDSA_HSS_BOOTSTRAP_PATH = '/router-ab/ecdsa-hss/bootstrap' as const;
export const ROUTER_AB_ECDSA_HSS_EXPORT_SHARE_PATH =
  '/router-ab/ecdsa-hss/export/share' as const;
export const ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH =
  '/router-ab/ecdsa-hss/presignature-pool/fill/init' as const;
export const ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH =
  '/router-ab/ecdsa-hss/presignature-pool/fill/step' as const;
export const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PREPARE_PATH =
  '/router-ab/ecdsa-hss/sign/prepare' as const;
export const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_PATH = '/router-ab/ecdsa-hss/sign' as const;
const ECDSA_HSS_CONTEXT_DOMAIN_TAG_V1 = 'ecdsa-hss:context:v4' as const;
const ECDSA_HSS_CONTEXT_BINDING_DOMAIN_V1 = 'ecdsa-hss:role-local:v2:context-binding' as const;
const ECDSA_HSS_SCHEME_ID_V1 = 'ecdsa-hss-v4' as const;
const ECDSA_HSS_CURVE_V1 = 'secp256k1' as const;
const ECDSA_HSS_CONTEXT_FIELD_BYTES_V1 = 0x01;
const ECDSA_HSS_PARTICIPANT_IDS_V1 = [1, 2] as const;
const ROUTER_AB_ECDSA_HSS_PUBLIC_IDENTITY_VERSION_V1 =
  'router-ab-protocol/ecdsa-hss/public-identity/v1' as const;
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_SCOPE_VERSION_V1 =
  'router-ab-protocol/ecdsa-hss/normal-signing-scope/v1' as const;
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_REQUEST_VERSION_V1 =
  'router-ab-protocol/ecdsa-hss/normal-signing-request/v1' as const;
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1 =
  'router-ab-protocol/ecdsa-hss/normal-signing-finalize-request/v1' as const;

export type RouterAbEcdsaHssStableKeyContextV1 = {
  application_binding_digest_b64u: string;
};

export type RouterAbEcdsaHssPublicIdentityV1 = {
  context_binding_b64u: string;
  client_public_key33_b64u: string;
  server_public_key33_b64u: string;
  threshold_public_key33_b64u: string;
  ethereum_address20_b64u: string;
  client_share_retry_counter: number;
  server_share_retry_counter: number;
};

export type RouterAbServerIdentityV1 = {
  server_id: string;
  key_epoch: string;
  recipient_encryption_key: string;
};

export type RouterAbPublicDigest32V1Wire = {
  bytes: number[];
};

export type RouterAbActiveSigningWorkerStateV1 = {
  account_id: string;
  session_id: string;
  account_public_key: string;
  signing_worker: RouterAbServerIdentityV1;
  activation_transcript_digest: RouterAbPublicDigest32V1Wire;
  activation_digest: RouterAbPublicDigest32V1Wire;
  signing_worker_material_handle: string;
  activated_at_ms: number;
};

export type RouterAbEcdsaHssNormalSigningScopeV1 = {
  wallet_key_id: string;
  wallet_id: string;
  ecdsa_threshold_key_id: string;
  signing_root_id: string;
  signing_root_version: string;
  context: RouterAbEcdsaHssStableKeyContextV1;
  public_identity: RouterAbEcdsaHssPublicIdentityV1;
  signing_worker: RouterAbServerIdentityV1;
  activation_epoch: string;
};

export type RouterAbEcdsaHssNormalSigningStateV1 = {
  kind: typeof ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1;
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
};

export type RouterAbEcdsaHssWalletRegistrationJwtBindingFactsV1 = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  relayerKeyId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  participantIds: readonly number[];
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  clientPublicKey33B64u: string;
  serverPublicKey33B64u: string;
  thresholdPublicKey33B64u: string;
  ethereumAddress: string;
  clientShareRetryCounter: number;
  serverShareRetryCounter: number;
};

export type RouterAbEcdsaHssServerPresignatureShareV1 = {
  serverKeyId: string;
  presignatureId: string;
  bigRB64u: string;
  kShareB64u: string;
  sigmaShareB64u: string;
  createdAtMs: number;
};

export type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  server_k_share32_b64u: string;
  server_sigma_share32_b64u: string;
  expires_at_ms: number;
};

export type CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire = {
  active_signing_worker_state: RouterAbActiveSigningWorkerStateV1;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  stored: boolean;
};

export type RouterAbEcdsaHssSignatureSchemeV1Wire = 'ecdsa_secp256k1_recoverable_v1';

export type RouterAbEcdsaHssEvmDigestSigningRequestV1Wire = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  request_id: string;
  client_presignature_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
};

export type RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  request_id: string;
  expires_at_ms: number;
  signing_digest_b64u: string;
  server_presignature_id: string;
  client_signature_share32_b64u: string;
};

export type RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire =
  RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire & {
    budget_reservation_id: string;
    budget_operation_id: string;
  };

export type RouterAbEcdsaHssBudgetStatusV1Wire = {
  committed_remaining_uses: number;
  reserved_uses: number;
  available_uses: number;
};

export type RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  request_id: string;
  budget_reservation_id: string;
  budget_operation_id: string;
  budget_status: RouterAbEcdsaHssBudgetStatusV1Wire;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  server_presignature_id: string;
  server_big_r33_b64u: string;
  rerandomization_entropy32_b64u: string;
  signature_scheme: RouterAbEcdsaHssSignatureSchemeV1Wire;
  prepared_at_ms: number;
  expires_at_ms: number;
};

export type RouterAbEcdsaHssEvmDigestSigningResponseV1Wire = {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  request_id: string;
  request_digest: RouterAbPublicDigest32V1Wire;
  signing_digest: RouterAbPublicDigest32V1Wire;
  signature_scheme: RouterAbEcdsaHssSignatureSchemeV1Wire;
  signature65_b64u: string;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new Error(`${label} must be an object`);
}

function requireExactKeys(
  record: Record<string, unknown>,
  label: string,
  allowedKeys: readonly string[],
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) throw new Error(`${label}.${key} is not a supported field`);
  }
}

function requireAsciiNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string') throw new Error(`${label} must be a string`);
  const parsed = value.trim();
  if (!parsed) throw new Error(`${label} is required`);
  if (!/^[\x20-\x7e]+$/.test(parsed)) throw new Error(`${label} must be printable ASCII`);
  return parsed;
}

function requirePositiveUnixMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed <= 0) throw new Error(`${label} must be a positive integer`);
  return parsed;
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0) throw new Error(`${label} must be a non-negative integer`);
  return parsed;
}

function requireU32(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0 || parsed > 0xffffffff) {
    throw new Error(`${label} must be a u32 integer`);
  }
  return parsed;
}

function requireBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`${label} must be a boolean`);
  return value;
}

function requireByte(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${label} must be a finite number`);
  }
  const parsed = Math.floor(value);
  if (parsed !== value || parsed < 0 || parsed > 255) {
    throw new Error(`${label} must be a byte`);
  }
  return parsed;
}

function requireBase64UrlFixed(value: unknown, label: string, byteLength: number): string {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (!/^[A-Za-z0-9_-]+$/.test(parsed)) {
    throw new Error(`${label} must be unpadded base64url`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlDecode(parsed);
  } catch {
    throw new Error(`${label} must be valid base64url`);
  }
  if (decoded.length !== byteLength) {
    throw new Error(`${label} must decode to ${byteLength} bytes`);
  }
  return parsed;
}

function requireUint8ArrayFixed(value: unknown, label: string, byteLength: number): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new Error(`${label} must be a Uint8Array`);
  if (value.length !== byteLength) throw new Error(`${label} must contain ${byteLength} bytes`);
  return value;
}

function requireSignatureScheme(
  value: unknown,
  label: string,
): RouterAbEcdsaHssSignatureSchemeV1Wire {
  const parsed = requireAsciiNonEmptyString(value, label);
  if (parsed !== 'ecdsa_secp256k1_recoverable_v1') {
    throw new Error(`${label} must be ecdsa_secp256k1_recoverable_v1`);
  }
  return parsed;
}

function parsePublicDigest32(value: unknown, label: string): RouterAbPublicDigest32V1Wire {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['bytes']);
  if (!Array.isArray(record.bytes)) throw new Error(`${label}.bytes must be an array`);
  if (record.bytes.length !== 32) throw new Error(`${label}.bytes must contain 32 bytes`);
  return {
    bytes: record.bytes.map((entry, index) => requireByte(entry, `${label}.bytes[${index}]`)),
  };
}

function parseStableKeyContext(value: unknown): RouterAbEcdsaHssStableKeyContextV1 {
  const record = requireRecord(value, 'scope.context');
  requireExactKeys(record, 'scope.context', ['application_binding_digest_b64u']);
  const digest = base64UrlDecode(
    requireAsciiNonEmptyString(
      record.application_binding_digest_b64u,
      'scope.context.application_binding_digest_b64u',
    ),
  );
  if (digest.length !== 32) {
    throw new Error('scope.context.application_binding_digest_b64u must decode to 32 bytes');
  }
  return {
    application_binding_digest_b64u: base64UrlEncode(digest),
  };
}

function parsePublicIdentity(value: unknown): RouterAbEcdsaHssPublicIdentityV1 {
  const record = requireRecord(value, 'scope.public_identity');
  requireExactKeys(record, 'scope.public_identity', [
    'context_binding_b64u',
    'client_public_key33_b64u',
    'server_public_key33_b64u',
    'threshold_public_key33_b64u',
    'ethereum_address20_b64u',
    'client_share_retry_counter',
    'server_share_retry_counter',
  ]);
  return {
    context_binding_b64u: requireBase64UrlFixed(
      record.context_binding_b64u,
      'scope.public_identity.context_binding_b64u',
      32,
    ),
    client_public_key33_b64u: requireBase64UrlFixed(
      record.client_public_key33_b64u,
      'scope.public_identity.client_public_key33_b64u',
      33,
    ),
    server_public_key33_b64u: requireBase64UrlFixed(
      record.server_public_key33_b64u,
      'scope.public_identity.server_public_key33_b64u',
      33,
    ),
    threshold_public_key33_b64u: requireBase64UrlFixed(
      record.threshold_public_key33_b64u,
      'scope.public_identity.threshold_public_key33_b64u',
      33,
    ),
    ethereum_address20_b64u: requireBase64UrlFixed(
      record.ethereum_address20_b64u,
      'scope.public_identity.ethereum_address20_b64u',
      20,
    ),
    client_share_retry_counter: requireU32(
      record.client_share_retry_counter,
      'scope.public_identity.client_share_retry_counter',
    ),
    server_share_retry_counter: requireU32(
      record.server_share_retry_counter,
      'scope.public_identity.server_share_retry_counter',
    ),
  };
}

function parseServerIdentity(value: unknown): RouterAbServerIdentityV1 {
  return parseServerIdentityWithLabel(value, 'scope.signing_worker');
}

function parseServerIdentityWithLabel(value: unknown, label: string): RouterAbServerIdentityV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['server_id', 'key_epoch', 'recipient_encryption_key']);
  return {
    server_id: requireAsciiNonEmptyString(record.server_id, `${label}.server_id`),
    key_epoch: requireAsciiNonEmptyString(record.key_epoch, `${label}.key_epoch`),
    recipient_encryption_key: requireAsciiNonEmptyString(
      record.recipient_encryption_key,
      `${label}.recipient_encryption_key`,
    ),
  };
}

function publicDigest32FromBase64Url(
  value: string,
  label = 'signing_digest_b64u',
): RouterAbPublicDigest32V1Wire {
  return {
    bytes: Array.from(base64UrlDecode(requireBase64UrlFixed(value, label, 32))),
  };
}

function samePublicDigest32(
  left: RouterAbPublicDigest32V1Wire,
  right: RouterAbPublicDigest32V1Wire,
): boolean {
  return (
    left.bytes.length === 32 &&
    right.bytes.length === 32 &&
    left.bytes.every((b, i) => b === right.bytes[i])
  );
}

function asciiBytes(value: string): Uint8Array {
  return new TextEncoder().encode(requireAsciiNonEmptyString(value, 'canonical string'));
}

function concatBytes(parts: readonly Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function pushBytes(out: number[], bytes: Uint8Array): void {
  for (const byte of bytes) out.push(byte);
}

function pushU16(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
    throw new Error('canonical u16 must be an integer between 0 and 65535');
  }
  out.push((value >>> 8) & 0xff, value & 0xff);
}

function pushU32(out: number[], value: number): void {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error('canonical u32 must be an integer between 0 and 4294967295');
  }
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function pushU64(out: number[], value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error('canonical u64 must be a non-negative safe integer');
  }
  let remaining = BigInt(value);
  for (let shift = 56; shift >= 0; shift -= 8) {
    out.push(Number((remaining >> BigInt(shift)) & 0xffn));
  }
}

function pushLen32(out: number[], bytes: Uint8Array): void {
  pushU32(out, bytes.length);
  pushBytes(out, bytes);
}

function pushAsciiU16(out: number[], value: string): void {
  const bytes = asciiBytes(value);
  pushU16(out, bytes.length);
  pushBytes(out, bytes);
}

function pushServerIdentity(out: number[], server: RouterAbServerIdentityV1): void {
  pushLen32(out, asciiBytes(server.server_id));
  pushLen32(out, asciiBytes(server.key_epoch));
  pushLen32(out, asciiBytes(server.recipient_encryption_key));
}

async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('crypto.subtle is required for ECDSA-HSS request digest binding');
  const buffer = new ArrayBuffer(input.byteLength);
  new Uint8Array(buffer).set(input);
  return new Uint8Array(await subtle.digest('SHA-256', buffer));
}

function canonicalStableKeyContextBytes(context: RouterAbEcdsaHssStableKeyContextV1): Uint8Array {
  const parsed = parseStableKeyContext(context);
  const out: number[] = [];
  pushBytes(out, asciiBytes(ECDSA_HSS_CONTEXT_DOMAIN_TAG_V1));
  pushAsciiU16(out, ECDSA_HSS_SCHEME_ID_V1);
  pushAsciiU16(out, ECDSA_HSS_CURVE_V1);
  pushBytes(out, base64UrlDecode(parsed.application_binding_digest_b64u));
  out.push(ECDSA_HSS_PARTICIPANT_IDS_V1.length);
  for (const participantId of ECDSA_HSS_PARTICIPANT_IDS_V1) pushU16(out, participantId);
  return new Uint8Array(out);
}

export async function routerAbEcdsaHssStableKeyContextFromSdkFactsV1(
  facts: SdkEcdsaHssBindingFacts,
): Promise<RouterAbEcdsaHssStableKeyContextV1> {
  return {
    application_binding_digest_b64u: await computeSdkEcdsaHssApplicationBindingDigestB64u(facts),
  };
}

function contextBindingFrame(contextBytes: Uint8Array): Uint8Array {
  const out: number[] = [];
  pushBytes(out, asciiBytes(ECDSA_HSS_CONTEXT_BINDING_DOMAIN_V1));
  out.push(1);
  out.push(ECDSA_HSS_CONTEXT_FIELD_BYTES_V1);
  pushU16(out, contextBytes.length);
  pushBytes(out, contextBytes);
  return new Uint8Array(out);
}

export async function routerAbEcdsaHssContextBindingDigestV1(
  context: RouterAbEcdsaHssStableKeyContextV1,
): Promise<RouterAbPublicDigest32V1Wire> {
  return publicDigest32FromCanonicalBytes(
    contextBindingFrame(canonicalStableKeyContextBytes(context)),
  );
}

export async function routerAbEcdsaHssContextBindingB64uV1(
  context: RouterAbEcdsaHssStableKeyContextV1,
): Promise<string> {
  const digest = await routerAbEcdsaHssContextBindingDigestV1(context);
  return base64UrlEncode(new Uint8Array(digest.bytes));
}

function canonicalPublicIdentityBytes(
  publicIdentity: RouterAbEcdsaHssPublicIdentityV1,
): Uint8Array {
  const parsed = parsePublicIdentity(publicIdentity);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_HSS_PUBLIC_IDENTITY_VERSION_V1));
  pushLen32(out, asciiBytes(parsed.context_binding_b64u));
  pushLen32(out, asciiBytes(parsed.client_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.server_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.threshold_public_key33_b64u));
  pushLen32(out, asciiBytes(parsed.ethereum_address20_b64u));
  pushU32(out, parsed.client_share_retry_counter);
  pushU32(out, parsed.server_share_retry_counter);
  return new Uint8Array(out);
}

function canonicalNormalSigningScopeBytes(scope: RouterAbEcdsaHssNormalSigningScopeV1): Uint8Array {
  const parsed = parseRouterAbEcdsaHssNormalSigningScopeV1(scope);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_SCOPE_VERSION_V1));
  pushLen32(out, asciiBytes(parsed.wallet_key_id));
  pushLen32(out, asciiBytes(parsed.wallet_id));
  pushLen32(out, asciiBytes(parsed.ecdsa_threshold_key_id));
  pushLen32(out, asciiBytes(parsed.signing_root_id));
  pushLen32(out, asciiBytes(parsed.signing_root_version));
  pushLen32(out, canonicalStableKeyContextBytes(parsed.context));
  pushLen32(out, canonicalPublicIdentityBytes(parsed.public_identity));
  pushServerIdentity(out, parsed.signing_worker);
  pushLen32(out, asciiBytes(parsed.activation_epoch));
  return new Uint8Array(out);
}

export function routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1(
  scope: RouterAbEcdsaHssNormalSigningScopeV1,
): Uint8Array {
  return canonicalNormalSigningScopeBytes(scope);
}

function sameCanonicalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function sameRouterAbEcdsaHssNormalSigningScopeV1(
  left: RouterAbEcdsaHssNormalSigningScopeV1,
  right: RouterAbEcdsaHssNormalSigningScopeV1,
): boolean {
  try {
    return sameCanonicalBytes(
      routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1(left),
      routerAbEcdsaHssNormalSigningScopeCanonicalBytesV1(right),
    );
  } catch {
    return false;
  }
}

async function publicDigest32FromCanonicalBytes(
  bytes: Uint8Array,
): Promise<RouterAbPublicDigest32V1Wire> {
  return { bytes: Array.from(await sha256Bytes(bytes)) };
}

export async function verifyRouterAbEcdsaHssNormalSigningScopeContextBindingV1(
  scope: RouterAbEcdsaHssNormalSigningScopeV1,
): Promise<RouterAbEcdsaHssNormalSigningScopeV1> {
  const parsed = parseRouterAbEcdsaHssNormalSigningScopeV1(scope);
  const expected = await routerAbEcdsaHssContextBindingDigestV1(parsed.context);
  const actual = publicDigest32FromBase64Url(
    parsed.public_identity.context_binding_b64u,
    'scope.public_identity.context_binding_b64u',
  );
  if (!samePublicDigest32(actual, expected)) {
    throw new Error('scope.public_identity.context_binding_b64u does not match scope.context');
  }
  return parsed;
}

export function routerAbEcdsaHssEvmDigestSigningRequestCanonicalBytesV1(
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
): Uint8Array {
  const parsed = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(request);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_REQUEST_VERSION_V1));
  pushLen32(out, canonicalNormalSigningScopeBytes(parsed.scope));
  pushLen32(out, asciiBytes(parsed.request_id));
  pushLen32(out, asciiBytes(parsed.client_presignature_id));
  pushU64(out, parsed.expires_at_ms);
  pushBytes(out, base64UrlDecode(parsed.signing_digest_b64u));
  return new Uint8Array(out);
}

export async function routerAbEcdsaHssEvmDigestSigningRequestDigestV1(
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
): Promise<RouterAbPublicDigest32V1Wire> {
  const parsed = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(request);
  await verifyRouterAbEcdsaHssNormalSigningScopeContextBindingV1(parsed.scope);
  return publicDigest32FromCanonicalBytes(
    routerAbEcdsaHssEvmDigestSigningRequestCanonicalBytesV1(parsed),
  );
}

export function routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestCanonicalBytesV1(
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire,
): Uint8Array {
  const parsed = parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1(request);
  const out: number[] = [];
  pushLen32(out, asciiBytes(ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1));
  pushLen32(out, canonicalNormalSigningScopeBytes(parsed.scope));
  pushLen32(out, asciiBytes(parsed.request_id));
  pushU64(out, parsed.expires_at_ms);
  pushBytes(out, base64UrlDecode(parsed.signing_digest_b64u));
  pushLen32(out, asciiBytes(parsed.server_presignature_id));
  pushLen32(out, base64UrlDecode(parsed.client_signature_share32_b64u));
  return new Uint8Array(out);
}

export async function routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestDigestV1(
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire,
): Promise<RouterAbPublicDigest32V1Wire> {
  const parsed = parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1(request);
  await verifyRouterAbEcdsaHssNormalSigningScopeContextBindingV1(parsed.scope);
  return publicDigest32FromCanonicalBytes(
    routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestCanonicalBytesV1(parsed),
  );
}

export function parseRouterAbEcdsaHssNormalSigningScopeV1(
  value: unknown,
): RouterAbEcdsaHssNormalSigningScopeV1 {
  const record = requireRecord(value, 'scope');
  requireExactKeys(record, 'scope', [
    'wallet_key_id',
    'wallet_id',
    'ecdsa_threshold_key_id',
    'signing_root_id',
    'signing_root_version',
    'context',
    'public_identity',
    'signing_worker',
    'activation_epoch',
  ]);
  return {
    wallet_key_id: requireAsciiNonEmptyString(record.wallet_key_id, 'scope.wallet_key_id'),
    wallet_id: requireAsciiNonEmptyString(record.wallet_id, 'scope.wallet_id'),
    ecdsa_threshold_key_id: requireAsciiNonEmptyString(
      record.ecdsa_threshold_key_id,
      'scope.ecdsa_threshold_key_id',
    ),
    signing_root_id: requireAsciiNonEmptyString(record.signing_root_id, 'scope.signing_root_id'),
    signing_root_version: requireAsciiNonEmptyString(
      record.signing_root_version,
      'scope.signing_root_version',
    ),
    context: parseStableKeyContext(record.context),
    public_identity: parsePublicIdentity(record.public_identity),
    signing_worker: parseServerIdentity(record.signing_worker),
    activation_epoch: requireAsciiNonEmptyString(record.activation_epoch, 'scope.activation_epoch'),
  };
}

export function parseRouterAbEcdsaHssNormalSigningStateV1(
  value: unknown,
): RouterAbEcdsaHssNormalSigningStateV1 | null {
  if (value === undefined || value === null) return null;
  const record = requireRecord(value, 'routerAbEcdsaHssNormalSigning');
  requireExactKeys(record, 'routerAbEcdsaHssNormalSigning', ['kind', 'scope']);
  const kind = requireAsciiNonEmptyString(record.kind, 'routerAbEcdsaHssNormalSigning.kind');
  if (kind !== ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1) {
    throw new Error('routerAbEcdsaHssNormalSigning.kind is not supported');
  }
  return {
    kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
  };
}

export function requireRouterAbEcdsaHssNormalSigningStateV1(
  value: unknown,
): RouterAbEcdsaHssNormalSigningStateV1 {
  const parsed = parseRouterAbEcdsaHssNormalSigningStateV1(value);
  if (!parsed) throw new Error('Router A/B ECDSA-HSS normal-signing state is required');
  return parsed;
}

function requireWalletRegistrationMatchingString(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): string {
  const expected = String(args.expected || '').trim();
  const actual = String(args.actual || '').trim();
  if (!expected || !actual) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireWalletRegistrationMatchingNumber(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): number {
  const expected = Math.floor(Number(args.expected));
  const actual = Math.floor(Number(args.actual));
  if (!Number.isSafeInteger(expected) || !Number.isSafeInteger(actual)) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireWalletRegistrationMatchingParticipantIds(args: {
  expected: readonly unknown[];
  actual: readonly unknown[];
}): number[] {
  const expected = args.expected.map((participantId) => Math.floor(Number(participantId)));
  const actual = args.actual.map((participantId) => Math.floor(Number(participantId)));
  const invalid =
    expected.length === 0 ||
    actual.length === 0 ||
    expected.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0) ||
    actual.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0);
  if (invalid) {
    throw new Error('ECDSA registration bootstrap returned incomplete participantIds');
  }
  if (expected.length !== actual.length || expected.some((id, index) => id !== actual[index])) {
    throw new Error('ECDSA registration bootstrap participantIds mismatch');
  }
  return actual;
}

function ethereumAddress20B64u(address: string): string {
  const normalized = String(address || '').trim();
  const hex = normalized.startsWith('0x') ? normalized.slice(2) : normalized;
  if (!/^[0-9a-fA-F]{40}$/.test(hex)) {
    throw new Error('ECDSA registration bootstrap returned invalid ethereumAddress');
  }
  const bytes = new Uint8Array(20);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return base64UrlEncode(bytes);
}

export function parseRouterAbEcdsaHssNormalSigningFromWalletRegistrationJwtV1(args: {
  walletSessionJwt: string;
  expected: RouterAbEcdsaHssWalletRegistrationJwtBindingFactsV1;
}): RouterAbEcdsaHssNormalSigningStateV1 {
  const payload = decodeJwtPayloadRecord(args.walletSessionJwt);
  if (!payload) {
    throw new Error('ECDSA registration bootstrap returned invalid Wallet Session JWT');
  }
  const expected = args.expected;
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.kind',
    expected: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    actual: payload.kind,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.sub',
    expected: expected.walletId,
    actual: payload.sub,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.walletId',
    expected: expected.walletId,
    actual: payload.walletId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.evmFamilySigningKeySlotId',
    expected: expected.evmFamilySigningKeySlotId,
    actual: payload.evmFamilySigningKeySlotId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.keyScope',
    expected: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
    actual: payload.keyScope,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.keyHandle',
    expected: expected.keyHandle,
    actual: payload.keyHandle,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.relayerKeyId',
    expected: expected.relayerKeyId,
    actual: payload.relayerKeyId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.thresholdSessionId',
    expected: expected.thresholdSessionId,
    actual: payload.thresholdSessionId,
  });
  requireWalletRegistrationMatchingString({
    field: 'walletSessionJwt.signingGrantId',
    expected: expected.signingGrantId,
    actual: payload.signingGrantId,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'walletSessionJwt.thresholdExpiresAtMs',
    expected: expected.expiresAtMs,
    actual: payload.thresholdExpiresAtMs,
  });
  requireWalletRegistrationMatchingParticipantIds({
    expected: expected.participantIds,
    actual: Array.isArray(payload.participantIds) ? payload.participantIds : [],
  });
  const hasNormalSigning = payload.routerAbEcdsaHssNormalSigning !== undefined;
  const hasIssuerBinding = payload.routerAbEcdsaHssIssuerBinding !== undefined;
  if (!hasNormalSigning) {
    throw new Error(
      hasIssuerBinding
        ? 'ECDSA registration bootstrap Wallet Session JWT is issuer-binding-only'
        : 'ECDSA registration bootstrap Wallet Session JWT missing routerAbEcdsaHssNormalSigning',
    );
  }
  if (hasIssuerBinding) {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT must contain normal-signing state only',
    );
  }
  let normalSigning: RouterAbEcdsaHssNormalSigningStateV1 | null = null;
  try {
    normalSigning = parseRouterAbEcdsaHssNormalSigningStateV1(
      payload.routerAbEcdsaHssNormalSigning,
    );
  } catch {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT has invalid routerAbEcdsaHssNormalSigning',
    );
  }
  if (!normalSigning) {
    throw new Error(
      'ECDSA registration bootstrap Wallet Session JWT missing routerAbEcdsaHssNormalSigning',
    );
  }
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.wallet_id',
    expected: expected.walletId,
    actual: normalSigning.scope.wallet_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.wallet_key_id',
    expected: expected.evmFamilySigningKeySlotId,
    actual: normalSigning.scope.wallet_key_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.ecdsa_threshold_key_id',
    expected: expected.ecdsaThresholdKeyId,
    actual: normalSigning.scope.ecdsa_threshold_key_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.signing_root_id',
    expected: expected.signingRootId,
    actual: normalSigning.scope.signing_root_id,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.signing_root_version',
    expected: expected.signingRootVersion,
    actual: normalSigning.scope.signing_root_version,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.context.application_binding_digest_b64u',
    expected: expected.applicationBindingDigestB64u,
    actual: normalSigning.scope.context.application_binding_digest_b64u,
  });
  const publicIdentity = normalSigning.scope.public_identity;
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.context_binding_b64u',
    expected: expected.contextBinding32B64u,
    actual: publicIdentity.context_binding_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.client_public_key33_b64u',
    expected: expected.clientPublicKey33B64u,
    actual: publicIdentity.client_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.server_public_key33_b64u',
    expected: expected.serverPublicKey33B64u,
    actual: publicIdentity.server_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.threshold_public_key33_b64u',
    expected: expected.thresholdPublicKey33B64u,
    actual: publicIdentity.threshold_public_key33_b64u,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.ethereum_address20_b64u',
    expected: ethereumAddress20B64u(expected.ethereumAddress),
    actual: publicIdentity.ethereum_address20_b64u,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.client_share_retry_counter',
    expected: expected.clientShareRetryCounter,
    actual: publicIdentity.client_share_retry_counter,
  });
  requireWalletRegistrationMatchingNumber({
    field: 'routerAbEcdsaHssNormalSigning.scope.public_identity.server_share_retry_counter',
    expected: expected.serverShareRetryCounter,
    actual: publicIdentity.server_share_retry_counter,
  });
  requireWalletRegistrationMatchingString({
    field: 'routerAbEcdsaHssNormalSigning.scope.activation_epoch',
    expected: expected.thresholdSessionId,
    actual: normalSigning.scope.activation_epoch,
  });
  if (!String(normalSigning.scope.signing_worker.server_id || '').trim()) {
    throw new Error('ECDSA registration bootstrap Wallet Session JWT missing signing worker id');
  }
  return normalSigning;
}

export function routerAbEcdsaHssActiveStateSessionId(
  state: RouterAbEcdsaHssNormalSigningStateV1,
): string {
  return [
    state.scope.ecdsa_threshold_key_id,
    state.scope.signing_root_id,
    state.scope.signing_root_version,
    state.scope.activation_epoch,
  ].join(':');
}

export function buildRouterAbEcdsaHssEvmDigestSigningRequestV1(input: {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  requestId: string;
  clientPresignatureId: string;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
}): RouterAbEcdsaHssEvmDigestSigningRequestV1Wire {
  return parseRouterAbEcdsaHssEvmDigestSigningRequestV1({
    scope: input.scope,
    request_id: input.requestId,
    client_presignature_id: input.clientPresignatureId,
    expires_at_ms: input.expiresAtMs,
    signing_digest_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.signingDigest32, 'signingDigest32', 32),
    ),
  });
}

export function parseRouterAbEcdsaHssEvmDigestSigningRequestV1(
  value: unknown,
): RouterAbEcdsaHssEvmDigestSigningRequestV1Wire {
  const record = requireRecord(value, 'ecdsaSigningRequest');
  requireExactKeys(record, 'ecdsaSigningRequest', [
    'scope',
    'request_id',
    'client_presignature_id',
    'expires_at_ms',
    'signing_digest_b64u',
  ]);
  return {
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaSigningRequest.request_id'),
    client_presignature_id: requireAsciiNonEmptyString(
      record.client_presignature_id,
      'ecdsaSigningRequest.client_presignature_id',
    ),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, 'ecdsaSigningRequest.expires_at_ms'),
    signing_digest_b64u: requireBase64UrlFixed(
      record.signing_digest_b64u,
      'ecdsaSigningRequest.signing_digest_b64u',
      32,
    ),
  };
}

export function buildRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1(input: {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  requestId: string;
  budgetReservationId: string;
  budgetOperationId: string;
  expiresAtMs: number;
  signingDigest32: Uint8Array;
  serverPresignatureId: string;
  clientSignatureShare32: Uint8Array;
}): RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire {
  return parseRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1({
    scope: input.scope,
    request_id: input.requestId,
    budget_reservation_id: input.budgetReservationId,
    budget_operation_id: input.budgetOperationId,
    expires_at_ms: input.expiresAtMs,
    signing_digest_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.signingDigest32, 'signingDigest32', 32),
    ),
    server_presignature_id: input.serverPresignatureId,
    client_signature_share32_b64u: base64UrlEncode(
      requireUint8ArrayFixed(input.clientSignatureShare32, 'clientSignatureShare32', 32),
    ),
  });
}

export function parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1(
  value: unknown,
): RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire {
  const record = requireRecord(value, 'ecdsaFinalizeCoreRequest');
  requireExactKeys(record, 'ecdsaFinalizeCoreRequest', [
    'scope',
    'request_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
  ]);
  return parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFields(record);
}

function parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFields(
  record: Record<string, unknown>,
): RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire {
  return {
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaFinalizeRequest.request_id'),
    expires_at_ms: requirePositiveUnixMs(
      record.expires_at_ms,
      'ecdsaFinalizeRequest.expires_at_ms',
    ),
    signing_digest_b64u: requireBase64UrlFixed(
      record.signing_digest_b64u,
      'ecdsaFinalizeRequest.signing_digest_b64u',
      32,
    ),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'ecdsaFinalizeRequest.server_presignature_id',
    ),
    client_signature_share32_b64u: requireBase64UrlFixed(
      record.client_signature_share32_b64u,
      'ecdsaFinalizeRequest.client_signature_share32_b64u',
      32,
    ),
  };
}

export function parseRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1(
  value: unknown,
): RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire {
  const record = requireRecord(value, 'ecdsaFinalizeRequest');
  requireExactKeys(record, 'ecdsaFinalizeRequest', [
    'scope',
    'request_id',
    'budget_reservation_id',
    'budget_operation_id',
    'expires_at_ms',
    'signing_digest_b64u',
    'server_presignature_id',
    'client_signature_share32_b64u',
  ]);
  const coreRequest = parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFields(record);
  return {
    ...coreRequest,
    budget_reservation_id: requireAsciiNonEmptyString(
      record.budget_reservation_id,
      'ecdsaFinalizeRequest.budget_reservation_id',
    ),
    budget_operation_id: requireAsciiNonEmptyString(
      record.budget_operation_id,
      'ecdsaFinalizeRequest.budget_operation_id',
    ),
  };
}

export function routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestFromBudgetedV1(
  request: RouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1Wire,
): RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire {
  const parsed = parseRouterAbEcdsaHssEvmDigestSigningBudgetedFinalizeRequestV1(request);
  return {
    scope: parsed.scope,
    request_id: parsed.request_id,
    expires_at_ms: parsed.expires_at_ms,
    signing_digest_b64u: parsed.signing_digest_b64u,
    server_presignature_id: parsed.server_presignature_id,
    client_signature_share32_b64u: parsed.client_signature_share32_b64u,
  };
}

function parseServerPresignatureShare(value: unknown): RouterAbEcdsaHssServerPresignatureShareV1 {
  const record = requireRecord(value, 'presignature');
  requireExactKeys(record, 'presignature', [
    'serverKeyId',
    'presignatureId',
    'bigRB64u',
    'kShareB64u',
    'sigmaShareB64u',
    'createdAtMs',
  ]);
  return {
    serverKeyId: requireAsciiNonEmptyString(record.serverKeyId, 'presignature.serverKeyId'),
    presignatureId: requireAsciiNonEmptyString(
      record.presignatureId,
      'presignature.presignatureId',
    ),
    bigRB64u: requireBase64UrlFixed(record.bigRB64u, 'presignature.bigRB64u', 33),
    kShareB64u: requireBase64UrlFixed(record.kShareB64u, 'presignature.kShareB64u', 32),
    sigmaShareB64u: requireBase64UrlFixed(record.sigmaShareB64u, 'presignature.sigmaShareB64u', 32),
    createdAtMs: requirePositiveUnixMs(record.createdAtMs, 'presignature.createdAtMs'),
  };
}

export function parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseV1(
  value: unknown,
): RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire {
  const record = requireRecord(value, 'ecdsaPrepareResponse');
  requireExactKeys(record, 'ecdsaPrepareResponse', [
    'scope',
    'request_id',
    'budget_reservation_id',
    'budget_operation_id',
    'budget_status',
    'request_digest',
    'signing_digest',
    'server_presignature_id',
    'server_big_r33_b64u',
    'rerandomization_entropy32_b64u',
    'signature_scheme',
    'prepared_at_ms',
    'expires_at_ms',
  ]);
  return {
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaPrepareResponse.request_id'),
    budget_reservation_id: requireAsciiNonEmptyString(
      record.budget_reservation_id,
      'ecdsaPrepareResponse.budget_reservation_id',
    ),
    budget_operation_id: requireAsciiNonEmptyString(
      record.budget_operation_id,
      'ecdsaPrepareResponse.budget_operation_id',
    ),
    budget_status: parseRouterAbEcdsaHssBudgetStatusV1(
      record.budget_status,
      'ecdsaPrepareResponse.budget_status',
    ),
    request_digest: parsePublicDigest32(
      record.request_digest,
      'ecdsaPrepareResponse.request_digest',
    ),
    signing_digest: parsePublicDigest32(
      record.signing_digest,
      'ecdsaPrepareResponse.signing_digest',
    ),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'ecdsaPrepareResponse.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'ecdsaPrepareResponse.server_big_r33_b64u',
      33,
    ),
    rerandomization_entropy32_b64u: requireBase64UrlFixed(
      record.rerandomization_entropy32_b64u,
      'ecdsaPrepareResponse.rerandomization_entropy32_b64u',
      32,
    ),
    signature_scheme: requireSignatureScheme(
      record.signature_scheme,
      'ecdsaPrepareResponse.signature_scheme',
    ),
    prepared_at_ms: requirePositiveUnixMs(
      record.prepared_at_ms,
      'ecdsaPrepareResponse.prepared_at_ms',
    ),
    expires_at_ms: requirePositiveUnixMs(
      record.expires_at_ms,
      'ecdsaPrepareResponse.expires_at_ms',
    ),
  };
}

function parseRouterAbEcdsaHssBudgetStatusV1(
  value: unknown,
  label: string,
): RouterAbEcdsaHssBudgetStatusV1Wire {
  const record = requireRecord(value, label);
  requireExactKeys(record, label, ['committed_remaining_uses', 'reserved_uses', 'available_uses']);
  return {
    committed_remaining_uses: requireNonNegativeInteger(
      record.committed_remaining_uses,
      `${label}.committed_remaining_uses`,
    ),
    reserved_uses: requireNonNegativeInteger(record.reserved_uses, `${label}.reserved_uses`),
    available_uses: requireNonNegativeInteger(record.available_uses, `${label}.available_uses`),
  };
}

export async function parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseForRequestV1(
  request: RouterAbEcdsaHssEvmDigestSigningRequestV1Wire,
  value: unknown,
): Promise<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1Wire> {
  const parsedRequest = parseRouterAbEcdsaHssEvmDigestSigningRequestV1(request);
  const response = parseRouterAbEcdsaHssEvmDigestSigningPrepareResponseV1(value);
  if (!sameRouterAbEcdsaHssNormalSigningScopeV1(response.scope, parsedRequest.scope)) {
    throw new Error('ecdsaPrepareResponse.scope does not match request');
  }
  if (response.request_id !== parsedRequest.request_id) {
    throw new Error('ecdsaPrepareResponse.request_id does not match request');
  }
  if (response.server_presignature_id !== parsedRequest.client_presignature_id) {
    throw new Error('ecdsaPrepareResponse.server_presignature_id does not match request');
  }
  if (
    !samePublicDigest32(
      response.signing_digest,
      publicDigest32FromBase64Url(parsedRequest.signing_digest_b64u),
    )
  ) {
    throw new Error('ecdsaPrepareResponse.signing_digest does not match request');
  }
  if (response.expires_at_ms !== parsedRequest.expires_at_ms) {
    throw new Error('ecdsaPrepareResponse.expires_at_ms does not match request');
  }
  if (
    !samePublicDigest32(
      response.request_digest,
      await routerAbEcdsaHssEvmDigestSigningRequestDigestV1(parsedRequest),
    )
  ) {
    throw new Error('ecdsaPrepareResponse.request_digest does not match request');
  }
  return response;
}

export function parseRouterAbEcdsaHssEvmDigestSigningResponseV1(
  value: unknown,
): RouterAbEcdsaHssEvmDigestSigningResponseV1Wire {
  const record = requireRecord(value, 'ecdsaSigningResponse');
  requireExactKeys(record, 'ecdsaSigningResponse', [
    'scope',
    'request_id',
    'request_digest',
    'signing_digest',
    'signature_scheme',
    'signature65_b64u',
  ]);
  return {
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
    request_id: requireAsciiNonEmptyString(record.request_id, 'ecdsaSigningResponse.request_id'),
    request_digest: parsePublicDigest32(
      record.request_digest,
      'ecdsaSigningResponse.request_digest',
    ),
    signing_digest: parsePublicDigest32(
      record.signing_digest,
      'ecdsaSigningResponse.signing_digest',
    ),
    signature_scheme: requireSignatureScheme(
      record.signature_scheme,
      'ecdsaSigningResponse.signature_scheme',
    ),
    signature65_b64u: requireBase64UrlFixed(
      record.signature65_b64u,
      'ecdsaSigningResponse.signature65_b64u',
      65,
    ),
  };
}

export async function parseRouterAbEcdsaHssEvmDigestSigningResponseForCoreRequestV1(
  request: RouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1Wire,
  value: unknown,
): Promise<RouterAbEcdsaHssEvmDigestSigningResponseV1Wire> {
  const parsedRequest = parseRouterAbEcdsaHssEvmDigestSigningFinalizeCoreRequestV1(request);
  const response = parseRouterAbEcdsaHssEvmDigestSigningResponseV1(value);
  if (!sameRouterAbEcdsaHssNormalSigningScopeV1(response.scope, parsedRequest.scope)) {
    throw new Error('ecdsaSigningResponse.scope does not match request');
  }
  if (response.request_id !== parsedRequest.request_id) {
    throw new Error('ecdsaSigningResponse.request_id does not match request');
  }
  if (
    !samePublicDigest32(
      response.signing_digest,
      publicDigest32FromBase64Url(parsedRequest.signing_digest_b64u),
    )
  ) {
    throw new Error('ecdsaSigningResponse.signing_digest does not match request');
  }
  if (
    !samePublicDigest32(
      response.request_digest,
      await routerAbEcdsaHssEvmDigestSigningFinalizeCoreRequestDigestV1(parsedRequest),
    )
  ) {
    throw new Error('ecdsaSigningResponse.request_digest does not match request');
  }
  return response;
}

function parseActiveSigningWorkerState(value: unknown): RouterAbActiveSigningWorkerStateV1 {
  const record = requireRecord(value, 'receipt.active_signing_worker_state');
  requireExactKeys(record, 'receipt.active_signing_worker_state', [
    'account_id',
    'session_id',
    'account_public_key',
    'signing_worker',
    'activation_transcript_digest',
    'activation_digest',
    'signing_worker_material_handle',
    'activated_at_ms',
  ]);
  return {
    account_id: requireAsciiNonEmptyString(
      record.account_id,
      'receipt.active_signing_worker_state.account_id',
    ),
    session_id: requireAsciiNonEmptyString(
      record.session_id,
      'receipt.active_signing_worker_state.session_id',
    ),
    account_public_key: requireAsciiNonEmptyString(
      record.account_public_key,
      'receipt.active_signing_worker_state.account_public_key',
    ),
    signing_worker: parseServerIdentityWithLabel(
      record.signing_worker,
      'receipt.active_signing_worker_state.signing_worker',
    ),
    activation_transcript_digest: parsePublicDigest32(
      record.activation_transcript_digest,
      'receipt.active_signing_worker_state.activation_transcript_digest',
    ),
    activation_digest: parsePublicDigest32(
      record.activation_digest,
      'receipt.active_signing_worker_state.activation_digest',
    ),
    signing_worker_material_handle: requireAsciiNonEmptyString(
      record.signing_worker_material_handle,
      'receipt.active_signing_worker_state.signing_worker_material_handle',
    ),
    activated_at_ms: requirePositiveUnixMs(
      record.activated_at_ms,
      'receipt.active_signing_worker_state.activated_at_ms',
    ),
  };
}

export function buildCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(input: {
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  presignature: RouterAbEcdsaHssServerPresignatureShareV1;
  expiresAtMs: number;
}): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire {
  const scope = parseRouterAbEcdsaHssNormalSigningScopeV1(input.scope);
  const presignature = parseServerPresignatureShare(input.presignature);
  const expiresAtMs = requirePositiveUnixMs(input.expiresAtMs, 'expiresAtMs');
  return {
    scope,
    server_presignature_id: presignature.presignatureId,
    server_big_r33_b64u: presignature.bigRB64u,
    server_k_share32_b64u: presignature.kShareB64u,
    server_sigma_share32_b64u: presignature.sigmaShareB64u,
    expires_at_ms: expiresAtMs,
  };
}

export function parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(
  value: unknown,
): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire {
  const record = requireRecord(value, 'poolFillRequest');
  requireExactKeys(record, 'poolFillRequest', [
    'scope',
    'server_presignature_id',
    'server_big_r33_b64u',
    'server_k_share32_b64u',
    'server_sigma_share32_b64u',
    'expires_at_ms',
  ]);
  return {
    scope: parseRouterAbEcdsaHssNormalSigningScopeV1(record.scope),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'poolFillRequest.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'poolFillRequest.server_big_r33_b64u',
      33,
    ),
    server_k_share32_b64u: requireBase64UrlFixed(
      record.server_k_share32_b64u,
      'poolFillRequest.server_k_share32_b64u',
      32,
    ),
    server_sigma_share32_b64u: requireBase64UrlFixed(
      record.server_sigma_share32_b64u,
      'poolFillRequest.server_sigma_share32_b64u',
      32,
    ),
    expires_at_ms: requirePositiveUnixMs(record.expires_at_ms, 'poolFillRequest.expires_at_ms'),
  };
}

export function parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1(
  value: unknown,
): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire {
  const record = requireRecord(value, 'receipt');
  requireExactKeys(record, 'receipt', [
    'active_signing_worker_state',
    'server_presignature_id',
    'server_big_r33_b64u',
    'stored',
  ]);
  return {
    active_signing_worker_state: parseActiveSigningWorkerState(record.active_signing_worker_state),
    server_presignature_id: requireAsciiNonEmptyString(
      record.server_presignature_id,
      'receipt.server_presignature_id',
    ),
    server_big_r33_b64u: requireBase64UrlFixed(
      record.server_big_r33_b64u,
      'receipt.server_big_r33_b64u',
      33,
    ),
    stored: requireBoolean(record.stored, 'receipt.stored'),
  };
}

export function parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptForRequestV1(
  request: CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1Wire,
  value: unknown,
): CloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1Wire {
  const parsedRequest = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1(request);
  const receipt = parseCloudflareSigningWorkerEcdsaHssPresignaturePoolPutReceiptV1(value);
  if (receipt.server_presignature_id !== parsedRequest.server_presignature_id) {
    throw new Error('receipt.server_presignature_id does not match pool-fill request');
  }
  if (receipt.server_big_r33_b64u !== parsedRequest.server_big_r33_b64u) {
    throw new Error('receipt.server_big_r33_b64u does not match pool-fill request');
  }
  return receipt;
}
