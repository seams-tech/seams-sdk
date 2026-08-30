import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '../utils/digests';
import {
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import { parseLinkDevicePublicKeyB64u } from './parsers';
import type { LinkDevicePublicKeyB64u } from './contracts';
import { parseLinkDeviceSessionId, type LinkDeviceSessionId } from '../signing-lanes/ids';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '../utils/domainIds';

export type LinkedDeviceWalletSessionCredentialDeliveryAadV1 = {
  readonly kind: 'linked_device_wallet_session_credential_delivery_aad_v1';
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly credentialDigestB64u: DigestB64u;
  readonly recipientPublicKey65B64u: string;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

/**
 * Scope authenticated by the activation response and checked independently
 * from the sealed envelope before Device 2 decrypts its credential.
 */
export type LinkedDeviceWalletSessionCredentialDeliveryBindingV1 = {
  readonly kind: 'linked_device_wallet_session_credential_delivery_binding_v1';
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
};

export type LinkedDeviceWalletSessionCredentialEnvelopeV1 = {
  readonly kind: 'linked_device_wallet_session_credential_envelope_v1';
  readonly algorithm: 'p256-ecdh-aes256gcm-v1';
  readonly serverEphemeralPublicKey65B64u: string;
  readonly nonce12B64u: string;
  readonly ciphertextB64u: string;
};

export type LinkedDeviceWalletSessionCredentialDeliveryV1 = {
  readonly kind: 'linked_device_wallet_session_credential_delivery_v1';
  readonly aad: LinkedDeviceWalletSessionCredentialDeliveryAadV1;
  readonly aadDigestB64u: DigestB64u;
  readonly recipientBindingDigestB64u: DigestB64u;
  readonly envelope: LinkedDeviceWalletSessionCredentialEnvelopeV1;
  readonly envelopeDigestB64u: DigestB64u;
  readonly installationReceiptDigestB64u: DigestB64u;
};

/**
 * Durable binding retained after acknowledgement. It is the only identity
 * needed to authenticate a retry once the live link-session row is gone.
 */
export type LinkedDeviceActivationCleanupReceiptV1 = {
  readonly kind: 'linked_device_activation_cleanup_receipt_v1';
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyDigestB64u: DigestB64u;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly credentialDigestB64u: DigestB64u;
  readonly installationReceiptDigestB64u: DigestB64u;
  readonly acknowledgedAtMs: number;
  readonly expiresAtMs: number;
};

const DELIVERY_AAD_DOMAIN = 'seams/linked-device/wallet-session-credential-delivery-aad/v1';
const DELIVERY_ENVELOPE_DOMAIN =
  'seams/linked-device/wallet-session-credential-delivery-envelope/v1';

export function encodeLinkedDeviceWalletSessionCredentialDeliveryAadV1(
  aad: LinkedDeviceWalletSessionCredentialDeliveryAadV1,
): string {
  return alphabetizeStringify({ domain: DELIVERY_AAD_DOMAIN, aad });
}

export function buildLinkedDeviceWalletSessionCredentialDeliveryBindingV1(
  aad: LinkedDeviceWalletSessionCredentialDeliveryAadV1,
): LinkedDeviceWalletSessionCredentialDeliveryBindingV1 {
  return {
    kind: 'linked_device_wallet_session_credential_delivery_binding_v1',
    namespace: aad.namespace,
    orgId: aad.orgId,
    projectId: aad.projectId,
    envId: aad.envId,
    tenantId: aad.tenantId,
    principalId: aad.principalId,
  };
}

export function parseLinkedDeviceWalletSessionCredentialDeliveryBindingV1(
  raw: unknown,
): LinkedDeviceWalletSessionCredentialDeliveryBindingV1 {
  const record = exactRecord(
    raw,
    ['kind', 'namespace', 'orgId', 'projectId', 'envId', 'tenantId', 'principalId'],
    'LinkedDeviceWalletSessionCredentialDeliveryBindingV1',
  );
  if (record.kind !== 'linked_device_wallet_session_credential_delivery_binding_v1') {
    throw new Error('LinkedDeviceWalletSessionCredentialDeliveryBindingV1.kind is invalid');
  }
  return {
    kind: 'linked_device_wallet_session_credential_delivery_binding_v1',
    namespace: nonEmpty(record.namespace, 'namespace'),
    orgId: nonEmpty(record.orgId, 'orgId'),
    projectId: nonEmpty(record.projectId, 'projectId'),
    envId: nonEmpty(record.envId, 'envId'),
    tenantId: parsed(parseTenantId(record.tenantId)),
    principalId: parsed(parsePrincipalId(record.principalId)),
  };
}

export async function computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u(
  aad: LinkedDeviceWalletSessionCredentialDeliveryAadV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(encodeLinkedDeviceWalletSessionCredentialDeliveryAadV1(aad)),
    ),
  );
}

export async function computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u(
  envelope: LinkedDeviceWalletSessionCredentialEnvelopeV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(alphabetizeStringify({ domain: DELIVERY_ENVELOPE_DOMAIN, envelope })),
    ),
  );
}

export async function computeLinkedDeviceActivationCleanupReceiptDigestB64u(
  receipt: LinkedDeviceActivationCleanupReceiptV1,
): Promise<DigestB64u> {
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({
          domain: 'seams/linked-device/activation-cleanup-receipt/v1',
          receipt,
        }),
      ),
    ),
  );
}

export function parseLinkedDeviceActivationCleanupReceiptV1(
  raw: unknown,
): LinkedDeviceActivationCleanupReceiptV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'devicePublicKeyB64u',
      'devicePublicKeyDigestB64u',
      'linkSessionId',
      'walletId',
      'authorityId',
      'walletAuthMethodId',
      'packageSetDigestB64u',
      'authorizationId',
      'walletSessionId',
      'credentialDigestB64u',
      'installationReceiptDigestB64u',
      'acknowledgedAtMs',
      'expiresAtMs',
    ],
    'LinkedDeviceActivationCleanupReceiptV1',
  );
  if (record.kind !== 'linked_device_activation_cleanup_receipt_v1') {
    throw new Error('LinkedDeviceActivationCleanupReceiptV1.kind is invalid');
  }
  const acknowledgedAtMs = positiveInteger(
    record.acknowledgedAtMs,
    'acknowledgedAtMs',
  );
  const expiresAtMs = positiveInteger(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= acknowledgedAtMs) {
    throw new Error('expiresAtMs must be after acknowledgedAtMs');
  }
  return {
    kind: 'linked_device_activation_cleanup_receipt_v1',
    devicePublicKeyB64u: parseLinkDevicePublicKeyB64u(record.devicePublicKeyB64u),
    devicePublicKeyDigestB64u: parseDigestB64u(record.devicePublicKeyDigestB64u),
    linkSessionId: parsed(parseLinkDeviceSessionId(record.linkSessionId)),
    walletId: parsed(parseWalletId(record.walletId)),
    authorityId: parsed(parseWalletAuthorityId(record.authorityId)),
    walletAuthMethodId: parsed(parseWalletAuthMethodId(record.walletAuthMethodId)),
    packageSetDigestB64u: parseDigestB64u(record.packageSetDigestB64u),
    authorizationId: parsed(parseWalletSessionAuthorizationId(record.authorizationId)),
    walletSessionId: parsed(parseWalletSessionId(record.walletSessionId)),
    credentialDigestB64u: parseDigestB64u(record.credentialDigestB64u),
    installationReceiptDigestB64u: parseDigestB64u(record.installationReceiptDigestB64u),
    acknowledgedAtMs,
    expiresAtMs,
  };
}

export async function assertLinkedDeviceWalletSessionCredentialDeliveryIntegrityV1(
  delivery: LinkedDeviceWalletSessionCredentialDeliveryV1,
): Promise<void> {
  const aadDigest = await computeLinkedDeviceWalletSessionCredentialDeliveryAadDigestB64u(
    delivery.aad,
  );
  if (aadDigest !== delivery.aadDigestB64u) {
    throw new Error('linked-device Wallet Session credential delivery AAD digest is invalid');
  }
  const envelopeDigest = await computeLinkedDeviceWalletSessionCredentialEnvelopeDigestB64u(
    delivery.envelope,
  );
  if (envelopeDigest !== delivery.envelopeDigestB64u) {
    throw new Error('linked-device Wallet Session credential delivery envelope digest is invalid');
  }
  const recipientBindingDigest = parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        alphabetizeStringify({
          domain: 'seams/linked-device/delivery-recipient/v1',
          recipientPublicKey65B64u: delivery.aad.recipientPublicKey65B64u,
        }),
      ),
    ),
  );
  if (recipientBindingDigest !== delivery.recipientBindingDigestB64u) {
    throw new Error('linked-device Wallet Session credential delivery recipient binding is invalid');
  }
}

export function parseLinkedDeviceWalletSessionCredentialDeliveryV1(
  raw: unknown,
): LinkedDeviceWalletSessionCredentialDeliveryV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'aad',
      'aadDigestB64u',
      'recipientBindingDigestB64u',
      'envelope',
      'envelopeDigestB64u',
      'installationReceiptDigestB64u',
    ],
    'LinkedDeviceWalletSessionCredentialDeliveryV1',
  );
  if (record.kind !== 'linked_device_wallet_session_credential_delivery_v1') {
    throw new Error('LinkedDeviceWalletSessionCredentialDeliveryV1.kind is invalid');
  }
  return {
    kind: 'linked_device_wallet_session_credential_delivery_v1',
    aad: parseDeliveryAad(record.aad),
    aadDigestB64u: parseDigestB64u(record.aadDigestB64u),
    recipientBindingDigestB64u: parseDigestB64u(record.recipientBindingDigestB64u),
    envelope: parseDeliveryEnvelope(record.envelope),
    envelopeDigestB64u: parseDigestB64u(record.envelopeDigestB64u),
    installationReceiptDigestB64u: parseDigestB64u(record.installationReceiptDigestB64u),
  };
}

function parseDeliveryAad(raw: unknown): LinkedDeviceWalletSessionCredentialDeliveryAadV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'namespace',
      'orgId',
      'projectId',
      'envId',
      'tenantId',
      'principalId',
      'linkSessionId',
      'walletId',
      'authorityId',
      'walletAuthMethodId',
      'authorizationId',
      'walletSessionId',
      'quotaId',
      'credentialDigestB64u',
      'recipientPublicKey65B64u',
      'issuedAtMs',
      'expiresAtMs',
    ],
    'LinkedDeviceWalletSessionCredentialDeliveryAadV1',
  );
  if (record.kind !== 'linked_device_wallet_session_credential_delivery_aad_v1') {
    throw new Error('LinkedDeviceWalletSessionCredentialDeliveryAadV1.kind is invalid');
  }
  const issuedAtMs = positiveInteger(record.issuedAtMs, 'issuedAtMs');
  const expiresAtMs = positiveInteger(record.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs <= issuedAtMs) throw new Error('expiresAtMs must be after issuedAtMs');
  return {
    kind: 'linked_device_wallet_session_credential_delivery_aad_v1',
    namespace: nonEmpty(record.namespace, 'namespace'),
    orgId: nonEmpty(record.orgId, 'orgId'),
    projectId: nonEmpty(record.projectId, 'projectId'),
    envId: nonEmpty(record.envId, 'envId'),
    tenantId: parsed(parseTenantId(record.tenantId)),
    principalId: parsed(parsePrincipalId(record.principalId)),
    linkSessionId: parsed(parseLinkDeviceSessionId(record.linkSessionId)),
    walletId: parsed(parseWalletId(record.walletId)),
    authorityId: parsed(parseWalletAuthorityId(record.authorityId)),
    walletAuthMethodId: parsed(parseWalletAuthMethodId(record.walletAuthMethodId)),
    authorizationId: parsed(parseWalletSessionAuthorizationId(record.authorizationId)),
    walletSessionId: parsed(parseWalletSessionId(record.walletSessionId)),
    quotaId: parsed(parseMpcWalletSigningQuotaId(record.quotaId)),
    credentialDigestB64u: parseDigestB64u(record.credentialDigestB64u),
    recipientPublicKey65B64u: fixedBase64Url(record.recipientPublicKey65B64u, 65),
    issuedAtMs,
    expiresAtMs,
  };
}

function parseDeliveryEnvelope(raw: unknown): LinkedDeviceWalletSessionCredentialEnvelopeV1 {
  const record = exactRecord(
    raw,
    ['kind', 'algorithm', 'serverEphemeralPublicKey65B64u', 'nonce12B64u', 'ciphertextB64u'],
    'LinkedDeviceWalletSessionCredentialEnvelopeV1',
  );
  if (
    record.kind !== 'linked_device_wallet_session_credential_envelope_v1' ||
    record.algorithm !== 'p256-ecdh-aes256gcm-v1'
  ) {
    throw new Error('LinkedDeviceWalletSessionCredentialEnvelopeV1 identity is invalid');
  }
  return {
    kind: 'linked_device_wallet_session_credential_envelope_v1',
    algorithm: 'p256-ecdh-aes256gcm-v1',
    serverEphemeralPublicKey65B64u: fixedBase64Url(record.serverEphemeralPublicKey65B64u, 65),
    nonce12B64u: fixedBase64Url(record.nonce12B64u, 12),
    ciphertextB64u: canonicalBase64Url(record.ciphertextB64u),
  };
}

function exactRecord(
  raw: unknown,
  fields: readonly string[],
  label: string,
): Readonly<Record<string, unknown>> {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error(`${label} must be an object`);
  }
  const record = raw as Readonly<Record<string, unknown>>;
  const expected = new Set(fields);
  for (const field of Object.keys(record)) {
    if (!expected.has(field)) throw new Error(`${label}.${field} is not supported`);
  }
  for (const field of fields) {
    if (!(field in record)) throw new Error(`${label}.${field} is required`);
  }
  return record;
}

function nonEmpty(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${label} is required`);
  }
  return raw;
}

function positiveInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) <= 0) throw new Error(`${label} is invalid`);
  return Number(raw);
}

function canonicalBase64Url(raw: unknown): string {
  const encoded = nonEmpty(raw, 'base64url');
  const bytes = base64UrlDecode(encoded);
  if (base64UrlEncode(bytes) !== encoded) throw new Error('base64url is not canonical');
  return encoded;
}

function fixedBase64Url(raw: unknown, length: number): string {
  const encoded = canonicalBase64Url(raw);
  const bytes = base64UrlDecode(encoded);
  if (bytes.length !== length) throw new Error(`base64url must contain ${length} bytes`);
  if (length === 65 && bytes[0] !== 4) throw new Error('P-256 public key is invalid');
  return encoded;
}

function parsed<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: { readonly message: string } }): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}
