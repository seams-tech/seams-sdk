/**
 * Branch-specific builders for the Refactor 103 Phase 8 owner-auth binding.
 *
 * Both construct through the production builders, so a change to the domain
 * type or to the canonical `WalletAuthMethodId` derivation surfaces here as a
 * type error rather than as a fixture that quietly encodes the old shape.
 * Rejection-path tests take one of these and apply a visible corrupting
 * override at the call site.
 */
import {
  buildLinkedOwnerEmailOtpAuthBindingV1,
  buildLinkedOwnerPasskeyAuthBindingV1,
  linkedOwnerEmailOtpBaseAuthMethodIdV1,
  type LinkedDeviceOwnerAuthBindingV1,
} from '../../../packages/shared-ts/src/device-linking/ownerAuthBinding';
import { parseTenantId } from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
} from '../../../packages/shared-ts/src/signing-lanes/ids';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import {
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../../packages/shared-ts/src/utils/domainIds';
import type { WalletAuthMethodRecord } from '../../../packages/shared-ts/src/utils/registrationIntent';
import { normalizeWalletAuthMethod } from '../../../packages/wallet-server/src/core/d1WalletAuthMethodStore';

const KEY_MANIFEST_DIGEST_B64U = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(7)));
const EMAIL_HASH_HEX = 'b'.repeat(64);

export const LINKED_OWNER_BINDING_ACTIVATED_AT_MS = 1_800_000_000_000;

export type LinkedOwnerAuthBindingFixtureOverridesV1 = {
  readonly walletId?: string;
  readonly enrollmentId?: string;
  readonly deviceId?: string;
  readonly keyManifestDigestB64u?: string;
  readonly activatedAtMs?: number;
};

export function buildLinkedOwnerPasskeyBindingFixtureV1(
  overrides: LinkedOwnerAuthBindingFixtureOverridesV1 & {
    readonly rpId?: string;
    readonly credentialIdB64u?: string;
  } = {},
): LinkedDeviceOwnerAuthBindingV1 {
  return buildLinkedOwnerPasskeyAuthBindingV1({
    ...bindingIdentity(overrides),
    rpId: required(parseWebAuthnRpId(overrides.rpId ?? 'wallet.example.localhost')),
    credentialIdB64u: required(
      parseWebAuthnCredentialIdB64u(overrides.credentialIdB64u ?? 'credential-device-2'),
    ),
  });
}

export function buildLinkedOwnerEmailOtpBindingFixtureV1(
  overrides: LinkedOwnerAuthBindingFixtureOverridesV1 & {
    readonly emailHashHex?: string;
    readonly registrationAuthorityId?: string;
  } = {},
): LinkedDeviceOwnerAuthBindingV1 {
  const identity = bindingIdentity(overrides);
  const emailHashHex = overrides.emailHashHex ?? EMAIL_HASH_HEX;
  const registrationAuthorityId = overrides.registrationAuthorityId ?? 'google';
  return buildLinkedOwnerEmailOtpAuthBindingV1({
    ...identity,
    emailHashHex,
    registrationAuthorityId,
    // Derived through the production formatter so the fixture's base reference
    // is the exact wallet-wide row a real enrollment would point at.
    baseWalletAuthMethodId: linkedOwnerEmailOtpBaseAuthMethodIdV1({
      walletId: identity.walletId,
      emailHashHex,
      registrationAuthorityId,
    }),
  });
}

export function buildActiveEmailOtpWalletAuthMethodFixtureV1(
  overrides: {
    readonly walletId?: string;
    readonly emailHashHex?: string;
    readonly registrationAuthorityId?: string;
    readonly createdAtMs?: number;
  } = {},
): Extract<WalletAuthMethodRecord, { readonly kind: 'email_otp'; readonly status: 'active' }> {
  const createdAtMs = overrides.createdAtMs ?? LINKED_OWNER_BINDING_ACTIVATED_AT_MS;
  const record = normalizeWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    walletId: overrides.walletId ?? 'wallet:r103p8',
    emailHashHex: overrides.emailHashHex ?? EMAIL_HASH_HEX,
    registrationAuthorityId: overrides.registrationAuthorityId ?? 'google',
    createdAtMs,
    updatedAtMs: createdAtMs,
  });
  if (!record || record.kind !== 'email_otp' || record.status !== 'active') {
    throw new Error('active Email OTP wallet auth-method fixture is invalid');
  }
  return record;
}

function bindingIdentity(overrides: LinkedOwnerAuthBindingFixtureOverridesV1) {
  return {
    tenantId: required(parseTenantId('tenant:r103p8')),
    walletId: required(parseWalletId(overrides.walletId ?? 'wallet:r103p8')),
    enrollmentId: required(
      parseLinkedDeviceEnrollmentId(overrides.enrollmentId ?? 'enrollment:r103p8'),
    ),
    deviceId: required(parseLinkedDeviceId(overrides.deviceId ?? 'device:r103p8')),
    keyManifestDigestB64u: overrides.keyManifestDigestB64u
      ? parseDigestB64u(overrides.keyManifestDigestB64u)
      : KEY_MANIFEST_DIGEST_B64U,
    activatedAtMs: overrides.activatedAtMs ?? LINKED_OWNER_BINDING_ACTIVATED_AT_MS,
  };
}

function required<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}
