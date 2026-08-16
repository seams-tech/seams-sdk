/**
 * Compile-time proof that the Refactor 103 Phase 8 owner-auth binding cannot
 * represent a device whose credential identity disagrees with its factor
 * branch, whose lifecycle carries the wrong timestamps, or whose core identity
 * is optional.
 */
import type {
  LinkedDeviceOwnerAuthBindingV1,
  LinkedOwnerAuthBindingLifecycleV1,
  LinkedOwnerAuthFactorV1,
} from './ownerAuthBinding';
import type { TenantId } from '../authorization/capabilityKinds';
import type { LinkedDeviceEnrollmentId, LinkedDeviceId } from '../signing-lanes/ids';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type {
  WalletAuthMethodId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';

declare const tenantId: TenantId;
declare const walletId: WalletId;
declare const enrollmentId: LinkedDeviceEnrollmentId;
declare const deviceId: LinkedDeviceId;
declare const walletAuthMethodId: WalletAuthMethodId;
declare const keyManifestDigestB64u: DigestB64u;
declare const rpId: WebAuthnRpId;
declare const credentialIdB64u: WebAuthnCredentialIdB64u;
declare const emailHashHex: string;
declare const registrationAuthorityId: string;

const passkeyFactor: LinkedOwnerAuthFactorV1 = {
  kind: 'passkey',
  rpId,
  credentialIdB64u,
};

const emailOtpFactor: LinkedOwnerAuthFactorV1 = {
  kind: 'email_otp',
  emailHashHex,
  registrationAuthorityId,
};

// @ts-expect-error a Passkey factor cannot carry Email OTP identity
const invalidPasskeyCarriesEmail: LinkedOwnerAuthFactorV1 = {
  ...passkeyFactor,
  emailHashHex,
};

// @ts-expect-error an Email OTP factor cannot carry WebAuthn credential identity
const invalidEmailOtpCarriesCredential: LinkedOwnerAuthFactorV1 = {
  ...emailOtpFactor,
  credentialIdB64u,
};

// @ts-expect-error an Email OTP factor cannot carry a WebAuthn relying party
const invalidEmailOtpCarriesRpId: LinkedOwnerAuthFactorV1 = {
  ...emailOtpFactor,
  rpId,
};

// @ts-expect-error a Passkey factor requires its exact credential id
const invalidPasskeyWithoutCredential: LinkedOwnerAuthFactorV1 = {
  kind: 'passkey',
  rpId,
};

// @ts-expect-error an Email OTP factor requires its registration authority
const invalidEmailOtpWithoutAuthority: LinkedOwnerAuthFactorV1 = {
  kind: 'email_otp',
  emailHashHex,
};

const activeLifecycle: LinkedOwnerAuthBindingLifecycleV1 = {
  state: 'active',
  activatedAtMs: 1,
};

const pausedLifecycle: LinkedOwnerAuthBindingLifecycleV1 = {
  state: 'paused',
  activatedAtMs: 1,
  pausedAtMs: 2,
};

const revokedLifecycle: LinkedOwnerAuthBindingLifecycleV1 = {
  state: 'revoked',
  activatedAtMs: 1,
  revokedAtMs: 3,
};

// @ts-expect-error an active lifecycle cannot carry a revocation timestamp
const invalidActiveRevoked: LinkedOwnerAuthBindingLifecycleV1 = {
  ...activeLifecycle,
  revokedAtMs: 3,
};

// @ts-expect-error a paused lifecycle cannot carry a revocation timestamp
const invalidPausedRevoked: LinkedOwnerAuthBindingLifecycleV1 = {
  ...pausedLifecycle,
  revokedAtMs: 3,
};

// @ts-expect-error a revoked lifecycle cannot claim it is merely paused
const invalidRevokedPaused: LinkedOwnerAuthBindingLifecycleV1 = {
  ...revokedLifecycle,
  pausedAtMs: 2,
};

// @ts-expect-error a paused lifecycle requires its pause timestamp
const invalidPausedWithoutTimestamp: LinkedOwnerAuthBindingLifecycleV1 = {
  state: 'paused',
  activatedAtMs: 1,
};

const passkeyBinding: LinkedDeviceOwnerAuthBindingV1 = {
  kind: 'linked_device_owner_auth_binding_v1',
  tenantId,
  walletId,
  enrollmentId,
  deviceId,
  walletAuthMethodId,
  factor: passkeyFactor,
  keyManifestDigestB64u,
  lifecycle: activeLifecycle,
  revocationEpoch: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
};

const emailOtpBinding: LinkedDeviceOwnerAuthBindingV1 = {
  ...passkeyBinding,
  factor: emailOtpFactor,
};

// @ts-expect-error a binding cannot omit its canonical owner auth-method id
const invalidBindingWithoutAuthMethod: LinkedDeviceOwnerAuthBindingV1 = {
  kind: 'linked_device_owner_auth_binding_v1',
  tenantId,
  walletId,
  enrollmentId,
  deviceId,
  factor: passkeyFactor,
  keyManifestDigestB64u,
  lifecycle: activeLifecycle,
  revocationEpoch: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
};

// @ts-expect-error a binding cannot omit the tenant it is scoped to
const invalidBindingWithoutTenant: LinkedDeviceOwnerAuthBindingV1 = {
  kind: 'linked_device_owner_auth_binding_v1',
  walletId,
  enrollmentId,
  deviceId,
  walletAuthMethodId,
  factor: passkeyFactor,
  keyManifestDigestB64u,
  lifecycle: activeLifecycle,
  revocationEpoch: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
};

// @ts-expect-error a binding cannot omit the verified key-manifest identity
const invalidBindingWithoutManifest: LinkedDeviceOwnerAuthBindingV1 = {
  kind: 'linked_device_owner_auth_binding_v1',
  tenantId,
  walletId,
  enrollmentId,
  deviceId,
  walletAuthMethodId,
  factor: passkeyFactor,
  lifecycle: activeLifecycle,
  revocationEpoch: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
};

// @ts-expect-error a binding cannot omit its device enrollment identity
const invalidBindingWithoutEnrollment: LinkedDeviceOwnerAuthBindingV1 = {
  kind: 'linked_device_owner_auth_binding_v1',
  tenantId,
  walletId,
  deviceId,
  walletAuthMethodId,
  factor: passkeyFactor,
  keyManifestDigestB64u,
  lifecycle: activeLifecycle,
  revocationEpoch: 0,
  createdAtMs: 1,
  updatedAtMs: 1,
};

const invalidBindingKind: LinkedDeviceOwnerAuthBindingV1 = {
  ...passkeyBinding,
  // @ts-expect-error the binding kind is exact
  kind: 'linked_device_target_credential_registration_v1',
};

