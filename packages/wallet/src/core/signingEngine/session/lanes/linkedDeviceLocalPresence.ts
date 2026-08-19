import {
  computeLinkedDeviceLocalPresenceChallengeDigestV1,
  computeLinkedDeviceTargetPreparationDigestV1,
} from '@shared/device-linking/digests';
import type {
  LinkedDeviceEmailOtpVerificationGrantV1,
  LinkedDeviceLocalPresenceAssertionV1,
} from '@shared/device-linking';
import type { AuthorizedOperationId } from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode } from '@shared/utils/base64';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { AuthenticatorPort } from '@/core/platform';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import type {
  LaneSealedHolderMaterialRepositoryV1,
  LaneSealedHolderRecordV1,
} from '@/core/indexedDB/seamsWalletDB/laneHolderMaterialStore';
import type {
  ActiveLinkedDeviceExecutionBundleV1,
  ActiveLinkedDeviceExecutionChildV1,
} from './linkedDeviceExecutionBundle';
import type {
  DeviceLinkingHolderSigningMaterialHandleV1,
  DeviceLinkingHolderSigningMaterialPortV1,
} from './linkedDevicePorts';

/**
 * Passkey local presence remains the existing WebAuthn assertion. Email OTP
 * uses the consumed, intent-bound registration grant and carries the derived
 * linked-owner authority without falling back to the wallet-wide factor.
 */
export type LinkedDeviceEmailOtpFactorAuthorizationV1 = {
  readonly kind: 'linked_device_email_otp_factor_authorization_v1';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly deviceId: ActiveLinkedDeviceExecutionBundleV1['deviceId'];
  readonly enrollmentId: ActiveLinkedDeviceExecutionBundleV1['enrollmentId'];
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly verificationGrant: LinkedDeviceEmailOtpVerificationGrantV1;
  readonly linkedOwnerAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
};

export type LinkedDeviceFactorAuthorizationV1 =
  | LinkedDeviceLocalPresenceAssertionV1
  | LinkedDeviceEmailOtpFactorAuthorizationV1;

export type LinkedDevicePresenceAndHolderV1<TAuthorizationResult> = {
  readonly localPresenceAssertion: LinkedDeviceFactorAuthorizationV1;
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialHandleV1;
  readonly authorizationResult: TAuthorizationResult;
};

export type LinkedDeviceLocalPresenceAuthenticationV1 =
  | {
      readonly factor: 'passkey_prf';
      readonly localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1;
      readonly factorSecret: Uint8Array;
    }
  | {
      readonly factor: 'email_otp';
      readonly localPresenceAssertion: LinkedDeviceEmailOtpFactorAuthorizationV1;
      readonly factorSecret?: never;
    };

function assertPresenceLifetime(input: {
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly walletSessionExpiresAtMs: number;
}): void {
  if (
    !Number.isSafeInteger(input.issuedAtMs) ||
    !Number.isSafeInteger(input.expiresAtMs) ||
    input.issuedAtMs < 0 ||
    input.issuedAtMs >= input.expiresAtMs ||
    input.expiresAtMs > input.walletSessionExpiresAtMs
  ) {
    throw new Error('linked-device local presence lifetime is invalid');
  }
}

function assertExecutionChildParent(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
}): void {
  if (
    String(input.child.job.enrollmentId) !== String(input.bundle.enrollmentId) ||
    String(input.child.job.walletId) !== String(input.bundle.walletId)
  ) {
    throw new Error('linked-device execution child changed its active parent');
  }
}

function requireExactCredential(input: {
  readonly credential: WebAuthnAuthenticationCredential;
  readonly returnedCredentialIdB64u: string;
  readonly expectedCredentialIdB64u: string;
  readonly returnedRpId: string;
  readonly expectedRpId: string;
}): WebAuthnAuthenticationCredential {
  if (
    input.returnedCredentialIdB64u !== input.expectedCredentialIdB64u ||
    input.credential.id !== input.expectedCredentialIdB64u ||
    input.credential.rawId !== input.expectedCredentialIdB64u ||
    input.returnedRpId !== input.expectedRpId
  ) {
    throw new Error('linked-device local presence credential binding changed');
  }
  return redactCredentialExtensionOutputs(input.credential);
}

async function requireHolderRecord(input: {
  readonly repository: LaneSealedHolderMaterialRepositoryV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
}): Promise<LaneSealedHolderRecordV1> {
  const record = await input.repository.get(input.child.holderRecordLookup);
  if (!record) throw new Error('linked-device sealed holder material is unavailable');
  return record;
}

export async function authorizeAndOpenLinkedDeviceHolderV1<TAuthorizationResult>(input: {
  readonly authenticator: AuthenticatorPort;
  readonly holderRepository: LaneSealedHolderMaterialRepositoryV1;
  readonly holderMaterial: DeviceLinkingHolderSigningMaterialPortV1;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  readonly authorizeBeforeOpen: (
    assertion: LinkedDeviceFactorAuthorizationV1,
  ) => Promise<TAuthorizationResult>;
}): Promise<LinkedDevicePresenceAndHolderV1<TAuthorizationResult>> {
  const holderRecord = await requireHolderRecord({
    repository: input.holderRepository,
    child: input.child,
  });
  const authentication = await authenticateLinkedDeviceLocalPresenceV1(input);
  if (authentication.factor !== 'passkey_prf') {
    throw new Error(
      'linked-device Email OTP holder opening requires the live worker factor handle',
    );
  }
  let authorizationResult: TAuthorizationResult;
  let holderMaterial: DeviceLinkingHolderSigningMaterialHandleV1;
  try {
    authorizationResult = await input.authorizeBeforeOpen(authentication.localPresenceAssertion);
    holderMaterial = await input.holderMaterial.openPersistedHolderSigningMaterialV1({
      factorSecret: authentication.factorSecret.buffer,
      job: input.child.job,
      protocolCommitReceipt: input.child.protocolCommitReceipt,
      materialActivation: input.child.materialActivation,
      holderRecord,
    });
  } finally {
    authentication.factorSecret.fill(0);
  }
  if (holderMaterial.keyFamily !== input.child.keyFamily) {
    await input.holderMaterial.discardHolderSigningMaterialV1({ handle: holderMaterial });
    throw new Error('linked-device holder material changed its active curve');
  }
  return {
    holderMaterial,
    localPresenceAssertion: authentication.localPresenceAssertion,
    authorizationResult,
  };
}

async function authenticateLinkedDevicePasskeyPresenceV1(input: {
  readonly authenticator: AuthenticatorPort;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<Extract<LinkedDeviceLocalPresenceAuthenticationV1, { readonly factor: 'passkey_prf' }>> {
  const registration = input.bundle.targetCredentialRegistration;
  const preparation = input.bundle.targetPreparation;
  if (
    registration.targetFactor.kind !== 'passkey_prf' ||
    preparation.targetFactor.kind !== 'passkey_prf' ||
    preparation.ownerEnrollment.kind !== 'linked_device_passkey_owner_enrollment_v1'
  ) {
    throw new Error('linked-device Passkey presence crossed an Email OTP target boundary');
  }
  const webauthnRegistration = registration.webauthnRegistration;
  if (!webauthnRegistration) {
    throw new Error('linked-device Passkey registration is missing WebAuthn evidence');
  }
  const credentialIdB64u = webauthnRegistration.credentialIdB64u;
  const challengeDigestB64u = await computeLinkedDeviceLocalPresenceChallengeDigestV1({
    authorizedOperationId: input.authorizedOperationId,
    deviceId: input.bundle.deviceId,
    enrollmentId: input.bundle.enrollmentId,
    credentialIdB64u,
    intentDigestB64u: input.intentDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
  });
  const authentication = await input.authenticator.run({
    kind: 'get_passkey',
    rpId: toRpId(preparation.ownerEnrollment.registration.rpId),
    credentialIdB64u,
    challengeB64u: challengeDigestB64u,
    requirePrfFirst: true,
  });
  if (
    !authentication.ok ||
    authentication.operation !== 'get_passkey' ||
    authentication.requirePrfFirst !== true
  ) {
    throw new Error(
      authentication.ok
        ? 'linked-device local presence returned the wrong authenticator operation'
        : authentication.message,
    );
  }
  const assertion = requireExactCredential({
    credential: authentication.credential,
    returnedCredentialIdB64u: authentication.credentialIdB64u,
    expectedCredentialIdB64u: credentialIdB64u,
    returnedRpId: authentication.rpId,
    expectedRpId: preparation.ownerEnrollment.registration.rpId,
  });
  const factorSecret = base64UrlDecode(authentication.prf.prfFirstB64u);
  if (factorSecret.length !== 32) {
    factorSecret.fill(0);
    throw new Error('linked-device local presence PRF output must be 32 bytes');
  }
  const localPresenceAssertion: LinkedDeviceLocalPresenceAssertionV1 = {
    kind: 'linked_device_local_presence_assertion_v1',
    authorizedOperationId: input.authorizedOperationId,
    deviceId: input.bundle.deviceId,
    enrollmentId: input.bundle.enrollmentId,
    credentialIdB64u,
    intentDigestB64u: input.intentDigestB64u,
    challengeDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    assertion,
  };
  return {
    factor: 'passkey_prf',
    localPresenceAssertion,
    factorSecret,
  };
}

export async function buildLinkedDeviceEmailOtpFactorAuthorizationV1(input: {
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<LinkedDeviceEmailOtpFactorAuthorizationV1> {
  assertPresenceLifetime({
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    walletSessionExpiresAtMs: input.bundle.expiresAtMs,
  });
  const registration = input.bundle.targetCredentialRegistration;
  const preparation = input.bundle.targetPreparation;
  if (
    registration.targetFactor.kind !== 'email_otp' ||
    preparation.targetFactor.kind !== 'email_otp' ||
    preparation.ownerEnrollment.kind !== 'linked_device_email_otp_owner_enrollment_v1'
  ) {
    throw new Error('linked-device Email OTP presence crossed a Passkey target boundary');
  }
  const grant = registration.emailOtpVerificationGrant;
  if (!grant) {
    throw new Error('linked-device Email OTP registration is missing its verification grant');
  }
  const preparationDigestB64u = await computeLinkedDeviceTargetPreparationDigestV1(preparation);
  if (
    registration.targetPreparationDigestB64u !== preparationDigestB64u ||
    grant.targetPreparationDigestB64u !== preparationDigestB64u ||
    grant.linkSessionId !== input.bundle.linkSessionId ||
    grant.walletId !== input.bundle.walletId ||
    grant.enrollmentId !== input.bundle.enrollmentId ||
    grant.deviceId !== input.bundle.deviceId ||
    grant.baseWalletAuthMethodId !== preparation.ownerEnrollment.baseWalletAuthMethodId ||
    grant.issuedAtMs > input.issuedAtMs ||
    input.issuedAtMs >= grant.expiresAtMs ||
    input.expiresAtMs > grant.expiresAtMs ||
    grant.expiresAtMs > input.bundle.expiresAtMs
  ) {
    throw new Error('linked-device Email OTP grant is not bound to this operation and enrollment');
  }
  if (
    grant.linkedOwnerAuthMethodId.length === 0 ||
    grant.authorityDigestB64u.length === 0 ||
    grant.grantToken.length === 0
  ) {
    throw new Error('linked-device Email OTP grant owner authority is incomplete');
  }
  return {
    kind: 'linked_device_email_otp_factor_authorization_v1',
    authorizedOperationId: input.authorizedOperationId,
    deviceId: input.bundle.deviceId,
    enrollmentId: input.bundle.enrollmentId,
    intentDigestB64u: input.intentDigestB64u,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    verificationGrant: grant,
    linkedOwnerAuthMethodId: grant.linkedOwnerAuthMethodId,
    authorityDigestB64u: grant.authorityDigestB64u,
  };
}

export async function authenticateLinkedDeviceLocalPresenceV1(input: {
  readonly authenticator: AuthenticatorPort;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<LinkedDeviceLocalPresenceAuthenticationV1> {
  assertPresenceLifetime({
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.expiresAtMs,
    walletSessionExpiresAtMs: input.bundle.expiresAtMs,
  });
  assertExecutionChildParent(input);
  switch (input.bundle.targetCredentialRegistration.targetFactor.kind) {
    case 'passkey_prf':
      return await authenticateLinkedDevicePasskeyPresenceV1(input);
    case 'email_otp':
      return {
        factor: 'email_otp',
        localPresenceAssertion: await buildLinkedDeviceEmailOtpFactorAuthorizationV1(input),
      };
  }
  input.bundle.targetCredentialRegistration.targetFactor satisfies never;
  throw new Error('linked-device target factor is unsupported');
}

export async function collectLinkedDeviceFactorAuthorizationV1(input: {
  readonly authenticator: AuthenticatorPort;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<LinkedDeviceFactorAuthorizationV1> {
  const authentication = await authenticateLinkedDeviceLocalPresenceV1(input);
  return authentication.localPresenceAssertion;
}

/** Existing Passkey-only callers keep the WebAuthn wire shape. */
export async function collectLinkedDeviceLocalPresenceV1(input: {
  readonly authenticator: AuthenticatorPort;
  readonly bundle: ActiveLinkedDeviceExecutionBundleV1;
  readonly child: ActiveLinkedDeviceExecutionChildV1;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): Promise<LinkedDeviceLocalPresenceAssertionV1> {
  const authentication = await authenticateLinkedDeviceLocalPresenceV1(input);
  if (authentication.factor !== 'passkey_prf') {
    throw new Error(
      'linked-device Email OTP local presence requires the factor-authorization wire contract',
    );
  }
  authentication.factorSecret.fill(0);
  return authentication.localPresenceAssertion;
}
