import {
  buildExactAdministeredSignerManifestV1,
  type ExactAdministeredSignerManifestV1,
} from '@shared/device-linking/delegatedActivationPlan';
import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  OrdinarySignerMaterialReservationPreparationV1,
  VerifiedLinkInputV1,
  VerifiedSourceAuthorityV1,
  VerifiedTargetFactorV1,
} from '@shared/device-linking/contracts';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  buildDelegatedWalletAuthorityV1,
  validateDelegatedWalletAuthorityAttenuationV1,
} from '@shared/authorization/delegatedAuthority';
import {
  walletAuthorityDigestsMatchV1,
} from '@shared/authorization/walletAuthority';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type {
  WalletAuthMethodRecordV2,
  PasskeyWalletAuthMethodDraftV1,
  EmailOtpWalletAuthMethodDraftV1,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { parseDeviceId } from '@shared/authorization/capabilityKinds';
import type { LinkedDeviceSessionRecordV1 } from '../../../../core/deviceLinking/linkedDeviceSession';
import type { VerifiedLinkedDeviceTargetFactorEvidenceV1 } from './d1LinkedDeviceTargetCredentialProvider';

const VERIFIED_TARGET_FACTOR_DOMAIN_V1 = 'seams/linked-device/verified-target-factor/v1';

export type VerifiedLinkSourceReadV1 = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly signerManifest: ExactAdministeredSignerManifestV1;
  readonly authorityDigestB64u: DigestB64u;
  readonly verifiedRevocationEpoch: number;
  readonly verifiedAtMs: number;
};

/**
 * Narrow source-authority port. The implementation performs the Wallet
 * Session V2 -> auth method -> authority read at its D1 boundary.
 */
export type VerifiedLinkSourceReaderV1 = {
  readVerifiedSourceV1(input: {
    readonly walletId: VerifiedLinkInputV1['walletId'];
    readonly walletSessionId: string;
    readonly authorizationId: string;
    readonly requestedAtMs: number;
  }): Promise<VerifiedLinkSourceReadV1>;
};

export type BuildVerifiedLinkInputV1 = {
  readonly session: LinkedDeviceSessionRecordV1;
  readonly approval: LinkedDeviceApprovalV1;
  readonly preparation: LinkedDeviceTargetPreparationV1;
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
  readonly source: VerifiedLinkSourceReaderV1;
  readonly requestedAtMs: number;
};

export async function buildVerifiedLinkInputV1(
  input: BuildVerifiedLinkInputV1,
): Promise<VerifiedLinkInputV1> {
  assertRegistrationIdentity(input);
  if (input.approval.ownerAuthorization.kind !== 'wallet_session') {
    throw new Error('verified device linking requires an ordinary Wallet Session');
  }
  const source = await input.source.readVerifiedSourceV1({
    walletId: input.registration.walletId,
    walletSessionId: String(input.approval.ownerAuthorization.walletSessionId),
    authorizationId: String(input.approval.ownerAuthorization.authorizationId),
    requestedAtMs: input.requestedAtMs,
  });
  await assertSourceRead(source, input.registration.walletId, input.requestedAtMs);
  const targetFactor = await buildVerifiedTargetFactorV1(input);
  assertPermissionAttenuation(source.authority, input.approval.permission);
  assertSourceManifestMatchesAuthority(source.authority, source.signerManifest);
  assertPreparationFamiliesMatchManifest(
    input.registration.ordinarySignerMaterialPreparations,
    source.signerManifest,
  );
  const sourceAuthority: VerifiedSourceAuthorityV1 = {
    authority: source.authority,
    authMethodId: source.authMethod.walletAuthMethodId,
    verifiedRevocationEpoch: source.verifiedRevocationEpoch,
    authorityDigestB64u: source.authorityDigestB64u,
    verifiedAtMs: source.verifiedAtMs,
  };
  return {
    walletId: input.registration.walletId,
    linkSessionId: input.registration.linkSessionId,
    enrollmentId: input.registration.enrollmentId,
    targetDeviceId: parseTargetDeviceId(input.registration.deviceId),
    sourceAuthority,
    targetFactor,
    permissions: input.approval.permission.permissions,
    signerManifest: source.signerManifest,
    ordinarySignerMaterialPreparations: input.registration.ordinarySignerMaterialPreparations,
  };
}

export async function computeVerifiedTargetFactorVerificationDigestV1(input: {
  readonly registration: LinkedDeviceTargetCredentialRegistrationV1;
  readonly evidence: VerifiedLinkedDeviceTargetFactorEvidenceV1;
  readonly verifiedAtMs: number;
}): Promise<DigestB64u> {
  const evidence = input.evidence.kind === 'passkey_prf'
    ? {
        kind: input.evidence.kind,
        credentialIdB64u: input.evidence.credential.credentialIdB64u,
        credentialPublicKeyB64u: input.evidence.credential.credentialPublicKeyB64u,
        counter: input.evidence.credential.counter,
      }
    : {
        kind: input.evidence.kind,
        grantId: input.evidence.grant.grantId,
        baseWalletAuthMethodId: input.evidence.grant.baseWalletAuthMethodId,
        linkedOwnerAuthMethodId: input.evidence.grant.linkedOwnerAuthMethodId,
        authorityDigestB64u: input.evidence.grant.authorityDigestB64u,
        descriptorCredentialIdB64u: input.evidence.grant.descriptorCredentialIdB64u,
      };
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `${VERIFIED_TARGET_FACTOR_DOMAIN_V1}\u0000${alphabetizeStringify({
          linkSessionId: input.registration.linkSessionId,
          walletId: input.registration.walletId,
          enrollmentId: input.registration.enrollmentId,
          deviceId: input.registration.deviceId,
          walletAuthMethodId: input.registration.walletAuthMethodId,
          targetPreparationDigestB64u: input.registration.targetPreparationDigestB64u,
          verifiedAtMs: input.verifiedAtMs,
          evidence,
        })}`,
      ),
    ),
  );
}

async function buildVerifiedTargetFactorV1(
  input: BuildVerifiedLinkInputV1,
): Promise<VerifiedTargetFactorV1> {
  const verifiedAtMs = input.registration.registeredAtMs;
  if (!Number.isSafeInteger(verifiedAtMs) || verifiedAtMs < 0 || verifiedAtMs > input.requestedAtMs) {
    throw new Error('target factor verification time is invalid');
  }
  const verificationDigestB64u = await computeVerifiedTargetFactorVerificationDigestV1({
    registration: input.registration,
    evidence: input.evidence,
    verifiedAtMs,
  });
  if (input.registration.targetFactor.kind === 'passkey_prf') {
    if (input.evidence.kind !== 'passkey_prf' || !input.registration.webauthnRegistration) {
      throw new Error('Passkey target factor evidence is missing');
    }
    if (
      input.registration.webauthnRegistration.credentialIdB64u !==
      input.evidence.credential.credentialIdB64u
    ) {
      throw new Error('Passkey target factor credential identity changed');
    }
    const authMethod: PasskeyWalletAuthMethodDraftV1 = {
      walletAuthMethodId: input.registration.walletAuthMethodId,
      walletId: input.registration.walletId,
      createdAtMs: verifiedAtMs,
      kind: 'passkey',
      rpId: requirePasskeyRpId(input.preparation),
      credentialIdB64u: requireCredentialId(input.evidence.credential.credentialIdB64u),
      credentialPublicKeyB64u: canonicalBase64Url(
        input.evidence.credential.credentialPublicKeyB64u,
        'Passkey credential public key',
      ),
      counter: requireCounter(input.evidence.credential.counter),
    };
    return { kind: 'verified_passkey_target_v1', authMethod, verificationDigestB64u, verifiedAtMs };
  }
  if (input.evidence.kind !== 'email_otp' || !input.registration.emailOtpVerificationGrant) {
    throw new Error('Email OTP target factor evidence is missing');
  }
  const grant = input.registration.emailOtpVerificationGrant;
  if (
    grant.linkSessionId !== input.registration.linkSessionId ||
    grant.walletId !== input.registration.walletId ||
    grant.enrollmentId !== input.registration.enrollmentId ||
    grant.deviceId !== input.registration.deviceId ||
    grant.targetPreparationDigestB64u !== input.registration.targetPreparationDigestB64u ||
    grant.grantId !== input.evidence.grant.grantId ||
    grant.authorityDigestB64u !== input.evidence.grant.authorityDigestB64u ||
    String(grant.linkedOwnerAuthMethodId) !==
      String(input.evidence.grant.linkedOwnerAuthMethodId)
  ) {
    throw new Error('Email OTP target factor grant identity changed');
  }
  const authMethod: EmailOtpWalletAuthMethodDraftV1 = {
    walletAuthMethodId: input.registration.walletAuthMethodId,
    walletId: input.registration.walletId,
    createdAtMs: grant.issuedAtMs,
    kind: 'email_otp',
    emailHashHex: grant.emailHashHex,
    registrationAuthorityId: grant.registrationAuthorityId,
  };
  return { kind: 'verified_email_otp_target_v1', authMethod, verificationDigestB64u, verifiedAtMs };
}

async function assertSourceRead(
  source: VerifiedLinkSourceReadV1,
  walletId: VerifiedLinkInputV1['walletId'],
  requestedAtMs: number,
): Promise<void> {
  if (source.authority.state !== 'active' || source.authority.walletId !== walletId) {
    throw new Error('source authority is not active for the requested wallet');
  }
  if (
    source.authMethod.status !== 'active' ||
    source.authMethod.walletId !== walletId ||
    source.authMethod.walletAuthorityId !== source.authority.authorityId
  ) {
    throw new Error('source Wallet Auth Method is not active for the source authority');
  }
  if (source.authorityDigestB64u !== source.authority.authorityDigestB64u) {
    throw new Error('source authority digest claim does not match the authority');
  }
  if (!(await walletAuthorityDigestsMatchV1(source.authority))) {
    throw new Error('source authority digest is invalid');
  }
  if (source.verifiedRevocationEpoch !== source.authority.revocationEpoch) {
    throw new Error('source authority revocation epoch is stale');
  }
  if (
    !Number.isSafeInteger(source.verifiedAtMs) ||
    source.verifiedAtMs < 0 ||
    source.verifiedAtMs > requestedAtMs
  ) {
    throw new Error('source authority verification time is invalid');
  }
  if (!source.authority.permissions.includes('link_devices')) {
    throw new Error('source authority does not grant link_devices');
  }
}

function assertRegistrationIdentity(input: BuildVerifiedLinkInputV1): void {
  const { registration, preparation, session, approval } = input;
  if (
    registration.linkSessionId !== session.linkSessionId ||
    registration.linkSessionId !== approval.linkSessionId ||
    registration.linkSessionId !== preparation.linkSessionId ||
    registration.walletId !== approval.walletId ||
    registration.walletId !== preparation.walletId ||
    registration.enrollmentId !== approval.enrollmentId ||
    registration.enrollmentId !== preparation.enrollmentId ||
    registration.deviceId !== approval.deviceId ||
    registration.deviceId !== preparation.deviceId ||
    registration.targetPreparationDigestB64u.length === 0
  ) {
    throw new Error('verified link identities do not match the approved session');
  }
  if (
    session.state.state !== 'awaiting_target_factor' &&
    session.state.state !== 'provisioning'
  ) {
    throw new Error(`verified link cannot commit from ${session.state.state}`);
  }
}

function parseTargetDeviceId(value: string): VerifiedLinkInputV1['targetDeviceId'] {
  const parsed = parseDeviceId(String(value));
  if (!parsed.ok) throw new Error(`target device id is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function requireCredentialId(value: string): PasskeyWalletAuthMethodDraftV1['credentialIdB64u'] {
  const parsed = parseWebAuthnCredentialIdB64u(value);
  if (!parsed.ok) throw new Error(`Passkey credential id is invalid: ${parsed.error.message}`);
  return parsed.value;
}

function requirePasskeyRpId(
  preparation: LinkedDeviceTargetPreparationV1,
): PasskeyWalletAuthMethodDraftV1['rpId'] {
  if (preparation.targetFactor.kind !== 'passkey_prf') {
    throw new Error('Passkey target factor preparation is missing');
  }
  if (!preparation.ownerEnrollment.registration) {
    throw new Error('Passkey target factor registration options are missing');
  }
  return preparation.ownerEnrollment.registration.rpId;
}

function assertPermissionAttenuation(
  source: ActiveWalletAuthorityV1,
  requested: { readonly permissions: VerifiedLinkInputV1['permissions'] },
): void {
  const result = validateDelegatedWalletAuthorityAttenuationV1({
    parent: buildDelegatedWalletAuthorityV1({ permissions: source.permissions }),
    child: buildDelegatedWalletAuthorityV1({ permissions: requested.permissions }),
  });
  if (!result.ok) throw new Error(result.error.message);
}

function assertSourceManifestMatchesAuthority(
  authority: ActiveWalletAuthorityV1,
  manifest: ExactAdministeredSignerManifestV1,
): void {
  const expected = manifestFromAuthority(authority);
  if (alphabetizeStringify(expected) !== alphabetizeStringify(manifest)) {
    throw new Error('source signer manifest does not match the active authority');
  }
}

function manifestFromAuthority(authority: ActiveWalletAuthorityV1): ExactAdministeredSignerManifestV1 {
  const signers = authority.signerActivations.keyFamilies.map((family) => {
    if (family === 'ed25519') {
      if (!authority.signerActivations.ed25519) throw new Error('source Ed25519 activation is missing');
      return authority.signerActivations.ed25519.signer;
    }
    if (!authority.signerActivations.ecdsa) throw new Error('source ECDSA activation is missing');
    return authority.signerActivations.ecdsa.signer;
  });
  return buildExactAdministeredSignerManifestV1(signers);
}

function assertPreparationFamiliesMatchManifest(
  preparations: readonly OrdinarySignerMaterialReservationPreparationV1[],
  manifest: ExactAdministeredSignerManifestV1,
): void {
  const families = preparations.map((entry) =>
    entry.kind === 'ordinary_ed25519_signer_material_reservation_preparation_v1'
      ? 'ed25519'
      : 'ecdsa_secp256k1',
  );
  if (
    families.length !== manifest.keyFamilies.length ||
    families.some((family, index) => family !== manifest.keyFamilies[index])
  ) {
    throw new Error('ordinary material preparation families do not match the source manifest');
  }
}

function canonicalBase64Url(value: string, label: string): string {
  try {
    const bytes = base64UrlDecode(value);
    if (bytes.length === 0 || base64UrlEncode(bytes) !== value) throw new Error('is not canonical base64url');
    return value;
  } catch (error: unknown) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function requireCounter(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error('Passkey counter is invalid');
  return value;
}
