import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  parseDeviceId,
  type DeviceId,
} from '@shared/authorization/capabilityKinds';
import {
  parsePasskeyEnvelopeId,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWalletRecoveryOperationId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type PasskeyEnvelopeId,
  type WalletAuthMethodId,
  type WalletAuthorityBindingDigest,
  type WalletAuthorityId,
  type WalletId,
  type WalletRecoveryOperationId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import { parseEnvelopeRevision, type EnvelopeRevision } from '@shared/passkey-custody';
import { parseWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  parseWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { parseRecoveryCodeReservationId, type RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type {
  WebAuthnRecoveryContinuityAnchorRecord,
  WebAuthnRecoveryContinuityEnvelopeAnchorRecord,
} from '../webauthn/d1WebAuthnRecords';

export type WalletRecoveryGoogleEmailOtpTargetV1 = {
  readonly kind: 'google_email_otp';
  readonly googleProvider: 'google';
};

export type WalletRecoveryGoogleEmailOtpTargetEnrollmentV1 =
  | {
      readonly kind: 'existing';
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
    }
  | {
      readonly kind: 'create';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
    };

type WalletRecoveryGoogleEmailOtpAttemptCommonV1 = {
  readonly version: 'wallet_recovery_google_email_otp_attempt_v1';
  readonly walletId: WalletId;
  readonly orgId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly target: WalletRecoveryGoogleEmailOtpTargetV1;
  readonly continuityAnchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly recoverySetVersion: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type WalletRecoveryGoogleEmailOtpAttemptRecord =
  | (WalletRecoveryGoogleEmailOtpAttemptCommonV1 & {
      readonly state: 'prepared';
      readonly providerSubject?: never;
      readonly verifiedEmail?: never;
      readonly challengeId?: never;
      readonly ownerProofBindingDigest?: never;
      readonly targetEnrollment?: never;
    })
  | (WalletRecoveryGoogleEmailOtpAttemptCommonV1 & {
      readonly state: 'otp_issued';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly challengeId: string;
      readonly ownerProofBindingDigest: DigestB64u;
      readonly targetEnrollment: WalletRecoveryGoogleEmailOtpTargetEnrollmentV1;
    })
  | (WalletRecoveryGoogleEmailOtpAttemptCommonV1 & {
      readonly state: 'otp_verified';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly challengeId: string;
      readonly ownerProofBindingDigest: DigestB64u;
      readonly targetEnrollment: WalletRecoveryGoogleEmailOtpTargetEnrollmentV1;
    })
  | (WalletRecoveryGoogleEmailOtpAttemptCommonV1 & {
      readonly state: 'finalized';
      readonly providerSubject: string;
      readonly verifiedEmail: string;
      readonly challengeId: string;
      readonly ownerProofBindingDigest: DigestB64u;
      readonly targetEnrollment: WalletRecoveryGoogleEmailOtpTargetEnrollmentV1;
    });

export type PreparedWalletRecoveryGoogleEmailOtpAttempt = Extract<
  WalletRecoveryGoogleEmailOtpAttemptRecord,
  { readonly state: 'prepared' }
>;

export type OtpIssuedWalletRecoveryGoogleEmailOtpAttempt = Extract<
  WalletRecoveryGoogleEmailOtpAttemptRecord,
  { readonly state: 'otp_issued' }
>;

export type OtpVerifiedWalletRecoveryGoogleEmailOtpAttempt = Extract<
  WalletRecoveryGoogleEmailOtpAttemptRecord,
  { readonly state: 'otp_verified' }
>;

export type WalletRecoveryGoogleEmailOtpFinalizationInput = {
  readonly kind: 'wallet_recovery_google_email_otp_finalization_v1';
  readonly walletId: WalletId;
  readonly orgId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly challengeId: string;
  readonly providerSubject: string;
  readonly verifiedEmail: string;
  readonly ownerProofBindingDigest: DigestB64u;
  readonly targetEnrollment: WalletRecoveryGoogleEmailOtpTargetEnrollmentV1;
};

export function walletRecoveryGoogleEmailOtpAttemptKey(
  recoveryOperationId: WalletRecoveryOperationId,
): string {
  return `recovery-operation:${String(recoveryOperationId)}`;
}

export function buildPreparedWalletRecoveryGoogleEmailOtpAttempt(input: {
  readonly walletId: WalletId;
  readonly orgId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly recoveryOperationId: WalletRecoveryOperationId;
  readonly targetDeviceId: DeviceId;
  readonly targetAuthorityId: WalletAuthorityId;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly continuityAnchor: WebAuthnRecoveryContinuityAnchorRecord;
  readonly recoverySetVersion: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
}): PreparedWalletRecoveryGoogleEmailOtpAttempt {
  return {
    version: 'wallet_recovery_google_email_otp_attempt_v1',
    walletId: input.walletId,
    orgId: input.orgId,
    reservationId: input.reservationId,
    recoveryOperationId: input.recoveryOperationId,
    targetDeviceId: input.targetDeviceId,
    targetAuthorityId: input.targetAuthorityId,
    targetWalletAuthMethodId: input.targetWalletAuthMethodId,
    target: { kind: 'google_email_otp', googleProvider: 'google' },
    continuityAnchor: input.continuityAnchor,
    recoverySetVersion: input.recoverySetVersion,
    state: 'prepared',
    createdAtMs: input.createdAtMs,
    expiresAtMs: input.expiresAtMs,
  };
}

export function markWalletRecoveryGoogleEmailOtpAttemptIssued(input: {
  readonly attempt: PreparedWalletRecoveryGoogleEmailOtpAttempt;
  readonly providerSubject: string;
  readonly verifiedEmail: string;
  readonly challengeId: string;
  readonly ownerProofBindingDigest: DigestB64u;
  readonly targetEnrollment: WalletRecoveryGoogleEmailOtpTargetEnrollmentV1;
}): OtpIssuedWalletRecoveryGoogleEmailOtpAttempt {
  return {
    ...input.attempt,
    state: 'otp_issued',
    providerSubject: input.providerSubject,
    verifiedEmail: input.verifiedEmail,
    challengeId: input.challengeId,
    ownerProofBindingDigest: input.ownerProofBindingDigest,
    targetEnrollment: input.targetEnrollment,
  };
}

export function markWalletRecoveryGoogleEmailOtpAttemptVerified(
  attempt: OtpIssuedWalletRecoveryGoogleEmailOtpAttempt,
): OtpVerifiedWalletRecoveryGoogleEmailOtpAttempt {
  return { ...attempt, state: 'otp_verified' };
}

export function walletRecoveryGoogleEmailOtpFinalizationInput(
  attempt: OtpVerifiedWalletRecoveryGoogleEmailOtpAttempt,
): WalletRecoveryGoogleEmailOtpFinalizationInput {
  return {
    kind: 'wallet_recovery_google_email_otp_finalization_v1',
    walletId: attempt.walletId,
    orgId: attempt.orgId,
    reservationId: attempt.reservationId,
    recoveryOperationId: attempt.recoveryOperationId,
    targetDeviceId: attempt.targetDeviceId,
    targetAuthorityId: attempt.targetAuthorityId,
    targetWalletAuthMethodId: attempt.targetWalletAuthMethodId,
    challengeId: attempt.challengeId,
    providerSubject: attempt.providerSubject,
    verifiedEmail: attempt.verifiedEmail,
    ownerProofBindingDigest: attempt.ownerProofBindingDigest,
    targetEnrollment: attempt.targetEnrollment,
  };
}

export function parseWalletRecoveryGoogleEmailOtpAttemptRecord(
  raw: unknown,
): WalletRecoveryGoogleEmailOtpAttemptRecord | null {
  if (!isRecord(raw)) return null;
  const expectedCommonFields = [
    'version',
    'walletId',
    'orgId',
    'reservationId',
    'recoveryOperationId',
    'targetDeviceId',
    'targetAuthorityId',
    'targetWalletAuthMethodId',
    'target',
    'continuityAnchor',
    'recoverySetVersion',
    'state',
    'createdAtMs',
    'expiresAtMs',
  ] as const;
  if (
    raw.version !== 'wallet_recovery_google_email_otp_attempt_v1' ||
    !hasFields(raw, expectedCommonFields) ||
    typeof raw.orgId !== 'string' ||
    !raw.orgId.trim() ||
    typeof raw.recoverySetVersion !== 'string' ||
    !raw.recoverySetVersion.trim()
  ) {
    return null;
  }
  const walletId = parseWalletId(raw.walletId);
  const reservationId = parseRecoveryCodeReservationIdSafe(raw.reservationId);
  const recoveryOperationId = parseWalletRecoveryOperationId(raw.recoveryOperationId);
  const targetDeviceId = parseDeviceId(raw.targetDeviceId);
  const targetAuthorityId = parseWalletAuthorityId(raw.targetAuthorityId);
  const targetWalletAuthMethodId = parseWalletAuthMethodId(raw.targetWalletAuthMethodId);
  const continuityAnchor = parseContinuityAnchor(raw.continuityAnchor);
  const createdAtMs = parsePositiveMs(raw.createdAtMs);
  const expiresAtMs = parsePositiveMs(raw.expiresAtMs);
  const target = parseTarget(raw.target);
  if (
    !walletId.ok ||
    !reservationId ||
    !recoveryOperationId.ok ||
    !targetDeviceId.ok ||
    !targetAuthorityId.ok ||
    !targetWalletAuthMethodId.ok ||
    !continuityAnchor ||
    !target ||
    createdAtMs === null ||
    expiresAtMs === null ||
    expiresAtMs <= createdAtMs ||
    continuityAnchor.method.walletId !== walletId.value ||
    continuityAnchor.envelope.walletId !== walletId.value
  ) {
    return null;
  }
  const common = {
    version: 'wallet_recovery_google_email_otp_attempt_v1' as const,
    walletId: walletId.value,
    orgId: raw.orgId,
    reservationId,
    recoveryOperationId: recoveryOperationId.value,
    targetDeviceId: targetDeviceId.value,
    targetAuthorityId: targetAuthorityId.value,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    target,
    continuityAnchor,
    recoverySetVersion: raw.recoverySetVersion,
    createdAtMs,
    expiresAtMs,
  };
  switch (raw.state) {
    case 'prepared':
      if (!hasExactFields(raw, [...expectedCommonFields])) return null;
      return { ...common, state: 'prepared' };
    case 'otp_issued':
    case 'otp_verified':
    case 'finalized': {
      const fields = [
        ...expectedCommonFields,
        'providerSubject',
        'verifiedEmail',
        'challengeId',
        'ownerProofBindingDigest',
        'targetEnrollment',
      ];
      if (!hasExactFields(raw, fields)) return null;
      const providerSubject = nonEmpty(raw.providerSubject);
      const verifiedEmail = nonEmpty(raw.verifiedEmail)?.toLowerCase();
      const challengeId = nonEmpty(raw.challengeId);
      let ownerProofBindingDigest: DigestB64u;
      try {
        ownerProofBindingDigest = parseDigestB64u(raw.ownerProofBindingDigest);
      } catch {
        return null;
      }
      const targetEnrollment = parseTargetEnrollment(raw.targetEnrollment);
      if (
        !providerSubject ||
        !verifiedEmail ||
        !challengeId ||
        !targetEnrollment
      ) {
        return null;
      }
      return {
        ...common,
        state: raw.state,
        providerSubject,
        verifiedEmail,
        challengeId,
        ownerProofBindingDigest,
        targetEnrollment,
      } as WalletRecoveryGoogleEmailOtpAttemptRecord;
    }
    default:
      return null;
  }
}

function parseContinuityAnchor(raw: unknown): WebAuthnRecoveryContinuityAnchorRecord | null {
  if (!isRecord(raw) || !hasExactFields(raw, [
    'kind',
    'authority',
    'method',
    'envelope',
  ])) return null;
  if (raw.kind !== 'wallet_recovery_continuity_anchor_v1') return null;
  const authority = parseWalletAuthorityV1(raw.authority);
  const method = parseWalletAuthMethodRecordV2(raw.method);
  const envelope = parseContinuityEnvelope(raw.envelope);
  if (
    !authority.ok ||
    authority.value.state !== 'active' ||
    !method ||
    method.status !== 'active' ||
    !envelope ||
    method.walletId !== authority.value.walletId ||
    method.walletAuthorityId !== authority.value.authorityId
  ) return null;
  if (
    method.kind === 'passkey' &&
    (envelope.kind !== 'passkey' ||
      method.rpId !== envelope.rpId ||
      method.credentialIdB64u !== envelope.credentialIdB64u)
  ) return null;
  if (method.kind === 'email_otp' && envelope.kind !== 'email_otp') return null;
  return {
    kind: 'wallet_recovery_continuity_anchor_v1',
    authority: authority.value,
    method,
    envelope,
  };
}

function parseContinuityEnvelope(
  raw: unknown,
): WebAuthnRecoveryContinuityEnvelopeAnchorRecord | null {
  if (!isRecord(raw)) return null;
  const commonFields = [
    'kind',
    'envelopeId',
    'walletId',
    'envelopeRevision',
    'updatedAtMs',
    'bindingKind',
  ] as const;
  if (!hasFields(raw, commonFields)) return null;
  const envelopeId = parsePasskeyEnvelopeId(raw.envelopeId);
  const walletId = parseWalletId(raw.walletId);
  let envelopeRevision: EnvelopeRevision;
  try {
    envelopeRevision = parseEnvelopeRevision(raw.envelopeRevision, 'continuity envelope revision');
  } catch {
    return null;
  }
  const updatedAtMs = parsePositiveMs(raw.updatedAtMs);
  if (!envelopeId.ok || !walletId.ok || updatedAtMs === null || raw.bindingKind !== 'wallet_custody_seed_v1') return null;
  if (raw.kind === 'passkey') {
    if (!hasExactFields(raw, [...commonFields, 'rpId', 'credentialIdB64u'])) return null;
    const rpId = parseWebAuthnRpId(raw.rpId);
    const credentialIdB64u = parseWebAuthnCredentialIdB64u(raw.credentialIdB64u);
    if (!rpId.ok || !credentialIdB64u.ok) return null;
    return {
      kind: 'passkey',
      envelopeId: envelopeId.value,
      walletId: walletId.value,
      rpId: rpId.value,
      credentialIdB64u: credentialIdB64u.value,
      envelopeRevision,
      updatedAtMs,
      bindingKind: 'wallet_custody_seed_v1',
    };
  }
  if (raw.kind === 'email_otp') {
    if (!hasExactFields(raw, [...commonFields, 'enrollmentId', 'enrollmentSealKeyVersion'])) return null;
    const enrollmentId = nonEmpty(raw.enrollmentId);
    const enrollmentSealKeyVersion = nonEmpty(raw.enrollmentSealKeyVersion);
    if (!enrollmentId || !enrollmentSealKeyVersion) return null;
    return {
      kind: 'email_otp',
      envelopeId: envelopeId.value,
      walletId: walletId.value,
      enrollmentId,
      enrollmentSealKeyVersion,
      envelopeRevision,
      updatedAtMs,
      bindingKind: 'wallet_custody_seed_v1',
    };
  }
  return null;
}

function parseTarget(raw: unknown): WalletRecoveryGoogleEmailOtpTargetV1 | null {
  return isRecord(raw) && hasExactFields(raw, ['kind', 'googleProvider']) && raw.kind === 'google_email_otp' && raw.googleProvider === 'google'
    ? { kind: 'google_email_otp', googleProvider: 'google' }
    : null;
}

function parseTargetEnrollment(raw: unknown): WalletRecoveryGoogleEmailOtpTargetEnrollmentV1 | null {
  if (!isRecord(raw) || typeof raw.kind !== 'string') return null;
  if (raw.kind === 'existing') {
    if (!hasExactFields(raw, ['kind', 'enrollmentId', 'enrollmentSealKeyVersion'])) return null;
    const enrollmentId = nonEmpty(raw.enrollmentId);
    const enrollmentSealKeyVersion = nonEmpty(raw.enrollmentSealKeyVersion);
    return enrollmentId && enrollmentSealKeyVersion
      ? { kind: 'existing', enrollmentId, enrollmentSealKeyVersion }
      : null;
  }
  if (raw.kind === 'create') {
    if (!hasExactFields(raw, ['kind', 'providerSubject', 'verifiedEmail'])) return null;
    const providerSubject = nonEmpty(raw.providerSubject);
    const verifiedEmail = nonEmpty(raw.verifiedEmail)?.toLowerCase();
    return providerSubject && verifiedEmail ? { kind: 'create', providerSubject, verifiedEmail } : null;
  }
  return null;
}

function parseRecoveryCodeReservationIdSafe(raw: unknown): RecoveryCodeReservationId | null {
  try {
    return parseRecoveryCodeReservationId(raw);
  } catch {
    return null;
  }
}

function parsePositiveMs(raw: unknown): number | null {
  return typeof raw === 'number' && Number.isSafeInteger(raw) && raw > 0 ? raw : null;
}

function nonEmpty(raw: unknown): string | null {
  return typeof raw === 'string' && raw.trim() ? raw.trim() : null;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return typeof raw === 'object' && raw !== null && !Array.isArray(raw);
}

function hasExactFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  const actual = Object.keys(record).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((field, index) => field === expected[index]);
}

function hasFields(record: Record<string, unknown>, fields: readonly string[]): boolean {
  return fields.every((field) => Object.hasOwn(record, field));
}

export type {
  WalletAuthMethodId,
  WalletAuthorityBindingDigest,
  WalletAuthorityId,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
};
