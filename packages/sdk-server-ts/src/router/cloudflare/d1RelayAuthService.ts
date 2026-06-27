import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { isValidAccountId, toOptionalTrimmedString } from '@shared/utils/validation';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
} from '@shared/utils/emailOtpRecoveryKey';
import { deriveHostedNearAccountId } from '../../core/hostedAccountIds';
import type {
  EmailOtpAuthStateRecord,
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../storage/tenantRoute';
import type { CloudflareRelayAuthService } from '../authServicePort';
import { createDisabledCloudflareRelayAuthService } from './disabledRelayAuthService';

export interface CloudflareD1RelayAuthServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
  readonly relayerAccount?: string;
  readonly relayerPublicKey?: string;
  readonly googleOidcClientId?: string;
  readonly accountIdDerivationSecret?: string;
}

type ListIdentitiesInput = Parameters<CloudflareRelayAuthService['listIdentities']>[0];
type ListIdentitiesResult = Awaited<ReturnType<CloudflareRelayAuthService['listIdentities']>>;
type LinkIdentityInput = Parameters<CloudflareRelayAuthService['linkIdentity']>[0];
type LinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['linkIdentity']>>;
type UnlinkIdentityInput = Parameters<CloudflareRelayAuthService['unlinkIdentity']>[0];
type UnlinkIdentityResult = Awaited<ReturnType<CloudflareRelayAuthService['unlinkIdentity']>>;
type ResolveOidcWalletIdInput = Parameters<CloudflareRelayAuthService['resolveOidcWalletId']>[0];
type ResolveOidcWalletIdResult = Awaited<
  ReturnType<CloudflareRelayAuthService['resolveOidcWalletId']>
>;
type ReadEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readEmailOtpEnrollment']
>[0];
type ReadEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readEmailOtpEnrollment']>
>;
type ReadActiveEmailOtpEnrollmentInput = Parameters<
  CloudflareRelayAuthService['readActiveEmailOtpEnrollment']
>[0];
type ReadActiveEmailOtpEnrollmentResult = Awaited<
  ReturnType<CloudflareRelayAuthService['readActiveEmailOtpEnrollment']>
>;
type IsEmailOtpStrongAuthRequiredInput = Parameters<
  CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']
>[0];
type IsEmailOtpStrongAuthRequiredResult = Awaited<
  ReturnType<CloudflareRelayAuthService['isEmailOtpStrongAuthRequired']>
>;
type MarkEmailOtpStrongAuthSatisfiedInput = Parameters<
  CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']
>[0];
type MarkEmailOtpStrongAuthSatisfiedResult = Awaited<
  ReturnType<CloudflareRelayAuthService['markEmailOtpStrongAuthSatisfied']>
>;
type GetEmailOtpRecoveryCodeStatusInput = Parameters<
  CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']
>[0];
type GetEmailOtpRecoveryCodeStatusResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getEmailOtpRecoveryCodeStatus']>
>;
type GetOrCreateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['getOrCreateAppSessionVersion']
>[0];
type GetOrCreateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['getOrCreateAppSessionVersion']>
>;
type RotateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['rotateAppSessionVersion']
>[0];
type RotateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['rotateAppSessionVersion']>
>;
type ValidateAppSessionVersionInput = Parameters<
  CloudflareRelayAuthService['validateAppSessionVersion']
>[0];
type ValidateAppSessionVersionResult = Awaited<
  ReturnType<CloudflareRelayAuthService['validateAppSessionVersion']>
>;
type ListWebAuthnAuthenticatorsInput = Parameters<
  CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']
>[0];
type ListWebAuthnAuthenticatorsResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listWebAuthnAuthenticatorsForUser']>
>;
type ListNearPublicKeysInput = Parameters<
  CloudflareRelayAuthService['listNearPublicKeysForUser']
>[0];
type ListNearPublicKeysResult = Awaited<
  ReturnType<CloudflareRelayAuthService['listNearPublicKeysForUser']>
>;

type D1IdentityRow = {
  readonly subject?: unknown;
  readonly user_id?: unknown;
  readonly created_at_ms?: unknown;
  readonly subject_count?: unknown;
};

type D1SessionRow = {
  readonly session_version?: unknown;
  readonly record_json?: unknown;
};

type D1EmailOtpEnrollmentRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpAuthStateRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1EmailOtpRecoveryEscrowRow = {
  readonly record_json?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
};

type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

type AppSessionVersionRecord = {
  readonly version: 'app_session_version_v1';
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type IdentitySubjectRecord = {
  readonly version: 'identity_subject_v1';
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WebAuthnCredentialBindingRecord = {
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly signerSlot: number;
  readonly publicKey?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly credentialIdB64u?: string;
  readonly rpId?: string;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

function requireD1RelayAuthScopeString(input: unknown, field: string): string {
  const value = toOptionalTrimmedString(input);
  if (!value) throw new Error(`${field} is required for Cloudflare D1 relay auth service`);
  return value;
}

function normalizeD1RelayAuthOptions(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareD1RelayAuthServiceOptions {
  return {
    database: input.database,
    namespace: requireD1RelayAuthScopeString(input.namespace, 'namespace'),
    orgId: requireD1RelayAuthScopeString(input.orgId, 'orgId'),
    projectId: requireD1RelayAuthScopeString(input.projectId, 'projectId'),
    envId: requireD1RelayAuthScopeString(input.envId, 'envId'),
    relayerAccount: toOptionalTrimmedString(input.relayerAccount),
    relayerPublicKey: toOptionalTrimmedString(input.relayerPublicKey),
    googleOidcClientId: toOptionalTrimmedString(input.googleOidcClientId),
    accountIdDerivationSecret: toOptionalTrimmedString(input.accountIdDerivationSecret),
  };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function appSessionVersion(): string {
  return secureRandomBase64Url(32, 'app session versions');
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return Boolean(input) && typeof input === 'object' && !Array.isArray(input);
}

function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecord(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecord(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function positiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

function positiveSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  return Math.floor(value);
}

function nonNegativeSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return Math.floor(value);
}

function isB64uString(input: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(input);
}

function optionalNonNegativeInteger(input: unknown): number | undefined {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

function parseAppSessionCreatedAt(input: unknown, fallback: number): number {
  const record = parseJsonObject(input);
  const value = positiveInteger(record?.createdAtMs);
  return value ?? fallback;
}

function parseIdentityCreatedAt(input: unknown, fallback: number): number {
  return positiveInteger(input) ?? fallback;
}

function parseIdentitySubjectCount(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

function d1MutationChanges(result: D1ResultLike<unknown>): number {
  const value = result.meta?.changes ?? result.meta?.rows_written;
  return parseIdentitySubjectCount(value);
}

function identitySubjectRecord(input: {
  readonly subject: string;
  readonly userId: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): IdentitySubjectRecord {
  return {
    version: 'identity_subject_v1',
    subject: input.subject,
    userId: input.userId,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function hasRecordField(record: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(record, field);
}

function parseEmailOtpWalletEnrollmentRecord(
  input: unknown,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseJsonObject(input);
  if (!record || hasRecordField(record, 'enrollmentEscrowCiphertextB64u')) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const verifiedEmail = toOptionalTrimmedString(record.verifiedEmail)?.toLowerCase() || '';
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryWrappedEnrollmentEscrowCount = positiveSafeInteger(
    record.recoveryWrappedEnrollmentEscrowCount,
  );
  const clientUnlockPublicKeyB64u = toOptionalTrimmedString(record.clientUnlockPublicKeyB64u);
  const unlockKeyVersion = toOptionalTrimmedString(record.unlockKeyVersion);
  const thresholdEcdsaClientVerifyingShareB64u = toOptionalTrimmedString(
    record.thresholdEcdsaClientVerifyingShareB64u,
  );
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  if (
    version !== 'email_otp_wallet_enrollment_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !verifiedEmail ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryWrappedEnrollmentEscrowCount ||
    !clientUnlockPublicKeyB64u ||
    !unlockKeyVersion ||
    !thresholdEcdsaClientVerifyingShareB64u ||
    !createdAtMs ||
    !updatedAtMs ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId,
    providerUserId,
    orgId,
    verifiedEmail,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryWrappedEnrollmentEscrowCount,
    clientUnlockPublicKeyB64u,
    unlockKeyVersion,
    thresholdEcdsaClientVerifyingShareB64u,
    createdAtMs,
    updatedAtMs,
  };
}

function parseEmailOtpWalletEnrollmentRow(
  row: D1EmailOtpEnrollmentRow | null,
): EmailOtpWalletEnrollmentRecord | null {
  const record = parseEmailOtpWalletEnrollmentRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function optionalPositiveSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return positiveSafeInteger(record[field]);
}

function optionalNonNegativeSafeIntegerField(
  record: Record<string, unknown>,
  field: string,
): number | undefined | null {
  if (!hasRecordField(record, field) || record[field] == null) return undefined;
  return nonNegativeSafeInteger(record[field]);
}

function parseEmailOtpAuthStateRecord(input: unknown): EmailOtpAuthStateRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const walletId = toOptionalTrimmedString(record.walletId);
  const providerUserId = toOptionalTrimmedString(record.providerUserId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const createdAtMs = positiveSafeInteger(record.createdAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const otpFailureCount = optionalNonNegativeSafeIntegerField(record, 'otpFailureCount');
  const lastOtpFailureAtMs = optionalPositiveSafeIntegerField(record, 'lastOtpFailureAtMs');
  const otpLockedUntilMs = optionalPositiveSafeIntegerField(record, 'otpLockedUntilMs');
  const lastEmailOtpLoginAtMs = optionalPositiveSafeIntegerField(
    record,
    'lastEmailOtpLoginAtMs',
  );
  const lastStrongAuthAtMs = optionalPositiveSafeIntegerField(record, 'lastStrongAuthAtMs');
  if (
    version !== 'email_otp_auth_state_v1' ||
    !walletId ||
    !providerUserId ||
    !orgId ||
    !createdAtMs ||
    !updatedAtMs ||
    otpFailureCount === null ||
    lastOtpFailureAtMs === null ||
    otpLockedUntilMs === null ||
    lastEmailOtpLoginAtMs === null ||
    lastStrongAuthAtMs === null ||
    updatedAtMs < createdAtMs
  ) {
    return null;
  }
  return {
    version: 'email_otp_auth_state_v1',
    walletId,
    providerUserId,
    orgId,
    createdAtMs,
    updatedAtMs,
    ...(otpFailureCount != null ? { otpFailureCount } : {}),
    ...(lastOtpFailureAtMs != null ? { lastOtpFailureAtMs } : {}),
    ...(otpLockedUntilMs != null ? { otpLockedUntilMs } : {}),
    ...(lastEmailOtpLoginAtMs != null ? { lastEmailOtpLoginAtMs } : {}),
    ...(lastStrongAuthAtMs != null ? { lastStrongAuthAtMs } : {}),
  };
}

function parseEmailOtpAuthStateRow(
  row: D1EmailOtpAuthStateRow | null,
): EmailOtpAuthStateRecord | null {
  const record = parseEmailOtpAuthStateRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function parseEmailOtpRecoveryEscrowRecord(
  input: unknown,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseJsonObject(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const alg = toOptionalTrimmedString(record.alg);
  const secretKind = toOptionalTrimmedString(record.secretKind);
  const escrowKind = toOptionalTrimmedString(record.escrowKind);
  const walletId = toOptionalTrimmedString(record.walletId);
  const userId = toOptionalTrimmedString(record.userId);
  const authSubjectId = toOptionalTrimmedString(record.authSubjectId);
  const authMethod = toOptionalTrimmedString(record.authMethod);
  const enrollmentId = toOptionalTrimmedString(record.enrollmentId);
  const enrollmentVersion = toOptionalTrimmedString(record.enrollmentVersion);
  const enrollmentSealKeyVersion = toOptionalTrimmedString(record.enrollmentSealKeyVersion);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const recoveryKeyId = toOptionalTrimmedString(record.recoveryKeyId);
  const recoveryKeyLabel = toOptionalTrimmedString(record.recoveryKeyLabel);
  const recoveryKeyStatus = toOptionalTrimmedString(record.recoveryKeyStatus);
  const nonceB64u = toOptionalTrimmedString(record.nonceB64u);
  const wrappedDeviceEnrollmentEscrowB64u = toOptionalTrimmedString(
    record.wrappedDeviceEnrollmentEscrowB64u,
  );
  const aadHashB64u = toOptionalTrimmedString(record.aadHashB64u);
  const issuedAtMs = positiveSafeInteger(record.issuedAtMs);
  const updatedAtMs = positiveSafeInteger(record.updatedAtMs);
  const consumedAtMs =
    record.consumedAtMs == null ? undefined : positiveSafeInteger(record.consumedAtMs);
  const revokedAtMs =
    record.revokedAtMs == null ? undefined : positiveSafeInteger(record.revokedAtMs);
  if (
    version !== 'email_otp_recovery_wrapped_enrollment_escrow_v1' ||
    alg !== EMAIL_OTP_RECOVERY_WRAP_ALG ||
    secretKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND ||
    escrowKind !== EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND ||
    !walletId ||
    !userId ||
    !authSubjectId ||
    authMethod !== 'google_sso_email_otp' ||
    !enrollmentId ||
    !enrollmentVersion ||
    !enrollmentSealKeyVersion ||
    !signingRootId ||
    !signingRootVersion ||
    !recoveryKeyId ||
    !nonceB64u ||
    !wrappedDeviceEnrollmentEscrowB64u ||
    !aadHashB64u ||
    !recoveryKeyStatus ||
    !issuedAtMs ||
    !updatedAtMs ||
    userId !== authSubjectId ||
    !isB64uString(nonceB64u) ||
    !isB64uString(wrappedDeviceEnrollmentEscrowB64u) ||
    !isB64uString(aadHashB64u) ||
    hasRecordField(record, 'acknowledgedAtMs') ||
    hasRecordField(record, 'abandonedAtMs') ||
    hasRecordField(record, 'cleanupReason') ||
    updatedAtMs < issuedAtMs
  ) {
    return null;
  }
  const base = {
    version: 'email_otp_recovery_wrapped_enrollment_escrow_v1' as const,
    alg: EMAIL_OTP_RECOVERY_WRAP_ALG,
    secretKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
    escrowKind: EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
    walletId,
    userId,
    authSubjectId,
    authMethod: 'google_sso_email_otp' as const,
    enrollmentId,
    enrollmentVersion,
    enrollmentSealKeyVersion,
    signingRootId,
    signingRootVersion,
    recoveryKeyId,
    ...(recoveryKeyLabel ? { recoveryKeyLabel } : {}),
    nonceB64u,
    wrappedDeviceEnrollmentEscrowB64u,
    aadHashB64u,
    issuedAtMs,
    updatedAtMs,
  };
  switch (recoveryKeyStatus) {
    case 'active':
      if (consumedAtMs !== undefined || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus };
    case 'consumed':
      if (consumedAtMs == null || revokedAtMs !== undefined) return null;
      return { ...base, recoveryKeyStatus, consumedAtMs };
    case 'revoked':
      if (consumedAtMs !== undefined || revokedAtMs == null) return null;
      return { ...base, recoveryKeyStatus, revokedAtMs };
    default:
      return null;
  }
}

function parseEmailOtpRecoveryEscrowRow(
  row: D1EmailOtpRecoveryEscrowRow | null,
): EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null {
  const record = parseEmailOtpRecoveryEscrowRecord(row?.record_json);
  const updatedAtMs = positiveSafeInteger(row?.updated_at_ms);
  if (!record || !updatedAtMs || record.updatedAtMs !== updatedAtMs) return null;
  return record;
}

function emailOtpRecoveryEscrowMatchesEnrollment(input: {
  readonly escrow: EmailOtpRecoveryWrappedEnrollmentEscrowRecord;
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
}): boolean {
  return (
    input.escrow.walletId === input.enrollment.walletId &&
    input.escrow.userId === input.enrollment.providerUserId &&
    input.escrow.authSubjectId === input.enrollment.providerUserId &&
    input.escrow.enrollmentId === input.enrollment.enrollmentId &&
    input.escrow.enrollmentVersion === input.enrollment.enrollmentVersion &&
    input.escrow.enrollmentSealKeyVersion === input.enrollment.enrollmentSealKeyVersion &&
    input.escrow.signingRootId === input.enrollment.signingRootId &&
    input.escrow.signingRootVersion === input.enrollment.signingRootVersion
  );
}

function resolveHostedOidcWalletScope(input: unknown): {
  readonly projectId: string;
  readonly envId: string;
} {
  const scope = isRecord(input) ? input : {};
  const orgId = toOptionalTrimmedString(scope.orgId);
  const projectId = toOptionalTrimmedString(scope.projectId);
  const envId = toOptionalTrimmedString(scope.envId);
  if (orgId && projectId && envId) return { projectId, envId };
  throw new Error(
    'runtimePolicyScope.orgId, runtimePolicyScope.projectId, and runtimePolicyScope.envId are required for hosted wallet id derivation',
  );
}

function codedError(code: string, message: string): Error & { code: string } {
  const error = new Error(message) as Error & { code: string };
  error.code = code;
  return error;
}

function appSessionRecord(input: {
  readonly userId: string;
  readonly appSessionVersion: string;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}): AppSessionVersionRecord {
  return {
    version: 'app_session_version_v1',
    userId: input.userId,
    appSessionVersion: input.appSessionVersion,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.updatedAtMs,
  };
}

function parseWebAuthnBinding(row: D1RecordJsonRow): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!rpId || !credentialIdB64u || !userId || signerSlot === null) return null;
  return {
    rpId,
    credentialIdB64u,
    userId,
    signerSlot,
    publicKey: toOptionalTrimmedString(record.publicKey),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonObject(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    credentialIdB64u: toOptionalTrimmedString(record.credentialIdB64u),
    rpId: toOptionalTrimmedString(record.rpId),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseNearPublicKeyKind(
  input: string | undefined,
): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

class CloudflareD1RelayAuthMetadataService {
  private readonly options: CloudflareD1RelayAuthServiceOptions;

  constructor(input: CloudflareD1RelayAuthServiceOptions) {
    this.options = normalizeD1RelayAuthOptions(input);
  }

  async listIdentities(input: ListIdentitiesInput): Promise<ListIdentitiesResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT subject
           FROM signer_identity_links
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY created_at_ms ASC`,
        [userId],
      ).all<D1IdentityRow>();
      const subjects: string[] = [];
      for (const row of result.results || []) {
        const subject = toOptionalTrimmedString(row.subject);
        if (subject) subjects.push(subject);
      }
      return { ok: true, subjects };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list identities',
      };
    }
  }

  async linkIdentity(input: LinkIdentityInput): Promise<LinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const now = Date.now();
      const existing = await this.readIdentityLinkBySubject(subject);
      const existingUserId = toOptionalTrimmedString(existing?.user_id);
      const createdAtMs = parseIdentityCreatedAt(existing?.created_at_ms, now);

      if (existingUserId && existingUserId !== userId) {
        return await this.moveIdentityIfAllowed({
          userId,
          subject,
          existingUserId,
          createdAtMs,
          updatedAtMs: now,
          allowMoveIfSoleIdentity: Boolean(input.allowMoveIfSoleIdentity),
        });
      }

      await this.scopePrepare(
        `INSERT INTO signer_identity_links (
          namespace,
          org_id,
          project_id,
          env_id,
          subject,
          user_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, subject)
        DO UPDATE SET
          user_id = EXCLUDED.user_id,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
        WHERE signer_identity_links.user_id = EXCLUDED.user_id`,
        [
          subject,
          userId,
          JSON.stringify(identitySubjectRecord({ subject, userId, createdAtMs, updatedAtMs: now })),
          createdAtMs,
          now,
        ],
      ).run();

      const finalUserId = await this.readIdentityUserIdBySubject(subject);
      if (finalUserId === userId) return { ok: true };
      if (finalUserId) return identityAlreadyLinked();
      return { ok: false, code: 'internal', message: 'Failed to link identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to link identity',
      };
    }
  }

  async unlinkIdentity(input: UnlinkIdentityInput): Promise<UnlinkIdentityResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const subject = toOptionalTrimmedString(input.subject);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      if (!subject) return { ok: false, code: 'invalid_args', message: 'Missing subject' };

      const deleted = d1MutationChanges(
        await this.options.database
          .prepare(
            `DELETE FROM signer_identity_links
              WHERE namespace = ?
                AND org_id = ?
                AND project_id = ?
                AND env_id = ?
                AND subject = ?
                AND user_id = ?
                AND (
                  SELECT COUNT(*)
                    FROM signer_identity_links
                   WHERE namespace = ?
                     AND org_id = ?
                     AND project_id = ?
                     AND env_id = ?
                     AND user_id = ?
                ) > 1`,
          )
          .bind(
            ...this.scopeValues([subject, userId]),
            ...this.scopeValues([userId]),
          )
          .run(),
      );
      if (deleted > 0) return { ok: true };

      const existingUserId = await this.readIdentityUserIdBySubject(subject);
      if (existingUserId !== userId) {
        return { ok: false, code: 'not_found', message: 'Subject is not linked to this user' };
      }
      const subjectCount = await this.readIdentitySubjectCountForUserId(userId);
      if (subjectCount <= 1) {
        return {
          ok: false,
          code: 'cannot_unlink_last_identity',
          message: 'Refusing to remove the last remaining identity',
        };
      }
      return { ok: false, code: 'internal', message: 'Failed to unlink identity' };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to unlink identity',
      };
    }
  }

  async resolveOidcWalletId(
    input: ResolveOidcWalletIdInput,
  ): Promise<ResolveOidcWalletIdResult> {
    const providerSubject = toOptionalTrimmedString(input.providerSubject ?? input.sub);
    if (!providerSubject) {
      throw new Error('Cannot resolve OIDC wallet id without provider subject');
    }
    if (providerSubject.startsWith('google:')) {
      throw codedError(
        'not_configured',
        'Google Email OTP session resolution is not configured for Cloudflare D1 relay auth',
      );
    }

    const linkedWalletId = await this.readIdentityUserIdBySubject(`wallet:${providerSubject}`);
    if (linkedWalletId && isValidAccountId(linkedWalletId)) return linkedWalletId;

    const scope = resolveHostedOidcWalletScope(input.runtimePolicyScope);
    const verifiedEmail = toOptionalTrimmedString(input.email);
    return await deriveHostedNearAccountId({
      accountIdDerivationSecret: requireD1RelayAuthScopeString(
        this.options.accountIdDerivationSecret,
        'ACCOUNT_ID_DERIVATION_SECRET',
      ),
      relayerAccount: requireD1RelayAuthScopeString(this.options.relayerAccount, 'relayerAccount'),
      projectId: scope.projectId,
      envId: scope.envId,
      authProvider: 'oidc',
      providerSubject,
      ...(verifiedEmail ? { verifiedEmail } : {}),
    });
  }

  async readEmailOtpEnrollment(
    input: ReadEmailOtpEnrollmentInput,
  ): Promise<ReadEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    return { ok: true, enrollment };
  }

  async readActiveEmailOtpEnrollment(
    input: ReadActiveEmailOtpEnrollmentInput,
  ): Promise<ReadActiveEmailOtpEnrollmentResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    const orgId = toOptionalTrimmedString(input.orgId);
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) {
      return { ok: false, code: 'not_found', message: 'Email OTP enrollment not found' };
    }
    if (enrollment.orgId !== orgId) return emailOtpEnrollmentTenantMismatch();
    if (providerUserId && enrollment.providerUserId !== providerUserId) {
      return {
        ok: false,
        code: 'provider_identity_mismatch',
        message: 'Email OTP enrollment does not match the requested provider user',
      };
    }
    return { ok: true, enrollment };
  }

  async isEmailOtpStrongAuthRequired(
    input: IsEmailOtpStrongAuthRequiredInput,
  ): Promise<IsEmailOtpStrongAuthRequiredResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, required: false, walletId };
    const authState = await this.readEmailOtpAuthStateForEnrollment(enrollment);
    if (!authState.ok) return authState;
    const state = authState.state;
    if (!state) return { ok: true, required: false, walletId };
    const lastEmailOtpLoginAtMs =
      typeof state.lastEmailOtpLoginAtMs === 'number' ? state.lastEmailOtpLoginAtMs : undefined;
    const lastStrongAuthAtMs =
      typeof state.lastStrongAuthAtMs === 'number' ? state.lastStrongAuthAtMs : undefined;
    return {
      ok: true,
      required: Boolean(
        lastEmailOtpLoginAtMs &&
          (!lastStrongAuthAtMs || lastEmailOtpLoginAtMs > lastStrongAuthAtMs),
      ),
      walletId,
      ...(lastEmailOtpLoginAtMs ? { lastEmailOtpLoginAtMs } : {}),
      ...(lastStrongAuthAtMs ? { lastStrongAuthAtMs } : {}),
    };
  }

  async markEmailOtpStrongAuthSatisfied(
    input: MarkEmailOtpStrongAuthSatisfiedInput,
  ): Promise<MarkEmailOtpStrongAuthSatisfiedResult> {
    const walletId = toOptionalTrimmedString(input.walletId);
    if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
    const enrollment = await this.readEmailOtpWalletEnrollment(walletId);
    if (!enrollment) return { ok: true, walletId };
    const nowMs = Date.now();
    await this.putEmailOtpAuthStateForEnrollment(enrollment, { lastStrongAuthAtMs: nowMs });
    return { ok: true, walletId, lastStrongAuthAtMs: nowMs };
  }

  async getEmailOtpRecoveryCodeStatus(
    input: GetEmailOtpRecoveryCodeStatusInput,
  ): Promise<GetEmailOtpRecoveryCodeStatusResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const walletId = toOptionalTrimmedString(input.walletId);
      const orgId = toOptionalTrimmedString(input.orgId);
      if (!userId) return { ok: false, code: 'invalid_body', message: 'Missing userId' };
      if (!walletId) return { ok: false, code: 'invalid_body', message: 'Missing walletId' };
      if (!orgId) return { ok: false, code: 'invalid_body', message: 'Missing orgId' };

      const enrollment = await this.readActiveEmailOtpEnrollment({
        walletId,
        orgId,
        providerUserId: userId,
      });
      if (!enrollment.ok) {
        if (enrollment.code === 'not_found') return emailOtpRecoveryNotEnrolledStatus(walletId);
        return enrollment;
      }

      const records = await this.listEmailOtpRecoveryEscrowsForEnrollment(enrollment.enrollment);
      let activeRecoveryCodeCount = 0;
      let consumedRecoveryCodeCount = 0;
      let revokedRecoveryCodeCount = 0;
      let issuedAtMs: number | null = null;
      for (const record of records) {
        switch (record.recoveryKeyStatus) {
          case 'active':
            activeRecoveryCodeCount += 1;
            break;
          case 'consumed':
            consumedRecoveryCodeCount += 1;
            break;
          case 'revoked':
            revokedRecoveryCodeCount += 1;
            break;
        }
        issuedAtMs =
          issuedAtMs === null ? record.issuedAtMs : Math.min(issuedAtMs, record.issuedAtMs);
      }
      return {
        ok: true,
        status:
          activeRecoveryCodeCount === EMAIL_OTP_RECOVERY_KEY_COUNT ? 'ready' : 'incomplete',
        walletId,
        enrollmentId: enrollment.enrollment.enrollmentId,
        enrollmentSealKeyVersion: enrollment.enrollment.enrollmentSealKeyVersion,
        expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        activeRecoveryCodeCount,
        consumedRecoveryCodeCount,
        revokedRecoveryCodeCount,
        totalRecoveryCodeCount: records.length,
        issuedAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to read Email OTP recovery-code status',
      };
    }
  }

  async getOrCreateAppSessionVersion(
    input: GetOrCreateAppSessionVersionInput,
  ): Promise<GetOrCreateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.readAppSessionVersion(userId);
      if (existing) return { ok: true, appSessionVersion: existing };
      const now = Date.now();
      const next = appSessionVersion();
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id) DO NOTHING`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs: now,
              updatedAtMs: now,
            }),
          ),
          now,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: (await this.readAppSessionVersion(userId)) || next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to ensure app session version',
      };
    }
  }

  async rotateAppSessionVersion(
    input: RotateAppSessionVersionInput,
  ): Promise<RotateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const existing = await this.scopePrepare(
        `SELECT record_json
           FROM signer_app_session_versions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          LIMIT 1`,
        [userId],
      ).first<D1SessionRow>();
      const now = Date.now();
      const next = appSessionVersion();
      const createdAtMs = parseAppSessionCreatedAt(existing?.record_json, now);
      await this.scopePrepare(
        `INSERT INTO signer_app_session_versions (
          namespace,
          org_id,
          project_id,
          env_id,
          user_id,
          session_version,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (namespace, org_id, project_id, env_id, user_id)
        DO UPDATE SET
          session_version = EXCLUDED.session_version,
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms`,
        [
          userId,
          next,
          JSON.stringify(
            appSessionRecord({
              userId,
              appSessionVersion: next,
              createdAtMs,
              updatedAtMs: now,
            }),
          ),
          createdAtMs,
          now,
        ],
      ).run();
      return { ok: true, appSessionVersion: next };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to rotate app session version',
      };
    }
  }

  async validateAppSessionVersion(
    input: ValidateAppSessionVersionInput,
  ): Promise<ValidateAppSessionVersionResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      const appSession = toOptionalTrimmedString(input.appSessionVersion);
      if (!userId || !appSession) {
        return { ok: false, code: 'unauthorized', message: 'Invalid app session' };
      }
      const current = await this.readAppSessionVersion(userId);
      if (!current || current !== appSession) {
        return { ok: false, code: 'invalid_session_version', message: 'App session revoked' };
      }
      return { ok: true };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to validate app session version',
      };
    }
  }

  async listWebAuthnAuthenticatorsForUser(
    input: ListWebAuthnAuthenticatorsInput,
  ): Promise<ListWebAuthnAuthenticatorsResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const rpId = toOptionalTrimmedString(input.rpId);
      const authRows = await this.readWebAuthnAuthenticatorRows(userId);
      const bindingRows = await this.readWebAuthnBindingRows({ userId, rpId });
      const authByCredentialId = new Map<string, D1AuthenticatorRow>();
      for (const row of authRows) {
        const credentialId = toOptionalTrimmedString(row.credential_id_b64u);
        if (credentialId) authByCredentialId.set(credentialId, row);
      }
      const authenticators: NonNullable<
        ListWebAuthnAuthenticatorsResult['authenticators']
      > = [];
      for (const row of bindingRows) {
        const binding = parseWebAuthnBinding(row);
        if (!binding) continue;
        const authenticator = authByCredentialId.get(binding.credentialIdB64u);
        authenticators.push({
          credentialIdB64u: binding.credentialIdB64u,
          signerSlot: binding.signerSlot,
          publicKey: binding.publicKey,
          createdAtMs:
            optionalNonNegativeInteger(authenticator?.created_at_ms) ?? binding.createdAtMs,
          updatedAtMs:
            optionalNonNegativeInteger(authenticator?.updated_at_ms) ?? binding.updatedAtMs,
        });
      }
      authenticators.sort(compareAuthenticatorSlots);
      return { ok: true, authenticators };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list authenticators',
      };
    }
  }

  async listNearPublicKeysForUser(
    input: ListNearPublicKeysInput,
  ): Promise<ListNearPublicKeysResult> {
    try {
      const userId = toOptionalTrimmedString(input.userId);
      if (!userId) return { ok: false, code: 'invalid_args', message: 'Missing userId' };
      const result = await this.scopePrepare(
        `SELECT record_json
           FROM signer_near_public_keys
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY COALESCE(signer_slot, 0) ASC, created_at_ms ASC, public_key ASC`,
        [userId],
      ).all<D1RecordJsonRow>();
      const keys: NonNullable<ListNearPublicKeysResult['keys']> = [];
      for (const row of result.results || []) {
        const record = parseNearPublicKey(row);
        if (!record) continue;
        keys.push({
          publicKey: record.publicKey,
          kind: record.kind,
          signerSlot: record.signerSlot,
          createdAtMs: record.createdAtMs,
          updatedAtMs: record.updatedAtMs,
          rpId: record.rpId,
          credentialIdB64u: record.credentialIdB64u,
        });
      }
      return { ok: true, keys };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to list keys',
      };
    }
  }

  getGoogleOidcPublicConfig(): ReturnType<CloudflareRelayAuthService['getGoogleOidcPublicConfig']> {
    const clientId = toOptionalTrimmedString(this.options.googleOidcClientId);
    return {
      configured: Boolean(clientId),
      ...(clientId ? { clientId } : {}),
    };
  }

  private scopePrepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.options.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [
      this.options.namespace,
      this.options.orgId,
      this.options.projectId,
      this.options.envId,
      ...values,
    ];
  }

  private async readIdentityLinkBySubject(subject: string): Promise<D1IdentityRow | null> {
    return await this.scopePrepare(
      `SELECT user_id, created_at_ms
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND subject = ?
        LIMIT 1`,
      [subject],
    ).first<D1IdentityRow>();
  }

  private async readIdentityUserIdBySubject(subject: string): Promise<string | null> {
    const row = await this.readIdentityLinkBySubject(subject);
    return toOptionalTrimmedString(row?.user_id) || null;
  }

  private async readIdentitySubjectCountForUserId(userId: string): Promise<number> {
    const row = await this.scopePrepare(
      `SELECT COUNT(*) AS subject_count
         FROM signer_identity_links
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?`,
      [userId],
    ).first<D1IdentityRow>();
    return parseIdentitySubjectCount(row?.subject_count);
  }

  private async moveIdentityIfAllowed(input: {
    readonly userId: string;
    readonly subject: string;
    readonly existingUserId: string;
    readonly createdAtMs: number;
    readonly updatedAtMs: number;
    readonly allowMoveIfSoleIdentity: boolean;
  }): Promise<LinkIdentityResult> {
    if (!input.allowMoveIfSoleIdentity) return identityAlreadyLinked();

    const moved = d1MutationChanges(
      await this.options.database
        .prepare(
          `UPDATE signer_identity_links
              SET user_id = ?,
                  record_json = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND project_id = ?
              AND env_id = ?
              AND subject = ?
              AND user_id = ?
              AND (
                SELECT COUNT(*)
                  FROM signer_identity_links
                 WHERE namespace = ?
                   AND org_id = ?
                   AND project_id = ?
                   AND env_id = ?
                   AND user_id = ?
              ) = 1`,
        )
        .bind(
          input.userId,
          JSON.stringify(
            identitySubjectRecord({
              subject: input.subject,
              userId: input.userId,
              createdAtMs: input.createdAtMs,
              updatedAtMs: input.updatedAtMs,
            }),
          ),
          input.updatedAtMs,
          ...this.scopeValues([input.subject, input.existingUserId]),
          ...this.scopeValues([input.existingUserId]),
        )
        .run(),
    );

    if (moved > 0) return { ok: true, movedFromUserId: input.existingUserId };
    const subjectCount = await this.readIdentitySubjectCountForUserId(input.existingUserId);
    if (subjectCount !== 1) return identityMoveDisallowed();
    return identityAlreadyLinked();
  }

  private async readEmailOtpWalletEnrollment(
    walletId: string,
  ): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  private async readEmailOtpAuthState(
    walletId: string,
  ): Promise<EmailOtpAuthStateRecord | null> {
    const row = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpAuthStateRow>();
    return parseEmailOtpAuthStateRow(row);
  }

  private async readEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<
    | { ok: true; state: EmailOtpAuthStateRecord | null }
    | { ok: false; code: string; message: string }
  > {
    const state = await this.readEmailOtpAuthState(enrollment.walletId);
    if (!state) return { ok: true, state: null };
    if (state.orgId !== enrollment.orgId || state.providerUserId !== enrollment.providerUserId) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  private async putEmailOtpAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: { readonly lastStrongAuthAtMs: number },
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.readEmailOtpAuthState(enrollment.walletId);
    if (
      existing &&
      (existing.orgId !== enrollment.orgId || existing.providerUserId !== enrollment.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next = emailOtpAuthStateRecord({
      enrollment,
      existing,
      updatedAtMs: nowMs,
      lastStrongAuthAtMs: patch.lastStrongAuthAtMs,
    });
    await this.scopePrepare(
      `INSERT INTO signer_email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        next.walletId,
        next.providerUserId,
        next.orgId,
        JSON.stringify(next),
        next.createdAtMs,
        next.updatedAtMs,
      ],
    ).run();
    return next;
  }

  private async listEmailOtpRecoveryEscrowsForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const result = await this.scopePrepare(
      `SELECT record_json, updated_at_ms
         FROM signer_email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        ORDER BY issued_at_ms ASC, recovery_key_id ASC`,
      [enrollment.walletId],
    ).all<D1EmailOtpRecoveryEscrowRow>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const row of result.results || []) {
      const escrow = parseEmailOtpRecoveryEscrowRow(row);
      if (!escrow) continue;
      if (!emailOtpRecoveryEscrowMatchesEnrollment({ escrow, enrollment })) continue;
      records.push(escrow);
    }
    return records;
  }

  private async readAppSessionVersion(userId: string): Promise<string | null> {
    const row = await this.scopePrepare(
      `SELECT session_version
         FROM signer_app_session_versions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        LIMIT 1`,
      [userId],
    ).first<D1SessionRow>();
    return toOptionalTrimmedString(row?.session_version) || null;
  }

  private async readWebAuthnAuthenticatorRows(userId: string): Promise<D1AuthenticatorRow[]> {
    const result = await this.scopePrepare(
      `SELECT credential_id_b64u, created_at_ms, updated_at_ms
         FROM signer_webauthn_authenticators
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND user_id = ?
        ORDER BY created_at_ms ASC`,
      [userId],
    ).all<D1AuthenticatorRow>();
    return [...(result.results || [])];
  }

  private async readWebAuthnBindingRows(input: {
    readonly userId: string;
    readonly rpId?: string;
  }): Promise<D1RecordJsonRow[]> {
    const rpId = toOptionalTrimmedString(input.rpId);
    const sql = rpId
      ? `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
            AND rp_id = ?
          ORDER BY signer_slot ASC`
      : `SELECT record_json
           FROM signer_webauthn_credential_bindings
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND user_id = ?
          ORDER BY signer_slot ASC`;
    const values = rpId ? [input.userId, rpId] : [input.userId];
    const result = await this.scopePrepare(sql, values).all<D1RecordJsonRow>();
    return [...(result.results || [])];
  }
}

function compareAuthenticatorSlots(
  left: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
  right: NonNullable<ListWebAuthnAuthenticatorsResult['authenticators']>[number],
): number {
  return (Number(left.signerSlot || 0) || 0) - (Number(right.signerSlot || 0) || 0);
}

function identityAlreadyLinked(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is already linked to a different user',
  };
}

function identityMoveDisallowed(): LinkIdentityResult {
  return {
    ok: false,
    code: 'already_linked',
    message: 'Subject is linked to a different user with other identities; merge is not allowed',
  };
}

function emailOtpEnrollmentTenantMismatch(): ReadEmailOtpEnrollmentResult {
  return {
    ok: false,
    code: 'tenant_scope_mismatch',
    message: 'Email OTP enrollment does not match the requested orgId',
  };
}

function emailOtpRecoveryNotEnrolledStatus(walletId: string): GetEmailOtpRecoveryCodeStatusResult {
  return {
    ok: true,
    status: 'not_enrolled',
    walletId,
    enrollmentId: '',
    enrollmentSealKeyVersion: '',
    expectedRecoveryCodeCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
    activeRecoveryCodeCount: 0,
    consumedRecoveryCodeCount: 0,
    revokedRecoveryCodeCount: 0,
    totalRecoveryCodeCount: 0,
    issuedAtMs: null,
  };
}

function emailOtpAuthStateRecord(input: {
  readonly enrollment: EmailOtpWalletEnrollmentRecord;
  readonly existing: EmailOtpAuthStateRecord | null;
  readonly updatedAtMs: number;
  readonly lastStrongAuthAtMs: number;
}): EmailOtpAuthStateRecord {
  return {
    version: 'email_otp_auth_state_v1',
    walletId: input.enrollment.walletId,
    providerUserId: input.enrollment.providerUserId,
    orgId: input.enrollment.orgId,
    createdAtMs: input.existing?.createdAtMs ?? input.updatedAtMs,
    updatedAtMs: input.updatedAtMs,
    ...(input.existing?.otpFailureCount != null
      ? { otpFailureCount: input.existing.otpFailureCount }
      : {}),
    ...(input.existing?.lastOtpFailureAtMs
      ? { lastOtpFailureAtMs: input.existing.lastOtpFailureAtMs }
      : {}),
    ...(input.existing?.otpLockedUntilMs
      ? { otpLockedUntilMs: input.existing.otpLockedUntilMs }
      : {}),
    ...(input.existing?.lastEmailOtpLoginAtMs
      ? { lastEmailOtpLoginAtMs: input.existing.lastEmailOtpLoginAtMs }
      : {}),
    lastStrongAuthAtMs: input.lastStrongAuthAtMs,
  };
}

export function createCloudflareD1RelayAuthService(
  input: CloudflareD1RelayAuthServiceOptions,
): CloudflareRelayAuthService {
  const service = createDisabledCloudflareRelayAuthService({
    relayerAccount: input.relayerAccount,
    relayerPublicKey: input.relayerPublicKey,
  });
  const metadata = new CloudflareD1RelayAuthMetadataService(input);
  service.listIdentities = metadata.listIdentities.bind(metadata);
  service.linkIdentity = metadata.linkIdentity.bind(metadata);
  service.unlinkIdentity = metadata.unlinkIdentity.bind(metadata);
  service.resolveOidcWalletId = metadata.resolveOidcWalletId.bind(metadata);
  service.readEmailOtpEnrollment = metadata.readEmailOtpEnrollment.bind(metadata);
  service.readActiveEmailOtpEnrollment = metadata.readActiveEmailOtpEnrollment.bind(metadata);
  service.isEmailOtpStrongAuthRequired = metadata.isEmailOtpStrongAuthRequired.bind(metadata);
  service.markEmailOtpStrongAuthSatisfied = metadata.markEmailOtpStrongAuthSatisfied.bind(metadata);
  service.getEmailOtpRecoveryCodeStatus =
    metadata.getEmailOtpRecoveryCodeStatus.bind(metadata);
  service.getOrCreateAppSessionVersion = metadata.getOrCreateAppSessionVersion.bind(metadata);
  service.rotateAppSessionVersion = metadata.rotateAppSessionVersion.bind(metadata);
  service.validateAppSessionVersion = metadata.validateAppSessionVersion.bind(metadata);
  service.listWebAuthnAuthenticatorsForUser =
    metadata.listWebAuthnAuthenticatorsForUser.bind(metadata);
  service.listNearPublicKeysForUser = metadata.listNearPublicKeysForUser.bind(metadata);
  service.getGoogleOidcPublicConfig = metadata.getGoogleOidcPublicConfig.bind(metadata);
  return service;
}
