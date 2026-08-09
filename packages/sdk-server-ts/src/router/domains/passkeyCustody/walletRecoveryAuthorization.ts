import {
  buildVaultOperationRef,
  parseAuthFactorId,
  parseAuthorizationAuditEventId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parseAuthorizedOperationId,
  parseCapabilityId,
  parseCapabilityOperationId,
  VAULT_OPERATION_KINDS,
  type AuthorizationParseResult,
} from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseEmailOtpChallengeId } from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { EMAIL_OTP_CHANNEL, WALLET_EMAIL_OTP_UNLOCK_OPERATION } from '@shared/utils/emailOtpDomain';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type { AuthorizedOperation } from '../../../authorization/domain';
import { buildVerifiedEmailOtpFactorResult } from '../../../authorization/factorEvidence';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiAuthorizedOperationService,
  RouterApiEmailOtpRouteService,
} from '../../framework/authServicePort';
import type { SessionAdapter } from '../../framework/routerApi';
import { hashEmailOtpAppSessionClaims } from '../emailOtp/emailOtpSessionRouteHelpers';
import { authenticateRouterAbOperationStepUpAppSessionIdentity } from '../signingOperations/routerAbPrivateSigningWorker';

const RECOVERY_LANE_DIGEST_DOMAIN_V1 = 'seams:wallet-recovery:lane:v1';
const RECOVERY_INTENT_DIGEST_DOMAIN_V1 = 'seams:wallet-recovery:intent:v1';
const RECOVERY_DISPLAY_DIGEST_DOMAIN_V1 = 'seams:wallet-recovery:display:v1';

type WalletRecoveryAuthenticatedContext = {
  readonly authorizedOperations: RouterApiAuthorizedOperationService;
  readonly activeSession: Awaited<
    ReturnType<RouterApiAuthorizationSessionService['readActiveSession']>
  > & {};
  readonly session: {
    readonly tenantId: Parameters<typeof buildWalletRecoveryOperation>[0]['tenantId'];
    readonly principalId: Parameters<typeof buildWalletRecoveryOperation>[0]['principalId'];
  };
  readonly authorityRef: Parameters<typeof buildVerifiedEmailOtpFactorResult>[0]['authorityRef'];
  readonly rawClaims: Record<string, unknown>;
  readonly expiresAtMs: number;
  readonly operation: CapabilityOperationEnvelope;
  readonly existing: AuthorizedOperation | null;
};

export type WalletRecoveryAuthorizationFailure = {
  readonly ok: false;
  readonly status: number;
  readonly code: string;
  readonly message: string;
};

export type WalletRecoveryAuthorizationContextResult =
  | { readonly ok: true; readonly context: WalletRecoveryAuthenticatedContext }
  | WalletRecoveryAuthorizationFailure;

export async function resolveWalletRecoveryAuthorizationContext(input: {
  readonly headers: Record<string, string | string[] | undefined>;
  readonly session: SessionAdapter | null | undefined;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
}): Promise<WalletRecoveryAuthorizationContextResult> {
  const authenticated = await authenticateRouterAbOperationStepUpAppSessionIdentity({
    headers: input.headers,
    session: input.session,
    walletId: input.walletId,
    materialOwner: input.walletId,
    authorizedOperations: input.authorizedOperations,
    authorizationSessions: input.authorizationSessions,
  });
  if (!authenticated.ok) {
    const body = recoveryErrorBody(authenticated.error.body);
    return {
      ok: false,
      status: authenticated.error.status,
      code: body.code,
      message: body.message,
    };
  }
  const operation = await buildWalletRecoveryOperation({
    tenantId: authenticated.session.tenantId,
    principalId: authenticated.session.principalId,
    walletId: input.walletId,
    reservationId: input.reservationId,
  });
  const existing = await authenticated.authorizedOperations.readAuthorizedOperation({
    tenantId: authenticated.session.tenantId,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(operation),
  });
  return {
    ok: true,
    context: {
      authorizedOperations: authenticated.authorizedOperations,
      activeSession: authenticated.activeSession,
      session: authenticated.session,
      authorityRef: authenticated.authorityRef,
      rawClaims: authenticated.rawClaims,
      expiresAtMs: authenticated.expiresAtMs,
      operation,
      existing,
    },
  };
}

export async function admitWalletRecoveryEmailOtp(input: {
  readonly context: WalletRecoveryAuthenticatedContext;
  readonly emailOtp: RouterApiEmailOtpRouteService;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly challengeId: string;
  readonly otpCode: string;
  readonly nowMs: number;
}): Promise<
  | { readonly ok: true; readonly operation: AuthorizedOperation }
  | WalletRecoveryAuthorizationFailure
> {
  if (input.context.existing) {
    return { ok: true, operation: input.context.existing };
  }
  const verified = await input.emailOtp.verifyEmailOtpChallenge({
    userId: input.context.session.principalId,
    walletId: input.walletId,
    orgId: input.context.session.tenantId,
    challengeId: input.challengeId,
    otpCode: input.otpCode,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: await hashEmailOtpAppSessionClaims(input.context.rawClaims),
    appSessionVersion: input.context.activeSession.appSessionVersion,
    operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
  });
  if (!verified.ok) {
    return {
      ok: false,
      status: verified.code === 'invalid_body' ? 400 : 401,
      code: verified.code,
      message: verified.message,
    };
  }
  const consumed = await input.emailOtp.consumeEmailOtpGrant({
    subject: {
      kind: 'authorization_session',
      tenantId: input.context.session.tenantId,
      principalId: input.context.session.principalId,
      walletId: walletIdFromString(input.walletId),
    },
    loginGrant: verified.loginGrant,
    otpChannel: EMAIL_OTP_CHANNEL,
  });
  if (!consumed.ok) {
    return {
      ok: false,
      status: consumed.code === 'invalid_body' ? 400 : 401,
      code: consumed.code,
      message: consumed.message,
    };
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    input.context.operation,
  );
  const factor = buildVerifiedEmailOtpFactorResult({
    tenantId: input.context.session.tenantId,
    principalId: input.context.session.principalId,
    sessionId: input.context.activeSession.sessionId,
    deviceId: input.context.activeSession.deviceId,
    factorId: authorizationValue(
      parseAuthFactorId(`email_otp:${input.context.session.principalId}`),
    ),
    authorityRef: input.context.authorityRef,
    operation: input.context.operation,
    challengeId: authorizationValue(parseEmailOtpChallengeId(consumed.challengeId)),
    verificationReceiptDigest: await digest('seams:wallet-recovery:email-otp-receipt:v1', {
      challengeId: consumed.challengeId,
      operationFingerprintDigest,
    }),
    verifiedAtMs: input.nowMs,
    expiresAtMs: Math.min(input.context.expiresAtMs, verified.grantExpiresAtMs),
  });
  const evidenceSet = await input.context.authorizedOperations.recordVerifiedFactorEvidenceSet({
    session: input.context.activeSession,
    operation: input.context.operation,
    evidenceId: authorizationValue(
      parseAuthorizationEvidenceId(`wallet-recovery-evidence:${input.reservationId}`),
    ),
    evidenceSetId: authorizationValue(
      parseAuthorizationEvidenceSetId(`wallet-recovery-evidence-set:${input.reservationId}`),
    ),
    factor,
  });
  const admitted = await input.context.authorizedOperations.admitAuthorizedOperation({
    operation: {
      tenantId: input.context.session.tenantId,
      authorizedOperationId: authorizationValue(
        parseAuthorizedOperationId(`wallet-recovery:${input.reservationId}`),
      ),
      auditEventId: authorizationValue(
        parseAuthorizationAuditEventId(`wallet-recovery-audit:${input.reservationId}`),
      ),
      operation: input.context.operation,
      authorization: { kind: 'verified_step_up', evidenceSetDigest: evidenceSet.evidenceSetDigest },
      quota: { kind: 'quota_neutral' },
      claimedAtMs: input.nowMs,
    },
  });
  switch (admitted.kind) {
    case 'claimed':
    case 'operation_in_progress':
    case 'replayed':
      return { ok: true, operation: admitted.operation };
    case 'authorization_grant_rejected':
    case 'verified_step_up_rejected':
    case 'wallet_session_quota_exhausted':
    case 'material_mismatch':
      return {
        ok: false,
        status: 403,
        code: 'recovery_authorization_rejected',
        message: 'wallet recovery authorization was rejected',
      };
  }
}

export async function buildWalletRecoveryOperation(input: {
  readonly tenantId: Parameters<typeof buildCapabilityOperationEnvelope>[0]['tenantId'];
  readonly principalId: Parameters<typeof buildCapabilityOperationEnvelope>[0]['principalId'];
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
}): Promise<CapabilityOperationEnvelope> {
  const operation = buildVaultOperationRef(VAULT_OPERATION_KINDS.reveal);
  const capabilityId = authorizationValue(parseCapabilityId(`wallet-recovery:${input.walletId}`));
  return buildCapabilityOperationEnvelope({
    tenantId: input.tenantId,
    principalId: input.principalId,
    capabilityId,
    operationId: authorizationValue(parseCapabilityOperationId(input.reservationId)),
    operation,
    digests: {
      laneDigest: await digest(RECOVERY_LANE_DIGEST_DOMAIN_V1, {
        tenantId: input.tenantId,
        walletId: input.walletId,
        capabilityId,
      }),
      intentDigest: await digest(RECOVERY_INTENT_DIGEST_DOMAIN_V1, {
        walletId: input.walletId,
        reservationId: input.reservationId,
        operation,
      }),
      displayDigest: await digest(RECOVERY_DISPLAY_DIGEST_DOMAIN_V1, {
        walletId: input.walletId,
        action: 'replace_wallet_credential',
      }),
    },
  });
}

function authorizationValue<T>(result: AuthorizationParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

async function digest(domain: string, value: Record<string, unknown>) {
  return parseDigestB64u(
    base64UrlEncode(await sha256BytesUtf8(`${domain}|${alphabetizeStringify(value)}`)),
  );
}

function recoveryErrorBody(value: unknown): { readonly code: string; readonly message: string } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return { code: 'unauthorized', message: 'wallet recovery authorization failed' };
  }
  const body = value as Record<string, unknown>;
  return {
    code: typeof body.code === 'string' ? body.code : 'unauthorized',
    message:
      typeof body.message === 'string'
        ? body.message
        : 'wallet recovery authorization failed',
  };
}
