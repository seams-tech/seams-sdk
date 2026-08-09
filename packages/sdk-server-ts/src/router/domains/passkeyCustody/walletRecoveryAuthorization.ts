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
import {
  parseAppSessionVersion,
  parseEmailOtpChallengeId,
  parseProviderSubject,
} from '@shared/utils/domainIds';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type { AuthorizedOperation } from '../../../authorization/domain';
import {
  buildActiveAuthorizationSession,
  parseSessionOrigin,
} from '../../../authorization/domain';
import {
  parseDeviceId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { buildVerifiedEmailOtpFactorResult } from '../../../authorization/factorEvidence';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiAuthorizedOperationService,
  RouterApiEmailOtpRouteService,
} from '../../framework/authServicePort';
import type { SessionAdapter } from '../../framework/routerApi';
import { hashEmailOtpAppSessionClaims } from '../emailOtp/emailOtpSessionRouteHelpers';
import { authenticateRouterAbOperationStepUpAppSessionIdentity } from '../signingOperations/routerAbPrivateSigningWorker';
import {
  buildEmailOtpWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

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

/**
 * Builds the recovery-only authorization session represented by a bootstrap
 * grant. This session is persisted solely as evidence for one recovery
 * operation; it has no app-session JWT and cannot authorize another capability.
 */
export async function resolveWalletRecoveryBootstrapAuthorizationContext(input: {
  readonly grant: {
    readonly walletId: string;
    readonly providerUserId: string;
    readonly orgId: string;
    readonly challengeId: string;
    readonly grantExpiresAtMs: number;
  };
  readonly reservationId: RecoveryCodeReservationId;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly requestOrigin: string;
  readonly nowMs: number;
}): Promise<WalletRecoveryAuthorizationContextResult> {
  if (!input.authorizedOperations || !input.authorizationSessions) {
    return {
      ok: false,
      status: 501,
      code: 'not_configured',
      message: 'wallet recovery authorization is unavailable',
    };
  }
  if (input.grant.grantExpiresAtMs <= input.nowMs) {
    return {
      ok: false,
      status: 401,
      code: 'recovery_bootstrap_grant_invalid_or_expired',
      message: 'Recovery bootstrap grant is invalid or expired',
    };
  }
  const tenantId = parseTenantId(input.grant.orgId);
  const principalId = parsePrincipalId(`recovery-bootstrap:${input.grant.walletId}`);
  const sessionId = parseSeamsSessionId(`recovery-bootstrap:${input.grant.challengeId}`);
  const deviceId = parseDeviceId(`recovery-bootstrap:${input.grant.walletId}`);
  const appSessionVersion = parseAppSessionVersion(
    `recovery-bootstrap:${input.grant.challengeId}`,
  );
  const providerSubject = parseProviderSubject(input.grant.providerUserId);
  if (
    !tenantId.ok ||
    !principalId.ok ||
    !sessionId.ok ||
    !deviceId.ok ||
    !appSessionVersion.ok ||
    !providerSubject.ok
  ) {
    return {
      ok: false,
      status: 401,
      code: 'recovery_bootstrap_grant_invalid',
      message: 'Recovery bootstrap grant is invalid',
    };
  }
  const expiresAtMs = input.grant.grantExpiresAtMs;
  let origin: ReturnType<typeof parseSessionOrigin>;
  try {
    origin = parseSessionOrigin(input.requestOrigin);
  } catch {
    return {
      ok: false,
      status: 400,
      code: 'invalid_origin',
      message: 'wallet recovery requires a valid request Origin header',
    };
  }
  const activeSession = buildActiveAuthorizationSession({
    tenantId: tenantId.value,
    principalId: principalId.value,
    sessionId: sessionId.value,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'oidc',
      providerSubject: providerSubject.value,
    },
    deviceId: deviceId.value,
    audience: { kind: 'first_party_web', origin },
    appSessionVersion: appSessionVersion.value,
    assurance: 'step_up',
    createdAtMs: input.nowMs,
    lifecycle: { kind: 'active', expiresAtMs },
  });
  await input.authorizationSessions.recordActiveSession(activeSession);
  const authority = buildEmailOtpWalletAuthAuthority({
    walletId: input.grant.walletId,
    provider: 'email',
    providerUserId: input.grant.providerUserId,
    emailHashHex: `recovery-bootstrap:${input.grant.challengeId}`,
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  const operation = await buildWalletRecoveryOperation({
    tenantId: tenantId.value,
    principalId: principalId.value,
    walletId: input.grant.walletId,
    reservationId: input.reservationId,
  });
  const existing = await input.authorizedOperations.readAuthorizedOperation({
    tenantId: tenantId.value,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(operation),
  });
  return {
    ok: true,
    context: {
      authorizedOperations: input.authorizedOperations,
      activeSession,
      session: { tenantId: tenantId.value, principalId: principalId.value },
      authorityRef,
      rawClaims: {
        sub: principalId.value,
        tenantId: tenantId.value,
        walletId: input.grant.walletId,
        walletAuthAuthorityRef: authorityRef,
        appSessionVersion: appSessionVersion.value,
      },
      expiresAtMs,
      operation,
      existing,
    },
  };
}

export async function admitWalletRecoveryBootstrapGrant(input: {
  readonly context: WalletRecoveryAuthenticatedContext;
  readonly reservationId: RecoveryCodeReservationId;
  readonly challengeId: string;
  readonly nowMs: number;
}): Promise<
  | { readonly ok: true; readonly operation: AuthorizedOperation }
  | WalletRecoveryAuthorizationFailure
> {
  if (input.context.existing) return { ok: true, operation: input.context.existing };
  const factor = buildVerifiedEmailOtpFactorResult({
    tenantId: input.context.session.tenantId,
    principalId: input.context.session.principalId,
    sessionId: input.context.activeSession.sessionId,
    deviceId: input.context.activeSession.deviceId,
    factorId: authorizationValue(
      parseAuthFactorId(`email_otp:recovery-bootstrap:${input.reservationId}`),
    ),
    authorityRef: input.context.authorityRef,
    operation: input.context.operation,
    challengeId: authorizationValue(parseEmailOtpChallengeId(input.challengeId)),
    verificationReceiptDigest: await digest('seams:wallet-recovery:bootstrap-receipt:v1', {
      challengeId: input.challengeId,
      reservationId: input.reservationId,
    }),
    verifiedAtMs: input.nowMs,
    expiresAtMs: input.context.expiresAtMs,
  });
  const evidenceSet = await input.context.authorizedOperations.recordVerifiedFactorEvidenceSet({
    session: input.context.activeSession,
    operation: input.context.operation,
    evidenceId: authorizationValue(
      parseAuthorizationEvidenceId(`wallet-recovery-bootstrap-evidence:${input.reservationId}`),
    ),
    evidenceSetId: authorizationValue(
      parseAuthorizationEvidenceSetId(`wallet-recovery-bootstrap-evidence-set:${input.reservationId}`),
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
        parseAuthorizationAuditEventId(`wallet-recovery-bootstrap-audit:${input.reservationId}`),
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

export async function resolveWalletRecoveryAuthorizationToken(input: {
  readonly token: string;
  readonly session: SessionAdapter | null | undefined;
  readonly walletId: string;
  readonly reservationId: RecoveryCodeReservationId;
  readonly challengeId: string;
  readonly requestOrigin: string;
  readonly authorizedOperations: RouterApiAuthorizedOperationService | null | undefined;
  readonly authorizationSessions: RouterApiAuthorizationSessionService | null | undefined;
  readonly nowMs: number;
}): Promise<WalletRecoveryAuthorizationContextResult> {
  if (!input.session || !input.authorizedOperations || !input.authorizationSessions) {
    return {
      ok: false,
      status: 501,
      code: 'not_configured',
      message: 'wallet recovery authorization is unavailable',
    };
  }
  let verified: Awaited<ReturnType<SessionAdapter['verifyJwt']>>;
  try {
    verified = await input.session.verifyJwt(input.token);
  } catch {
    return {
      ok: false,
      status: 401,
      code: 'recovery_authorization_invalid',
      message: 'wallet recovery authorization is invalid',
    };
  }
  if (!verified.valid) {
    return {
      ok: false,
      status: 401,
      code: 'recovery_authorization_invalid',
      message: 'wallet recovery authorization is invalid',
    };
  }
  const claims = verified.payload;
  if (claims.kind !== 'wallet_recovery_authorization_v1') {
    return {
      ok: false,
      status: 401,
      code: 'recovery_authorization_invalid',
      message: 'wallet recovery authorization is invalid',
    };
  }
  const walletId = typeof claims.walletId === 'string' ? claims.walletId.trim() : '';
  const reservationId = typeof claims.reservationId === 'string' ? claims.reservationId.trim() : '';
  const challengeId = typeof claims.challengeId === 'string' ? claims.challengeId.trim() : '';
  const tenantId = parseTenantId(claims.tenantId);
  const principalId = parsePrincipalId(claims.principalId);
  const sessionId = parseSeamsSessionId(`recovery-token:${reservationId}`);
  const deviceId = parseDeviceId(`recovery-token:${walletId}`);
  const appSessionVersion = parseAppSessionVersion(`recovery-token:${reservationId}`);
  const providerSubject = parseProviderSubject(String(principalId.ok ? principalId.value : ''));
  const authorityRef = parseWalletAuthAuthorityRef(claims.authorityRef);
  const tokenOrigin = typeof claims.origin === 'string' ? claims.origin.trim() : '';
  const expiresAtMs = Number(claims.exp) * 1_000;
  if (
    walletId !== input.walletId ||
    reservationId !== String(input.reservationId) ||
    challengeId !== input.challengeId ||
    !tenantId.ok ||
    !principalId.ok ||
    !sessionId.ok ||
    !deviceId.ok ||
    !appSessionVersion.ok ||
    !providerSubject.ok ||
    !authorityRef ||
    authorityRef.walletId !== input.walletId ||
    (tokenOrigin && tokenOrigin !== input.requestOrigin) ||
    !Number.isSafeInteger(expiresAtMs) ||
    expiresAtMs <= input.nowMs
  ) {
    return {
      ok: false,
      status: 401,
      code: 'recovery_authorization_invalid',
      message: 'wallet recovery authorization is invalid',
    };
  }
  let audience: ReturnType<typeof parseSessionOrigin>;
  try {
    audience = parseSessionOrigin(input.requestOrigin);
  } catch {
    return {
      ok: false,
      status: 400,
      code: 'invalid_origin',
      message: 'wallet recovery requires a valid request Origin header',
    };
  }
  const activeSession = buildActiveAuthorizationSession({
    tenantId: tenantId.value,
    principalId: principalId.value,
    sessionId: sessionId.value,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'oidc',
      providerSubject: providerSubject.value,
    },
    deviceId: deviceId.value,
    audience: { kind: 'first_party_web', origin: audience },
    appSessionVersion: appSessionVersion.value,
    assurance: 'step_up',
    createdAtMs: input.nowMs,
    lifecycle: { kind: 'active', expiresAtMs },
  });
  await input.authorizationSessions.recordActiveSession(activeSession);
  const operation = await buildWalletRecoveryOperation({
    tenantId: tenantId.value,
    principalId: principalId.value,
    walletId: input.walletId,
    reservationId: input.reservationId,
  });
  const existing = await input.authorizedOperations.readAuthorizedOperation({
    tenantId: tenantId.value,
    operationFingerprintDigest: await computeCapabilityOperationFingerprintDigest(operation),
  });
  if (!existing) {
    return {
      ok: false,
      status: 403,
      code: 'recovery_authorization_required',
      message: 'wallet recovery authorization is unavailable',
    };
  }
  return {
    ok: true,
    context: {
      authorizedOperations: input.authorizedOperations,
      activeSession,
      session: { tenantId: tenantId.value, principalId: principalId.value },
      authorityRef,
      rawClaims: claims,
      expiresAtMs,
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
  const verified = await input.emailOtp.verifyEmailOtpWalletRecoveryChallenge({
    userId: input.context.session.principalId,
    walletId: input.walletId,
    orgId: input.context.session.tenantId,
    challengeId: input.challengeId,
    otpCode: input.otpCode,
    otpChannel: EMAIL_OTP_CHANNEL,
    sessionHash: await hashEmailOtpAppSessionClaims(input.context.rawClaims),
    appSessionVersion: input.context.activeSession.appSessionVersion,
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
