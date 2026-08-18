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
import type { RecoveryCodeReservationId } from '@shared/wallet-recovery/recoveryCodeReservation';
import type { AuthorizedOperation } from '../../../authorization/domain';
import { parseSessionOrigin, type SessionOrigin } from '../../../authorization/domain';
import { parsePrincipalId, parseTenantId } from '@shared/authorization/capabilityKinds';
import { buildVerifiedWalletOperationEmailOtpFactorResult } from '../../../authorization/factorEvidence';
import type {
  RouterApiAuthorizedOperationService,
} from '../../framework/authServicePort';
import type { SessionAdapter } from '../../framework/routerApi';
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
  readonly session: {
    readonly tenantId: Parameters<typeof buildWalletRecoveryOperation>[0]['tenantId'];
    readonly principalId: Parameters<typeof buildWalletRecoveryOperation>[0]['principalId'];
  };
  readonly authorityRef: Parameters<
    typeof buildVerifiedWalletOperationEmailOtpFactorResult
  >[0]['authorityRef'];
  readonly requestOrigin: SessionOrigin;
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

/** Builds one operation-bound recovery authorization from a bootstrap grant. */
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
  readonly requestOrigin: string;
  readonly nowMs: number;
}): Promise<WalletRecoveryAuthorizationContextResult> {
  if (!input.authorizedOperations) {
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
  if (!tenantId.ok || !principalId.ok) {
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
      session: { tenantId: tenantId.value, principalId: principalId.value },
      authorityRef,
      requestOrigin: origin,
      rawClaims: {
        sub: principalId.value,
        tenantId: tenantId.value,
        walletId: input.grant.walletId,
        walletAuthAuthorityRef: authorityRef,
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
  const factor = buildVerifiedWalletOperationEmailOtpFactorResult({
    tenantId: input.context.session.tenantId,
    principalId: input.context.session.principalId,
    walletId: input.context.authorityRef.walletId,
    requestOrigin: input.context.requestOrigin,
    audience: input.context.requestOrigin,
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
  const evidenceSet =
    await input.context.authorizedOperations.recordVerifiedWalletOperationFactorEvidenceSet({
      operation: input.context.operation,
      evidenceId: authorizationValue(
        parseAuthorizationEvidenceId(`wallet-recovery-bootstrap-evidence:${input.reservationId}`),
      ),
      evidenceSetId: authorizationValue(
        parseAuthorizationEvidenceSetId(
          `wallet-recovery-bootstrap-evidence-set:${input.reservationId}`,
        ),
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
  readonly nowMs: number;
}): Promise<WalletRecoveryAuthorizationContextResult> {
  if (!input.session || !input.authorizedOperations) {
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
  const authorityRef = parseWalletAuthAuthorityRef(claims.authorityRef);
  const tokenOrigin = typeof claims.origin === 'string' ? claims.origin.trim() : '';
  const expiresAtMs = Number(claims.exp) * 1_000;
  if (
    walletId !== input.walletId ||
    reservationId !== String(input.reservationId) ||
    challengeId !== input.challengeId ||
    !tenantId.ok ||
    !principalId.ok ||
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
      session: { tenantId: tenantId.value, principalId: principalId.value },
      authorityRef,
      requestOrigin: audience,
      rawClaims: claims,
      expiresAtMs,
      operation,
      existing,
    },
  };
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
