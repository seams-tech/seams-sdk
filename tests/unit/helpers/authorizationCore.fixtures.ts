import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthFactorId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationResultStorageRef,
  parseAuthorizedOperationId,
  parseDeviceId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  parseReusableWalletSessionMintId,
  buildAuthorizationGrantRef,
  type AuthorizationParseResult,
  type EvmEcdsaMpcOperationKind,
  type AuthorizationEvidenceId,
  type AuthorizationEvidenceSetId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '../../../packages/shared-ts/src/authorization/operationFingerprint';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseAppSessionVersion,
  parseEmailOtpChallengeId,
  parseProviderSubject,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
} from '../../../packages/shared-ts/src/utils/domainIds';
import {
  buildPasskeyWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
  walletAuthAuthorityRef,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '../../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  buildActiveAuthorizationSession,
  buildAuthorizedOperation,
  buildWalletSessionAuthorization,
  buildActiveWalletSessionQuota,
  parseSessionOrigin,
  type ActiveAuthorizationSession,
  type ActiveWalletSessionQuota,
  type WalletSessionAuthorization,
  type AuthorizedOperation,
  type CapabilityOperationResultRef,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  buildVerifiedSessionEvidenceSet,
  type VerifiedEmailOtpFactorResult,
  type VerifiedAuthorizationEvidenceSet,
  type VerifiedPasskeyFactorResult,
  type VerifiedSessionEvidenceSetInput,
} from '../../../packages/sdk-server-ts/src/authorization/factorEvidence';

const FIXTURE_NOW_MS = 1_900_000_000_000;

export type ReusableAuthorizationCoreFixture = {
  readonly session: ActiveAuthorizationSession;
  readonly sessionEvidenceInput: VerifiedSessionEvidenceSetInput;
  readonly evidenceSet: VerifiedAuthorizationEvidenceSet;
  readonly quota: ActiveWalletSessionQuota;
  readonly reusableWalletSession: WalletSessionAuthorization;
  readonly authorizedOperation: AuthorizedOperation;
  readonly resultRef: CapabilityOperationResultRef;
};

export type StepUpAuthorizationCoreFixture = Omit<
  ReusableAuthorizationCoreFixture,
  'quota' | 'reusableWalletSession'
>;

export type PasskeyVerifiedFactorFixture = {
  readonly authorization: ReusableAuthorizationCoreFixture;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly factor: VerifiedPasskeyFactorResult;
};

export type EmailOtpVerifiedFactorFixture = {
  readonly authorization: ReusableAuthorizationCoreFixture;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly factor: VerifiedEmailOtpFactorResult;
};

export type PasskeyAuthorizationSessionFixture = {
  readonly session: ActiveAuthorizationSession;
  readonly authority: PasskeyWalletAuthAuthority;
  readonly authorityRef: WalletAuthAuthorityRef;
};

export async function buildReusableAuthorizationCoreFixture(
  input: {
    readonly operationKind?: EvmEcdsaMpcOperationKind;
    readonly quotaExpiresAtMs?: number;
    readonly quotaRemainingUses?: number;
  } = {},
): Promise<ReusableAuthorizationCoreFixture> {
  const operation = buildEvmEcdsaMpcOperationRef(input.operationKind ?? 'evm.sign_transaction');
  const tenantId = parsed('tenant-authorization', parseTenantId);
  const principalId = parsed('principal-human', parsePrincipalId);
  const sessionId = parsed('session-browser', parseSeamsSessionId);
  const deviceId = parsed('device-browser', parseDeviceId);
  const capabilityId = parsed('capability-evm', parseCapabilityId);
  const evidenceSetId = parsed('evidence-set-1', parseAuthorizationEvidenceSetId);
  const walletSessionId = parsed('wallet-session-1', parseWalletSessionId);
  const authorizationId = parsed('authorization-grant-1', parseWalletSessionAuthorizationId);
  const quotaId = parsed('wallet-quota-1', parseMpcWalletSigningQuotaId);
  const walletId = parsed('wallet-authorization', parseWalletId);
  const walletSessionExpiresAtMs = input.quotaExpiresAtMs ?? FIXTURE_NOW_MS + 80_000;
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: parsed('authority-digest-1', parseWalletAuthorityBindingDigest),
  });
  if (!authority) throw new Error('fixture wallet authority is invalid');
  const laneDigest = fixtureDigest(1);
  const intentDigest = fixtureDigest(2);
  const displayDigest = fixtureDigest(3);
  const envelope = buildCapabilityOperationEnvelope({
    tenantId,
    principalId,
    capabilityId,
    operationId: parsed('operation-1', parseCapabilityOperationId),
    operation,
    digests: { laneDigest, intentDigest, displayDigest },
  });
  const session = buildActiveAuthorizationSession({
    tenantId,
    principalId,
    sessionId,
    authSource: {
      kind: 'oidc_provider',
      providerId: 'google_oidc',
      providerSubject: parsed('google-subject-1', parseProviderSubject),
    },
    deviceId,
    audience: {
      kind: 'first_party_web',
      origin: parseSessionOrigin('https://app.example.test'),
    },
    appSessionVersion: parsed('app-session-version-1', parseAppSessionVersion),
    assurance: 'session',
    createdAtMs: FIXTURE_NOW_MS,
    lifecycle: {
      kind: 'active',
      expiresAtMs: FIXTURE_NOW_MS + 100_000,
    },
  });
  const sessionEvidenceInput = {
    session,
    operation: envelope,
    evidenceId: parsed('evidence-session-1', parseAuthorizationEvidenceId),
    evidenceSetId,
    expiresAtMs: FIXTURE_NOW_MS + 90_000,
  };
  const evidenceSet = await buildVerifiedSessionEvidenceSet(sessionEvidenceInput);
  const authorizedOperation = await buildAuthorizedOperation({
    tenantId,
    authorizedOperationId: parsed('authorized-operation-1', parseAuthorizedOperationId),
    auditEventId: parsed('audit-event-1', parseAuthorizationAuditEventId),
    operation: envelope,
    authorization: {
      kind: 'authorization_grant',
      authorizationGrantRef: buildAuthorizationGrantRef(authorizationId),
    },
    quota:
      operation.operationKind === 'evm.export_key'
        ? { kind: 'quota_neutral' }
        : { kind: 'consume_reusable_wallet_session', quotaId },
    claimedAtMs: FIXTURE_NOW_MS + 1_000,
  });
  return {
    session,
    sessionEvidenceInput,
    evidenceSet,
    quota: buildActiveWalletSessionQuota({
      tenantId,
      principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.quotaRemainingUses ?? 2,
      expiresAtMs: walletSessionExpiresAtMs,
    }),
    reusableWalletSession: buildWalletSessionAuthorization({
      tenantId,
      principalId,
      walletId,
      authority,
      mintId: parsed('wallet-session-mint-1', parseReusableWalletSessionMintId),
      authorizationId,
      walletSessionId,
      quotaId,
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: walletSessionExpiresAtMs,
    }),
    authorizedOperation,
    resultRef: {
      authorizedOperationId: authorizedOperation.authorizedOperationId,
      operationFingerprintDigest: authorizedOperation.operationFingerprintDigest,
      resultDigest: fixtureDigest(6),
      resultStorageRef: parsed('operation-result-1', parseCapabilityOperationResultStorageRef),
    },
  };
}

export async function buildAdditionalAuthorizedOperation(
  fixture: ReusableAuthorizationCoreFixture,
  suffix: string,
): Promise<AuthorizedOperation> {
  const operation = buildCapabilityOperationEnvelope({
    tenantId: fixture.authorizedOperation.operation.tenantId,
    principalId: fixture.authorizedOperation.operation.principalId,
    capabilityId: fixture.authorizedOperation.operation.capabilityId,
    operationId: parsed(`operation-${suffix}`, parseCapabilityOperationId),
    operation: fixture.authorizedOperation.operation.operation,
    digests: fixture.authorizedOperation.operation.digests,
  });
  return await buildAuthorizedOperation({
    tenantId: fixture.authorizedOperation.tenantId,
    authorizedOperationId: parsed(`authorized-operation-${suffix}`, parseAuthorizedOperationId),
    auditEventId: parsed(`audit-event-${suffix}`, parseAuthorizationAuditEventId),
    operation,
    authorization: fixture.authorizedOperation.authorization,
    quota: fixture.authorizedOperation.quota,
    claimedAtMs: FIXTURE_NOW_MS + 1_000,
  });
}

export async function buildStepUpAuthorizationCoreFixture(): Promise<StepUpAuthorizationCoreFixture> {
  const reusable = await buildReusableAuthorizationCoreFixture();
  const operation = reusable.authorizedOperation.operation;
  return {
    session: reusable.session,
    sessionEvidenceInput: reusable.sessionEvidenceInput,
    evidenceSet: reusable.evidenceSet,
    authorizedOperation: await buildAuthorizedOperation({
      tenantId: reusable.authorizedOperation.tenantId,
      authorizedOperationId: reusable.authorizedOperation.authorizedOperationId,
      auditEventId: reusable.authorizedOperation.auditEventId,
      operation,
      authorization: {
        kind: 'verified_step_up',
        evidenceSetDigest: reusable.evidenceSet.evidenceSetDigest,
      },
      quota: { kind: 'quota_neutral' },
      claimedAtMs: FIXTURE_NOW_MS + 1_000,
    }),
    resultRef: reusable.resultRef,
  };
}

export async function buildPasskeyVerifiedFactorFixture(): Promise<PasskeyVerifiedFactorFixture> {
  const authorization = await buildReusableAuthorizationCoreFixture();
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: parsedDomain('wallet-passkey', parseWalletId),
    authorityDigest: parsedDomain(fixtureDigest(7), parseWalletAuthorityBindingDigest),
  });
  if (!authorityRef) throw new Error('Passkey authority ref fixture is invalid');
  return {
    authorization,
    evidenceId: parsed('evidence-passkey-adapter', parseAuthorizationEvidenceId),
    evidenceSetId: parsed('evidence-set-passkey-adapter', parseAuthorizationEvidenceSetId),
    factor: buildVerifiedPasskeyFactorResult({
      tenantId: authorization.session.tenantId,
      principalId: authorization.session.principalId,
      sessionId: authorization.session.sessionId,
      deviceId: authorization.session.deviceId,
      factorId: parsed('factor-passkey-adapter', parseAuthFactorId),
      authorityRef,
      operation: authorization.authorizedOperation.operation,
      credentialIdB64u: parsedDomain('credential-passkey-adapter', parseWebAuthnCredentialIdB64u),
      assertionDigest: fixtureDigest(8),
      verifiedAtMs: authorization.session.createdAtMs + 1_000,
      expiresAtMs: authorization.session.createdAtMs + 60_000,
    }),
  };
}

export async function buildPasskeyAuthorizationSessionFixture(input: {
  readonly tenantId: string;
  readonly principalId: string;
  readonly sessionId: string;
  readonly deviceId: string;
  readonly walletId: string;
  readonly credentialIdB64u: string;
  readonly rpId: string;
  readonly origin: string;
  readonly expiresAtMs: number;
}): Promise<PasskeyAuthorizationSessionFixture> {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: input.walletId,
    credentialIdB64u: input.credentialIdB64u,
    rpId: input.rpId,
  });
  return {
    authority,
    authorityRef: await walletAuthAuthorityRef({ authority }),
    session: buildActiveAuthorizationSession({
      tenantId: parsed(input.tenantId, parseTenantId),
      principalId: parsed(input.principalId, parsePrincipalId),
      sessionId: parsed(input.sessionId, parseSeamsSessionId),
      authSource: {
        kind: 'passkey',
        credentialIdB64u: authority.factor.credentialIdB64u,
      },
      deviceId: parsed(input.deviceId, parseDeviceId),
      audience: {
        kind: 'first_party_web',
        origin: parseSessionOrigin(input.origin),
      },
      appSessionVersion: parsed('app-session-version-1', parseAppSessionVersion),
      assurance: 'session',
      createdAtMs: input.expiresAtMs - 60_000,
      lifecycle: {
        kind: 'active',
        expiresAtMs: input.expiresAtMs,
      },
    }),
  };
}

export async function buildEmailOtpVerifiedFactorFixture(): Promise<EmailOtpVerifiedFactorFixture> {
  const authorization = await buildReusableAuthorizationCoreFixture();
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: parsedDomain('wallet-email-otp', parseWalletId),
    authorityDigest: parsedDomain(fixtureDigest(9), parseWalletAuthorityBindingDigest),
  });
  if (!authorityRef) throw new Error('Email OTP authority ref fixture is invalid');
  return {
    authorization,
    evidenceId: parsed('evidence-email-otp-adapter', parseAuthorizationEvidenceId),
    evidenceSetId: parsed('evidence-set-email-otp-adapter', parseAuthorizationEvidenceSetId),
    factor: buildVerifiedEmailOtpFactorResult({
      tenantId: authorization.session.tenantId,
      principalId: authorization.session.principalId,
      sessionId: authorization.session.sessionId,
      deviceId: authorization.session.deviceId,
      factorId: parsed('factor-email-otp-adapter', parseAuthFactorId),
      authorityRef,
      operation: authorization.authorizedOperation.operation,
      challengeId: parsedDomain('challenge-email-otp-adapter', parseEmailOtpChallengeId),
      verificationReceiptDigest: fixtureDigest(10),
      verifiedAtMs: authorization.session.createdAtMs + 1_000,
      expiresAtMs: authorization.session.createdAtMs + 60_000,
    }),
  };
}

function fixtureDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

function parsed<T>(value: string, parser: (raw: unknown) => AuthorizationParseResult<T>): T {
  const result = parser(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function parsedDomain<T>(
  value: unknown,
  parser: (raw: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  const result = parser(value);
  if (!result.ok) throw new Error('authorization fixture domain identifier is invalid');
  return result.value;
}
