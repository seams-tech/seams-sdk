import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthFactorId,
  parseCapabilityBindingId,
  parseCapabilityGrantId,
  parseCapabilityGrantUseId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseCapabilityOperationResultStorageRef,
  parseDeviceId,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  parseReusableWalletSessionMintId,
  type AuthorizationParseResult,
  type EvmEcdsaMpcOperationKind,
  type GrantEvidenceId,
  type GrantEvidenceSetId,
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
  buildActiveCapabilityGrant,
  buildWalletSessionAuthorization,
  buildActiveWalletSessionQuota,
  buildCapabilityOperationClaim,
  parseSessionOrigin,
  type ActiveAuthorizationSession,
  type ActiveCapabilityGrant,
  type ActiveWalletSessionQuota,
  type WalletSessionAuthorization,
  type CapabilityOperationClaim,
  type ClaimCapabilityOperationResult,
  type CapabilityOperationResultRef,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildVerifiedEmailOtpFactorResult,
  buildVerifiedPasskeyFactorResult,
  buildVerifiedSessionEvidenceSet,
  type VerifiedEmailOtpFactorResult,
  type VerifiedGrantEvidenceSet,
  type VerifiedPasskeyFactorResult,
  type VerifiedSessionEvidenceSetInput,
} from '../../../packages/sdk-server-ts/src/authorization/factorEvidence';

const FIXTURE_NOW_MS = 1_900_000_000_000;

export type ReusableAuthorizationCoreFixture = {
  readonly session: ActiveAuthorizationSession;
  readonly sessionEvidenceInput: VerifiedSessionEvidenceSetInput;
  readonly evidenceSet: VerifiedGrantEvidenceSet;
  readonly grant: ActiveCapabilityGrant;
  readonly quota: ActiveWalletSessionQuota;
  readonly reusableWalletSession: WalletSessionAuthorization;
  readonly claim: CapabilityOperationClaim;
  readonly resultRef: CapabilityOperationResultRef;
};

export type StepUpAuthorizationCoreFixture = Omit<
  ReusableAuthorizationCoreFixture,
  'quota' | 'reusableWalletSession'
>;

export type PasskeyVerifiedFactorFixture = {
  readonly authorization: ReusableAuthorizationCoreFixture;
  readonly evidenceId: GrantEvidenceId;
  readonly evidenceSetId: GrantEvidenceSetId;
  readonly factor: VerifiedPasskeyFactorResult;
};

export type EmailOtpVerifiedFactorFixture = {
  readonly authorization: ReusableAuthorizationCoreFixture;
  readonly evidenceId: GrantEvidenceId;
  readonly evidenceSetId: GrantEvidenceSetId;
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
  const evidenceSetId = parsed('evidence-set-1', parseGrantEvidenceSetId);
  const grantId = parsed('grant-1', parseCapabilityGrantId);
  const walletSessionId = parsed('wallet-session-1', parseWalletSessionId);
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
    evidenceId: parsed('evidence-session-1', parseGrantEvidenceId),
    evidenceSetId,
    expiresAtMs: FIXTURE_NOW_MS + 90_000,
  };
  const evidenceSet = await buildVerifiedSessionEvidenceSet(sessionEvidenceInput);
  return {
    session,
    sessionEvidenceInput,
    evidenceSet,
    grant: buildActiveCapabilityGrant({
      tenantId,
      principalId,
      grantId,
      bindingId: parsed('binding-owner-1', parseCapabilityBindingId),
      evidenceSetId,
      evidenceSetDigest: evidenceSet.evidenceSetDigest,
      capabilityId,
      operationId: envelope.operationId,
      operation,
      laneDigest,
      intentDigest,
      displayDigest,
      authority: {
        kind: 'reusable_wallet_session',
        walletSessionId,
        quotaId,
      },
      remainingUses: 1,
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: walletSessionExpiresAtMs,
    }),
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
      walletSessionId,
      quotaId,
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: walletSessionExpiresAtMs,
    }),
    claim: await buildCapabilityOperationClaim({
      tenantId,
      useId: parsed('grant-use-1', parseCapabilityGrantUseId),
      auditEventId: parsed('audit-event-1', parseAuthorizationAuditEventId),
      grantId,
      operation: envelope,
      evidenceSetDigest: evidenceSet.evidenceSetDigest,
      claimedAtMs: FIXTURE_NOW_MS + 1_000,
      authorization: {
        kind: 'reusable_wallet_session',
        walletSessionId,
        quotaId,
      },
    }),
    resultRef: {
      resultDigest: fixtureDigest(6),
      resultStorageRef: parsed('operation-result-1', parseCapabilityOperationResultStorageRef),
    },
  };
}

export async function buildAdditionalAuthorizationClaim(
  fixture: ReusableAuthorizationCoreFixture,
  suffix: string,
): Promise<CapabilityOperationClaim> {
  const operation = buildCapabilityOperationEnvelope({
    tenantId: fixture.claim.operation.tenantId,
    principalId: fixture.claim.operation.principalId,
    capabilityId: fixture.claim.operation.capabilityId,
    operationId: parsed(`operation-${suffix}`, parseCapabilityOperationId),
    operation: fixture.claim.operation.operation,
    digests: fixture.claim.operation.digests,
  });
  return await buildCapabilityOperationClaim({
    tenantId: fixture.claim.tenantId,
    useId: parsed(`grant-use-${suffix}`, parseCapabilityGrantUseId),
    auditEventId: parsed(`audit-event-${suffix}`, parseAuthorizationAuditEventId),
    grantId: fixture.claim.grantId,
    operation,
    evidenceSetDigest: fixture.claim.evidenceSetDigest,
    claimedAtMs: fixture.claim.claimedAtMs,
    authorization: fixture.claim.authorization,
  });
}

export async function buildStepUpAuthorizationCoreFixture(): Promise<StepUpAuthorizationCoreFixture> {
  const reusable = await buildReusableAuthorizationCoreFixture();
  const operation = reusable.evidenceSet.operation;
  return {
    session: reusable.session,
    sessionEvidenceInput: reusable.sessionEvidenceInput,
    evidenceSet: reusable.evidenceSet,
    grant: buildActiveCapabilityGrant({
      tenantId: reusable.grant.tenantId,
      principalId: reusable.grant.principalId,
      grantId: reusable.grant.grantId,
      bindingId: reusable.grant.bindingId,
      evidenceSetId: reusable.grant.evidenceSetId,
      evidenceSetDigest: reusable.grant.evidenceSetDigest,
      capabilityId: reusable.grant.capabilityId,
      operationId: reusable.grant.operationId,
      operation,
      laneDigest: reusable.grant.laneDigest,
      intentDigest: reusable.grant.intentDigest,
      displayDigest: reusable.grant.displayDigest,
      authority: { kind: 'operation_step_up' },
      remainingUses: 1,
      createdAtMs: reusable.grant.createdAtMs,
      expiresAtMs: reusable.grant.expiresAtMs,
    }),
    claim: await buildCapabilityOperationClaim({
      tenantId: reusable.claim.tenantId,
      useId: reusable.claim.useId,
      auditEventId: reusable.claim.auditEventId,
      grantId: reusable.claim.grantId,
      operation: reusable.claim.operation,
      evidenceSetDigest: reusable.claim.evidenceSetDigest,
      claimedAtMs: reusable.claim.claimedAtMs,
      authorization: { kind: 'operation_step_up' },
    }),
    resultRef: reusable.resultRef,
  };
}

export function buildClaimedCapabilityOperationResult(
  fixture: StepUpAuthorizationCoreFixture,
  input: {
    readonly useId?: CapabilityOperationClaim['useId'];
  } = {},
): ClaimCapabilityOperationResult {
  return {
    kind: 'claimed',
    use: {
      kind: 'claimed',
      tenantId: fixture.claim.tenantId,
      useId: input.useId ?? fixture.claim.useId,
      grantId: fixture.claim.grantId,
      principalId: fixture.claim.operation.principalId,
      capabilityId: fixture.claim.operation.capabilityId,
      operationId: fixture.claim.operation.operationId,
      operation: fixture.claim.operation.operation,
      operationFingerprintDigest: fixture.claim.operationFingerprintDigest,
      evidenceSetDigest: fixture.claim.evidenceSetDigest,
      claimedAtMs: fixture.claim.claimedAtMs,
    },
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
    evidenceId: parsed('evidence-passkey-adapter', parseGrantEvidenceId),
    evidenceSetId: parsed('evidence-set-passkey-adapter', parseGrantEvidenceSetId),
    factor: buildVerifiedPasskeyFactorResult({
      tenantId: authorization.session.tenantId,
      principalId: authorization.session.principalId,
      sessionId: authorization.session.sessionId,
      deviceId: authorization.session.deviceId,
      factorId: parsed('factor-passkey-adapter', parseAuthFactorId),
      authorityRef,
      operation: authorization.claim.operation,
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
    evidenceId: parsed('evidence-email-otp-adapter', parseGrantEvidenceId),
    evidenceSetId: parsed('evidence-set-email-otp-adapter', parseGrantEvidenceSetId),
    factor: buildVerifiedEmailOtpFactorResult({
      tenantId: authorization.session.tenantId,
      principalId: authorization.session.principalId,
      sessionId: authorization.session.sessionId,
      deviceId: authorization.session.deviceId,
      factorId: parsed('factor-email-otp-adapter', parseAuthFactorId),
      authorityRef,
      operation: authorization.claim.operation,
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
