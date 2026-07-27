import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
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
  type AuthorizationParseResult,
  type EvmEcdsaMpcOperationKind,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { buildCapabilityOperationEnvelope } from '../../../packages/shared-ts/src/authorization/operationFingerprint';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildActiveAuthorizationSession,
  buildActiveCapabilityGrant,
  buildActiveWalletSessionQuota,
  buildCapabilityOperationClaim,
  buildVerifiedGrantEvidenceSet,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '../../../packages/sdk-server-ts/src/authorization/domain';

const FIXTURE_NOW_MS = 1_900_000_000_000;

export async function buildReusableAuthorizationCoreFixture(
  input: {
    readonly operationKind?: EvmEcdsaMpcOperationKind;
    readonly quotaExpiresAtMs?: number;
    readonly grantRemainingUses?: number;
    readonly quotaRemainingUses?: number;
  } = {},
) {
  const operation = buildEvmEcdsaMpcOperationRef(input.operationKind ?? 'evm.sign_transaction');
  const tenantId = parsed('tenant-authorization', parseTenantId);
  const principalId = parsed('principal-human', parsePrincipalId);
  const sessionId = parsed('session-browser', parseSeamsSessionId);
  const deviceId = parsed('device-browser', parseDeviceId);
  const capabilityId = parsed('capability-evm', parseCapabilityId);
  const evidenceSetId = parsed('evidence-set-1', parseGrantEvidenceSetId);
  const grantId = parsed('grant-1', parseCapabilityGrantId);
  const walletSessionId = parseWalletSessionId('wallet-session-1');
  const quotaId = parseMpcWalletSigningQuotaId('wallet-quota-1');
  const laneDigest = fixtureDigest(1);
  const intentDigest = fixtureDigest(2);
  const displayDigest = fixtureDigest(3);
  const evidenceSetDigest = fixtureDigest(4);
  const envelope = buildCapabilityOperationEnvelope({
    tenantId,
    principalId,
    capabilityId,
    operationId: parsed('operation-1', parseCapabilityOperationId),
    operation,
    digests: { laneDigest, intentDigest, displayDigest },
  });
  return {
    session: buildActiveAuthorizationSession({
      tenantId,
      principalId,
      sessionId,
      deviceId,
      assurance: 'session',
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: FIXTURE_NOW_MS + 100_000,
    }),
    evidenceSet: buildVerifiedGrantEvidenceSet({
      tenantId,
      principalId,
      sessionId,
      deviceId,
      evidenceSetId,
      evidence: [
        {
          evidenceId: parsed('evidence-passkey-1', parseGrantEvidenceId),
          evidenceKind: 'passkey_assertion',
          evidenceDigest: fixtureDigest(5),
        },
      ],
      evidenceSetDigest,
      operation,
      laneDigest,
      intentDigest,
      displayDigest,
      assurance: 'session',
      expiresAtMs: FIXTURE_NOW_MS + 90_000,
    }),
    grant: buildActiveCapabilityGrant({
      tenantId,
      principalId,
      grantId,
      bindingId: parsed('binding-owner-1', parseCapabilityBindingId),
      evidenceSetId,
      evidenceSetDigest,
      capabilityId,
      operation,
      laneDigest,
      intentDigest,
      displayDigest,
      authority: {
        kind: 'reusable_wallet_session',
        walletSessionId,
        quotaId,
      },
      remainingUses: input.grantRemainingUses ?? 2,
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: FIXTURE_NOW_MS + 80_000,
    }),
    quota: buildActiveWalletSessionQuota({
      tenantId,
      principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.quotaRemainingUses ?? 2,
      expiresAtMs: input.quotaExpiresAtMs ?? FIXTURE_NOW_MS + 70_000,
    }),
    claim: await buildCapabilityOperationClaim({
      tenantId,
      useId: parsed('grant-use-1', parseCapabilityGrantUseId),
      auditEventId: parsed('audit-event-1', parseAuthorizationAuditEventId),
      grantId,
      operation: envelope,
      evidenceSetDigest,
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
  fixture: Awaited<ReturnType<typeof buildReusableAuthorizationCoreFixture>>,
  suffix: string,
) {
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

export async function buildStepUpAuthorizationCoreFixture() {
  const reusable = await buildReusableAuthorizationCoreFixture();
  const operation = reusable.evidenceSet.operation;
  return {
    session: reusable.session,
    evidenceSet: reusable.evidenceSet,
    grant: buildActiveCapabilityGrant({
      tenantId: reusable.grant.tenantId,
      principalId: reusable.grant.principalId,
      grantId: reusable.grant.grantId,
      bindingId: reusable.grant.bindingId,
      evidenceSetId: reusable.grant.evidenceSetId,
      evidenceSetDigest: reusable.grant.evidenceSetDigest,
      capabilityId: reusable.grant.capabilityId,
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

function fixtureDigest(fill: number) {
  return parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(fill)));
}

function parsed<T>(value: string, parser: (raw: unknown) => AuthorizationParseResult<T>): T {
  const result = parser(value);
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}
