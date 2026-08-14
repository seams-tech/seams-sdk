import {
  buildEvmEcdsaMpcOperationRef,
  parseAuthorizationAuditEventId,
  parseAuthFactorId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseAuthorizedOperationId,
  parseAuthorizationEvidenceId,
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parsePrincipalId,
  parseTenantId,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  parseReusableWalletSessionMintId,
  buildAuthorizationGrantRef,
  type AuthorizationParseResult,
  type EvmEcdsaMpcOperationKind,
  type AuthorizationAuditEventId,
  type AuthorizedOperationId,
  type MpcWalletSigningQuotaId,
  type PrincipalId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type CapabilityOperationRef,
  type AuthorizationEvidenceId,
  type AuthorizationEvidenceSetId,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '../../../packages/shared-ts/src/authorization/operationFingerprint';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
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
  buildAuthorizedOperation,
  buildWalletSessionAuthorization,
  buildActiveWalletSessionQuota,
  parseSessionOrigin,
  computeAuthorizedOperationResultDigest,
  parseAuthorizedOperationReplayResponse,
  type ActiveWalletSessionQuota,
  type WalletSessionAuthorization,
  type AuthorizedOperation,
  type AuthorizedOperationReplayResponse,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildVerifiedWalletOperationPasskeyFactorResult,
  buildVerifiedWalletOperationFactorEvidenceSet,
  type VerifiedAuthorizationEvidenceSet,
  type VerifiedWalletOperationPasskeyFactorResult,
} from '../../../packages/sdk-server-ts/src/authorization/factorEvidence';

const FIXTURE_NOW_MS = 1_900_000_000_000;

export type ReusableAuthorizationCoreFixture = {
  readonly session: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
    readonly origin: ReturnType<typeof parseSessionOrigin>;
  };
  readonly evidenceSet: VerifiedAuthorizationEvidenceSet;
  readonly quota: ActiveWalletSessionQuota;
  readonly reusableWalletSession: WalletSessionAuthorization;
  readonly authorizedOperation: AuthorizedOperation;
  readonly response: AuthorizedOperationReplayResponse;
};

export type StepUpAuthorizationCoreFixture = Omit<
  ReusableAuthorizationCoreFixture,
  'quota' | 'reusableWalletSession'
>;

export type WalletOperationPasskeyVerifiedFactorFixture = {
  readonly authorization: ReusableAuthorizationCoreFixture;
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceSetId: AuthorizationEvidenceSetId;
  readonly factor: VerifiedWalletOperationPasskeyFactorResult;
};

export type PasskeyWalletSessionIssuanceFixture = {
  readonly session: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly createdAtMs: number;
    readonly expiresAtMs: number;
    readonly origin: ReturnType<typeof parseSessionOrigin>;
  };
  readonly authority: PasskeyWalletAuthAuthority;
  readonly authorityRef: WalletAuthAuthorityRef;
};

type EvmFixtureOperation =
  | {
      readonly operationKind: 'evm.sign_transaction';
      readonly envelope: CapabilityOperationEnvelope<
        Extract<CapabilityOperationRef, { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }> & {
          readonly operationKind: 'evm.sign_transaction';
        }
      >;
    }
  | {
      readonly operationKind: 'evm.export_key';
      readonly envelope: CapabilityOperationEnvelope<
        Extract<CapabilityOperationRef, { readonly capabilityKind: 'evm_ecdsa_mpc_signing' }> & {
          readonly operationKind: 'evm.export_key';
        }
      >;
    };

export async function buildReusableAuthorizationCoreFixture(
  input: {
    readonly operationKind?: EvmEcdsaMpcOperationKind;
    readonly quotaExpiresAtMs?: number;
    readonly quotaRemainingUses?: number;
  } = {},
): Promise<ReusableAuthorizationCoreFixture> {
  const operationKind = input.operationKind ?? 'evm.sign_transaction';
  const tenantId = parsed('tenant-authorization', parseTenantId);
  const principalId = parsed('principal-human', parsePrincipalId);
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
  const operationId = parsed('operation-1', parseCapabilityOperationId);
  const fixtureOperation: EvmFixtureOperation =
    operationKind === 'evm.export_key'
      ? {
          operationKind,
          envelope: buildCapabilityOperationEnvelope({
            tenantId,
            principalId,
            capabilityId,
            operationId,
            operation: buildEvmEcdsaMpcOperationRef(operationKind),
            digests: { laneDigest, intentDigest, displayDigest },
          }),
        }
      : {
          operationKind,
          envelope: buildCapabilityOperationEnvelope({
            tenantId,
            principalId,
            capabilityId,
            operationId,
            operation: buildEvmEcdsaMpcOperationRef(operationKind),
            digests: { laneDigest, intentDigest, displayDigest },
          }),
        };
  const envelope = fixtureOperation.envelope;
  const origin = parseSessionOrigin('https://app.example.test');
  const factor = buildVerifiedWalletOperationPasskeyFactorResult({
    tenantId,
    principalId,
    walletId,
    authorityRef: authority,
    requestOrigin: origin,
    audience: origin,
    factorId: parsed('factor-wallet-operation', parseAuthFactorId),
    operation: envelope,
    credentialIdB64u: parsedDomain('credential-wallet-operation', parseWebAuthnCredentialIdB64u),
    assertionDigest: fixtureDigest(7),
    verifiedAtMs: FIXTURE_NOW_MS + 500,
    expiresAtMs: FIXTURE_NOW_MS + 90_000,
  });
  const evidenceSet = await buildVerifiedWalletOperationFactorEvidenceSet({
    operation: envelope,
    evidenceId: parsed('evidence-wallet-operation-1', parseAuthorizationEvidenceId),
    evidenceSetId,
    factor,
  });
  const authorizedOperation = await buildReusableFixtureAuthorizedOperation({
    tenantId,
    authorizedOperationId: parsed('authorized-operation-1', parseAuthorizedOperationId),
    auditEventId: parsed('audit-event-1', parseAuthorizationAuditEventId),
    fixtureOperation,
    authorizationId,
    quotaId,
    claimedAtMs: FIXTURE_NOW_MS + 1_000,
  });
  return {
    session: {
      tenantId,
      principalId,
      createdAtMs: FIXTURE_NOW_MS,
      expiresAtMs: FIXTURE_NOW_MS + 100_000,
      origin,
    },
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
    response: {
      status: 200,
      contentType: 'application/json',
      bodyText: '{"ok":true}',
    },
  };
}

export async function buildAdditionalAuthorizedOperation(
  fixture: ReusableAuthorizationCoreFixture,
  suffix: string,
): Promise<AuthorizedOperation> {
  const operationRef = fixture.authorizedOperation.operation.operation;
  if (operationRef.capabilityKind !== 'evm_ecdsa_mpc_signing') {
    throw new Error('reusable authorization fixture operation must be EVM');
  }
  const operationId = parsed(`operation-${suffix}`, parseCapabilityOperationId);
  const fixtureOperation =
    operationRef.operationKind === 'evm.export_key'
      ? {
          operationKind: 'evm.export_key' as const,
          envelope: buildCapabilityOperationEnvelope({
            tenantId: fixture.authorizedOperation.operation.tenantId,
            principalId: fixture.authorizedOperation.operation.principalId,
            capabilityId: fixture.authorizedOperation.operation.capabilityId,
            operationId,
            operation: buildEvmEcdsaMpcOperationRef('evm.export_key'),
            digests: fixture.authorizedOperation.operation.digests,
          }),
        }
      : {
          operationKind: 'evm.sign_transaction' as const,
          envelope: buildCapabilityOperationEnvelope({
            tenantId: fixture.authorizedOperation.operation.tenantId,
            principalId: fixture.authorizedOperation.operation.principalId,
            capabilityId: fixture.authorizedOperation.operation.capabilityId,
            operationId,
            operation: buildEvmEcdsaMpcOperationRef('evm.sign_transaction'),
            digests: fixture.authorizedOperation.operation.digests,
          }),
        };
  return await buildReusableFixtureAuthorizedOperation({
    tenantId: fixture.authorizedOperation.tenantId,
    authorizedOperationId: parsed(`authorized-operation-${suffix}`, parseAuthorizedOperationId),
    auditEventId: parsed(`audit-event-${suffix}`, parseAuthorizationAuditEventId),
    fixtureOperation,
    authorizationId: fixture.reusableWalletSession.authorizationId,
    quotaId: fixture.reusableWalletSession.quotaId,
    claimedAtMs: FIXTURE_NOW_MS + 1_000,
  });
}

async function buildReusableFixtureAuthorizedOperation(input: {
  readonly tenantId: TenantId;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly fixtureOperation: EvmFixtureOperation;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly claimedAtMs: number;
}): Promise<AuthorizedOperation> {
  switch (input.fixtureOperation.operationKind) {
    case 'evm.export_key':
      return await buildAuthorizedOperation({
        tenantId: input.tenantId,
        authorizedOperationId: input.authorizedOperationId,
        auditEventId: input.auditEventId,
        operation: input.fixtureOperation.envelope,
        authorization: {
          kind: 'authorization_grant',
          authorizationGrantRef: buildAuthorizationGrantRef(input.authorizationId),
        },
        quota: { kind: 'quota_neutral' },
        claimedAtMs: input.claimedAtMs,
      });
    case 'evm.sign_transaction':
      return await buildAuthorizedOperation({
        tenantId: input.tenantId,
        authorizedOperationId: input.authorizedOperationId,
        auditEventId: input.auditEventId,
        operation: input.fixtureOperation.envelope,
        authorization: {
          kind: 'authorization_grant',
          authorizationGrantRef: buildAuthorizationGrantRef(input.authorizationId),
        },
        quota: { kind: 'consume_reusable_wallet_session', quotaId: input.quotaId },
        claimedAtMs: input.claimedAtMs,
      });
  }
}

export async function buildCompletedAuthorizedOperationFixture(
  fixture: ReusableAuthorizationCoreFixture,
): Promise<AuthorizedOperation> {
  const operation = fixture.authorizedOperation;
  if (operation.lifecycle !== 'claimed') {
    throw new Error('authorization fixture operation must start claimed');
  }
  const response = parseAuthorizedOperationReplayResponse(fixture.response);
  return {
    ...operation,
    lifecycle: 'completed',
    result: 'succeeded',
    response,
    resultDigest: await computeAuthorizedOperationResultDigest(response),
    completedAtMs: operation.claimedAtMs + 1,
  };
}

export async function buildStepUpAuthorizationCoreFixture(): Promise<StepUpAuthorizationCoreFixture> {
  const reusable = await buildReusableAuthorizationCoreFixture();
  const operation = reusable.authorizedOperation.operation;
  return {
    session: reusable.session,
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
    response: reusable.response,
  };
}

export async function buildWalletOperationPasskeyVerifiedFactorFixture(): Promise<WalletOperationPasskeyVerifiedFactorFixture> {
  const authorization = await buildReusableAuthorizationCoreFixture();
  const walletId = parsedDomain('wallet-passkey', parseWalletId);
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId,
    authorityDigest: parsedDomain(fixtureDigest(17), parseWalletAuthorityBindingDigest),
  });
  if (!authorityRef) throw new Error('Wallet operation Passkey authority ref fixture is invalid');
  const requestOrigin = parseSessionOrigin('https://app.example.test');
  return {
    authorization,
    evidenceId: parsed('evidence-wallet-passkey', parseAuthorizationEvidenceId),
    evidenceSetId: parsed('evidence-set-wallet-passkey', parseAuthorizationEvidenceSetId),
    factor: buildVerifiedWalletOperationPasskeyFactorResult({
      tenantId: authorization.session.tenantId,
      principalId: authorization.session.principalId,
      walletId,
      authorityRef,
      requestOrigin,
      audience: requestOrigin,
      factorId: parsed('factor-wallet-passkey', parseAuthFactorId),
      operation: authorization.authorizedOperation.operation,
      credentialIdB64u: parsedDomain('credential-wallet-passkey', parseWebAuthnCredentialIdB64u),
      assertionDigest: fixtureDigest(18),
      verifiedAtMs: authorization.session.createdAtMs + 1_000,
      expiresAtMs: authorization.session.createdAtMs + 60_000,
    }),
  };
}

export async function buildPasskeyWalletSessionIssuanceFixture(input: {
  readonly tenantId: string;
  readonly principalId: string;
  readonly walletId: string;
  readonly credentialIdB64u: string;
  readonly rpId: string;
  readonly origin: string;
  readonly expiresAtMs: number;
}): Promise<PasskeyWalletSessionIssuanceFixture> {
  const authority = buildPasskeyWalletAuthAuthority({
    walletId: input.walletId,
    credentialIdB64u: input.credentialIdB64u,
    rpId: input.rpId,
  });
  return {
    authority,
    authorityRef: await walletAuthAuthorityRef({ authority }),
    session: {
      tenantId: parsed(input.tenantId, parseTenantId),
      principalId: parsed(input.principalId, parsePrincipalId),
      createdAtMs: input.expiresAtMs - 60_000,
      expiresAtMs: input.expiresAtMs,
      origin: parseSessionOrigin(input.origin),
    },
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
