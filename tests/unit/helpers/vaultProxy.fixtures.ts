import {
  buildGrantEvidenceRequirement,
  parseAuthorizationAuditEventId,
  parseAuthFactorId,
  parseCapabilityId,
  parseCapabilityOperationId,
  parseAuthorizedOperationId,
  parseDeviceId,
  parseGrantEvidenceId,
  parseGrantEvidenceSetId,
  parsePrincipalId,
  parseSeamsSessionId,
  parseTenantId,
  parseVaultId,
  parseVaultItemId,
  type AuthorizationParseResult,
} from '../../../packages/shared-ts/src/authorization/capabilityKinds';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';
import { parseDigestB64u } from '../../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  parseAppSessionVersion,
  parseWalletAuthorityBindingDigest,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
} from '../../../packages/shared-ts/src/utils/domainIds';
import { parseWalletAuthAuthorityRef } from '../../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  buildActiveAuthorizationSession,
  buildAuthorizedOperation,
  parseSessionOrigin,
  type ActiveAuthorizationSession,
  type AuthorizedOperation,
} from '../../../packages/sdk-server-ts/src/authorization/domain';
import {
  buildVerifiedPasskeyFactorResult,
  type VerifiedGrantEvidenceSet,
} from '../../../packages/sdk-server-ts/src/authorization/factorEvidence';
import { buildCapabilityOperationEnvelope } from '../../../packages/shared-ts/src/authorization/operationFingerprint';
import {
  buildVaultProxyUseOperation,
  parseVaultProxyDestination,
} from '../../../packages/sdk-server-ts/src/authorization/vaultProxyUse';

export const VAULT_PROXY_FIXTURE_TIME_MS = 1_900_000_000_000;

export async function buildVaultProxyFixture() {
  const tenantId = parsed('tenant-vault-proxy', parseTenantId);
  const principalId = parsed('principal-vault-user', parsePrincipalId);
  const capabilityId = parsed('capability-vault', parseCapabilityId);
  const operationId = parsed('operation-vault-proxy-1', parseCapabilityOperationId);
  const vaultId = parsed('vault-1', parseVaultId);
  const itemId = parsed('vault-item-1', parseVaultItemId);
  const destination = parseVaultProxyDestination('https://api.example.test/charge');
  return {
    tenantId,
    principalId,
    capabilityId,
    operationId,
    vaultId,
    itemId,
    destination,
    sourceSession: buildActiveAuthorizationSession({
      tenantId,
      principalId,
      sessionId: parsed('session-vault-app', parseSeamsSessionId),
      authSource: {
        kind: 'passkey',
        credentialIdB64u: parsedDomain('credential-vault-app', parseWebAuthnCredentialIdB64u),
      },
      deviceId: parsed('device-vault-browser', parseDeviceId),
      audience: {
        kind: 'first_party_web',
        origin: parseSessionOrigin('https://app.example.test'),
      },
      appSessionVersion: parsedDomain('app-session-vault-1', parseAppSessionVersion),
      assurance: 'session',
      createdAtMs: VAULT_PROXY_FIXTURE_TIME_MS - 1_000,
      lifecycle: {
        kind: 'active',
        expiresAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 100_000,
      },
    }),
    operation: await buildVaultProxyUseOperation({
      tenantId,
      principalId,
      capabilityId,
      operationId,
      vaultId,
      itemId,
      destination,
    }),
    evidenceId: parsed('evidence-vault-passkey', parseGrantEvidenceId),
    evidenceSetId: parsed('evidence-set-vault-passkey', parseGrantEvidenceSetId),
    authorizedOperationId: parsed('authorized-operation-vault-proxy-1', parseAuthorizedOperationId),
    auditEventId: parsed('audit-vault-proxy-1', parseAuthorizationAuditEventId),
    evidenceRequirement: buildGrantEvidenceRequirement({
      mode: 'all',
      evidenceKinds: ['passkey_assertion'],
    }),
  };
}

export function buildVaultProxyPasskeyFactor(input: {
  readonly fixture: Awaited<ReturnType<typeof buildVaultProxyFixture>>;
  readonly session: ActiveAuthorizationSession;
}) {
  const authorityRef = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: parsedDomain('wallet-vault-passkey', parseWalletId),
    authorityDigest: parsedDomain(fixtureDigest(7), parseWalletAuthorityBindingDigest),
  });
  if (!authorityRef) throw new Error('vault Passkey authority ref fixture is invalid');
  return buildVerifiedPasskeyFactorResult({
    tenantId: input.session.tenantId,
    principalId: input.session.principalId,
    sessionId: input.session.sessionId,
    deviceId: input.session.deviceId,
    factorId: parsed('factor-vault-passkey', parseAuthFactorId),
    authorityRef,
    operation: input.fixture.operation,
    credentialIdB64u: parsedDomain('credential-vault-assertion', parseWebAuthnCredentialIdB64u),
    assertionDigest: fixtureDigest(8),
    verifiedAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 20,
    expiresAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 40_000,
  });
}

export async function buildVaultProxyAuthorizedOperation(input: {
  readonly fixture: Awaited<ReturnType<typeof buildVaultProxyFixture>>;
  readonly evidenceSet: VerifiedGrantEvidenceSet;
}): Promise<AuthorizedOperation> {
  return buildAuthorizedOperation({
    tenantId: input.fixture.tenantId,
    authorizedOperationId: input.fixture.authorizedOperationId,
    auditEventId: input.fixture.auditEventId,
    operation: buildCapabilityOperationEnvelope({
      tenantId: input.fixture.tenantId,
      principalId: input.fixture.principalId,
      capabilityId: input.fixture.capabilityId,
      operationId: input.fixture.operation.operationId,
      operation: input.fixture.operation.operation,
      digests: input.fixture.operation.digests,
    }),
    authorization: {
      kind: 'verified_step_up',
      evidenceSetDigest: input.evidenceSet.evidenceSetDigest,
    },
    quota: { kind: 'quota_neutral' },
    claimedAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 20,
  });
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
  if (!result.ok) throw new Error('vault proxy fixture identifier is invalid');
  return result.value;
}
