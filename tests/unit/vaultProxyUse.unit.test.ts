import { expect, test } from '@playwright/test';
import { capabilityPolicyPort } from '../../packages/sdk-server-ts/src/authorization/capabilityPolicy';
import { AuthorizationService } from '../../packages/sdk-server-ts/src/authorization/service';
import {
  LocalWorkerVaultProxyGateway,
  VaultProxyUseService,
  createVaultProxyUseRouteExtension,
} from '../../packages/sdk-server-ts/src/authorization/vaultProxyUse';
import { parseSessionOrigin } from '../../packages/sdk-server-ts/src/authorization/domain';
import { CloudflareD1AuthorizationStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1AuthorizationStore';
import { CloudflareD1VaultProxyStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1VaultProxyStore';
import { coerceRouterLogger } from '../../packages/sdk-server-ts/src/router/logger';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  VAULT_PROXY_FIXTURE_TIME_MS,
  buildVaultProxyFixture,
  buildVaultProxyOneUseGrant,
  buildVaultProxyPasskeyFactor,
} from './helpers/vaultProxy.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');

test('routes one persisted vault secret through a one-use Passkey grant and records audit', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const authorizationStore = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace: 'vault-proxy-test',
    });
    const authorization = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: authorizationStore,
      evidence: authorizationStore,
      grants: authorizationStore,
      claims: authorizationStore,
      audit: authorizationStore,
    });
    const fixture = await buildVaultProxyFixture();
    await authorization.recordActiveSession(fixture.sourceSession);
    const exchange = await authorization.mintHostedWalletSeamsSessionExchange({
      tenantId: fixture.tenantId,
      principalId: fixture.principalId,
      sourceSessionId: fixture.sourceSession.sessionId,
      appOrigin: fixture.sourceSession.audience.origin,
      walletOrigin: parseSessionOrigin('https://wallet.example.test'),
      issuedAtMs: VAULT_PROXY_FIXTURE_TIME_MS,
      expiresAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 50_000,
    });
    const redeemed = await authorization.redeemHostedWalletSeamsSessionExchange({
      exchangeCode: exchange.exchangeCode,
      nonce: exchange.nonce,
      walletOrigin: exchange.walletOrigin,
      redeemedAtMs: VAULT_PROXY_FIXTURE_TIME_MS + 10,
    });
    if (redeemed.kind !== 'redeemed') throw new Error(`session exchange failed: ${redeemed.kind}`);

    const evidenceSet = await authorization.recordVerifiedFactorEvidenceSet({
      session: redeemed.session,
      operation: fixture.operation,
      evidenceId: fixture.evidenceId,
      evidenceSetId: fixture.evidenceSetId,
      factor: buildVaultProxyPasskeyFactor({ fixture, session: redeemed.session }),
    });
    expect(
      authorization.evaluateEvidenceRequirement(fixture.evidenceRequirement, evidenceSet),
    ).toMatchObject({ kind: 'satisfied', mode: 'all' });
    await authorization.issueGrant({
      operation: fixture.operation,
      evidenceSet,
      grant: buildVaultProxyOneUseGrant({ fixture, evidenceSet }),
    });

    const secretStore = new CloudflareD1VaultProxyStore(
      temporary.database,
      'vault-proxy-test',
      new Uint8Array(32).fill(9),
    );
    await secretStore.putSecret({
      tenantId: fixture.tenantId,
      capabilityId: fixture.capabilityId,
      vaultId: fixture.vaultId,
      itemId: fixture.itemId,
      destination: fixture.destination,
      secret: 'merchant-secret-token',
    });
    const upstream = new RecordingVaultUpstream();
    const extension = createVaultProxyUseRouteExtension({
      service: new VaultProxyUseService(
        authorization,
        secretStore,
        new LocalWorkerVaultProxyGateway(upstream.fetch.bind(upstream)),
      ),
      now: fixedVaultProxyTime,
    });
    const route = extension.routes[0];
    if (!route) throw new Error('vault proxy route is missing');
    const request = new Request('https://router.example.test/vault/proxy-use', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        tenantId: fixture.tenantId,
        principalId: fixture.principalId,
        capabilityId: fixture.capabilityId,
        operationId: fixture.operationId,
        grantId: fixture.grantId,
        useId: fixture.useId,
        auditEventId: fixture.auditEventId,
        evidenceSetDigest: evidenceSet.evidenceSetDigest,
        vaultId: fixture.vaultId,
        itemId: fixture.itemId,
        destination: fixture.destination,
        payload: '{"amount":42}',
      }),
    });
    const response = await extension.handleCloudflareRoute({
      request,
      route,
      pathname: route.path,
      method: route.method,
      logger: coerceRouterLogger(undefined),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      kind: 'succeeded',
      status: 201,
      body: '{"accepted":true}',
    });
    expect(upstream.authorization).toBe('Bearer merchant-secret-token');
    expect(upstream.payload).toBe('{"amount":42}');
    await expect(
      temporary.database
        .prepare(
          `SELECT remaining_uses
             FROM capability_grants
            WHERE namespace = ? AND tenant_id = ? AND grant_id = ?`,
        )
        .bind('vault-proxy-test', fixture.tenantId, fixture.grantId)
        .first<{ readonly remaining_uses: number }>(),
    ).resolves.toEqual({ remaining_uses: 0 });
    await expect(
      authorization.readAuditEvent({
        tenantId: fixture.tenantId,
        eventId: fixture.auditEventId,
      }),
    ).resolves.toMatchObject({
      capabilityId: fixture.capabilityId,
      operation: {
        capabilityKind: 'vault_access',
        operationKind: 'vault.proxy_use',
      },
      result: 'succeeded',
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

class RecordingVaultUpstream {
  authorization: string | null = null;
  payload = '';

  async fetch(request: Request): Promise<Response> {
    this.authorization = request.headers.get('authorization');
    this.payload = await request.text();
    return Response.json({ accepted: true }, { status: 201 });
  }
}

function fixedVaultProxyTime(): number {
  return VAULT_PROXY_FIXTURE_TIME_MS + 30;
}
