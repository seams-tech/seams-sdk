import { expect, test } from '@playwright/test';
import { capabilityPolicyPort } from '../../packages/wallet-server/src/authorization/capabilityPolicy';
import { AuthorizationService } from '../../packages/wallet-server/src/authorization/service';
import {
  LocalWorkerVaultProxyGateway,
  VaultProxyUseService,
  createVaultProxyUseRouteExtension,
  type VaultProxySecretRef,
  type VaultProxySecretStore,
} from '../../packages/wallet-server/src/authorization/vaultProxyUse';
import { CloudflareD1AuthorizationStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore';
import { CloudflareD1VaultProxyStore } from '../../packages/wallet-server/src/router/cloudflare/d1/authorization/d1VaultProxyStore';
import { coerceRouterLogger } from '../../packages/wallet-server/src/router/framework/logger';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  VAULT_PROXY_FIXTURE_TIME_MS,
  buildVaultProxyFixture,
  buildVaultProxyPasskeyFactor,
} from './helpers/vaultProxy.fixtures';

const signerMigrations = listD1MigrationFiles('d1-signer');

test('routes one persisted vault secret through a direct Passkey step-up operation and records audit', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applyD1MigrationFiles(temporary.database, signerMigrations);
    const authorizationStore = new CloudflareD1AuthorizationStore({
      database: temporary.database,
      namespace: 'vault-proxy-test',
      walletSignerScope: {
        namespace: 'vault-proxy-test',
        orgId: 'vault-proxy-org',
        projectId: 'vault-proxy-project',
        envId: 'vault-proxy-env',
      },
    });
    const authorization = new AuthorizationService({
      policy: capabilityPolicyPort,
      sessions: authorizationStore,
      evidence: authorizationStore,
      grants: authorizationStore,
      authorizedOperations: authorizationStore,
      audit: authorizationStore,
    });
    const fixture = await buildVaultProxyFixture();
    const evidenceSet = await authorization.recordVerifiedWalletOperationFactorEvidenceSet({
      operation: fixture.operation,
      evidenceId: fixture.evidenceId,
      evidenceSetId: fixture.evidenceSetId,
      factor: buildVaultProxyPasskeyFactor({ fixture }),
    });
    expect(
      authorization.evaluateEvidenceRequirement(fixture.evidenceRequirement, evidenceSet),
    ).toMatchObject({ kind: 'satisfied', mode: 'all' });
    const persistedSecretStore = new CloudflareD1VaultProxyStore(
      temporary.database,
      'vault-proxy-test',
      new Uint8Array(32).fill(9),
    );
    await persistedSecretStore.putSecret({
      tenantId: fixture.tenantId,
      capabilityId: fixture.capabilityId,
      vaultId: fixture.vaultId,
      itemId: fixture.itemId,
      destination: fixture.destination,
      secret: 'merchant-secret-token',
    });
    const secretStore = new CountingVaultProxySecretStore(persistedSecretStore);
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
    const request = buildVaultProxyRequest(fixture, evidenceSet.evidenceSetDigest);
    const response = await extension.handleFetchRoute({
      request,
      route,
      pathname: route.path,
      method: route.method,
      logger: coerceRouterLogger(undefined),
      runtime: { kind: 'inline' },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/json');
    const firstBody = await response.text();
    expect(JSON.parse(firstBody)).toEqual({
      kind: 'succeeded',
      status: 201,
      body: '{"accepted":true}',
    });
    expect(upstream.authorization).toBe('Bearer merchant-secret-token');
    expect(upstream.payload).toBe('{"amount":42}');
    const replay = await extension.handleFetchRoute({
      request: buildVaultProxyRequest(fixture, evidenceSet.evidenceSetDigest),
      route,
      pathname: route.path,
      method: route.method,
      logger: coerceRouterLogger(undefined),
      runtime: { kind: 'inline' },
    });
    expect(replay.status).toBe(response.status);
    expect(replay.headers.get('content-type')).toBe(response.headers.get('content-type'));
    await expect(replay.text()).resolves.toBe(firstBody);
    expect(secretStore.openCalls).toBe(1);
    expect(upstream.calls).toBe(1);
    await expect(
      temporary.database
        .prepare(
          `SELECT COUNT(*) AS count
             FROM authorized_operations
            WHERE namespace = ? AND tenant_id = ? AND authorized_operation_id = ?`,
        )
        .bind('vault-proxy-test', fixture.tenantId, fixture.authorizedOperationId)
        .first<{ readonly count: number }>(),
    ).resolves.toEqual({ count: 1 });
    await expect(
      temporary.database
        .prepare(
          `SELECT capability_id, capability_kind, operation_kind, result_kind,
                  result_status, result_content_type, result_body_text
             FROM authorized_operations
            WHERE namespace = ? AND tenant_id = ? AND authorized_operation_id = ?`,
        )
        .bind('vault-proxy-test', fixture.tenantId, fixture.authorizedOperationId)
        .first<{
          readonly capability_id: string;
          readonly capability_kind: string;
          readonly operation_kind: string;
          readonly result_kind: string;
          readonly result_status: number;
          readonly result_content_type: string;
          readonly result_body_text: string;
        }>(),
    ).resolves.toEqual({
      capability_id: fixture.capabilityId,
      capability_kind: 'vault_access',
      operation_kind: 'vault.proxy_use',
      result_kind: 'succeeded',
      result_status: 200,
      result_content_type: 'application/json',
      result_body_text: firstBody,
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

class RecordingVaultUpstream {
  authorization: string | null = null;
  payload = '';
  calls = 0;

  async fetch(request: Request): Promise<Response> {
    this.calls += 1;
    this.authorization = request.headers.get('authorization');
    this.payload = await request.text();
    return Response.json({ accepted: true }, { status: 201 });
  }
}

class CountingVaultProxySecretStore implements VaultProxySecretStore {
  openCalls = 0;

  constructor(private readonly delegate: VaultProxySecretStore) {}

  async openSecret(input: VaultProxySecretRef): Promise<Uint8Array | null> {
    this.openCalls += 1;
    return await this.delegate.openSecret(input);
  }
}

function buildVaultProxyRequest(
  fixture: Awaited<ReturnType<typeof buildVaultProxyFixture>>,
  evidenceSetDigest: string,
): Request {
  return new Request('https://router.example.test/vault/proxy-use', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      tenantId: fixture.tenantId,
      principalId: fixture.principalId,
      capabilityId: fixture.capabilityId,
      operationId: fixture.operationId,
      authorizedOperationId: fixture.authorizedOperationId,
      auditEventId: fixture.auditEventId,
      evidenceSetDigest,
      vaultId: fixture.vaultId,
      itemId: fixture.itemId,
      destination: fixture.destination,
      payload: '{"amount":42}',
    }),
  });
}

function fixedVaultProxyTime(): number {
  return VAULT_PROXY_FIXTURE_TIME_MS + 30;
}
