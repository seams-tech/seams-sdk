import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleApiKeyService,
  createPostgresConsoleBillingService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  type ConsoleApiKeyService,
  type ConsoleBillingService,
  type ConsoleOrgProjectEnvService,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

async function expectConsoleError(fn: () => Promise<unknown>, code: string): Promise<void> {
  let caught: any;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(String(caught?.code || '')).toBe(code);
}

test.describe('console postgres tenant-isolation harness', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console:tenant-isolation:postgres');

  let orgProjectEnv: ConsoleOrgProjectEnvService | null = null;
  let wallets: ConsoleWalletService | null = null;
  let apiKeys: ConsoleApiKeyService | null = null;
  let webhooks: ConsoleWebhookService | null = null;
  let billing: ConsoleBillingService | null = null;

  const ownerOrgId = 'org-tenant-owner';
  const ownerProjectId = 'owner-project-main';
  const ownerEnvironmentId = `${ownerProjectId}:prod`;

  const attackerOrgId = 'org-tenant-attacker';
  const attackerProjectId = 'attacker-project-main';
  const attackerEnvironmentId = `${attackerProjectId}:prod`;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    orgProjectEnv = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    wallets = await createPostgresConsoleWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    apiKeys = await createPostgresConsoleApiKeyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    webhooks = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    billing = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [
      namespace,
    ]);
    await pool.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [
      namespace,
    ]);
    await pool.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_api_keys WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_wallet_index WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
  });

  test('org/project/environment service enforces org-scoped reads', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-admin',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-admin',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    const ownerOrg = await orgProjectEnv!.getOrganization(ownerCtx);
    expect(ownerOrg.id).toBe(ownerOrgId);

    await orgProjectEnv!.getOrganization(attackerCtx);

    const ownerProjects = await orgProjectEnv!.listProjects(ownerCtx);
    expect(ownerProjects.length).toBeGreaterThan(0);
    expect(ownerProjects.every((entry) => entry.orgId === ownerOrgId)).toBe(true);
    expect(ownerProjects.some((entry) => entry.id === ownerProjectId)).toBe(true);
    expect(ownerProjects.some((entry) => entry.id === attackerProjectId)).toBe(false);
    const ownerActiveProjects = await orgProjectEnv!.listProjects(ownerCtx, {
      status: 'ACTIVE',
    });
    expect(ownerActiveProjects.length).toBeGreaterThan(0);
    expect(ownerActiveProjects.every((entry) => entry.status === 'ACTIVE')).toBe(true);
    expect(ownerActiveProjects.some((entry) => entry.id === ownerProjectId)).toBe(true);
    expect(ownerActiveProjects.some((entry) => entry.id === attackerProjectId)).toBe(false);

    const ownerEnvironments = await orgProjectEnv!.listEnvironments(ownerCtx);
    expect(ownerEnvironments.length).toBeGreaterThan(0);
    expect(ownerEnvironments.every((entry) => entry.orgId === ownerOrgId)).toBe(true);
    expect(ownerEnvironments.some((entry) => entry.id === ownerEnvironmentId)).toBe(true);
    expect(ownerEnvironments.some((entry) => entry.id === attackerEnvironmentId)).toBe(false);

    const ownerScopedToAttackerProject = await orgProjectEnv!.listEnvironments(ownerCtx, {
      projectId: attackerProjectId,
    });
    expect(ownerScopedToAttackerProject.length).toBe(0);
  });

  test('org/project/environment service denies cross-org mutations', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-mutation-admin',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-mutation-admin',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    const ownerProject = await orgProjectEnv!.createProject(ownerCtx, {
      id: 'owner-managed-project',
      name: 'Owner Managed Project',
    });
    expect(ownerProject.id).toBe('owner-managed-project');

    const ownerEnvironment = await orgProjectEnv!.createEnvironment(ownerCtx, {
      id: 'owner-managed-env',
      projectId: ownerProject.id,
      key: 'staging',
      name: 'Owner Managed Staging',
    });
    expect(ownerEnvironment.id).toBe('owner-managed-env');

    const attackerPatchProject = await orgProjectEnv!.updateProject(attackerCtx, ownerProject.id, {
      name: 'attacker patch',
    });
    expect(attackerPatchProject).toBeNull();

    const attackerArchiveProject = await orgProjectEnv!.archiveProject(attackerCtx, ownerProject.id);
    expect(attackerArchiveProject).toBeNull();

    const attackerPatchEnvironment = await orgProjectEnv!.updateEnvironment(
      attackerCtx,
      ownerEnvironment.id,
      { name: 'attacker patch env' },
    );
    expect(attackerPatchEnvironment).toBeNull();

    const attackerArchiveEnvironment = await orgProjectEnv!.archiveEnvironment(
      attackerCtx,
      ownerEnvironment.id,
    );
    expect(attackerArchiveEnvironment).toBeNull();

    const ownerProjectAfterAttacker = await orgProjectEnv!.updateProject(ownerCtx, ownerProject.id, {
      name: 'owner patch',
    });
    expect(ownerProjectAfterAttacker?.name).toBe('owner patch');
    expect(ownerProjectAfterAttacker?.status).toBe('ACTIVE');

    const ownerArchivedProject = await orgProjectEnv!.archiveProject(ownerCtx, ownerProject.id);
    expect(ownerArchivedProject?.status).toBe('ARCHIVED');
    const ownerArchivedProjects = await orgProjectEnv!.listProjects(ownerCtx, {
      status: 'ARCHIVED',
    });
    expect(ownerArchivedProjects.some((entry) => entry.id === ownerProject.id)).toBe(true);
    expect(ownerArchivedProjects.every((entry) => entry.status === 'ARCHIVED')).toBe(true);

    const ownerActiveProjects = await orgProjectEnv!.listProjects(ownerCtx, {
      status: 'ACTIVE',
    });
    expect(ownerActiveProjects.some((entry) => entry.id === ownerProject.id)).toBe(false);
    expect(ownerActiveProjects.every((entry) => entry.status === 'ACTIVE')).toBe(true);

    const ownerEnvironmentsAfterArchive = await orgProjectEnv!.listEnvironments(ownerCtx, {
      projectId: ownerProject.id,
    });
    expect(ownerEnvironmentsAfterArchive.some((entry) => entry.id === ownerEnvironment.id)).toBe(true);
    expect(
      ownerEnvironmentsAfterArchive.some(
        (entry) => entry.id === ownerEnvironment.id && entry.status === 'ARCHIVED',
      ),
    ).toBe(true);

    const ownerActiveEnvironmentsAfterArchive = await orgProjectEnv!.listEnvironments(ownerCtx, {
      projectId: ownerProject.id,
      status: 'ACTIVE',
    });
    expect(ownerActiveEnvironmentsAfterArchive.length).toBe(0);

    const ownerArchivedEnvironmentsAfterArchive = await orgProjectEnv!.listEnvironments(ownerCtx, {
      projectId: ownerProject.id,
      status: 'ARCHIVED',
    });
    expect(
      ownerArchivedEnvironmentsAfterArchive.some(
        (entry) => entry.id === ownerEnvironment.id && entry.status === 'ARCHIVED',
      ),
    ).toBe(true);
  });

  test('environment rows cannot attach to a project owned by another org', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const createdAtMs = Date.now();
    const sharedProjectId = 'project-owner-fk-check';
    const violatingEnvironmentId = `env_violation_${Math.random().toString(16).slice(2, 10)}`;

    await pool.query(
      `INSERT INTO console_organizations
        (namespace, id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, 'ACTIVE', $5, $5)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [namespace, ownerOrgId, 'Owner Org', 'owner-org', createdAtMs],
    );
    await pool.query(
      `INSERT INTO console_organizations
        (namespace, id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, 'ACTIVE', $5, $5)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [namespace, attackerOrgId, 'Attacker Org', 'attacker-org', createdAtMs],
    );
    await pool.query(
      `INSERT INTO console_projects
        (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [namespace, sharedProjectId, ownerOrgId, 'Owner Project FK Check', 'owner-project-fk-check', createdAtMs],
    );

    let caught: any;
    try {
      await pool.query(
        `INSERT INTO console_environments
          (namespace, id, org_id, project_id, env_key, name, status, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, 'prod', $5, 'ACTIVE', $6, $6)`,
        [
          namespace,
          violatingEnvironmentId,
          attackerOrgId,
          sharedProjectId,
          'Cross Org Environment',
          createdAtMs,
        ],
      );
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('23503');
  });

  test('wallet rows cannot attach to environment/project owned by another org', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const createdAtMs = Date.now();
    const ownerFkProjectId = 'wallet-fk-owner-project';
    const ownerFkEnvironmentId = 'wallet-fk-owner-env';
    const violatingWalletId = `wallet_fk_violation_${Math.random().toString(16).slice(2, 10)}`;

    await pool.query(
      `INSERT INTO console_organizations
        (namespace, id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, 'ACTIVE', $5, $5)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [namespace, ownerOrgId, 'Owner Org', 'owner-org', createdAtMs],
    );
    await pool.query(
      `INSERT INTO console_organizations
        (namespace, id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, 'ACTIVE', $5, $5)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [namespace, attackerOrgId, 'Attacker Org', 'attacker-org', createdAtMs],
    );
    await pool.query(
      `INSERT INTO console_projects
        (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, 'ACTIVE', $6, $6)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [
        namespace,
        ownerFkProjectId,
        ownerOrgId,
        'Wallet FK Owner Project',
        'wallet-fk-owner-project',
        createdAtMs,
      ],
    );
    await pool.query(
      `INSERT INTO console_environments
        (namespace, id, org_id, project_id, env_key, name, status, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, 'prod', $5, 'ACTIVE', $6, $6)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [
        namespace,
        ownerFkEnvironmentId,
        ownerOrgId,
        ownerFkProjectId,
        'Wallet FK Owner Environment',
        createdAtMs,
      ],
    );

    let caught: any;
    try {
      await pool.query(
        `INSERT INTO console_wallet_index
          (namespace, id, org_id, project_id, environment_id, user_id, external_ref_id, address, chain, wallet_type, status, policy_id, balance_minor, last_activity_at_ms, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, 'Ethereum', 'EOA', 'ACTIVE', 'policy_default', 0, NULL, $9, $9)`,
        [
          namespace,
          violatingWalletId,
          attackerOrgId,
          ownerFkProjectId,
          ownerFkEnvironmentId,
          'wallet-fk-attacker-user',
          'wallet-fk-attacker-ext',
          '0x9e8f03f8ca5fd84f4c10ed35a7ed2f4b7c7a9c51',
          createdAtMs,
        ],
      );
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('23503');
  });

  test('wallet service denies cross-org list/search/detail access', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-wallet-admin',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-wallet-admin',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    const ownerWallets = await wallets!.listWallets(ownerCtx, { limit: 10 });
    const attackerWallets = await wallets!.listWallets(attackerCtx, { limit: 10 });
    expect(ownerWallets.items.length).toBeGreaterThan(0);
    expect(attackerWallets.items.length).toBeGreaterThan(0);
    expect(ownerWallets.items.every((entry) => entry.orgId === ownerOrgId)).toBe(true);
    const attackerWalletId = attackerWallets.items[0].id;

    const ownerSearch = await wallets!.searchWallets(ownerCtx, {
      q: attackerWalletId,
      limit: 10,
    });
    expect(ownerSearch.items.length).toBe(0);

    const ownerGetAttackerWallet = await wallets!.getWallet(ownerCtx, attackerWalletId);
    expect(ownerGetAttackerWallet).toBeNull();
  });

  test('api key service denies cross-org rotate/revoke access', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-api-admin',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-api-admin',
      roles: ['admin'],
    };

    const ownerCreated = await apiKeys!.createApiKey(ownerCtx, {
      name: 'owner-key',
      environmentId: ownerEnvironmentId,
      scopes: ['wallets:read'],
      ipAllowlist: [],
    });
    const attackerCreated = await apiKeys!.createApiKey(attackerCtx, {
      name: 'attacker-key',
      environmentId: attackerEnvironmentId,
      scopes: ['wallets:read'],
      ipAllowlist: [],
    });

    const ownerList = await apiKeys!.listApiKeys(ownerCtx);
    expect(ownerList.some((entry) => entry.id === ownerCreated.apiKey.id)).toBe(true);
    expect(ownerList.some((entry) => entry.id === attackerCreated.apiKey.id)).toBe(false);

    const ownerRotateAttacker = await apiKeys!.rotateApiKey(ownerCtx, attackerCreated.apiKey.id);
    expect(ownerRotateAttacker).toBeNull();

    const ownerRevokeAttacker = await apiKeys!.revokeApiKey(ownerCtx, attackerCreated.apiKey.id);
    expect(ownerRevokeAttacker.revoked).toBe(false);
    expect(ownerRevokeAttacker.apiKey).toBeNull();
  });

  test('webhook service denies cross-org endpoint access', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-webhook-admin',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-webhook-admin',
      roles: ['admin'],
    };

    const ownerEndpoint = await webhooks!.createEndpoint(ownerCtx, {
      url: 'https://example.com/owner-webhook',
      subscriptions: ['billing'],
    });
    const attackerEndpoint = await webhooks!.createEndpoint(attackerCtx, {
      url: 'https://example.com/attacker-webhook',
      subscriptions: ['billing'],
    });

    const ownerEndpoints = await webhooks!.listEndpoints(ownerCtx);
    expect(ownerEndpoints.some((entry) => entry.id === ownerEndpoint.id)).toBe(true);
    expect(ownerEndpoints.some((entry) => entry.id === attackerEndpoint.id)).toBe(false);

    const ownerUpdateAttacker = await webhooks!.updateEndpoint(ownerCtx, attackerEndpoint.id, {
      status: 'DISABLED',
    });
    expect(ownerUpdateAttacker).toBeNull();

    const ownerDeleteAttacker = await webhooks!.deleteEndpoint(ownerCtx, attackerEndpoint.id);
    expect(ownerDeleteAttacker.removed).toBe(false);

    await expectConsoleError(async () => {
      await webhooks!.listDeliveries(ownerCtx, attackerEndpoint.id, {});
    }, 'webhook_not_found');
  });

  test('billing service denies cross-org invoice and stablecoin intent access', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-billing-admin',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-billing-admin',
      roles: ['admin'],
    };

    const ownerInvoices = await billing!.listInvoices(ownerCtx);
    const attackerInvoices = await billing!.listInvoices(attackerCtx);
    expect(ownerInvoices.length).toBeGreaterThan(0);
    expect(attackerInvoices.length).toBeGreaterThan(0);
    const attackerInvoiceId = attackerInvoices[0].id;

    const ownerGetAttackerInvoice = await billing!.getInvoice(ownerCtx, attackerInvoiceId);
    expect(ownerGetAttackerInvoice).toBeNull();

    const ownerAttackerInvoiceItems = await billing!.listInvoiceLineItems(ownerCtx, attackerInvoiceId);
    expect(ownerAttackerInvoiceItems.length).toBe(0);

    await expectConsoleError(async () => {
      await billing!.createStablecoinQuote(ownerCtx, {
        invoiceId: attackerInvoiceId,
        asset: 'USDC',
        chain: 'Base',
      });
    }, 'invoice_not_found');

    const attackerQuote = await billing!.createStablecoinQuote(attackerCtx, {
      invoiceId: attackerInvoiceId,
      asset: 'USDT',
      chain: 'Ethereum',
    });
    const attackerIntent = await billing!.createStablecoinPaymentIntent(attackerCtx, {
      invoiceId: attackerInvoiceId,
      quoteId: attackerQuote.id,
    });

    const ownerGetAttackerIntent = await billing!.getStablecoinPaymentIntent(
      ownerCtx,
      attackerIntent.id,
    );
    expect(ownerGetAttackerIntent).toBeNull();

    const ownerCancelAttackerIntent = await billing!.cancelStablecoinPaymentIntent(
      ownerCtx,
      attackerIntent.id,
    );
    expect(ownerCancelAttackerIntent).toBeNull();
  });
});
