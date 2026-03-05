import { test, expect } from '@playwright/test';
import {
  createPostgresConsoleAuditService,
  createPostgresConsoleApiKeyService,
  createPostgresConsoleBillingService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsolePolicyService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  type ConsoleAuditService,
  type ConsoleApiKeyService,
  type ConsoleBillingService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicyService,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
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
  let audit: ConsoleAuditService | null = null;
  let apiKeys: ConsoleApiKeyService | null = null;
  let policies: ConsolePolicyService | null = null;
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
    audit = await createPostgresConsoleAuditService({
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
    policies = await createPostgresConsolePolicyService({
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
    for (const scopedOrgId of [ownerOrgId, attackerOrgId]) {
      await withConsoleTenantContextTx(pool, { namespace, orgId: scopedOrgId }, async (q) => {
        await q.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_payment_state_transitions WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_stablecoin_payment_intents WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_stablecoin_quotes WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_stripe_payment_intents WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_audit_evidence WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_audit_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_policy_assignments WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_policy_versions WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_policies WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_api_keys WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_wallet_index WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
      });
    }
    await pool.query('DELETE FROM console_stripe_provider_refs WHERE namespace = $1', [namespace]);
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

  test('org/project/environment tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-rls-db',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-rls-db',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    await orgProjectEnv!.getOrganization(ownerCtx);
    await orgProjectEnv!.getOrganization(attackerCtx);

    const ownerProjects = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_projects
            WHERE namespace = $1
            ORDER BY id ASC`,
          [namespace],
        ),
    );
    expect(ownerProjects.rows.length).toBeGreaterThan(0);
    expect(
      ownerProjects.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerProjects = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_projects
            WHERE namespace = $1
            ORDER BY id ASC`,
          [namespace],
        ),
    );
    expect(attackerProjects.rows.length).toBeGreaterThan(0);
    expect(
      attackerProjects.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantContextRows = await pool.query(
      `SELECT org_id, id
         FROM console_projects
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantContextRows.rows.length).toBe(0);
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

    const ownerEnvironments = await orgProjectEnv!.listEnvironments(ownerCtx, {
      projectId: ownerProject.id,
    });
    const ownerManagedEnvironment =
      ownerEnvironments.find((entry) => entry.key === 'staging') || ownerEnvironments[0] || null;
    expect(ownerManagedEnvironment).toBeTruthy();
    const ownerManagedEnvironmentId = String(ownerManagedEnvironment?.id || '');
    expect(ownerManagedEnvironmentId).toBeTruthy();

    const attackerPatchProject = await orgProjectEnv!.updateProject(attackerCtx, ownerProject.id, {
      name: 'attacker patch',
    });
    expect(attackerPatchProject).toBeNull();

    const attackerArchiveProject = await orgProjectEnv!.archiveProject(attackerCtx, ownerProject.id);
    expect(attackerArchiveProject).toBeNull();

    const attackerPatchEnvironment = await orgProjectEnv!.updateEnvironment(
      attackerCtx,
      ownerManagedEnvironmentId,
      { name: 'attacker patch env' },
    );
    expect(attackerPatchEnvironment).toBeNull();

    const attackerArchiveEnvironment = await orgProjectEnv!.archiveEnvironment(
      attackerCtx,
      ownerManagedEnvironmentId,
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
    expect(ownerEnvironmentsAfterArchive.some((entry) => entry.id === ownerManagedEnvironmentId)).toBe(
      true,
    );
    expect(
      ownerEnvironmentsAfterArchive.some(
        (entry) => entry.id === ownerManagedEnvironmentId && entry.status === 'ARCHIVED',
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
        (entry) => entry.id === ownerManagedEnvironmentId && entry.status === 'ARCHIVED',
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

  test('wallet table enforces DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-wallet-rls',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-wallet-rls',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    await wallets!.listWallets(ownerCtx, { limit: 5 });
    await wallets!.listWallets(attackerCtx, { limit: 5 });

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_wallet_index
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_wallet_index
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(attackerRows.rows.length).toBeGreaterThan(0);
    expect(
      attackerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantContextRows = await pool.query(
      `SELECT org_id, id
         FROM console_wallet_index
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantContextRows.rows.length).toBe(0);
  });

  test('audit service enforces org-scoped event/evidence visibility', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-audit-admin',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-audit-admin',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    const ownerEvent = await audit!.appendEvent(ownerCtx, {
      id: 'aud_owner_visibility_event',
      category: 'POLICY',
      action: 'policy.publish',
      outcome: 'SUCCESS',
      summary: 'Owner policy publish event',
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
      metadata: { policyId: 'owner-policy' },
    });
    const attackerEvent = await audit!.appendEvent(attackerCtx, {
      id: 'aud_attacker_visibility_event',
      category: 'POLICY',
      action: 'policy.publish',
      outcome: 'SUCCESS',
      summary: 'Attacker policy publish event',
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
      metadata: { policyId: 'attacker-policy' },
    });

    await audit!.appendEvidence(ownerCtx, {
      id: 'evd_owner_visibility',
      domain: 'POLICY',
      title: 'Owner evidence',
      summary: 'Owner audit evidence',
      eventIds: [ownerEvent.id],
      references: [{ kind: 'LOG', referenceId: 'owner-log', label: 'Owner log' }],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    });
    await audit!.appendEvidence(attackerCtx, {
      id: 'evd_attacker_visibility',
      domain: 'POLICY',
      title: 'Attacker evidence',
      summary: 'Attacker audit evidence',
      eventIds: [attackerEvent.id],
      references: [{ kind: 'LOG', referenceId: 'attacker-log', label: 'Attacker log' }],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    });

    const ownerEvents = await audit!.listEvents(ownerCtx, { limit: 200 });
    expect(ownerEvents.some((entry) => entry.id === ownerEvent.id)).toBe(true);
    expect(ownerEvents.some((entry) => entry.id === attackerEvent.id)).toBe(false);

    const attackerEvents = await audit!.listEvents(attackerCtx, { limit: 200 });
    expect(attackerEvents.some((entry) => entry.id === attackerEvent.id)).toBe(true);
    expect(attackerEvents.some((entry) => entry.id === ownerEvent.id)).toBe(false);

    const ownerEvidenceRows = await audit!.listEvidence(ownerCtx, { limit: 200 });
    expect(ownerEvidenceRows.some((entry) => entry.id === 'evd_owner_visibility')).toBe(true);
    expect(ownerEvidenceRows.some((entry) => entry.id === 'evd_attacker_visibility')).toBe(false);

    const attackerEvidenceRows = await audit!.listEvidence(attackerCtx, { limit: 200 });
    expect(attackerEvidenceRows.some((entry) => entry.id === 'evd_attacker_visibility')).toBe(true);
    expect(attackerEvidenceRows.some((entry) => entry.id === 'evd_owner_visibility')).toBe(false);
  });

  test('audit tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-audit-rls',
      roles: ['admin'],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-audit-rls',
      roles: ['admin'],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    };

    await audit!.appendEvent(ownerCtx, {
      id: 'aud_owner_rls_event',
      category: 'SETTINGS',
      action: 'settings.security.update',
      outcome: 'SUCCESS',
      summary: 'Owner security settings update',
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    });
    await audit!.appendEvent(attackerCtx, {
      id: 'aud_attacker_rls_event',
      category: 'SETTINGS',
      action: 'settings.security.update',
      outcome: 'SUCCESS',
      summary: 'Attacker security settings update',
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    });
    await audit!.appendEvidence(ownerCtx, {
      id: 'evd_owner_rls_evidence',
      domain: 'SECURITY',
      title: 'Owner security evidence',
      summary: 'Owner RLS evidence row',
      eventIds: ['aud_owner_rls_event'],
      references: [{ kind: 'LOG', referenceId: 'owner-security-log', label: 'Owner security log' }],
      projectId: ownerProjectId,
      environmentId: ownerEnvironmentId,
    });
    await audit!.appendEvidence(attackerCtx, {
      id: 'evd_attacker_rls_evidence',
      domain: 'SECURITY',
      title: 'Attacker security evidence',
      summary: 'Attacker RLS evidence row',
      eventIds: ['aud_attacker_rls_event'],
      references: [
        { kind: 'LOG', referenceId: 'attacker-security-log', label: 'Attacker security log' },
      ],
      projectId: attackerProjectId,
      environmentId: attackerEnvironmentId,
    });

    const ownerEventRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_audit_events
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerEventRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerEventRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerEvidenceRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_audit_evidence
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerEvidenceRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerEvidenceRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const noTenantEventRows = await pool.query(
      `SELECT org_id, id
         FROM console_audit_events
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantEventRows.rows.length).toBe(0);

    const noTenantEvidenceRows = await pool.query(
      `SELECT org_id, id
         FROM console_audit_evidence
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantEvidenceRows.rows.length).toBe(0);
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

  test('policy tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-policy-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-policy-rls',
      roles: ['admin'],
    };

    const ownerPolicy = await policies!.createPolicy(ownerCtx, {
      id: 'policy-owner-rls',
      name: 'Owner Policy',
      rules: {
        blockedActions: [],
      },
    });
    const attackerPolicy = await policies!.createPolicy(attackerCtx, {
      id: 'policy-attacker-rls',
      name: 'Attacker Policy',
      rules: {
        blockedActions: ['export'],
      },
    });
    expect(ownerPolicy.id).toBe('policy-owner-rls');
    expect(attackerPolicy.id).toBe('policy-attacker-rls');

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_policies
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const noTenantRows = await pool.query(
      `SELECT org_id, id
         FROM console_policies
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantRows.rows.length).toBe(0);
  });

  test('api key table enforces DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-apikey-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-apikey-rls',
      roles: ['admin'],
    };

    await apiKeys!.createApiKey(ownerCtx, {
      name: 'owner-rls-key',
      environmentId: ownerEnvironmentId,
      scopes: ['wallets:read'],
      ipAllowlist: [],
    });
    await apiKeys!.createApiKey(attackerCtx, {
      name: 'attacker-rls-key',
      environmentId: attackerEnvironmentId,
      scopes: ['wallets:read'],
      ipAllowlist: [],
    });

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_api_keys
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_api_keys
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(attackerRows.rows.length).toBeGreaterThan(0);
    expect(
      attackerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantContextRows = await pool.query(
      `SELECT org_id, id
         FROM console_api_keys
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantContextRows.rows.length).toBe(0);
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

  test('webhook tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-webhook-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-webhook-rls',
      roles: ['admin'],
    };

    await webhooks!.createEndpoint(ownerCtx, {
      url: 'https://example.com/owner-rls-webhook',
      subscriptions: ['billing'],
    });
    await webhooks!.createEndpoint(attackerCtx, {
      url: 'https://example.com/attacker-rls-webhook',
      subscriptions: ['billing'],
    });

    const ownerEndpointRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_webhook_endpoints
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerEndpointRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerEndpointRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const noTenantRows = await pool.query(
      `SELECT org_id, id
         FROM console_webhook_endpoints
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantRows.rows.length).toBe(0);
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

  test('billing core tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-billing-core-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-billing-core-rls',
      roles: ['admin'],
    };
    const periodMonthUtc = '2026-12';
    const ownerUsageSourceEventId = `owner-usage-${Date.now()}`;
    const attackerUsageSourceEventId = `attacker-usage-${Date.now()}`;

    await billing!.recordUsageEvent(ownerCtx, {
      walletId: 'owner-billing-core-wallet',
      action: 'transfer',
      succeeded: true,
      sourceEventId: ownerUsageSourceEventId,
      occurredAt: `${periodMonthUtc}-15T12:00:00.000Z`,
    });
    await billing!.recordUsageEvent(attackerCtx, {
      walletId: 'attacker-billing-core-wallet',
      action: 'swap',
      succeeded: true,
      sourceEventId: attackerUsageSourceEventId,
      occurredAt: `${periodMonthUtc}-16T12:00:00.000Z`,
    });
    const ownerGeneration = await billing!.generateMonthlyInvoice(ownerCtx, {
      periodMonthUtc,
    });
    const attackerGeneration = await billing!.generateMonthlyInvoice(attackerCtx, {
      periodMonthUtc,
    });
    const ownerPaymentMethod = await billing!.addCardPaymentMethod(ownerCtx, {
      providerRef: `pm_owner_core_rls_${Date.now()}`,
      brand: 'visa',
      last4: '4242',
      expMonth: 12,
      expYear: 2030,
    });
    const attackerPaymentMethod = await billing!.addCardPaymentMethod(attackerCtx, {
      providerRef: `pm_attacker_core_rls_${Date.now()}`,
      brand: 'mastercard',
      last4: '4444',
      expMonth: 11,
      expYear: 2031,
    });

    const ownerAccountRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id
             FROM console_billing_accounts
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerAccountRows.rows.length).toBeGreaterThan(0);
    expect(
      ownerAccountRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerUsageRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, source_event_id
             FROM console_usage_meter_events
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerUsageRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).source_event_id || '') === ownerUsageSourceEventId,
      ),
    ).toBe(true);
    expect(
      ownerUsageRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).source_event_id || '') ===
          attackerUsageSourceEventId,
      ),
    ).toBe(false);
    expect(
      ownerUsageRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerRollupRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, month_utc
             FROM console_usage_rollups_monthly
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerRollupRows.rows.some(
        (row) => String((row as Record<string, unknown>).month_utc || '') === periodMonthUtc,
      ),
    ).toBe(true);
    expect(
      ownerRollupRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerInvoiceRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_invoices
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerInvoiceRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerGeneration.invoice.id,
      ),
    ).toBe(true);
    expect(
      ownerInvoiceRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerGeneration.invoice.id,
      ),
    ).toBe(false);
    expect(
      ownerInvoiceRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerLineItemRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, invoice_id
             FROM console_invoice_line_items
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerLineItemRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).invoice_id || '') === ownerGeneration.invoice.id,
      ),
    ).toBe(true);
    expect(
      ownerLineItemRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).invoice_id || '') ===
          attackerGeneration.invoice.id,
      ),
    ).toBe(false);
    expect(
      ownerLineItemRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const ownerPaymentRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_payment_methods
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerPaymentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerPaymentMethod.id,
      ),
    ).toBe(true);
    expect(
      ownerPaymentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerPaymentMethod.id,
      ),
    ).toBe(false);
    expect(
      ownerPaymentRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerAccountRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id
             FROM console_billing_accounts
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(attackerAccountRows.rows.length).toBeGreaterThan(0);
    expect(
      attackerAccountRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const attackerUsageRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, source_event_id
             FROM console_usage_meter_events
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerUsageRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).source_event_id || '') ===
          attackerUsageSourceEventId,
      ),
    ).toBe(true);
    expect(
      attackerUsageRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).source_event_id || '') === ownerUsageSourceEventId,
      ),
    ).toBe(false);
    expect(
      attackerUsageRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const attackerRollupRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, month_utc
             FROM console_usage_rollups_monthly
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerRollupRows.rows.some(
        (row) => String((row as Record<string, unknown>).month_utc || '') === periodMonthUtc,
      ),
    ).toBe(true);
    expect(
      attackerRollupRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const attackerInvoiceRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_invoices
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerInvoiceRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerGeneration.invoice.id,
      ),
    ).toBe(true);
    expect(
      attackerInvoiceRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerGeneration.invoice.id,
      ),
    ).toBe(false);
    expect(
      attackerInvoiceRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const attackerLineItemRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, invoice_id
             FROM console_invoice_line_items
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerLineItemRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).invoice_id || '') ===
          attackerGeneration.invoice.id,
      ),
    ).toBe(true);
    expect(
      attackerLineItemRows.rows.some(
        (row) =>
          String((row as Record<string, unknown>).invoice_id || '') === ownerGeneration.invoice.id,
      ),
    ).toBe(false);
    expect(
      attackerLineItemRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const attackerPaymentRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_payment_methods
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerPaymentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerPaymentMethod.id,
      ),
    ).toBe(true);
    expect(
      attackerPaymentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerPaymentMethod.id,
      ),
    ).toBe(false);
    expect(
      attackerPaymentRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantAccountRows = await pool.query(
      `SELECT org_id
         FROM console_billing_accounts
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantAccountRows.rows.length).toBe(0);

    const noTenantUsageRows = await pool.query(
      `SELECT org_id, source_event_id
         FROM console_usage_meter_events
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantUsageRows.rows.length).toBe(0);

    const noTenantRollupRows = await pool.query(
      `SELECT org_id, month_utc
         FROM console_usage_rollups_monthly
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantRollupRows.rows.length).toBe(0);

    const noTenantInvoiceRows = await pool.query(
      `SELECT org_id, id
         FROM console_invoices
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantInvoiceRows.rows.length).toBe(0);

    const noTenantLineItemRows = await pool.query(
      `SELECT org_id, invoice_id
         FROM console_invoice_line_items
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantLineItemRows.rows.length).toBe(0);

    const noTenantPaymentRows = await pool.query(
      `SELECT org_id, id
         FROM console_payment_methods
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantPaymentRows.rows.length).toBe(0);
  });

  test('stripe payment intents table enforces DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-billing-stripe-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-billing-stripe-rls',
      roles: ['admin'],
    };

    const ownerGeneration = await billing!.generateMonthlyInvoice(ownerCtx, {
      periodMonthUtc: '2026-01',
    });
    const attackerGeneration = await billing!.generateMonthlyInvoice(attackerCtx, {
      periodMonthUtc: '2026-01',
    });
    const ownerIntent = await billing!.createStripePaymentIntent(ownerCtx, {
      invoiceId: ownerGeneration.invoice.id,
    });
    const attackerIntent = await billing!.createStripePaymentIntent(attackerCtx, {
      invoiceId: attackerGeneration.invoice.id,
    });

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stripe_payment_intents
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(ownerRows.rows.some((row) => String((row as any).id || '') === ownerIntent.id)).toBe(true);
    expect(
      ownerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);
    expect(ownerRows.rows.some((row) => String((row as any).id || '') === attackerIntent.id)).toBe(
      false,
    );

    const attackerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stripe_payment_intents
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerRows.rows.some((row) => String((row as any).id || '') === attackerIntent.id),
    ).toBe(true);
    expect(
      attackerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);
    expect(
      attackerRows.rows.some((row) => String((row as any).id || '') === ownerIntent.id),
    ).toBe(false);

    const noTenantRows = await pool.query(
      `SELECT org_id, id
         FROM console_stripe_payment_intents
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantRows.rows.length).toBe(0);
  });

  test('stablecoin quote/intent/transition tables enforce DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-billing-stablecoin-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-billing-stablecoin-rls',
      roles: ['admin'],
    };

    const ownerGeneration = await billing!.generateMonthlyInvoice(ownerCtx, {
      periodMonthUtc: '2026-01',
    });
    const attackerGeneration = await billing!.generateMonthlyInvoice(attackerCtx, {
      periodMonthUtc: '2026-01',
    });
    const ownerQuote = await billing!.createStablecoinQuote(ownerCtx, {
      invoiceId: ownerGeneration.invoice.id,
      asset: 'USDC',
      chain: 'Base',
    });
    const attackerQuote = await billing!.createStablecoinQuote(attackerCtx, {
      invoiceId: attackerGeneration.invoice.id,
      asset: 'USDT',
      chain: 'Ethereum',
    });
    const ownerIntent = await billing!.createStablecoinPaymentIntent(ownerCtx, {
      invoiceId: ownerGeneration.invoice.id,
      quoteId: ownerQuote.id,
    });
    const attackerIntent = await billing!.createStablecoinPaymentIntent(attackerCtx, {
      invoiceId: attackerGeneration.invoice.id,
      quoteId: attackerQuote.id,
    });

    const ownerQuoteRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stablecoin_quotes
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerQuoteRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerQuote.id,
      ),
    ).toBe(true);
    expect(
      ownerQuoteRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerQuote.id,
      ),
    ).toBe(false);
    expect(
      ownerQuoteRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerQuoteRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stablecoin_quotes
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerQuoteRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerQuote.id,
      ),
    ).toBe(true);
    expect(
      attackerQuoteRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerQuote.id,
      ),
    ).toBe(false);
    expect(
      attackerQuoteRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const ownerIntentRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerIntentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerIntent.id,
      ),
    ).toBe(true);
    expect(
      ownerIntentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerIntent.id,
      ),
    ).toBe(false);
    expect(
      ownerIntentRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerIntentRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, id
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerIntentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === attackerIntent.id,
      ),
    ).toBe(true);
    expect(
      attackerIntentRows.rows.some(
        (row) => String((row as Record<string, unknown>).id || '') === ownerIntent.id,
      ),
    ).toBe(false);
    expect(
      attackerIntentRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const ownerTransitionRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, payment_id
             FROM console_payment_state_transitions
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerTransitionRows.rows.some(
        (row) => String((row as Record<string, unknown>).payment_id || '') === ownerIntent.id,
      ),
    ).toBe(true);
    expect(
      ownerTransitionRows.rows.some(
        (row) => String((row as Record<string, unknown>).payment_id || '') === attackerIntent.id,
      ),
    ).toBe(false);
    expect(
      ownerTransitionRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerTransitionRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, payment_id
             FROM console_payment_state_transitions
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerTransitionRows.rows.some(
        (row) => String((row as Record<string, unknown>).payment_id || '') === attackerIntent.id,
      ),
    ).toBe(true);
    expect(
      attackerTransitionRows.rows.some(
        (row) => String((row as Record<string, unknown>).payment_id || '') === ownerIntent.id,
      ),
    ).toBe(false);
    expect(
      attackerTransitionRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantQuoteRows = await pool.query(
      `SELECT org_id, id
         FROM console_stablecoin_quotes
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantQuoteRows.rows.length).toBe(0);

    const noTenantIntentRows = await pool.query(
      `SELECT org_id, id
         FROM console_stablecoin_payment_intents
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantIntentRows.rows.length).toBe(0);

    const noTenantTransitionRows = await pool.query(
      `SELECT org_id, payment_id
         FROM console_payment_state_transitions
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantTransitionRows.rows.length).toBe(0);
  });

  test('stripe webhook events table enforces DB-level tenant RLS policies', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const pool = await getPostgresPool(postgresUrl);
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: 'owner-billing-webhook-rls',
      roles: ['admin'],
    };
    const attackerCtx = {
      orgId: attackerOrgId,
      actorUserId: 'attacker-billing-webhook-rls',
      roles: ['admin'],
    };

    const ownerGeneration = await billing!.generateMonthlyInvoice(ownerCtx, {
      periodMonthUtc: '2026-01',
    });
    const attackerGeneration = await billing!.generateMonthlyInvoice(attackerCtx, {
      periodMonthUtc: '2026-01',
    });
    const ownerIntent = await billing!.createStripePaymentIntent(ownerCtx, {
      invoiceId: ownerGeneration.invoice.id,
    });
    const attackerIntent = await billing!.createStripePaymentIntent(attackerCtx, {
      invoiceId: attackerGeneration.invoice.id,
    });

    const ownerEventId = `evt_owner_${Date.now()}`;
    const attackerEventId = `evt_attacker_${Date.now()}`;
    await billing!.processStripeWebhookEvent({
      eventId: ownerEventId,
      providerRef: ownerIntent.providerRef,
      providerStatus: 'PENDING',
    });
    await billing!.processStripeWebhookEvent({
      eventId: attackerEventId,
      providerRef: attackerIntent.providerRef,
      providerStatus: 'PENDING',
    });

    const ownerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: ownerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, event_id
             FROM console_stripe_webhook_events
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      ownerRows.rows.some((row) => String((row as Record<string, unknown>).event_id || '') === ownerEventId),
    ).toBe(true);
    expect(
      ownerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === ownerOrgId,
      ),
    ).toBe(true);

    const attackerRows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId: attackerOrgId },
      async (q) =>
        q.query(
          `SELECT org_id, event_id
             FROM console_stripe_webhook_events
            WHERE namespace = $1`,
          [namespace],
        ),
    );
    expect(
      attackerRows.rows.some(
        (row) => String((row as Record<string, unknown>).event_id || '') === attackerEventId,
      ),
    ).toBe(true);
    expect(
      attackerRows.rows.every(
        (row) => String((row as Record<string, unknown>).org_id || '') === attackerOrgId,
      ),
    ).toBe(true);

    const noTenantRows = await pool.query(
      `SELECT org_id, event_id
         FROM console_stripe_webhook_events
        WHERE namespace = $1`,
      [namespace],
    );
    expect(noTenantRows.rows.length).toBe(0);
  });
});
