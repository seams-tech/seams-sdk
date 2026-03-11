import { expect, test } from '@playwright/test';
import { ensureConsoleApprovalsPostgresSchema } from '../../server/src/console/approvals';
import { ensureConsoleAuditPostgresSchema } from '../../server/src/console/audit';
import { ensureConsolePoliciesPostgresSchema } from '../../server/src/console/policies';
import {
  createPostgresConsoleSponsoredCallService,
  ensureConsoleSponsoredCallPostgresSchema,
} from '../../server/src/console/sponsoredCalls';
import {
  createPostgresConsoleSponsorshipSpendCapService,
  ensureConsoleSponsorshipSpendCapPostgresSchema,
} from '../../server/src/console/sponsorshipSpendCaps';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../server/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

test.describe('console policy id postgres migration', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-policy-id:postgres');
  const ctx = {
    orgId: 'org-policy-id-migration',
    actorUserId: 'user-policy-id-migration',
    roles: ['admin'],
  };
  const fixedNow = new Date('2026-03-10T12:00:00.000Z');
  const fixedNowMs = fixedNow.getTime();
  const legacyPolicyId = 'policy_manual_custom';

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
      await q.query('DELETE FROM console_sponsored_call_records WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_sponsorship_spend_cap_windows WHERE namespace = $1', [
        namespace,
      ]);
      await q.query('DELETE FROM console_sponsorship_spend_cap_reservations WHERE namespace = $1', [
        namespace,
      ]);
      await q.query('DELETE FROM console_audit_events WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_approvals WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_policy_assignments WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_policy_versions WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_policies WHERE namespace = $1', [namespace]);
    });
  });

  test('schema migration rewrites manual canonical policy ids and persisted references', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    await ensureConsoleApprovalsPostgresSchema({
      postgresUrl,
      logger: console as any,
    });
    await ensureConsoleAuditPostgresSchema({
      postgresUrl,
      logger: console as any,
    });
    await ensureConsoleSponsorshipSpendCapPostgresSchema({
      postgresUrl,
      logger: console as any,
    });
    await ensureConsoleSponsoredCallPostgresSchema({
      postgresUrl,
      logger: console as any,
    });
    await ensureConsolePoliciesPostgresSchema({
      postgresUrl,
      logger: console as any,
    });

    const spendCapService = await createPostgresConsoleSponsorshipSpendCapService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNow),
    });
    const sponsoredCallService = await createPostgresConsoleSponsoredCallService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNow),
    });
    const pool = await getPostgresPool(postgresUrl);

    await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
      await q.query(
        `INSERT INTO console_policies
          (namespace, org_id, id, name, description, status, version, rules, created_at_ms, updated_at_ms, published_at_ms, is_system_default)
         VALUES
          ($1, $2, $3, $4, $5, 'PUBLISHED', 1, $6::jsonb, $7, $7, $7, FALSE)`,
        [
          namespace,
          ctx.orgId,
          legacyPolicyId,
          'Manual Policy',
          'Legacy manual canonical id',
          JSON.stringify({
            schemaVersion: 1,
            blockedActions: ['transfer'],
            allowedChains: ['Ethereum'],
            allowedContractCalls: [],
          }),
          fixedNowMs,
        ],
      );
      await q.query(
        `INSERT INTO console_policy_versions
          (namespace, org_id, policy_id, version, status, rules, published_at_ms, created_at_ms, actor_user_id)
         VALUES
          ($1, $2, $3, 1, 'PUBLISHED', $4::jsonb, $5, $5, $6)`,
        [
          namespace,
          ctx.orgId,
          legacyPolicyId,
          JSON.stringify({
            schemaVersion: 1,
            blockedActions: ['transfer'],
            allowedChains: ['Ethereum'],
            allowedContractCalls: [],
          }),
          fixedNowMs,
          ctx.actorUserId,
        ],
      );
      await q.query(
        `INSERT INTO console_policy_assignments
          (namespace, org_id, id, scope_type, scope_id, policy_id, created_at_ms, updated_at_ms)
         VALUES
          ($1, $2, $3, 'ENVIRONMENT', $4, $5, $6, $6)`,
        [namespace, ctx.orgId, 'assignment_manual_policy_1', 'env-migration', legacyPolicyId, fixedNowMs],
      );
      await q.query(
        `INSERT INTO console_approvals
          (namespace, org_id, id, operation_type, status, reason, requested_by_user_id, required_approvals, require_mfa, project_id, environment_id, resource_type, resource_id, metadata, decisions, created_at_ms, updated_at_ms, resolved_at_ms)
         VALUES
          ($1, $2, $3, 'POLICY_PUBLISH', 'PENDING', $4, $5, 1, FALSE, $6, $7, 'policy', $8, $9::jsonb, '[]'::jsonb, $10, $10, NULL)`,
        [
          namespace,
          ctx.orgId,
          'apr_manual_policy_1',
          'Publish manual policy',
          ctx.actorUserId,
          'proj-migration',
          'env-migration',
          legacyPolicyId,
          JSON.stringify({
            policyId: legacyPolicyId,
            resourceId: legacyPolicyId,
          }),
          fixedNowMs,
        ],
      );
      await q.query(
        `INSERT INTO console_audit_events
          (namespace, org_id, id, project_id, environment_id, actor_user_id, actor_type, category, action, outcome, summary, metadata, created_at_ms)
         VALUES
          ($1, $2, $3, $4, $5, $6, 'USER', 'POLICY', 'policy.publish', 'SUCCESS', $7, $8::jsonb, $9)`,
        [
          namespace,
          ctx.orgId,
          'aud_manual_policy_1',
          'proj-migration',
          'env-migration',
          ctx.actorUserId,
          `Published manual policy ${legacyPolicyId}`,
          JSON.stringify({
            policyId: legacyPolicyId,
            resourceId: legacyPolicyId,
          }),
          fixedNowMs,
        ],
      );
    });

    await spendCapService.reserve(ctx, {
      sourceEventId: 'source-event-manual-policy-1',
      environmentId: 'env-migration',
      policyId: legacyPolicyId,
      chainId: 1,
      mode: 'CHAIN_TOTAL',
      period: 'MONTHLY',
      capMinor: 1_000,
      estimatedSpendMinor: 250,
    });
    await sponsoredCallService.createRecord(ctx, {
      environmentId: 'env-migration',
      apiKeyId: 'pk_manual_policy_1',
      apiKeyKind: 'publishable_key',
      route: 'sponsored_evm_call_v1',
      policyId: legacyPolicyId,
      chainFamily: 'evm',
      intentKind: 'evm_call',
      accountRef: 'near:alice.testnet',
      targetRef: 'evm:1:0x1111111111111111111111111111111111111111',
      sponsorRef: 'evm:1:0x2222222222222222222222222222222222222222',
      txOrExecutionRef: '0xabc123',
      receiptStatus: 'success',
      feeUnit: 'wei',
      feeAmount: '10',
      detailsJson: JSON.stringify({ ok: true }),
      sourceEventId: 'source-event-manual-policy-1',
    });

    await ensureConsolePoliciesPostgresSchema({
      postgresUrl,
      logger: console as any,
    });

    await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
      const policiesResult = await q.query(
        `SELECT id
           FROM console_policies
          WHERE namespace = $1 AND org_id = $2 AND name = $3`,
        [namespace, ctx.orgId, 'Manual Policy'],
      );
      expect(policiesResult.rows).toHaveLength(1);
      const migratedPolicyId = String(
        (policiesResult.rows[0] as Record<string, unknown>).id || '',
      );
      expect(migratedPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]{8}$/);
      expect(migratedPolicyId).not.toBe(legacyPolicyId);

      const legacyPolicyResult = await q.query(
        `SELECT id
           FROM console_policies
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, ctx.orgId, legacyPolicyId],
      );
      expect(legacyPolicyResult.rows).toHaveLength(0);

      const versionIds = await q.query(
        `SELECT policy_id
           FROM console_policy_versions
          WHERE namespace = $1 AND org_id = $2`,
        [namespace, ctx.orgId],
      );
      expect(versionIds.rows.map((row) => String((row as Record<string, unknown>).policy_id || ''))).toEqual([
        migratedPolicyId,
      ]);

      const assignmentIds = await q.query(
        `SELECT policy_id
           FROM console_policy_assignments
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, ctx.orgId, 'assignment_manual_policy_1'],
      );
      expect(
        assignmentIds.rows.map((row) => String((row as Record<string, unknown>).policy_id || '')),
      ).toEqual([migratedPolicyId]);

      const approvals = await q.query(
        `SELECT resource_id, metadata->>'policyId' AS policy_id, metadata->>'resourceId' AS metadata_resource_id
           FROM console_approvals
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, ctx.orgId, 'apr_manual_policy_1'],
      );
      expect(approvals.rows).toHaveLength(1);
      expect(approvals.rows[0]).toMatchObject({
        metadata_resource_id: migratedPolicyId,
        policy_id: migratedPolicyId,
        resource_id: migratedPolicyId,
      });

      const audit = await q.query(
        `SELECT summary, metadata->>'policyId' AS policy_id, metadata->>'resourceId' AS metadata_resource_id
           FROM console_audit_events
          WHERE namespace = $1 AND org_id = $2 AND id = $3`,
        [namespace, ctx.orgId, 'aud_manual_policy_1'],
      );
      expect(audit.rows).toHaveLength(1);
      expect(String((audit.rows[0] as Record<string, unknown>).summary || '')).toContain(
        migratedPolicyId,
      );
      expect(audit.rows[0]).toMatchObject({
        metadata_resource_id: migratedPolicyId,
        policy_id: migratedPolicyId,
      });

      const windows = await q.query(
        `SELECT policy_id
           FROM console_sponsorship_spend_cap_windows
          WHERE namespace = $1 AND org_id = $2`,
        [namespace, ctx.orgId],
      );
      expect(windows.rows.map((row) => String((row as Record<string, unknown>).policy_id || ''))).toEqual([
        migratedPolicyId,
      ]);

      const reservations = await q.query(
        `SELECT policy_id
           FROM console_sponsorship_spend_cap_reservations
          WHERE namespace = $1 AND org_id = $2 AND source_event_id = $3`,
        [namespace, ctx.orgId, 'source-event-manual-policy-1'],
      );
      expect(
        reservations.rows.map((row) => String((row as Record<string, unknown>).policy_id || '')),
      ).toEqual([migratedPolicyId]);

      const sponsoredCalls = await q.query(
        `SELECT policy_id
           FROM console_sponsored_call_records
          WHERE namespace = $1 AND org_id = $2 AND source_event_id = $3`,
        [namespace, ctx.orgId, 'source-event-manual-policy-1'],
      );
      expect(
        sponsoredCalls.rows.map((row) => String((row as Record<string, unknown>).policy_id || '')),
      ).toEqual([migratedPolicyId]);
    });

    const poolIndexResult = await pool.query(
      `SELECT indexname
         FROM pg_indexes
        WHERE tablename = 'console_policies'
          AND indexname = 'console_policies_namespace_id_uidx'`,
    );
    expect(poolIndexResult.rows).toHaveLength(1);
  });
});
