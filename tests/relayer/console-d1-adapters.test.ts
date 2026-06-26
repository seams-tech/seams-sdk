import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';
import { createD1ConsoleAccountService } from '../../packages/sdk-server-ts/src/console/account/d1';
import { createD1ConsoleBillingService } from '../../packages/sdk-server-ts/src/console/billing/d1';
import { createD1ConsoleBillingPrepaidReservationService } from '../../packages/sdk-server-ts/src/console/billingPrepaidReservations/d1';
import { createD1ConsoleOrgProjectEnvService } from '../../packages/sdk-server-ts/src/console/orgProjectEnv/d1';
import { createD1ConsolePolicyService } from '../../packages/sdk-server-ts/src/console/policies/d1';
import {
  createD1ConsoleRuntimeSnapshotService,
  runD1ConsoleRuntimeSnapshotOutboxDispatch,
  type D1ConsoleRuntimeSnapshotOutboxDispatchResult,
} from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/d1';
import type { ConsoleRuntimeSnapshotOutboxEvent } from '../../packages/sdk-server-ts/src/console/runtimeSnapshots/types';
import { createD1ConsoleSponsoredCallService } from '../../packages/sdk-server-ts/src/console/sponsoredCalls/d1';
import { createD1ConsoleTeamRbacService } from '../../packages/sdk-server-ts/src/console/teamRbac/d1';
import { D1SigningRootSecretStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/SigningRootSecretStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import {
  recordSponsoredExecution,
  type RecordSponsoredExecutionInput,
} from '../../packages/sdk-server-ts/src/router/sponsorshipExecution';
import type {
  SponsorshipSpendPricingEstimateInput,
  SponsorshipSpendPricingFinalizeInput,
  SponsorshipSpendPricingQuote,
  SponsorshipSpendPricingService,
} from '../../packages/sdk-server-ts/src/sponsorship/spendCaps';

type SqliteJsonRow = Record<string, unknown>;
type ErrorWithCode = { readonly code?: unknown };
type SponsoredRecordBuildInput = Parameters<RecordSponsoredExecutionInput['buildRecord']>[0];
type SponsoredRecordBuildOutput = ReturnType<RecordSponsoredExecutionInput['buildRecord']>;

class SqliteCliD1Database implements D1DatabaseLike {
  constructor(readonly databasePath: string) {}

  prepare(query: string): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, query, []);
  }

  async batch<T = unknown>(
    statements: readonly D1PreparedStatementLike[],
  ): Promise<readonly T[]> {
    const sqlStatements = statements.map(sqlFromD1PreparedStatement);
    runSqlite(this.databasePath, `BEGIN IMMEDIATE; ${sqlStatements.join(' ')} COMMIT;`);
    return sqlStatements.map(buildSuccessfulD1BatchResult) as readonly T[];
  }

  async exec(query: string): Promise<unknown> {
    runSqlite(this.databasePath, query);
    return null;
  }
}

class SqliteCliD1PreparedStatement implements D1PreparedStatementLike {
  constructor(
    private readonly databasePath: string,
    private readonly query: string,
    private readonly values: readonly unknown[],
  ) {}

  bind(...values: readonly unknown[]): D1PreparedStatementLike {
    return new SqliteCliD1PreparedStatement(this.databasePath, this.query, values);
  }

  async first<T = unknown>(columnName?: string): Promise<T | null> {
    const result = await this.all<SqliteJsonRow>();
    const row = result.results?.[0] || null;
    if (!row) return null;
    if (!columnName) return row as T;
    const value = row[columnName];
    return value === undefined ? null : (value as T);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    const results = runSqliteJson(this.databasePath, this.toSql());
    return {
      success: true,
      results: results as readonly T[],
      meta: {
        rows_read: results.length,
        rows_written: 0,
      },
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    const sql = `${this.toSql()} SELECT changes() AS changes, last_insert_rowid() AS last_row_id;`;
    const results = runSqliteJson(this.databasePath, sql);
    const metaRow = results.at(-1) || {};
    return {
      success: true,
      results: [] as readonly T[],
      meta: {
        changes: toInteger(metaRow.changes),
        last_row_id: toInteger(metaRow.last_row_id),
        rows_written: toInteger(metaRow.changes),
      },
    };
  }

  toSql(): string {
    return interpolateSql(this.query, this.values);
  }
}

class RuntimeSnapshotOutboxRaceHarness {
  readonly dispatchedEventIds: string[] = [];
  competitorResult: D1ConsoleRuntimeSnapshotOutboxDispatchResult | null = null;

  constructor(
    private readonly database: D1DatabaseLike,
    private readonly namespace: string,
    private readonly orgId: string,
    private readonly nowMs: number,
  ) {}

  now(): Date {
    return new Date(this.nowMs);
  }

  async dispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(event.eventId);
    this.competitorResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
      database: this.database,
      namespace: this.namespace,
      orgIds: [this.orgId],
      limit: 1,
      ensureSchema: false,
      now: this.now.bind(this),
      workerId: 'snapshot-race-worker-b',
      claimTtlMs: 60_000,
      dispatch: this.competitorDispatch.bind(this),
    });
  }

  async competitorDispatch(event: ConsoleRuntimeSnapshotOutboxEvent): Promise<void> {
    this.dispatchedEventIds.push(`competitor:${event.eventId}`);
  }
}

class StaticSponsoredSpendPricingService implements SponsorshipSpendPricingService {
  constructor(
    private readonly estimatedSpendMinor: number,
    private readonly settledSpendMinor: number,
  ) {}

  async estimateSponsoredExecutionSpend(
    _input: SponsorshipSpendPricingEstimateInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return {
      spendMinor: this.estimatedSpendMinor,
      pricingVersion: 'static:estimate',
    };
  }

  async finalizeSponsoredExecutionSpend(
    _input: SponsorshipSpendPricingFinalizeInput,
  ): Promise<SponsorshipSpendPricingQuote> {
    return {
      spendMinor: this.settledSpendMinor,
      pricingVersion: 'static:settled',
    };
  }
}

class AtomicD1SponsoredRecordBuilder {
  constructor(private readonly idempotencyKey: string) {}

  build(input: SponsoredRecordBuildInput): SponsoredRecordBuildOutput {
    return {
      environmentId: 'env-production',
      apiKeyId: 'api-key-d1-atomic',
      apiKeyKind: 'publishable_key',
      route: 'sponsored_evm_call_v1',
      policyId: 'policy-sponsored-gas',
      chainFamily: 'evm',
      intentKind: 'evm_call',
      accountRef: '0x1111111111111111111111111111111111111111',
      targetRef: '0x2222222222222222222222222222222222222222',
      sponsorRef: '0x3333333333333333333333333333333333333333',
      detailsJson: JSON.stringify({
        kind: 'd1-atomic-sponsored-settlement',
        billing: input.prepaidSettlement,
      }),
      estimatedSpendMinor: input.prepaidSettlement?.estimatedSpendMinor ?? null,
      settledSpendMinor: input.prepaidSettlement?.settledSpendMinor ?? null,
      pricingVersion: input.prepaidSettlement?.pricingVersion ?? null,
      pricingSource: input.prepaidSettlement ? 'sponsorship_pricing_service' : null,
      billingLedgerEntryId: input.billingLedgerEntryId,
      prepaidReservationId: input.prepaidSettlement?.reservationId || null,
      charged: Boolean(
        input.prepaidSettlement &&
          !input.prepaidSettlement.released &&
          input.prepaidSettlement.settledSpendMinor > 0,
      ),
      chargedReason: input.prepaidSettlement
        ? input.prepaidSettlement.released
          ? 'released_zero_spend'
          : input.prepaidSettlement.settledSpendMinor > 0
            ? 'sponsored_execution_debit'
            : 'settled_zero_spend'
        : null,
      settledAt: input.prepaidSettlement?.settledAt || null,
      idempotencyKey: this.idempotencyKey,
    };
  }
}

function fixedD1AtomicBillingNow(): Date {
  return new Date('2026-06-27T00:00:00.000Z');
}

function createD1AtomicAssessment(): RecordSponsoredExecutionInput['assessment'] {
  return {
    succeeded: true,
    txOrExecutionRef: '0xatomicsettled',
    receiptStatus: 'success',
    feeUnit: 'wei',
    feeAmount: '1000000000000000',
    executorKind: 'evm_eoa',
    responseCode: 'ok',
    responseMessage: 'settled',
    recordErrorCode: null,
    recordErrorMessage: null,
  };
}

function sqlFromD1PreparedStatement(statement: D1PreparedStatementLike): string {
  if (!(statement instanceof SqliteCliD1PreparedStatement)) {
    throw new Error('SQLite D1 test batch only accepts SQLite-backed statements');
  }
  return statement.toSql();
}

function buildSuccessfulD1BatchResult(): D1ResultLike {
  return {
    success: true,
    results: [],
    meta: {
      changes: 0,
      rows_written: 0,
    },
  };
}

function createTemporaryD1Database(): { readonly database: D1DatabaseLike; readonly tempDir: string } {
  const tempDir = mkdtempSync(path.join(tmpdir(), 'seams-d1-adapter-test-'));
  return {
    database: new SqliteCliD1Database(path.join(tempDir, 'test.sqlite')),
    tempDir,
  };
}

function cleanupTemporaryD1Database(tempDir: string): void {
  rmSync(tempDir, { recursive: true, force: true });
}

function runSqlite(databasePath: string, sql: string): void {
  const result = spawnSync('sqlite3', [databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status === 0) return;
  throw new Error(formatSqliteError(result.stderr, sql));
}

function runSqliteJson(databasePath: string, sql: string): readonly SqliteJsonRow[] {
  const result = spawnSync('sqlite3', ['-json', databasePath, sql], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (result.status !== 0) {
    throw new Error(formatSqliteError(result.stderr, sql));
  }
  const stdout = result.stdout.trim();
  if (!stdout) return [];
  const parsed: unknown = JSON.parse(stdout);
  if (!Array.isArray(parsed)) {
    throw new Error(`sqlite3 JSON output was not an array: ${stdout}`);
  }
  return parsed.filter(isSqliteJsonRow);
}

function formatSqliteError(stderr: string, sql: string): string {
  return `sqlite3 failed: ${stderr.trim() || 'unknown error'}\nSQL: ${sql}`;
}

function isSqliteJsonRow(input: unknown): input is SqliteJsonRow {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function interpolateSql(query: string, values: readonly unknown[]): string {
  const segments = splitSqlByPlaceholders(query);
  if (segments.length - 1 !== values.length) {
    throw new Error(
      `SQL placeholder count ${segments.length - 1} did not match bound value count ${values.length}`,
    );
  }
  let sql = segments[0] || '';
  for (let i = 0; i < values.length; i += 1) {
    sql += `${sqlLiteral(values[i])}${segments[i + 1] || ''}`;
  }
  return ensureSqlStatementTerminator(sql);
}

function splitSqlByPlaceholders(query: string): readonly string[] {
  const segments: string[] = [];
  let current = '';
  let inSingleQuote = false;
  for (let i = 0; i < query.length; i += 1) {
    const char = query[i] || '';
    const next = query[i + 1] || '';
    if (char === "'" && inSingleQuote && next === "'") {
      current += "''";
      i += 1;
      continue;
    }
    if (char === "'") {
      inSingleQuote = !inSingleQuote;
      current += char;
      continue;
    }
    if (char === '?' && !inSingleQuote) {
      segments.push(current);
      current = '';
      continue;
    }
    current += char;
  }
  segments.push(current);
  return segments;
}

function ensureSqlStatementTerminator(sql: string): string {
  const trimmed = sql.trim();
  return trimmed.endsWith(';') ? trimmed : `${trimmed};`;
}

function sqlLiteral(value: unknown): string {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? '1' : '0';
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString('hex')}'`;
  if (value instanceof Date) return quoteSqlString(value.toISOString());
  return quoteSqlString(String(value));
}

function quoteSqlString(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function toInteger(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function errorCode(error: unknown): string {
  const maybeCode = isErrorWithCode(error) ? error.code : null;
  return String(maybeCode || '');
}

function isErrorWithCode(input: unknown): input is ErrorWithCode {
  return Boolean(input && typeof input === 'object' && 'code' in input);
}

test.describe('D1 adapter contracts', () => {
  test('org project environment adapter scopes tenants and default environments', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleOrgProjectEnvService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const primaryCtx = {
        orgId: 'org-d1-projects-primary',
        actorUserId: 'user-d1-projects-primary',
        roles: ['admin'],
      };
      const secondaryCtx = {
        orgId: 'org-d1-projects-secondary',
        actorUserId: 'user-d1-projects-secondary',
        roles: ['admin'],
      };

      let missingOrgError: unknown = null;
      try {
        await service.getOrganization(primaryCtx);
      } catch (error: unknown) {
        missingOrgError = error;
      }
      expect(errorCode(missingOrgError)).toBe('organization_not_found');

      const primaryOrg = await service.upsertOrganization(primaryCtx, {
        name: 'D1 Primary Org',
      });
      expect(primaryOrg.slug).toBe('d1-primary-org');
      await expect(service.findDefaultOrganization()).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });

      const project = await service.createProject(primaryCtx, {
        id: 'project-d1-org',
        name: 'D1 Control Plane',
        liveEnvironmentsEnabled: false,
      });
      expect(project.environmentCount).toBe(3);

      const environments = await service.listEnvironments(primaryCtx, {
        projectId: project.id,
      });
      expect(environments.map((environment) => environment.key)).toEqual([
        'prod',
        'staging',
        'dev',
      ]);
      expect(environments.map((environment) => environment.status)).toEqual([
        'DISABLED',
        'DISABLED',
        'ACTIVE',
      ]);

      const prodEnvironment = await service.updateEnvironment(
        primaryCtx,
        'project-d1-org:prod',
        {
          signingRootVersion: 'signing-root-d1-v2',
          name: 'Production Root',
        },
      );
      expect(prodEnvironment?.signingRootVersion).toBe('signing-root-d1-v2');

      await service.upsertOrganization(secondaryCtx, {
        name: 'D1 Secondary Org',
      });
      await expect(service.findDefaultOrganization()).resolves.toBeNull();
      await expect(service.listProjects(secondaryCtx)).resolves.toHaveLength(0);
      await expect(
        service.updateEnvironment(secondaryCtx, 'project-d1-org:prod', {
          name: 'Cross Tenant Mutation',
        }),
      ).resolves.toBeNull();

      await expect(
        service.findOrganizationForScope({ projectId: project.id }),
      ).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });
      await expect(
        service.findOrganizationForScope({
          projectId: project.id,
          environmentId: 'project-d1-org:prod',
        }),
      ).resolves.toMatchObject({
        id: primaryCtx.orgId,
      });
      await expect(service.searchOrganizations({ query: 'primary', limit: 5 })).resolves.toEqual([
        expect.objectContaining({ id: primaryCtx.orgId }),
      ]);

      let duplicateEnvironmentKeyError: unknown = null;
      try {
        await service.createEnvironment(primaryCtx, {
          projectId: project.id,
          key: 'dev',
          name: 'Duplicate Development',
        });
      } catch (error: unknown) {
        duplicateEnvironmentKeyError = error;
      }
      expect(errorCode(duplicateEnvironmentKeyError)).toBe('environment_key_conflict');

      const archivedProject = await service.archiveProject(primaryCtx, project.id);
      expect(archivedProject?.status).toBe('ARCHIVED');
      const archivedEnvironments = await service.listEnvironments(primaryCtx, {
        projectId: project.id,
        status: 'ARCHIVED',
      });
      expect(archivedEnvironments).toHaveLength(3);

      let archivedProjectError: unknown = null;
      try {
        await service.updateProject(primaryCtx, project.id, {
          name: 'Archived Project Update',
        });
      } catch (error: unknown) {
        archivedProjectError = error;
      }
      expect(errorCode(archivedProjectError)).toBe('project_archived');

      const deleted = await service.deleteOrganization(primaryCtx);
      expect(deleted.deleted).toBe(true);
      await expect(service.findOrganizationForScope({ projectId: project.id })).resolves.toBeNull();
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('account adapter stores profiles and resolves created organizations from D1', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgProjectEnv = await createD1ConsoleOrgProjectEnvService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const teamRbac = await createD1ConsoleTeamRbacService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const service = await createD1ConsoleAccountService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        orgProjectEnv,
        teamRbac,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        userId: 'user-d1-account',
        orgId: 'org-d1-account-home',
        roles: [],
        email: 'USER-D1-ACCOUNT@example.com',
        name: 'D1 Account User',
      };

      const initialProfile = await service.getProfile(ctx);
      expect(initialProfile.displayName).toBe('D1 Account User');
      expect(initialProfile.primaryEmail).toBe('user-d1-account@example.com');
      expect(initialProfile.backupEmails).toHaveLength(0);

      const updatedProfile = await service.updateProfile(ctx, {
        displayName: 'D1 Account Owner',
        primaryEmail: 'owner-d1-account@example.com',
        addBackupEmail: 'backup-d1-account@example.com',
      });
      expect(updatedProfile.displayName).toBe('D1 Account Owner');
      expect(updatedProfile.primaryEmail).toBe('owner-d1-account@example.com');
      expect(updatedProfile.backupEmails).toEqual([
        expect.objectContaining({
          email: 'backup-d1-account@example.com',
          status: 'PENDING',
        }),
      ]);

      const duplicateBackupProfile = await service.updateProfile(ctx, {
        addBackupEmail: 'backup-d1-account@example.com',
      });
      expect(duplicateBackupProfile.backupEmails).toHaveLength(1);

      const removedBackupProfile = await service.updateProfile(ctx, {
        removeBackupEmail: 'backup-d1-account@example.com',
      });
      expect(removedBackupProfile.backupEmails).toHaveLength(0);

      let readOnlyEmailError: unknown = null;
      try {
        await service.updateProfile(
          { ...ctx, provider: 'oidc' },
          { primaryEmail: 'oidc-owned@example.com' },
        );
      } catch (error: unknown) {
        readOnlyEmailError = error;
      }
      expect(errorCode(readOnlyEmailError)).toBe('primary_email_read_only');

      const organization = await service.createOrganization(ctx, {
        id: 'org-d1-account-created',
        name: 'D1 Account Created Org',
      });
      expect(organization.actorIsOwner).toBe(true);
      expect(organization.actorRoles).toContain('owner');

      await orgProjectEnv.createProject(
        {
          orgId: organization.id,
          actorUserId: ctx.userId,
          roles: ['owner'],
        },
        {
          id: 'project-d1-account',
          name: 'D1 Account Project',
          liveEnvironmentsEnabled: true,
        },
      );

      const organizations = await service.listOrganizations(ctx);
      expect(organizations).toHaveLength(1);
      expect(organizations[0]).toMatchObject({
        id: organization.id,
        selectedProjectId: 'project-d1-account',
        selectedEnvironmentId: 'project-d1-account:prod',
      });

      const switched = await service.switchOrganizationContext(ctx, organization.id);
      expect(switched.actorRoles).toContain('owner');
      expect(switched.projectId).toBe('project-d1-account');
      expect(switched.environmentId).toBe('project-d1-account:prod');

      const renamed = await service.updateOrganization(ctx, organization.id, {
        name: 'D1 Account Renamed Org',
      });
      expect(renamed.name).toBe('D1 Account Renamed Org');

      let duplicateOrganizationError: unknown = null;
      try {
        await service.createOrganization(ctx, {
          id: organization.id,
          name: 'Duplicate Org',
        });
      } catch (error: unknown) {
        duplicateOrganizationError = error;
      }
      expect(errorCode(duplicateOrganizationError)).toBe('organization_already_exists');
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('team RBAC adapter preserves owner and member lifecycle invariants', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleTeamRbacService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ownerCtx = {
        orgId: 'org-d1-team-rbac',
        actorUserId: 'user-d1-owner',
        roles: [],
        actorEmail: 'owner-d1-team@example.com',
        actorDisplayName: 'D1 Owner',
      };
      const ownerClaimCtx = {
        ...ownerCtx,
        roles: ['owner'],
      };

      const owner = await service.bootstrapOwner(ownerCtx);
      expect(owner.roles.map((entry) => entry.role)).toContain('owner');

      let forbiddenOwnerInviteError: unknown = null;
      try {
        await service.inviteMember(ownerCtx, {
          userId: 'user-d1-forbidden-owner',
          email: 'forbidden-owner@example.com',
          roles: [{ role: 'owner', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        forbiddenOwnerInviteError = error;
      }
      expect(errorCode(forbiddenOwnerInviteError)).toBe('forbidden');

      const admin = await service.inviteMember(ownerClaimCtx, {
        userId: 'user-d1-admin',
        email: 'admin-d1-team@example.com',
        displayName: 'D1 Admin',
        roles: [{ role: 'admin', scope: 'ORG' }],
      });
      expect(admin.status).toBe('ACTIVE');
      expect(admin.roles.map((entry) => entry.role)).toEqual(['admin']);

      let duplicateMemberError: unknown = null;
      try {
        await service.inviteMember(ownerClaimCtx, {
          userId: 'user-d1-admin-copy',
          email: 'admin-d1-team@example.com',
          roles: [{ role: 'billing_read', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        duplicateMemberError = error;
      }
      expect(errorCode(duplicateMemberError)).toBe('member_already_exists');

      let lastOwnerRoleError: unknown = null;
      try {
        await service.updateMemberRoles(ownerClaimCtx, owner.id, {
          roles: [{ role: 'admin', scope: 'ORG' }],
        });
      } catch (error: unknown) {
        lastOwnerRoleError = error;
      }
      expect(errorCode(lastOwnerRoleError)).toBe('last_owner_required');

      const transfer = await service.transferOwner(ownerClaimCtx, admin.id);
      expect(transfer.previousOwner.roles.map((entry) => entry.role)).toEqual(['admin']);
      expect(transfer.nextOwner.roles.map((entry) => entry.role)).toEqual(['admin', 'owner']);

      let lastOwnerRemoveError: unknown = null;
      try {
        await service.removeMember(
          {
            ...ownerClaimCtx,
            actorUserId: admin.userId,
            actorEmail: admin.email,
          },
          admin.id,
        );
      } catch (error: unknown) {
        lastOwnerRemoveError = error;
      }
      expect(errorCode(lastOwnerRemoveError)).toBe('last_owner_required');

      const removedPreviousOwner = await service.removeMember(
        {
          ...ownerClaimCtx,
          actorUserId: admin.userId,
          actorEmail: admin.email,
        },
        owner.id,
      );
      expect(removedPreviousOwner.removed).toBe(true);
      expect(removedPreviousOwner.member?.status).toBe('REMOVED');

      const restored = await service.inviteMember(
        {
          ...ownerClaimCtx,
          actorUserId: admin.userId,
          actorEmail: admin.email,
        },
        {
          userId: owner.userId,
          email: owner.email,
          roles: [{ role: 'billing_read', scope: 'ORG' }],
        },
      );
      expect(restored.id).toBe(owner.id);
      expect(restored.status).toBe('ACTIVE');
      expect(restored.roles.map((entry) => entry.role)).toEqual(['billing_read']);

      const activeMembers = service.listOrganizationMembers
        ? await service.listOrganizationMembers('org-d1-team-rbac', { status: 'ACTIVE' })
        : [];
      expect(activeMembers).toHaveLength(2);
      const otherOrgMembers = service.listOrganizationMembers
        ? await service.listOrganizationMembers('org-d1-team-rbac-other')
        : [];
      expect(otherOrgMembers).toEqual([]);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('policy adapter bootstraps defaults and resolves published scope precedence', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsolePolicyService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        orgId: 'org-d1-policies',
        actorUserId: 'user-d1-policies',
        roles: ['admin'],
      };

      const initialPolicies = await service.listPolicies(ctx);
      expect(initialPolicies).toHaveLength(1);
      const defaultPolicy = initialPolicies[0];
      expect(defaultPolicy).toMatchObject({
        orgId: ctx.orgId,
        isSystemDefault: true,
        kind: 'TRANSACTION',
        status: 'PUBLISHED',
        version: 1,
      });

      const defaultVersions = await service.listPolicyVersions(ctx, defaultPolicy.id);
      expect(defaultVersions).toEqual([
        expect.objectContaining({
          policyId: defaultPolicy.id,
          version: 1,
          actorUserId: 'system-bootstrap',
        }),
      ]);

      let defaultDeleteError: unknown = null;
      try {
        await service.deletePolicy(ctx, defaultPolicy.id);
      } catch (error: unknown) {
        defaultDeleteError = error;
      }
      expect(errorCode(defaultDeleteError)).toBe('default_policy_protected');

      const created = await service.createPolicy(ctx, {
        kind: 'TRANSACTION',
        name: 'D1 Project Policy',
        rules: {
          allowedChains: ['eip155:84532'],
          blockedActions: ['delete_wallet'],
        },
        assignment: {
          scopeType: 'PROJECT',
          scopeId: 'project-d1-policy',
        },
      });
      expect(created.status).toBe('DRAFT');
      expect(created.version).toBe(0);

      const firstPublish = await service.publishPolicy(ctx, created.id);
      expect(firstPublish?.policy).toMatchObject({
        id: created.id,
        status: 'PUBLISHED',
        version: 1,
      });

      const updated = await service.updatePolicy(ctx, created.id, {
        rules: {
          allowedChains: ['eip155:1'],
          blockedActions: ['delete_wallet'],
        },
      });
      expect(updated?.status).toBe('DRAFT');
      const secondPublish = await service.publishPolicy(ctx, created.id);
      expect(secondPublish?.policy.version).toBe(2);

      const versions = await service.listPolicyVersions(ctx, created.id);
      expect(versions?.map((version) => version.version)).toEqual([2, 1]);
      expect(versions?.map((version) => version.actorUserId)).toEqual([
        ctx.actorUserId,
        ctx.actorUserId,
      ]);

      const allowedSimulation = await service.simulatePolicy(ctx, created.id, {
        action: 'sign_transaction',
        chain: 'eip155:1',
        amountMinor: 1,
      });
      expect(allowedSimulation?.decision).toBe('ALLOW');

      const deniedSimulation = await service.simulatePolicy(ctx, created.id, {
        action: 'sign_transaction',
        chain: 'eip155:84532',
        amountMinor: 1,
      });
      expect(deniedSimulation?.decision).toBe('DENY');
      expect(deniedSimulation?.denyReasons.map((reason) => reason.code)).toContain(
        'CHAIN_NOT_ALLOWED',
      );

      const envAssignment = await service.upsertAssignment(ctx, {
        scopeType: 'ENVIRONMENT',
        scopeId: 'env-d1-policy',
        policyId: created.id,
      });
      const resolved = await service.resolvePoliciesForWallets(ctx, [
        {
          walletId: 'wallet-d1-env',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
        },
        {
          walletId: 'wallet-d1-project',
          projectId: 'project-d1-policy',
        },
        {
          walletId: 'wallet-d1-default',
        },
      ]);
      expect(resolved).toEqual({
        'wallet-d1-env': created.id,
        'wallet-d1-project': created.id,
        'wallet-d1-default': defaultPolicy.id,
      });

      const removedAssignment = await service.deleteAssignment(ctx, envAssignment.id);
      expect(removedAssignment.removed).toBe(true);
      const resolvedAfterDelete = await service.resolvePoliciesForWallets(ctx, [
        {
          walletId: 'wallet-d1-env',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
        },
      ]);
      expect(resolvedAfterDelete['wallet-d1-env']).toBe(created.id);

      const gasPolicy = await service.createPolicy(ctx, {
        kind: 'GAS_SPONSORSHIP',
        name: 'D1 Gas Policy',
        rules: {
          kind: 'evm_call',
          scopeType: 'ENVIRONMENT',
          projectId: 'project-d1-policy',
          environmentId: 'env-d1-policy',
          allowedCalls: [
            {
              chainId: 84532,
              to: '0x1111111111111111111111111111111111111111',
              functionSignature: 'mint(address)',
              maxGasLimit: '100000',
              maxValueWei: '0',
            },
          ],
        },
      });

      let gasAssignmentError: unknown = null;
      try {
        await service.upsertAssignment(ctx, {
          scopeType: 'WALLET',
          scopeId: 'wallet-d1-gas',
          policyId: gasPolicy.id,
        });
      } catch (error: unknown) {
        gasAssignmentError = error;
      }
      expect(errorCode(gasAssignmentError)).toBe('policy_assignment_unsupported');

      const otherCtx = {
        orgId: 'org-d1-policies-other',
        actorUserId: 'user-d1-policies-other',
        roles: ['admin'],
      };
      await expect(service.getPolicy(otherCtx, created.id)).resolves.toBeNull();
      const otherPolicies = await service.listPolicies(otherCtx);
      expect(otherPolicies).toHaveLength(1);
      expect(otherPolicies[0].id).not.toBe(defaultPolicy.id);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('billing reservations are trigger-atomic and idempotent', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
        defaultReservationTtlMs: 60_000,
      });
      const ctx = {
        orgId: 'org-d1-billing',
        actorUserId: 'user-d1-billing',
        roles: ['admin'],
      };

      const first = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 300,
      });
      expect(first.summary.reservedMinor).toBe(300);
      expect(first.summary.activeReservationCount).toBe(1);

      const duplicate = await service.reserve(ctx, {
        sourceEventId: 'reservation-source-1',
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: 500,
        estimatedSpendMinor: 450,
      });
      expect(duplicate.reservation.id).toBe(first.reservation.id);
      expect(duplicate.summary.reservedMinor).toBe(300);
      expect(duplicate.summary.activeReservationCount).toBe(1);

      let insufficientError: unknown = null;
      try {
        await service.reserve(ctx, {
          sourceEventId: 'reservation-source-2',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          postedBalanceMinor: 500,
          estimatedSpendMinor: 250,
        });
      } catch (error: unknown) {
        insufficientError = error;
      }
      expect(errorCode(insufficientError)).toBe('prepaid_balance_insufficient');
      expect(await service.getReservationBySourceEventId(ctx, 'reservation-source-2')).toBeNull();

      const summaryAfterFailure = await service.getSummary(ctx);
      expect(summaryAfterFailure.reservedMinor).toBe(300);
      expect(summaryAfterFailure.activeReservationCount).toBe(1);

      const settled = await service.settle(ctx, {
        sourceEventId: 'reservation-source-1',
        settledSpendMinor: 175,
        txOrExecutionRef: '0xsettled',
        pricingVersion: 'static:v1',
      });
      expect(settled?.reservation.status).toBe('SETTLED');
      expect(settled?.reservation.settledMinor).toBe(175);
      expect(settled?.reservation.releasedMinor).toBe(125);
      expect(settled?.summary.reservedMinor).toBe(0);
      expect(settled?.summary.activeReservationCount).toBe(0);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('billing credit purchases settle through D1 Stripe webhook idempotency', async () => {
    const temp = createTemporaryD1Database();
    try {
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId: 'org-d1-billing-purchase',
        actorUserId: 'user-d1-billing-purchase',
        roles: ['admin'],
      };

      const checkout = await billing.createStripeCheckoutSession(ctx, {
        creditPackId: 'usd_10',
        successUrl: 'https://example.test/success',
        cancelUrl: 'https://example.test/cancel',
      });
      expect(checkout.amountMinor).toBe(1000);
      expect(checkout.id).toMatch(/^cs_/);

      const settled = await billing.reconcileStripeCheckoutSession(ctx, {
        checkoutSessionId: checkout.id,
      });
      expect(settled.settled).toBe(true);
      expect(settled.settledNow).toBe(true);
      expect(settled.purchase).toMatchObject({
        status: 'SETTLED',
        amountMinor: 1000,
        providerCheckoutSessionRef: checkout.id,
      });
      expect(settled.invoice).toMatchObject({
        documentType: 'PURCHASE_RECEIPT',
        status: 'PAID',
        amountDueMinor: 1000,
        amountPaidMinor: 1000,
      });

      const lineItems = await billing.listInvoiceLineItems(ctx, settled.invoice?.id || '');
      expect(lineItems).toEqual([
        expect.objectContaining({
          itemType: 'CREDIT_TOP_UP',
          quantity: 1,
          unitAmountMinor: 1000,
          amountMinor: 1000,
        }),
      ]);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 1000,
        recentCreditPurchasedMinor: 1000,
      });

      const duplicateReconcile = await billing.reconcileStripeCheckoutSession(ctx, {
        checkoutSessionId: checkout.id,
      });
      expect(duplicateReconcile.settled).toBe(true);
      expect(duplicateReconcile.settledNow).toBe(false);

      const duplicateWebhook = await billing.processStripeWebhookEvent({
        eventId: `stripe_checkout_reconcile:${checkout.id}`,
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId: checkout.id,
        providerCustomerRef: checkout.customerRef,
      });
      expect(duplicateWebhook.accepted).toBe(false);
      expect(duplicateWebhook.purchase?.id).toBe(settled.purchase?.id);

      const freshWebhook = await billing.processStripeWebhookEvent({
        eventId: 'evt_d1_purchase_second_delivery',
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId: checkout.id,
        providerCustomerRef: checkout.customerRef,
      });
      expect(freshWebhook.accepted).toBe(true);
      expect(freshWebhook.purchase?.id).toBe(settled.purchase?.id);

      const creditActivity = await billing.listAccountActivity(ctx, {
        eventType: 'CREDIT_PURCHASE',
        limit: 10,
      });
      expect(creditActivity.entries).toHaveLength(1);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 1000,
      });

      const invoices = await billing.listInvoicesPage(ctx, {
        documentType: 'PURCHASE_RECEIPT',
        limit: 10,
      });
      expect(invoices.totalCount).toBe(1);
      expect(invoices.summary.receiptCount).toBe(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored gas settlement writes reservation, billing, and call record in one D1 batch', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const billing = await createD1ConsoleBillingService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const prepaidReservations = await createD1ConsoleBillingPrepaidReservationService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
        defaultReservationTtlMs: 60_000,
      });
      const sponsoredCalls = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: fixedD1AtomicBillingNow,
      });
      const ctx = {
        orgId: 'org-d1-atomic-sponsored',
        actorUserId: 'user-d1-atomic-sponsored',
        roles: ['platform_admin'],
      };
      const reservationSourceEventId = 'prepaid-reservation-d1-atomic';

      await billing.grantManualSupportCredit(ctx, {
        amountMinor: 1000,
        reasonCode: 'test_credit',
        note: 'Seed prepaid balance for D1 sponsored settlement',
        idempotencyKey: 'manual-credit-d1-atomic',
      });
      const overviewBeforeReservation = await billing.getOverview(ctx);
      expect(overviewBeforeReservation.creditBalanceMinor).toBe(1000);

      const reserved = await prepaidReservations.reserve(ctx, {
        sourceEventId: reservationSourceEventId,
        environmentId: 'env-production',
        policyId: 'policy-sponsored-gas',
        postedBalanceMinor: overviewBeforeReservation.creditBalanceMinor,
        estimatedSpendMinor: 700,
      });
      const pricing = new StaticSponsoredSpendPricingService(700, 425);
      const builder = new AtomicD1SponsoredRecordBuilder('sponsored-call-d1-atomic');
      const assessment = createD1AtomicAssessment();
      const record = await recordSponsoredExecution({
        billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: ctx,
        ledger: sponsoredCalls,
        buildRecord: builder.build.bind(builder),
        assessment,
        walletId: 'wallet-d1-atomic',
        prepaidSettlementInput: {
          reservation: {
            sourceEventId: reservationSourceEventId,
            estimatedSpendMinor: 700,
            estimatedPricingVersion: 'static:estimate',
          },
          prepaidReservations,
          pricing,
          ctx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: 'evm_eoa',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          accountRef: '0x1111111111111111111111111111111111111111',
          targetRef: '0x2222222222222222222222222222222222222222',
          chainId: 84532,
          txOrExecutionRef: assessment.txOrExecutionRef,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: {
            kind: 'd1-atomic-sponsored-settlement',
          },
        },
      });

      expect(record.charged).toBe(true);
      expect(record.settledSpendMinor).toBe(425);
      expect(record.billingLedgerEntryId).toMatch(/^ble_scr_/);
      expect(record.prepaidReservationId).toBe(reserved.reservation.id);

      const settledReservation = await prepaidReservations.getReservationBySourceEventId(
        ctx,
        reservationSourceEventId,
      );
      expect(settledReservation?.status).toBe('SETTLED');
      expect(settledReservation?.settledMinor).toBe(425);
      expect(settledReservation?.releasedMinor).toBe(275);

      const summary = await prepaidReservations.getSummary(ctx);
      expect(summary.reservedMinor).toBe(0);
      expect(summary.activeReservationCount).toBe(0);

      const debits = await billing.getSponsoredExecutionDebitsByIds(ctx, [
        record.billingLedgerEntryId || '',
      ]);
      expect(debits).toHaveLength(1);
      expect(debits[0]).toMatchObject({
        amountMinor: -425,
        sourceEventId: `sponsored_evm_call_debit:${reservationSourceEventId}`,
      });
      const overviewAfterSettlement = await billing.getOverview(ctx);
      expect(overviewAfterSettlement.creditBalanceMinor).toBe(575);

      const duplicate = await recordSponsoredExecution({
        billing,
        billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
        context: ctx,
        ledger: sponsoredCalls,
        buildRecord: builder.build.bind(builder),
        assessment,
        walletId: 'wallet-d1-atomic',
        prepaidSettlementInput: {
          reservation: {
            sourceEventId: reservationSourceEventId,
            estimatedSpendMinor: 700,
            estimatedPricingVersion: 'static:estimate',
          },
          prepaidReservations,
          pricing,
          ctx,
          chainFamily: 'evm',
          intentKind: 'evm_call',
          executorKind: 'evm_eoa',
          environmentId: 'env-production',
          policyId: 'policy-sponsored-gas',
          accountRef: '0x1111111111111111111111111111111111111111',
          targetRef: '0x2222222222222222222222222222222222222222',
          chainId: 84532,
          txOrExecutionRef: assessment.txOrExecutionRef,
          receiptStatus: assessment.receiptStatus,
          feeUnit: assessment.feeUnit,
          feeAmount: assessment.feeAmount,
          requestDetails: {
            kind: 'd1-atomic-sponsored-settlement',
          },
        },
      });
      expect(duplicate.id).toBe(record.id);

      const sponsoredDebitActivity = await billing.listAccountActivity(ctx, {
        eventType: 'SPONSORED_EXECUTION_DEBIT',
        limit: 10,
      });
      expect(sponsoredDebitActivity.entries).toHaveLength(1);
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 575,
      });

      const conflictingBuilder = new AtomicD1SponsoredRecordBuilder(
        'sponsored-call-d1-atomic-conflict',
      );
      let duplicateReservationError: unknown = null;
      try {
        await recordSponsoredExecution({
          billing,
          billingSourceEventIdPrefix: 'sponsored_evm_call_debit',
          context: ctx,
          ledger: sponsoredCalls,
          buildRecord: conflictingBuilder.build.bind(conflictingBuilder),
          assessment,
          walletId: 'wallet-d1-atomic',
          prepaidSettlementInput: {
            reservation: {
              sourceEventId: reservationSourceEventId,
              estimatedSpendMinor: 700,
              estimatedPricingVersion: 'static:estimate',
            },
            prepaidReservations,
            pricing,
            ctx,
            chainFamily: 'evm',
            intentKind: 'evm_call',
            executorKind: 'evm_eoa',
            environmentId: 'env-production',
            policyId: 'policy-sponsored-gas',
            accountRef: '0x1111111111111111111111111111111111111111',
            targetRef: '0x2222222222222222222222222222222222222222',
            chainId: 84532,
            txOrExecutionRef: assessment.txOrExecutionRef,
            receiptStatus: assessment.receiptStatus,
            feeUnit: assessment.feeUnit,
            feeAmount: assessment.feeAmount,
            requestDetails: {
              kind: 'd1-atomic-sponsored-settlement',
            },
          },
        });
      } catch (error: unknown) {
        duplicateReservationError = error;
      }
      expect(String(duplicateReservationError)).toContain('UNIQUE constraint failed');
      await expect(billing.getOverview(ctx)).resolves.toMatchObject({
        creditBalanceMinor: 575,
      });
      const recordsPage = await sponsoredCalls.listRecords(ctx, { limit: 10, lookbackDays: 1 });
      expect(recordsPage.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('sponsored call idempotency returns the original record', async () => {
    const temp = createTemporaryD1Database();
    try {
      const service = await createD1ConsoleSponsoredCallService({
        database: temp.database,
        namespace: 'd1-contracts',
        ensureSchema: true,
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      });
      const ctx = {
        orgId: 'org-d1-sponsored',
        actorUserId: 'user-d1-sponsored',
        roles: ['admin'],
      };
      const request = {
        environmentId: 'env-production',
        apiKeyId: 'api-key-1',
        apiKeyKind: 'secret_key' as const,
        route: 'sponsored_evm_call_v1',
        policyId: 'policy-sponsored-gas',
        chainFamily: 'evm' as const,
        intentKind: 'evm_call' as const,
        executorKind: 'evm_eoa' as const,
        accountRef: '0x1111111111111111111111111111111111111111',
        targetRef: '0x2222222222222222222222222222222222222222',
        sponsorRef: '0x3333333333333333333333333333333333333333',
        receiptStatus: 'success' as const,
        feeUnit: 'wei' as const,
        feeAmount: '1000000000000000',
        detailsJson: '{"kind":"contract-test"}',
        estimatedSpendMinor: 100,
        settledSpendMinor: 75,
        pricingVersion: 'static:v1',
        pricingSource: 'contract-test',
        billingLedgerEntryId: 'ledger-entry-1',
        prepaidReservationId: 'reservation-1',
        charged: true,
        chargedReason: 'sponsored_gas',
        settledAt: '2026-06-27T00:00:01.000Z',
        idempotencyKey: 'sponsored-idempotency-1',
      };

      const first = await service.createRecord(ctx, request);
      const duplicate = await service.createRecord(ctx, {
        ...request,
        id: 'different-record-id',
        feeAmount: '9999999999999999',
      });
      const page = await service.listRecords(ctx, { limit: 10, lookbackDays: 1 });

      expect(duplicate.id).toBe(first.id);
      expect(duplicate.feeAmount).toBe(first.feeAmount);
      expect(page.items).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('signer sealed shares are scoped by tenant, project, and environment', async () => {
    const temp = createTemporaryD1Database();
    try {
      const sharedOptions = {
        database: temp.database,
        namespace: 'd1-contracts',
        orgId: 'org-d1-signer',
        projectId: 'project-d1-signer',
        envelopeVersion: 'd1-secret-share-v1',
        lastAuditEventId: 'audit-event-1',
        now: () => new Date('2026-06-27T00:00:00.000Z'),
      };
      const productionStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-production',
      });
      const developmentStore = new D1SigningRootSecretStore({
        ...sharedOptions,
        envId: 'env-development',
      });

      await productionStore.putSealedSigningRootSecretShare({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
        shareId: 1,
        sealedShare: new Uint8Array([1, 2, 3, 4]),
        storageId: 'r2://shares/signing-root-1/share-1',
        kekId: 'kek-production-1',
      });

      const productionShares = await productionStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });
      const developmentShares = await developmentStore.listSealedSigningRootSecretShares({
        signingRootId: 'signing-root-1',
        signingRootVersion: 'version-1',
      });

      expect(productionShares).toHaveLength(1);
      expect(productionShares[0]?.kekId).toBe('kek-production-1');
      expect(Array.from(productionShares[0]?.sealedShare || [])).toEqual([1, 2, 3, 4]);
      expect(developmentShares).toHaveLength(0);

      let missingKekError: unknown = null;
      try {
        await productionStore.putSealedSigningRootSecretShare({
          signingRootId: 'signing-root-1',
          signingRootVersion: 'version-1',
          shareId: 2,
          sealedShare: new Uint8Array([5, 6, 7, 8]),
        });
      } catch (error: unknown) {
        missingKekError = error;
      }
      expect(String(missingKekError)).toContain(
        'kekId is required for D1 signing-root secret shares',
      );
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });

  test('runtime snapshot outbox claim lease prevents duplicate dispatch', async () => {
    const temp = createTemporaryD1Database();
    try {
      const namespace = 'd1-contracts';
      const orgId = 'org-d1-runtime-snapshot';
      const nowMs = Date.parse('2026-06-27T00:00:00.000Z');
      const harness = new RuntimeSnapshotOutboxRaceHarness(
        temp.database,
        namespace,
        orgId,
        nowMs,
      );
      const service = await createD1ConsoleRuntimeSnapshotService({
        database: temp.database,
        namespace,
        ensureSchema: true,
        now: harness.now.bind(harness),
        retentionTtlMs: 1000 * 60 * 60,
      });
      const ctx = {
        orgId,
        actorUserId: 'user-d1-runtime-snapshot',
        roles: ['admin'],
      };

      await service.publishSnapshot(ctx, {
        snapshotId: 'snapshot-race-1',
        projectId: 'project-runtime',
        environmentId: 'env-production',
        payload: {
          policy: { id: 'policy-runtime' },
          gasSponsorship: { enabled: true },
          metadata: { source: 'd1-contract-test' },
        },
      });

      const primaryResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-a',
        claimTtlMs: 60_000,
        dispatch: harness.dispatch.bind(harness),
      });
      const afterDispatchResult = await runD1ConsoleRuntimeSnapshotOutboxDispatch({
        database: temp.database,
        namespace,
        orgIds: [orgId],
        limit: 1,
        ensureSchema: false,
        now: harness.now.bind(harness),
        workerId: 'snapshot-race-worker-c',
        claimTtlMs: 60_000,
        dispatch: harness.competitorDispatch.bind(harness),
      });

      expect(primaryResult.dispatchedCount).toBe(1);
      expect(primaryResult.failureCount).toBe(0);
      expect(harness.competitorResult?.dispatchedCount).toBe(0);
      expect(harness.competitorResult?.failureCount).toBe(0);
      expect(afterDispatchResult.dispatchedCount).toBe(0);
      expect(harness.dispatchedEventIds).toHaveLength(1);
    } finally {
      cleanupTemporaryD1Database(temp.tempDir);
    }
  });
});
