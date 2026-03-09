import express, { Express } from 'express';
import { Pool } from 'pg';
import {
  AuthService,
  createInMemoryConsoleSponsoredCallService,
  createPostgresConsoleSponsoredCallService,
  createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship,
  createEcdsaAuthSessionStore,
  createPrfSessionSealPolicyFromEcdsaAuthSessionStore,
  createPrfSessionSealRoutesOptions,
  createPrfSessionSealShamir3PassCipherAdapter,
  DEFAULT_TEMPO_DRIP_GAS_LIMIT,
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  ensureTempoOnboardingSponsorshipForExistingEnvironments,
  resolvePrfSessionSealIdempotencyFromEnv,
  resolvePrfSessionSealRateLimitFromEnv,
  resolveSponsoredEvmCallConfigFromEnv,
  requireEnvVar,
  createThresholdSigningService,
  type ConsoleSponsoredCallService,
} from '@tatchi-xyz/sdk/server';
import {
  createConsoleRouter,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleAuditService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleGasSponsorshipService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleObservabilityService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleApprovalService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleApprovalService,
  createPostgresConsoleApiKeyService,
  createPostgresConsoleAuditService,
  createPostgresConsoleBillingService,
  createPostgresConsoleBootstrapTokenService,
  createPostgresConsoleGasSponsorshipService,
  createPostgresConsoleObservabilityIngestionService,
  createPostgresConsoleObservabilityService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsolePolicyService,
  createPostgresConsoleRuntimeSnapshotService,
  createPostgresConsoleTeamRbacService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  createRelayApiKeyAuthAdapter,
  createRelayBillingUsageMeterAdapter,
  createRelayBootstrapGrantBroker,
  createAppSessionConsoleAuthAdapter,
  normalizeConsoleOrgScopedRoleList,
  mergeConsoleOrgScopedRoleLists,
  createRelayRouter,
  type ConsoleApiKeyService,
  type ConsoleBillingService,
  type ConsoleAuditService,
  type ConsoleBootstrapTokenService,
  type ConsoleGasSponsorshipService,
  type ConsoleApprovalService,
  type ConsoleObservabilityIngestionService,
  type ConsoleObservabilityService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicyService,
  type ConsoleRuntimeSnapshotService,
  type ConsoleTeamRbacService,
  type ConsoleWallet,
  type ConsoleWalletService,
  type ConsoleWebhookService,
  type BillingProviderAdapters,
  type InviteConsoleTeamMemberRequest,
} from '@tatchi-xyz/sdk/server/router/express';

import dotenv from 'dotenv';
import { createJwtSession } from './jwtSession.js';
import { resolveRelayServerConsoleConfig, toOptionalSecret } from './consoleConfig.js';
import { createStripeBillingProviderAdapter } from './stripeBillingProvider.js';

dotenv.config();

let server: ReturnType<Express['listen']> | null = null;

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  if (!server) {
    process.exit(0);
  }
  server.close(() => {
    console.log('[shutdown] http server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('[shutdown] force exit after 10s');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

function hostnameFromOrigin(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function sanitizeOrigins(values: string[]): string[] {
  const out = new Set<string>();
  for (const raw of values) {
    try {
      const u = new URL(String(raw || '').trim());
      const scheme = u.protocol;
      const host = u.hostname.toLowerCase();
      if (!host) continue;
      if (scheme !== 'https:' && !(scheme === 'http:' && host === 'localhost')) continue;
      if ((u.pathname && u.pathname !== '/') || u.search || u.hash) continue;
      const port = u.port ? `:${u.port}` : '';
      out.add(`${scheme}//${host}${port}`);
    } catch {}
  }
  return Array.from(out);
}

function parseOptionalPositiveInteger(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const integer = Math.floor(parsed);
  return integer > 0 ? integer : undefined;
}

function parseCsvValues(value: unknown): string[] {
  return String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseBooleanFlag(value: unknown): boolean {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function parseBooleanFlagWithDefault(value: unknown, fallback: boolean): boolean {
  const normalized = String(value || '').trim();
  if (!normalized) return fallback;
  return parseBooleanFlag(normalized);
}

function parsePrfSealLimiterKind(value: unknown): 'in-memory' | 'upstash-redis-rest' | 'redis-tcp' {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (normalized === 'upstash-redis-rest') return 'upstash-redis-rest';
  if (normalized === 'redis-tcp') return 'redis-tcp';
  return 'in-memory';
}

function hasConsoleErrorCode(error: unknown, code: string): boolean {
  if (!error || typeof error !== 'object') return false;
  return String((error as { code?: unknown }).code || '').trim() === code;
}

async function seedDemoConsoleOrgAndMembers(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  orgId: string;
  projectId: string;
  environmentId: string;
  logger: Pick<Console, 'log' | 'warn'>;
}): Promise<void> {
  const seedCtx = {
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    roles: ['owner', 'admin'],
    projectId: input.projectId,
    environmentId: input.environmentId,
  };

  // Seed must create the org explicitly on fresh databases.
  await input.orgProjectEnv.upsertOrganization(seedCtx, {});

  try {
    await input.orgProjectEnv.createProject(seedCtx, {
      id: input.projectId,
      name: 'Console Core',
    });
  } catch (error: unknown) {
    if (!hasConsoleErrorCode(error, 'project_already_exists')) throw error;
  }

  for (const environment of [
    { id: `${input.projectId}-dev`, key: 'dev' as const, name: 'Development' },
    { id: `${input.projectId}-staging`, key: 'staging' as const, name: 'Staging' },
    { id: input.environmentId, key: 'prod' as const, name: 'Production' },
  ]) {
    try {
      await input.orgProjectEnv.createEnvironment(seedCtx, {
        id: environment.id,
        projectId: input.projectId,
        key: environment.key,
        name: environment.name,
      });
    } catch (error: unknown) {
      if (
        !hasConsoleErrorCode(error, 'environment_already_exists') &&
        !hasConsoleErrorCode(error, 'environment_key_conflict')
      ) {
        throw error;
      }
    }

  }

  const seedMembers: InviteConsoleTeamMemberRequest[] = [
    {
      userId: 'console-owner',
      email: 'owner@demo.tatchi.local',
      displayName: 'Console Owner',
      roles: [
        { role: 'owner', scope: 'ORG' as const },
        { role: 'admin', scope: 'ORG' as const },
        { role: 'admin_manage_admins', scope: 'ORG' as const },
        { role: 'admin_manage_members', scope: 'ORG' as const },
        { role: 'overview_write', scope: 'ORG' as const },
        { role: 'administration_write', scope: 'ORG' as const },
        { role: 'wallet_operations_write', scope: 'ORG' as const },
        { role: 'integrations_write', scope: 'ORG' as const },
        { role: 'billing_write', scope: 'ORG' as const },
      ],
    },
    {
      userId: 'console-admin',
      email: 'admin@demo.tatchi.local',
      displayName: 'Console Admin',
      roles: [
        { role: 'admin', scope: 'ORG' as const },
        { role: 'admin_manage_members', scope: 'ORG' as const },
        { role: 'overview_write', scope: 'ORG' as const },
        { role: 'administration_write', scope: 'ORG' as const },
        { role: 'wallet_operations_write', scope: 'ORG' as const },
        { role: 'integrations_write', scope: 'ORG' as const },
        { role: 'billing_read', scope: 'ORG' as const },
      ],
    },
    {
      userId: 'console-operator',
      email: 'operator@demo.tatchi.local',
      displayName: 'Console Operator',
      roles: [
        { role: 'overview_read', scope: 'ORG' as const },
        { role: 'wallet_operations_read', scope: 'ORG' as const },
        { role: 'integrations_read', scope: 'ORG' as const },
      ],
    },
  ];

  for (const member of seedMembers) {
    try {
      await input.teamRbac.inviteMember(seedCtx, member);
    } catch (error: unknown) {
      if (!hasConsoleErrorCode(error, 'member_already_exists')) throw error;
    }
  }

  const deprecatedSeedEmails = new Set<string>([
    'security@demo.tatchi.local',
    'billing@demo.tatchi.local',
    'devops@demo.tatchi.local',
  ]);
  try {
    const existingMembers = await input.teamRbac.listMembers(seedCtx, {});
    for (const member of existingMembers) {
      const email = String(member.email || '')
        .trim()
        .toLowerCase();
      if (!deprecatedSeedEmails.has(email)) continue;
      if (member.status === 'REMOVED') continue;
      try {
        await input.teamRbac.removeMember(seedCtx, member.id);
      } catch (error: unknown) {
        input.logger.warn(
          `[console-demo-seed] failed to remove deprecated seed member ${member.userId}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }
  } catch (error: unknown) {
    input.logger.warn(
      `[console-demo-seed] failed to sweep deprecated members: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  input.logger.log(
    `[console-demo-seed] org=${input.orgId} project=${input.projectId} environment=${input.environmentId} members=${seedMembers.length}`,
  );
}

function makeDemoWalletAddress(seed: string): `0x${string}` {
  const normalized = String(seed || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]/g, '');
  let hex = '';
  for (const char of normalized) {
    hex += char.charCodeAt(0).toString(16).padStart(2, '0');
  }
  return `0x${(hex + '0'.repeat(40)).slice(0, 40)}` as `0x${string}`;
}

function makeDemoConsoleWallet(input: {
  id: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  chain: ConsoleWallet['chain'];
  walletType?: ConsoleWallet['walletType'];
  status?: ConsoleWallet['status'];
  policyId?: string | null;
  balanceMinor?: number;
  lastActivityAt?: string | null;
}): ConsoleWallet {
  const nowIso = new Date().toISOString();
  return {
    id: input.id,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    userId: `user_${input.id}`,
    externalRefId: `ext_${input.id}`,
    address: makeDemoWalletAddress(input.id),
    chain: input.chain,
    walletType: input.walletType || 'EOA',
    status: input.status || 'ACTIVE',
    policyId: input.policyId === undefined ? null : input.policyId,
    balanceMinor: input.balanceMinor === undefined ? 0 : input.balanceMinor,
    lastActivityAt: input.lastActivityAt === undefined ? nowIso : input.lastActivityAt,
    createdAt: nowIso,
    updatedAt: nowIso,
  };
}

function buildDemoConsoleWalletSeeds(input: {
  orgId: string;
  projectId: string;
  environmentId: string;
}): ConsoleWallet[] {
  const stagingEnvironmentId = `${input.projectId}-staging`;
  const developmentEnvironmentId = `${input.projectId}-dev`;
  return [
    makeDemoConsoleWallet({
      id: 'wallet_console_core_prod_eth_1',
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      chain: 'Ethereum',
      balanceMinor: 425_000,
    }),
    makeDemoConsoleWallet({
      id: 'wallet_console_core_prod_base_1',
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      chain: 'Base',
      balanceMinor: 310_000,
    }),
    makeDemoConsoleWallet({
      id: 'wallet_console_core_prod_near_1',
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      chain: 'NEAR',
      walletType: 'SMART',
      balanceMinor: 155_000,
    }),
    makeDemoConsoleWallet({
      id: 'wallet_console_core_staging_tempo_1',
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: stagingEnvironmentId,
      chain: 'Tempo',
      balanceMinor: 92_500,
    }),
    makeDemoConsoleWallet({
      id: 'wallet_console_core_dev_arc_1',
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: developmentEnvironmentId,
      chain: 'Arc Circle',
      status: 'ARCHIVED',
      balanceMinor: 0,
      lastActivityAt: null,
    }),
  ];
}

async function seedDemoConsoleWalletsInPostgres(input: {
  postgresUrl: string;
  namespace: string;
  wallets: ConsoleWallet[];
  logger: Pick<Console, 'log'>;
}): Promise<void> {
  const pool = new Pool({ connectionString: input.postgresUrl });
  try {
    for (const wallet of input.wallets) {
      await pool.query(
        `
          INSERT INTO console_wallet_index (
            namespace,
            id,
            org_id,
            project_id,
            environment_id,
            user_id,
            external_ref_id,
            address,
            chain,
            wallet_type,
            status,
            policy_id,
            balance_minor,
            last_activity_at_ms,
            created_at_ms,
            updated_at_ms
          )
          VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
          )
          ON CONFLICT (namespace, id) DO NOTHING
        `,
        [
          input.namespace,
          wallet.id,
          wallet.orgId,
          wallet.projectId,
          wallet.environmentId,
          wallet.userId,
          wallet.externalRefId,
          wallet.address,
          wallet.chain,
          wallet.walletType,
          wallet.status,
          wallet.policyId,
          wallet.balanceMinor,
          wallet.lastActivityAt ? Date.parse(wallet.lastActivityAt) : null,
          Date.parse(wallet.createdAt),
          Date.parse(wallet.updatedAt),
        ],
      );
    }
  } finally {
    await pool.end();
  }

  input.logger.log(
    `[console-demo-seed] wallets=${input.wallets.length} namespace=${input.namespace} storage=postgres`,
  );
}

async function ensureDemoPolicyExists(input: {
  policies: ConsolePolicyService;
  orgId: string;
  actorUserId: string;
  id: string;
  name: string;
  description?: string;
  rules?: Record<string, unknown>;
  publish?: boolean;
}): Promise<void> {
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: ['owner', 'admin'],
  };
  try {
    await input.policies.createPolicy(ctx, {
      id: input.id,
      name: input.name,
      ...(input.description ? { description: input.description } : {}),
      ...(input.rules ? { rules: input.rules } : {}),
    });
    if (input.publish) {
      await input.policies.publishPolicy(ctx, input.id);
    }
  } catch (error: unknown) {
    if (!hasConsoleErrorCode(error, 'policy_already_exists')) throw error;
  }
}

async function ensureDemoAssignmentExists(input: {
  policies: ConsolePolicyService;
  orgId: string;
  actorUserId: string;
  scopeType: 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
  scopeId: string;
  policyId: string;
}): Promise<void> {
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: ['owner', 'admin'],
  };
  const existing = await input.policies.listAssignments(ctx, {
    scopeType: input.scopeType,
    scopeId: input.scopeId,
  });
  if (existing.length > 0) return;
  await input.policies.upsertAssignment(ctx, {
    scopeType: input.scopeType,
    scopeId: input.scopeId,
    policyId: input.policyId,
  });
}

async function ensureDemoApprovalRequest(input: {
  approvals: ConsoleApprovalService;
  orgId: string;
  projectId: string;
  environmentId: string;
  id: string;
  reason: string;
  resourceType: string;
  resourceId: string;
  approved?: boolean;
}): Promise<void> {
  const requesterCtx = {
    orgId: input.orgId,
    actorUserId: 'console-admin',
    roles: ['owner', 'admin'],
    projectId: input.projectId,
    environmentId: input.environmentId,
  };
  const approverCtx = {
    orgId: input.orgId,
    actorUserId: 'console-owner',
    roles: ['owner', 'admin'],
    projectId: input.projectId,
    environmentId: input.environmentId,
  };

  let approval = await input.approvals.getApprovalRequest(requesterCtx, input.id);
  if (!approval) {
    approval = await input.approvals.createApprovalRequest(requesterCtx, {
      id: input.id,
      operationType: 'POLICY_PUBLISH',
      reason: input.reason,
      projectId: input.projectId,
      environmentId: input.environmentId,
      resourceType: input.resourceType,
      resourceId: input.resourceId,
      metadata: {
        seededBy: 'console-demo-seed',
      },
    });
  }

  if (input.approved && approval.status === 'PENDING') {
    try {
      await input.approvals.approveApprovalRequest(approverCtx, input.id, {
        reason: 'Approved by console demo seed',
        mfaVerified: false,
      });
    } catch (error: unknown) {
      if (!hasConsoleErrorCode(error, 'already_decided')) throw error;
    }
  }
}

async function seedDemoConsolePoliciesAndApprovals(input: {
  policies: ConsolePolicyService;
  approvals: ConsoleApprovalService;
  orgId: string;
  projectId: string;
  environmentId: string;
  walletIds: string[];
  logger: Pick<Console, 'log'>;
}): Promise<void> {
  const walletOverrideId = input.walletIds[0];
  await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    id: 'policy_console_project_default',
    name: 'Project signing policy',
    description: 'Default project guardrails for managed signing wallets.',
    rules: {
      allowedChains: ['Ethereum', 'Base', 'NEAR'],
      blockedActions: ['export_key'],
      maxAmountMinor: 250_000,
    },
    publish: true,
  });
  await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    id: 'policy_console_environment_prod',
    name: 'Production environment policy',
    description: 'Tighter production limits for the active environment.',
    rules: {
      allowedChains: ['Base', 'NEAR'],
      blockedActions: ['export_key'],
      maxAmountMinor: 125_000,
    },
    publish: true,
  });
  await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    id: 'policy_console_wallet_override',
    name: 'Wallet override policy',
    description: 'Single-wallet override for sensitive NEAR activity.',
    rules: {
      allowedChains: ['NEAR'],
      blockedActions: ['export_key', 'transfer'],
      maxAmountMinor: 50_000,
    },
    publish: true,
  });
  await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    id: 'policy_console_publish_candidate',
    name: 'Draft publish candidate',
    description: 'Draft policy intended for approval-backed publish testing.',
    rules: {
      allowedChains: ['Ethereum', 'Base'],
      blockedActions: ['export_key'],
      maxAmountMinor: 80_000,
    },
    publish: false,
  });

  await ensureDemoAssignmentExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    scopeType: 'PROJECT',
    scopeId: input.projectId,
    policyId: 'policy_console_project_default',
  });
  await ensureDemoAssignmentExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    scopeType: 'ENVIRONMENT',
    scopeId: input.environmentId,
    policyId: 'policy_console_environment_prod',
  });
  if (walletOverrideId) {
    await ensureDemoAssignmentExists({
      policies: input.policies,
      orgId: input.orgId,
      actorUserId: 'console-seed-owner',
      scopeType: 'WALLET',
      scopeId: walletOverrideId,
      policyId: 'policy_console_wallet_override',
    });
  }

  await ensureDemoApprovalRequest({
    approvals: input.approvals,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    id: 'apr_policy_publish_pending_demo',
    reason: 'Review the draft publish candidate for production rollout.',
    resourceType: 'policy',
    resourceId: 'policy_console_publish_candidate',
  });
  await ensureDemoApprovalRequest({
    approvals: input.approvals,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    id: 'apr_policy_publish_approved_demo',
    reason: 'Approved seed request for policy publish testing.',
    resourceType: 'policy',
    resourceId: 'policy_console_publish_candidate',
    approved: true,
  });

  input.logger.log(
    `[console-demo-seed] policies=4 approvals=2 project=${input.projectId} environment=${input.environmentId}`,
  );
}

async function main() {
  const env = process.env;
  const sessionCookieName = String(env.SESSION_COOKIE_NAME || 'tatchi-jwt').trim() || 'tatchi-jwt';
  const jwtSession = createJwtSession(sessionCookieName);
  const redisUrl = typeof env.REDIS_URL === 'string' ? env.REDIS_URL.trim() : '';
  const {
    thresholdPostgresUrl,
    consolePostgresUrl,
    consoleBillingBackend,
    consoleBillingEnsureSchema,
    consoleBillingNamespace,
    consoleWebhooksBackend,
    consoleWebhooksEnsureSchema,
    consoleWebhooksNamespace,
    consoleObservabilityBackend,
    consoleObservabilityEnsureSchema,
    consoleObservabilityNamespace,
    consoleObservabilityQueryMaxWindowMs,
    consoleObservabilityIngestMaxBatchSize,
    consoleObservabilityIngestMaxEventsPerMinute,
    consoleObservabilityRetentionTtlMs,
    consoleObservabilityRetentionPruneIntervalMs,
    consoleObservabilityRetentionBatchSize,
    consoleBillingStripeWebhookSecret,
  } = resolveRelayServerConsoleConfig(env as Record<string, unknown>);
  const ed25519MasterSecretB64u =
    typeof env.THRESHOLD_ED25519_MASTER_SECRET_B64U === 'string'
      ? env.THRESHOLD_ED25519_MASTER_SECRET_B64U.trim()
      : '';
  const secp256k1MasterSecretB64u = requireEnvVar(env, 'THRESHOLD_SECP256K1_MASTER_SECRET_B64U');
  const usePostgresForThreshold = Boolean(thresholdPostgresUrl);
  const thresholdRedisUrl = usePostgresForThreshold ? '' : redisUrl;

  if (usePostgresForThreshold && redisUrl) {
    console.warn(
      '[threshold] POSTGRES_URL and REDIS_URL are both set; using Postgres for threshold stores and ignoring REDIS_URL.',
    );
  }

  const host =
    typeof env.HOST === 'string' && env.HOST.trim().length > 0 ? env.HOST.trim() : undefined;
  const config = {
    port: Number(env.PORT || 3000),
    host,
    expectedOrigin: env.EXPECTED_ORIGIN || 'https://localhost', // Frontend origin
    expectedWalletOrigin: env.EXPECTED_WALLET_ORIGIN || 'https://localhost:8443', // Wallet origin (optional)
  };
  const sponsoredEvmCallConfig = resolveSponsoredEvmCallConfigFromEnv(env);
  const tempoOnboardingFaucetContractRaw = String(env.TEMPO_ONBOARDING_FAUCET_CONTRACT || '').trim();
  const rorRpId = String(env.ROR_RP_ID || hostnameFromOrigin(config.expectedWalletOrigin))
    .trim()
    .toLowerCase();
  const rorOrigins = sanitizeOrigins([
    config.expectedOrigin,
    config.expectedWalletOrigin,
    ...String(env.ROR_ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  ]);

  const thresholdEd25519KeyStore = {
    // Share mode + deterministic relayer share derivation (optional)
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    THRESHOLD_ED25519_MASTER_SECRET_B64U: ed25519MasterSecretB64u || undefined,
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: secp256k1MasterSecretB64u,
    // Node role + coordinator/cosigner wiring (optional)
    THRESHOLD_NODE_ROLE: env.THRESHOLD_NODE_ROLE,
    THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    THRESHOLD_COORDINATOR_INSTANCE_ID: env.THRESHOLD_COORDINATOR_INSTANCE_ID,
    THRESHOLD_COORDINATOR_PEERS: env.THRESHOLD_COORDINATOR_PEERS,
    // Optional persistence for sessions/shares
    POSTGRES_URL: thresholdPostgresUrl || undefined,
    UPSTASH_REDIS_REST_URL: env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: env.UPSTASH_REDIS_REST_TOKEN,
    REDIS_URL: thresholdRedisUrl || undefined,
    // Optional key prefixes (useful when sharing a single database)
    THRESHOLD_ED25519_KEYSTORE_PREFIX: env.THRESHOLD_ED25519_KEYSTORE_PREFIX,
    THRESHOLD_ED25519_SESSION_PREFIX: env.THRESHOLD_ED25519_SESSION_PREFIX,
    THRESHOLD_ED25519_AUTH_PREFIX: env.THRESHOLD_ED25519_AUTH_PREFIX,
  } as const;

  const googleClientIds = Array.from(
    new Set<string>([
      ...parseCsvValues(env.GOOGLE_OIDC_CLIENT_IDS),
      ...parseCsvValues(env.GOOGLE_OIDC_CLIENT_ID),
    ]),
  );

  const authService = new AuthService({
    // new accounts with be created with this account: e.g. bob.{relayer-account-id}.near
    relayerAccount: requireEnvVar(env, 'RELAYER_ACCOUNT_ID'),
    relayerPrivateKey: requireEnvVar(env, 'RELAYER_PRIVATE_KEY'),
    // Optional overrides (SDK provides defaults when omitted)
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID,
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    createAccountAndRegisterGas: env.CREATE_ACCOUNT_AND_REGISTER_GAS,
    logger: console,
    thresholdEd25519KeyStore,
    googleOidc: {
      GOOGLE_OIDC_CLIENT_ID: env.GOOGLE_OIDC_CLIENT_ID,
      GOOGLE_OIDC_CLIENT_IDS: env.GOOGLE_OIDC_CLIENT_IDS,
      GOOGLE_OIDC_HOSTED_DOMAINS: env.GOOGLE_OIDC_HOSTED_DOMAINS,
    },
    oidcExchange: googleClientIds.length
      ? {
          issuers: [
            {
              issuer: 'https://accounts.google.com',
              jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
              audiences: googleClientIds,
              subjectPrefix: 'google:',
            },
            {
              issuer: 'accounts.google.com',
              jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
              audiences: googleClientIds,
              subjectPrefix: 'google:',
            },
          ],
        }
      : undefined,
  });

  await authService.initStorage();

  const threshold = createThresholdSigningService({
    authService,
    thresholdEd25519KeyStore,
    logger: console,
  });

  const prfSessionSealEnabled = parseBooleanFlag(env.PRF_SESSION_SEAL_ENABLED);
  const prfSessionSeal = (() => {
    if (!prfSessionSealEnabled) return null;

    const shamirPrimeB64u = requireEnvVar(env, 'SHAMIR_P_B64U');
    const serverEncryptExponentB64u = requireEnvVar(env, 'SHAMIR_E_S_B64U');
    const serverDecryptExponentB64u = requireEnvVar(env, 'SHAMIR_D_S_B64U');
    const keyVersion = String(env.PRF_SESSION_SEAL_KEY_VERSION || 'kek-s-2026-02').trim();
    if (!keyVersion) {
      throw new Error(
        'PRF_SESSION_SEAL_KEY_VERSION must be a non-empty string when PRF_SESSION_SEAL_ENABLED=1',
      );
    }

    const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
      config: thresholdEd25519KeyStore,
      logger: console,
      isNode: true,
    });

    const limiterKind = parsePrfSealLimiterKind(env.PRF_SESSION_SEAL_RATE_LIMIT_KIND);
    const rateLimit = resolvePrfSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl: env.UPSTASH_REDIS_REST_URL,
      upstashToken: env.UPSTASH_REDIS_REST_TOKEN,
      redisUrl: thresholdRedisUrl || redisUrl,
      keyPrefix: String(
        env.PRF_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX || 'threshold:prf-seal:rate:',
      ).trim(),
      limit: parseOptionalPositiveInteger(env.PRF_SESSION_SEAL_RATE_LIMIT) || 30,
      windowMs: parseOptionalPositiveInteger(env.PRF_SESSION_SEAL_RATE_LIMIT_WINDOW_MS) || 60_000,
    });
    const idempotencyKind = String(env.PRF_SESSION_SEAL_IDEMPOTENCY_KIND || '')
      .trim()
      .toLowerCase();
    const idempotency = idempotencyKind
      ? resolvePrfSessionSealIdempotencyFromEnv({
          idempotencyKind,
          upstashUrl:
            env.PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL || env.UPSTASH_REDIS_REST_URL || undefined,
          upstashToken:
            env.PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN ||
            env.UPSTASH_REDIS_REST_TOKEN ||
            undefined,
          redisUrl:
            env.PRF_SESSION_SEAL_IDEMPOTENCY_REDIS_URL ||
            thresholdRedisUrl ||
            redisUrl ||
            undefined,
          postgresUrl:
            env.PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL || thresholdPostgresUrl || undefined,
          postgresNamespace: env.PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE || undefined,
          keyPrefix:
            String(
              env.PRF_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX || 'threshold:prf-seal:idempotency:',
            ).trim() || undefined,
          ttlMs: parseOptionalPositiveInteger(env.PRF_SESSION_SEAL_IDEMPOTENCY_TTL_MS),
        })
      : undefined;

    return createPrfSessionSealRoutesOptions({
      sessionPolicy: createPrfSessionSealPolicyFromEcdsaAuthSessionStore(ecdsaAuthSessionStore),
      cipher: createPrfSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: keyVersion,
        keys: [
          {
            keyVersion,
            shamirPrimeB64u,
            serverEncryptExponentB64u,
            serverDecryptExponentB64u,
          },
        ],
      }),
      capabilities: {
        mode: 'sealed_refresh_v1',
        keyVersion,
        shamirPrimeB64u,
      },
      rateLimit,
      ...(idempotency ? { idempotency } : {}),
      logger: console,
    });
  })();

  const app: Express = express();
  const consoleDemoSeedEnabled = parseBooleanFlagWithDefault(env.CONSOLE_DEMO_SEED_ENABLED, true);
  const consoleDemoOrgId = String(env.CONSOLE_DEMO_ORG_ID || 'org-dev').trim() || 'org-dev';
  const consoleDemoProjectId =
    String(env.CONSOLE_DEMO_PROJECT_ID || 'proj_console_core').trim() || 'proj_console_core';
  const consoleDemoEnvironmentId =
    String(env.CONSOLE_DEMO_ENVIRONMENT_ID || `${consoleDemoProjectId}-prod`).trim() ||
    `${consoleDemoProjectId}-prod`;
  const defaultConsoleRoles = normalizeConsoleOrgScopedRoleList(
    env.CONSOLE_SSO_DEFAULT_ROLES || env.CONSOLE_DEMO_ROLES || 'admin',
  );
  const consoleSsoBootstrapRoles = mergeConsoleOrgScopedRoleLists(
    ['owner', 'admin'],
    defaultConsoleRoles,
  );
  const stripeApiSecretKey = String(env.STRIPE_API_SK || '').trim() || '';
  const stripeApiPublishableKey = String(env.STRIPE_API_PK || '').trim() || '';
  const stripeCheckoutPriceId = String(env.STRIPE_CHECKOUT_PRICE_ID || '').trim() || '';
  const stripeApiBaseUrl = String(env.STRIPE_API_BASE_URL || '').trim() || '';
  const stripeApiTimeoutMs = parseOptionalPositiveInteger(env.STRIPE_API_TIMEOUT_MS);
  const relayApiKeyAuthEnabled = parseBooleanFlagWithDefault(env.RELAY_API_KEY_AUTH_ENABLED, true);
  const stripeProviderOverrides: Partial<BillingProviderAdapters> | undefined = stripeApiSecretKey
    ? {
        stripe: createStripeBillingProviderAdapter({
          secretKey: stripeApiSecretKey,
          ...(stripeCheckoutPriceId ? { defaultCheckoutPriceId: stripeCheckoutPriceId } : {}),
          ...(stripeApiBaseUrl ? { apiBaseUrl: stripeApiBaseUrl } : {}),
          ...(stripeApiTimeoutMs ? { requestTimeoutMs: stripeApiTimeoutMs } : {}),
        }),
      }
    : undefined;
  let consoleBilling: ConsoleBillingService;
  let consoleWebhooks: ConsoleWebhookService;
  let consoleObservability: ConsoleObservabilityService;
  let consoleObservabilityIngestion: ConsoleObservabilityIngestionService | null;
  let consoleAudit: ConsoleAuditService;
  let consoleOrgProjectEnvBase: ConsoleOrgProjectEnvService;
  let consoleOrgProjectEnv: ConsoleOrgProjectEnvService;
  let consoleApiKeys: ConsoleApiKeyService;
  let consoleBootstrapTokens: ConsoleBootstrapTokenService;
  let consoleGasSponsorship: ConsoleGasSponsorshipService;
  let consoleApprovals: ConsoleApprovalService;
  let consolePolicies: ConsolePolicyService;
  let consoleRuntimeSnapshots: ConsoleRuntimeSnapshotService;
  let consoleTeamRbac: ConsoleTeamRbacService;
  let consoleWallets: ConsoleWalletService;
  let consoleSponsoredCalls: ConsoleSponsoredCallService;
  const consoleCoreNamespace = consoleBillingNamespace;
  const demoWalletSeeds = buildDemoConsoleWalletSeeds({
    orgId: consoleDemoOrgId,
    projectId: consoleDemoProjectId,
    environmentId: consoleDemoEnvironmentId,
  });
  if (consoleBillingBackend === 'postgres') {
    if (!consolePostgresUrl) {
      throw new Error('CONSOLE_BILLING_BACKEND=postgres requires CONSOLE_POSTGRES_URL');
    }
    consoleBilling = await createPostgresConsoleBillingService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleBillingNamespace,
      logger: console as any,
      ensureSchema: consoleBillingEnsureSchema,
      ...(stripeProviderOverrides ? { providers: stripeProviderOverrides } : {}),
    });
  } else {
    consoleBilling = createInMemoryConsoleBillingService({
      ...(stripeProviderOverrides ? { providers: stripeProviderOverrides } : {}),
    });
  }

  if (consolePostgresUrl) {
    consoleAudit = await createPostgresConsoleAuditService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleOrgProjectEnvBase = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleApiKeys = await createPostgresConsoleApiKeyService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleBootstrapTokens = await createPostgresConsoleBootstrapTokenService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleGasSponsorship = await createPostgresConsoleGasSponsorshipService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleApprovals = await createPostgresConsoleApprovalService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consolePolicies = await createPostgresConsolePolicyService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleRuntimeSnapshots = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleTeamRbac = await createPostgresConsoleTeamRbacService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleWallets = await createPostgresConsoleWalletService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleSponsoredCalls = await createPostgresConsoleSponsoredCallService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
  } else {
    consoleAudit = createInMemoryConsoleAuditService({
      seedDemoData: consoleDemoSeedEnabled,
    });
    consoleOrgProjectEnvBase = createInMemoryConsoleOrgProjectEnvService();
    consoleApiKeys = createInMemoryConsoleApiKeyService();
    consoleBootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    consoleGasSponsorship = createInMemoryConsoleGasSponsorshipService();
    consoleApprovals = createInMemoryConsoleApprovalService();
    consolePolicies = createInMemoryConsolePolicyService();
    consoleRuntimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    consoleTeamRbac = createInMemoryConsoleTeamRbacService();
    consoleWallets = createInMemoryConsoleWalletService({
      seedWallets: demoWalletSeeds,
    });
    consoleSponsoredCalls = createInMemoryConsoleSponsoredCallService();
  }

  const normalizedOnboardingContractAddress = (() => {
    const value = tempoOnboardingFaucetContractRaw;
    return /^0x[0-9a-fA-F]{40}$/.test(value)
      ? (value as `0x${string}`)
      : DEFAULT_TEMPO_ONBOARDING_CONTRACT;
  })();
  consoleOrgProjectEnv = createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship({
    base: consoleOrgProjectEnvBase,
    gasSponsorship: consoleGasSponsorship,
    runtimeSnapshots: consoleRuntimeSnapshots,
    faucetContractAddress: normalizedOnboardingContractAddress,
    maxGasLimit: DEFAULT_TEMPO_DRIP_GAS_LIMIT,
  });

  if (consoleWebhooksBackend === 'postgres') {
    if (!consolePostgresUrl) {
      throw new Error('CONSOLE_WEBHOOKS_BACKEND=postgres requires CONSOLE_POSTGRES_URL');
    }
    consoleWebhooks = await createPostgresConsoleWebhookService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleWebhooksNamespace,
      logger: console as any,
      ensureSchema: consoleWebhooksEnsureSchema,
    });
  } else {
    consoleWebhooks = createInMemoryConsoleWebhookService();
  }

  if (consoleObservabilityBackend === 'postgres') {
    if (!consolePostgresUrl) {
      throw new Error('CONSOLE_OBSERVABILITY_BACKEND=postgres requires CONSOLE_POSTGRES_URL');
    }
    consoleObservability = await createPostgresConsoleObservabilityService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleObservabilityNamespace,
      logger: console as any,
      ensureSchema: consoleObservabilityEnsureSchema,
      queryMaxWindowMs: consoleObservabilityQueryMaxWindowMs,
    });
    consoleObservabilityIngestion = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleObservabilityNamespace,
      logger: console as any,
      ensureSchema: consoleObservabilityEnsureSchema,
      maxBatchSize: consoleObservabilityIngestMaxBatchSize,
      maxEventsPerMinute: consoleObservabilityIngestMaxEventsPerMinute,
      retentionTtlMs: consoleObservabilityRetentionTtlMs,
      retentionPruneIntervalMs: consoleObservabilityRetentionPruneIntervalMs,
      retentionBatchSize: consoleObservabilityRetentionBatchSize,
    });
  } else {
    consoleObservability = createInMemoryConsoleObservabilityService();
    consoleObservabilityIngestion = null;
  }
  const relayApiKeyAuth = relayApiKeyAuthEnabled
    ? createRelayApiKeyAuthAdapter(consoleApiKeys)
    : null;
  const relayApiKeyUsageMeter = relayApiKeyAuthEnabled
    ? createRelayBillingUsageMeterAdapter(consoleBilling)
    : null;
  const relayBootstrapGrantBroker = createRelayBootstrapGrantBroker({
    apiKeys: consoleApiKeys,
    tokenStore: consoleBootstrapTokens,
    orgProjectEnv: consoleOrgProjectEnv,
    tokenTtlMs: 60_000,
    rateLimitsByBucket: {
      default: { windowMs: 60_000, maxIssued: 60 },
      default_web_v1: { windowMs: 60_000, maxIssued: 60 },
    },
    quotasByBucket: {
      default: { maxIssued: 1_000 },
      free_registrations_v1: { maxIssued: 1_000 },
    },
  });
  const consoleOnboarding = createInMemoryConsoleOnboardingService({
    orgProjectEnv: consoleOrgProjectEnv,
    apiKeys: consoleApiKeys,
    teamRbac: consoleTeamRbac,
  });
  const consoleAuth = createAppSessionConsoleAuthAdapter({
    session: jwtSession,
    authService,
    defaultOrgId: consoleDemoOrgId,
    fallbackRoles: consoleSsoBootstrapRoles,
    provisioning: {
      bootstrapRoles: consoleSsoBootstrapRoles,
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      audit: consoleAudit,
      logger: console,
    },
  });
  if (consoleDemoSeedEnabled) {
    await seedDemoConsoleOrgAndMembers({
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      orgId: consoleDemoOrgId,
      projectId: consoleDemoProjectId,
      environmentId: consoleDemoEnvironmentId,
      logger: console,
    });
    if (consolePostgresUrl) {
      await seedDemoConsoleWalletsInPostgres({
        postgresUrl: consolePostgresUrl,
        namespace: consoleCoreNamespace,
        wallets: demoWalletSeeds,
        logger: console,
      });
    }
    await seedDemoConsolePoliciesAndApprovals({
      policies: consolePolicies,
      approvals: consoleApprovals,
      orgId: consoleDemoOrgId,
      projectId: consoleDemoProjectId,
      environmentId: consoleDemoEnvironmentId,
      walletIds: demoWalletSeeds.map((wallet) => wallet.id),
      logger: console,
    });
  }
  await ensureTempoOnboardingSponsorshipForExistingEnvironments({
    orgProjectEnv: consoleOrgProjectEnv,
    gasSponsorship: consoleGasSponsorship,
    runtimeSnapshots: consoleRuntimeSnapshots,
    ctx: {
      orgId: consoleDemoOrgId,
      actorUserId: 'tempo-onboarding-seed',
      roles: ['owner', 'admin'],
      projectId: consoleDemoProjectId,
      environmentId: consoleDemoEnvironmentId,
    },
    faucetContractAddress: normalizedOnboardingContractAddress,
    maxGasLimit: DEFAULT_TEMPO_DRIP_GAS_LIMIT,
    projectId: consoleDemoProjectId,
  });

  app.use((_req, res, next) => {
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  // Mount router built from AuthService
  app.use(
    '/',
    createRelayRouter(authService, {
      healthz: true,
      readyz: true,
      corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
      ...(rorRpId
        ? {
            ror: {
              rpId: rorRpId,
              provider: {
                getAllowedOrigins: async (input: { rpId: string; host?: string }) =>
                  input.rpId === rorRpId ? rorOrigins : [],
              },
            },
          }
        : {}),
      signedDelegate: { route: '/signed-delegate' },
      session: jwtSession,
      sessionCookieName,
      threshold,
      ...(relayApiKeyAuth ? { apiKeyAuth: relayApiKeyAuth } : {}),
      ...(relayApiKeyUsageMeter ? { apiKeyUsageMeter: relayApiKeyUsageMeter } : {}),
      bootstrapGrantBroker: relayBootstrapGrantBroker,
      bootstrapTokenStore: consoleBootstrapTokens,
      sponsoredEvmCall: {
        apiKeys: consoleApiKeys,
        billing: consoleBilling,
        ledger: consoleSponsoredCalls,
        runtimeSnapshots: consoleRuntimeSnapshots,
        config: sponsoredEvmCallConfig,
      },
      prfSessionSeal,
      logger: console,
    }),
  );

  // Mount console/admin router on /console/*
  app.use(
    '/',
    createConsoleRouter({
      healthz: true,
      readyz: true,
      corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
      auth: consoleAuth,
      billing: consoleBilling,
      billingStripeWebhookSecret: toOptionalSecret(consoleBillingStripeWebhookSecret),
      webhooks: consoleWebhooks,
      apiKeys: consoleApiKeys,
      gasSponsorship: consoleGasSponsorship,
      approvals: consoleApprovals,
      policies: consolePolicies,
      runtimeSnapshots: consoleRuntimeSnapshots,
      onboarding: consoleOnboarding,
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      wallets: consoleWallets,
      audit: consoleAudit,
      observability: consoleObservability,
      observabilityIngestion: consoleObservabilityIngestion,
      logger: console,
    }),
  );

  const onListening = () => {
    const listenHost = config.host || 'localhost';
    console.log(`Server listening on http://${listenHost}:${config.port}`);
    console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
    console.log(
      `Sponsored EVM route: ${
        sponsoredEvmCallConfig?.enabled ? 'enabled' : 'disabled'
      }`,
    );
    if (sponsoredEvmCallConfig?.enabled) {
      console.log(
        `Sponsored EVM executor: chainId=${sponsoredEvmCallConfig.chainId} sponsor=${sponsoredEvmCallConfig.sponsorAddress} onboardingContract=${normalizedOnboardingContractAddress}`,
      );
    }
    if (rorRpId) {
      console.log(`ROR RP ID: ${rorRpId}`);
      console.log(`ROR Origins: ${rorOrigins.join(', ') || '(none)'}`);
    }
    console.log(`PRF session seal routes: ${prfSessionSealEnabled ? 'enabled' : 'disabled'}`);
    console.log(
      `Relay API key auth (/registration/bootstrap): ${relayApiKeyAuth ? 'enabled' : 'disabled'}`,
    );
    console.log(
      `Relay usage meter (billing linkage): ${relayApiKeyUsageMeter ? 'enabled' : 'disabled'}`,
    );
    console.log(`Console core backend: ${consolePostgresUrl ? 'postgres' : 'memory'}`);
    if (consolePostgresUrl) {
      console.log(`Console core namespace: ${consoleCoreNamespace}`);
    }
    console.log('Console routes mounted at /console/*');
    console.log(
      `Console session auth: app_session_v1 cookie/JWT (bootstrap roles: ${consoleSsoBootstrapRoles.join(', ') || 'none'})`,
    );
    console.log(
      `Console demo seed: ${consoleDemoSeedEnabled ? 'enabled' : 'disabled'} (org=${consoleDemoOrgId})`,
    );
    console.log(
      `Console Stripe provider mode: ${stripeApiSecretKey ? 'live_api' : 'mock'}${
        stripeCheckoutPriceId ? ` (checkout_price=${stripeCheckoutPriceId})` : ''
      }`,
    );
    if (stripeApiPublishableKey) {
      console.log('Stripe publishable key detected (frontend can use STRIPE_API_PK if needed).');
    }
    console.log(`Console billing backend: ${consoleBillingBackend}`);
    if (consoleBillingBackend === 'postgres') {
      console.log(`Console billing namespace: ${consoleBillingNamespace}`);
      console.log(
        `Console billing ensure schema: ${consoleBillingEnsureSchema ? 'enabled' : 'disabled'}`,
      );
      console.log('Console Postgres URL source: CONSOLE_POSTGRES_URL');
    }
    console.log(
      `Console billing Stripe webhook secret: ${
        consoleBillingStripeWebhookSecret ? 'configured' : 'not configured'
      }`,
    );
    console.log(`Console webhooks backend: ${consoleWebhooksBackend}`);
    if (consoleWebhooksBackend === 'postgres') {
      console.log(`Console webhooks namespace: ${consoleWebhooksNamespace}`);
      console.log(
        `Console webhooks ensure schema: ${consoleWebhooksEnsureSchema ? 'enabled' : 'disabled'}`,
      );
    }
    console.log(`Console observability backend: ${consoleObservabilityBackend}`);
    if (consoleObservabilityBackend === 'postgres') {
      console.log(`Console observability namespace: ${consoleObservabilityNamespace}`);
      console.log(
        `Console observability ensure schema: ${consoleObservabilityEnsureSchema ? 'enabled' : 'disabled'}`,
      );
      console.log(
        `Console observability query max window (ms): ${consoleObservabilityQueryMaxWindowMs}`,
      );
      console.log(
        `Console observability ingest max batch size: ${consoleObservabilityIngestMaxBatchSize}`,
      );
      console.log(
        `Console observability ingest max events/min: ${consoleObservabilityIngestMaxEventsPerMinute}`,
      );
      console.log(
        `Console observability retention TTL (ms): ${consoleObservabilityRetentionTtlMs}`,
      );
      console.log(
        `Console observability retention prune interval (ms): ${consoleObservabilityRetentionPruneIntervalMs}`,
      );
      console.log(
        `Console observability retention batch size: ${consoleObservabilityRetentionBatchSize}`,
      );
    }
    authService
      .getRelayerAccount()
      .then((relayer) =>
        console.log(`AuthService started with relayer account: ${relayer.accountId}`),
      )
      .catch((err: Error) => console.error('AuthService initial check failed:', err));
  };

  server = config.host
    ? app.listen(config.port, config.host, onListening)
    : app.listen(config.port, onListening);
}

main().catch((err) => {
  console.error('[relay-server] fatal startup error:', err);
  process.exit(1);
});
