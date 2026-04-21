import express, { Express } from 'express';
import { Pool } from 'pg';
import {
  AuthService,
  createEd25519AuthSessionStore,
  createInMemoryConsoleSponsorshipSpendCapService,
  createPostgresConsoleSponsorshipSpendCapService,
  createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship,
  createRecoveryAuthorityIntervalRunner,
  createEvmSmartAccountDeployHandler,
  createEcdsaAuthSessionStore,
  createSigningSessionSealPolicyFromThresholdAuthSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  ensureTempoOnboardingSponsorshipForAllOrganizations,
  resolveSigningSessionSealIdempotencyFromEnv,
  resolveSigningSessionSealRateLimitFromEnv,
  resolveCoinGeckoSponsoredExecutionPricingFromEnv,
  resolveSponsoredEvmCallConfigFromEnv,
  resolveStaticSponsoredExecutionPricingFromEnv,
  requireEnvVar,
  type ConsoleBillingPrepaidReservationService,
  type ConsoleSponsoredCallService,
  type ConsoleSponsorshipSpendCapService,
  type SigningRootSecretShareId,
  type SigningRootShareResolver,
} from '@tatchi-xyz/sdk/server';
import {
  createConsoleRouter,
  createInMemoryConsoleAccountService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleBillingPrepaidReservationService,
  createInMemoryConsoleSponsoredCallService,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleAuditService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleObservabilityService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleApprovalService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleAccountService,
  createPostgresConsoleApprovalService,
  createPostgresConsoleApiKeyService,
  createPostgresConsoleAuditService,
  createPostgresConsoleBillingService,
  createPostgresConsoleBillingPrepaidReservationService,
  createPostgresConsoleBootstrapTokenService,
  createPostgresConsoleObservabilityIngestionService,
  createPostgresConsoleObservabilityService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsolePolicyService,
  createPostgresConsoleRuntimeSnapshotService,
  createPostgresConsoleTeamRbacService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  createPostgresConsoleSponsoredCallService,
  createRelayApiKeyAuthAdapter,
  createRelayBillingUsageMeterAdapter,
  createRelayBootstrapGrantBroker,
  createRelayPublishableKeyAuthAdapter,
  createAppSessionConsoleAuthAdapter,
  normalizeConsoleOrgScopedRoleList,
  mergeConsoleOrgScopedRoleLists,
  createRelayRouter,
  type ConsoleAccountService,
  type ConsoleApiKeyService,
  type ConsoleBillingService,
  type ConsoleAuditService,
  type ConsoleBootstrapTokenService,
  type ConsoleApprovalService,
  type ConsoleObservabilityIngestionService,
  type ConsoleObservabilityService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicy,
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
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createJwtSession } from './jwtSession.js';
import { resolveRelayServerConsoleConfig, toOptionalSecret } from './consoleConfig.js';
import {
  createStripeBillingProviderAdapter,
  normalizeOptionalStripePublishableKey,
  normalizeStripeSecretKey,
} from './stripeBillingProvider.js';

const relayServerDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const relayDotenvPath = resolve(relayServerDir, '.env');
dotenv.config({ path: relayDotenvPath, override: true });

let server: ReturnType<Express['listen']> | null = null;
let recoveryAuthorityRunner: ReturnType<typeof createRecoveryAuthorityIntervalRunner> | null = null;

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  if (recoveryAuthorityRunner) {
    recoveryAuthorityRunner.stop();
    recoveryAuthorityRunner = null;
  }
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

function isLocalDevelopmentHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return (
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '::1' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.local')
  );
}

function isLocalDevelopmentOrigin(origin: string): boolean {
  return isLocalDevelopmentHost(hostnameFromOrigin(origin));
}

function parseBooleanFlagWithDefault(value: unknown, fallback: boolean): boolean {
  const normalized = String(value || '').trim();
  if (!normalized) return fallback;
  return parseBooleanFlag(normalized);
}

function parseSigningSessionSealLimiterKind(
  value: unknown,
): 'in-memory' | 'upstash-redis-rest' | 'redis-tcp' {
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

function readServiceRuntimeBySymbolDescription(
  service: unknown,
  symbolDescription: string,
): { pool: unknown; namespace: string } | null {
  if (!service || typeof service !== 'object') return null;
  for (const symbolKey of Object.getOwnPropertySymbols(service)) {
    if (symbolKey.description !== symbolDescription) continue;
    const runtime = (service as Record<symbol, unknown>)[symbolKey];
    if (!runtime || typeof runtime !== 'object') return null;
    const namespace = String((runtime as { namespace?: unknown }).namespace || '').trim();
    if (!namespace) return null;
    return {
      pool: (runtime as { pool?: unknown }).pool,
      namespace,
    };
  }
  return null;
}

const LOCAL_DEV_SIGNING_ROOT_SECRET_SHARE_WIRES: ReadonlyArray<{
  readonly shareId: SigningRootSecretShareId;
  readonly wireHex: string;
}> = [
  {
    shareId: 1,
    wireHex: '011ba5f9c2f4003d409a9358a20b40b37eb32a28daacc5676a468b64a203c1e303',
  },
  {
    shareId: 2,
    wireHex: '021bb9834016ae79b9a815f68d1f456b35acb1b5631dd04e1cab9f640852aaed0d',
  },
  {
    shareId: 3,
    wireHex: '032ef917611df8a3dae0fa9bd6545044d7a43843ed8dda35ce0fb4646ea093f707',
  },
];

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

function cloneLocalDevSigningRootSharePair(
  preferredShareIds?: readonly [SigningRootSecretShareId, SigningRootSecretShareId],
): readonly [Uint8Array, Uint8Array] {
  const shares = new Map<SigningRootSecretShareId, Uint8Array>(
    LOCAL_DEV_SIGNING_ROOT_SECRET_SHARE_WIRES.map((share) => [
      share.shareId,
      hexToBytes(share.wireHex),
    ]),
  );
  const selectedIds =
    preferredShareIds ??
    ([...shares.keys()].sort((a, b) => a - b).slice(0, 2) as [
      SigningRootSecretShareId,
      SigningRootSecretShareId,
    ]);
  if (selectedIds.length !== 2 || selectedIds[0] === selectedIds[1]) {
    throw new Error('preferredShareIds must identify two distinct signing-root shares');
  }
  const first = shares.get(selectedIds[0]);
  const second = shares.get(selectedIds[1]);
  if (!first || !second) throw new Error('requested signing-root shares are not available');
  return [new Uint8Array(first), new Uint8Array(second)] as const;
}

function shouldEnableLocalDevSigningRootResolver(input: {
  readonly env: NodeJS.ProcessEnv;
  readonly expectedOrigin: string;
  readonly expectedWalletOrigin: string;
}): boolean {
  if (
    String(input.env.NODE_ENV || '')
      .trim()
      .toLowerCase() === 'production'
  )
    return false;
  if (parseBooleanFlag(input.env.THRESHOLD_SIGNING_ROOT_LOCAL_DEV_RESOLVER)) return true;
  return (
    isLocalDevelopmentOrigin(input.expectedOrigin) ||
    isLocalDevelopmentOrigin(input.expectedWalletOrigin)
  );
}

function createLocalDevSigningRootShareResolver(): SigningRootShareResolver {
  return {
    resolveSigningRootSharePair: async (request) => {
      const signingRootId = String(request.signingRootId || '').trim();
      if (!signingRootId) throw new Error('signingRootId is required');
      return cloneLocalDevSigningRootSharePair(request.preferredShareIds);
    },
  };
}

async function resolveConsoleDemoOrgId(input: {
  configuredOrgId: string;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  logger: Pick<Console, 'warn'>;
}): Promise<string> {
  const configuredOrgId = String(input.configuredOrgId || '').trim();
  if (configuredOrgId) return configuredOrgId;
  try {
    return String((await input.orgProjectEnv.findDefaultOrganization())?.id || '').trim();
  } catch (error: unknown) {
    input.logger.warn(
      `[console-demo-seed] failed to resolve persisted organization: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return '';
  }
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
  name: string;
  description?: string;
  rules?: Record<string, unknown>;
  publish?: boolean;
}): Promise<ConsolePolicy> {
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: ['owner', 'admin'],
  };

  const existing =
    (await input.policies.listPolicies(ctx)).find((policy) => policy.name === input.name) || null;
  const policy =
    existing ||
    (await input.policies.createPolicy(ctx, {
      name: input.name,
      ...(input.description ? { description: input.description } : {}),
      ...(input.rules ? { rules: input.rules } : {}),
    }));

  if (!input.publish || policy.status === 'PUBLISHED') {
    return policy;
  }

  const published = await input.policies.publishPolicy(ctx, policy.id);
  return published?.policy || policy;
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
  const projectPolicy = await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    name: 'Project signing policy',
    description: 'Default project guardrails for managed signing wallets.',
    rules: {
      allowedChains: ['Ethereum', 'Base', 'NEAR'],
      blockedActions: ['export_key'],
      maxAmountMinor: 250_000,
    },
    publish: true,
  });
  const environmentPolicy = await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    name: 'Production environment policy',
    description: 'Tighter production limits for the active environment.',
    rules: {
      allowedChains: ['Base', 'NEAR'],
      blockedActions: ['export_key'],
      maxAmountMinor: 125_000,
    },
    publish: true,
  });
  const walletOverridePolicy = await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    name: 'Wallet override policy',
    description: 'Single-wallet override for sensitive NEAR activity.',
    rules: {
      allowedChains: ['NEAR'],
      blockedActions: ['export_key', 'transfer'],
      maxAmountMinor: 50_000,
    },
    publish: true,
  });
  const publishCandidatePolicy = await ensureDemoPolicyExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
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
    policyId: projectPolicy.id,
  });
  await ensureDemoAssignmentExists({
    policies: input.policies,
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
    scopeType: 'ENVIRONMENT',
    scopeId: input.environmentId,
    policyId: environmentPolicy.id,
  });
  if (walletOverrideId) {
    await ensureDemoAssignmentExists({
      policies: input.policies,
      orgId: input.orgId,
      actorUserId: 'console-seed-owner',
      scopeType: 'WALLET',
      scopeId: walletOverrideId,
      policyId: walletOverridePolicy.id,
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
    resourceId: publishCandidatePolicy.id,
  });
  await ensureDemoApprovalRequest({
    approvals: input.approvals,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    id: 'apr_policy_publish_approved_demo',
    reason: 'Approved seed request for policy publish testing.',
    resourceType: 'policy',
    resourceId: publishCandidatePolicy.id,
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
    consoleRuntimeSnapshotRetentionTtlMs,
    consoleRuntimeSnapshotRetentionPruneIntervalMs,
    consoleRuntimeSnapshotRetentionBatchSize,
    consoleBillingStripeWebhookSecret,
  } = resolveRelayServerConsoleConfig(env as Record<string, unknown>);
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
  const startupHost = config.host || '0.0.0.0';
  console.log(`[relay-server] startup target http://${startupHost}:${config.port}`);
  if (String(env.ACCOUNT_ID_DERIVATION_SECRET || '').trim()) {
    console.log('[relay-server] Hosted account-id derivation: configured');
  } else {
    console.warn('[relay-server] ACCOUNT_ID_DERIVATION_SECRET is not set');
  }
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromEnv(env);
  const requiresAtomicSponsoredSettlement = Boolean(sponsoredEvmCallConfig);
  const recoveryAuthorityContinuationEnabled = parseBooleanFlag(
    env.RECOVERY_AUTHORITY_CONTINUATION_ENABLED,
  );
  const recoveryAuthorityContinuationIntervalMs =
    parseOptionalPositiveInteger(env.RECOVERY_AUTHORITY_CONTINUATION_INTERVAL_MS) || 30_000;
  const recoveryAuthorityContinuationLimit = parseOptionalPositiveInteger(
    env.RECOVERY_AUTHORITY_CONTINUATION_LIMIT,
  );
  const sponsorshipRealPricing = resolveCoinGeckoSponsoredExecutionPricingFromEnv(env);
  const sponsorshipStaticPricing = resolveStaticSponsoredExecutionPricingFromEnv(env);
  const sponsorshipPricing = sponsorshipRealPricing || sponsorshipStaticPricing;
  const hasRealSponsorshipPricingConfig = Boolean(
    String(env.SPONSORED_EXECUTION_REAL_PRICING_JSON || '').trim(),
  );
  const hasStaticSponsorshipPricingConfig = Boolean(
    String(env.SPONSORED_EXECUTION_STATIC_PRICING_JSON || '').trim(),
  );
  const tempoOnboardingFaucetContractRaw = String(
    env.TEMPO_ONBOARDING_FAUCET_CONTRACT || '',
  ).trim();
  if (hasRealSponsorshipPricingConfig && !sponsorshipRealPricing) {
    console.warn(
      '[sponsorship-pricing] SPONSORED_EXECUTION_REAL_PRICING_JSON is invalid; real spend pricing is disabled',
    );
  }
  if (hasStaticSponsorshipPricingConfig && !sponsorshipStaticPricing) {
    console.warn(
      '[sponsorship-pricing] SPONSORED_EXECUTION_STATIC_PRICING_JSON is invalid; static spend pricing is disabled',
    );
  }
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
  const localDevSigningRootResolver = shouldEnableLocalDevSigningRootResolver({
    env,
    expectedOrigin: config.expectedOrigin,
    expectedWalletOrigin: config.expectedWalletOrigin,
  })
    ? createLocalDevSigningRootShareResolver()
    : undefined;
  if (localDevSigningRootResolver) {
    console.warn(
      '[threshold] using dynamic local-dev fixture signing-root shares; do not use this signer for real funds.',
    );
  }

  const thresholdStore = {
    // Share mode and threshold-prf signing-root share derivation.
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    ...(localDevSigningRootResolver ? { signingRootShareResolver: localDevSigningRootResolver } : {}),
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
    thresholdStore,
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

  console.log('[relay-server] initializing storage');
  await authService.initStorage();

  console.log('[relay-server] warming registration runtime');
  await authService.warmRegistrationRuntime();

  console.log('[relay-server] initializing threshold services');
  const threshold = authService.getThresholdSigningService();

  const signingSessionSealEnabled = parseBooleanFlag(env.SIGNING_SESSION_SEAL_ENABLED);
  const signingSessionSeal = (() => {
    if (!signingSessionSealEnabled) return null;

    const shamirPrimeB64u = requireEnvVar(env, 'SIGNING_SESSION_SHAMIR_P_B64U');
    const serverEncryptExponentB64u = requireEnvVar(env, 'SIGNING_SESSION_SEAL_E_S_B64U');
    const serverDecryptExponentB64u = requireEnvVar(env, 'SIGNING_SESSION_SEAL_D_S_B64U');
    const keyVersion = String(env.SIGNING_SESSION_SEAL_KEY_VERSION || 'kek-s-2026-02').trim();
    if (!keyVersion) {
      throw new Error(
        'SIGNING_SESSION_SEAL_KEY_VERSION must be a non-empty string when SIGNING_SESSION_SEAL_ENABLED=1',
      );
    }

    const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
      config: thresholdStore,
      logger: console,
      isNode: true,
    });
    const authSessionStore = createEd25519AuthSessionStore({
      config: thresholdStore,
      logger: console,
      isNode: true,
    });

    const limiterKind = parseSigningSessionSealLimiterKind(env.SIGNING_SESSION_SEAL_RATE_LIMIT_KIND);
    const rateLimit = resolveSigningSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl: env.UPSTASH_REDIS_REST_URL,
      upstashToken: env.UPSTASH_REDIS_REST_TOKEN,
      redisUrl: thresholdRedisUrl || redisUrl,
      keyPrefix: String(
        env.SIGNING_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX || 'threshold:signing-session-seal:rate:',
      ).trim(),
      limit: parseOptionalPositiveInteger(env.SIGNING_SESSION_SEAL_RATE_LIMIT) || 30,
      windowMs:
        parseOptionalPositiveInteger(env.SIGNING_SESSION_SEAL_RATE_LIMIT_WINDOW_MS) || 60_000,
    });
    const idempotencyKind = String(env.SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND || '')
      .trim()
      .toLowerCase();
    const idempotency = idempotencyKind
      ? resolveSigningSessionSealIdempotencyFromEnv({
          idempotencyKind,
          upstashUrl:
            env.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL ||
            env.UPSTASH_REDIS_REST_URL ||
            undefined,
          upstashToken:
            env.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN ||
            env.UPSTASH_REDIS_REST_TOKEN ||
            undefined,
          redisUrl:
            env.SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL ||
            thresholdRedisUrl ||
            redisUrl ||
            undefined,
          postgresUrl:
            env.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL || thresholdPostgresUrl || undefined,
          postgresNamespace:
            env.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE || undefined,
          keyPrefix:
            String(
              env.SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX ||
                'threshold:signing-session-seal:idempotency:',
            ).trim() || undefined,
          ttlMs: parseOptionalPositiveInteger(env.SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS),
        })
      : undefined;

    return createSigningSessionSealRoutesOptions({
      sessionPolicy: createSigningSessionSealPolicyFromThresholdAuthSessionStores({
        stores: [authSessionStore, ecdsaAuthSessionStore],
      }),
      cipher: createSigningSessionSealShamir3PassCipherAdapter({
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
  const configuredConsoleDemoOrgId = String(env.CONSOLE_DEMO_ORG_ID || '').trim();
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
  const stripeApiSecretKey = normalizeStripeSecretKey(env.STRIPE_API_SK);
  const stripeApiPublishableKey = normalizeOptionalStripePublishableKey(env.STRIPE_API_PK);
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
  const effectiveConsoleBillingBackend = requiresAtomicSponsoredSettlement
    ? 'postgres'
    : consoleBillingBackend;
  if (requiresAtomicSponsoredSettlement && !consolePostgresUrl) {
    throw new Error(
      'Sponsored EVM call requires CONSOLE_POSTGRES_URL because atomic sponsored settlement needs Postgres billing/prepaid/ledger services',
    );
  }
  if (requiresAtomicSponsoredSettlement && consoleBillingBackend !== 'postgres') {
    console.warn(
      `[relay-server] forcing CONSOLE_BILLING_BACKEND=postgres because sponsored EVM call is enabled (configured=${consoleBillingBackend})`,
    );
  }
  let consoleBilling: ConsoleBillingService;
  let consoleWebhooks: ConsoleWebhookService;
  let consoleObservability: ConsoleObservabilityService;
  let consoleObservabilityIngestion: ConsoleObservabilityIngestionService | null;
  let consoleAudit: ConsoleAuditService;
  let consoleOrgProjectEnvBase: ConsoleOrgProjectEnvService;
  let consoleOrgProjectEnv: ConsoleOrgProjectEnvService;
  let consoleApiKeys: ConsoleApiKeyService;
  let consoleBootstrapTokens: ConsoleBootstrapTokenService;
  let consoleApprovals: ConsoleApprovalService;
  let consolePolicies: ConsolePolicyService;
  let consoleRuntimeSnapshots: ConsoleRuntimeSnapshotService;
  let consoleTeamRbac: ConsoleTeamRbacService;
  let consoleWallets: ConsoleWalletService;
  let consoleSponsoredCalls: ConsoleSponsoredCallService;
  let consoleSponsorshipSpendCaps: ConsoleSponsorshipSpendCapService;
  let consoleBillingPrepaidReservations: ConsoleBillingPrepaidReservationService;
  let consoleAccount: ConsoleAccountService;
  const consoleCoreNamespace = consoleBillingNamespace;
  let consoleDemoOrgId = '';
  let demoWalletSeeds: ConsoleWallet[] = [];
  if (effectiveConsoleBillingBackend === 'postgres') {
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
    consolePolicies = await createPostgresConsolePolicyService({
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
    consoleRuntimeSnapshots = await createPostgresConsoleRuntimeSnapshotService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
      retentionTtlMs: consoleRuntimeSnapshotRetentionTtlMs,
      retentionPruneIntervalMs: consoleRuntimeSnapshotRetentionPruneIntervalMs,
      retentionBatchSize: consoleRuntimeSnapshotRetentionBatchSize,
    });
    consoleTeamRbac = await createPostgresConsoleTeamRbacService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      logger: console as any,
      ensureSchema: true,
    });
    consoleDemoOrgId = await resolveConsoleDemoOrgId({
      configuredOrgId: configuredConsoleDemoOrgId,
      orgProjectEnv: consoleOrgProjectEnvBase,
      logger: console,
    });
    demoWalletSeeds = consoleDemoOrgId
      ? buildDemoConsoleWalletSeeds({
          orgId: consoleDemoOrgId,
          projectId: consoleDemoProjectId,
          environmentId: consoleDemoEnvironmentId,
        })
      : [];
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
    consoleBillingPrepaidReservations = await createPostgresConsoleBillingPrepaidReservationService(
      {
        postgresUrl: consolePostgresUrl,
        namespace: consoleCoreNamespace,
        logger: console as any,
        ensureSchema: true,
      },
    );
    consoleSponsorshipSpendCaps = await createPostgresConsoleSponsorshipSpendCapService({
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
    consolePolicies = createInMemoryConsolePolicyService();
    consoleApprovals = createInMemoryConsoleApprovalService();
    consoleRuntimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    consoleTeamRbac = createInMemoryConsoleTeamRbacService();
    consoleDemoOrgId = await resolveConsoleDemoOrgId({
      configuredOrgId: configuredConsoleDemoOrgId,
      orgProjectEnv: consoleOrgProjectEnvBase,
      logger: console,
    });
    demoWalletSeeds = consoleDemoOrgId
      ? buildDemoConsoleWalletSeeds({
          orgId: consoleDemoOrgId,
          projectId: consoleDemoProjectId,
          environmentId: consoleDemoEnvironmentId,
        })
      : [];
    consoleWallets = createInMemoryConsoleWalletService({
      seedWallets: demoWalletSeeds,
    });
    consoleSponsoredCalls = createInMemoryConsoleSponsoredCallService();
    consoleBillingPrepaidReservations = createInMemoryConsoleBillingPrepaidReservationService();
    consoleSponsorshipSpendCaps = createInMemoryConsoleSponsorshipSpendCapService();
  }

  const normalizedOnboardingContractAddress = (() => {
    const value = tempoOnboardingFaucetContractRaw;
    return /^0x[0-9a-fA-F]{40}$/.test(value)
      ? (value as `0x${string}`)
      : DEFAULT_TEMPO_ONBOARDING_CONTRACT;
  })();
  consoleOrgProjectEnv = createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship({
    base: consoleOrgProjectEnvBase,
    policies: consolePolicies,
    runtimeSnapshots: consoleRuntimeSnapshots,
    faucetContractAddress: normalizedOnboardingContractAddress,
  });

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
  if (consoleWebhooksBackend === 'postgres') {
    if (!consolePostgresUrl) {
      throw new Error('CONSOLE_WEBHOOKS_BACKEND=postgres requires CONSOLE_POSTGRES_URL');
    }
    consoleWebhooks = await createPostgresConsoleWebhookService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleWebhooksNamespace,
      logger: console as any,
      ensureSchema: consoleWebhooksEnsureSchema,
      observabilityIngestion: consoleObservabilityIngestion,
      observabilityLogger: console as any,
    } as any);
  } else {
    consoleWebhooks = createInMemoryConsoleWebhookService({
      observabilityIngestion: consoleObservabilityIngestion,
      observabilityLogger: console as any,
    } as any);
  }
  const relayApiKeyAuth = relayApiKeyAuthEnabled
    ? createRelayApiKeyAuthAdapter(consoleApiKeys)
    : null;
  const relayPublishableKeyAuth = relayApiKeyAuthEnabled
    ? createRelayPublishableKeyAuthAdapter(consoleApiKeys)
    : null;
  const relayApiKeyUsageMeter = relayApiKeyAuthEnabled
    ? createRelayBillingUsageMeterAdapter(consoleBilling, {
        orgProjectEnv: consoleOrgProjectEnv,
        wallets: consoleWallets,
      })
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
  if (consolePostgresUrl) {
    consoleAccount = await createPostgresConsoleAccountService({
      postgresUrl: consolePostgresUrl,
      namespace: consoleCoreNamespace,
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      onboarding: consoleOnboarding,
      wallets: consoleWallets,
      logger: console,
    });
  } else {
    consoleAccount = createInMemoryConsoleAccountService({
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      onboarding: consoleOnboarding,
      wallets: consoleWallets,
    });
  }
  const consoleAuth = createAppSessionConsoleAuthAdapter({
    session: jwtSession,
    authService,
    ...(consoleDemoOrgId ? { defaultOrgId: consoleDemoOrgId } : {}),
    fallbackRoles: consoleSsoBootstrapRoles,
    platformAdminEmails: env.CONSOLE_PLATFORM_ADMIN_EMAILS,
    provisioning: {
      bootstrapRoles: consoleSsoBootstrapRoles,
      orgProjectEnv: consoleOrgProjectEnv,
      teamRbac: consoleTeamRbac,
      audit: consoleAudit,
      logger: console,
    },
  });
  if (consoleDemoSeedEnabled) {
    if (!consoleDemoOrgId) {
      console.warn(
        '[console-demo-seed] skipped: CONSOLE_DEMO_ORG_ID is unset and storage does not contain exactly one organization',
      );
    } else {
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
  }
  await ensureTempoOnboardingSponsorshipForAllOrganizations({
    orgProjectEnv: consoleOrgProjectEnv,
    policies: consolePolicies,
    runtimeSnapshots: consoleRuntimeSnapshots,
    faucetContractAddress: normalizedOnboardingContractAddress,
  });

  if (requiresAtomicSponsoredSettlement) {
    const billingRuntime = readServiceRuntimeBySymbolDescription(
      consoleBilling,
      'consoleBillingPostgresRuntime',
    );
    const prepaidRuntime = readServiceRuntimeBySymbolDescription(
      consoleBillingPrepaidReservations,
      'consoleBillingPrepaidReservationPostgresRuntime',
    );
    const sponsoredRuntime = readServiceRuntimeBySymbolDescription(
      consoleSponsoredCalls,
      'consoleSponsoredCallPostgresRuntime',
    );
    const hasAllRuntimes = Boolean(billingRuntime && prepaidRuntime && sponsoredRuntime);
    const samePool = Boolean(
      billingRuntime &&
      prepaidRuntime &&
      sponsoredRuntime &&
      billingRuntime.pool === prepaidRuntime.pool &&
      billingRuntime.pool === sponsoredRuntime.pool,
    );
    const sameNamespace = Boolean(
      billingRuntime &&
      prepaidRuntime &&
      sponsoredRuntime &&
      billingRuntime.namespace === prepaidRuntime.namespace &&
      billingRuntime.namespace === sponsoredRuntime.namespace,
    );
    if (!hasAllRuntimes || !samePool || !sameNamespace) {
      const diagnostics = {
        requiresAtomicSponsoredSettlement,
        effectiveConsoleBillingBackend,
        consoleBillingBackendConfigured: consoleBillingBackend,
        hasConsolePostgresUrl: Boolean(consolePostgresUrl),
        hasBillingRuntime: Boolean(billingRuntime),
        hasPrepaidRuntime: Boolean(prepaidRuntime),
        hasSponsoredRuntime: Boolean(sponsoredRuntime),
        samePool,
        sameNamespace,
        billingNamespace: billingRuntime?.namespace || null,
        prepaidNamespace: prepaidRuntime?.namespace || null,
        sponsoredNamespace: sponsoredRuntime?.namespace || null,
      };
      console.error('[relay-server] atomic sponsorship storage wiring invalid', diagnostics);
      throw new Error(
        'Atomic sponsored settlement startup check failed. Require Postgres billing, prepaidReservations, and sponsoredCalls with one shared pool and namespace.',
      );
    }
    console.log(
      `[relay-server] atomic sponsorship storage wiring: ok (namespace=${billingRuntime!.namespace})`,
    );
  }

  if (recoveryAuthorityContinuationEnabled) {
    recoveryAuthorityRunner = createRecoveryAuthorityIntervalRunner(authService, {
      logger: console,
      intervalMs: recoveryAuthorityContinuationIntervalMs,
      ...(typeof recoveryAuthorityContinuationLimit === 'number'
        ? { limit: recoveryAuthorityContinuationLimit }
        : {}),
      sponsorship:
        sponsoredEvmCallConfig && consoleRuntimeSnapshots
          ? {
              logger: console as any,
              billing: consoleBilling,
              ledger: consoleSponsoredCalls,
              runtimeSnapshots: consoleRuntimeSnapshots,
              config: sponsoredEvmCallConfig,
              spendCaps: consoleSponsorshipSpendCaps,
              pricing: sponsorshipPricing,
              prepaidReservations: consoleBillingPrepaidReservations,
              observabilityIngestion: consoleObservabilityIngestion,
              webhooks: consoleWebhooks,
              webhookActorUserId: 'recovery-authority',
              webhookRoles: ['system'],
            }
          : null,
    });
  }

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
      signedDelegate: {
        route: '/signed-delegate',
        billing: consoleBilling,
        ledger: consoleSponsoredCalls,
        runtimeSnapshots: consoleRuntimeSnapshots,
      },
      sponsorship: {
        prepaidReservations: consoleBillingPrepaidReservations,
        spendCaps: consoleSponsorshipSpendCaps,
        pricing: sponsorshipPricing,
      },
      session: jwtSession,
      sessionCookieName,
      threshold,
      ...(relayApiKeyAuth ? { apiKeyAuth: relayApiKeyAuth } : {}),
      ...(relayPublishableKeyAuth ? { publishableKeyAuth: relayPublishableKeyAuth } : {}),
      ...(relayApiKeyUsageMeter ? { apiKeyUsageMeter: relayApiKeyUsageMeter } : {}),
      bootstrapGrantBroker: relayBootstrapGrantBroker,
      bootstrapTokenStore: consoleBootstrapTokens,
      ...(sponsoredEvmCallConfig
        ? {
            smartAccountDeploy: createEvmSmartAccountDeployHandler({
              config: sponsoredEvmCallConfig,
              logger: console,
            }),
          }
        : {}),
      sponsoredEvmCall: {
        apiKeys: consoleApiKeys,
        billing: consoleBilling,
        ledger: consoleSponsoredCalls,
        runtimeSnapshots: consoleRuntimeSnapshots,
        config: sponsoredEvmCallConfig,
      },
      orgProjectEnv: consoleOrgProjectEnv,
      signingSessionSeal,
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
      session: jwtSession,
      billing: consoleBilling,
      billingStripeWebhookSecret: toOptionalSecret(consoleBillingStripeWebhookSecret),
      webhooks: consoleWebhooks,
      apiKeys: consoleApiKeys,
      approvals: consoleApprovals,
      policies: consolePolicies,
      runtimeSnapshots: consoleRuntimeSnapshots,
      onboarding: consoleOnboarding,
      account: consoleAccount,
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
    const boundAddress = server?.address();
    if (boundAddress && typeof boundAddress === 'object') {
      const host = boundAddress.address || config.host || 'localhost';
      const printableHost = host.includes(':') ? `[${host}]` : host;
      console.log(`[relay-server] listening on http://${printableHost}:${boundAddress.port}`);
    } else {
      const listenHost = config.host || 'localhost';
      console.log(`[relay-server] listening on http://${listenHost}:${config.port}`);
    }
    console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
    const sponsoredExecutors = sponsoredEvmCallConfig
      ? [...sponsoredEvmCallConfig.executorsByChain.values()]
      : [];
    console.log(`Sponsored EVM route: ${sponsoredExecutors.length > 0 ? 'enabled' : 'disabled'}`);
    for (const executor of sponsoredExecutors) {
      console.log(
        `Sponsored EVM executor: chainId=${executor.chainId} sponsor=${executor.sponsorAddress} onboardingContract=${normalizedOnboardingContractAddress}`,
      );
    }
    console.log(
      `Sponsored spend pricing: ${
        sponsorshipRealPricing
          ? 'real_configured'
          : sponsorshipStaticPricing
            ? 'static_configured'
            : hasRealSponsorshipPricingConfig || hasStaticSponsorshipPricingConfig
              ? 'invalid'
              : 'disabled'
      }`,
    );
    if (rorRpId) {
      console.log(`ROR RP ID: ${rorRpId}`);
      console.log(`ROR Origins: ${rorOrigins.join(', ') || '(none)'}`);
    }
    console.log(
      `Signing-session seal routes: ${signingSessionSealEnabled ? 'enabled' : 'disabled'}`,
    );
    console.log(
      `Relay API key auth (/registration/bootstrap): ${relayApiKeyAuth ? 'enabled' : 'disabled'}`,
    );
    console.log(
      `Relay usage meter (billing linkage): ${relayApiKeyUsageMeter ? 'enabled' : 'disabled'}`,
    );
    console.log(
      `Recovery authority continuation: ${
        recoveryAuthorityRunner
          ? `enabled (interval_ms=${recoveryAuthorityContinuationIntervalMs}${
              recoveryAuthorityContinuationLimit
                ? ` limit=${recoveryAuthorityContinuationLimit}`
                : ''
            })`
          : 'disabled'
      }`,
    );
    console.log(`Console core backend: ${consolePostgresUrl ? 'postgres' : 'memory'}`);
    if (consolePostgresUrl) {
      console.log(`Console core namespace: ${consoleCoreNamespace}`);
      console.log(`Console runtime snapshot retention TTL (ms): ${consoleRuntimeSnapshotRetentionTtlMs}`);
      console.log(
        `Console runtime snapshot retention prune interval (ms): ${consoleRuntimeSnapshotRetentionPruneIntervalMs}`,
      );
      console.log(
        `Console runtime snapshot retention batch size: ${consoleRuntimeSnapshotRetentionBatchSize}`,
      );
    }
    console.log('Console routes mounted at /console/*');
    console.log(
      `Console session auth: app_session_v1 cookie/JWT (bootstrap roles: ${consoleSsoBootstrapRoles.join(', ') || 'none'})`,
    );
    console.log(
      `Console demo seed: ${consoleDemoSeedEnabled ? 'enabled' : 'disabled'} (org=${consoleDemoOrgId || 'unresolved'})`,
    );
    console.log(
      `Console Stripe provider mode: ${stripeApiSecretKey ? 'live_api' : 'mock'}${
        stripeCheckoutPriceId ? ` (checkout_price=${stripeCheckoutPriceId})` : ''
      }`,
    );
    if (stripeApiPublishableKey) {
      console.log('Stripe publishable key detected (frontend can use STRIPE_API_PK if needed).');
    }
    console.log(`Console billing backend: ${effectiveConsoleBillingBackend}`);
    if (effectiveConsoleBillingBackend === 'postgres') {
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
    recoveryAuthorityRunner?.start();
  };

  const requestedListenHost = config.host || '0.0.0.0';
  console.log('[relay-server] startup complete, binding http listener');
  console.log(`[relay-server] attempting listen on http://${requestedListenHost}:${config.port}`);
  server = config.host
    ? app.listen(config.port, config.host, onListening)
    : app.listen(config.port, onListening);
  server.on('error', (error: Error) => {
    console.error(
      `[relay-server] failed to listen on http://${requestedListenHost}:${config.port}`,
      error,
    );
  });
}

main().catch((err) => {
  console.error('[relay-server] fatal startup error:', err);
  process.exit(1);
});
