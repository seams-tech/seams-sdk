import express, { Express, type RequestHandler } from 'express';
import { WALLET_API_CREDENTIAL_SCOPE_VALIDATION } from '@seams-internal/wallet-console-shared/apiKeyScopes';
import { WALLET_CONSOLE_WEBHOOK_EVENT_CATEGORY_VALIDATION } from '@seams-internal/wallet-console-shared/webhookEventCategories';
import { Buffer } from 'node:buffer';
import type { IncomingMessage } from 'node:http';
import { AuthService, requireEnvVar, type ThresholdStoreConfigInput } from '@seams/sdk-server';
import {
  createInMemoryConsoleSponsorshipSpendCapService,
  createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship,
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  ensureTempoOnboardingSponsorshipForAllOrganizations,
  resolveSponsoredExecutionPricingFromEnv,
  resolveSponsoredEvmCallConfigFromEnv,
  resolveStaticSponsoredExecutionPricingFromEnv,
  type ConsoleBillingPrepaidReservationService,
  type ConsoleSponsoredCallService,
  type ConsoleSponsorshipSpendCapService,
} from '@seams-internal/wallet-console-server';
import {
  createConsoleRouter,
  createInMemoryConsoleAccountService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleBillingPrepaidReservationService,
  createInMemoryConsoleSponsoredCallService,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleAuditService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleObservabilityService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleApprovalService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleOrganizationAccessService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  createAppSessionConsoleAuthAdapter,
  type ConsoleAccountService,
  type ConsoleApiKeyService,
  type ConsoleBillingService,
  type ConsoleAuditService,
  type ConsoleApprovalService,
  type ConsoleObservabilityIngestionService,
  type ConsoleObservabilityService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicy,
  type ConsolePolicyService,
  type ConsoleRuntimeSnapshotService,
  type ConsoleOrganizationAccessService,
  type ConsoleWallet,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@seams-internal/wallet-console-server/router/express-adaptor';

import dotenv from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createJwtSession } from './jwtSession.js';
import { resolveWebServerConsoleConfig, toOptionalSecret } from './consoleConfig.js';
const webServerDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const webServerDotenvPath = resolve(webServerDir, '.env');
dotenv.config({ path: webServerDotenvPath });

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

function captureRawJsonBody(req: IncomingMessage, _res: unknown, buffer: Buffer): void {
  (req as IncomingMessage & { rawBody?: Uint8Array }).rawBody = Uint8Array.from(buffer);
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

function hasConsoleErrorCode(error: unknown, code: string): boolean {
  if (!error || typeof error !== 'object') return false;
  return String((error as { code?: unknown }).code || '').trim() === code;
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
  organizationAccess: ConsoleOrganizationAccessService;
  orgId: string;
  projectId: string;
  environmentId: string;
  logger: Pick<Console, 'log' | 'warn'>;
}): Promise<void> {
  const seedCtx = {
    orgId: input.orgId,
    actorUserId: 'console-seed-owner',
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

  await input.organizationAccess.bootstrapInitialOwner({
    orgId: input.orgId,
    userId: 'console-seed-owner',
    email: 'owner@demo.seams.local',
    displayName: 'Console Owner',
  });

  const seedMembers = [
    {
      account: {
        userId: 'console-backup-owner',
        verifiedEmail: 'backup-owner@demo.seams.local',
      },
      invitation: {
        email: 'backup-owner@demo.seams.local',
        role: 'OWNER' as const,
      },
    },
    {
      account: {
        userId: 'console-admin',
        verifiedEmail: 'admin@demo.seams.local',
      },
      invitation: {
        email: 'admin@demo.seams.local',
        role: 'ADMIN' as const,
        adminPermissions: [
          'members.manage',
          'projects.manage',
          'billing.view',
          'billing.manage',
        ] as const,
      },
    },
    {
      account: {
        userId: 'console-operator',
        verifiedEmail: 'operator@demo.seams.local',
      },
      invitation: {
        email: 'operator@demo.seams.local',
        role: 'MEMBER' as const,
        projectAccess: [{ projectId: input.projectId, accessLevel: 'editor' as const }],
      },
    },
  ];

  for (const member of seedMembers) {
    try {
      const issued = await input.organizationAccess.invite(seedCtx, member.invitation);
      await input.organizationAccess.acceptInvitation(member.account, issued.invitation.id, {
        token: issued.token,
      });
    } catch (error: unknown) {
      if (
        !hasConsoleErrorCode(error, 'membership_already_exists') &&
        !hasConsoleErrorCode(error, 'invitation_already_exists')
      ) {
        throw error;
      }
    }
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

async function seedDemoConsoleWallets(input: {
  wallets: ConsoleWalletService;
  seeds: ConsoleWallet[];
  logger: Pick<Console, 'log'>;
}): Promise<void> {
  if (!input.wallets.upsertWallet) {
    throw new Error('Console demo wallet seeding requires wallet upsert support');
  }

  let created = 0;
  let skipped = 0;
  const upsertWallet = input.wallets.upsertWallet.bind(input.wallets);
  for (const wallet of input.seeds) {
    const ctx = {
      orgId: wallet.orgId,
      actorUserId: 'console-seed-owner',
      projectId: wallet.projectId,
      environmentId: wallet.environmentId,
    };
    const existing = await input.wallets.getWallet(ctx, wallet.id);
    if (existing) {
      skipped += 1;
      continue;
    }
    await upsertWallet(ctx, {
      id: wallet.id,
      projectId: wallet.projectId,
      environmentId: wallet.environmentId,
      userId: wallet.userId,
      externalRefId: wallet.externalRefId,
      address: wallet.address,
      chain: wallet.chain,
      walletType: wallet.walletType,
      status: wallet.status,
      policyId: wallet.policyId,
      balanceMinor: wallet.balanceMinor,
      lastActivityAt: wallet.lastActivityAt,
      createdAt: wallet.createdAt,
      updatedAt: wallet.updatedAt,
    });
    created += 1;
  }
  input.logger.log(
    `[console-demo-seed] wallets=${created} skipped=${skipped} storage=wallet-service`,
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
    projectId: input.projectId,
    environmentId: input.environmentId,
  };
  const approverCtx = {
    orgId: input.orgId,
    actorUserId: 'console-owner',
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
  const sessionCookieName = String(env.SESSION_COOKIE_NAME || 'seams-jwt').trim() || 'seams-jwt';
  const jwtSession = createJwtSession(sessionCookieName);
  const redisUrl = typeof env.REDIS_URL === 'string' ? env.REDIS_URL.trim() : '';
  const { stripeWebhookSigningSecret } = resolveWebServerConsoleConfig(
    env as Record<string, unknown>,
  );
  const host =
    typeof env.HOST === 'string' && env.HOST.trim().length > 0 ? env.HOST.trim() : undefined;
  const config = {
    port: Number(env.PORT || 3000),
    host,
    expectedOrigin: env.EXPECTED_ORIGIN || 'https://localhost', // Frontend origin
    expectedWalletOrigin: env.EXPECTED_WALLET_ORIGIN || 'https://localhost:8443', // Wallet origin (optional)
  };
  const startupHost = config.host || '0.0.0.0';
  console.log(`[web-server] startup target http://${startupHost}:${config.port}`);
  if (String(env.ACCOUNT_ID_DERIVATION_SECRET || '').trim()) {
    console.log('[web-server] Hosted account-id derivation: configured');
  } else {
    console.warn('[web-server] ACCOUNT_ID_DERIVATION_SECRET is not set');
  }
  const configuredSponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromEnv(env);
  if (configuredSponsoredEvmCallConfig) {
    throw new Error(
      'Node web-server sponsored EVM execution was removed for Refactor 82. Use the Cloudflare D1/DO Worker for prepaid sponsored gas settlement.',
    );
  }
  const sponsorshipPricingEnv = {
    SPONSORED_EXECUTION_REAL_PRICING_JSON: env.SPONSORED_EXECUTION_REAL_PRICING_JSON,
    SPONSORED_EXECUTION_STATIC_PRICING_JSON: env.SPONSORED_EXECUTION_STATIC_PRICING_JSON,
  };
  const sponsorshipRealPricing = resolveSponsoredExecutionPricingFromEnv({
    SPONSORED_EXECUTION_REAL_PRICING_JSON:
      sponsorshipPricingEnv.SPONSORED_EXECUTION_REAL_PRICING_JSON,
  });
  const sponsorshipStaticPricing =
    resolveStaticSponsoredExecutionPricingFromEnv(sponsorshipPricingEnv);
  const sponsorshipPricing = sponsorshipRealPricing || sponsorshipStaticPricing;
  const hasStaticSponsorshipPricingConfig = Boolean(
    String(env.SPONSORED_EXECUTION_STATIC_PRICING_JSON || '').trim(),
  );
  const tempoOnboardingFaucetContractRaw = String(
    env.TEMPO_ONBOARDING_FAUCET_CONTRACT || '',
  ).trim();
  if (hasStaticSponsorshipPricingConfig && !sponsorshipStaticPricing) {
    console.warn(
      '[sponsorship-pricing] SPONSORED_EXECUTION_STATIC_PRICING_JSON is invalid; static spend pricing is disabled',
    );
  }
  const thresholdStore = {
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    // Node role + coordinator/cosigner wiring (optional)
    THRESHOLD_NODE_ROLE: env.THRESHOLD_NODE_ROLE,
    THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    THRESHOLD_COORDINATOR_INSTANCE_ID: env.THRESHOLD_COORDINATOR_INSTANCE_ID,
    THRESHOLD_COORDINATOR_PEERS: env.THRESHOLD_COORDINATOR_PEERS,
    UPSTASH_REDIS_REST_URL: env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: env.UPSTASH_REDIS_REST_TOKEN,
    REDIS_URL: redisUrl || undefined,
    // Optional key prefixes (useful when sharing a single database)
    THRESHOLD_ED25519_KEYSTORE_PREFIX: env.THRESHOLD_ED25519_KEYSTORE_PREFIX,
    THRESHOLD_ED25519_SESSION_PREFIX: env.THRESHOLD_ED25519_SESSION_PREFIX,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: env.ROUTER_AB_NORMAL_SIGNING_WORKER_ID,
    ROUTER_AB_SIGNING_WORKER_URL: env.ROUTER_AB_SIGNING_WORKER_URL,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: env.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
    SIGNING_SESSION_SEAL_ROOT_SECRET_B64U: env.SIGNING_SESSION_SEAL_ROOT_SECRET_B64U,
    SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION: env.SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION,
    SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS:
      env.SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS,
  } as const satisfies ThresholdStoreConfigInput;

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
    githubOAuth: {
      GITHUB_OAUTH_CLIENT_ID: env.GITHUB_OAUTH_CLIENT_ID,
      GITHUB_OAUTH_CLIENT_SECRET: env.GITHUB_OAUTH_CLIENT_SECRET,
      GITHUB_OAUTH_CALLBACK_URL: env.GITHUB_OAUTH_CALLBACK_URL,
    },
  });

  console.log('[web-server] warming registration runtime');
  await authService.warmRegistrationRuntime();

  const app: Express = express();
  const consoleDemoSeedEnabled = parseBooleanFlagWithDefault(env.CONSOLE_DEMO_SEED_ENABLED, true);
  const configuredConsoleDemoOrgId = String(env.CONSOLE_DEMO_ORG_ID || '').trim();
  const consoleDemoProjectId =
    String(env.CONSOLE_DEMO_PROJECT_ID || 'proj_console_core').trim() || 'proj_console_core';
  const consoleDemoEnvironmentId =
    String(env.CONSOLE_DEMO_ENVIRONMENT_ID || `${consoleDemoProjectId}-prod`).trim() ||
    `${consoleDemoProjectId}-prod`;
  if (String(env.STRIPE_API_SK || '').trim()) {
    throw new Error(
      'STRIPE_API_SK requires the durable D1 console billing service; live Stripe cannot use in-memory billing state',
    );
  }
  const consoleBilling: ConsoleBillingService = createInMemoryConsoleBillingService();
  const consoleAudit: ConsoleAuditService = createInMemoryConsoleAuditService({
    seedDemoData: consoleDemoSeedEnabled,
  });
  const consoleOrgProjectEnvBase: ConsoleOrgProjectEnvService =
    createInMemoryConsoleOrgProjectEnvService();
  const consoleApiKeys: ConsoleApiKeyService = createInMemoryConsoleApiKeyService({
    scopeValidation: WALLET_API_CREDENTIAL_SCOPE_VALIDATION,
  });
  const consolePolicies: ConsolePolicyService = createInMemoryConsolePolicyService();
  const consoleApprovals: ConsoleApprovalService = createInMemoryConsoleApprovalService();
  const consoleRuntimeSnapshots: ConsoleRuntimeSnapshotService =
    createInMemoryConsoleRuntimeSnapshotService();
  const consoleOrganizationAccess: ConsoleOrganizationAccessService =
    createInMemoryConsoleOrganizationAccessService();
  const consoleWallets: ConsoleWalletService = createInMemoryConsoleWalletService();
  const consoleSponsoredCalls: ConsoleSponsoredCallService =
    createInMemoryConsoleSponsoredCallService();
  const consoleBillingPrepaidReservations: ConsoleBillingPrepaidReservationService =
    createInMemoryConsoleBillingPrepaidReservationService();
  const consoleSponsorshipSpendCaps: ConsoleSponsorshipSpendCapService =
    createInMemoryConsoleSponsorshipSpendCapService();
  const consoleDemoOrgId = await resolveConsoleDemoOrgId({
    configuredOrgId: configuredConsoleDemoOrgId,
    orgProjectEnv: consoleOrgProjectEnvBase,
    logger: console,
  });
  const demoWalletSeeds = consoleDemoOrgId
    ? buildDemoConsoleWalletSeeds({
        orgId: consoleDemoOrgId,
        projectId: consoleDemoProjectId,
        environmentId: consoleDemoEnvironmentId,
      })
    : [];

  const normalizedOnboardingContractAddress = (() => {
    const value = tempoOnboardingFaucetContractRaw;
    return /^0x[0-9a-fA-F]{40}$/.test(value)
      ? (value as `0x${string}`)
      : DEFAULT_TEMPO_ONBOARDING_CONTRACT;
  })();
  const consoleOrgProjectEnv = createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship({
    base: consoleOrgProjectEnvBase,
    policies: consolePolicies,
    runtimeSnapshots: consoleRuntimeSnapshots,
    faucetContractAddress: normalizedOnboardingContractAddress,
  });

  const consoleObservability: ConsoleObservabilityService =
    createInMemoryConsoleObservabilityService();
  const consoleObservabilityIngestion: ConsoleObservabilityIngestionService | null = null;
  const consoleWebhooks: ConsoleWebhookService = createInMemoryConsoleWebhookService({
    categoryValidation: WALLET_CONSOLE_WEBHOOK_EVENT_CATEGORY_VALIDATION,
    observabilityIngestion: consoleObservabilityIngestion,
    observabilityLogger: console as any,
  } as any);
  const consoleOnboarding = createInMemoryConsoleOnboardingService({
    orgProjectEnv: consoleOrgProjectEnv,
    apiKeys: consoleApiKeys,
    organizationAccess: consoleOrganizationAccess,
  });
  const consoleAccount: ConsoleAccountService = createInMemoryConsoleAccountService({
    orgProjectEnv: consoleOrgProjectEnv,
    organizationAccess: consoleOrganizationAccess,
    onboarding: consoleOnboarding,
    wallets: consoleWallets,
  });
  const consoleAuth = createAppSessionConsoleAuthAdapter({
    session: jwtSession,
    organizationAccess: consoleOrganizationAccess,
    ...(consoleDemoOrgId ? { defaultOrgId: consoleDemoOrgId } : {}),
    platformSupportEmails: env.CONSOLE_PLATFORM_SUPPORT_EMAILS,
    provisioning: {
      orgProjectEnv: consoleOrgProjectEnv,
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
        organizationAccess: consoleOrganizationAccess,
        orgId: consoleDemoOrgId,
        projectId: consoleDemoProjectId,
        environmentId: consoleDemoEnvironmentId,
        logger: console,
      });
      await seedDemoConsoleWallets({
        wallets: consoleWallets,
        seeds: demoWalletSeeds,
        logger: console,
      });
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

  app.use((_req, res, next) => {
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
    next();
  });

  app.use(express.json({ limit: '1mb', verify: captureRawJsonBody }));

  // Mount console/admin router on /console/*
  const consoleRouter = createConsoleRouter({
    healthz: true,
    readyz: true,
    corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
    auth: consoleAuth,
    session: jwtSession,
    billing: consoleBilling,
    billingStripeWebhookSigningSecret: toOptionalSecret(stripeWebhookSigningSecret),
    webhooks: consoleWebhooks,
    apiKeys: consoleApiKeys,
    approvals: consoleApprovals,
    policies: consolePolicies,
    runtimeSnapshots: consoleRuntimeSnapshots,
    onboarding: consoleOnboarding,
    account: consoleAccount,
    orgProjectEnv: consoleOrgProjectEnv,
    organizationAccess: consoleOrganizationAccess,
    wallets: consoleWallets,
    audit: consoleAudit,
    observability: consoleObservability,
    observabilityIngestion: consoleObservabilityIngestion,
    logger: console,
  }) as unknown as RequestHandler;
  app.use('/', consoleRouter);

  const onListening = () => {
    const boundAddress = server?.address();
    if (boundAddress && typeof boundAddress === 'object') {
      const host = boundAddress.address || config.host || 'localhost';
      const printableHost = host.includes(':') ? `[${host}]` : host;
      console.log(`[web-server] listening on http://${printableHost}:${boundAddress.port}`);
    } else {
      const listenHost = config.host || 'localhost';
      console.log(`[web-server] listening on http://${listenHost}:${config.port}`);
    }
    console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
    console.log(
      `Sponsored spend pricing: ${
        sponsorshipRealPricing
          ? 'real_configured'
          : sponsorshipStaticPricing
            ? 'static_configured'
            : hasStaticSponsorshipPricingConfig
              ? 'invalid'
              : 'disabled'
      }`,
    );
    console.log('Console backend: memory');
    console.log('Console routes mounted at /console/*');
    console.log('Console session auth: app_session_v1 cookie/JWT with live organization access');
    console.log(
      `Console demo seed: ${consoleDemoSeedEnabled ? 'enabled' : 'disabled'} (org=${consoleDemoOrgId || 'unresolved'})`,
    );
    console.log('Console Stripe provider mode: mock (in-memory console)');
    console.log(
      `Console billing Stripe webhook signing secret: ${
        stripeWebhookSigningSecret ? 'configured' : 'not configured'
      }`,
    );
    authService
      .getRelayerAccount()
      .then((relayer) =>
        console.log(`AuthService started with relayer account: ${relayer.accountId}`),
      )
      .catch((err: Error) => console.error('AuthService initial check failed:', err));
  };

  const requestedListenHost = config.host || '0.0.0.0';
  console.log('[web-server] startup complete, binding http listener');
  console.log(`[web-server] attempting listen on http://${requestedListenHost}:${config.port}`);
  server = config.host
    ? app.listen(config.port, config.host, onListening)
    : app.listen(config.port, onListening);
  server.on('error', (error: Error) => {
    console.error(
      `[web-server] failed to listen on http://${requestedListenHost}:${config.port}`,
      error,
    );
  });
}

main().catch((err) => {
  console.error('[web-server] fatal startup error:', err);
  process.exit(1);
});
