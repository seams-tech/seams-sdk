import type { D1DatabaseLike } from '@seams/wallet-server/cloud-host';
import { createWalletConsoleRouter } from '../consoleComposition';
import { HostedConsoleAuthHandler } from '../hostedConsoleAuth';
import { createWalletConsoleOpsHandler } from '../../serviceBinding/walletConsoleOpsHandler';
import { createWalletRuntimeOpsClient } from '../../serviceBinding/walletRuntimeOpsClient';
import type { WalletRuntimeServiceBinding } from '../../serviceBinding/walletRuntimeOps';
import { createWalletConsoleRelayHandler } from '../../serviceBinding/walletConsoleRelay';
import {
  createConsoleRouterApiRouteExtensions,
  DEFAULT_SIGNED_DELEGATE_ROUTE,
} from '../routeExtensions';
import { DEFAULT_SPONSORED_EVM_CALL_ROUTE } from '../../sponsorship/evmRoutes';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '../../sponsorship/evmWorkerExecutionAdapter';
import { resolveSponsoredExecutionPricingFromEnv } from '../../sponsorship/pricing';
import { createWalletProjectEnvironmentResolver } from '../projectEnvironmentAdapter';
import {
  createRouterApiBillingUsageMeterAdapter,
  createRouterApiKeyAuthAdapter,
  createRouterApiPublishableKeyAuthAdapter,
} from '@seams-internal/wallet-console-server/router/routerApiKeyAuth';
import {
  createConsoleProviderIdentity,
  type ConsoleGithubOAuthConfig,
} from '@seams-internal/console-server/boundary/providerIdentity';
import {
  consoleCoreServicesFromBundle,
  createCloudflareD1ConsoleOnlyServiceBundle,
  walletConsoleServicesFromBundle,
} from './d1ConsoleServices';
import type {
  CfExecutionContext,
  CfScheduledEvent,
  FetchHandler,
  ScheduledHandler,
} from '@seams/wallet-server/cloud-host';
import {
  createConsoleSessionAuthAdapter,
  createHmacSessionAdapterFromEnv,
  readEnvString,
  requireEnvString,
  type CloudflareD1StagingSessionEnv,
} from './d1StagingSession';
import { requireStripeBillingProviderAdaptersFromEnv } from '@seams-internal/console-server/billing/stripeProvider';
import { createCloudflareCron, resolveCloudflareConsoleEmailDispatchCronOptions } from './cron';
import type { RouterApiCloudflareConsoleWorkerEnv } from './cloudflareConsole.types';

interface CloudflareD1ConsoleStagingEnv
  extends CloudflareD1StagingSessionEnv, RouterApiCloudflareConsoleWorkerEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly WALLET_RUNTIME: WalletRuntimeServiceBinding;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
  readonly CONSOLE_BASE_URL?: string;
  readonly CONSOLE_SESSION_HMAC_SECRET?: string;
  readonly CONSOLE_SESSION_COOKIE_NAME?: string;
  readonly CONSOLE_SESSION_ISSUER?: string;
  readonly CONSOLE_SESSION_AUDIENCE?: string;
  readonly CONSOLE_DEFAULT_ORG_ID?: string;
  readonly CONSOLE_DEFAULT_PROJECT_ID?: string;
  readonly CONSOLE_DEFAULT_ENVIRONMENT_ID?: string;
  readonly CONSOLE_PLATFORM_SUPPORT_EMAILS?: string;
  readonly STRIPE_API_SK?: string;
  readonly STRIPE_WEBHOOK_SECRET?: string;
  readonly STRIPE_API_BASE_URL?: string;
  readonly STRIPE_API_TIMEOUT_MS?: string;
  readonly GOOGLE_OIDC_CLIENT_ID?: string;
  readonly GITHUB_OAUTH_CLIENT_ID?: string;
  readonly GITHUB_OAUTH_CLIENT_SECRET?: string;
  readonly GITHUB_OAUTH_CALLBACK_URL?: string;
  readonly CONSOLE_CORS_ORIGINS?: string;
  readonly SPONSORED_EVM_EXECUTORS_JSON?: string;
  readonly SPONSORED_EXECUTION_REAL_PRICING_JSON?: string;
  readonly SPONSORED_EXECUTION_STATIC_PRICING_JSON?: string;
}

function consoleGithubOAuthConfig(
  env: CloudflareD1ConsoleStagingEnv,
): ConsoleGithubOAuthConfig | undefined {
  const clientId = readEnvString(env, 'GITHUB_OAUTH_CLIENT_ID');
  const clientSecret = readEnvString(env, 'GITHUB_OAUTH_CLIENT_SECRET');
  const callbackUrl = readEnvString(env, 'GITHUB_OAUTH_CALLBACK_URL');
  if (!clientId || !clientSecret || !callbackUrl) return undefined;
  return { clientId, clientSecret, callbackUrl };
}

function consoleCorsOrigins(env: CloudflareD1ConsoleStagingEnv): string[] {
  return String(env.CONSOLE_CORS_ORIGINS || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

type ConsoleReadyRow = {
  readonly table_count?: unknown;
};

const CONSOLE_STAGING_READY_TABLES = Object.freeze([
  'organizations',
  'projects',
  'environments',
  'organization_memberships',
  'organization_admin_permissions',
  'organization_invitations',
  'project_member_access',
  'organization_owner_events',
  'billing_accounts',
  'billing_prepaid_reservations',
  'billing_stripe_post_processing_outbox',
  'sponsorship_pricing_rules',
  'sponsored_call_records',
  'runtime_snapshot_outbox',
  'console_email_outbox',
  'console_email_deliveries',
]);

async function createConsoleHandler(env: CloudflareD1ConsoleStagingEnv): Promise<FetchHandler> {
  const namespace = requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE');
  const emailDispatch = resolveCloudflareConsoleEmailDispatchCronOptions({
    env,
    database: env.CONSOLE_DB,
    namespace,
    ensureSchema: false,
    invitationDelivery: { kind: 'ENABLED' },
  });
  const invitationSecretCipher = emailDispatch.invitationSecretCipher;
  if (!invitationSecretCipher) {
    throw new Error('Console invitation email cipher was not configured');
  }
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const bundle = await createCloudflareD1ConsoleOnlyServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
    },
    route: {
      namespace,
    },
    adapters: {
      ensureSchema: false,
      billingProviders: requireStripeBillingProviderAdaptersFromEnv(env),
      billingEmailConsoleBaseUrl: requireEnvString(env, 'CONSOLE_BASE_URL'),
      organizationEmail: {
        invitationSecretCipher,
        consoleBaseUrl: requireEnvString(env, 'CONSOLE_BASE_URL'),
      },
      sponsoredEvmCallConfig,
      resolveSponsoredEvmExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
      sponsorshipPricing: resolveSponsoredExecutionPricingFromEnv(env),
    },
  });
  const session = createHmacSessionAdapterFromEnv({
    env,
    secretName: 'CONSOLE_SESSION_HMAC_SECRET',
    cookieName: readEnvString(env, 'CONSOLE_SESSION_COOKIE_NAME'),
    issuer: readEnvString(env, 'CONSOLE_SESSION_ISSUER'),
    audience: readEnvString(env, 'CONSOLE_SESSION_AUDIENCE'),
  });
  const auth = createConsoleSessionAuthAdapter({
    session,
    organizationAccess: bundle.organizationAccess,
    defaultOrgId: readEnvString(env, 'CONSOLE_DEFAULT_ORG_ID'),
    defaultProjectId: readEnvString(env, 'CONSOLE_DEFAULT_PROJECT_ID'),
    defaultEnvironmentId: readEnvString(env, 'CONSOLE_DEFAULT_ENVIRONMENT_ID'),
    platformSupportEmails: readEnvString(env, 'CONSOLE_PLATFORM_SUPPORT_EMAILS'),
  });
  const router = createWalletConsoleRouter({
    core: consoleCoreServicesFromBundle(bundle),
    walletConsole: walletConsoleServicesFromBundle(bundle),
    auth,
    readyCheck: createConsoleReadyCheck(env),
    billingStripeWebhookSigningSecret: requireEnvString(env, 'STRIPE_WEBHOOK_SECRET'),
  });
  const walletRuntime = createWalletRuntimeOpsClient(env.WALLET_RUNTIME);
  const relayHandler = createWalletConsoleRelayHandler(
    createConsoleRouterApiRouteExtensions({
      apiKeyAuth: createRouterApiKeyAuthAdapter(bundle.apiKeys),
      wallets: bundle.wallets,
      signedDelegate: {
        route: DEFAULT_SIGNED_DELEGATE_ROUTE,
        authService: walletRuntime,
        billing: bundle.billing,
        ledger: bundle.sponsoredCalls,
        runtimeSnapshots: bundle.runtimeSnapshots,
        publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(bundle.apiKeys),
        observabilityIngestion: bundle.observabilityIngestion,
        prepaidReservations: bundle.prepaidReservations,
        pricing: bundle.sponsorshipPricing,
        spendCaps: bundle.spendCaps,
        webhooks: bundle.webhooks,
      },
      ...(sponsoredEvmCallConfig
        ? {
            sponsoredEvmCall: {
              route: DEFAULT_SPONSORED_EVM_CALL_ROUTE,
              publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(bundle.apiKeys),
              billing: bundle.billing,
              ledger: bundle.sponsoredCalls,
              runtimeSnapshots: bundle.runtimeSnapshots,
              config: sponsoredEvmCallConfig,
              resolveExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
              observabilityIngestion: bundle.observabilityIngestion,
              prepaidReservations: bundle.prepaidReservations,
              pricing: bundle.sponsorshipPricing,
              spendCaps: bundle.spendCaps,
              webhooks: bundle.webhooks,
            },
          }
        : {}),
    }),
  );
  // Private service-binding target: exactly the four declared Wallet Console
  // operations, served ahead of the console router.
  const opsHandler = createWalletConsoleOpsHandler({
    apiKeyAuth: createRouterApiKeyAuthAdapter(bundle.apiKeys),
    publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(bundle.apiKeys),
    usageMeter: createRouterApiBillingUsageMeterAdapter(bundle.billing, {
      orgProjectEnv: bundle.orgProjectEnv,
      wallets: bundle.wallets,
    }),
    projectEnvironments: createWalletProjectEnvironmentResolver(bundle.orgProjectEnv),
  });
  const routerWithOps: FetchHandler = async (request, workerEnv, ctx) => {
    const opsResponse = await opsHandler(request);
    if (opsResponse) return opsResponse;
    const relayResponse = await relayHandler(request, ctx);
    if (relayResponse) return relayResponse;
    return await router(request, workerEnv, ctx);
  };
  // The Console Worker owns /console/auth/* end-to-end: provider verification
  // is Console-owned (no signer D1, Wasm, or identity-link store involved).
  const authHandler = new HostedConsoleAuthHandler({
    handler: routerWithOps,
    identity: createConsoleProviderIdentity({
      googleOidcClientId: readEnvString(env, 'GOOGLE_OIDC_CLIENT_ID'),
      githubOAuth: consoleGithubOAuthConfig(env),
    }),
    session,
    organizationAccess: bundle.organizationAccess,
    orgProjectEnv: bundle.orgProjectEnv,
    scope: {
      orgId: requireEnvString(env, 'CONSOLE_DEFAULT_ORG_ID'),
      projectId: requireEnvString(env, 'CONSOLE_DEFAULT_PROJECT_ID'),
      envId: requireEnvString(env, 'CONSOLE_DEFAULT_ENVIRONMENT_ID'),
    },
    initialOwner: readEnvString(env, 'CONSOLE_INITIAL_OWNER_EMAIL')
      ? {
          kind: 'configured_google_email',
          email: readEnvString(env, 'CONSOLE_INITIAL_OWNER_EMAIL'),
        }
      : { kind: 'first_verified_google' },
    corsOrigins: consoleCorsOrigins(env),
  });
  return authHandler.fetch.bind(authHandler);
}

function consoleHandler(env: CloudflareD1ConsoleStagingEnv): Promise<FetchHandler> {
  return createConsoleHandler(env);
}

function createConsoleReadyCheck(env: CloudflareD1ConsoleStagingEnv): () => Promise<void> {
  const check = new ConsoleStagingReadyCheck(env);
  return check.check.bind(check);
}

class ConsoleStagingReadyCheck {
  constructor(private readonly env: CloudflareD1ConsoleStagingEnv) {}

  async check(): Promise<void> {
    await assertD1Tables({
      database: this.env.CONSOLE_DB,
      label: 'CONSOLE_DB',
      tables: CONSOLE_STAGING_READY_TABLES,
    });
  }
}

async function assertD1Tables(input: {
  readonly database: D1DatabaseLike;
  readonly label: string;
  readonly tables: readonly string[];
}): Promise<void> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS table_count
         FROM sqlite_master
        WHERE type = 'table'
          AND name IN (${d1StringList(input.tables)})`,
    )
    .first<ConsoleReadyRow>();
  const count = Number(row?.table_count || 0);
  if (count !== input.tables.length) {
    throw new Error(
      `${input.label} migration has created ${count} of ${input.tables.length} staging-ready tables`,
    );
  }
}

function d1StringList(values: readonly string[]): string {
  return values.map(d1StringLiteral).join(', ');
}

function d1StringLiteral(value: string): string {
  if (!/^[a-z0-9_]+$/.test(value)) {
    throw new Error(`invalid D1 table name ${value}`);
  }
  return `'${value}'`;
}

async function fetch(
  request: Request,
  env: CloudflareD1ConsoleStagingEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  const handler = await consoleHandler(env);
  return await handler(request, env, ctx);
}

function consoleScheduledHandler(env: CloudflareD1ConsoleStagingEnv): ScheduledHandler {
  const namespace = requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE');
  return createCloudflareCron({
    consoleEmailDispatch: resolveCloudflareConsoleEmailDispatchCronOptions({
      env,
      database: env.CONSOLE_DB,
      namespace,
      ensureSchema: false,
      invitationDelivery: { kind: 'ENABLED' },
    }),
  });
}

async function scheduled(
  event: CfScheduledEvent,
  env: CloudflareD1ConsoleStagingEnv,
  ctx: CfExecutionContext,
): Promise<void> {
  const handler = consoleScheduledHandler(env);
  await handler(event, env, ctx);
}

export default { fetch, scheduled };
