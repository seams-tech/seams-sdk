import type { D1DatabaseLike } from '@seams/wallet-server/cloud-host';
import { createWalletConsoleRouter } from '../consoleComposition';
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
  return createWalletConsoleRouter({
    core: consoleCoreServicesFromBundle(bundle),
    walletConsole: walletConsoleServicesFromBundle(bundle),
    auth,
    readyCheck: createConsoleReadyCheck(env),
    billingStripeWebhookSigningSecret: requireEnvString(env, 'STRIPE_WEBHOOK_SECRET'),
  });
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
