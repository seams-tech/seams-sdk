import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { createCloudflareConsoleRouter } from './createCloudflareConsoleRouter';
import { createCloudflareD1ConsoleOnlyServiceBundle } from './d1ConsoleServices';
import type { CfExecutionContext, FetchHandler } from './cloudflare.types';
import {
  createConsoleSessionAuthAdapter,
  createHmacSessionAdapterFromEnv,
  readEnvString,
  requireEnvString,
  type CloudflareD1StagingSessionEnv,
} from './d1StagingSession';

interface CloudflareD1ConsoleStagingEnv extends CloudflareD1StagingSessionEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
  readonly CONSOLE_SESSION_HMAC_SECRET?: string;
  readonly CONSOLE_SESSION_COOKIE_NAME?: string;
  readonly CONSOLE_SESSION_ISSUER?: string;
  readonly CONSOLE_SESSION_AUDIENCE?: string;
  readonly CONSOLE_DEFAULT_ORG_ID?: string;
  readonly CONSOLE_DEFAULT_PROJECT_ID?: string;
  readonly CONSOLE_DEFAULT_ENVIRONMENT_ID?: string;
  readonly CONSOLE_PLATFORM_ADMIN_EMAILS?: string;
}

type ConsoleReadyRow = {
  readonly table_count?: unknown;
};

const CONSOLE_STAGING_READY_TABLES = Object.freeze([
  'organizations',
  'projects',
  'environments',
  'team_members',
  'billing_accounts',
  'billing_prepaid_reservations',
  'sponsorship_pricing_rules',
  'sponsored_call_records',
  'runtime_snapshot_outbox',
]);

async function createConsoleHandler(env: CloudflareD1ConsoleStagingEnv): Promise<FetchHandler> {
  const namespace = requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE');
  const bundle = await createCloudflareD1ConsoleOnlyServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
    },
    route: {
      namespace,
    },
    adapters: {
      ensureSchema: false,
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
    teamRbac: bundle.teamRbac,
    defaultOrgId: readEnvString(env, 'CONSOLE_DEFAULT_ORG_ID'),
    defaultProjectId: readEnvString(env, 'CONSOLE_DEFAULT_PROJECT_ID'),
    defaultEnvironmentId: readEnvString(env, 'CONSOLE_DEFAULT_ENVIRONMENT_ID'),
    platformAdminEmails: readEnvString(env, 'CONSOLE_PLATFORM_ADMIN_EMAILS'),
  });
  return createCloudflareConsoleRouter({
    ...bundle.consoleRouterOptions,
    healthz: true,
    readyz: true,
    auth,
    readyCheck: createConsoleReadyCheck(env),
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

export default { fetch };
