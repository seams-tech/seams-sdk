import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export type D1StagingConfigPaths = {
  readonly consoleConfigPath: string;
  readonly gatewayConfigPath: string;
};

export type D1StagingCommandResult = {
  readonly command: string;
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
};

export type D1StagingCommandRunner = (command: string) => D1StagingCommandResult;

export const D1_STAGING_GENERATED_AT_ISO = '2026-06-28T00:00:00.000Z';
export const D1_STAGING_CONSOLE_ORIGIN = 'https://console.staging.example';
export const D1_STAGING_GATEWAY_ORIGIN = 'https://gateway.staging.example';
export const D1_STAGING_REPO_ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../..',
);
export const D1_STAGING_PACKAGE_ROOT = path.join(
  D1_STAGING_REPO_ROOT,
  'packages/console-server-ts',
);

export async function loadD1StagingScriptModule<T>(scriptFileName: string): Promise<T> {
  const scriptPath = path.join(D1_STAGING_PACKAGE_ROOT, 'scripts', scriptFileName);
  return (await import(pathToFileURL(scriptPath).href)) as T;
}

export function d1StagingPackagePath(...segments: string[]): string {
  return path.join(D1_STAGING_PACKAGE_ROOT, ...segments);
}

export function d1StagingUnquoteShellToken(input: string): string {
  if (input.startsWith("'") && input.endsWith("'")) return input.slice(1, -1);
  return input;
}

export function d1StagingCommandResult(
  command: string,
  input: {
    readonly status?: number;
    readonly stdout?: string;
    readonly stderr?: string;
  } = {},
): D1StagingCommandResult {
  return {
    command,
    status: input.status ?? 0,
    stdout: input.stdout ?? '',
    stderr: input.stderr ?? '',
  };
}

export function d1StagingJsonCommandResult(
  command: string,
  value: unknown,
  input: { readonly status?: number; readonly stderr?: string } = {},
): D1StagingCommandResult {
  return d1StagingCommandResult(command, { ...input, stdout: JSON.stringify(value) });
}

export function d1StagingOkCommandRunner(command: string): D1StagingCommandResult {
  return d1StagingCommandResult(command, { stdout: 'ok' });
}

export function d1StagingFailedCommandResult(
  command: string,
  stderr: string,
  stdout = '',
): D1StagingCommandResult {
  return d1StagingCommandResult(command, { status: 1, stdout, stderr });
}

export function writeD1StagingTempFile(prefix: string, fileName: string, source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  const filePath = path.join(dir, fileName);
  fs.writeFileSync(filePath, source);
  return filePath;
}

export function writeD1StagingPackageFile(relativePath: string, source: string): void {
  const filePath = path.join(D1_STAGING_PACKAGE_ROOT, relativePath);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, source);
}

export function readD1StagingJsonFile(filePath: string): Record<string, unknown> {
  return JSON.parse(fs.readFileSync(filePath, 'utf8')) as Record<string, unknown>;
}

export function d1StagingManifestPath(prefix: string): string {
  return path.join(os.tmpdir(), `${prefix}-${Date.now()}.json`);
}

export function d1StagingRequestUrl(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  if (input instanceof URL) return input.href;
  return input.url;
}

export function d1StagingJsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

export function writeValidD1StagingConfigFiles(prefix: string): D1StagingConfigPaths {
  return {
    consoleConfigPath: writeD1StagingTempFile(
      prefix,
      'wrangler.d1-staging-console.toml',
      validD1ConsoleStagingConfig(),
    ),
    gatewayConfigPath: writeD1StagingTempFile(
      prefix,
      'wrangler.d1-staging-gateway.toml',
      validD1GatewayStagingConfig(),
    ),
  };
}

export function writeMisScopedConsoleD1StagingConfigFiles(prefix: string): D1StagingConfigPaths {
  return {
    consoleConfigPath: writeD1StagingTempFile(
      prefix,
      'wrangler.d1-staging-console.toml',
      validD1GatewayStagingConfig(),
    ),
    gatewayConfigPath: writeD1StagingTempFile(
      prefix,
      'wrangler.d1-staging-gateway.toml',
      validD1GatewayStagingConfig(),
    ),
  };
}

export function validD1ConsoleStagingConfig(): string {
  return `
name = "seams-sdk-d1-console-staging"
main = "src/router/cloudflare/d1ConsoleStagingWorker.ts"
compatibility_date = "2026-04-17"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console-staging-nrt"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[vars]
SEAMS_TENANT_STORAGE_NAMESPACE = "seams-staging"
CONSOLE_SESSION_ISSUER = "seams-console-staging-nrt"
CONSOLE_SESSION_AUDIENCE = "seams-console-dashboard"

[secrets]
required = ["CONSOLE_SESSION_HMAC_SECRET", "STRIPE_API_SK", "STRIPE_WEBHOOK_SECRET"]
`;
}

export function validD1GatewayStagingConfig(): string {
  return `
name = "seams-sdk-d1-gateway-staging"
main = "src/router/cloudflare/d1RouterApiStagingWorker.ts"
compatibility_date = "2026-04-17"
compatibility_flags = ["nodejs_compat"]

[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console-staging-nrt"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer-staging-nrt"
database_id = "22222222-2222-4222-8222-222222222222"
migrations_dir = "node_modules/@seams/sdk-server/migrations/d1-signer"

[[services]]
binding = "SIGNING_WORKER"
service = "router-ab-signing-worker-staging"

[[services]]
binding = "MPC_ROUTER"
service = "router-ab-mpc-router-staging"

[vars]
SEAMS_TENANT_STORAGE_NAMESPACE = "seams-staging"
SEAMS_STAGING_ORG_ID = "org_staging"
SEAMS_STAGING_PROJECT_ID = "project_staging"
SEAMS_STAGING_ENV_ID = "staging"
ROUTER_AB_NORMAL_SIGNING_WORKER_ID = "router-ab-signing-worker-staging"
SIGNING_WORKER_ID = "router-ab-signing-worker-staging"
DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY = "x25519:1111111111111111111111111111111111111111111111111111111111111111"
DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY = "x25519:2222222222222222222222222222222222222222222222222222222222222222"
SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY = "x25519:3333333333333333333333333333333333333333333333333333333333333333"
RELAYER_ACCOUNT_ID = "seams-relayer-staging.testnet"
RELAYER_PUBLIC_KEY = "ed25519:11111111111111111111111111111111"
ROUTER_AB_CEREMONY_JWT_KEY_ID = "router-ab-ceremony-staging-r1"
ROUTER_AB_CEREMONY_JWT_ISSUER = "https://seams-gateway-staging.example"
ROUTER_AB_CEREMONY_JWT_AUDIENCE = "router-ab"
LINKED_DEVICE_WEBAUTHN_RP_ID = "wallet.staging.example"
LINKED_DEVICE_WEBAUTHN_ORIGIN = "https://app.staging.example"
SPONSORED_EXECUTION_REAL_PRICING_JSON = '{"provider":"outlayer","nearRpcUrl":"https://free.rpc.fastnear.com","oracleContractId":"price-oracle.near","nearUsdPriceId":"c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750","maxAgeSeconds":120,"maxLatestToEmaDeviationBps":1000,"cacheTtlMs":60000,"near":{"TESTNET":{"nativeUnitDecimals":24,"estimateFeeAmountYocto":"1000000000000000000000","pricingVersionPrefix":"outlayer-near-testnet"}}}'
SPONSORED_EXECUTION_STATIC_PRICING_JSON = '{"near":{"TESTNET":{"estimateFeeAmountYocto":"1000000000000000000000","minorPerFeeUnitNumerator":"300","minorPerFeeUnitDenominator":"1000000000000000000000000","pricingVersion":"static-near-testnet-v1"}}}'
CONSOLE_BASE_URL = "https://console.staging.example"
CONSOLE_SESSION_COOKIE_NAME = "seams-console-jwt"
CONSOLE_SESSION_ISSUER = "https://seams-gateway-staging.example/console"
CONSOLE_SESSION_AUDIENCE = "seams-console-session"
CONSOLE_EMAIL_RUNTIME_PROFILE = "PRODUCTION"
CONSOLE_EMAIL_PROVIDER = "RESEND"
CONSOLE_EMAIL_INVITATION_SECRET_KEY_ID = "console-email-staging-r1"
CONSOLE_EMAIL_FROM = "Seams <notifications@seams.sh>"
CONSOLE_EMAIL_CRON_EXPRESSIONS = "*/5 * * * *"
[triggers]
crons = ["*/5 * * * *"]

[secrets]
required = ["CONSOLE_SESSION_HMAC_SECRET", "ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK", "ACCOUNT_ID_DERIVATION_SECRET", "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET", "LINKED_DEVICE_OPERATOR_RECOVERY_SECRET", "LINKED_DEVICE_TARGET_DESCRIPTOR_HMAC_SECRET", "SPONSORED_EVM_EXECUTORS_JSON", "STRIPE_API_SK", "STRIPE_WEBHOOK_SECRET", "RESEND_API_KEY", "CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U"]
`;
}
