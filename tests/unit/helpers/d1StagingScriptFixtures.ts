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
database_name = "seams-console-staging"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[vars]
SEAMS_TENANT_STORAGE_NAMESPACE = "seams-staging"
CONSOLE_SESSION_ISSUER = "seams-console-staging"
CONSOLE_SESSION_AUDIENCE = "seams-console-dashboard"

[secrets]
required = ["CONSOLE_SESSION_HMAC_SECRET"]
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
database_name = "seams-console-staging"
database_id = "11111111-1111-4111-8111-111111111111"
migrations_dir = "migrations/d1-console"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer-staging"
database_id = "22222222-2222-4222-8222-222222222222"
migrations_dir = "../sdk-server-ts/migrations/d1-signer"

[[durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[durable_objects.bindings]]
name = "ROUTER_API_RUNTIME"
class_name = "RouterApiRuntimeDurableObject"

[[services]]
binding = "DERIVER_A"
service = "router-ab-deriver-a-staging"

[[services]]
binding = "DERIVER_B"
service = "router-ab-deriver-b-staging"

[[services]]
binding = "SIGNING_WORKER"
service = "router-ab-signing-worker-staging"

[[migrations]]
tag = "threshold-store-sqlite-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]

[[migrations]]
tag = "router-api-runtime-sqlite-v1"
new_sqlite_classes = ["RouterApiRuntimeDurableObject"]

[[secrets_store_secrets]]
binding = "SIGNING_ROOT_KEK_STAGING_R1"
store_id = "33333333333333333333333333333333"
secret_name = "signing-root-kek-staging-r1"

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
RELAY_SESSION_ISSUER = "seams-gateway-staging"
RELAY_SESSION_AUDIENCE = "seams-wallet-session"
SIGNING_ROOT_KEK_PROVIDER = "cloudflare_secrets_store"
SIGNING_ROOT_KEK_ENCODING = "base64url"
SIGNING_ROOT_KEK_IDS = "signing-root-kek-staging-r1"

[secrets]
required = ["RELAY_SESSION_HMAC_SECRET", "ACCOUNT_ID_DERIVATION_SECRET", "ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET", "SPONSORED_EVM_EXECUTORS_JSON"]
`;
}
