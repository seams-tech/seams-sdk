import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const VALID_TARGETS = new Set(['staging', 'production']);
const RESOURCE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const D1_DATABASE_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SECRETS_STORE_ID_PATTERN = /^[0-9a-f]{32}$/;

function main() {
  const options = parseArguments(process.argv.slice(2));
  const config = buildConfig(options.target, process.cwd());
  const outputPath = path.resolve(process.cwd(), options.output);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${outputPath}\n`);
}

function parseArguments(args) {
  let target = '';
  let output = '';
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--target') {
      target = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--output') {
      output = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!VALID_TARGETS.has(target)) {
    throw new Error('--target must be staging or production');
  }
  if (!output) {
    throw new Error('--output is required');
  }
  return { target, output };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function buildConfig(target, packageRoot) {
  const workerName = requireResourceName('GATEWAY_WORKER_NAME');
  const consoleDatabaseName = requireResourceName('GATEWAY_CONSOLE_D1_DATABASE_NAME');
  const signerDatabaseName = requireResourceName('GATEWAY_SIGNER_D1_DATABASE_NAME');
  const consoleDatabaseId = requireMatchingEnv(
    'GATEWAY_CONSOLE_D1_DATABASE_ID',
    D1_DATABASE_ID_PATTERN,
    'a Cloudflare D1 UUID',
  );
  const signerDatabaseId = requireMatchingEnv(
    'GATEWAY_SIGNER_D1_DATABASE_ID',
    D1_DATABASE_ID_PATTERN,
    'a Cloudflare D1 UUID',
  );
  if (consoleDatabaseId === signerDatabaseId) {
    throw new Error('Gateway console and signer D1 database IDs must be different');
  }

  const secretsStoreId = requireMatchingEnv(
    'GATEWAY_SECRETS_STORE_ID',
    SECRETS_STORE_ID_PATTERN,
    'a 32-character Cloudflare Secrets Store ID',
  );
  const signingRootKekId = requireEnv('SIGNING_ROOT_KEK_ID');
  const signingRootKekSecretName = requireEnv('SIGNING_ROOT_KEK_SECRET_NAME');
  const serviceNames = buildServiceNames(target);
  const vars = buildWorkerVars({
    target,
    signingRootKekId,
    signingWorkerName: serviceNames.signingWorker,
  });

  return {
    name: workerName,
    main: path.join(packageRoot, 'src/router/cloudflare/d1RouterApiWorker.ts'),
    compatibility_date: '2026-07-18',
    compatibility_flags: ['nodejs_compat'],
    workers_dev: true,
    d1_databases: [
      {
        binding: 'CONSOLE_DB',
        database_name: consoleDatabaseName,
        database_id: consoleDatabaseId,
        migrations_dir: path.join(packageRoot, 'migrations/d1-console'),
      },
      {
        binding: 'SIGNER_DB',
        database_name: signerDatabaseName,
        database_id: signerDatabaseId,
        migrations_dir: path.join(packageRoot, '../sdk-server-ts/migrations/d1-signer'),
      },
    ],
    durable_objects: {
      bindings: [
        { name: 'THRESHOLD_STORE', class_name: 'ThresholdStoreDurableObject' },
        { name: 'ROUTER_API_RUNTIME', class_name: 'RouterApiRuntimeDurableObject' },
      ],
    },
    services: [
      { binding: 'DERIVER_A', service: serviceNames.deriverA },
      { binding: 'DERIVER_B', service: serviceNames.deriverB },
      { binding: 'SIGNING_WORKER', service: serviceNames.signingWorker },
      { binding: 'MPC_ROUTER', service: serviceNames.mpcRouter },
    ],
    migrations: [
      {
        tag: 'threshold-store-sqlite-v1',
        new_sqlite_classes: ['ThresholdStoreDurableObject'],
      },
      {
        tag: 'router-api-runtime-sqlite-v1',
        new_sqlite_classes: ['RouterApiRuntimeDurableObject'],
      },
    ],
    secrets_store_secrets: [
      {
        binding: signingRootBindingName(signingRootKekId),
        store_id: secretsStoreId,
        secret_name: signingRootKekSecretName,
      },
    ],
    vars,
  };
}

function buildServiceNames(target) {
  if (target === 'production') {
    return {
      deriverA: 'router-ab-deriver-a',
      deriverB: 'router-ab-deriver-b',
      signingWorker: 'router-ab-signing-worker',
      mpcRouter: 'router-ab-mpc-router',
    };
  }
  return {
    deriverA: 'router-ab-deriver-a-staging',
    deriverB: 'router-ab-deriver-b-staging',
    signingWorker: 'router-ab-signing-worker-staging',
    mpcRouter: 'router-ab-mpc-router-staging',
  };
}

function buildWorkerVars(input) {
  const production = input.target === 'production';
  const vars = {
    SEAMS_TENANT_STORAGE_NAMESPACE: requireEnv('SEAMS_TENANT_STORAGE_NAMESPACE'),
    SEAMS_STAGING_ORG_ID: requireEnv('SEAMS_ORG_ID'),
    SEAMS_STAGING_PROJECT_ID: requireEnv('SEAMS_PROJECT_ID'),
    SEAMS_STAGING_ENV_ID: requireEnv('SEAMS_ENV_ID'),
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: input.signingWorkerName,
    SIGNING_WORKER_ID: input.signingWorkerName,
    ROUTER_AB_CEREMONY_JWT_ISSUER: requireAbsoluteHttpsUrl('GATEWAY_ORIGIN'),
    ROUTER_AB_CEREMONY_JWT_AUDIENCE: requireEnv('ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
    ROUTER_AB_CEREMONY_JWT_KEY_ID: requireEnv('ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    ROUTER_AB_PUBLIC_KEYSET_JSON: requireJsonObjectEnv('ROUTER_AB_PUBLIC_KEYSET_JSON'),
    ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: requireJsonObjectEnv(
      'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON',
    ),
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: requireEnv(
      'ROUTER_AB_DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
    ),
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: requireEnv(
      'ROUTER_AB_DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
    ),
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: requireEnv(
      'ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
    ),
    RELAYER_ACCOUNT_ID: requireEnv('RELAYER_ACCOUNT_ID'),
    RELAYER_PUBLIC_KEY: requireEnv('RELAYER_PUBLIC_KEY'),
    NEAR_RPC_URL: requireAbsoluteHttpsUrl('NEAR_RPC_URL'),
    ACCOUNT_INITIAL_BALANCE: requireUnsignedIntegerEnv('ACCOUNT_INITIAL_BALANCE'),
    ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING: 'false',
    RELAY_SESSION_ISSUER: requireEnv('RELAY_SESSION_ISSUER'),
    RELAY_SESSION_AUDIENCE: requireEnv('RELAY_SESSION_AUDIENCE'),
    RELAY_CORS_ORIGINS: requireHttpsOriginList('RELAY_CORS_ORIGINS'),
    SESSION_COOKIE_NAME: requireEnv('SESSION_COOKIE_NAME'),
    GOOGLE_OIDC_CLIENT_ID: requireEnv('GOOGLE_OIDC_CLIENT_ID'),
    EMAIL_OTP_DELIVERY_MODE: production ? 'email_provider' : 'dev_d1_outbox',
    EMAIL_OTP_PRODUCTION: String(production),
    EMAIL_OTP_DEV_OUTBOX_ENABLED: String(!production),
    SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
    SIGNING_ROOT_KEK_ENCODING: requireKekEncoding(),
    SIGNING_ROOT_KEK_IDS: input.signingRootKekId,
  };
  addOptionalJsonVar(vars, 'SEAMS_OIDC_EXCHANGE_JSON');
  addOptionalUnsignedIntegerVar(vars, 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX');
  addOptionalUnsignedIntegerVar(vars, 'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS');
  addOptionalUnsignedIntegerVar(vars, 'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX');
  addOptionalUnsignedIntegerVar(vars, 'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS');
  return vars;
}

function addOptionalJsonVar(vars, name) {
  const value = readOptionalEnv(name);
  if (!value) return;
  vars[name] = parseJsonObject(name, value);
}

function addOptionalUnsignedIntegerVar(vars, name) {
  const value = readOptionalEnv(name);
  if (!value) return;
  vars[name] = parseUnsignedInteger(name, value);
}

function requireEnv(name) {
  const value = readOptionalEnv(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function readOptionalEnv(name) {
  return String(process.env[name] || '').trim();
}

function requireResourceName(name) {
  return requireMatchingEnv(name, RESOURCE_NAME_PATTERN, 'a lowercase Cloudflare resource name');
}

function requireMatchingEnv(name, pattern, description) {
  const value = requireEnv(name);
  if (!pattern.test(value)) {
    throw new Error(`${name} must be ${description}`);
  }
  return value;
}

function requireJsonObjectEnv(name) {
  return parseJsonObject(name, requireEnv(name));
}

function parseJsonObject(name, value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must contain a JSON object`);
  }
  return JSON.stringify(parsed);
}

function requireAbsoluteHttpsUrl(name) {
  const value = requireEnv(name);
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute HTTPS URL`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`${name} must be an absolute HTTPS URL`);
  }
  return value.replace(/\/+$/, '');
}

function requireHttpsOriginList(name) {
  const values = requireEnv(name).split(',');
  const origins = [];
  for (const rawValue of values) {
    const value = rawValue.trim();
    if (!value) continue;
    const url = new URL(requireAbsoluteHttpsValue(name, value));
    if (url.origin !== value.replace(/\/+$/, '')) {
      throw new Error(`${name} entries must be HTTPS origins without paths`);
    }
    origins.push(url.origin);
  }
  if (origins.length === 0) throw new Error(`${name} must contain at least one HTTPS origin`);
  return [...new Set(origins)].join(',');
}

function requireAbsoluteHttpsValue(name, value) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} entries must be absolute HTTPS origins`);
  }
  if (url.protocol !== 'https:') {
    throw new Error(`${name} entries must be absolute HTTPS origins`);
  }
  return value;
}

function requireUnsignedIntegerEnv(name) {
  return parseUnsignedInteger(name, requireEnv(name));
}

function parseUnsignedInteger(name, value) {
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be an unsigned base-10 integer`);
  }
  return value;
}

function requireKekEncoding() {
  const value = requireEnv('SIGNING_ROOT_KEK_ENCODING');
  switch (value) {
    case 'base64url':
    case 'base64':
    case 'hex':
      return value;
    default:
      throw new Error('SIGNING_ROOT_KEK_ENCODING must be base64url, base64, or hex');
  }
}

function signingRootBindingName(kekId) {
  const bindingName = kekId.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  if (!bindingName) throw new Error('SIGNING_ROOT_KEK_ID must produce a binding name');
  return bindingName;
}

main();
