import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const VALID_TARGETS = new Set(['staging', 'production']);
const RESOURCE_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const D1_DATABASE_ID_PATTERN = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const SECRETS_STORE_ID_PATTERN = /^[0-9a-f]{32}$/;

function main() {
  const options = parseArguments(process.argv.slice(2));
  const outputPath = path.resolve(process.cwd(), options.output);
  const config = buildConfig(options.target, process.cwd());
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${outputPath}\n`);
}

function parseArguments(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const name = args[index];
    const value = String(args[index + 1] || '').trim();
    if (!['--target', '--output'].includes(name) || !value) {
      throw new Error(`Invalid argument: ${name || '<missing>'}`);
    }
    values.set(name, value);
  }
  const target = values.get('--target') || '';
  const output = values.get('--output') || '';
  if (!VALID_TARGETS.has(target)) throw new Error('--target must be staging or production');
  if (!output) throw new Error('--output is required');
  return { target, output };
}

function buildConfig(target, packageRoot) {
  const consoleDatabaseId = requireMatchingEnv(
    'ROUTER_API_CONSOLE_D1_DATABASE_ID',
    D1_DATABASE_ID_PATTERN,
  );
  const signerDatabaseId = requireMatchingEnv(
    'ROUTER_API_SIGNER_D1_DATABASE_ID',
    D1_DATABASE_ID_PATTERN,
  );
  if (consoleDatabaseId === signerDatabaseId) {
    throw new Error('Router API console and signer D1 database IDs must be different');
  }
  const signingRootKekId = requireEnv('SIGNING_ROOT_KEK_ID');
  const serviceNames = buildServiceNames(target);

  return {
    name: requireResourceName('ROUTER_API_WORKER_NAME'),
    main: path.join(packageRoot, 'src/router/cloudflare/d1RouterApiWorker.ts'),
    compatibility_date: '2026-07-18',
    compatibility_flags: ['nodejs_compat'],
    workers_dev: true,
    d1_databases: [
      {
        binding: 'CONSOLE_DB',
        database_name: requireResourceName('ROUTER_API_CONSOLE_D1_DATABASE_NAME'),
        database_id: consoleDatabaseId,
        migrations_dir: path.join(packageRoot, 'migrations/d1-console'),
      },
      {
        binding: 'SIGNER_DB',
        database_name: requireResourceName('ROUTER_API_SIGNER_D1_DATABASE_NAME'),
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
      { binding: 'ROUTER', service: serviceNames.router },
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
        store_id: requireMatchingEnv('ROUTER_API_SECRETS_STORE_ID', SECRETS_STORE_ID_PATTERN),
        secret_name: requireEnv('SIGNING_ROOT_KEK_SECRET_NAME'),
      },
    ],
    vars: buildWorkerVars(target, serviceNames.signingWorker, signingRootKekId),
  };
}

function buildServiceNames(target) {
  if (target === 'production') {
    return {
      deriverA: 'router-ab-deriver-a',
      deriverB: 'router-ab-deriver-b',
      signingWorker: 'router-ab-signing-worker',
      router: 'router-ab-router',
    };
  }
  return {
    deriverA: 'router-ab-deriver-a-staging',
    deriverB: 'router-ab-deriver-b-staging',
    signingWorker: 'router-ab-signing-worker-staging',
    router: 'router-ab-router-staging',
  };
}

function buildWorkerVars(target, signingWorkerName, signingRootKekId) {
  const production = target === 'production';
  const vars = {
    SEAMS_TENANT_STORAGE_NAMESPACE: requireEnv('SEAMS_TENANT_STORAGE_NAMESPACE'),
    SEAMS_STAGING_ORG_ID: requireEnv('SEAMS_ORG_ID'),
    SEAMS_STAGING_PROJECT_ID: requireEnv('SEAMS_PROJECT_ID'),
    SEAMS_STAGING_ENV_ID: requireEnv('SEAMS_ENV_ID'),
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: signingWorkerName,
    SIGNING_WORKER_ID: signingWorkerName,
    ROUTER_AB_CEREMONY_JWT_ISSUER: requireHttpsUrl('ROUTER_API_ORIGIN'),
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
    NEAR_RPC_URL: requireHttpsUrl('NEAR_RPC_URL'),
    ACCOUNT_INITIAL_BALANCE: requireUnsignedIntegerEnv('ACCOUNT_INITIAL_BALANCE'),
    ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING: 'false',
    RELAY_SESSION_ISSUER: requireEnv('RELAY_SESSION_ISSUER'),
    RELAY_SESSION_AUDIENCE: requireEnv('RELAY_SESSION_AUDIENCE'),
    RELAY_CORS_ORIGINS: requireHttpsOrigins('RELAY_CORS_ORIGINS'),
    SESSION_COOKIE_NAME: requireEnv('SESSION_COOKIE_NAME'),
    GOOGLE_OIDC_CLIENT_ID: requireEnv('GOOGLE_OIDC_CLIENT_ID'),
    EMAIL_OTP_DELIVERY_MODE: production ? 'email_provider' : 'dev_d1_outbox',
    EMAIL_OTP_PRODUCTION: String(production),
    EMAIL_OTP_DEV_OUTBOX_ENABLED: String(!production),
    SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
    SIGNING_ROOT_KEK_ENCODING: requireEnv('SIGNING_ROOT_KEK_ENCODING'),
    SIGNING_ROOT_KEK_IDS: signingRootKekId,
  };
  const oidcExchange = readEnv('SEAMS_OIDC_EXCHANGE_JSON');
  if (oidcExchange) vars.SEAMS_OIDC_EXCHANGE_JSON = requireJsonObjectEnv('SEAMS_OIDC_EXCHANGE_JSON');
  return vars;
}

function requireEnv(name) {
  const value = readEnv(name);
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function readEnv(name) {
  return String(process.env[name] || '').trim();
}

function requireResourceName(name) {
  const value = requireEnv(name);
  if (!RESOURCE_NAME_PATTERN.test(value)) throw new Error(`${name} is not a valid resource name`);
  return value;
}

function requireMatchingEnv(name, pattern) {
  const value = requireEnv(name);
  if (!pattern.test(value)) throw new Error(`${name} has an invalid format`);
  return value;
}

function requireJsonObjectEnv(name) {
  const value = requireEnv(name);
  const parsed = JSON.parse(value);
  if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
    throw new Error(`${name} must contain a JSON object`);
  }
  return value;
}

function requireHttpsUrl(name) {
  const value = requireEnv(name);
  const url = new URL(value);
  if (url.protocol !== 'https:') throw new Error(`${name} must use HTTPS`);
  return value;
}

function requireHttpsOrigins(name) {
  const value = requireEnv(name);
  for (const origin of value.split(',').map((item) => item.trim())) {
    const url = new URL(origin);
    if (url.protocol !== 'https:' || url.origin !== origin) {
      throw new Error(`${name} must contain comma-separated HTTPS origins`);
    }
  }
  return value;
}

function requireUnsignedIntegerEnv(name) {
  const value = requireEnv(name);
  if (!/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} must be unsigned`);
  return value;
}

function signingRootBindingName(signingRootKekId) {
  const binding = signingRootKekId.toUpperCase().replace(/[^A-Z0-9_]/g, '_');
  if (!/^[A-Z_][A-Z0-9_]*$/.test(binding)) {
    throw new Error('SIGNING_ROOT_KEK_ID cannot form a Worker binding name');
  }
  return binding;
}

main();
