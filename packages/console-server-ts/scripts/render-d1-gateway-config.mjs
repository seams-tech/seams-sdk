import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  buildGatewayDeploymentPlan,
  DEFAULT_EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_GRANT_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_LOCKOUT_TTL_MS,
  DEFAULT_EMAIL_OTP_MAX_ATTEMPTS,
  DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
  DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_VERIFY_RATE_LIMIT_MAX,
  DEFAULT_RELAY_SESSION_AUDIENCE,
  DEFAULT_SESSION_COOKIE_NAME,
  parseGatewayDeploymentConfig,
} from './gateway-deployment-config.mjs';

const VALID_TARGETS = new Set(['staging', 'production']);

function main() {
  const options = parseArguments(process.argv.slice(2));
  const deployment = parseGatewayDeploymentConfig(
    process.env.GATEWAY_DEPLOYMENT_CONFIG_JSON,
    options.target,
  );
  assertNearRelayerSecretConsistency(deployment.optional.nearRelayer);
  const config = buildConfig(deployment, process.cwd());
  const plan = buildGatewayDeploymentPlan(deployment);
  writePrivateJson(options.output, config);
  writePrivateJson(options.deploymentPlanOutput, plan);
  process.stdout.write(`${path.resolve(process.cwd(), options.output)}\n`);
}

function parseArguments(args) {
  let target = '';
  let output = '';
  let deploymentPlanOutput = '';
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
    if (argument === '--deployment-plan-output') {
      deploymentPlanOutput = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!VALID_TARGETS.has(target)) throw new Error('--target must be staging or production');
  if (!output) throw new Error('--output is required');
  if (!deploymentPlanOutput) throw new Error('--deployment-plan-output is required');
  return { target, output, deploymentPlanOutput };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function writePrivateJson(relativePath, value) {
  const outputPath = path.resolve(process.cwd(), relativePath);
  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function buildConfig(deployment, packageRoot) {
  const resources = deployment.resources;
  if (resources.consoleD1.id === resources.signerD1.id) {
    throw new Error('resources.consoleD1.id and resources.signerD1.id must be different');
  }
  const vars = buildWorkerVars(deployment);
  return {
    name: resources.workerName,
    main: path.join(packageRoot, 'src/router/cloudflare/d1RouterApiWorker.ts'),
    compatibility_date: '2026-07-18',
    compatibility_flags: ['nodejs_compat'],
    workers_dev: true,
    d1_databases: [
      {
        binding: 'CONSOLE_DB',
        database_name: resources.consoleD1.name,
        database_id: resources.consoleD1.id,
        migrations_dir: path.join(packageRoot, 'migrations/d1-console'),
      },
      {
        binding: 'SIGNER_DB',
        database_name: resources.signerD1.name,
        database_id: resources.signerD1.id,
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
      { binding: 'DERIVER_A', service: deployment.serviceNames.deriverA },
      { binding: 'DERIVER_B', service: deployment.serviceNames.deriverB },
      { binding: 'SIGNING_WORKER', service: deployment.serviceNames.signingWorker },
      { binding: 'MPC_ROUTER', service: deployment.serviceNames.mpcRouter },
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
        binding: signingRootBindingName(deployment.signingRoot.id),
        store_id: resources.secretsStoreId,
        secret_name: deployment.signingRoot.secretName,
      },
    ],
    vars,
  };
}

function buildWorkerVars(deployment) {
  const production = deployment.target === 'production';
  const implicitNearTestFunding =
    deployment.runtimeProfile.nearFunding.kind === 'implicit_account_relayer';
  const demoEmailOtpDelivery =
    deployment.runtimeProfile.emailOtpDelivery.kind === 'demo_code_response';
  const vars = {
    SEAMS_TENANT_STORAGE_NAMESPACE: deployment.tenant.namespace,
    SEAMS_STAGING_ORG_ID: deployment.tenant.orgId,
    SEAMS_STAGING_PROJECT_ID: deployment.tenant.projectId,
    SEAMS_STAGING_ENV_ID: deployment.tenant.environmentId,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: deployment.serviceNames.signingWorker,
    SIGNING_WORKER_ID: deployment.serviceNames.signingWorker,
    ROUTER_AB_CEREMONY_JWT_ISSUER: deployment.origins.gateway,
    ROUTER_AB_CEREMONY_JWT_AUDIENCE: deployment.routerAb.ceremonyJwtAudience,
    ROUTER_AB_CEREMONY_JWT_KEY_ID: deployment.routerAb.ceremonyJwtKeyId,
    ROUTER_AB_PUBLIC_KEYSET_JSON: JSON.stringify(deployment.routerAb.publicKeyset),
    ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: JSON.stringify(
      deployment.routerAb.registrationTopology,
    ),
    DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: deployment.routerAb.deriverAInputPublicKey,
    DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: deployment.routerAb.deriverBInputPublicKey,
    SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: deployment.routerAb.signingWorkerOutputPublicKey,
    ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING: String(implicitNearTestFunding),
    RELAY_SESSION_ISSUER: deployment.session.issuer,
    RELAY_SESSION_AUDIENCE: DEFAULT_RELAY_SESSION_AUDIENCE,
    RELAY_CORS_ORIGINS: deployment.origins.allowedCors.join(','),
    SESSION_COOKIE_NAME: DEFAULT_SESSION_COOKIE_NAME,
    EMAIL_OTP_RUNTIME_PROFILE: deployment.runtimeProfile.kind,
    EMAIL_OTP_DELIVERY_MODE:
      deployment.runtimeProfile.emailOtpDelivery.kind,
    EMAIL_OTP_PRODUCTION: String(production),
    EMAIL_OTP_DEV_OUTBOX_ENABLED: 'false',
    EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX: DEFAULT_EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX,
    EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS: DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
    EMAIL_OTP_VERIFY_RATE_LIMIT_MAX: DEFAULT_EMAIL_OTP_VERIFY_RATE_LIMIT_MAX,
    EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS: DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
    EMAIL_OTP_GRANT_RATE_LIMIT_MAX: DEFAULT_EMAIL_OTP_GRANT_RATE_LIMIT_MAX,
    EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS: DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
    EMAIL_OTP_MAX_ATTEMPTS: DEFAULT_EMAIL_OTP_MAX_ATTEMPTS,
    EMAIL_OTP_LOCKOUT_TTL_MS: DEFAULT_EMAIL_OTP_LOCKOUT_TTL_MS,
    EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX:
      DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX,
    EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS: DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
    EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX:
      DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX,
    EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS:
      DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
    SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
    SIGNING_ROOT_KEK_ENCODING: deployment.signingRoot.encoding,
    SIGNING_ROOT_KEK_IDS: deployment.signingRoot.id,
  };
  if (demoEmailOtpDelivery) {
    vars.EMAIL_OTP_DEMO_ALLOWED_ORIGINS = deployment.origins.allowedCors.join(',');
  }
  addNearRelayerVars(vars, deployment.optional.nearRelayer);
  addOptionalStringVar(vars, 'GOOGLE_OIDC_CLIENT_ID', deployment.optional.googleOidcClientId);
  addOptionalObjectVar(vars, 'SEAMS_OIDC_EXCHANGE_JSON', deployment.optional.oidcExchange);
  return vars;
}

function addNearRelayerVars(vars, nearRelayer) {
  if (!nearRelayer) return;
  vars.RELAYER_ACCOUNT_ID = nearRelayer.accountId;
  addOptionalStringVar(vars, 'RELAYER_PUBLIC_KEY', nearRelayer.publicKey);
  vars.NEAR_RPC_URL = nearRelayer.rpcUrl;
  vars.ACCOUNT_INITIAL_BALANCE = nearRelayer.initialBalanceYocto;
}

function addOptionalStringVar(vars, name, value) {
  if (value === null) return;
  vars[name] = value;
}

function addOptionalObjectVar(vars, name, value) {
  if (value === null) return;
  vars[name] = JSON.stringify(value);
}

function assertNearRelayerSecretConsistency(nearRelayer) {
  const hasPrivateKey = Boolean(String(process.env.RELAYER_PRIVATE_KEY || '').trim());
  if (nearRelayer && !hasPrivateKey) {
    throw new Error('RELAYER_PRIVATE_KEY is required when optional.nearRelayer is configured');
  }
  if (!nearRelayer && hasPrivateKey) {
    throw new Error('RELAYER_PRIVATE_KEY must be absent when optional.nearRelayer is null');
  }
}

function signingRootBindingName(kekId) {
  const bindingName = kekId.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  if (!bindingName) throw new Error('signingRoot.id must produce a binding name');
  return bindingName;
}

main();
