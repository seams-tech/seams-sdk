import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import process from 'node:process';
import {
  DEFAULT_EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_GRANT_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_LOCKOUT_TTL_MS,
  DEFAULT_EMAIL_OTP_MAX_ATTEMPTS,
  DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
  DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX,
  DEFAULT_EMAIL_OTP_VERIFY_RATE_LIMIT_MAX,
  DEFAULT_CONSOLE_SESSION_AUDIENCE,
  DEFAULT_CONSOLE_SESSION_COOKIE_NAME,
  DEFAULT_RELAY_SESSION_AUDIENCE,
  DEFAULT_SESSION_COOKIE_NAME,
  GATEWAY_WORKER_COMPATIBILITY_DATE,
  GATEWAY_WORKER_COMPATIBILITY_FLAGS,
  consoleOriginFor,
  gatewayRuntimeProfileNearNetwork,
} from './gateway-deployment-config.mjs';
import { readBackendLane } from '../../../scripts/deployment-targets.mjs';

const VALID_LANES = new Set(['staging-testnet', 'production-testnet', 'production-mainnet']);

function walletServerMigrationsDirectory(packageRoot) {
  const requireFromWalletConsole = createRequire(
    path.join(packageRoot, '../wallet-console-server-ts/package.json'),
  );
  const walletServerRoot = path.dirname(
    requireFromWalletConsole.resolve('@seams/wallet-server/package.json'),
  );
  return path.join(walletServerRoot, 'migrations', 'd1-signer');
}

function main() {
  const options = parseArguments(process.argv.slice(2));
  const lane = readBackendLane(options.lane);
  const deployment = requireProvisionedGatewayDeploymentConfig(options.lane, lane.provisioning);
  const config =
    options.worker === 'console'
      ? buildConsoleConfig(deployment, lane.site.origin, lane.emailOtpDelivery, process.cwd())
      : options.worker === 'wallet-runtime'
        ? buildWalletRuntimeConfig(
            deployment,
            lane.site.origin,
            lane.walletOrigin,
            lane.emailOtpDelivery,
            lane.site.docsOrigin,
            process.cwd(),
          )
        : buildConfig(
            deployment,
            lane.site.origin,
            lane.walletOrigin,
            lane.emailOtpDelivery,
            lane.site.docsOrigin,
            process.cwd(),
          );
  writePrivateJson(options.output, config);
  process.stdout.write(`${path.resolve(process.cwd(), options.output)}\n`);
}

function requireProvisionedGatewayDeploymentConfig(laneId, provisioning) {
  if (!provisioning || provisioning.kind !== 'provisioned') {
    throw new Error(`backend lane ${laneId} has no provisioned Gateway deployment config`);
  }
  const deployment = provisioning.gatewayDeploymentConfig;
  if (!deployment || typeof deployment !== 'object' || Array.isArray(deployment)) {
    throw new Error(`backend lane ${laneId} has no provisioned Gateway deployment config`);
  }
  return deployment;
}

function parseArguments(args) {
  let lane = '';
  let output = '';
  let worker = 'gateway';
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--lane') {
      lane = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--output') {
      output = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--worker') {
      worker = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!VALID_LANES.has(lane)) {
    throw new Error('--lane must be staging-testnet, production-testnet, or production-mainnet');
  }
  if (!output) throw new Error('--output is required');
  if (!['gateway', 'console', 'wallet-runtime'].includes(worker)) {
    throw new Error('--worker must be gateway, console, or wallet-runtime');
  }
  return { lane, output, worker };
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

export function consoleWorkerNameFor(gatewayWorkerName) {
  if (!gatewayWorkerName.includes('gateway')) {
    throw new Error(`cannot derive console worker name from ${gatewayWorkerName}`);
  }
  return gatewayWorkerName.replace('gateway', 'console');
}

export function walletRuntimeWorkerNameFor(gatewayWorkerName) {
  if (!gatewayWorkerName.includes('gateway')) {
    throw new Error(`cannot derive wallet runtime worker name from ${gatewayWorkerName}`);
  }
  return gatewayWorkerName.replace('gateway', 'wallet-runtime');
}

// The Console Worker (R105 Phase 4): its own origin, session plane, cron, and
// only the Console D1 binding. It is also the private WALLET_CONSOLE service
// binding target for the split Gateway.
function buildConsoleConfig(deployment, siteOrigin, emailOtpDelivery, packageRoot) {
  const resources = deployment.resources;
  const consoleOrigin = consoleOriginFor(deployment.origins.gateway);
  const production = deployment.lane !== 'staging-testnet';
  const vars = {
    SEAMS_TENANT_STORAGE_NAMESPACE: deployment.tenant.namespace,
    CONSOLE_DEFAULT_ORG_ID: deployment.tenant.orgId,
    CONSOLE_DEFAULT_PROJECT_ID: deployment.tenant.projectId,
    CONSOLE_DEFAULT_ENVIRONMENT_ID: deployment.tenant.environmentId,
    CONSOLE_BASE_URL: deployment.origins.allowedCors[0],
    CONSOLE_CORS_ORIGINS: deployment.origins.allowedCors.join(','),
    CONSOLE_SESSION_COOKIE_NAME: DEFAULT_CONSOLE_SESSION_COOKIE_NAME,
    CONSOLE_SESSION_ISSUER: `${consoleOrigin}/console`,
    CONSOLE_SESSION_AUDIENCE: DEFAULT_CONSOLE_SESSION_AUDIENCE,
  };
  addOptionalStringVar(vars, 'GOOGLE_OIDC_CLIENT_ID', deployment.optional.googleOidcClientId);
  vars.SPONSORED_EXECUTION_REAL_PRICING_JSON = JSON.stringify(
    buildOutlayerSponsoredExecutionPricingConfig(deployment.runtimeProfile),
  );
  vars.SPONSORED_EXECUTION_STATIC_PRICING_JSON = JSON.stringify(
    buildStaticSponsoredExecutionPricingConfig(deployment.runtimeProfile),
  );
  if (production) {
    vars.CONSOLE_EMAIL_RUNTIME_PROFILE = 'PRODUCTION';
    vars.CONSOLE_EMAIL_PROVIDER = 'RESEND';
    vars.CONSOLE_EMAIL_FROM = `Seams <${emailOtpDelivery.provider.fromAddress}>`;
    vars.CONSOLE_EMAIL_CRON_EXPRESSIONS = '* * * * *';
  } else {
    vars.CONSOLE_EMAIL_RUNTIME_PROFILE = 'DEVELOPMENT';
    vars.CONSOLE_EMAIL_PROVIDER = 'CAPTURE';
  }
  return {
    name: consoleWorkerNameFor(resources.workerName),
    main: path.join(
      packageRoot,
      '../wallet-console-server-ts/src/router/cloudflare/d1ConsoleStagingWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
    workers_dev: false,
    routes: [
      {
        pattern: new URL(consoleOrigin).hostname,
        custom_domain: true,
      },
    ],
    d1_databases: [
      {
        binding: 'CONSOLE_DB',
        database_name: resources.consoleD1.name,
        database_id: resources.consoleD1.id,
        migrations_dir: path.join(packageRoot, '../wallet-console-server-ts/migrations/d1-console'),
      },
    ],
    services: [
      {
        binding: 'WALLET_RUNTIME',
        service: walletRuntimeWorkerNameFor(resources.workerName),
      },
    ],
    triggers: {
      crons: ['* * * * *'],
    },
    observability: {
      enabled: true,
      logs: {
        enabled: true,
      },
    },
    vars,
  };
}

function buildWalletRuntimeConfig(
  deployment,
  siteOrigin,
  walletOrigin,
  emailOtpDelivery,
  docsOrigin,
  packageRoot,
) {
  const resources = deployment.resources;
  return {
    name: walletRuntimeWorkerNameFor(resources.workerName),
    main: path.join(
      packageRoot,
      '../wallet-console-server-ts/src/router/cloudflare/d1WalletRuntimeWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
    workers_dev: false,
    d1_databases: [
      {
        binding: 'SIGNER_DB',
        database_name: resources.signerD1.name,
        database_id: resources.signerD1.id,
        migrations_dir: walletServerMigrationsDirectory(packageRoot),
      },
    ],
    services: [
      { binding: 'SIGNING_WORKER', service: deployment.serviceNames.signingWorker },
      { binding: 'MPC_ROUTER', service: deployment.serviceNames.mpcRouter },
    ],
    observability: {
      enabled: true,
      logs: { enabled: true },
    },
    vars: buildWorkerVars(deployment, siteOrigin, walletOrigin, emailOtpDelivery, docsOrigin),
  };
}

function buildConfig(
  deployment,
  siteOrigin,
  walletOrigin,
  emailOtpDelivery,
  docsOrigin,
  packageRoot,
) {
  const resources = deployment.resources;
  if (resources.consoleD1.id === resources.signerD1.id) {
    throw new Error('resources.consoleD1.id and resources.signerD1.id must be different');
  }
  const vars = buildWorkerVars(deployment, siteOrigin, walletOrigin, emailOtpDelivery, docsOrigin);
  return {
    name: resources.workerName,
    main: path.join(
      packageRoot,
      '../wallet-console-server-ts/src/router/cloudflare/d1GatewayWorker.ts',
    ),
    compatibility_date: GATEWAY_WORKER_COMPATIBILITY_DATE,
    compatibility_flags: GATEWAY_WORKER_COMPATIBILITY_FLAGS,
    workers_dev: true,
    routes: [
      {
        pattern: new URL(deployment.origins.gateway).hostname,
        custom_domain: true,
      },
    ],
    d1_databases: [
      // R105 Phase 4 cutover: the Gateway holds no Console database binding.
      // Console data crosses the private WALLET_CONSOLE service binding only.
      {
        binding: 'SIGNER_DB',
        database_name: resources.signerD1.name,
        database_id: resources.signerD1.id,
        migrations_dir: walletServerMigrationsDirectory(packageRoot),
      },
    ],
    services: [
      { binding: 'SIGNING_WORKER', service: deployment.serviceNames.signingWorker },
      { binding: 'MPC_ROUTER', service: deployment.serviceNames.mpcRouter },
      { binding: 'WALLET_CONSOLE', service: consoleWorkerNameFor(resources.workerName) },
    ],
    triggers: {
      crons: ['* * * * *'],
    },
    observability: {
      enabled: true,
      logs: {
        enabled: true,
        head_sampling_rate: 1,
        invocation_logs: true,
      },
      traces: {
        enabled: true,
        head_sampling_rate: 1,
      },
    },
    vars,
  };
}

function buildWorkerVars(deployment, siteOrigin, walletOrigin, emailOtpDelivery, docsOrigin) {
  const production = deployment.lane !== 'staging-testnet';
  const implicitNearTestFunding =
    deployment.runtimeProfile.nearFunding.kind === 'implicit_account_relayer';
  const demoEmailOtpDelivery =
    deployment.runtimeProfile.emailOtpDelivery.kind === 'demo_code_response' ||
    deployment.runtimeProfile.emailOtpDelivery.kind === 'provider_and_demo_code';
  const vars = {
    SEAMS_TENANT_STORAGE_NAMESPACE: deployment.tenant.namespace,
    SEAMS_STAGING_ORG_ID: deployment.tenant.orgId,
    SEAMS_STAGING_PROJECT_ID: deployment.tenant.projectId,
    SEAMS_STAGING_ENV_ID: deployment.tenant.environmentId,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: deployment.serviceNames.signingWorker,
    ROUTER_AB_PREWARM_ENABLED: 'true',
    SIGNING_WORKER_ID: deployment.serviceNames.signingWorker,
    ROUTER_AB_CEREMONY_JWT_ISSUER: deployment.origins.gateway,
    ROUTER_AB_CEREMONY_JWT_AUDIENCE: deployment.routerAb.ceremonyJwtAudience,
    ROUTER_AB_CEREMONY_JWT_KEY_ID: deployment.routerAb.ceremonyJwtKeyId,
    LINKED_DEVICE_WEBAUTHN_RP_ID: new URL(walletOrigin).hostname,
    LINKED_DEVICE_WEBAUTHN_ORIGIN: siteOrigin,
    ROUTER_AB_PUBLIC_KEYSET_JSON: JSON.stringify(deployment.routerAb.publicKeyset),
    ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON: JSON.stringify(
      deployment.routerAb.registrationTopology,
    ),
    ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING: String(implicitNearTestFunding),
    RELAY_SESSION_ISSUER: deployment.session.issuer,
    RELAY_SESSION_AUDIENCE: DEFAULT_RELAY_SESSION_AUDIENCE,
    RELAY_CORS_ORIGINS: deployment.origins.allowedCors.join(','),
    SESSION_COOKIE_NAME: DEFAULT_SESSION_COOKIE_NAME,
    SIGNING_SESSION_SEAL_CURRENT_KEY_VERSION: deployment.signingSessionSeal.currentKeyVersion,
    SIGNING_SESSION_SEAL_ACCEPTED_WARM_KEY_VERSIONS:
      deployment.signingSessionSeal.acceptedWarmKeyVersions.join(','),
    EMAIL_OTP_RUNTIME_PROFILE: deployment.runtimeProfile.kind,
    EMAIL_OTP_DELIVERY_MODE: deployment.runtimeProfile.emailOtpDelivery.kind,
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
    EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX:
      DEFAULT_EMAIL_OTP_SENSITIVE_ATTEMPT_RATE_LIMIT_MAX,
    EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS:
      DEFAULT_EMAIL_OTP_RATE_LIMIT_WINDOW_MS,
  };
  if (production) {
    if (emailOtpDelivery.kind === 'demo_code_response') {
      throw new Error('Production transactional email requires a configured email provider');
    }
    vars.CONSOLE_DOCS_BASE_URL = docsOrigin;
    vars.CONSOLE_EMAIL_RUNTIME_PROFILE = 'PRODUCTION';
    vars.CONSOLE_EMAIL_PROVIDER = 'RESEND';
    vars.CONSOLE_EMAIL_FROM = `Seams <${emailOtpDelivery.provider.fromAddress}>`;
    vars.CONSOLE_EMAIL_CRON_EXPRESSIONS = '* * * * *';
  }
  if (demoEmailOtpDelivery) {
    vars.EMAIL_OTP_DEMO_ALLOWED_ORIGINS = deployment.origins.allowedCors.join(',');
  }
  if (emailOtpDelivery.kind !== 'demo_code_response') {
    vars.EMAIL_OTP_PROVIDER = emailOtpDelivery.provider.kind;
    vars.EMAIL_OTP_FROM_ADDRESS = emailOtpDelivery.provider.fromAddress;
    if (emailOtpDelivery.provider.kind === 'amazon_ses') {
      vars.EMAIL_OTP_SES_REGION = emailOtpDelivery.provider.region;
    }
  }
  addNearRelayerVars(vars, deployment.optional.nearRelayer);
  addOptionalStringVar(vars, 'GOOGLE_OIDC_CLIENT_ID', deployment.optional.googleOidcClientId);
  return vars;
}

function buildOutlayerSponsoredExecutionPricingConfig(runtimeProfile) {
  const networkClass =
    gatewayRuntimeProfileNearNetwork(runtimeProfile) === 'mainnet' ? 'MAINNET' : 'TESTNET';
  return {
    provider: 'outlayer',
    nearRpcUrl: 'https://free.rpc.fastnear.com',
    oracleContractId: 'price-oracle.near',
    nearUsdPriceId: 'c415de8d2efa7db216527dff4b60e8f3a5311c740dadb233e13e12547e226750',
    maxAgeSeconds: 120,
    maxLatestToEmaDeviationBps: 1_000,
    cacheTtlMs: 60_000,
    near: {
      [networkClass]: {
        nativeUnitDecimals: 24,
        estimateFeeAmountYocto: '1000000000000000000000',
        pricingVersionPrefix: `outlayer-near-${networkClass.toLowerCase()}`,
      },
    },
  };
}

function buildStaticSponsoredExecutionPricingConfig(runtimeProfile) {
  const networkClass =
    gatewayRuntimeProfileNearNetwork(runtimeProfile) === 'mainnet' ? 'MAINNET' : 'TESTNET';
  return {
    near: {
      [networkClass]: {
        estimateFeeAmountYocto: '1000000000000000000000',
        minorPerFeeUnitNumerator: '300',
        minorPerFeeUnitDenominator: '1000000000000000000000000',
        pricingVersion: `static-near-${networkClass.toLowerCase()}-v1`,
      },
    },
  };
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

main();
