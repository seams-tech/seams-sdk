import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseEnv } from 'node:util';
import {
  buildGatewayRuntimeProfile,
  DEFAULT_NEAR_INITIAL_BALANCE_YOCTO,
  GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
  GATEWAY_RUNTIME_PROFILE_KINDS,
  gatewayRuntimeProfileNearNetwork,
  parseGatewayDeploymentConfig as parseStrictGatewayDeploymentConfig,
} from '../../../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const VALID_TARGETS = new Set(['staging', 'production']);
const VALID_DEPLOYMENT_COMPONENTS = new Set(['wallet-core', 'product']);
const CEREMONY_JWKS_PATH = '/.well-known/router-ab-ceremony-jwks.json';
const githubCli = process.env.GITHUB_CLI_BIN || 'gh';
const argv = process.argv.slice(2).filter((argument) => argument !== '--');
const scriptDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(scriptDir, '../../..');
const wranglerCli =
  process.env.WRANGLER_CLI_BIN || join(repoRoot, 'node_modules', '.bin', 'wrangler');
let wranglerEnvironment = process.env;
const SUPPLIED_VALUE_ALIASES = Object.freeze({
  GATEWAY_ORIGIN: ['VITE_RELAYER_URL'],
  RELAYER_ACCOUNT_ID: ['VITE_RELAYER_ACCOUNT_ID'],
  VITE_RELAYER_ACCOUNT_ID: ['RELAYER_ACCOUNT_ID'],
  NEAR_RPC_URL: ['VITE_NEAR_RPC_URL'],
  VITE_NEAR_RPC_URL: ['NEAR_RPC_URL'],
  RELAYER_INITIAL_BALANCE_YOCTO: ['ACCOUNT_INITIAL_BALANCE'],
  VITE_CONSOLE_BASE_URL: ['GATEWAY_ORIGIN', 'VITE_RELAYER_URL'],
  VITE_RELAYER_URL: ['GATEWAY_ORIGIN'],
});
const OPTIONAL_SECRET_NAMES = new Set([
  'RELAYER_PRIVATE_KEY',
  'SPONSORED_EVM_EXECUTORS_JSON',
]);
const DEPLOYMENT_AUDIT_VARIABLE_UPLOAD_ORDER = Object.freeze([
  'SEAMS_DEPLOYMENT_GENERATED_AT',
  'SEAMS_DEPLOYMENT_MANIFEST_SHA256',
  'SEAMS_DEPLOYMENT_GENERATION_ID',
]);
const DEPLOYMENT_AUDIT_VARIABLE_NAMES = new Set(DEPLOYMENT_AUDIT_VARIABLE_UPLOAD_ORDER);
const OBSOLETE_GATEWAY_VARIABLE_NAMES = new Set([
  'GATEWAY_WORKER_NAME',
  'GATEWAY_CONSOLE_D1_DATABASE_NAME',
  'GATEWAY_CONSOLE_D1_DATABASE_ID',
  'GATEWAY_SIGNER_D1_DATABASE_NAME',
  'GATEWAY_SIGNER_D1_DATABASE_ID',
  'GATEWAY_SECRETS_STORE_ID',
  'SIGNING_ROOT_KEK_ID',
  'SIGNING_ROOT_KEK_SECRET_NAME',
  'SIGNING_ROOT_KEK_ENCODING',
  'SEAMS_TENANT_STORAGE_NAMESPACE',
  'SEAMS_ORG_ID',
  'SEAMS_PROJECT_ID',
  'SEAMS_ENV_ID',
  'SEAMS_BOOTSTRAP_PUBLISHABLE_KEY',
  'SEAMS_BOOTSTRAP_ALLOWED_ORIGINS_JSON',
  'GATEWAY_ORIGIN',
  'ROUTER_AB_CEREMONY_JWT_AUDIENCE',
  'ROUTER_AB_CEREMONY_JWT_KEY_ID',
  'ROUTER_AB_PUBLIC_KEYSET_JSON',
  'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON',
  'ROUTER_AB_DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
  'ROUTER_AB_DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
  'ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
  'RELAYER_ACCOUNT_ID',
  'RELAYER_PUBLIC_KEY',
  'NEAR_RPC_URL',
  'GATEWAY_RUNTIME_PROFILE',
  'RELAYER_INITIAL_BALANCE_YOCTO',
  'ACCOUNT_INITIAL_BALANCE',
  'RELAY_SESSION_ISSUER',
  'RELAY_SESSION_AUDIENCE',
  'RELAY_CORS_ORIGINS',
  'SESSION_COOKIE_NAME',
  'EMAIL_OTP_RUNTIME_PROFILE',
  'EMAIL_OTP_DEMO_ALLOWED_ORIGINS',
  'GOOGLE_OIDC_CLIENT_ID',
  'SEAMS_OIDC_EXCHANGE_JSON',
  'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX',
  'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS',
  'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX',
  'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
]);
const GENERATED_IDENTITY_SECRET_MARKERS = new Map([
  ['gateway', 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK'],
  ['mpc-router', 'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET'],
  ['deriver-a', 'DERIVER_A_ROOT_SHARE_WIRE_SECRET'],
  ['deriver-b', 'DERIVER_B_ROOT_SHARE_WIRE_SECRET'],
  ['signing-worker', 'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY'],
]);
const ANSI = Object.freeze({
  reset: '\u001b[0m',
  bold: '\u001b[1m',
  dim: '\u001b[2m',
  cyan: '\u001b[36m',
  green: '\u001b[32m',
  red: '\u001b[31m',
  yellow: '\u001b[33m',
});

class TerminalProgressLogger {
  constructor(totalSteps, colorEnabled) {
    this.totalSteps = totalSteps;
    this.colorEnabled = colorEnabled;
    this.completedSteps = 0;
    this.barWidth = 24;
    this.stepWidth = String(totalSteps).length;
  }

  step(message) {
    this.completedSteps += 1;
    const filledWidth = Math.min(
      this.barWidth,
      Math.round((this.completedSteps / this.totalSteps) * this.barWidth),
    );
    const complete = filledWidth === this.barWidth;
    const filled = '━'.repeat(filledWidth);
    const remaining = '─'.repeat(this.barWidth - filledWidth);
    const label = paint(ANSI.bold + ANSI.cyan, 'ENV KEYGEN', this.colorEnabled);
    const filledBar = paint(ANSI.green, filled, this.colorEnabled);
    const remainingBar = paint(ANSI.dim, remaining, this.colorEnabled);
    const count = `${String(this.completedSteps).padStart(this.stepWidth, '0')}/${this.totalSteps}`;
    const coloredCount = paint(
      complete ? ANSI.bold + ANSI.green : ANSI.bold + ANSI.yellow,
      count,
      this.colorEnabled,
    );
    const coloredMessage = paint(
      complete ? ANSI.bold + ANSI.green : ANSI.bold,
      message,
      this.colorEnabled,
    );
    process.stderr.write(
      `  ${label}  ${filledBar}${remainingBar}  ${coloredCount}  ${coloredMessage}\n`,
    );
  }

  detail(message) {
    const warning = /\b(?:skipped|unavailable|expected)\b/i.test(message);
    const marker = warning
      ? paint(ANSI.yellow, '!', this.colorEnabled)
      : paint(ANSI.green, '+', this.colorEnabled);
    const text = warning ? paint(ANSI.yellow, message, this.colorEnabled) : message;
    process.stderr.write(`              ${marker} ${text}\n`);
  }
}

process.on('uncaughtException', handleFatalError);

if (argv.includes('--help')) {
  printUsage();
  process.exit(0);
}

const target = requireTarget();
const json = argv.includes('--json');
const apply = argv.includes('--apply');
const prepare = argv.includes('--prepare');
const rotate = argv.includes('--rotate');
const verifyGeneration = argv.includes('--verify-generation');
const migrateGatewayConfig = argv.includes('--migrate-gateway-config');
const allowIncomplete = argv.includes('--allow-incomplete');
const requestedRepository = readOption('--repo');
const deploymentComponent = readDeploymentComponent();
const manifestFile = readOption('--manifest-file');
const valuesFile = readOption('--values-file') || findDefaultValuesFile(target);
const progress = createProgressLogger(resolveProgressStepCount());
let repository = requestedRepository;
if (verifyGeneration) {
  if (apply || rotate || migrateGatewayConfig) {
    throw new Error('--verify-generation cannot be combined with an apply or migration option');
  }
  progress.step('Validate GitHub authentication and repository access');
  repository = resolveGitHubRepository(requestedRepository);
  progress.step('Verify deployment generation metadata');
  const verification = verifyAppliedGenerationMetadata(target, repository);
  if (json) {
    process.stdout.write(`${JSON.stringify(verification, null, 2)}\n`);
  } else {
    printGenerationVerification(verification);
  }
  process.exit(0);
}
if (migrateGatewayConfig) {
  if (!apply) {
    throw new Error('--migrate-gateway-config requires --apply');
  }
  progress.step('Validate GitHub authentication and repository access');
  repository = resolveGitHubRepository(requestedRepository);
  progress.step('Consolidate existing Gateway variables');
  const migration = migrateExistingGatewayVariables(target, repository);
  process.stdout.write(`${JSON.stringify(migration, null, 2)}\n`);
  process.exit(0);
}
if (manifestFile) {
  if (!apply || prepare || migrateGatewayConfig || verifyGeneration) {
    throw new Error('--manifest-file requires --apply and cannot be combined with another mode');
  }
  if (!deploymentComponent) {
    throw new Error('--manifest-file requires --component wallet-core or --component product');
  }
  progress.step('Load and verify prepared component manifest');
  const preparedManifest = loadPreparedComponentManifest(manifestFile, target, deploymentComponent);
  progress.step('Validate GitHub authentication and repository access');
  repository = resolveGitHubRepository(requestedRepository);
  if (deploymentComponent === 'wallet-core') {
    assertTargetCanInitialize(target, repository, rotate);
  } else {
    assertWalletCoreGenerationMatches(preparedManifest, repository);
  }
  assertCompleteApplyInput(preparedManifest, true, allowIncomplete, manifestFile);
  const application = applyGeneratedValues(
    preparedManifest,
    repository,
    progress,
    resolve(repoRoot, manifestFile),
  );
  let verification;
  if (deploymentComponent === 'product') {
    verification = verifyAppliedGenerationMetadata(target, repository);
  }
  if (json) {
    process.stdout.write(
      `${JSON.stringify({ ...preparedManifest, application, verification }, null, 2)}\n`,
    );
  } else {
    printHumanOutput(preparedManifest, application);
    if (verification) printGenerationVerification(verification);
  }
  process.exit(0);
}
if (deploymentComponent) {
  throw new Error('--component is valid only with --manifest-file');
}
if (prepare && apply) {
  throw new Error('--prepare and --apply are separate operations');
}
if (apply) {
  throw new Error('--apply requires --manifest-file and --component');
}
if (prepare) {
  progress.step('Validate GitHub authentication and repository access');
  repository = resolveGitHubRepository(requestedRepository);
  assertTargetCanInitialize(target, repository, rotate);
}
progress.step('Load supplied deployment values');
const suppliedValues = loadSuppliedValues(valuesFile);
validateOptionalIntegrationInputs(target, suppliedValues);
if (prepare) {
  requireCloudflareApiTokenForApply(target, suppliedValues, valuesFile);
  configureWranglerEnvironment(target, suppliedValues);
  await discoverCloudflareValues(target, suppliedValues, progress);
}

function validateOptionalIntegrationInputs(targetName, suppliedValues) {
  const gatewayEnvironment = `${targetName}-gateway`;
  const runtimeProfileKind = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'GATEWAY_RUNTIME_PROFILE',
  );
  const emailOtpDeliveryKind = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'EMAIL_OTP_DELIVERY_MODE',
  );
  const runtimeProfile = buildGatewayRuntimeProfile(
    runtimeProfileKind || GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo,
    emailOtpDeliveryKind,
  );
  const relayerAccountId = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'RELAYER_ACCOUNT_ID',
  );
  const relayerPrivateKey = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'RELAYER_PRIVATE_KEY',
  );
  const relayerPublicKey = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'RELAYER_PUBLIC_KEY',
  );
  if (Boolean(relayerAccountId) !== Boolean(relayerPrivateKey)) {
    throw new Error(
      'RELAYER_ACCOUNT_ID and RELAYER_PRIVATE_KEY must be configured together for NEAR sponsorship',
    );
  }
  if (relayerPublicKey && !relayerAccountId) {
    throw new Error('RELAYER_PUBLIC_KEY requires RELAYER_ACCOUNT_ID');
  }
  if (runtimeProfile.nearFunding.kind === 'implicit_account_relayer' && !relayerAccountId) {
    throw new Error('GATEWAY_RUNTIME_PROFILE=testnet_live_demo requires a NEAR relayer');
  }
  const initialBalanceYocto = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'RELAYER_INITIAL_BALANCE_YOCTO',
  );
  if (initialBalanceYocto) {
    requirePositiveUnsignedInteger(initialBalanceYocto, 'RELAYER_INITIAL_BALANCE_YOCTO');
  }
  const sponsoredEvmExecutors = readSuppliedValue(
    suppliedValues,
    targetName,
    gatewayEnvironment,
    'SPONSORED_EVM_EXECUTORS_JSON',
  );
  if (sponsoredEvmExecutors) {
    parseSuppliedJsonObject('SPONSORED_EVM_EXECUTORS_JSON', sponsoredEvmExecutors);
  }
}

function requirePositiveUnsignedInteger(value, name) {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive unsigned integer`);
  }
  return value;
}
progress.step('Generate Router A/B deployment identities');
const deployment = runJsonScript(join(scriptDir, 'generate-deployment-keys.mjs'), [
  '--env',
  target,
  '--show-secrets',
  '--json',
]);
progress.step('Generate matched Deriver root shares');
const rootShares = runJsonScript(join(scriptDir, 'generate-root-share-keys.mjs'), ['--json']);
progress.step('Generate signing-session seal material');
const sealMaterial = runJsonScript(
  join(repoRoot, 'apps/web-server/scripts/generate-signing-session-seal-keys.mjs'),
  ['--key-version', `signing-session-seal-${target}-r1`, '--json'],
);
progress.step('Build and validate the GitHub Environment manifest');
const configuration = buildTargetConfiguration(target, suppliedValues);
const generatedSecrets = buildGeneratedSecrets(target, sealMaterial);
const output = buildOutput({
  target,
  deployment,
  rootShares,
  configuration,
  generatedSecrets,
});

resolveSuppliedEnvironmentValues(output.environments, target, suppliedValues);
attachDeploymentAuditMetadata(output);
output.manualInputs = collectManualInputs(output.environments);
output.requiredManualInputs = collectRequiredManualInputs(output.environments);
validateOutput(output);
validateWorkflowCoverage(output);
assertCompleteApplyInput(output, prepare, allowIncomplete, valuesFile);
const preparation = prepare ? writePreparedComponentManifests(output) : undefined;
if (preparation) {
  progress.detail(`Saved wallet-core manifest to ${preparation.walletCoreManifestPath}`);
  progress.detail(`Saved product manifest to ${preparation.productManifestPath}`);
}

if (json) {
  process.stdout.write(`${JSON.stringify({ ...output, preparation }, null, 2)}\n`);
} else {
  printHumanOutput(output, undefined);
  if (preparation) printPreparationOutput(preparation);
}

function printUsage() {
  console.log(`Generate the complete GitHub Environment manifest for one deployment target.

Usage:
  pnpm wallet-core:deploy:env-prepare -- --env staging
  pnpm wallet-core:deploy:env-prepare -- --env production
  pnpm wallet-core:deploy:env-prepare -- --env staging --rotate
  pnpm wallet-core:deploy:env-apply -- --env staging --manifest-file <path> --rotate
  pnpm product:deploy:env-apply -- --env staging --manifest-file <path>
  pnpm --silent wallet-core:deploy:env-prepare -- --env staging --json

Options:
  --env <target>               Required. staging or production.
  --gateway-origin <url>       Public HTTPS Gateway origin.
  --org-id <id>                Seams organization id.
  --project-id <id>            Seams project id.
  --environment-id <id>        Seams environment id.
  --project-environment-id <id>
                               Browser-facing project-environment id.
  --tenant-namespace <name>    Tenant storage namespace.
  --values-file <path>         Protected .env file containing external values.
                               Defaults to ~/.seams/<target>-deployment.env.
  --prepare                    Provision infrastructure and write separate protected manifests.
  --manifest-file <path>       Prepared wallet-core or product component manifest.
  --component <name>           wallet-core or product; required with --manifest-file.
  --apply                      Upload one prepared component manifest.
  --rotate                     Permit replacement of existing wallet-critical identities.
  --verify-generation          Verify audit metadata across all target environments.
  --migrate-gateway-config     Consolidate an initialized Gateway without rotating identities.
  --allow-incomplete           Permit a partial apply with unresolved required values.
  --repo <owner/repo>          GitHub repository; defaults to the current repo.
  --json                       Print one machine-readable JSON document.
  --help                       Show this help.

The command generates fresh Router A/B identities, matched root shares, internal
service authentication, ceremony JWT signing material, Gateway random secrets,
and signing-session seal material. Values from --values-file and the current
shell resolve matching external infrastructure, funded-account, domain, OAuth,
and Cloudflare placeholders. Prepare mode also discovers the Cloudflare account
and existing D1 database IDs through Wrangler when possible.

The output contains sensitive private keys and secrets. Redirect it only to an
encrypted secret-management location and do not commit it.

Prepare mode writes one protected wallet-core manifest and one protected
product manifest under ~/.seams/backups. Apply wallet-core first. Product apply
verifies the matching wallet-core generation before uploading the base target
environment.

WARNING: Every prepare invocation generates fresh identities. Preparing or
applying wallet-core for an initialized target requires --rotate.`);
}

function requireTarget() {
  const value = readOption('--env');
  if (!value) {
    throw new Error('--env is required; expected staging or production');
  }
  if (!VALID_TARGETS.has(value)) {
    throw new Error('--env must be staging or production');
  }
  return value;
}

function buildTargetConfiguration(targetName, suppliedValues) {
  const production = targetName === 'production';
  const runtimeProfileKind =
    readSuppliedValue(
      suppliedValues,
      targetName,
      `${targetName}-gateway`,
      'GATEWAY_RUNTIME_PROFILE',
    ) ||
    GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo;
  const emailOtpDeliveryKind = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'EMAIL_OTP_DELIVERY_MODE',
  );
  const runtimeProfile = buildGatewayRuntimeProfile(runtimeProfileKind, emailOtpDeliveryKind);
  const nearNetwork = gatewayRuntimeProfileNearNetwork(runtimeProfile);
  const generatedOrgId = `org_${targetName}`;
  const generatedProjectId = `project_${targetName}`;
  const generatedEnvironmentId = targetName;
  const gatewayOrigin =
    readOption('--gateway-origin') ||
    readSuppliedValue(suppliedValues, targetName, targetName, 'GATEWAY_ORIGIN') ||
    manual(`${targetName}-gateway-origin`);
  const orgId =
    readOption('--org-id') ||
    readSuppliedValue(suppliedValues, targetName, `${targetName}-gateway`, 'SEAMS_ORG_ID') ||
    generatedOrgId;
  const projectId =
    readOption('--project-id') ||
    readSuppliedValue(suppliedValues, targetName, `${targetName}-gateway`, 'SEAMS_PROJECT_ID') ||
    generatedProjectId;
  const environmentId =
    readOption('--environment-id') ||
    readSuppliedValue(suppliedValues, targetName, `${targetName}-gateway`, 'SEAMS_ENV_ID') ||
    generatedEnvironmentId;
  const projectEnvironmentId =
    readOption('--project-environment-id') ||
    readSuppliedValue(
      suppliedValues,
      targetName,
      targetName,
      'VITE_SEAMS_PROJECT_ENVIRONMENT_ID',
    ) ||
    environmentId;
  const tenantNamespace =
    readOption('--tenant-namespace') ||
    readSuppliedValue(
      suppliedValues,
      targetName,
      `${targetName}-gateway`,
      'SEAMS_TENANT_STORAGE_NAMESPACE',
    ) ||
    `seams-${targetName}`;
  const appOrigin =
    readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_APP_ORIGIN') ||
    manual(`${targetName}-app-origin`);
  const walletOrigin =
    readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_WALLET_ORIGIN') ||
    manual(`${targetName}-wallet-origin`);
  const rpId =
    readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_RP_ID_BASE') ||
    (targetName === 'production' ? 'sign.seams.sh' : undefined) ||
    hostnameFromOrigin(walletOrigin) ||
    manual(`${targetName}-webauthn-rp-id`);
  const nearRpcUrl =
    readSuppliedValue(suppliedValues, targetName, targetName, 'NEAR_RPC_URL') ||
    (nearNetwork === 'mainnet' ? 'https://rpc.mainnet.near.org' : 'https://rpc.testnet.near.org');
  const nearExplorerUrl =
    readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_NEAR_EXPLORER') ||
    (nearNetwork === 'mainnet' ? 'https://nearblocks.io' : 'https://testnet.nearblocks.io');
  const consoleDatabaseId =
    readSuppliedValue(
      suppliedValues,
      targetName,
      `${targetName}-gateway`,
      'GATEWAY_CONSOLE_D1_DATABASE_ID',
    ) || manual(`${targetName}-console-d1-database-id`);
  const signerDatabaseId =
    readSuppliedValue(
      suppliedValues,
      targetName,
      `${targetName}-gateway`,
      'GATEWAY_SIGNER_D1_DATABASE_ID',
    ) || manual(`${targetName}-signer-d1-database-id`);
  const secretsStoreId =
    readSuppliedValue(
      suppliedValues,
      targetName,
      `${targetName}-gateway`,
      'GATEWAY_SECRETS_STORE_ID',
    ) || manual(`${targetName}-cloudflare-secrets-store-id`);

  return {
    suppliedValues,
    runtimeProfile,
    gatewayOrigin,
    appOrigin,
    walletOrigin,
    rpId,
    nearRpcUrl,
    nearExplorerUrl,
    orgId,
    projectId,
    environmentId,
    projectEnvironmentId,
    tenantNamespace,
    gatewayWorkerName: production ? 'seams-sdk-d1-gateway' : 'seams-sdk-d1-gateway-staging',
    mpcRouterWorkerName: production ? 'router-ab-mpc-router' : 'router-ab-mpc-router-staging',
    deriverAWorkerName: production ? 'router-ab-deriver-a' : 'router-ab-deriver-a-staging',
    deriverBWorkerName: production ? 'router-ab-deriver-b' : 'router-ab-deriver-b-staging',
    signingWorkerName: production ? 'router-ab-signing-worker' : 'router-ab-signing-worker-staging',
    consoleDatabaseName: production ? 'seams-console' : 'seams-console-staging',
    consoleDatabaseId,
    signerDatabaseName: production ? 'seams-signer' : 'seams-signer-staging',
    signerDatabaseId,
    secretsStoreId,
    signingRootKekId: `signing-root-kek-${targetName}-r1`,
    ceremonyJwtKeyId: `router-ab-ceremony-${targetName}-r1`,
    signerSetId: `router-ab-${targetName}-signers-r1`,
    relaySessionIssuer: `seams-gateway-${targetName}`,
    routerJwtAudience: 'router-ab',
    nearNetwork,
  };
}

function buildGeneratedSecrets(targetName, sealMaterial) {
  return {
    internalServiceAuth: `router-ab-internal-service-auth-v1:${randomBase64Url(32)}`,
    relaySessionHmac: randomBase64Url(32),
    accountIdDerivation: randomBase64Url(32),
    ceremonyPrivateJwk: generateCeremonyPrivateJwk(),
    publishableKey: `pk_${randomBytes(16).toString('hex')}`,
    signingRootKek: randomBase64Url(32),
    signingSession: {
      keyVersion: sealMaterial.keyVersion,
      shamirPrimeB64u: sealMaterial.shamirPrimeB64u,
      serverEncryptExponentB64u: sealMaterial.serverEncryptExponentB64u,
      serverDecryptExponentB64u: sealMaterial.serverDecryptExponentB64u,
    },
    generationId: `${targetName}-${randomBase64Url(12)}`,
  };
}

function buildOutput(input) {
  const keyset = buildPublicKeyset(input.deployment);
  const registrationTopology = buildRegistrationTopology(input.configuration, input.deployment);
  const projectPolicy = buildProjectPolicy(input.target, input.configuration);
  const environments = buildEnvironments({
    target: input.target,
    deployment: input.deployment,
    rootShares: input.rootShares,
    configuration: input.configuration,
    generatedSecrets: input.generatedSecrets,
    keyset,
    registrationTopology,
    projectPolicy,
  });

  return {
    schemaVersion: 1,
    target: input.target,
    generationId: input.generatedSecrets.generationId,
    generatedAt: new Date().toISOString(),
    warning:
      'This document contains private keys and secrets. Store it securely and never commit it.',
    environments,
    manualInputs: collectManualInputs(environments),
  };
}

function attachDeploymentAuditMetadata(output) {
  const manifestSha256 = createHash('sha256')
    .update(JSON.stringify(buildDeploymentDigestPayload(output)), 'utf8')
    .digest('hex');
  output.manifestSha256 = manifestSha256;
  for (const environment of Object.values(output.environments)) {
    environment.variables = {
      SEAMS_DEPLOYMENT_GENERATION_ID: output.generationId,
      SEAMS_DEPLOYMENT_GENERATED_AT: output.generatedAt,
      SEAMS_DEPLOYMENT_MANIFEST_SHA256: manifestSha256,
      ...environment.variables,
    };
  }
}

function buildDeploymentDigestPayload(output) {
  return {
    schemaVersion: output.schemaVersion,
    target: output.target,
    generationId: output.generationId,
    generatedAt: output.generatedAt,
    environments: output.environments,
  };
}

function buildEnvironments(input) {
  return Object.fromEntries([
    buildGeneralEnvironment(input),
    buildGatewayEnvironment(input),
    buildMpcRouterEnvironment(input),
    buildDeriverAEnvironment(input),
    buildDeriverBEnvironment(input),
    buildSigningWorkerEnvironment(input),
  ]);
}

function deploymentComponentEnvironmentNames(targetName, component) {
  switch (component) {
    case 'wallet-core':
      return [
        `${targetName}-gateway`,
        `${targetName}-mpc-router`,
        `${targetName}-deriver-a`,
        `${targetName}-deriver-b`,
        `${targetName}-signing-worker`,
      ];
    case 'product':
      return [targetName];
    default:
      throw new Error(`unsupported deployment component: ${component}`);
  }
}

function buildPreparedComponentManifest(output, component) {
  const environmentNames = deploymentComponentEnvironmentNames(output.target, component);
  const environments = {};
  for (const environmentName of environmentNames) {
    environments[environmentName] = output.environments[environmentName];
  }
  const manifest = {
    schemaVersion: output.schemaVersion,
    target: output.target,
    deploymentComponent: component,
    generationId: output.generationId,
    generatedAt: output.generatedAt,
    manifestSha256: output.manifestSha256,
    warning: output.warning,
    environments,
    manualInputs: collectManualInputs(environments),
    requiredManualInputs: collectRequiredManualInputs(environments),
  };
  manifest.componentManifestSha256 = computeComponentManifestSha256(manifest);
  return manifest;
}

function computeComponentManifestSha256(manifest) {
  return createHash('sha256')
    .update(
      JSON.stringify({
        schemaVersion: manifest.schemaVersion,
        target: manifest.target,
        deploymentComponent: manifest.deploymentComponent,
        generationId: manifest.generationId,
        generatedAt: manifest.generatedAt,
        manifestSha256: manifest.manifestSha256,
        environments: manifest.environments,
      }),
      'utf8',
    )
    .digest('hex');
}

function buildGeneralEnvironment(input) {
  const environmentName = input.target;
  const configuration = input.configuration;
  const signingSession = input.generatedSecrets.signingSession;
  return [
    environmentName,
    {
      purpose: 'Pages builds',
      variables: {
        VITE_RELAYER_URL: configuration.gatewayOrigin,
        VITE_SEAMS_PROJECT_ENVIRONMENT_ID: configuration.projectEnvironmentId,
        VITE_SEAMS_PUBLISHABLE_KEY: input.generatedSecrets.publishableKey,
        VITE_NEAR_NETWORK: configuration.nearNetwork,
        VITE_NEAR_RPC_URL: configuration.nearRpcUrl,
        VITE_NEAR_EXPLORER: configuration.nearExplorerUrl,
        VITE_WALLET_ORIGIN: configuration.walletOrigin,
        VITE_RP_ID_BASE: configuration.rpId,
        VITE_SIGNING_SESSION_PERSISTENCE_MODE: 'sealed_refresh_v1',
        VITE_SIGNING_SESSION_SEAL_KEY_VERSION: signingSession.keyVersion,
        VITE_SIGNING_SESSION_SHAMIR_P_B64U: signingSession.shamirPrimeB64u,
        VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: configuration.signingWorkerName,
      },
      optionalVariables: {
        VITE_CONSOLE_BASE_URL: configuration.gatewayOrigin,
        VITE_RELAYER_ACCOUNT_ID: manual(`${input.target}-near-relayer-account-id`),
        VITE_TEMPO_RPC_URL: manual(`${input.target}-tempo-rpc-url`),
        VITE_TEMPO_EXPLORER: manual(`${input.target}-tempo-explorer-url`),
        VITE_TEMPO_FEE_TOKEN: manual(`${input.target}-tempo-fee-token`),
        VITE_ARC_RPC_URL: manual(`${input.target}-arc-rpc-url`),
        VITE_ARC_EXPLORER: manual(`${input.target}-arc-explorer-url`),
        VITE_WALLET_SERVICE_PATH: '/wallet-service',
        VITE_SDK_BASE_PATH: '/sdk',
        VITE_DOCS_ORIGIN: configuration.appOrigin,
        VITE_DASHBOARD_WALLETS_ROUTES_ENABLED: 'true',
      },
      secrets: {
        CLOUDFLARE_API_TOKEN: manual(`${environmentName}-cloudflare-pages-api-token`),
        CLOUDFLARE_ACCOUNT_ID: manual(`${input.target}-cloudflare-account-id`),
        CF_PAGES_PROJECT_VITE: manual(`${environmentName}-cloudflare-pages-app-project`),
        CF_PAGES_PROJECT_WALLET: manual(`${environmentName}-cloudflare-pages-wallet-project`),
      },
    },
  ];
}

function buildGatewayEnvironment(input) {
  const environmentName = `${input.target}-gateway`;
  const signingSession = input.generatedSecrets.signingSession;
  const deploymentConfig = buildGatewayDeploymentConfig(input);
  return [
    environmentName,
    {
      purpose: 'Gateway Worker, D1, tenant state, and public ceremony JWT issuer',
      variables: {
        GATEWAY_DEPLOYMENT_CONFIG_JSON: JSON.stringify(deploymentConfig),
      },
      optionalVariables: {},
      secrets: {
        CLOUDFLARE_API_TOKEN: manual(`${environmentName}-cloudflare-worker-api-token`),
        CLOUDFLARE_ACCOUNT_ID: manual(`${input.target}-cloudflare-account-id`),
        RELAY_SESSION_HMAC_SECRET: input.generatedSecrets.relaySessionHmac,
        ACCOUNT_ID_DERIVATION_SECRET: input.generatedSecrets.accountIdDerivation,
        ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: input.generatedSecrets.internalServiceAuth,
        ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK: input.generatedSecrets.ceremonyPrivateJwk,
        RELAYER_PRIVATE_KEY: manual(`${input.target}-near-relayer-private-key`),
        SPONSORED_EVM_EXECUTORS_JSON: manual(`${input.target}-sponsored-evm-executors-json`),
        SIGNING_ROOT_KEK_VALUE: input.generatedSecrets.signingRootKek,
        SIGNING_SESSION_SEAL_KEY_VERSION: signingSession.keyVersion,
        SIGNING_SESSION_SHAMIR_P_B64U: signingSession.shamirPrimeB64u,
        SIGNING_SESSION_SEAL_E_S_B64U: signingSession.serverEncryptExponentB64u,
        SIGNING_SESSION_SEAL_D_S_B64U: signingSession.serverDecryptExponentB64u,
      },
    },
  ];
}

function buildGatewayDeploymentConfig(input) {
  const configuration = input.configuration;
  const deploymentVariables = input.deployment.variables;
  return {
    schemaVersion: GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
    target: input.target,
    runtimeProfile: configuration.runtimeProfile,
    resources: {
      workerName: configuration.gatewayWorkerName,
      consoleD1: {
        name: configuration.consoleDatabaseName,
        id: configuration.consoleDatabaseId,
      },
      signerD1: {
        name: configuration.signerDatabaseName,
        id: configuration.signerDatabaseId,
      },
      secretsStoreId: configuration.secretsStoreId,
    },
    tenant: {
      namespace: configuration.tenantNamespace,
      orgId: configuration.orgId,
      projectId: configuration.projectId,
      environmentId: configuration.environmentId,
    },
    origins: {
      gateway: configuration.gatewayOrigin,
      allowedCors: [configuration.appOrigin, configuration.walletOrigin],
    },
    signingRoot: {
      id: configuration.signingRootKekId,
      secretName: configuration.signingRootKekId,
      encoding: 'base64url',
    },
    session: {
      issuer: configuration.relaySessionIssuer,
    },
    routerAb: {
      ceremonyJwtAudience: configuration.routerJwtAudience,
      ceremonyJwtKeyId: configuration.ceremonyJwtKeyId,
      publicKeyset: input.keyset,
      registrationTopology: input.registrationTopology,
      deriverAYaoInputPublicKey: deploymentVariables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
      deriverBYaoInputPublicKey: deploymentVariables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
      signingWorkerOutputPublicKey:
        deploymentVariables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    },
    bootstrap: {
      publishableKey: input.generatedSecrets.publishableKey,
      allowedOrigins: [configuration.appOrigin, configuration.walletOrigin],
    },
    optional: buildGatewayOptionalDeploymentConfig(input),
  };
}

function buildGatewayOptionalDeploymentConfig(input) {
  const suppliedValues = input.configuration.suppliedValues;
  const relayerAccountId = readSuppliedValue(
    suppliedValues,
    input.target,
    `${input.target}-gateway`,
    'RELAYER_ACCOUNT_ID',
  );
  const relayerPublicKey = readSuppliedValue(
    suppliedValues,
    input.target,
    `${input.target}-gateway`,
    'RELAYER_PUBLIC_KEY',
  );
  const initialBalanceYocto =
    readSuppliedValue(
      suppliedValues,
      input.target,
      `${input.target}-gateway`,
      'RELAYER_INITIAL_BALANCE_YOCTO',
    ) || DEFAULT_NEAR_INITIAL_BALANCE_YOCTO;
  const googleOidcClientId = readSuppliedValue(
    suppliedValues,
    input.target,
    `${input.target}-gateway`,
    'GOOGLE_OIDC_CLIENT_ID',
  );
  const oidcExchangeJson = readSuppliedValue(
    suppliedValues,
    input.target,
    `${input.target}-gateway`,
    'SEAMS_OIDC_EXCHANGE_JSON',
  );
  return {
    nearRelayer: relayerAccountId
      ? {
          accountId: relayerAccountId,
          publicKey: relayerPublicKey || null,
          rpcUrl: input.configuration.nearRpcUrl,
          initialBalanceYocto,
        }
      : null,
    googleOidcClientId: googleOidcClientId || null,
    oidcExchange: oidcExchangeJson
      ? parseSuppliedJsonObject('SEAMS_OIDC_EXCHANGE_JSON', oidcExchangeJson)
      : null,
  };
}

function buildMpcRouterEnvironment(input) {
  const environmentName = `${input.target}-mpc-router`;
  const variables = input.deployment.variables;
  return [
    environmentName,
    {
      purpose: 'MPCRouter Worker',
      variables: {
        ROUTER_AB_JWT_ISSUER: input.configuration.gatewayOrigin,
        ROUTER_AB_JWT_AUDIENCE: input.configuration.routerJwtAudience,
        ROUTER_AB_JWT_JWKS_URL: buildGatewayJwksUrl(input.configuration.gatewayOrigin),
        ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:
          variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:
          variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
          variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON: JSON.stringify(input.projectPolicy),
      },
      optionalVariables: {},
      secrets: buildWorkerDeploymentSecrets(
        input.target,
        environmentName,
        input.generatedSecrets.internalServiceAuth,
      ),
    },
  ];
}

function buildDeriverAEnvironment(input) {
  const environmentName = `${input.target}-deriver-a`;
  const variables = input.deployment.variables;
  const secrets = buildWorkerDeploymentSecrets(
    input.target,
    environmentName,
    input.generatedSecrets.internalServiceAuth,
  );
  secrets.DERIVER_A_ROOT_SHARE_WIRE_SECRET =
    input.rootShares.secrets.account1DeriverA.DERIVER_A_ROOT_SHARE_WIRE_SECRET;
  secrets.DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY =
    input.deployment.secrets.DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY;
  secrets.DERIVER_A_PEER_SIGNING_KEY = input.deployment.secrets.DERIVER_A_PEER_SIGNING_KEY;
  return [
    environmentName,
    {
      purpose: 'Deriver A Worker',
      variables: {
        ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY:
          variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
      optionalVariables: {},
      secrets,
    },
  ];
}

function buildDeriverBEnvironment(input) {
  const environmentName = `${input.target}-deriver-b`;
  const variables = input.deployment.variables;
  const secrets = buildWorkerDeploymentSecrets(
    input.target,
    environmentName,
    input.generatedSecrets.internalServiceAuth,
  );
  secrets.DERIVER_B_ROOT_SHARE_WIRE_SECRET =
    input.rootShares.secrets.account2DeriverB.DERIVER_B_ROOT_SHARE_WIRE_SECRET;
  secrets.DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY =
    input.deployment.secrets.DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY;
  secrets.DERIVER_B_PEER_SIGNING_KEY = input.deployment.secrets.DERIVER_B_PEER_SIGNING_KEY;
  return [
    environmentName,
    {
      purpose: 'Deriver B Worker',
      variables: {
        ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY:
          variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
        ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
        ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX:
          variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
      optionalVariables: {},
      secrets,
    },
  ];
}

function buildSigningWorkerEnvironment(input) {
  const environmentName = `${input.target}-signing-worker`;
  const secrets = buildWorkerDeploymentSecrets(
    input.target,
    environmentName,
    input.generatedSecrets.internalServiceAuth,
  );
  secrets.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY =
    input.deployment.secrets.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PRIVATE_KEY;
  return [
    environmentName,
    {
      purpose: 'SigningWorker Worker',
      variables: {
        ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY:
          input.deployment.variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
      },
      optionalVariables: {},
      secrets,
    },
  ];
}

function buildWorkerDeploymentSecrets(targetName, environmentName, internalServiceAuth) {
  return {
    CLOUDFLARE_API_TOKEN: manual(`${environmentName}-cloudflare-worker-api-token`),
    CLOUDFLARE_ACCOUNT_ID: manual(`${targetName}-cloudflare-account-id`),
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: internalServiceAuth,
  };
}

function buildPublicKeyset(deployment) {
  const variables = deployment.variables;
  return {
    keyset_version: 'router_ab_keyset_v2',
    signer_envelope_hpke: {
      current: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: 'epoch-1',
          public_key: variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: 'epoch-1',
          public_key: variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
        },
      },
    },
    signer_peer_verifying_keys: {
      deriver_a: {
        role: 'signer_a',
        verifying_key_hex: variables.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
      },
      deriver_b: {
        role: 'signer_b',
        verifying_key_hex: variables.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
      },
    },
    signing_worker_server_output_hpke: {
      key_epoch: 'epoch-1',
      public_key: variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    },
  };
}

function buildRegistrationTopology(configuration, deployment) {
  const variables = deployment.variables;
  return {
    routerId: configuration.mpcRouterWorkerName,
    signerSet: {
      signer_set_id: configuration.signerSetId,
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: 'epoch-1',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: 'epoch-1',
      },
      selected_server: {
        server_id: configuration.signingWorkerName,
        key_epoch: 'epoch-1',
        recipient_encryption_key: variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
      },
    },
    deriverRecipientKeys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-1',
        public_key: variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-1',
        public_key: variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
      },
    },
  };
}

function buildProjectPolicy(targetName, configuration) {
  return {
    org_id: configuration.orgId,
    project_id: configuration.projectId,
    environment: targetName,
    allowed_work_kinds: ['registration_prepare', 'key_export', 'recovery', 'server_share_refresh'],
    allow_normal_signing: true,
    rejected_retry_after_ms: 1000,
  };
}

function generateCeremonyPrivateJwk() {
  const { privateKey } = generateKeyPairSync('ed25519');
  const privateJwk = privateKey.export({ format: 'jwk' });
  if (
    privateJwk.kty !== 'OKP' ||
    privateJwk.crv !== 'Ed25519' ||
    typeof privateJwk.x !== 'string' ||
    typeof privateJwk.d !== 'string'
  ) {
    throw new Error('generated ceremony JWT key is not an Ed25519 private JWK');
  }
  return JSON.stringify({
    kty: privateJwk.kty,
    crv: privateJwk.crv,
    x: privateJwk.x,
    d: privateJwk.d,
  });
}

function buildGatewayJwksUrl(gatewayOrigin) {
  return `${gatewayOrigin.replace(/\/+$/, '')}${CEREMONY_JWKS_PATH}`;
}

function hostnameFromOrigin(origin) {
  if (isManualValue(origin)) {
    return undefined;
  }
  try {
    return new URL(origin).hostname;
  } catch {
    throw new Error(`wallet origin must be an absolute URL: ${origin}`);
  }
}

function parseSuppliedJsonObject(name, value) {
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must contain a JSON object`);
  }
  return parsed;
}

function randomBase64Url(byteLength) {
  return randomBytes(byteLength).toString('base64url');
}

function loadSuppliedValues(valuesFilePath) {
  const fileValues = valuesFilePath ? loadValuesFile(valuesFilePath) : {};
  return {
    ...fileValues,
    ...process.env,
  };
}

function findDefaultValuesFile(targetName) {
  const defaultPath = join(homedir(), '.seams', `${targetName}-deployment.env`);
  return existsSync(defaultPath) ? defaultPath : undefined;
}

function loadValuesFile(valuesFilePath) {
  const absolutePath = resolve(repoRoot, valuesFilePath);
  try {
    return parseEnv(readFileSync(absolutePath, 'utf8'));
  } catch (error) {
    throw new Error(`failed to load deployment values file ${absolutePath}: ${error.message}`);
  }
}

async function discoverCloudflareValues(targetName, suppliedValues, progressLogger) {
  const accountId = discoverCloudflareAccountId(targetName, suppliedValues, progressLogger);
  ensureD1Database({
    targetName,
    suppliedValues,
    progressLogger,
    variableName: 'GATEWAY_CONSOLE_D1_DATABASE_ID',
    databaseName: targetName === 'production' ? 'seams-console' : 'seams-console-staging',
  });
  ensureD1Database({
    targetName,
    suppliedValues,
    progressLogger,
    variableName: 'GATEWAY_SIGNER_D1_DATABASE_ID',
    databaseName: targetName === 'production' ? 'seams-signer' : 'seams-signer-staging',
  });
  ensurePagesProjects(targetName, suppliedValues, progressLogger);
  ensureSecretsStore(targetName, suppliedValues, progressLogger);
  await discoverWorkersDevOrigin(targetName, suppliedValues, accountId, progressLogger);
}

function requireCloudflareApiTokenForApply(targetName, suppliedValues, valuesFilePath) {
  const token = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'CLOUDFLARE_API_TOKEN',
  );
  if (token) {
    return;
  }
  const source = valuesFilePath
    ? resolve(repoRoot, valuesFilePath)
    : join(homedir(), '.seams', `${targetName}-deployment.env`);
  throw new Error(
    `CLOUDFLARE_API_TOKEN is required before apply mode can provision resources. ` +
      `Add it to ${source}.`,
  );
}

function configureWranglerEnvironment(targetName, suppliedValues) {
  const apiToken = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'CLOUDFLARE_API_TOKEN',
  );
  const accountId = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'CLOUDFLARE_ACCOUNT_ID',
  );
  wranglerEnvironment = {
    ...process.env,
    ...(apiToken ? { CLOUDFLARE_API_TOKEN: apiToken } : {}),
    ...(accountId ? { CLOUDFLARE_ACCOUNT_ID: accountId } : {}),
  };
}

function discoverCloudflareAccountId(targetName, suppliedValues, progressLogger) {
  const existing = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'CLOUDFLARE_ACCOUNT_ID',
  );
  if (existing) {
    return existing;
  }
  const whoami = runWranglerJson(['whoami', '--json']);
  if (!whoami.ok) {
    progressLogger.detail(
      'Cloudflare account discovery skipped: Wrangler authentication is unavailable',
    );
    return undefined;
  }
  const accounts = Array.isArray(whoami.value.accounts) ? whoami.value.accounts : [];
  if (accounts.length !== 1 || typeof accounts[0]?.id !== 'string') {
    progressLogger.detail(
      `Cloudflare account discovery skipped: expected one Wrangler account, found ${accounts.length}`,
    );
    return undefined;
  }
  suppliedValues.CLOUDFLARE_ACCOUNT_ID = accounts[0].id;
  wranglerEnvironment = {
    ...wranglerEnvironment,
    CLOUDFLARE_ACCOUNT_ID: accounts[0].id,
  };
  progressLogger.detail('Discovered CLOUDFLARE_ACCOUNT_ID through Wrangler');
  return accounts[0].id;
}

function ensureD1Database(input) {
  const existing = readSuppliedValue(
    input.suppliedValues,
    input.targetName,
    `${input.targetName}-gateway`,
    input.variableName,
  );
  if (existing) {
    return;
  }
  let database = runWranglerJson(['d1', 'info', input.databaseName, '--json']);
  if (!database.ok || typeof database.value.uuid !== 'string') {
    const created = runWrangler(['d1', 'create', input.databaseName]);
    if (created.status !== 0) {
      throw new Error(formatWranglerFailure(`create D1 database ${input.databaseName}`, created));
    }
    database = runWranglerJson(['d1', 'info', input.databaseName, '--json']);
    if (!database.ok || typeof database.value.uuid !== 'string') {
      throw new Error(`created D1 database ${input.databaseName} but could not resolve its UUID`);
    }
    input.progressLogger.detail(`Created D1 database ${input.databaseName}`);
  }
  input.suppliedValues[input.variableName] = database.value.uuid;
  input.progressLogger.detail(`Resolved ${input.variableName} from ${input.databaseName}`);
}

function ensurePagesProjects(targetName, suppliedValues, progressLogger) {
  const appProject = readSuppliedValue(
    suppliedValues,
    targetName,
    targetName,
    'CF_PAGES_PROJECT_VITE',
  );
  const walletProject = readSuppliedValue(
    suppliedValues,
    targetName,
    targetName,
    'CF_PAGES_PROJECT_WALLET',
  );
  const projects = runWranglerJson(['pages', 'project', 'list', '--json']);
  if (!projects.ok || !Array.isArray(projects.value)) {
    throw new Error('failed to list Cloudflare Pages projects');
  }
  const names = new Set();
  const projectsByName = new Map();
  for (const project of projects.value) {
    const projectName = readPagesProjectName(project);
    if (projectName) {
      names.add(projectName);
      projectsByName.set(projectName, project);
    }
  }
  const defaultAppProject =
    targetName === 'production' && names.has('seams-site')
      ? 'seams-site'
      : `seams-site-${targetName}`;
  const defaultWalletProject =
    targetName === 'production' && names.has('seams-wallet')
      ? 'seams-wallet'
      : `seams-wallet-${targetName}`;
  const resolvedAppProject = appProject || defaultAppProject;
  const resolvedWalletProject = walletProject || defaultWalletProject;
  ensurePagesProject(resolvedAppProject, names, targetName, progressLogger);
  ensurePagesProject(resolvedWalletProject, names, targetName, progressLogger);
  suppliedValues.CF_PAGES_PROJECT_VITE = resolvedAppProject;
  suppliedValues.CF_PAGES_PROJECT_WALLET = resolvedWalletProject;
  if (!readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_APP_ORIGIN')) {
    suppliedValues.VITE_APP_ORIGIN = pagesProjectOrigin(
      resolvedAppProject,
      projectsByName.get(resolvedAppProject),
    );
  }
  if (!readSuppliedValue(suppliedValues, targetName, targetName, 'VITE_WALLET_ORIGIN')) {
    suppliedValues.VITE_WALLET_ORIGIN =
      targetName === 'production'
        ? 'https://sign.seams.sh'
        : pagesProjectOrigin(resolvedWalletProject, projectsByName.get(resolvedWalletProject));
  }
  progressLogger.detail(
    `Resolved Pages projects ${resolvedAppProject} and ${resolvedWalletProject}`,
  );
}

function ensurePagesProject(projectName, existingNames, targetName, progressLogger) {
  if (existingNames.has(projectName)) {
    return;
  }
  const productionBranch = targetName === 'production' ? 'main' : 'dev';
  const created = runWrangler([
    'pages',
    'project',
    'create',
    projectName,
    '--production-branch',
    productionBranch,
  ]);
  if (created.status !== 0) {
    throw new Error(formatWranglerFailure(`create Pages project ${projectName}`, created));
  }
  existingNames.add(projectName);
  progressLogger.detail(`Created Pages project ${projectName}`);
}

function readPagesProjectName(project) {
  if (!project || typeof project !== 'object') {
    return undefined;
  }
  const name = project['Project Name'];
  return typeof name === 'string' ? name : undefined;
}

function pagesProjectOrigin(projectName, project) {
  const domains =
    typeof project?.['Project Domains'] === 'string'
      ? project['Project Domains']
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean)
      : [];
  const customDomain = domains.find((domain) => domain !== `${projectName}.pages.dev`);
  return `https://${customDomain || `${projectName}.pages.dev`}`;
}

function ensureSecretsStore(targetName, suppliedValues, progressLogger) {
  const suppliedStoreId = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'GATEWAY_SECRETS_STORE_ID',
  );
  if (suppliedStoreId) {
    return;
  }
  const storeName = `seams-gateway-${targetName}`;
  let stores = listSecretsStores();
  let storeId = stores.get(storeName);
  if (!storeId && stores.size === 1) {
    const [[existingStoreName, existingStoreId]] = stores;
    storeId = existingStoreId;
    progressLogger.detail(`Reusing account Secrets Store ${existingStoreName}`);
  }
  if (!storeId && stores.size > 1) {
    throw new Error(
      'Multiple Cloudflare Secrets Stores are available; supply GATEWAY_SECRETS_STORE_ID',
    );
  }
  if (!storeId) {
    const created = runWrangler(['secrets-store', 'store', 'create', storeName, '--remote']);
    if (created.status !== 0) {
      throw new Error(formatWranglerFailure(`create Secrets Store ${storeName}`, created));
    }
    stores = listSecretsStores();
    storeId = stores.get(storeName);
    if (!storeId) {
      throw new Error(`created Secrets Store ${storeName} but could not resolve its ID`);
    }
    progressLogger.detail(`Created Secrets Store ${storeName}`);
  }
  suppliedValues.GATEWAY_SECRETS_STORE_ID = storeId;
  progressLogger.detail(`Resolved GATEWAY_SECRETS_STORE_ID from ${storeName}`);
}

function listSecretsStores() {
  const listed = runWrangler(['secrets-store', 'store', 'list', '--remote', '--per-page', '100']);
  if (listed.status !== 0) {
    throw new Error(formatWranglerFailure('list Secrets Stores', listed));
  }
  const stores = new Map();
  for (const line of String(listed.stdout).split(/\r?\n/)) {
    const match = /^│\s*([A-Za-z0-9_.-]+)\s*│\s*([a-f0-9]{32})\s*│/.exec(line);
    if (match) {
      stores.set(match[1], match[2]);
    }
  }
  return stores;
}

async function discoverWorkersDevOrigin(targetName, suppliedValues, accountId, progressLogger) {
  const existing = readSuppliedValue(suppliedValues, targetName, targetName, 'GATEWAY_ORIGIN');
  if (existing || !accountId) {
    return;
  }
  const apiToken = readSuppliedValue(
    suppliedValues,
    targetName,
    `${targetName}-gateway`,
    'CLOUDFLARE_API_TOKEN',
  );
  if (!apiToken) {
    progressLogger.detail('Gateway origin discovery requires CLOUDFLARE_API_TOKEN');
    return;
  }
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/subdomain`,
    {
      headers: {
        Authorization: `Bearer ${apiToken}`,
      },
    },
  );
  const body = await response.json();
  const subdomain = body?.result?.subdomain;
  if (!response.ok || body?.success !== true || typeof subdomain !== 'string' || !subdomain) {
    throw new Error('failed to resolve the Cloudflare Workers subdomain');
  }
  const workerName =
    targetName === 'production' ? 'seams-sdk-d1-gateway' : 'seams-sdk-d1-gateway-staging';
  suppliedValues.GATEWAY_ORIGIN = `https://${workerName}.${subdomain}.workers.dev`;
  progressLogger.detail('Derived GATEWAY_ORIGIN from the Cloudflare Workers subdomain');
}

function runWranglerJson(args) {
  const child = runWrangler(args);
  if (child.status !== 0) {
    return { ok: false };
  }
  try {
    return {
      ok: true,
      value: JSON.parse(child.stdout),
    };
  } catch {
    return { ok: false };
  }
}

function runWrangler(args) {
  return spawnSync(wranglerCli, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: wranglerEnvironment,
    maxBuffer: 10 * 1024 * 1024,
  });
}

function formatWranglerFailure(operation, child) {
  const detail = String(child.stderr || child.stdout || `exit status ${child.status}`).trim();
  return `${operation} failed: ${detail}`;
}

function resolveSuppliedEnvironmentValues(environments, targetName, suppliedValues) {
  for (const [environmentName, environment] of Object.entries(environments)) {
    resolveSuppliedSectionValues(
      environment.variables,
      targetName,
      environmentName,
      suppliedValues,
    );
    resolveSuppliedSectionValues(
      environment.optionalVariables,
      targetName,
      environmentName,
      suppliedValues,
    );
    resolveSuppliedSectionValues(environment.secrets, targetName, environmentName, suppliedValues);
  }
}

function resolveSuppliedSectionValues(values, targetName, environmentName, suppliedValues) {
  for (const [name, value] of Object.entries(values)) {
    if (!isManualValue(value)) {
      continue;
    }
    const supplied = readSuppliedValue(suppliedValues, targetName, environmentName, name);
    if (supplied) {
      values[name] = supplied;
    }
  }
}

function readSuppliedValue(suppliedValues, targetName, environmentName, name) {
  const aliases = SUPPLIED_VALUE_ALIASES[name] || [];
  const names = [name, ...aliases];
  for (const candidateName of names) {
    const value = readFirstNonEmptyValue(suppliedValues, [
      `${toEnvironmentPrefix(environmentName)}__${candidateName}`,
      `${toEnvironmentPrefix(targetName)}__${candidateName}`,
      candidateName,
    ]);
    if (value) {
      return value;
    }
  }
  return undefined;
}

function readFirstNonEmptyValue(values, names) {
  for (const name of names) {
    const value = values[name];
    if (typeof value === 'string' && value.trim() && !value.includes('<manual:')) {
      return value.trim();
    }
  }
  return undefined;
}

function toEnvironmentPrefix(environmentName) {
  return environmentName.replace(/[^A-Za-z0-9]+/g, '_').toUpperCase();
}

function manual(name) {
  return `<manual:${name}>`;
}

function collectManualInputs(environments) {
  const paths = [];
  for (const [environmentName, environment] of Object.entries(environments)) {
    collectManualValuePaths(paths, environmentName, 'variables', environment.variables);
    collectManualValuePaths(
      paths,
      environmentName,
      'optionalVariables',
      environment.optionalVariables,
    );
    collectManualValuePaths(paths, environmentName, 'secrets', environment.secrets);
  }
  return paths;
}

function collectRequiredManualInputs(environments) {
  const paths = [];
  for (const [environmentName, environment] of Object.entries(environments)) {
    collectManualValuePaths(paths, environmentName, 'variables', environment.variables);
    collectRequiredSecretPaths(paths, environmentName, environment.secrets);
  }
  return paths;
}

function collectRequiredSecretPaths(paths, environmentName, secrets) {
  for (const [name, value] of Object.entries(secrets)) {
    if (OPTIONAL_SECRET_NAMES.has(name) || !String(value).includes('<manual:')) {
      continue;
    }
    paths.push(`${environmentName}.secrets.${name}`);
  }
}

function collectManualValuePaths(paths, environmentName, sectionName, values) {
  for (const [name, value] of Object.entries(values)) {
    if (String(value).includes('<manual:')) {
      paths.push(`${environmentName}.${sectionName}.${name}`);
    }
  }
}

function assertCompleteApplyInput(outputDocument, shouldApply, incompleteAllowed, valuesFilePath) {
  if (!shouldApply || incompleteAllowed || outputDocument.requiredManualInputs.length === 0) {
    return;
  }
  let valuesFileInstruction;
  if (outputDocument.deploymentComponent) {
    valuesFileInstruction =
      'Update the protected deployment values and prepare a new generation. ' +
      'Prepared manifests are immutable.';
  } else if (valuesFilePath) {
    valuesFileInstruction = `Complete ${resolve(repoRoot, valuesFilePath)} and rerun the command.`;
  } else {
    valuesFileInstruction =
      'Create ~/.seams/' +
      `${outputDocument.target}-deployment.env from ` +
      'crates/router-ab-cloudflare/env/deployment-values.example.env, fill it, and rerun.';
  }
  throw new Error(
    `Required deployment values are unresolved. ${valuesFileInstruction}\n\n` +
      `Missing:\n- ${outputDocument.requiredManualInputs.join('\n- ')}\n\n` +
      'Use --allow-incomplete only for an intentional partial bootstrap.',
  );
}

function validateOutput(outputDocument) {
  const expectedEnvironmentNames = [
    outputDocument.target,
    `${outputDocument.target}-gateway`,
    `${outputDocument.target}-mpc-router`,
    `${outputDocument.target}-deriver-a`,
    `${outputDocument.target}-deriver-b`,
    `${outputDocument.target}-signing-worker`,
  ];
  assertEqual(
    Object.keys(outputDocument.environments),
    expectedEnvironmentNames,
    'generated GitHub Environment names',
  );
  validateEnvironmentValues(outputDocument.environments);
  validateCloudflareServiceBindingAccount(outputDocument);
  validateSharedInternalServiceAuth(outputDocument);
  validateRoleSecretIsolation(outputDocument);
  validateRouterPublicIdentityConsistency(outputDocument);
  validateGatewayRegistrationDocuments(outputDocument);
  validateSigningSessionConsistency(outputDocument);
}

function validateWorkflowCoverage(outputDocument) {
  const targetName = outputDocument.target;
  const routerWorkflow = readWorkflow('internal-deploy-cloudflare-stack.yml');
  const requirements = new Map([
    [
      targetName,
      mergeWorkflowRequirements(
        collectWorkflowRequirements(readWorkflow('internal-deploy-cloudflare-pages.yml')),
      ),
    ],
    [
      `${targetName}-gateway`,
      collectWorkflowRequirements(readWorkflow('internal-deploy-cloudflare-gateway.yml')),
    ],
    [
      `${targetName}-mpc-router`,
      collectWorkflowRequirements(extractWorkflowJob(routerWorkflow, 'deploy_mpc_router')),
    ],
    [
      `${targetName}-deriver-a`,
      collectWorkflowRequirements(extractWorkflowJob(routerWorkflow, 'deploy_deriver_a')),
    ],
    [
      `${targetName}-deriver-b`,
      collectWorkflowRequirements(extractWorkflowJob(routerWorkflow, 'deploy_deriver_b')),
    ],
    [
      `${targetName}-signing-worker`,
      collectWorkflowRequirements(extractWorkflowJob(routerWorkflow, 'deploy_signing_worker')),
    ],
  ]);

  for (const [environmentName, required] of requirements) {
    const environment = outputDocument.environments[environmentName];
    const generatedVariables = new Set([
      ...Object.keys(environment.variables),
      ...Object.keys(environment.optionalVariables),
    ]);
    assertWorkflowNamesCovered(environmentName, 'variable', required.variables, generatedVariables);
    assertWorkflowNamesCovered(
      environmentName,
      'secret',
      required.secrets,
      new Set(Object.keys(environment.secrets)),
    );
  }
}

function readWorkflow(fileName) {
  return readFileSync(join(repoRoot, '.github/workflows', fileName), 'utf8');
}

function extractWorkflowJob(workflowSource, jobName) {
  const jobsIndex = workflowSource.search(/^jobs:\s*$/m);
  if (jobsIndex === -1) {
    throw new Error(`workflow does not define jobs: ${jobName}`);
  }
  const jobsSource = workflowSource.slice(jobsIndex);
  const jobPattern = /^ {2}([A-Za-z0-9_-]+):\s*$/gm;
  const matches = [...jobsSource.matchAll(jobPattern)];
  const matchIndex = matches.findIndex((match) => match[1] === jobName);
  if (matchIndex === -1) {
    throw new Error(`workflow job was not found: ${jobName}`);
  }
  const start = matches[matchIndex].index;
  const end = matches[matchIndex + 1]?.index ?? jobsSource.length;
  return jobsSource.slice(start, end);
}

function collectWorkflowRequirements(workflowSource) {
  const variables = new Set();
  const secrets = new Set();
  const referencePattern = /\b(vars|secrets)\.([A-Z][A-Z0-9_]*)/g;
  for (const match of workflowSource.matchAll(referencePattern)) {
    (match[1] === 'vars' ? variables : secrets).add(match[2]);
  }
  return { variables, secrets };
}

function mergeWorkflowRequirements(...requirements) {
  return {
    variables: new Set(requirements.flatMap((requirement) => [...requirement.variables])),
    secrets: new Set(requirements.flatMap((requirement) => [...requirement.secrets])),
  };
}

function assertWorkflowNamesCovered(environmentName, kind, required, generated) {
  const missing = [...required].filter((name) => !generated.has(name));
  if (missing.length > 0) {
    throw new Error(
      `${environmentName} is missing GitHub workflow ${kind}s: ${missing.join(', ')}`,
    );
  }
}

function validateEnvironmentValues(environments) {
  for (const [environmentName, environment] of Object.entries(environments)) {
    for (const sectionName of ['variables', 'optionalVariables', 'secrets']) {
      const section = environment[sectionName];
      if (!section || typeof section !== 'object' || Array.isArray(section)) {
        throw new Error(`${environmentName}.${sectionName} must be an object`);
      }
      for (const [name, value] of Object.entries(section)) {
        if (typeof value !== 'string' || value.trim() === '') {
          throw new Error(`${environmentName}.${sectionName}.${name} must be non-empty`);
        }
      }
    }
  }
}

function validateCloudflareServiceBindingAccount(outputDocument) {
  const names = [
    `${outputDocument.target}-gateway`,
    `${outputDocument.target}-mpc-router`,
    `${outputDocument.target}-deriver-a`,
    `${outputDocument.target}-deriver-b`,
    `${outputDocument.target}-signing-worker`,
  ];
  const accountIds = names.map(
    (name) => outputDocument.environments[name].secrets.CLOUDFLARE_ACCOUNT_ID,
  );
  if (new Set(accountIds).size !== 1) {
    throw new Error('Gateway and Router A/B service bindings require one Cloudflare account');
  }
}

function validateSharedInternalServiceAuth(outputDocument) {
  const names = [
    `${outputDocument.target}-gateway`,
    `${outputDocument.target}-mpc-router`,
    `${outputDocument.target}-deriver-a`,
    `${outputDocument.target}-deriver-b`,
    `${outputDocument.target}-signing-worker`,
  ];
  const values = names.map(
    (name) => outputDocument.environments[name].secrets.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET,
  );
  if (new Set(values).size !== 1) {
    throw new Error('Router A/B and Gateway internal service authentication must match');
  }
}

function validateRoleSecretIsolation(outputDocument) {
  const deriverA = outputDocument.environments[`${outputDocument.target}-deriver-a`].secrets;
  const deriverB = outputDocument.environments[`${outputDocument.target}-deriver-b`].secrets;
  const signingWorker =
    outputDocument.environments[`${outputDocument.target}-signing-worker`].secrets;
  assertAbsent(deriverA, [
    'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
    'DERIVER_B_PEER_SIGNING_KEY',
  ]);
  assertAbsent(deriverB, [
    'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
    'DERIVER_A_PEER_SIGNING_KEY',
  ]);
  assertAbsent(signingWorker, [
    'DERIVER_A_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_B_ROOT_SHARE_WIRE_SECRET',
    'DERIVER_A_ENVELOPE_HPKE_PRIVATE_KEY',
    'DERIVER_B_ENVELOPE_HPKE_PRIVATE_KEY',
  ]);
  if (deriverA.DERIVER_A_ROOT_SHARE_WIRE_SECRET === deriverB.DERIVER_B_ROOT_SHARE_WIRE_SECRET) {
    throw new Error('Deriver A and Deriver B root shares must differ');
  }
}

function validateRouterPublicIdentityConsistency(outputDocument) {
  const environments = outputDocument.environments;
  const router = environments[`${outputDocument.target}-mpc-router`].variables;
  const deriverA = environments[`${outputDocument.target}-deriver-a`].variables;
  const deriverB = environments[`${outputDocument.target}-deriver-b`].variables;
  const signingWorker = environments[`${outputDocument.target}-signing-worker`].variables;
  assertEqual(
    deriverA.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
    router.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
    'Deriver A envelope public key',
  );
  assertEqual(
    deriverB.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
    router.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
    'Deriver B envelope public key',
  );
  assertEqual(
    signingWorker.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    router.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    'SigningWorker output public key',
  );
  assertEqual(
    deriverA.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
    router.ROUTER_AB_DERIVER_A_PEER_VERIFYING_KEY_HEX,
    'Deriver A peer verifying key',
  );
  assertEqual(
    deriverB.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
    router.ROUTER_AB_DERIVER_B_PEER_VERIFYING_KEY_HEX,
    'Deriver B peer verifying key',
  );
}

function validateGatewayRegistrationDocuments(outputDocument) {
  const environments = outputDocument.environments;
  const gateway = environments[`${outputDocument.target}-gateway`];
  const router = environments[`${outputDocument.target}-mpc-router`];
  const deploymentConfig = parseGatewayDeploymentConfig(gateway);
  const keyset = deploymentConfig.routerAb.publicKeyset;
  const topology = deploymentConfig.routerAb.registrationTopology;
  const policy = JSON.parse(router.variables.ROUTER_AB_PROJECT_POLICY_BOOTSTRAP_JSON);
  assertEqual(
    keyset.signer_envelope_hpke.current.deriver_a.public_key,
    router.variables.ROUTER_AB_DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
    'Gateway keyset Deriver A public key',
  );
  assertEqual(
    keyset.signer_envelope_hpke.current.deriver_b.public_key,
    router.variables.ROUTER_AB_DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
    'Gateway keyset Deriver B public key',
  );
  assertEqual(
    keyset.signing_worker_server_output_hpke.public_key,
    router.variables.ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
    'Gateway keyset SigningWorker public key',
  );
  assertEqual(
    topology.deriverRecipientKeys.deriver_a.public_key,
    keyset.signer_envelope_hpke.current.deriver_a.public_key,
    'registration topology Deriver A public key',
  );
  assertEqual(
    topology.deriverRecipientKeys.deriver_b.public_key,
    keyset.signer_envelope_hpke.current.deriver_b.public_key,
    'registration topology Deriver B public key',
  );
  assertEqual(policy.environment, outputDocument.target, 'MPCRouter project policy environment');
  const ceremonyJwk = JSON.parse(gateway.secrets.ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK);
  assertEqual(ceremonyJwk.kty, 'OKP', 'ceremony JWT JWK kty');
  assertEqual(ceremonyJwk.crv, 'Ed25519', 'ceremony JWT JWK curve');
  assertExactKeys(ceremonyJwk, ['kty', 'crv', 'x', 'd'], 'ceremony JWT private JWK');
}

function parseGatewayDeploymentConfig(gatewayEnvironment) {
  const raw = gatewayEnvironment.variables.GATEWAY_DEPLOYMENT_CONFIG_JSON;
  const config = parseSuppliedJsonObject('GATEWAY_DEPLOYMENT_CONFIG_JSON', raw);
  assertEqual(
    config.schemaVersion,
    GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
    'Gateway deployment config schema version',
  );
  if (!config.routerAb || typeof config.routerAb !== 'object') {
    throw new Error('Gateway deployment config routerAb object is missing');
  }
  return config;
}

function validateSigningSessionConsistency(outputDocument) {
  const general = outputDocument.environments[outputDocument.target];
  const gateway = outputDocument.environments[`${outputDocument.target}-gateway`];
  assertEqual(
    general.variables.VITE_SIGNING_SESSION_SEAL_KEY_VERSION,
    gateway.secrets.SIGNING_SESSION_SEAL_KEY_VERSION,
    'signing-session seal key version',
  );
  assertEqual(
    general.variables.VITE_SIGNING_SESSION_SHAMIR_P_B64U,
    gateway.secrets.SIGNING_SESSION_SHAMIR_P_B64U,
    'signing-session Shamir prime',
  );
  for (const name of [
    'SIGNING_SESSION_SEAL_KEY_VERSION',
    'SIGNING_SESSION_SHAMIR_P_B64U',
    'SIGNING_SESSION_SEAL_E_S_B64U',
    'SIGNING_SESSION_SEAL_D_S_B64U',
  ]) {
    if (!gateway.secrets[name]) {
      throw new Error(`Gateway signing-session seal secret ${name} is missing`);
    }
  }
}

function assertAbsent(values, names) {
  for (const name of names) {
    if (Object.hasOwn(values, name)) {
      throw new Error(`${name} is present in the wrong GitHub Environment`);
    }
  }
}

function assertExactKeys(value, expectedKeys, label) {
  assertEqual(Object.keys(value), expectedKeys, `${label} fields`);
}

function assertEqual(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} mismatch: ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`);
  }
}

function runJsonScript(scriptPath, args) {
  const child = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: repoRoot,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (child.status !== 0) {
    process.stderr.write(child.stderr || child.stdout || `${scriptPath} failed\n`);
    process.exit(child.status ?? 1);
  }
  try {
    return JSON.parse(child.stdout);
  } catch {
    throw new Error(`${scriptPath} did not return valid JSON`);
  }
}

function writePreparedComponentManifests(output) {
  const backupDirectory = join(homedir(), '.seams', 'backups');
  mkdirSync(backupDirectory, { recursive: true, mode: 0o700 });
  chmodSync(backupDirectory, 0o700);
  const walletCoreManifest = buildPreparedComponentManifest(output, 'wallet-core');
  const productManifest = buildPreparedComponentManifest(output, 'product');
  const walletCoreManifestPath = writePreparedComponentManifest(
    backupDirectory,
    walletCoreManifest,
  );
  const productManifestPath = writePreparedComponentManifest(backupDirectory, productManifest);
  return {
    generationId: output.generationId,
    manifestSha256: output.manifestSha256,
    walletCoreManifestPath,
    productManifestPath,
  };
}

function writePreparedComponentManifest(backupDirectory, manifest) {
  const manifestPath = join(
    backupDirectory,
    `${manifest.target}-${manifest.generationId}-${manifest.deploymentComponent}-github-environments.json`,
  );
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  return manifestPath;
}

function loadPreparedComponentManifest(manifestFilePath, targetName, component) {
  const absolutePath = resolve(repoRoot, manifestFilePath);
  if (!existsSync(absolutePath)) {
    throw new Error(`prepared deployment manifest does not exist: ${absolutePath}`);
  }
  const mode = statSync(absolutePath).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(`prepared deployment manifest must be owner-only (chmod 600): ${absolutePath}`);
  }
  let manifest;
  try {
    manifest = JSON.parse(readFileSync(absolutePath, 'utf8'));
  } catch (error) {
    throw new Error(
      `failed to load prepared deployment manifest ${absolutePath}: ${error.message}`,
    );
  }
  validatePreparedComponentManifest(manifest, targetName, component);
  return manifest;
}

function validatePreparedComponentManifest(manifest, targetName, component) {
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('prepared deployment manifest must be a JSON object');
  }
  assertEqual(manifest.schemaVersion, 1, 'prepared deployment manifest schema version');
  assertEqual(manifest.target, targetName, 'prepared deployment target');
  assertEqual(manifest.deploymentComponent, component, 'prepared deployment component');
  const expectedEnvironmentNames = deploymentComponentEnvironmentNames(targetName, component);
  assertEqual(
    Object.keys(manifest.environments || {}),
    expectedEnvironmentNames,
    'prepared deployment environment names',
  );
  if (!/^[a-f0-9]{64}$/.test(manifest.manifestSha256 || '')) {
    throw new Error('prepared deployment manifest SHA-256 is invalid');
  }
  if (!/^[a-f0-9]{64}$/.test(manifest.componentManifestSha256 || '')) {
    throw new Error('prepared component manifest SHA-256 is invalid');
  }
  assertEqual(
    computeComponentManifestSha256(manifest),
    manifest.componentManifestSha256,
    'prepared component manifest SHA-256',
  );
  for (const [environmentName, environment] of Object.entries(manifest.environments)) {
    if (!environment || typeof environment !== 'object' || Array.isArray(environment)) {
      throw new Error(`prepared environment ${environmentName} must be an object`);
    }
    assertEqual(
      environment.variables?.SEAMS_DEPLOYMENT_GENERATION_ID,
      manifest.generationId,
      `${environmentName} deployment generation id`,
    );
    assertEqual(
      environment.variables?.SEAMS_DEPLOYMENT_GENERATED_AT,
      manifest.generatedAt,
      `${environmentName} deployment generation timestamp`,
    );
    assertEqual(
      environment.variables?.SEAMS_DEPLOYMENT_MANIFEST_SHA256,
      manifest.manifestSha256,
      `${environmentName} deployment manifest SHA-256`,
    );
  }
  manifest.manualInputs = collectManualInputs(manifest.environments);
  manifest.requiredManualInputs = collectRequiredManualInputs(manifest.environments);
}

function applyGeneratedValues(data, repositoryName, progressLogger, backupPath) {
  const createdEnvironments = [];
  const existingEnvironments = [];
  const appliedVariables = [];
  const appliedSecrets = [];
  const removedVariables = [];
  const removedSecrets = [];

  progressLogger.step('Create or verify GitHub Environments');
  let environmentIndex = 0;
  for (const environmentName of Object.keys(data.environments)) {
    environmentIndex += 1;
    if (ensureGitHubEnvironment(environmentName, repositoryName)) {
      createdEnvironments.push(environmentName);
      progressLogger.detail(
        `Environment ${environmentIndex}/${Object.keys(data.environments).length}: created ${environmentName}`,
      );
    } else {
      existingEnvironments.push(environmentName);
      progressLogger.detail(
        `Environment ${environmentIndex}/${Object.keys(data.environments).length}: preserved ${environmentName}`,
      );
    }
  }

  for (const [environmentName, environment] of Object.entries(data.environments)) {
    const appliedVariableCountBefore = appliedVariables.length;
    const appliedSecretCountBefore = appliedSecrets.length;
    progressLogger.step(`Upload generated values to ${environmentName}`);
    const variables = {
      ...environment.variables,
      ...environment.optionalVariables,
    };
    for (const [name, value] of Object.entries(variables)) {
      if (isManualValue(value) || DEPLOYMENT_AUDIT_VARIABLE_NAMES.has(name)) {
        continue;
      }
      runGh(
        ['variable', 'set', name, '--env', environmentName, ...githubRepoArgs(repositoryName)],
        value,
        repositoryName,
      );
      appliedVariables.push(`${environmentName}.variables.${name}`);
    }
    for (const [name, value] of Object.entries(environment.secrets)) {
      if (isManualValue(value)) {
        continue;
      }
      runGh(
        ['secret', 'set', name, '--env', environmentName, ...githubRepoArgs(repositoryName)],
        value,
        repositoryName,
      );
      appliedSecrets.push(`${environmentName}.secrets.${name}`);
    }
    if (environmentName === `${data.target}-gateway`) {
      removedVariables.push(...removeObsoleteGatewayVariables(environmentName, repositoryName));
      removedSecrets.push(
        ...removeDisabledGatewaySecrets(environmentName, environment, repositoryName),
      );
    }
    progressLogger.detail(
      `Uploaded ${appliedVariables.length - appliedVariableCountBefore} variables and ` +
        `${appliedSecrets.length - appliedSecretCountBefore} secrets`,
    );
  }

  progressLogger.step('Commit deployment generation metadata');
  for (const [environmentName, environment] of Object.entries(data.environments)) {
    for (const name of DEPLOYMENT_AUDIT_VARIABLE_UPLOAD_ORDER) {
      const value = environment.variables[name];
      runGh(
        ['variable', 'set', name, '--env', environmentName, ...githubRepoArgs(repositoryName)],
        value,
        repositoryName,
      );
      appliedVariables.push(`${environmentName}.variables.${name}`);
    }
    progressLogger.detail(`Committed generation ${data.generationId} to ${environmentName}`);
  }

  return {
    repository: repositoryName || 'current repository',
    createdEnvironments,
    existingEnvironments,
    appliedVariableCount: appliedVariables.length,
    appliedSecretCount: appliedSecrets.length,
    appliedVariables,
    appliedSecrets,
    removedVariables,
    removedSecrets,
    backupPath,
    skippedManualInputs: data.manualInputs,
  };
}

function removeDisabledGatewaySecrets(environmentName, environment, repositoryName) {
  const config = parseSuppliedJsonObject(
    'GATEWAY_DEPLOYMENT_CONFIG_JSON',
    environment.variables.GATEWAY_DEPLOYMENT_CONFIG_JSON,
  );
  const disabledNames = new Set();
  if (config.optional.nearRelayer === null) {
    disabledNames.add('RELAYER_PRIVATE_KEY');
  }
  if (isManualValue(environment.secrets.SPONSORED_EVM_EXECUTORS_JSON)) {
    disabledNames.add('SPONSORED_EVM_EXECUTORS_JSON');
  }
  const listed = runGhResult(
    [
      'secret',
      'list',
      '--env',
      environmentName,
      '--json',
      'name',
      '--jq',
      '.[].name',
      ...githubRepoArgs(repositoryName),
    ],
    undefined,
    repositoryName,
  );
  if (listed.status !== 0) {
    throw new Error(formatGhFailure(`list secrets for ${environmentName}`, listed));
  }
  const removed = [];
  for (const name of String(listed.stdout).split(/\r?\n/)) {
    if (!disabledNames.has(name)) {
      continue;
    }
    runGh(
      ['secret', 'delete', name, '--env', environmentName, ...githubRepoArgs(repositoryName)],
      undefined,
      repositoryName,
    );
    removed.push(`${environmentName}.secrets.${name}`);
  }
  return removed;
}

function removeObsoleteGatewayVariables(environmentName, repositoryName) {
  const listed = runGhResult(
    [
      'variable',
      'list',
      '--env',
      environmentName,
      '--json',
      'name',
      '--jq',
      '.[].name',
      ...githubRepoArgs(repositoryName),
    ],
    undefined,
    repositoryName,
  );
  if (listed.status !== 0) {
    throw new Error(formatGhFailure(`list variables for ${environmentName}`, listed));
  }
  const removed = [];
  for (const name of String(listed.stdout).split(/\r?\n/)) {
    if (!OBSOLETE_GATEWAY_VARIABLE_NAMES.has(name)) {
      continue;
    }
    runGh(
      ['variable', 'delete', name, '--env', environmentName, ...githubRepoArgs(repositoryName)],
      undefined,
      repositoryName,
    );
    removed.push(`${environmentName}.variables.${name}`);
  }
  return removed;
}

function migrateExistingGatewayVariables(targetName, repositoryName) {
  const gatewayEnvironmentName = `${targetName}-gateway`;
  const gatewayVariables = readGitHubEnvironmentVariables(gatewayEnvironmentName, repositoryName);
  const generalVariables = readGitHubEnvironmentVariables(targetName, repositoryName);
  const existingConfig = gatewayVariables.get('GATEWAY_DEPLOYMENT_CONFIG_JSON');
  const config = existingConfig
    ? parseStrictGatewayDeploymentConfig(existingConfig, targetName)
    : parseStrictGatewayDeploymentConfig(
        JSON.stringify(
          buildGatewayConfigFromScalarVariables(targetName, gatewayVariables, generalVariables),
        ),
        targetName,
      );
  const serialized = JSON.stringify(stripDerivedGatewayConfigFields(config));
  runGh(
    [
      'variable',
      'set',
      'GATEWAY_DEPLOYMENT_CONFIG_JSON',
      '--env',
      gatewayEnvironmentName,
      ...githubRepoArgs(repositoryName),
    ],
    serialized,
    repositoryName,
  );
  const removedVariables = removeObsoleteGatewayVariables(gatewayEnvironmentName, repositoryName);
  return {
    environment: gatewayEnvironmentName,
    variable: 'GATEWAY_DEPLOYMENT_CONFIG_JSON',
    removedVariables,
    rotatedSecrets: false,
  };
}

function verifyAppliedGenerationMetadata(targetName, repositoryName) {
  const environments = deploymentEnvironmentNames(targetName).map((environmentName) => {
    const variables = readGitHubEnvironmentVariables(environmentName, repositoryName);
    return {
      environment: environmentName,
      generationId: requireAuditVariable(
        variables,
        environmentName,
        'SEAMS_DEPLOYMENT_GENERATION_ID',
      ),
      generatedAt: requireAuditVariable(
        variables,
        environmentName,
        'SEAMS_DEPLOYMENT_GENERATED_AT',
      ),
      manifestSha256: requireAuditVariable(
        variables,
        environmentName,
        'SEAMS_DEPLOYMENT_MANIFEST_SHA256',
      ),
    };
  });
  const expected = environments[0];
  for (const environment of environments.slice(1)) {
    assertEqual(environment.generationId, expected.generationId, 'deployment generation id');
    assertEqual(environment.generatedAt, expected.generatedAt, 'deployment generation timestamp');
    assertEqual(environment.manifestSha256, expected.manifestSha256, 'deployment manifest SHA-256');
  }
  return {
    target: targetName,
    repository: repositoryName,
    generationId: expected.generationId,
    generatedAt: expected.generatedAt,
    manifestSha256: expected.manifestSha256,
    environments: environments.map((environment) => environment.environment),
  };
}

function assertWalletCoreGenerationMatches(productManifest, repositoryName) {
  for (const environmentName of deploymentComponentEnvironmentNames(
    productManifest.target,
    'wallet-core',
  )) {
    const variables = readGitHubEnvironmentVariables(environmentName, repositoryName);
    assertEqual(
      requireAuditVariable(variables, environmentName, 'SEAMS_DEPLOYMENT_GENERATION_ID'),
      productManifest.generationId,
      `${environmentName} wallet-core generation id`,
    );
    assertEqual(
      requireAuditVariable(variables, environmentName, 'SEAMS_DEPLOYMENT_GENERATED_AT'),
      productManifest.generatedAt,
      `${environmentName} wallet-core generation timestamp`,
    );
    assertEqual(
      requireAuditVariable(variables, environmentName, 'SEAMS_DEPLOYMENT_MANIFEST_SHA256'),
      productManifest.manifestSha256,
      `${environmentName} wallet-core manifest SHA-256`,
    );
  }
}

function deploymentEnvironmentNames(targetName) {
  return [
    targetName,
    `${targetName}-gateway`,
    `${targetName}-mpc-router`,
    `${targetName}-deriver-a`,
    `${targetName}-deriver-b`,
    `${targetName}-signing-worker`,
  ];
}

function requireAuditVariable(variables, environmentName, variableName) {
  const value = variables.get(variableName);
  if (!value) {
    throw new Error(`${environmentName} is missing ${variableName}`);
  }
  return value;
}

function printGenerationVerification(verification) {
  console.log('GitHub deployment generation verified');
  console.log(`Target: ${verification.target}`);
  console.log(`Repository: ${verification.repository}`);
  console.log(`Generation id: ${verification.generationId}`);
  console.log(`Generated at: ${verification.generatedAt}`);
  console.log(`Manifest SHA-256: ${verification.manifestSha256}`);
  console.log(`Matching environments: ${verification.environments.join(', ')}`);
}

function readGitHubEnvironmentVariables(environmentName, repositoryName) {
  const listed = runGhResult(
    [
      'variable',
      'list',
      '--env',
      environmentName,
      '--json',
      'name,value',
      ...githubRepoArgs(repositoryName),
    ],
    undefined,
    repositoryName,
  );
  if (listed.status !== 0) {
    throw new Error(formatGhFailure(`list variables for ${environmentName}`, listed));
  }
  let variables;
  try {
    variables = JSON.parse(listed.stdout);
  } catch {
    throw new Error(`GitHub returned invalid variable JSON for ${environmentName}`);
  }
  if (!Array.isArray(variables)) {
    throw new Error(`GitHub variable response for ${environmentName} must be an array`);
  }
  return new Map(
    variables.map((variable) => [
      requireGitHubVariableField(variable, 'name', environmentName),
      requireGitHubVariableField(variable, 'value', environmentName),
    ]),
  );
}

function requireGitHubVariableField(variable, field, environmentName) {
  const value = typeof variable?.[field] === 'string' ? variable[field].trim() : '';
  if (!value) {
    throw new Error(`GitHub variable ${field} is missing in ${environmentName}`);
  }
  return value;
}

function buildGatewayConfigFromScalarVariables(targetName, gateway, general) {
  const allowedCors = requireScalarVariable(gateway, 'RELAY_CORS_ORIGINS')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const bootstrapOrigins = readJsonArrayVariable(
    gateway,
    'SEAMS_BOOTSTRAP_ALLOWED_ORIGINS_JSON',
    allowedCors,
  );
  const relayerAccountId = gateway.get('RELAYER_ACCOUNT_ID') || null;
  const relayerPublicKey = gateway.get('RELAYER_PUBLIC_KEY') || null;
  const oidcExchange = readNullableJsonObjectVariable(gateway, 'SEAMS_OIDC_EXCHANGE_JSON');
  return {
    schemaVersion: GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
    target: targetName,
    runtimeProfile: buildGatewayRuntimeProfile(
      gateway.get('GATEWAY_RUNTIME_PROFILE') ||
        GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo,
      gateway.get('EMAIL_OTP_DELIVERY_MODE') || undefined,
    ),
    resources: {
      workerName: requireScalarVariable(gateway, 'GATEWAY_WORKER_NAME'),
      consoleD1: {
        name: requireScalarVariable(gateway, 'GATEWAY_CONSOLE_D1_DATABASE_NAME'),
        id: requireScalarVariable(gateway, 'GATEWAY_CONSOLE_D1_DATABASE_ID'),
      },
      signerD1: {
        name: requireScalarVariable(gateway, 'GATEWAY_SIGNER_D1_DATABASE_NAME'),
        id: requireScalarVariable(gateway, 'GATEWAY_SIGNER_D1_DATABASE_ID'),
      },
      secretsStoreId: requireScalarVariable(gateway, 'GATEWAY_SECRETS_STORE_ID'),
    },
    tenant: {
      namespace: requireScalarVariable(gateway, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
      orgId: requireScalarVariable(gateway, 'SEAMS_ORG_ID'),
      projectId: requireScalarVariable(gateway, 'SEAMS_PROJECT_ID'),
      environmentId: requireScalarVariable(gateway, 'SEAMS_ENV_ID'),
    },
    origins: {
      gateway: requireScalarVariable(gateway, 'GATEWAY_ORIGIN'),
      allowedCors,
    },
    signingRoot: {
      id: requireScalarVariable(gateway, 'SIGNING_ROOT_KEK_ID'),
      secretName: requireScalarVariable(gateway, 'SIGNING_ROOT_KEK_SECRET_NAME'),
      encoding: requireScalarVariable(gateway, 'SIGNING_ROOT_KEK_ENCODING'),
    },
    session: {
      issuer: requireScalarVariable(gateway, 'RELAY_SESSION_ISSUER'),
    },
    routerAb: {
      ceremonyJwtAudience: requireScalarVariable(gateway, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
      ceremonyJwtKeyId: requireScalarVariable(gateway, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
      publicKeyset: readJsonObjectVariable(gateway, 'ROUTER_AB_PUBLIC_KEYSET_JSON'),
      registrationTopology: readJsonObjectVariable(
        gateway,
        'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON',
      ),
      deriverAYaoInputPublicKey: requireScalarVariable(
        gateway,
        'ROUTER_AB_DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
      ),
      deriverBYaoInputPublicKey: requireScalarVariable(
        gateway,
        'ROUTER_AB_DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
      ),
      signingWorkerOutputPublicKey: requireScalarVariable(
        gateway,
        'ROUTER_AB_SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      ),
    },
    bootstrap: {
      publishableKey:
        gateway.get('SEAMS_BOOTSTRAP_PUBLISHABLE_KEY') ||
        requireScalarVariable(general, 'VITE_SEAMS_PUBLISHABLE_KEY'),
      allowedOrigins: bootstrapOrigins,
    },
    optional: {
      nearRelayer: relayerAccountId
        ? {
            accountId: relayerAccountId,
            publicKey: relayerPublicKey,
            rpcUrl: requireScalarVariable(gateway, 'NEAR_RPC_URL'),
            initialBalanceYocto:
              gateway.get('ACCOUNT_INITIAL_BALANCE') || '30000000000000000000000',
          }
        : null,
      googleOidcClientId: gateway.get('GOOGLE_OIDC_CLIENT_ID') || null,
      oidcExchange,
    },
  };
}

function stripDerivedGatewayConfigFields(config) {
  return {
    schemaVersion: config.schemaVersion,
    target: config.target,
    runtimeProfile: config.runtimeProfile,
    resources: config.resources,
    tenant: config.tenant,
    origins: config.origins,
    signingRoot: config.signingRoot,
    session: config.session,
    routerAb: {
      ceremonyJwtAudience: config.routerAb.ceremonyJwtAudience,
      ceremonyJwtKeyId: config.routerAb.ceremonyJwtKeyId,
      publicKeyset: config.routerAb.publicKeyset,
      registrationTopology: config.routerAb.registrationTopology,
      deriverAYaoInputPublicKey: config.routerAb.deriverAInputPublicKey,
      deriverBYaoInputPublicKey: config.routerAb.deriverBInputPublicKey,
      signingWorkerOutputPublicKey: config.routerAb.signingWorkerOutputPublicKey,
    },
    bootstrap: config.bootstrap,
    optional: config.optional,
  };
}

function requireScalarVariable(variables, name) {
  const value = variables.get(name);
  if (!value) {
    throw new Error(`GitHub Environment variable ${name} is required for migration`);
  }
  return value;
}

function readJsonObjectVariable(variables, name) {
  return parseSuppliedJsonObject(name, requireScalarVariable(variables, name));
}

function readNullableJsonObjectVariable(variables, name) {
  const value = variables.get(name);
  return value ? parseSuppliedJsonObject(name, value) : null;
}

function readJsonArrayVariable(variables, name, fallback) {
  const value = variables.get(name);
  if (!value) {
    return fallback;
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
  if (!Array.isArray(parsed)) {
    throw new Error(`${name} must contain a JSON array`);
  }
  return parsed;
}

function resolveGitHubRepository(repositoryName) {
  validateGitHubRepositoryName(repositoryName);
  assertGhAvailable(repositoryName);
  const args = ['repo', 'view'];
  if (repositoryName) {
    args.push(repositoryName);
  }
  args.push('--json', 'nameWithOwner', '--jq', '.nameWithOwner');
  const child = runGhResult(args, undefined, repositoryName);
  if (child.status !== 0) {
    const targetDescription = repositoryName || 'the repository for the current checkout';
    throw new Error(
      `${formatGhFailure(`resolve GitHub repository ${targetDescription}`, child)}. ` +
        'Verify the repository name and your GitHub access before using --apply.',
    );
  }
  const resolved = String(child.stdout || '').trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(resolved)) {
    throw new Error(`gh repo view returned an invalid repository name: ${resolved || '<empty>'}`);
  }
  return resolved;
}

function assertTargetCanInitialize(targetName, repositoryName, rotationAllowed) {
  if (rotationAllowed) {
    return;
  }
  const existingMarkers = [];
  for (const [role, marker] of GENERATED_IDENTITY_SECRET_MARKERS) {
    const environmentName = `${targetName}-${role}`;
    const listed = runGhResult(
      [
        'secret',
        'list',
        '--env',
        environmentName,
        '--json',
        'name',
        '--jq',
        '.[].name',
        ...githubRepoArgs(repositoryName),
      ],
      undefined,
      repositoryName,
    );
    if (listed.status !== 0) {
      if (isGithubNotFound(listed)) {
        continue;
      }
      throw new Error(formatGhFailure(`list secrets for ${environmentName}`, listed));
    }
    const names = new Set(String(listed.stdout).split(/\r?\n/));
    if (names.has(marker)) {
      existingMarkers.push(`${environmentName}.${marker}`);
    }
  }
  if (existingMarkers.length === 0) {
    return;
  }
  throw new Error(
    `Deployment target ${targetName} already contains generated wallet identities:\n- ` +
      `${existingMarkers.join('\n- ')}\n\n` +
      'Re-running apply would replace active cryptographic material. Use --rotate only for an ' +
      'intentional coordinated identity rotation.',
  );
}

function validateGitHubRepositoryName(repositoryName) {
  if (!repositoryName) {
    return;
  }
  const normalized = repositoryName.trim().toLowerCase();
  const parts = normalized.split('/');
  if (
    normalized.includes('<') ||
    normalized.includes('>') ||
    normalized === 'owner/repo' ||
    parts.includes('your-org') ||
    parts.includes('your-owner')
  ) {
    throw new Error(
      `--repo ${repositoryName} is documentation placeholder text. ` +
        'Use the actual owner/repository name or omit --repo when running from the repository checkout.',
    );
  }
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repositoryName)) {
    throw new Error('--repo must use owner/repository format');
  }
}

function assertGhAvailable(repositoryName) {
  const child = runGhResult(['auth', 'status'], undefined, repositoryName);
  if (child.status !== 0) {
    throw new Error(formatGhFailure('gh auth status', child));
  }
}

function ensureGitHubEnvironment(environmentName, repositoryName) {
  const endpoint = `repos/{owner}/{repo}/environments/${encodeURIComponent(environmentName)}`;
  const existing = runGhResult(['api', endpoint, '--silent'], undefined, repositoryName);
  if (existing.status === 0) {
    return false;
  }
  if (!isGithubNotFound(existing)) {
    throw new Error(formatGhFailure(`check GitHub Environment ${environmentName}`, existing));
  }
  const created = runGhResult(
    ['api', '--method', 'PUT', endpoint, '--input', '-', '--silent'],
    '{}',
    repositoryName,
  );
  if (created.status !== 0) {
    throw new Error(
      `${formatGhFailure(`create GitHub Environment ${environmentName}`, created)}. ` +
        `Verify that your token can administer Actions environments in ${repositoryName}.`,
    );
  }
  return true;
}

function runGh(args, input, repositoryName) {
  const child = runGhResult(args, input, repositoryName);
  if (child.status !== 0) {
    throw new Error(formatGhFailure(`gh ${args.join(' ')}`, child));
  }
}

function runGhResult(args, input, repositoryName) {
  return spawnSync(githubCli, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    input,
    env: {
      ...process.env,
      ...(repositoryName ? { GH_REPO: repositoryName } : {}),
    },
  });
}

function githubRepoArgs(repositoryName) {
  return repositoryName ? ['--repo', repositoryName] : [];
}

function isGithubNotFound(child) {
  return /(?:HTTP\s+404|\bNot Found\b)/i.test(`${child.stderr || ''}\n${child.stdout || ''}`);
}

function formatGhFailure(operation, child) {
  const detail = String(child.stderr || child.stdout || `exit status ${child.status}`).trim();
  return `${operation} failed: ${detail}`;
}

function isManualValue(value) {
  return String(value).includes('<manual:');
}

function createProgressLogger(totalSteps) {
  return new TerminalProgressLogger(totalSteps, shouldUseTerminalColor());
}

function resolveProgressStepCount() {
  if (migrateGatewayConfig || verifyGeneration) return 2;
  if (manifestFile) {
    const environmentCount = deploymentComponent
      ? deploymentComponentEnvironmentNames(target, deploymentComponent).length
      : 0;
    return environmentCount + 4;
  }
  if (apply) return 14;
  if (prepare) return 6;
  return 5;
}

function shouldUseTerminalColor() {
  if (process.env.NO_COLOR !== undefined || process.env.FORCE_COLOR === '0') {
    return false;
  }
  if (process.env.FORCE_COLOR && process.env.FORCE_COLOR !== '0') {
    return true;
  }
  return Boolean(process.stderr.isTTY) && process.env.TERM !== 'dumb';
}

function handleFatalError(error) {
  const colorEnabled = shouldUseTerminalColor();
  const label = paint(ANSI.bold + ANSI.red, 'ENV KEYGEN', colorEnabled);
  const marker = paint(ANSI.bold + ANSI.red, 'FAILED', colorEnabled);
  let detail = String(error);
  if (error instanceof Error) {
    detail = process.env.DEBUG ? error.stack : error.message;
  }
  process.stderr.write(`\n  ${label}  ${marker}\n\n${detail}\n`);
  process.exitCode = 1;
}

function paint(style, text, enabled) {
  return enabled ? `${style}${text}${ANSI.reset}` : text;
}

function printHumanOutput(data, application) {
  console.log('GitHub deployment Environment manifest');
  console.log(`Target: ${data.target}`);
  console.log(`Generation id: ${data.generationId}`);
  console.log(`Generated at: ${data.generatedAt}`);
  console.log(`Manifest SHA-256: ${data.manifestSha256}`);
  console.log(`WARNING: ${data.warning}`);

  if (application) {
    printApplicationOutput(application);
    printAppliedValueBackup(data);
    printManualInputs(data);
    return;
  }

  for (const [environmentName, environment] of Object.entries(data.environments)) {
    console.log(`\n[${environmentName}] ${environment.purpose}`);
    printSection(environmentName, 'variables', environment.variables);
    printSection(environmentName, 'optional variables', environment.optionalVariables);
    printSection(environmentName, 'secrets', environment.secrets);
  }

  printManualInputs(data);
}

function printApplicationOutput(application) {
  console.log(`\nApplied generated values to ${application.repository}.`);
  console.log(`Created environments: ${formatList(application.createdEnvironments)}`);
  console.log(`Existing environments preserved: ${formatList(application.existingEnvironments)}`);
  console.log(`Variables uploaded: ${application.appliedVariableCount}`);
  console.log(`Secrets uploaded: ${application.appliedSecretCount}`);
  console.log(`Obsolete Gateway variables removed: ${application.removedVariables.length}`);
  console.log(`Disabled optional Gateway secrets removed: ${application.removedSecrets.length}`);
  console.log(`Applied component manifest: ${application.backupPath}`);
}

function printPreparationOutput(preparation) {
  console.log('\nPrepared deployment component manifests');
  console.log(`Generation id: ${preparation.generationId}`);
  console.log(`Manifest SHA-256: ${preparation.manifestSha256}`);
  console.log(`Wallet core: ${preparation.walletCoreManifestPath}`);
  console.log(`Product: ${preparation.productManifestPath}`);
  console.log('Apply wallet-core first, then apply product from these exact files.');
}

function printAppliedValueBackup(data) {
  console.log('\nApplied value backup');
  console.log('WARNING: The following output contains private keys and secrets.');
  for (const [environmentName, environment] of Object.entries(data.environments)) {
    const appliedVariables = filterAppliedValues({
      ...environment.variables,
      ...environment.optionalVariables,
    });
    const appliedSecrets = filterAppliedValues(environment.secrets);
    printSection(environmentName, 'applied variables', appliedVariables);
    printSection(environmentName, 'applied secrets', appliedSecrets);
  }
}

function filterAppliedValues(values) {
  return Object.fromEntries(Object.entries(values).filter(([, value]) => !isManualValue(value)));
}

function printManualInputs(data) {
  console.log('\nRequired external values still unresolved');
  printPathList(data.requiredManualInputs);
  console.log('\nOptional external values still unresolved');
  const optionalInputs = readOptionalManualInputs(data);
  printPathList(optionalInputs);
}

function readOptionalManualInputs(data) {
  const required = new Set(data.requiredManualInputs);
  const optional = [];
  for (const path of data.manualInputs) {
    if (!required.has(path)) {
      optional.push(path);
    }
  }
  return optional;
}

function printPathList(paths) {
  if (paths.length === 0) {
    console.log('- none');
    return;
  }
  for (const path of paths) {
    console.log(`- ${path}`);
  }
}

function formatList(values) {
  return values.length > 0 ? values.join(', ') : 'none';
}

function printSection(environmentName, sectionName, values) {
  if (Object.keys(values).length === 0) {
    return;
  }
  console.log(`\n[${environmentName}] ${sectionName}`);
  for (const [name, value] of Object.entries(values)) {
    console.log(`${name}=${value}`);
  }
}

function readOption(name) {
  const exactIndex = argv.indexOf(name);
  if (exactIndex !== -1) {
    const value = argv[exactIndex + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`${name} requires a value`);
    }
    return value;
  }
  const prefix = `${name}=`;
  const assignment = argv.find((argument) => argument.startsWith(prefix));
  if (!assignment) {
    return undefined;
  }
  const value = assignment.slice(prefix.length).trim();
  if (!value) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function readDeploymentComponent() {
  const component = readOption('--component');
  if (!component) return undefined;
  if (!VALID_DEPLOYMENT_COMPONENTS.has(component)) {
    throw new Error('--component must be wallet-core or product');
  }
  return component;
}
