import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { isDeepStrictEqual, parseEnv } from 'node:util';
import { gatewayRuntimeProfileNearNetwork } from '../../../packages/console-server-ts/scripts/gateway-deployment-config.mjs';
import { readBackendLane, readFrontendSite } from '../../../scripts/deployment-targets.mjs';

const COMPONENTS = new Set(['wallet-core', 'product']);
const githubCli = process.env.GITHUB_CLI_BIN || 'gh';
const GENERAL_VARIABLE_INPUTS = Object.freeze([
  ['VITE_WALLET_ORIGIN', 'VITE_WALLET_ORIGIN'],
  ['VITE_RP_ID_BASE', 'VITE_RP_ID_BASE'],
  ['VITE_TEMPO_RPC_URL', 'VITE_TEMPO_RPC_URL'],
  ['VITE_TEMPO_EXPLORER', 'VITE_TEMPO_EXPLORER'],
  ['VITE_TEMPO_FEE_TOKEN', 'VITE_TEMPO_FEE_TOKEN'],
  ['VITE_ARC_RPC_URL', 'VITE_ARC_RPC_URL'],
  ['VITE_ARC_EXPLORER', 'VITE_ARC_EXPLORER'],
]);
const CLOUDFLARE_SECRET_INPUTS = Object.freeze([
  ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_API_TOKEN'],
  ['CLOUDFLARE_ACCOUNT_ID', 'CLOUDFLARE_ACCOUNT_ID'],
]);
const WALLET_CORE_CLOUDFLARE_ENVIRONMENT_SUFFIXES = Object.freeze([
  '-gateway',
  '-mpc-router',
  '-deriver-a',
  '-deriver-b',
  '-signing-worker',
]);
const GATEWAY_SECRET_INPUTS = Object.freeze([
  ['SPONSORED_EVM_EXECUTORS_JSON', 'SPONSORED_EVM_EXECUTORS_JSON'],
  ['STRIPE_API_SK', 'STRIPE_API_SK'],
  ['STRIPE_WEBHOOK_SECRET', 'STRIPE_WEBHOOK_SECRET'],
  ['CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U', 'CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U'],
  ['CONSOLE_WEBHOOK_SECRET_KEY_B64U', 'CONSOLE_WEBHOOK_SECRET_KEY_B64U'],
]);
const GATEWAY_EMAIL_SECRET_INPUTS = Object.freeze([['RESEND_API_KEY', 'RESEND_API_KEY']]);
const GATEWAY_EMAIL_VARIABLE_INPUTS = Object.freeze([['CONSOLE_EMAIL_FROM', 'CONSOLE_EMAIL_FROM']]);
const PRODUCTION_LANE_VARIABLE_SUFFIXES = Object.freeze([
  'SEAMS_PROJECT_ENVIRONMENT_ID',
  'SEAMS_PUBLISHABLE_KEY',
  'NEAR_RPC_URL',
  'NEAR_EXPLORER',
  'TEMPO_RPC_URL',
  'TEMPO_EXPLORER',
  'TEMPO_FEE_TOKEN',
  'ARC_RPC_URL',
  'ARC_EXPLORER',
]);
const NEAR_PUBLIC_CONFIG_BY_NETWORK = Object.freeze({
  testnet: Object.freeze({
    rpcUrl: 'https://test.rpc.fastnear.com',
    explorerUrl: 'https://testnet.nearblocks.io',
  }),
  mainnet: Object.freeze({
    rpcUrl: 'https://rpc.mainnet.near.org',
    explorerUrl: 'https://nearblocks.io',
  }),
});

const argv = process.argv.slice(2).filter((argument) => argument !== '--');

assertNoLegacyIdentityFlags();

if (argv.includes('--help')) {
  printUsage();
  process.exit(0);
}

await main(parseOptions());

async function main(options) {
  const values = loadProtectedValues(options.valuesFile);
  validateExternalValues(values, options.component);
  const repository = resolveGitHubRepository(options.repository);
  const plan = buildBasePlan(options, repository, values);
  validateCheckedInGatewayConfiguration(plan.gatewayDeploymentConfig, values);
  if (options.component === 'product') {
    if (options.site.id === 'staging') {
      addProductNearRelayerUpdate(plan, values);
      addProductNearNetworkUpdates(plan);
    }
  } else {
    addWalletCoreNearRelayerSecretUpdate(plan, values);
  }
  validatePlan(plan);
  const selectedPlan = selectPlan(plan, options.selection);
  printPlan(selectedPlan, options.apply);
  if (options.apply) {
    applyPlan(selectedPlan);
  }
}

function parseOptions() {
  const component = requireOption('--component');
  if (!COMPONENTS.has(component)) {
    throw new Error('--component must be wallet-core or product');
  }
  const laneId = readOption('--lane');
  const siteId = readOption('--site');
  if (laneId && siteId) {
    throw new Error('--lane and --site are mutually exclusive');
  }
  if (component === 'wallet-core' && !laneId) {
    throw new Error('--lane is required for wallet-core operations');
  }
  if (component === 'product' && !siteId) {
    throw new Error('--site is required for product operations');
  }
  if (component === 'wallet-core' && siteId) {
    throw new Error('--site cannot be used for wallet-core operations');
  }
  if (component === 'product' && laneId) {
    throw new Error('--lane cannot be used for product operations');
  }
  const identity = resolveDeploymentIdentity(component, laneId, siteId);
  const valuesFile = readOption('--values-file') || defaultValuesFile(identity);
  const selection = parseUpdateSelection();
  return {
    release: identity.release,
    identityId: identity.id,
    environmentPrefix: deploymentEnvironmentPrefix(identity),
    lane: identity.lane,
    site: identity.site,
    component,
    valuesFile,
    repository: readOption('--repo'),
    apply: argv.includes('--apply'),
    selection,
  };
}

function deploymentEnvironmentPrefix(identity) {
  if (!identity.lane) return identity.site.id;
  const deploymentEnvironment = identity.lane.resources.router.deploymentEnvironment;
  return deploymentEnvironment.kind === 'named'
    ? deploymentEnvironment.name
    : identity.lane.release;
}

function resolveDeploymentIdentity(component, laneId, siteId) {
  if (component === 'wallet-core') {
    const lane = readBackendLane(laneId);
    assertProvisionedIdentity(lane.id, lane.provisioning.kind);
    return { id: lane.id, release: lane.release, lane, site: lane.site };
  }
  const site = readFrontendSite(siteId);
  const lane = site.lanes.find((candidate) => candidate.network === site.defaultNetwork);
  if (!lane) {
    throw new Error(`site ${site.id} has no lane for default network ${site.defaultNetwork}`);
  }
  const pendingLane = site.lanes.find((candidate) => candidate.provisioning.kind === 'pending');
  if (pendingLane) {
    throw new Error(
      `${site.id} is pending provisioning for ${pendingLane.id}; deployment environment updates are blocked`,
    );
  }
  return { id: site.id, release: site.release, lane, site };
}

function assertProvisionedIdentity(identityId, provisioningKind) {
  if (provisioningKind === 'pending') {
    throw new Error(
      `${identityId} is pending provisioning; deployment environment updates are blocked`,
    );
  }
}

function defaultValuesFile(identity) {
  const fileName =
    identity.lane.id === 'production-testnet'
      ? 'production-testnet-deployment.env'
      : identity.release === 'production'
        ? 'production-deployment.env'
        : 'staging-deployment.env';
  return resolve(homedir(), '.seams', fileName);
}

function parseUpdateSelection() {
  const variablesOnly = argv.includes('--variables-only');
  const secretsOnly = argv.includes('--secrets-only');
  if (variablesOnly && secretsOnly) {
    throw new Error('--variables-only and --secrets-only are mutually exclusive');
  }
  const only = readOption('--only');
  const names = only ? new Set(only.split(',').map(normalizeSelectedName).filter(Boolean)) : null;
  if (only && names?.size === 0) {
    throw new Error('--only requires at least one variable or secret name');
  }
  return {
    kind: variablesOnly ? 'variables' : secretsOnly ? 'secrets' : 'all',
    names,
  };
}

function normalizeSelectedName(value) {
  return value.trim();
}

function loadProtectedValues(valuesFile) {
  if (!existsSync(valuesFile)) {
    throw new Error(`deployment values file does not exist: ${valuesFile}`);
  }
  const mode = statSync(valuesFile).mode & 0o777;
  if ((mode & 0o077) !== 0) {
    throw new Error(`deployment values file must be owner-only (chmod 600): ${valuesFile}`);
  }
  return parseEnv(readFileSync(valuesFile, 'utf8'));
}

function validateExternalValues(values, component) {
  validatePair(values, 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'Cloudflare deployment');
  if (component === 'product') {
    return;
  }
  validatePair(values, 'RELAYER_ACCOUNT_ID', 'RELAYER_PRIVATE_KEY', 'NEAR sponsorship');
  const relayerPublicKey = readValue(values, 'RELAYER_PUBLIC_KEY');
  const relayerAccountId = readValue(values, 'RELAYER_ACCOUNT_ID');
  if (relayerPublicKey && !relayerAccountId) {
    throw new Error('RELAYER_PUBLIC_KEY requires RELAYER_ACCOUNT_ID');
  }
  const initialBalanceYocto = readValue(values, 'RELAYER_INITIAL_BALANCE_YOCTO');
  if (initialBalanceYocto) {
    requirePositiveUnsignedInteger(initialBalanceYocto, 'RELAYER_INITIAL_BALANCE_YOCTO');
  }
  parseOptionalJsonObject(values, 'SPONSORED_EVM_EXECUTORS_JSON');
  const stripeSecretKey = readValue(values, 'STRIPE_API_SK');
  if (stripeSecretKey) {
    requireStripeSecretKey(stripeSecretKey);
  }
  const resendApiKey = readValue(values, 'RESEND_API_KEY');
  if (resendApiKey && !resendApiKey.startsWith('re_')) {
    throw new Error('RESEND_API_KEY must start with re_');
  }
  const invitationSecretKey = readValue(values, 'CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U');
  if (invitationSecretKey) {
    requireConsoleEmailInvitationSecretKey(invitationSecretKey);
  }
  const webhookSecretKey = readValue(values, 'CONSOLE_WEBHOOK_SECRET_KEY_B64U');
  if (webhookSecretKey) {
    requireConsoleWebhookSecretKey(webhookSecretKey);
  }
}

function validatePair(values, leftName, rightName, label) {
  const left = readValue(values, leftName);
  const right = readValue(values, rightName);
  if (Boolean(left) !== Boolean(right)) {
    throw new Error(`${label} requires both ${leftName} and ${rightName}`);
  }
}

function requireStripeSecretKey(value) {
  if (!/^(?:sk|rk)_/.test(value)) {
    throw new Error(
      'STRIPE_API_SK must be a Stripe secret key (sk_...) or restricted key (rk_...)',
    );
  }
  return value;
}

function requireConsoleEmailInvitationSecretKey(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || Buffer.from(value, 'base64url').byteLength !== 32) {
    throw new Error('CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U must encode exactly 32 bytes');
  }
  return value;
}

function requireConsoleWebhookSecretKey(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || Buffer.from(value, 'base64url').byteLength !== 32) {
    throw new Error('CONSOLE_WEBHOOK_SECRET_KEY_B64U must encode exactly 32 bytes');
  }
  return value;
}

function buildBasePlan(options, repository, values) {
  const plan = {
    release: options.release,
    identityId: options.identityId,
    lane: options.lane,
    site: options.site,
    component: options.component,
    repository,
    valuesFile: options.valuesFile,
    variables: [],
    secrets: [],
    gatewayDeploymentConfig: options.lane.provisioning.gatewayDeploymentConfig,
  };
  if (options.component === 'product') {
    if (options.site.id === 'production') {
      appendProductionProductUpdates(plan, values);
    } else {
      appendMappedUpdates(plan.variables, options.release, values, GENERAL_VARIABLE_INPUTS);
      appendMappedUpdates(plan.secrets, options.release, values, CLOUDFLARE_SECRET_INPUTS);
    }
  } else {
    appendWalletCoreCloudflareDeploymentUpdates(plan, options.environmentPrefix, values);
    appendMappedUpdates(
      plan.secrets,
      `${options.environmentPrefix}-gateway`,
      values,
      GATEWAY_SECRET_INPUTS,
    );
    if (options.lane.id !== 'production-mainnet') {
      appendMappedUpdates(
        plan.variables,
        `${options.environmentPrefix}-gateway`,
        values,
        GATEWAY_EMAIL_VARIABLE_INPUTS,
      );
      appendMappedUpdates(
        plan.secrets,
        `${options.environmentPrefix}-gateway`,
        values,
        GATEWAY_EMAIL_SECRET_INPUTS,
      );
    }
  }
  return plan;
}

function appendProductionProductUpdates(plan, values) {
  appendMappedUpdates(plan.secrets, plan.environmentPrefix, values, CLOUDFLARE_SECRET_INPUTS);
  appendMappedUpdates(plan.secrets, plan.environmentPrefix, values, [
    ['CF_PAGES_PROJECT_DOCS', 'CF_PAGES_PROJECT_DOCS'],
    ['CF_PAGES_PROJECT_WALLET_TESTNET', 'CF_PAGES_PROJECT_WALLET_TESTNET'],
    ['CF_PAGES_PROJECT_WALLET_MAINNET', 'CF_PAGES_PROJECT_WALLET_MAINNET'],
  ]);
  for (const lane of plan.site.lanes) {
    const prefix = `VITE_${lane.network.toUpperCase()}_`;
    plan.variables.push(
      {
        environment: plan.environmentPrefix,
        name: `${prefix}RELAYER_URL`,
        value: lane.gatewayOrigin,
      },
      {
        environment: plan.environmentPrefix,
        name: `${prefix}CONSOLE_BASE_URL`,
        value: lane.gatewayOrigin,
      },
      { environment: plan.environmentPrefix, name: `${prefix}NEAR_NETWORK`, value: lane.network },
      {
        environment: plan.environmentPrefix,
        name: `${prefix}WALLET_SERVICE_PATH`,
        value: '/wallet-service',
      },
      { environment: plan.environmentPrefix, name: `${prefix}SDK_BASE_PATH`, value: '/sdk' },
      {
        environment: plan.environmentPrefix,
        name: `${prefix}SIGNING_SESSION_PERSISTENCE_MODE`,
        value: 'sealed_refresh_v1',
      },
      {
        environment: plan.environmentPrefix,
        name: `${prefix}ROUTER_AB_NORMAL_SIGNING_WORKER_ID`,
        value: lane.resources.signingWorker.workerName,
      },
    );
    for (const suffix of PRODUCTION_LANE_VARIABLE_SUFFIXES) {
      const value = readValue(values, `${prefix}${suffix}`);
      if (value) {
        plan.variables.push({
          environment: plan.environmentPrefix,
          name: `${prefix}${suffix}`,
          value,
        });
      }
    }
  }
  appendMappedUpdates(plan.variables, plan.environmentPrefix, values, [
    ['VITE_DASHBOARD_WALLETS_ROUTES_ENABLED', 'VITE_DASHBOARD_WALLETS_ROUTES_ENABLED'],
  ]);
}

function appendWalletCoreCloudflareDeploymentUpdates(plan, target, values) {
  for (const suffix of WALLET_CORE_CLOUDFLARE_ENVIRONMENT_SUFFIXES) {
    appendMappedUpdates(plan.secrets, `${target}${suffix}`, values, CLOUDFLARE_SECRET_INPUTS);
  }
}

function appendMappedUpdates(updates, environment, values, mappings) {
  for (const [githubName, inputName] of mappings) {
    const value = readValue(values, inputName);
    if (value) {
      updates.push({ environment, name: githubName, value });
    }
  }
}

function addProductNearRelayerUpdate(plan, values) {
  const accountId = readValue(values, 'RELAYER_ACCOUNT_ID');
  if (!accountId) {
    return;
  }
  plan.variables.push({
    environment: plan.environmentPrefix,
    name: 'VITE_RELAYER_ACCOUNT_ID',
    value: accountId,
  });
}

function addProductNearNetworkUpdates(plan) {
  const config = plan.gatewayDeploymentConfig;
  const runtimeProfile = config.runtimeProfile;
  const network = gatewayRuntimeProfileNearNetwork(runtimeProfile);
  const publicConfig = NEAR_PUBLIC_CONFIG_BY_NETWORK[network];
  if (!publicConfig) {
    throw new Error(`Unsupported Gateway NEAR network: ${String(network)}`);
  }
  const nearRpcUrl = config.optional.nearRelayer?.rpcUrl || publicConfig.rpcUrl;
  plan.variables.push(
    {
      environment: plan.environmentPrefix,
      name: 'VITE_NEAR_NETWORK',
      value: network,
    },
    {
      environment: plan.environmentPrefix,
      name: 'VITE_NEAR_RPC_URL',
      value: nearRpcUrl,
    },
    {
      environment: plan.environmentPrefix,
      name: 'VITE_NEAR_EXPLORER',
      value: publicConfig.explorerUrl,
    },
  );
}

function addWalletCoreNearRelayerSecretUpdate(plan, values) {
  const privateKey = readValue(values, 'RELAYER_PRIVATE_KEY');
  if (!privateKey) {
    return;
  }
  if (!plan.gatewayDeploymentConfig.optional.nearRelayer) {
    throw new Error('RELAYER_PRIVATE_KEY requires nearRelayer in deployment/targets.json');
  }
  plan.secrets.push({
    environment: `${plan.environmentPrefix}-gateway`,
    name: 'RELAYER_PRIVATE_KEY',
    value: privateKey,
  });
}

function validateCheckedInGatewayConfiguration(config, values) {
  assertSuppliedValueMatches(values, 'GATEWAY_RUNTIME_PROFILE', config.runtimeProfile.kind);
  assertSuppliedValueMatches(
    values,
    'EMAIL_OTP_DELIVERY_MODE',
    config.runtimeProfile.emailOtpDelivery.kind,
  );
  assertSuppliedValueMatches(values, 'GOOGLE_OIDC_CLIENT_ID', config.optional.googleOidcClientId);
  const walletOrigin = readValue(values, 'VITE_WALLET_ORIGIN');
  if (walletOrigin && !config.origins.allowedCors.includes(walletOrigin)) {
    throw new Error('VITE_WALLET_ORIGIN must be updated in deployment/targets.json first');
  }
  const nearRelayer = config.optional.nearRelayer;
  assertSuppliedValueMatches(values, 'RELAYER_ACCOUNT_ID', nearRelayer?.accountId ?? null);
  assertSuppliedValueMatches(values, 'RELAYER_PUBLIC_KEY', nearRelayer?.publicKey ?? null);
  assertSuppliedValueMatches(values, 'NEAR_RPC_URL', nearRelayer?.rpcUrl ?? null);
  assertSuppliedValueMatches(
    values,
    'RELAYER_INITIAL_BALANCE_YOCTO',
    nearRelayer?.initialBalanceYocto ?? null,
  );
}

function assertSuppliedValueMatches(values, name, expected) {
  const supplied = readValue(values, name);
  if (supplied && supplied !== expected) {
    throw new Error(`${name} must be updated in deployment/targets.json first`);
  }
}

function assertSuppliedJsonMatches(values, name, expected) {
  const supplied = parseOptionalJsonObject(values, name);
  if (supplied && !isDeepStrictEqual(supplied, expected)) {
    throw new Error(`${name} must be updated in deployment/targets.json first`);
  }
}

function validatePlan(plan) {
  validateUniqueUpdates(plan.variables, 'variable');
  validateUniqueUpdates(plan.secrets, 'secret');
}

function requirePositiveUnsignedInteger(value, name) {
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive unsigned integer`);
  }
  return value;
}

function selectPlan(plan, selection) {
  const variables =
    selection.kind === 'secrets' ? [] : selectUpdatesByName(plan.variables, selection.names);
  const secrets =
    selection.kind === 'variables' ? [] : selectUpdatesByName(plan.secrets, selection.names);
  if (selection.names) {
    assertAllSelectedNamesResolved(selection.names, variables, secrets);
  }
  if (variables.length === 0 && secrets.length === 0) {
    throw new Error('the selected deployment update contains no values');
  }
  return {
    release: plan.release,
    identityId: plan.identityId,
    environmentPrefix: plan.environmentPrefix,
    lane: plan.lane.id,
    site: plan.site.id,
    component: plan.component,
    repository: plan.repository,
    valuesFile: plan.valuesFile,
    variables,
    secrets,
    gatewayDeploymentConfig: plan.gatewayDeploymentConfig,
  };
}

function selectUpdatesByName(updates, names) {
  if (!names) {
    return updates;
  }
  return updates.filter((update) => names.has(update.name));
}

function assertAllSelectedNamesResolved(names, variables, secrets) {
  const resolvedNames = new Set();
  for (const update of variables) {
    resolvedNames.add(update.name);
  }
  for (const update of secrets) {
    resolvedNames.add(update.name);
  }
  const unresolvedNames = [...names].filter((name) => !resolvedNames.has(name));
  if (unresolvedNames.length > 0) {
    throw new Error(`selected values are missing or unavailable: ${unresolvedNames.join(', ')}`);
  }
}

function validateUniqueUpdates(updates, kind) {
  const seen = new Set();
  for (const update of updates) {
    const key = `${update.environment}:${update.name}`;
    if (seen.has(key)) {
      throw new Error(`duplicate GitHub ${kind} update: ${key}`);
    }
    seen.add(key);
  }
}

function applyPlan(plan) {
  for (const secret of plan.secrets) {
    setGitHubValue('secret', secret, plan.repository);
  }
  for (const variable of plan.variables) {
    setGitHubValue('variable', variable, plan.repository);
  }
  process.stdout.write(
    `Applied ${plan.variables.length} variables and ${plan.secrets.length} secrets.\n`,
  );
}

function setGitHubValue(kind, update, repository) {
  runGh(
    [kind, 'set', update.name, '--env', update.environment, '--repo', repository],
    update.value,
  );
}

function printPlan(plan, applying) {
  process.stdout.write(
    `${applying ? 'Applying' : 'Dry run for'} external deployment values from ${plan.valuesFile}\n`,
  );
  process.stdout.write(`Repository: ${plan.repository}\n`);
  process.stdout.write(
    `${plan.component === 'wallet-core' ? 'Lane' : 'Site'}: ${plan.identityId} (release ${plan.release})\n\n`,
  );
  process.stdout.write(`Component: ${plan.component}\n\n`);
  printGatewayRuntimeProfile(plan);
  printUpdates('Variables', plan.variables, false);
  printUpdates('Secrets', plan.secrets, true);
  if (!applying) {
    process.stdout.write('\nNo GitHub values were changed. Add --apply to upload this plan.\n');
  }
}

function printGatewayRuntimeProfile(plan) {
  const parsed = plan.gatewayDeploymentConfig;
  process.stdout.write(`Gateway runtime profile: ${parsed.runtimeProfile.kind}\n`);
  process.stdout.write(
    `NEAR network: ${gatewayRuntimeProfileNearNetwork(parsed.runtimeProfile)}\n`,
  );
  process.stdout.write(
    `Implicit NEAR account funding: ` +
      `${parsed.runtimeProfile.nearFunding.kind === 'implicit_account_relayer' ? 'enabled' : 'disabled'}\n`,
  );
  process.stdout.write(`Email OTP delivery: ${parsed.runtimeProfile.emailOtpDelivery.kind}\n`);
  if (parsed.runtimeProfile.emailOtpDelivery.kind === 'demo_code_response') {
    process.stdout.write(`Email OTP demo origins: ${parsed.origins.allowedCors.join(', ')}\n`);
  }
  process.stdout.write('\n');
}

function printUpdates(label, updates, redactValues) {
  process.stdout.write(`${label}:\n`);
  if (updates.length === 0) {
    process.stdout.write('- none\n');
    return;
  }
  for (const update of updates) {
    const value = displayUpdateValue(update, redactValues);
    process.stdout.write(`- ${update.environment}.${update.name}=${value}\n`);
  }
}

function displayUpdateValue(update, redactValue) {
  if (redactValue) {
    return '<redacted>';
  }
  return update.value;
}

function resolveGitHubRepository(requestedRepository) {
  const args = ['repo', 'view'];
  if (requestedRepository) {
    args.push(requestedRepository);
  }
  args.push('--json', 'nameWithOwner', '--jq', '.nameWithOwner');
  const child = runGhResult(args);
  if (child.status !== 0) {
    throw new Error(formatGhFailure('resolve GitHub repository', child));
  }
  const repository = String(child.stdout).trim();
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error(`GitHub returned an invalid repository name: ${repository}`);
  }
  return repository;
}

function runGh(args, input) {
  const child = runGhResult(args, input);
  if (child.status !== 0) {
    throw new Error(formatGhFailure(`gh ${args.join(' ')}`, child));
  }
}

function runGhResult(args, input) {
  return spawnSync(githubCli, args, {
    encoding: 'utf8',
    input,
  });
}

function formatGhFailure(operation, child) {
  const detail = String(child.stderr || child.stdout || `exit status ${child.status}`).trim();
  return `${operation} failed: ${detail}`;
}

function parseOptionalJsonObject(values, name) {
  const value = readValue(values, name);
  if (!value) {
    return null;
  }
  return parseJsonObject(value, name);
}

function parseJsonObject(source, name) {
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw new Error(`${name} must contain valid JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`${name} must contain a JSON object`);
  }
  return parsed;
}

function readValue(values, name) {
  const value = values[name];
  if (typeof value !== 'string') {
    return '';
  }
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith('<')) {
    return '';
  }
  return trimmed;
}

function requireOption(name) {
  const value = readOption(name);
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function readOption(name) {
  const index = argv.indexOf(name);
  if (index !== -1) {
    const value = argv[index + 1];
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

function assertNoLegacyIdentityFlags() {
  const legacyFlag = argv.find(
    (argument) =>
      argument === '--env' ||
      argument.startsWith('--env=') ||
      argument === '--target' ||
      argument.startsWith('--target='),
  );
  if (legacyFlag) {
    throw new Error(`${legacyFlag} is retired; use --lane for wallet-core or --site for product`);
  }
}

function printUsage() {
  process.stdout
    .write(`Apply operator-owned deployment values without rotating generated identities.

Usage:
  pnpm wallet-core:deploy:env-update -- --lane staging-testnet --repo seams-tech/seams-sdk
  pnpm product:deploy:env-update -- --site staging --repo seams-tech/seams-sdk

Options:
  --lane <id>           Required for wallet-core: staging-testnet, production-testnet, or production-mainnet.
  --site <id>           Required for product: staging or production.
  --component <name>    Required. wallet-core or product.
  --values-file <path>  Defaults to the lane/site deployment values file under ~/.seams.
  --repo <owner/repo>   Defaults to the repository for the current checkout.
  --only <names>        Update only the comma-separated GitHub value names.
  --variables-only      Update variables and leave every secret unchanged.
  --secrets-only        Update secrets and leave every variable unchanged.
  --apply               Upload the planned variables and secrets.
  --help                Show this help.

Dry run is the default. The command only updates whitelisted external values.
It never generates or replaces Router A/B, Gateway, or signing-session identity
material.
`);
}
