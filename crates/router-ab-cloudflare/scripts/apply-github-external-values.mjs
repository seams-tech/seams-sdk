import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import {
  buildGatewayRuntimeProfile,
  DEFAULT_NEAR_INITIAL_BALANCE_YOCTO,
  GATEWAY_RUNTIME_PROFILE_KINDS,
  GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION,
  gatewayRuntimeProfileNearNetwork,
  parseGatewayDeploymentConfig,
} from '../../../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const TARGETS = new Set(['staging', 'production']);
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
const GENERAL_SECRET_INPUTS = Object.freeze([
  ['R2_ENDPOINT', 'R2_ENDPOINT'],
  ['R2_BUCKET', 'R2_BUCKET'],
  ['R2_ACCESS_KEY_ID', 'R2_ACCESS_KEY_ID'],
  ['R2_SECRET_ACCESS_KEY', 'R2_SECRET_ACCESS_KEY'],
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
  if (options.component === 'product') {
    addProductNearRelayerUpdate(plan, values);
    addProductNearNetworkUpdates(plan, values, repository);
  } else {
    addGatewayRuntimeProfileUpdate(plan, values, repository);
    addWalletCoreNearRelayerUpdates(plan, values, repository);
    addGatewayOptionalConfigUpdates(plan, values, repository);
  }
  validatePlan(plan);
  const selectedPlan = selectPlan(plan, options.selection);
  printPlan(selectedPlan, options.apply);
  if (options.apply) {
    applyPlan(selectedPlan);
  }
}

function parseOptions() {
  const target = requireOption('--env');
  if (!TARGETS.has(target)) {
    throw new Error('--env must be staging or production');
  }
  const valuesFile =
    readOption('--values-file') || resolve(homedir(), '.seams', `${target}-deployment.env`);
  const component = requireOption('--component');
  if (!COMPONENTS.has(component)) {
    throw new Error('--component must be wallet-core or product');
  }
  const selection = parseUpdateSelection();
  return {
    target,
    component,
    valuesFile,
    repository: readOption('--repo'),
    apply: argv.includes('--apply'),
    selection,
  };
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
    validatePair(values, 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2 publication');
    return;
  }
  validatePair(values, 'RELAYER_ACCOUNT_ID', 'RELAYER_PRIVATE_KEY', 'NEAR sponsorship');
  const relayerPublicKey = readValue(values, 'RELAYER_PUBLIC_KEY');
  const relayerAccountId = readValue(values, 'RELAYER_ACCOUNT_ID');
  if (relayerPublicKey && !relayerAccountId) {
    throw new Error('RELAYER_PUBLIC_KEY requires RELAYER_ACCOUNT_ID');
  }
  const runtimeProfileKind = readValue(values, 'GATEWAY_RUNTIME_PROFILE');
  const emailOtpDeliveryKind = readValue(values, 'EMAIL_OTP_DELIVERY_MODE');
  if (runtimeProfileKind || emailOtpDeliveryKind) {
    buildGatewayRuntimeProfile(
      runtimeProfileKind || GATEWAY_RUNTIME_PROFILE_KINDS.testnetLiveDemo,
      emailOtpDeliveryKind || undefined,
    );
  }
  const initialBalanceYocto = readValue(values, 'RELAYER_INITIAL_BALANCE_YOCTO');
  if (initialBalanceYocto) {
    requirePositiveUnsignedInteger(initialBalanceYocto, 'RELAYER_INITIAL_BALANCE_YOCTO');
  }
  parseOptionalJsonObject(values, 'SPONSORED_EVM_EXECUTORS_JSON');
  parseOptionalJsonObject(values, 'SEAMS_OIDC_EXCHANGE_JSON');
}

function validatePair(values, leftName, rightName, label) {
  const left = readValue(values, leftName);
  const right = readValue(values, rightName);
  if (Boolean(left) !== Boolean(right)) {
    throw new Error(`${label} requires both ${leftName} and ${rightName}`);
  }
}

function buildBasePlan(options, repository, values) {
  const plan = {
    target: options.target,
    component: options.component,
    repository,
    valuesFile: options.valuesFile,
    variables: [],
    secrets: [],
    gatewayConfig: null,
  };
  if (options.component === 'product') {
    appendMappedUpdates(plan.variables, options.target, values, GENERAL_VARIABLE_INPUTS);
    appendMappedUpdates(plan.secrets, options.target, values, GENERAL_SECRET_INPUTS);
    appendMappedUpdates(plan.secrets, options.target, values, CLOUDFLARE_SECRET_INPUTS);
  } else {
    appendWalletCoreCloudflareDeploymentUpdates(plan, options.target, values);
    addGatewayWalletOriginUpdate(plan, values, repository);
    appendMappedUpdates(plan.secrets, `${options.target}-gateway`, values, GATEWAY_SECRET_INPUTS);
  }
  return plan;
}

function addGatewayWalletOriginUpdate(plan, values, repository) {
  const walletOrigin = readValue(values, 'VITE_WALLET_ORIGIN');
  if (!walletOrigin) {
    return;
  }
  const previousWalletOrigin = readGitHubVariable(
    plan.target,
    'VITE_WALLET_ORIGIN',
    repository,
  );
  const config = requireGatewayConfig(plan, repository);
  config.origins.allowedCors = replaceExactOrigin(
    config.origins.allowedCors,
    previousWalletOrigin,
    walletOrigin,
    'Gateway CORS origins',
  );
  config.bootstrap.allowedOrigins = replaceExactOrigin(
    config.bootstrap.allowedOrigins,
    previousWalletOrigin,
    walletOrigin,
    'Gateway publishable-key origins',
  );
}

function replaceExactOrigin(origins, previousOrigin, nextOrigin, label) {
  const matchCount = origins.filter((origin) => origin === previousOrigin).length;
  if (matchCount !== 1) {
    throw new Error(`${label} must contain the current wallet origin exactly once`);
  }
  return origins.map((origin) => (origin === previousOrigin ? nextOrigin : origin));
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
    environment: plan.target,
    name: 'VITE_RELAYER_ACCOUNT_ID',
    value: accountId,
  });
}

function addProductNearNetworkUpdates(plan, values, repository) {
  const config = readCurrentGatewayConfig(plan.target, repository);
  const runtimeProfile = config.runtimeProfile;
  const network = gatewayRuntimeProfileNearNetwork(runtimeProfile);
  const publicConfig = NEAR_PUBLIC_CONFIG_BY_NETWORK[network];
  if (!publicConfig) {
    throw new Error(`Unsupported Gateway NEAR network: ${String(network)}`);
  }
  const nearRpcUrl = config.optional.nearRelayer?.rpcUrl || publicConfig.rpcUrl;
  plan.variables.push(
    {
      environment: plan.target,
      name: 'VITE_NEAR_NETWORK',
      value: network,
    },
    {
      environment: plan.target,
      name: 'VITE_NEAR_RPC_URL',
      value: nearRpcUrl,
    },
    {
      environment: plan.target,
      name: 'VITE_NEAR_EXPLORER',
      value: publicConfig.explorerUrl,
    },
  );
}

function addWalletCoreNearRelayerUpdates(plan, values, repository) {
  const accountId = readValue(values, 'RELAYER_ACCOUNT_ID');
  const privateKey = readValue(values, 'RELAYER_PRIVATE_KEY');
  const publicKey = readValue(values, 'RELAYER_PUBLIC_KEY');
  const suppliedRpcUrl = readValue(values, 'NEAR_RPC_URL');
  const suppliedInitialBalanceYocto = readValue(values, 'RELAYER_INITIAL_BALANCE_YOCTO');
  if (!accountId && !privateKey && !publicKey && !suppliedRpcUrl && !suppliedInitialBalanceYocto) {
    return;
  }
  const config = requireGatewayConfig(plan, repository);
  const nearRelayer = config.optional.nearRelayer;
  if (!nearRelayer && !accountId) {
    throw new Error('NEAR relayer funding updates require an existing or supplied relayer account');
  }
  if (accountId) {
    const current = nearRelayer?.accountId === accountId ? nearRelayer : null;
    const defaultRpcUrl = current
      ? current.rpcUrl
      : readGitHubVariable(plan.target, 'VITE_NEAR_RPC_URL', repository);
    config.optional.nearRelayer = buildUpdatedNearRelayer({
      accountId,
      publicKey,
      suppliedRpcUrl,
      suppliedInitialBalanceYocto,
      current,
      defaultRpcUrl,
    });
    plan.secrets.push({
      environment: `${plan.target}-gateway`,
      name: 'RELAYER_PRIVATE_KEY',
      value: privateKey,
    });
    return;
  }
  if (suppliedRpcUrl) {
    nearRelayer.rpcUrl = suppliedRpcUrl;
  }
  if (suppliedInitialBalanceYocto) {
    nearRelayer.initialBalanceYocto = suppliedInitialBalanceYocto;
  }
}

function buildUpdatedNearRelayer(input) {
  return {
    accountId: input.accountId,
    publicKey: input.publicKey || input.current?.publicKey || null,
    rpcUrl: input.suppliedRpcUrl || input.current?.rpcUrl || input.defaultRpcUrl,
    initialBalanceYocto:
      input.suppliedInitialBalanceYocto ||
      input.current?.initialBalanceYocto ||
      DEFAULT_NEAR_INITIAL_BALANCE_YOCTO,
  };
}

function addGatewayRuntimeProfileUpdate(plan, values, repository) {
  const runtimeProfileKind = readValue(values, 'GATEWAY_RUNTIME_PROFILE');
  const emailOtpDeliveryKind = readValue(values, 'EMAIL_OTP_DELIVERY_MODE');
  if (!runtimeProfileKind && !emailOtpDeliveryKind) {
    return;
  }
  const config = requireGatewayConfig(plan, repository);
  const parsed = parseGatewayDeploymentConfig(JSON.stringify(config), plan.target);
  config.schemaVersion = GATEWAY_DEPLOYMENT_CONFIG_SCHEMA_VERSION;
  config.runtimeProfile = buildGatewayRuntimeProfile(
    runtimeProfileKind || parsed.runtimeProfile.kind,
    emailOtpDeliveryKind || parsed.runtimeProfile.emailOtpDelivery.kind,
  );
}

function addGatewayOptionalConfigUpdates(plan, values, repository) {
  const googleOidcClientId = readValue(values, 'GOOGLE_OIDC_CLIENT_ID');
  const oidcExchange = parseOptionalJsonObject(values, 'SEAMS_OIDC_EXCHANGE_JSON');
  if (!googleOidcClientId && !oidcExchange) {
    return;
  }
  const config = requireGatewayConfig(plan, repository);
  if (googleOidcClientId) {
    config.optional.googleOidcClientId = googleOidcClientId;
  }
  if (oidcExchange) {
    config.optional.oidcExchange = oidcExchange;
  }
}

function requireGatewayConfig(plan, repository) {
  if (plan.gatewayConfig) {
    return plan.gatewayConfig;
  }
  const environment = `${plan.target}-gateway`;
  const source = readGitHubVariable(environment, 'GATEWAY_DEPLOYMENT_CONFIG_JSON', repository);
  parseGatewayDeploymentConfig(source, plan.target);
  const raw = parseJsonObject(source, 'GATEWAY_DEPLOYMENT_CONFIG_JSON');
  plan.gatewayConfig = raw;
  return raw;
}

function readCurrentGatewayConfig(target, repository) {
  const environment = `${target}-gateway`;
  const source = readGitHubVariable(
    environment,
    'GATEWAY_DEPLOYMENT_CONFIG_JSON',
    repository,
  );
  return parseGatewayDeploymentConfig(source, target);
}

function validatePlan(plan) {
  validateUniqueUpdates(plan.variables, 'variable');
  validateUniqueUpdates(plan.secrets, 'secret');
  if (plan.gatewayConfig) {
    const source = JSON.stringify(plan.gatewayConfig);
    parseGatewayDeploymentConfig(source, plan.target);
    plan.variables.push({
      environment: `${plan.target}-gateway`,
      name: 'GATEWAY_DEPLOYMENT_CONFIG_JSON',
      value: source,
    });
    validateUniqueUpdates(plan.variables, 'variable');
  }
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
    target: plan.target,
    component: plan.component,
    repository: plan.repository,
    valuesFile: plan.valuesFile,
    variables,
    secrets,
    gatewayConfig: plan.gatewayConfig,
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
  process.stdout.write(`Target: ${plan.target}\n\n`);
  process.stdout.write(`Component: ${plan.component}\n\n`);
  printGatewayRuntimeProfile(plan);
  printUpdates('Variables', plan.variables, false);
  printUpdates('Secrets', plan.secrets, true);
  if (!applying) {
    process.stdout.write('\nNo GitHub values were changed. Add --apply to upload this plan.\n');
  }
}

function printGatewayRuntimeProfile(plan) {
  if (!plan.gatewayConfig) {
    return;
  }
  const parsed = parseGatewayDeploymentConfig(JSON.stringify(plan.gatewayConfig), plan.target);
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
  if (update.name === 'GATEWAY_DEPLOYMENT_CONFIG_JSON') {
    return '<validated-config-update>';
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

function readGitHubVariable(environment, name, repository) {
  const child = runGhResult(['variable', 'get', name, '--env', environment, '--repo', repository]);
  if (child.status !== 0) {
    throw new Error(formatGhFailure(`read ${environment}.${name}`, child));
  }
  const value = String(child.stdout).trim();
  if (!value) {
    throw new Error(`GitHub variable ${environment}.${name} is empty`);
  }
  return value;
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
  if (index === -1) {
    return undefined;
  }
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${name} requires a value`);
  }
  return value;
}

function printUsage() {
  process.stdout
    .write(`Apply operator-owned deployment values without rotating generated identities.

Usage:
  pnpm wallet-core:deploy:env-update -- --env staging --repo seams-tech/seams-sdk
  pnpm product:deploy:env-update -- --env staging --repo seams-tech/seams-sdk

Options:
  --env <target>        Required. staging or production.
  --component <name>    Required. wallet-core or product.
  --values-file <path>  Defaults to ~/.seams/<target>-deployment.env.
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
