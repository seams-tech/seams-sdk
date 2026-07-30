import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { isDeepStrictEqual, parseEnv } from 'node:util';
import { gatewayRuntimeProfileNearNetwork } from '../../../packages/console-server-ts/scripts/gateway-deployment-config.mjs';
import { readDeploymentTarget } from '../../../scripts/deployment-targets.mjs';

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
  ['RESEND_API_KEY', 'RESEND_API_KEY'],
  ['CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U', 'CONSOLE_EMAIL_INVITATION_SECRET_KEY_B64U'],
]);
const GATEWAY_VARIABLE_INPUTS = Object.freeze([['CONSOLE_EMAIL_FROM', 'CONSOLE_EMAIL_FROM']]);
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
  validateCheckedInGatewayConfiguration(plan.target, values);
  if (options.component === 'product') {
    addProductNearRelayerUpdate(plan, values);
    addProductNearNetworkUpdates(plan);
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
  parseOptionalJsonObject(values, 'SEAMS_OIDC_EXCHANGE_JSON');
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

function buildBasePlan(options, repository, values) {
  const plan = {
    target: options.target,
    component: options.component,
    repository,
    valuesFile: options.valuesFile,
    variables: [],
    secrets: [],
    gatewayDeploymentConfig: readDeploymentTarget(options.target).gatewayDeploymentConfig,
  };
  if (options.component === 'product') {
    appendMappedUpdates(plan.variables, options.target, values, GENERAL_VARIABLE_INPUTS);
    appendMappedUpdates(plan.secrets, options.target, values, CLOUDFLARE_SECRET_INPUTS);
  } else {
    appendWalletCoreCloudflareDeploymentUpdates(plan, options.target, values);
    appendMappedUpdates(
      plan.variables,
      `${options.target}-gateway`,
      values,
      GATEWAY_VARIABLE_INPUTS,
    );
    appendMappedUpdates(plan.secrets, `${options.target}-gateway`, values, GATEWAY_SECRET_INPUTS);
  }
  return plan;
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

function addWalletCoreNearRelayerSecretUpdate(plan, values) {
  const privateKey = readValue(values, 'RELAYER_PRIVATE_KEY');
  if (!privateKey) {
    return;
  }
  if (!plan.gatewayDeploymentConfig.optional.nearRelayer) {
    throw new Error('RELAYER_PRIVATE_KEY requires nearRelayer in deployment/targets.json');
  }
  plan.secrets.push({
    environment: `${plan.target}-gateway`,
    name: 'RELAYER_PRIVATE_KEY',
    value: privateKey,
  });
}

function validateCheckedInGatewayConfiguration(target, values) {
  const config = readDeploymentTarget(target).gatewayDeploymentConfig;
  assertSuppliedValueMatches(values, 'GATEWAY_RUNTIME_PROFILE', config.runtimeProfile.kind);
  assertSuppliedValueMatches(
    values,
    'EMAIL_OTP_DELIVERY_MODE',
    config.runtimeProfile.emailOtpDelivery.kind,
  );
  assertSuppliedValueMatches(values, 'GOOGLE_OIDC_CLIENT_ID', config.optional.googleOidcClientId);
  assertSuppliedJsonMatches(values, 'SEAMS_OIDC_EXCHANGE_JSON', config.optional.oidcExchange);
  const walletOrigin = readValue(values, 'VITE_WALLET_ORIGIN');
  if (
    walletOrigin &&
    (!config.origins.allowedCors.includes(walletOrigin) ||
      !config.bootstrap.allowedOrigins.includes(walletOrigin))
  ) {
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
    target: plan.target,
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
