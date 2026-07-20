import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { parseEnv } from 'node:util';
import {
  DEFAULT_NEAR_INITIAL_BALANCE_YOCTO,
  parseGatewayDeploymentConfig,
} from '../../../packages/console-server-ts/scripts/gateway-deployment-config.mjs';

const TARGETS = new Set(['staging', 'production']);
const githubCli = process.env.GITHUB_CLI_BIN || 'gh';
const GENERAL_VARIABLE_INPUTS = Object.freeze([
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
const CLOUDFLARE_ENVIRONMENT_SUFFIXES = Object.freeze([
  '',
  '-gateway',
  '-mpc-router',
  '-deriver-a',
  '-deriver-b',
  '-signing-worker',
]);
const GATEWAY_SECRET_INPUTS = Object.freeze([
  ['SPONSORED_EVM_EXECUTORS_JSON', 'SPONSORED_EVM_EXECUTORS_JSON'],
]);

const argv = process.argv.slice(2).filter((argument) => argument !== '--');

if (argv.includes('--help')) {
  printUsage();
  process.exit(0);
}

await main(parseOptions());

async function main(options) {
  const values = loadProtectedValues(options.valuesFile);
  validateExternalValues(values);
  const repository = resolveGitHubRepository(options.repository);
  const plan = buildBasePlan(options, repository, values);
  addNearRelayerUpdates(plan, values, repository);
  addGatewayOptionalConfigUpdates(plan, values, repository);
  validatePlan(plan);
  printPlan(plan, options.apply);
  if (options.apply) {
    applyPlan(plan);
  }
}

function parseOptions() {
  const target = requireOption('--env');
  if (!TARGETS.has(target)) {
    throw new Error('--env must be staging or production');
  }
  const valuesFile =
    readOption('--values-file') || resolve(homedir(), '.seams', `${target}-deployment.env`);
  return {
    target,
    valuesFile,
    repository: readOption('--repo'),
    apply: argv.includes('--apply'),
  };
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

function validateExternalValues(values) {
  validatePair(values, 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID', 'Cloudflare deployment');
  validatePair(values, 'RELAYER_ACCOUNT_ID', 'RELAYER_PRIVATE_KEY', 'NEAR sponsorship');
  validatePair(values, 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2 publication');
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
    repository,
    valuesFile: options.valuesFile,
    variables: [],
    secrets: [],
    gatewayConfig: null,
  };
  appendMappedUpdates(plan.variables, options.target, values, GENERAL_VARIABLE_INPUTS);
  appendMappedUpdates(plan.secrets, options.target, values, GENERAL_SECRET_INPUTS);
  appendCloudflareDeploymentUpdates(plan, options.target, values);
  appendMappedUpdates(plan.secrets, `${options.target}-gateway`, values, GATEWAY_SECRET_INPUTS);
  return plan;
}

function appendCloudflareDeploymentUpdates(plan, target, values) {
  for (const suffix of CLOUDFLARE_ENVIRONMENT_SUFFIXES) {
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

function addNearRelayerUpdates(plan, values, repository) {
  const accountId = readValue(values, 'RELAYER_ACCOUNT_ID');
  if (!accountId) {
    return;
  }
  const privateKey = readValue(values, 'RELAYER_PRIVATE_KEY');
  const publicKey = readValue(values, 'RELAYER_PUBLIC_KEY');
  const rpcUrl =
    readValue(values, 'NEAR_RPC_URL') ||
    readGitHubVariable(plan.target, 'VITE_NEAR_RPC_URL', repository);
  const initialBalanceYocto =
    readValue(values, 'RELAYER_INITIAL_BALANCE_YOCTO') || DEFAULT_NEAR_INITIAL_BALANCE_YOCTO;
  plan.variables.push({
    environment: plan.target,
    name: 'VITE_RELAYER_ACCOUNT_ID',
    value: accountId,
  });
  plan.secrets.push({
    environment: `${plan.target}-gateway`,
    name: 'RELAYER_PRIVATE_KEY',
    value: privateKey,
  });
  const config = requireGatewayConfig(plan, repository);
  config.optional.nearRelayer = {
    accountId,
    publicKey: publicKey || null,
    rpcUrl,
    initialBalanceYocto,
  };
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
  printUpdates('Variables', plan.variables, false);
  printUpdates('Secrets', plan.secrets, true);
  if (!applying) {
    process.stdout.write('\nNo GitHub values were changed. Add --apply to upload this plan.\n');
  }
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
  pnpm router:deploy:env-apply -- --env staging --repo seams-tech/seams-sdk
  pnpm router:deploy:env-apply -- --env staging --repo seams-tech/seams-sdk --apply

Options:
  --env <target>        Required. staging or production.
  --values-file <path>  Defaults to ~/.seams/<target>-deployment.env.
  --repo <owner/repo>   Defaults to the repository for the current checkout.
  --apply               Upload the planned variables and secrets.
  --help                Show this help.

Dry run is the default. The command only updates whitelisted external values.
It never generates or replaces Router A/B, Gateway, or signing-session identity
material.
`);
}
