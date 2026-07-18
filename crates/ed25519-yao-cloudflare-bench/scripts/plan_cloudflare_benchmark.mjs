import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

import { BoundaryError, parseDeploymentEnvironment } from './deployment_boundary.mjs';
import {
  assertArtifactEvidenceEqual,
  attachConstantTimeCodegen,
  attachRoleDeployment,
  attachRoleArtifact,
  collectArtifactEvidence,
  completeDeploymentReceipt,
  deploymentReceiptPath,
  initialDeploymentReceipt,
  readDeploymentReceipt,
  writeDeploymentReceipt,
} from './deployment_receipt.mjs';
import {
  evaluateLocalPreflight,
  loadWorkspaceArtifact,
} from './evaluate_phase13a_local_preflight.mjs';
import { loadLocalReadinessBundle } from './local_readiness_bundle.mjs';
import { inspectWorkerArtifacts } from '../../ed25519-yao/scripts/check_constant_time_codegen.mjs';

const PACKAGE_ROOT = fileURLToPath(new URL('../', import.meta.url));
const DEFAULT_WRANGLER = fileURLToPath(
  new URL('../../../packages/console-server-ts/node_modules/.bin/wrangler', import.meta.url),
);
const PROFILE_OVERRIDING_CREDENTIALS = Object.freeze([
  'CLOUDFLARE_API_TOKEN',
  'CLOUDFLARE_API_KEY',
  'CLOUDFLARE_ACCOUNT_ID',
  'CF_API_TOKEN',
  'WRANGLER_OUTPUT_FILE_PATH',
]);

function sourceConfigName(configuration, role) {
  if (configuration.topology === 'one-account') {
    return role === 'a' ? 'wrangler.a.jsonc' : 'wrangler.b.jsonc';
  }
  return role === 'a' ? 'wrangler.a.cross-account.jsonc' : 'wrangler.b.cross-account.jsonc';
}

function readSourceConfig(configuration, role) {
  const name = sourceConfigName(configuration, role);
  return JSON.parse(readFileSync(join(PACKAGE_ROOT, name), 'utf8'));
}

function customDomain(hostname) {
  return [Object.freeze({ pattern: hostname, custom_domain: true })];
}

function quotedCommandArgument(value) {
  return JSON.stringify(value);
}

function makeRenderedConfigSelfContained(rendered) {
  const match = /^worker-build --release --out-dir ([a-z0-9/-]+) --features ([a-z0-9,-]+)$/.exec(
    rendered.build?.command,
  );
  if (match === null || rendered.build.watch_dir !== 'src') {
    throw new BoundaryError('checked-in Wrangler build contract changed');
  }
  const outputDirectory = join(PACKAGE_ROOT, match[1]);
  rendered.main = join(PACKAGE_ROOT, rendered.main);
  rendered.build.command = [
    'worker-build --release --out-dir',
    quotedCommandArgument(outputDirectory),
    quotedCommandArgument(PACKAGE_ROOT),
    '--features',
    match[2],
  ].join(' ');
  rendered.build.watch_dir = join(PACKAGE_ROOT, 'src');
}

function renderRoleConfig(configuration, role, deploymentId) {
  const rendered = readSourceConfig(configuration, role);
  makeRenderedConfigSelfContained(rendered);
  const roleConfiguration = role === 'a' ? configuration.a : configuration.b;
  rendered.account_id = roleConfiguration.accountId;
  rendered.name = roleConfiguration.scriptName;
  if (deploymentId !== undefined) {
    rendered.vars.BENCHMARK_DEPLOYMENT_ID = deploymentId;
  }
  if (role === 'a') {
    rendered.workers_dev = false;
    rendered.routes = customDomain(configuration.a.publicHostname);
    if (configuration.topology === 'one-account') {
      rendered.services[0].service = configuration.b.scriptName;
    } else {
      rendered.vars.DERIVER_B_WEBSOCKET_ENDPOINT = configuration.b.publicEndpoint;
    }
  } else if (configuration.topology === 'two-account') {
    rendered.workers_dev = false;
    rendered.routes = customDomain(configuration.b.publicHostname);
  }
  return rendered;
}

export function renderDeploymentConfigs(configuration, deploymentId) {
  return Object.freeze({
    a: renderRoleConfig(configuration, 'a', deploymentId),
    b: renderRoleConfig(configuration, 'b', deploymentId),
  });
}

function operation(role, configuration) {
  const selected = role === 'a' ? configuration.a : configuration.b;
  return Object.freeze({
    action: 'wrangler deploy --strict',
    role: role === 'a' ? 'deriver-a' : 'deriver-b',
    profile: selected.profile,
    script_name: selected.scriptName,
    source_config: sourceConfigName(configuration, role),
  });
}

function preflightOperation(role, configuration) {
  const selected = role === 'a' ? configuration.a : configuration.b;
  return Object.freeze({
    action: 'wrangler auth activate + whoami --account --json',
    role: role === 'a' ? 'deriver-a' : 'deriver-b',
    profile: selected.profile,
    expected_account: 'boundary-only',
  });
}

function cleanupOperation(role, configuration) {
  const selected = role === 'a' ? configuration.a : configuration.b;
  return Object.freeze({
    action: 'wrangler delete --force',
    role: role === 'a' ? 'deriver-a' : 'deriver-b',
    profile: selected.profile,
    script_name: selected.scriptName,
  });
}

function planOperations(configuration, lifecycle) {
  if (lifecycle === 'deploy') {
    return Object.freeze([
      preflightOperation('a', configuration),
      preflightOperation('b', configuration),
      operation('b', configuration),
      operation('a', configuration),
    ]);
  }
  return Object.freeze([
    preflightOperation('a', configuration),
    preflightOperation('b', configuration),
    cleanupOperation('a', configuration),
    cleanupOperation('b', configuration),
  ]);
}

export function buildDeploymentPlan(configuration, mode) {
  const execute = mode.endsWith('execute');
  const lifecycle = mode.startsWith('cleanup') ? 'cleanup' : 'deploy';
  return Object.freeze({
    benchmark: 'phase9b-cloudflare-deployment-plan',
    benchmark_only: true,
    security_claim: 'none',
    mode,
    lifecycle,
    topology: configuration.topology,
    account_relationship:
      configuration.topology === 'one-account' ? 'same-account' : 'distinct-accounts',
    region_label: configuration.regionLabel,
    sample_count: configuration.sampleCount,
    endpoints: Object.freeze({
      a_public: configuration.a.publicEndpoint,
      b_websocket: configuration.b.publicEndpoint ?? null,
    }),
    operations: planOperations(configuration, lifecycle),
    external_state_change_requested: execute,
    external_state_changed: false,
    deployment_receipt_required_for_execute_and_cleanup: true,
    next:
      lifecycle === 'deploy'
        ? 'Review the plan. Use the explicit deployment execute command only after configuring both profiles and accepting the benchmark-only constraints.'
        : 'Review the reverse dependency deletion order. Use cleanup execute only after confirming deletion of both benchmark Workers.',
  });
}

function parseMode(argumentsList) {
  if (argumentsList.length === 0) {
    return 'deploy-plan';
  }
  if (argumentsList.length === 1 && argumentsList[0] === '--execute') {
    return 'deploy-execute';
  }
  if (argumentsList.length === 1 && argumentsList[0] === '--cleanup') {
    return 'cleanup-plan';
  }
  if (
    argumentsList.length === 2 &&
    argumentsList[0] === '--cleanup' &&
    argumentsList[1] === '--execute'
  ) {
    return 'cleanup-execute';
  }
  throw new BoundaryError('supported modes are plan, --execute, --cleanup, or --cleanup --execute');
}

function ensureExecutionConfirmation(environment, lifecycle) {
  if (environment.YAOS_AB_CONFIRM_NON_PRODUCTION !== 'YES') {
    throw new BoundaryError('--execute requires YAOS_AB_CONFIRM_NON_PRODUCTION=YES');
  }
  if (environment.YAOS_AB_CONFIRM_NO_AUTH_CLAIM !== 'YES') {
    throw new BoundaryError('--execute requires YAOS_AB_CONFIRM_NO_AUTH_CLAIM=YES');
  }
  if (lifecycle === 'cleanup' && environment.YAOS_AB_CONFIRM_DELETE_BENCHMARK !== 'YES') {
    throw new BoundaryError('cleanup execute requires YAOS_AB_CONFIRM_DELETE_BENCHMARK=YES');
  }
  for (const name of PROFILE_OVERRIDING_CREDENTIALS) {
    if (environment[name] !== undefined) {
      throw new BoundaryError(`${name} must be unset because it overrides Wrangler profiles`);
    }
  }
}

function wranglerBinary(environment) {
  const override = environment.YAOS_AB_WRANGLER_BIN;
  if (override === undefined) {
    return DEFAULT_WRANGLER;
  }
  if (!override.startsWith('/') || /[\r\n\0]/.test(override)) {
    throw new BoundaryError('YAOS_AB_WRANGLER_BIN must be an absolute path');
  }
  return override;
}

function redactedOutput(raw, configuration, environment) {
  let output = raw ?? '';
  for (const secret of [
    configuration.a.accountId,
    configuration.b.accountId,
    environment.CLOUDFLARE_ANALYTICS_TOKEN_A,
    environment.CLOUDFLARE_ANALYTICS_TOKEN_B,
  ]) {
    if (typeof secret === 'string' && secret.length > 0) {
      output = output.replaceAll(secret, '[REDACTED]');
    }
  }
  return output;
}

function profileCapableWrangler(binary, configuration, environment) {
  const result = spawnSync(binary, ['deploy', '--help'], {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
    env: childEnvironment(environment),
  });
  const combined = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
  if (result.status !== 0 || !combined.includes('--profile')) {
    throw new BoundaryError(
      'selected Wrangler does not support auth profiles; install a reviewed release with --profile support',
    );
  }
  return redactedOutput(combined, configuration, environment);
}

function preflightProfile(binary, role, profile, accountId, configuration, environment) {
  const profileDirectory = mkdtempSync(join(tmpdir(), 'ed25519-yao-wrangler-profile-'));
  let preflightError = null;
  let accountIds = null;
  try {
    const activation = spawnSync(binary, ['auth', 'activate', profile, profileDirectory], {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      env: childEnvironment(environment),
    });
    if (activation.status !== 0) {
      throw new BoundaryError(`${role} profile could not be activated for preflight`);
    }
    const result = spawnSync(binary, ['whoami', '--account', accountId, '--json'], {
      cwd: profileDirectory,
      encoding: 'utf8',
      env: childEnvironment(environment),
    });
    if (result.status !== 0) {
      const stderr = redactedOutput(result.stderr, configuration, environment);
      if (stderr.length > 0) {
        process.stderr.write(stderr);
      }
      throw new BoundaryError(`${role} profile cannot access its expected account`);
    }
    accountIds = parseWhoamiAccountIds(result.stdout);
  } catch (error) {
    preflightError = error;
  }
  const deactivation = spawnSync(binary, ['auth', 'deactivate', profileDirectory], {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
    env: childEnvironment(environment),
  });
  rmSync(profileDirectory, { recursive: true, force: true });
  if (preflightError !== null) {
    throw preflightError;
  }
  if (deactivation.status !== 0) {
    throw new BoundaryError(`${role} profile preflight binding could not be removed`);
  }
  if (accountIds === null) {
    throw new BoundaryError(`${role} profile preflight returned no account set`);
  }
  if (!accountIds.has(accountId)) {
    throw new BoundaryError(`${role} profile did not report its expected account`);
  }
  const peerAccountId =
    role === 'Deriver A' ? configuration.b.accountId : configuration.a.accountId;
  if (configuration.topology === 'two-account' && accountIds.has(peerAccountId)) {
    throw new BoundaryError(`${role} profile can access the peer benchmark account`);
  }
}

export function parseWhoamiAccountIds(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new BoundaryError('wrangler whoami returned invalid JSON');
  }
  if (parsed?.loggedIn !== true || !Array.isArray(parsed.accounts)) {
    throw new BoundaryError('wrangler whoami returned an invalid account set');
  }
  const ids = new Set();
  for (const account of parsed.accounts) {
    if (
      account === null ||
      typeof account !== 'object' ||
      typeof account.id !== 'string' ||
      !/^[0-9a-f]{32}$/.test(account.id) ||
      ids.has(account.id)
    ) {
      throw new BoundaryError('wrangler whoami returned an invalid account identity');
    }
    ids.add(account.id);
  }
  if (ids.size === 0) {
    throw new BoundaryError('wrangler whoami returned no accounts');
  }
  return ids;
}

function preflightProfiles(binary, configuration, environment) {
  preflightProfile(
    binary,
    'Deriver A',
    configuration.a.profile,
    configuration.a.accountId,
    configuration,
    environment,
  );
  preflightProfile(
    binary,
    'Deriver B',
    configuration.b.profile,
    configuration.b.accountId,
    configuration,
    environment,
  );
}

function childEnvironment(environment, wranglerOutputPath) {
  const child = { ...environment };
  delete child.CLOUDFLARE_ANALYTICS_TOKEN_A;
  delete child.CLOUDFLARE_ANALYTICS_TOKEN_B;
  delete child.WRANGLER_OUTPUT_FILE_PATH;
  if (wranglerOutputPath !== undefined) {
    child.WRANGLER_OUTPUT_FILE_PATH = wranglerOutputPath;
  }
  return child;
}

function writeRenderedConfig(directory, role, config) {
  const path = join(directory, `wrangler.${role}.json`);
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, { mode: 0o600 });
  return path;
}

function deploymentFeature(configuration, role) {
  if (configuration.topology === 'one-account') {
    return role === 'a' ? 'deriver-a' : 'deriver-b';
  }
  return role === 'a' ? 'deriver-a-cross-account' : 'deriver-b-cross-account';
}

function buildWorkerArtifact(role, configuration, directory, environment) {
  const outputDirectory = join(directory, `artifact-${role}`);
  const result = spawnSync(
    'worker-build',
    [
      '--release',
      '--out-dir',
      outputDirectory,
      PACKAGE_ROOT,
      '--features',
      deploymentFeature(configuration, role),
    ],
    {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      env: childEnvironment(environment),
    },
  );
  if (result.status !== 0) {
    const stderr = redactedOutput(result.stderr, configuration, environment);
    if (stderr.length > 0) {
      process.stderr.write(stderr);
    }
    throw new BoundaryError(`Deriver ${role.toUpperCase()} artifact build failed`);
  }
  return outputDirectory;
}

function assertArtifactDirectoryUnchanged(role, directory, expected, stage) {
  const observed = collectArtifactEvidence(directory);
  assertArtifactEvidenceEqual(
    expected,
    observed,
    `Deriver ${role.toUpperCase()} artifact ${stage}`,
  );
}

export function bindPrebuiltArtifact(config, artifactDirectory) {
  const rendered = structuredClone(config);
  rendered.main = join(artifactDirectory, 'index.js');
  rendered.no_bundle = true;
  delete rendered.build;
  return rendered;
}

function deployRole(binary, role, profile, configPath, outputPath, configuration, environment) {
  const result = spawnSync(
    binary,
    ['deploy', '--config', configPath, '--profile', profile, '--strict', '--no-bundle'],
    {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      env: childEnvironment(environment, outputPath),
    },
  );
  const stdout = redactedOutput(result.stdout, configuration, environment);
  const stderr = redactedOutput(result.stderr, configuration, environment);
  if (stdout.length > 0) {
    process.stdout.write(stdout);
  }
  if (stderr.length > 0) {
    process.stderr.write(stderr);
  }
  if (result.status !== 0) {
    throw new BoundaryError(`${role} deployment failed`);
  }
  try {
    return readFileSync(outputPath, 'utf8');
  } catch {
    throw new BoundaryError(`${role} deployment produced no Wrangler receipt`);
  }
}

function deleteRole(binary, role, profile, scriptName, configPath, configuration, environment) {
  const result = spawnSync(
    binary,
    ['delete', scriptName, '--config', configPath, '--profile', profile, '--force'],
    {
      cwd: PACKAGE_ROOT,
      encoding: 'utf8',
      env: childEnvironment(environment),
    },
  );
  const stdout = redactedOutput(result.stdout, configuration, environment);
  const stderr = redactedOutput(result.stderr, configuration, environment);
  if (stdout.length > 0) {
    process.stdout.write(stdout);
  }
  if (stderr.length > 0) {
    process.stderr.write(stderr);
  }
  return Object.freeze({ role, succeeded: result.status === 0 });
}

function assertCleanupResults(aResult, bResult) {
  if (!aResult.succeeded || !bResult.succeeded) {
    throw new BoundaryError(
      'benchmark cleanup attempted A then B; one or both deletions failed and require inspection',
    );
  }
}

function validatedLocalReadinessBundleSha256() {
  try {
    const bundle = loadLocalReadinessBundle();
    const result = evaluateLocalPreflight(bundle.evidence, loadWorkspaceArtifact);
    if (result.status !== 'deployment-required' || result.phase13a_decision !== 'unavailable') {
      throw new Error('unexpected local-readiness decision');
    }
    return bundle.sha256;
  } catch {
    throw new BoundaryError('local-readiness evidence bundle failed validation');
  }
}

function executeLifecycle(configuration, environment, lifecycle) {
  ensureExecutionConfirmation(environment, lifecycle);
  const binary = wranglerBinary(environment);
  profileCapableWrangler(binary, configuration, environment);
  preflightProfiles(binary, configuration, environment);
  const receiptPath = deploymentReceiptPath(environment);
  const existingReceipt =
    lifecycle === 'cleanup' ? readDeploymentReceipt(receiptPath, configuration, false) : null;
  const deploymentId =
    existingReceipt === null ? randomBytes(16).toString('hex') : existingReceipt.deployment_id;
  const configs = renderDeploymentConfigs(configuration, deploymentId);
  const directory = mkdtempSync(join(tmpdir(), 'ed25519-yao-phase9b-'));
  try {
    if (lifecycle === 'deploy') {
      const localReadinessBundleSha256 = validatedLocalReadinessBundleSha256();
      const bArtifactDirectory = buildWorkerArtifact('b', configuration, directory, environment);
      const aArtifactDirectory = buildWorkerArtifact('a', configuration, directory, environment);
      const bArtifact = collectArtifactEvidence(bArtifactDirectory);
      const aArtifact = collectArtifactEvidence(aArtifactDirectory);
      const inspection = inspectWorkerArtifacts(
        join(aArtifactDirectory, 'index_bg.wasm'),
        join(bArtifactDirectory, 'index_bg.wasm'),
      );
      const bPath = writeRenderedConfig(
        directory,
        'b',
        bindPrebuiltArtifact(configs.b, bArtifactDirectory),
      );
      const aPath = writeRenderedConfig(
        directory,
        'a',
        bindPrebuiltArtifact(configs.a, aArtifactDirectory),
      );
      const receipt = initialDeploymentReceipt(
        configuration,
        deploymentId,
        new Date().toISOString(),
        localReadinessBundleSha256,
      );
      attachRoleArtifact(receipt, 'b', bArtifact);
      attachRoleArtifact(receipt, 'a', aArtifact);
      attachConstantTimeCodegen(receipt, inspection);
      writeDeploymentReceipt(receiptPath, receipt, true);
      const bOutputPath = join(directory, 'wrangler-output-b.jsonl');
      assertArtifactDirectoryUnchanged('b', bArtifactDirectory, bArtifact, 'before deployment');
      const bOutput = deployRole(
        binary,
        'Deriver B',
        configuration.b.profile,
        bPath,
        bOutputPath,
        configuration,
        environment,
      );
      assertArtifactDirectoryUnchanged('b', bArtifactDirectory, bArtifact, 'after deployment');
      attachRoleDeployment(receipt, 'b', bOutput);
      writeDeploymentReceipt(receiptPath, receipt, false);
      const aOutputPath = join(directory, 'wrangler-output-a.jsonl');
      assertArtifactDirectoryUnchanged('a', aArtifactDirectory, aArtifact, 'before deployment');
      const aOutput = deployRole(
        binary,
        'Deriver A',
        configuration.a.profile,
        aPath,
        aOutputPath,
        configuration,
        environment,
      );
      assertArtifactDirectoryUnchanged('a', aArtifactDirectory, aArtifact, 'after deployment');
      attachRoleDeployment(receipt, 'a', aOutput);
      completeDeploymentReceipt(receipt);
      writeDeploymentReceipt(receiptPath, receipt, false);
    } else {
      const bPath = writeRenderedConfig(directory, 'b', configs.b);
      const aPath = writeRenderedConfig(directory, 'a', configs.a);
      const aResult = deleteRole(
        binary,
        'Deriver A',
        configuration.a.profile,
        configuration.a.scriptName,
        aPath,
        configuration,
        environment,
      );
      const bResult = deleteRole(
        binary,
        'Deriver B',
        configuration.b.profile,
        configuration.b.scriptName,
        bPath,
        configuration,
        environment,
      );
      assertCleanupResults(aResult, bResult);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

function isMainModule() {
  return process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
}

function main() {
  const mode = parseMode(process.argv.slice(2));
  const configuration = parseDeploymentEnvironment(process.env);
  const plan = buildDeploymentPlan(configuration, mode);
  process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
  if (mode.endsWith('execute')) {
    executeLifecycle(configuration, process.env, mode.startsWith('cleanup') ? 'cleanup' : 'deploy');
  }
}

function handleFatal(error) {
  const message =
    error instanceof BoundaryError ? error.message : 'deployment orchestration failed';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}

if (isMainModule()) {
  try {
    main();
  } catch (error) {
    handleFatal(error);
  }
}
