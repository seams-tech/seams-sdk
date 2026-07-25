#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readDeploymentTarget } from './deployment-targets.mjs';

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, '..');
const ROUTER_ROOT = path.join(REPOSITORY_ROOT, 'crates', 'router-ab-cloudflare');
const SITE_ROOT = path.join(REPOSITORY_ROOT, 'apps', 'seams-site');
const SITE_OUTPUT = path.join(SITE_ROOT, 'dist');
const SDK_OUTPUT = path.join(REPOSITORY_ROOT, 'packages', 'sdk-web', 'dist');
const FRONTEND_SMOKE_PATHS = Object.freeze({
  site: ['/', '/sdk/workers/near-signer.worker.js'],
  wallet: [
    '/',
    '/wallet-service/index.html',
    '/sdk/workers/near-signer.worker.js',
    '/sdk/workers/router_ab_ed25519_yao_client_bg.wasm',
  ],
});

main(process.argv.slice(2)).catch(handleFailure);

async function main(args) {
  const options = parseArguments(args);
  const target = readDeploymentTarget(options.target);
  switch (options.operation) {
    case 'plan':
      printPlan(options.target, target);
      return;
    case 'build':
      buildFrontend(options.target, target);
      return;
    case 'deploy':
      deployFrontend(options.target, target);
      return;
    case 'smoke':
      await smokeFrontend(target);
      return;
    default:
      throw new Error(`Unsupported frontend operation: ${options.operation}`);
  }
}

function parseArguments(args) {
  const operation = String(args[0] || '').trim();
  let targetName = '';
  for (let index = 1; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--target') {
      targetName = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    if (argument === '--component') {
      throw new Error('--component is not allowed for frontend operations');
    }
    throw new Error('usage: deploy-frontend.mjs <plan|build|deploy|smoke> --target <target>');
  }
  if (!['plan', 'build', 'deploy', 'smoke'].includes(operation)) {
    throw new Error('usage: deploy-frontend.mjs <plan|build|deploy|smoke> --target <target>');
  }
  if (!targetName)
    throw new Error(
      '--target is required (usage: deploy-frontend.mjs <operation> --target <target>)',
    );
  return { operation, target: targetName };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value || value.startsWith('--')) throw new Error(`${name} requires a value`);
  return value;
}

function printPlan(targetName, target) {
  const lines = [
    `Frontend deployment plan: ${targetName}`,
    `Branch: ${target.branch}`,
    `Site: ${target.origins.site}`,
    `Wallet: ${target.origins.wallet}`,
    `Pages branch: ${target.resources.frontend.pagesBranch}`,
    '',
    'Order:',
    '  1. build production SDK and Pages output once',
    '  2. deploy the app Pages project',
    '  3. deploy the wallet Pages project from the same output',
    '  4. smoke app, SDK, wallet, and wallet-service endpoints',
  ];
  process.stdout.write(`${lines.join('\n')}\n`);
}

function buildFrontend(targetName, target) {
  runCommand('pnpm', ['install', '--frozen-lockfile']);
  const buildEnvironment = buildFrontendEnvironment(targetName, target);
  runCommand('pnpm', ['build:sdk-prod'], { env: buildEnvironment });
  runCommand('pnpm', ['-C', 'apps/seams-site', 'exec', 'vite', 'build'], {
    env: buildEnvironment,
  });
  copySdkAssets();
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  assertFile(path.join(SITE_OUTPUT, 'wallet-service', 'index.html'), 'wallet-service entry');
}

function buildFrontendEnvironment(targetName, target) {
  const environment = {
    ...process.env,
    VITE_RELAYER_URL: target.origins.gateway,
    VITE_CONSOLE_BASE_URL: target.origins.gateway,
    VITE_WALLET_ORIGIN: target.origins.wallet,
    VITE_DOCS_ORIGIN: target.origins.site,
    VITE_RP_ID_BASE: new URL(target.origins.wallet).hostname,
    VITE_ROUTER_AB_NORMAL_SIGNING_WORKER_ID: target.resources.signingWorker.workerName,
  };
  const required = [
    'VITE_SEAMS_PROJECT_ENVIRONMENT_ID',
    'VITE_SEAMS_PUBLISHABLE_KEY',
    'VITE_NEAR_NETWORK',
    'VITE_NEAR_RPC_URL',
    'VITE_NEAR_EXPLORER',
    'VITE_SIGNING_SESSION_PERSISTENCE_MODE',
    'VITE_SIGNING_SESSION_SEAL_KEY_VERSION',
    'VITE_SIGNING_SESSION_SHAMIR_P_B64U',
  ];
  if (targetName === 'production' && !String(environment.VITE_NEAR_NETWORK || '').trim()) {
    throw new Error('VITE_NEAR_NETWORK is required for production frontend builds');
  }
  requireEnvironmentValues(required, environment);
  return environment;
}

function copySdkAssets() {
  const sdkEsm = path.join(SDK_OUTPUT, 'esm', 'sdk');
  const sdkWorkers = path.join(SDK_OUTPUT, 'workers');
  const walletService = path.join(SDK_OUTPUT, 'public', 'wallet-service');
  assertDirectory(sdkEsm, 'SDK ESM output');
  assertFile(path.join(walletService, 'index.html'), 'SDK wallet-service output');
  copyDirectory(sdkEsm, path.join(SITE_OUTPUT, 'sdk'));
  if (fs.existsSync(sdkWorkers))
    copyDirectory(sdkWorkers, path.join(SITE_OUTPUT, 'sdk', 'workers'));
  copyDirectory(walletService, path.join(SITE_OUTPUT, 'wallet-service'));
}

function copyDirectory(source, destination) {
  fs.mkdirSync(destination, { recursive: true });
  runCommand('rsync', ['-a', '--delete', `${source}${path.sep}`, `${destination}${path.sep}`]);
}

function deployFrontend(targetName, target) {
  requireEnvironmentValues(['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID'], process.env);
  const frontend = target.resources.frontend;
  requireEnvironmentValues([frontend.appProjectEnv, frontend.walletProjectEnv], process.env);
  assertDirectory(SITE_OUTPUT, 'Pages build output');
  const commonArguments = [
    'pages',
    'deploy',
    path.relative(ROUTER_ROOT, SITE_OUTPUT),
    '--branch',
    frontend.pagesBranch,
    '--commit-dirty=false',
  ];
  const sourceSha = String(process.env.DEPLOY_SHA || '').trim();
  if (sourceSha) commonArguments.push('--commit-hash', sourceSha);
  deployPagesProject(commonArguments, process.env[frontend.appProjectEnv]);
  deployPagesProject(commonArguments, process.env[frontend.walletProjectEnv]);
  process.stdout.write(`Frontend deploy completed: ${targetName}\n`);
}

function deployPagesProject(commonArguments, projectName) {
  const args = ['exec', 'wrangler', ...commonArguments, '--project-name', projectName];
  runCommand('pnpm', args, { cwd: ROUTER_ROOT });
}

async function smokeFrontend(target) {
  const checks = buildSmokeChecks(target);
  const results = await Promise.all(checks.map(runHttpCheck));
  const failed = results.filter(isFailedHttpCheck);
  process.stdout.write(`${JSON.stringify({ results })}\n`);
  if (failed.length > 0) {
    throw new Error(`frontend smoke failed: ${failed.map(formatFailedHttpCheck).join(', ')}`);
  }
}

function buildSmokeChecks(target) {
  const checks = [];
  addSmokeChecks(checks, 'site', target.origins.site, FRONTEND_SMOKE_PATHS.site);
  addSmokeChecks(checks, 'wallet', target.origins.wallet, FRONTEND_SMOKE_PATHS.wallet);
  return checks;
}

function addSmokeChecks(checks, surface, origin, requestPaths) {
  for (const requestPath of requestPaths) {
    checks.push({
      name: `${surface}${requestPath}`,
      url: new URL(requestPath, origin).toString(),
    });
  }
}

async function runHttpCheck(check) {
  try {
    const response = await fetch(check.url, { signal: AbortSignal.timeout(5000) });
    return {
      name: check.name,
      ok: response.status >= 200 && response.status < 400,
      status: response.status,
    };
  } catch (error) {
    return { name: check.name, ok: false, error: formatError(error) };
  }
}

function isFailedHttpCheck(result) {
  return !result.ok;
}

function formatFailedHttpCheck(result) {
  return result.name;
}

function requireEnvironmentValues(names, environment) {
  for (const name of names) {
    const value = String(environment[name] || '').trim();
    if (!value) throw new Error(`${name} is required`);
  }
}

function runCommand(command, args, options = {}) {
  const child = spawnSync(command, args, {
    cwd: options.cwd || REPOSITORY_ROOT,
    env: options.env || process.env,
    encoding: 'utf8',
    stdio: 'inherit',
  });
  if (child.error) throw child.error;
  if (child.status !== 0)
    throw new Error(`${command} ${args.join(' ')} failed with status ${child.status}`);
}

function assertDirectory(directory, label) {
  if (!fs.existsSync(directory) || !fs.statSync(directory).isDirectory()) {
    throw new Error(`${label} is missing: ${directory}`);
  }
}

function assertFile(filePath, label) {
  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    throw new Error(`${label} is missing: ${filePath}`);
  }
}

function formatError(error) {
  return error instanceof Error ? error.message : String(error);
}

function handleFailure(error) {
  process.stderr.write(`${formatError(error)}\n`);
  process.exitCode = 1;
}
