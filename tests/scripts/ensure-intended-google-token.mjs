#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import {
  defaultEnvFile,
  defaultGoogleTokenMinimumTtlSeconds,
  describeUsableGoogleIdToken,
  firstNonEmptyString,
  readEnvFile,
  repoRoot,
  resolveGoogleClientId,
  resolveGoogleIdToken,
  resolveRepoPath,
} from './intended-google-oidc-env.mjs';

await main().catch(handleFatalError);

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const envFilePath = resolveRepoPath(args.envFile);
  const fileEnv = readEnvFile(envFilePath);
  const clientId = resolveGoogleClientId({
    explicitClientId: args.clientId,
    processEnv: process.env,
    fileEnv,
  });
  const token = resolveGoogleIdToken({
    processToken: process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
    fileToken: fileEnv.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
    clientId,
    minimumTtlSeconds: args.minimumTtlSeconds,
  });
  const existingToken = describeUsableGoogleIdToken({
    token,
    clientId,
    minimumTtlSeconds: args.minimumTtlSeconds,
  });
  if (existingToken.status === 'usable') {
    console.log(`[intended-google-token] existing token ok exp=${existingToken.expiresAtIso}`);
    return;
  }

  const serviceAccount = resolveServiceAccount(args, fileEnv);
  if (!serviceAccount) {
    throw new Error(
      [
        `Google ID token is ${existingToken.reason}.`,
        'Run pnpm setup:intended-google-oidc once, or set',
        'SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT and run pnpm refresh:intended-google-token.',
      ].join(' '),
    );
  }

  console.log(`[intended-google-token] refreshing token because ${existingToken.reason}`);
  refreshGoogleIdToken({ envFilePath, serviceAccount, clientId });
}

function handleFatalError(error) {
  console.error(
    `[intended-google-token] ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
}

function printHelp() {
  console.log(`Usage:
  pnpm ensure:intended-google-token

Options:
  --service-account <email>  Service account to impersonate when refresh is needed.
  --client-id <client-id>    Google OIDC audience. Defaults to the local intended client id.
  --env-file <path>          Env file to read/update. Defaults to .env.local.
  --minimum-ttl <seconds>    Refresh when token has less TTL. Defaults to 1200.
  --help                     Show this help.

Environment:
  SEAMS_INTENDED_GOOGLE_ID_TOKEN
  SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT
  SEAMS_INTENDED_GOOGLE_CLIENT_ID
  SEAMS_INTENDED_ENV_FILE
`);
}

function parseCliArgs(argv) {
  const args = {
    serviceAccount: '',
    clientId: '',
    envFile: process.env.SEAMS_INTENDED_ENV_FILE || defaultEnvFile,
    minimumTtlSeconds: defaultGoogleTokenMinimumTtlSeconds,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') continue;
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg === '--service-account') {
      args.serviceAccount = requireNextCliValue(argv, index, '--service-account');
      index += 1;
      continue;
    }
    if (arg.startsWith('--service-account=')) {
      args.serviceAccount = requireInlineCliValue(arg, '--service-account=');
      continue;
    }
    if (arg === '--client-id') {
      args.clientId = requireNextCliValue(argv, index, '--client-id');
      index += 1;
      continue;
    }
    if (arg.startsWith('--client-id=')) {
      args.clientId = requireInlineCliValue(arg, '--client-id=');
      continue;
    }
    if (arg === '--env-file') {
      args.envFile = requireNextCliValue(argv, index, '--env-file');
      index += 1;
      continue;
    }
    if (arg.startsWith('--env-file=')) {
      args.envFile = requireInlineCliValue(arg, '--env-file=');
      continue;
    }
    if (arg === '--minimum-ttl') {
      args.minimumTtlSeconds = parsePositiveInteger(
        requireNextCliValue(argv, index, '--minimum-ttl'),
        '--minimum-ttl',
      );
      index += 1;
      continue;
    }
    if (arg.startsWith('--minimum-ttl=')) {
      args.minimumTtlSeconds = parsePositiveInteger(
        requireInlineCliValue(arg, '--minimum-ttl='),
        '--minimum-ttl',
      );
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }
  return args;
}

function requireNextCliValue(argv, index, optionName) {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) {
    throw new Error(`${optionName} requires a value`);
  }
  return value;
}

function requireInlineCliValue(arg, prefix) {
  const value = arg.slice(prefix.length);
  if (!value) throw new Error(`${prefix.slice(0, -1)} requires a value`);
  return value;
}

function parsePositiveInteger(value, optionName) {
  const parsed = Number(value);
  if (Number.isInteger(parsed) && parsed > 0) return parsed;
  throw new Error(`${optionName} must be a positive integer`);
}

function resolveServiceAccount(args, fileEnv) {
  return firstNonEmptyString([
    args.serviceAccount,
    process.env.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    process.env.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
  ]);
}

function refreshGoogleIdToken(args) {
  const result = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, 'tests/scripts/refresh-intended-google-token.mjs'),
      '--service-account',
      args.serviceAccount,
      '--client-id',
      args.clientId,
      '--env-file',
      args.envFilePath,
    ],
    {
      cwd: repoRoot,
      env: process.env,
      stdio: 'inherit',
    },
  );
  if (result.error) {
    throw new Error(`token refresh failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`token refresh exited with ${String(result.status ?? 'unknown')}`);
  }
}
