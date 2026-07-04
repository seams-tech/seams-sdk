#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import {
  defaultEnvFile,
  defaultGoogleClientId,
  firstNonEmptyString,
  readEnvFile,
  repoRoot,
  resolveRepoPath,
} from './intended-google-oidc-env.mjs';

const defaultMinimumTtlSeconds = 10 * 60;

await main().catch(handleFatalError);

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const envFilePath = resolveRepoPath(args.envFile);
  const fileEnv = readEnvFile(envFilePath);
  const clientId = resolveClientId(args, fileEnv);
  const token = resolveGoogleIdToken(fileEnv);
  const existingToken = describeUsableToken({
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
  --env-file <path>          Env file to read/update. Defaults to .env.intended.local.
  --minimum-ttl <seconds>    Refresh when token has less TTL. Defaults to 600.
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
    minimumTtlSeconds: defaultMinimumTtlSeconds,
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

function resolveClientId(args, fileEnv) {
  return (
    firstNonEmptyString([
      args.clientId,
      process.env.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      process.env.GOOGLE_OIDC_CLIENT_ID,
      fileEnv.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      fileEnv.GOOGLE_OIDC_CLIENT_ID,
    ]) || defaultGoogleClientId
  );
}

function resolveGoogleIdToken(fileEnv) {
  return firstNonEmptyString([
    process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
    fileEnv.SEAMS_INTENDED_GOOGLE_ID_TOKEN,
  ]);
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

function describeUsableToken(args) {
  if (!args.token) return { status: 'unusable', reason: 'missing' };
  const segments = args.token.split('.');
  if (segments.length !== 3) return { status: 'unusable', reason: 'not a compact JWT' };
  const payload = parseTokenPayload(segments[1]);
  if (!payload) return { status: 'unusable', reason: 'not decodable' };
  const aud = payload.aud;
  const audiences = Array.isArray(aud) ? aud.map(String) : [String(aud || '')];
  if (!audiences.includes(args.clientId)) {
    return { status: 'unusable', reason: 'for a different audience' };
  }
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp)) return { status: 'unusable', reason: 'missing exp' };
  const minimumExpiryMs = Date.now() + args.minimumTtlSeconds * 1000;
  if (exp * 1000 <= minimumExpiryMs) {
    return { status: 'unusable', reason: 'expired or near expiry' };
  }
  return {
    status: 'usable',
    expiresAtIso: new Date(exp * 1000).toISOString(),
  };
}

function parseTokenPayload(segment) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
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
