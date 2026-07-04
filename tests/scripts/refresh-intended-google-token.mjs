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
  updateEnvFile,
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
  const serviceAccount = firstNonEmptyString([
    args.serviceAccount,
    process.env.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    process.env.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
  ]);
  const clientId =
    firstNonEmptyString([
      args.clientId,
      process.env.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      process.env.GOOGLE_OIDC_CLIENT_ID,
      fileEnv.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      fileEnv.GOOGLE_OIDC_CLIENT_ID,
    ]) || defaultGoogleClientId;

  if (!serviceAccount) {
    throw new Error(
      [
        'Missing service account.',
        'Pass --service-account=<email> or set SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT.',
      ].join(' '),
    );
  }

  const token = mintGoogleIdToken({
    serviceAccount,
    clientId,
    includeEmail: args.includeEmail,
  });
  const claims = validateGoogleIdTokenClaims({ token, clientId });
  updateEnvFile(envFilePath, {
    SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT: serviceAccount,
    SEAMS_INTENDED_GOOGLE_CLIENT_ID: clientId,
    GOOGLE_OIDC_CLIENT_ID: clientId,
    SEAMS_INTENDED_GOOGLE_ID_TOKEN: token,
    SEAMS_INTENDED_MUTATION_FRESH_STARTUP: '1',
  });

  console.log(`[intended-google-token] wrote ${path.relative(repoRoot, envFilePath)}`);
  console.log(`[intended-google-token] aud=${claims.aud}`);
  console.log(`[intended-google-token] sub=${claims.sub}`);
  if (claims.email) console.log(`[intended-google-token] email=${claims.email}`);
  console.log(`[intended-google-token] exp=${new Date(claims.exp * 1000).toISOString()}`);
}

function handleFatalError(error) {
  console.error(`[intended-google-token] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}

function printHelp() {
  console.log(`Usage:
  pnpm refresh:intended-google-token -- --service-account=<service-account-email>

Options:
  --service-account <email>  Service account to impersonate.
  --client-id <client-id>    Google OIDC audience. Defaults to the local intended client id.
  --env-file <path>          Env file to update. Defaults to .env.intended.local.
  --no-include-email         Omit gcloud --include-email.
  --help                     Show this help.

Environment:
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
    includeEmail: true,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') continue;
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg === '--no-include-email') {
      args.includeEmail = false;
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

function mintGoogleIdToken(args) {
  const gcloudArgs = [
    'auth',
    'print-identity-token',
    `--impersonate-service-account=${args.serviceAccount}`,
    `--audiences=${args.clientId}`,
  ];
  if (args.includeEmail) {
    gcloudArgs.push('--include-email');
  }
  const result = spawnSync('gcloud', gcloudArgs, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) {
    throw new Error(`gcloud failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    const stderr = String(result.stderr || '').trim();
    throw new Error(`gcloud identity-token mint failed (${result.status}): ${stderr}`);
  }
  const token = String(result.stdout || '').trim();
  if (!token) throw new Error('gcloud returned an empty identity token');
  return token;
}

function validateGoogleIdTokenClaims(args) {
  const segments = args.token.split('.');
  if (segments.length !== 3) {
    throw new Error('minted Google ID token is not a compact JWT');
  }
  const header = parseBase64UrlJson(segments[0], 'header');
  const payload = parseBase64UrlJson(segments[1], 'payload');
  if (String(header.alg || '') !== 'RS256') {
    throw new Error(`minted Google ID token alg must be RS256, got ${String(header.alg || '')}`);
  }
  const iss = String(payload.iss || '').trim();
  if (iss !== 'https://accounts.google.com' && iss !== 'accounts.google.com') {
    throw new Error(`minted Google ID token issuer is not Google: ${iss}`);
  }
  const aud = payload.aud;
  const audiences = Array.isArray(aud) ? aud.map(String) : [String(aud || '')];
  if (!audiences.includes(args.clientId)) {
    throw new Error(`minted Google ID token audience mismatch: ${audiences.join(', ')}`);
  }
  const sub = String(payload.sub || '').trim();
  if (!sub) throw new Error('minted Google ID token is missing sub');
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp * 1000 <= Date.now()) {
    throw new Error('minted Google ID token is already expired');
  }
  return {
    aud: audiences.join(','),
    sub,
    exp,
    email: optionalString(payload.email),
  };
}

function parseBase64UrlJson(segment, label) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    throw new Error(`minted Google ID token has invalid ${label}`);
  }
}

function optionalString(value) {
  const normalized = String(value || '').trim();
  return normalized || '';
}
