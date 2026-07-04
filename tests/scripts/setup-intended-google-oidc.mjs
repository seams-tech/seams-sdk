#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import {
  defaultEnvFile,
  defaultGoogleClientId,
  defaultGoogleProjectId,
  firstNonEmptyString,
  readEnvFile,
  repoRoot,
  resolveRepoPath,
  updateEnvFile,
} from './intended-google-oidc-env.mjs';

const defaultServiceAccountId = 'intended-oidc-token';
const iamCredentialsService = 'iamcredentials.googleapis.com';
const serviceAccountTokenCreatorRole = 'roles/iam.serviceAccountTokenCreator';

await main().catch(handleFatalError);

async function main() {
  const args = parseCliArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }

  const envFilePath = resolveRepoPath(args.envFile);
  const fileEnv = readEnvFile(envFilePath);
  const projectId = resolveProjectId(args, fileEnv);
  const clientId = resolveClientId(args, fileEnv);
  const clientSecret = resolveClientSecret(args, fileEnv);
  const serviceAccountEmail = resolveServiceAccountEmail(args, fileEnv, projectId);
  const activeAccount = readActiveGcloudAccount();
  const impersonationMember = iamMemberForGcloudAccount(activeAccount);

  enableIamCredentialsApi(projectId);
  ensureServiceAccount({ projectId, serviceAccountEmail });
  grantImpersonation({
    projectId,
    serviceAccountEmail,
    impersonationMember,
  });
  updateEnvFile(
    envFilePath,
    buildLocalGoogleOidcEnvUpdates({
      projectId,
      serviceAccountEmail,
      clientId,
      clientSecret,
    }),
  );

  console.log(`[intended-google-oidc] wrote ${path.relative(repoRoot, envFilePath)}`);
  console.log(`[intended-google-oidc] project=${projectId}`);
  console.log(`[intended-google-oidc] serviceAccount=${serviceAccountEmail}`);
  console.log(`[intended-google-oidc] impersonator=${impersonationMember}`);
  if (args.refresh) {
    refreshGoogleIdToken({ envFilePath, serviceAccountEmail, clientId });
  }
}

function handleFatalError(error) {
  console.error(`[intended-google-oidc] ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}

function printHelp() {
  console.log(`Usage:
  pnpm setup:intended-google-oidc

Options:
  --project-id <project-id>          Google project id. Defaults to seams-501403.
  --client-id <client-id>            Google OIDC audience/client id.
  --client-secret <client-secret>    Google OAuth client secret for local runtime env.
  --service-account <email-or-id>    Service account email or local account id.
  --service-account-id <id>          Local account id to create when --service-account is omitted.
  --env-file <path>                  Env file to update. Defaults to .env.intended.local.
  --no-refresh                       Skip minting SEAMS_INTENDED_GOOGLE_ID_TOKEN.
  --help                             Show this help.

Environment:
  SEAMS_INTENDED_GOOGLE_PROJECT_ID
  SEAMS_INTENDED_GOOGLE_CLIENT_ID
  SEAMS_INTENDED_GOOGLE_CLIENT_SECRET
  SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT
  SEAMS_INTENDED_ENV_FILE

The active gcloud account receives roles/iam.serviceAccountTokenCreator on the
test service account, then pnpm refresh:intended-google-token mints a one-hour
Google ID token for the intended Email OTP contracts.
`);
}

function parseCliArgs(argv) {
  const args = {
    projectId: '',
    clientId: '',
    clientSecret: '',
    serviceAccount: '',
    serviceAccountId: '',
    envFile: process.env.SEAMS_INTENDED_ENV_FILE || defaultEnvFile,
    refresh: true,
    help: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--') continue;
    if (arg === '--help' || arg === '-h') {
      args.help = true;
      continue;
    }
    if (arg === '--no-refresh') {
      args.refresh = false;
      continue;
    }
    if (arg === '--project-id') {
      args.projectId = requireNextCliValue(argv, index, '--project-id');
      index += 1;
      continue;
    }
    if (arg.startsWith('--project-id=')) {
      args.projectId = requireInlineCliValue(arg, '--project-id=');
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
    if (arg === '--client-secret') {
      args.clientSecret = requireNextCliValue(argv, index, '--client-secret');
      index += 1;
      continue;
    }
    if (arg.startsWith('--client-secret=')) {
      args.clientSecret = requireInlineCliValue(arg, '--client-secret=');
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
    if (arg === '--service-account-id') {
      args.serviceAccountId = requireNextCliValue(argv, index, '--service-account-id');
      index += 1;
      continue;
    }
    if (arg.startsWith('--service-account-id=')) {
      args.serviceAccountId = requireInlineCliValue(arg, '--service-account-id=');
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

function resolveProjectId(args, fileEnv) {
  return (
    firstNonEmptyString([
      args.projectId,
      process.env.SEAMS_INTENDED_GOOGLE_PROJECT_ID,
      process.env.GOOGLE_CLOUD_PROJECT,
      process.env.GCLOUD_PROJECT,
      fileEnv.SEAMS_INTENDED_GOOGLE_PROJECT_ID,
    ]) || defaultGoogleProjectId
  );
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

function resolveClientSecret(args, fileEnv) {
  return firstNonEmptyString([
    args.clientSecret,
    process.env.SEAMS_INTENDED_GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_OIDC_CLIENT_SECRET,
    fileEnv.SEAMS_INTENDED_GOOGLE_CLIENT_SECRET,
    fileEnv.GOOGLE_OIDC_CLIENT_SECRET,
  ]);
}

function resolveServiceAccountEmail(args, fileEnv, projectId) {
  const serviceAccount = firstNonEmptyString([
    args.serviceAccount,
    process.env.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    process.env.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT,
    fileEnv.SEAMS_INTENDED_GOOGLE_IMPERSONATE_SERVICE_ACCOUNT,
  ]);
  if (serviceAccount.includes('@')) return serviceAccount;
  const serviceAccountId = firstNonEmptyString([
    serviceAccount,
    args.serviceAccountId,
    process.env.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT_ID,
    fileEnv.SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT_ID,
  ]);
  return serviceAccountEmailForId(serviceAccountId || defaultServiceAccountId, projectId);
}

function serviceAccountEmailForId(serviceAccountId, projectId) {
  return `${serviceAccountId}@${projectId}.iam.gserviceaccount.com`;
}

function readActiveGcloudAccount() {
  const result = runGcloudCapture([
    'auth',
    'list',
    '--filter=status:ACTIVE',
    '--format=value(account)',
  ]);
  const accounts = result.stdout.split(/\r?\n/).map(trimString).filter(Boolean);
  if (accounts.length !== 1) {
    throw new Error('exactly one active gcloud account is required; run gcloud auth login');
  }
  return accounts[0];
}

function trimString(value) {
  return value.trim();
}

function iamMemberForGcloudAccount(account) {
  if (account.endsWith('.gserviceaccount.com')) return `serviceAccount:${account}`;
  return `user:${account}`;
}

function enableIamCredentialsApi(projectId) {
  runGcloudPassthrough([
    'services',
    'enable',
    iamCredentialsService,
    `--project=${projectId}`,
    '--quiet',
  ]);
}

function ensureServiceAccount(args) {
  const describe = runGcloudOptional([
    'iam',
    'service-accounts',
    'describe',
    args.serviceAccountEmail,
    `--project=${args.projectId}`,
  ]);
  if (describe.status === 0) return;

  runGcloudPassthrough([
    'iam',
    'service-accounts',
    'create',
    serviceAccountIdFromEmail(args.serviceAccountEmail),
    `--project=${args.projectId}`,
    '--display-name=Seams intended OIDC token minter',
    '--quiet',
  ]);
}

function serviceAccountIdFromEmail(serviceAccountEmail) {
  return serviceAccountEmail.split('@')[0];
}

function buildLocalGoogleOidcEnvUpdates(args) {
  const updates = {
    SEAMS_INTENDED_GOOGLE_PROJECT_ID: args.projectId,
    SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT: args.serviceAccountEmail,
    SEAMS_INTENDED_GOOGLE_CLIENT_ID: args.clientId,
    GOOGLE_OIDC_CLIENT_ID: args.clientId,
    SEAMS_INTENDED_MUTATION_FRESH_STARTUP: '1',
  };
  if (args.clientSecret) {
    updates.SEAMS_INTENDED_GOOGLE_CLIENT_SECRET = args.clientSecret;
    updates.GOOGLE_OIDC_CLIENT_SECRET = args.clientSecret;
  }
  return updates;
}

function grantImpersonation(args) {
  runGcloudPassthrough([
    'iam',
    'service-accounts',
    'add-iam-policy-binding',
    args.serviceAccountEmail,
    `--member=${args.impersonationMember}`,
    `--role=${serviceAccountTokenCreatorRole}`,
    `--project=${args.projectId}`,
    '--quiet',
  ]);
}

function refreshGoogleIdToken(args) {
  const result = spawnSync(
    process.execPath,
    [
      path.join(repoRoot, 'tests/scripts/refresh-intended-google-token.mjs'),
      '--service-account',
      args.serviceAccountEmail,
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
    throw new Error(
      `token refresh exited with ${String(result.status ?? 'unknown')}; IAM propagation can take a minute, then rerun pnpm refresh:intended-google-token`,
    );
  }
}

function runGcloudCapture(args) {
  const result = spawnSync('gcloud', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) {
    throw new Error(`gcloud failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`gcloud ${args.join(' ')} failed (${result.status}): ${result.stderr}`);
  }
  return {
    stdout: String(result.stdout || ''),
    stderr: String(result.stderr || ''),
  };
}

function runGcloudOptional(args) {
  const result = spawnSync('gcloud', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) {
    throw new Error(`gcloud failed to start: ${result.error.message}`);
  }
  return {
    status: result.status ?? 1,
    stdout: String(result.stdout || ''),
    stderr: String(result.stderr || ''),
  };
}

function runGcloudPassthrough(args) {
  console.log(`[intended-google-oidc] gcloud ${args.join(' ')}`);
  const result = spawnSync('gcloud', args, {
    cwd: repoRoot,
    env: process.env,
    stdio: 'inherit',
  });
  if (result.error) {
    throw new Error(`gcloud failed to start: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(`gcloud ${args.join(' ')} failed (${String(result.status ?? 'unknown')})`);
  }
}
