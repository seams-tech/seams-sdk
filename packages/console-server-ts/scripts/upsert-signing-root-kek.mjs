import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { parseGatewayDeploymentPlan } from './gateway-deployment-config.mjs';

const CLOUDFLARE_ID_PATTERN = /^[0-9a-f]{32}$/;
const MAX_SECRET_BYTES = 1024;

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const plan = parseGatewayDeploymentPlan(fs.readFileSync(options.plan, 'utf8'));
  const credentials = readCredentials();
  const secretValue = requireSecretValue();
  const existingSecret = await findSecret({
    credentials,
    storeId: plan.signingRootSecret.storeId,
    secretName: plan.signingRootSecret.secretName,
  });
  if (existingSecret) {
    await updateSecret({
      credentials,
      storeId: plan.signingRootSecret.storeId,
      secretId: existingSecret.id,
      secretValue,
    });
    process.stdout.write(`Updated Secrets Store secret ${plan.signingRootSecret.secretName}\n`);
    return;
  }
  await createSecret({
    credentials,
    storeId: plan.signingRootSecret.storeId,
    secretName: plan.signingRootSecret.secretName,
    secretValue,
  });
  process.stdout.write(`Created Secrets Store secret ${plan.signingRootSecret.secretName}\n`);
}

function parseArguments(args) {
  let plan = '';
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--plan') {
      plan = requireArgumentValue(args, index, argument);
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${argument}`);
  }
  if (!plan) throw new Error('--plan is required');
  return { plan: path.resolve(process.cwd(), plan) };
}

function requireArgumentValue(args, index, name) {
  const value = String(args[index + 1] || '').trim();
  if (!value) throw new Error(`${name} requires a value`);
  return value;
}

function readCredentials() {
  const apiToken = requireEnv('CLOUDFLARE_API_TOKEN');
  const accountId = requireEnv('CLOUDFLARE_ACCOUNT_ID');
  if (!CLOUDFLARE_ID_PATTERN.test(accountId)) {
    throw new Error('CLOUDFLARE_ACCOUNT_ID must be a 32-character lowercase hexadecimal ID');
  }
  return { apiToken, accountId };
}

function requireSecretValue() {
  const value = requireEnv('SIGNING_ROOT_KEK_VALUE');
  const byteLength = Buffer.byteLength(value, 'utf8');
  if (byteLength > MAX_SECRET_BYTES) {
    throw new Error(`SIGNING_ROOT_KEK_VALUE must not exceed ${MAX_SECRET_BYTES} bytes`);
  }
  return value;
}

function requireEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

async function findSecret(input) {
  const endpoint = secretsEndpoint(input.credentials, input.storeId);
  endpoint.searchParams.set('page', '1');
  endpoint.searchParams.set('per_page', '100');
  const response = await cloudflareRequest(input.credentials, endpoint, {
    method: 'GET',
  });
  for (const secret of requireResultArray(response, 'list Secrets Store secrets')) {
    if (secret?.name !== input.secretName || secret?.status === 'deleted') continue;
    const id = String(secret.id || '').trim();
    if (!CLOUDFLARE_ID_PATTERN.test(id)) {
      throw new Error(`Secrets Store returned an invalid ID for ${input.secretName}`);
    }
    return { id };
  }
  return null;
}

async function createSecret(input) {
  const endpoint = secretsEndpoint(input.credentials, input.storeId);
  const response = await cloudflareRequest(input.credentials, endpoint, {
    method: 'POST',
    body: JSON.stringify([
      {
        name: input.secretName,
        value: input.secretValue,
        scopes: ['workers'],
        comment: 'Gateway signing root KEK',
      },
    ]),
  });
  requireResultArray(response, 'create Secrets Store secret');
}

async function updateSecret(input) {
  const endpoint = secretsEndpoint(input.credentials, input.storeId);
  endpoint.pathname = `${endpoint.pathname}/${encodeURIComponent(input.secretId)}`;
  const response = await cloudflareRequest(input.credentials, endpoint, {
    method: 'PATCH',
    body: JSON.stringify({
      value: input.secretValue,
      scopes: ['workers'],
      comment: 'Gateway signing root KEK',
    }),
  });
  requireSuccessfulResponse(response, 'update Secrets Store secret');
}

function secretsEndpoint(credentials, storeId) {
  return new URL(
    `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(credentials.accountId)}/secrets_store/stores/${encodeURIComponent(storeId)}/secrets`,
  );
}

async function cloudflareRequest(credentials, endpoint, init) {
  const response = await fetch(endpoint, {
    ...init,
    headers: {
      Authorization: `Bearer ${credentials.apiToken}`,
      'Content-Type': 'application/json',
    },
  });
  let body;
  try {
    body = await response.json();
  } catch {
    throw new Error(`Cloudflare API returned non-JSON HTTP ${response.status}`);
  }
  if (!response.ok || body?.success !== true) {
    const messages = Array.isArray(body?.errors)
      ? body.errors.map(formatCloudflareError).join('; ')
      : '';
    throw new Error(`Cloudflare API HTTP ${response.status}${messages ? `: ${messages}` : ''}`);
  }
  return body;
}

function formatCloudflareError(error) {
  const code = String(error?.code || '').trim();
  const message = String(error?.message || '').trim();
  return [code, message].filter(Boolean).join(' ');
}

function requireResultArray(response, operation) {
  requireSuccessfulResponse(response, operation);
  if (!Array.isArray(response.result)) {
    throw new Error(`Cloudflare API ${operation} response must contain a result array`);
  }
  return response.result;
}

function requireSuccessfulResponse(response, operation) {
  if (!response || response.success !== true) {
    throw new Error(`Cloudflare API failed to ${operation}`);
  }
}

main().catch(handleFatalError);

function handleFatalError(error) {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
}
