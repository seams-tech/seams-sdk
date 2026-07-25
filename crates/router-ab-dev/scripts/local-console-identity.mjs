import { randomInt } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const LOCAL_CONSOLE_ORGANIZATION_ID_PATTERN = /^org_[a-z0-9]{12}$/;
const LOCAL_CONSOLE_ORGANIZATION_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';
const LOCAL_CONSOLE_IDENTITY_RELATIVE_PATH = '.runtime/local-console/identity.json';

export function parseLocalConsoleOrganizationId(value) {
  const organizationId = String(value || '').trim();
  if (!LOCAL_CONSOLE_ORGANIZATION_ID_PATTERN.test(organizationId)) {
    throw new Error('local console organization ID must match org_[a-z0-9]{12}');
  }
  return organizationId;
}

export function resolveLocalConsoleOrganizationId(input) {
  const localEnvRoot = path.resolve(input.localEnvRoot);
  const identityPath = path.join(localEnvRoot, LOCAL_CONSOLE_IDENTITY_RELATIVE_PATH);
  if (existsSync(identityPath)) {
    return parsePersistedLocalConsoleOrganizationId(identityPath);
  }

  const organizationId = generateLocalConsoleOrganizationId();
  mkdirSync(path.dirname(identityPath), { recursive: true });
  persistLocalConsoleOrganizationId(identityPath, organizationId);
  chmodSync(identityPath, 0o600);
  return parsePersistedLocalConsoleOrganizationId(identityPath);
}

function generateLocalConsoleOrganizationId() {
  let suffix = '';
  for (let index = 0; index < 12; index += 1) {
    suffix += LOCAL_CONSOLE_ORGANIZATION_ID_ALPHABET[randomInt(36)];
  }
  return `org_${suffix}`;
}

function persistLocalConsoleOrganizationId(identityPath, organizationId) {
  try {
    writeFileSync(identityPath, `${JSON.stringify({ organizationId }, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
      flag: 'wx',
    });
  } catch (error) {
    if (!error || typeof error !== 'object' || error.code !== 'EEXIST') throw error;
  }
}

function parsePersistedLocalConsoleOrganizationId(identityPath) {
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(identityPath, 'utf8'));
  } catch {
    throw new Error(`local console identity is invalid: ${identityPath}`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`local console identity is invalid: ${identityPath}`);
  }
  return parseLocalConsoleOrganizationId(parsed.organizationId);
}
