import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const defaultEnvFile = '.env.local';
export const defaultGoogleProjectId = 'seams-501403';
export const defaultGoogleClientId =
  '971053349716-2ck8cp6ucohvkd075aebdtv9jskla2b5.apps.googleusercontent.com';
export const defaultGoogleTokenMinimumTtlSeconds = 20 * 60;

const defaultEnvFileHeader = [
  '# Canonical local environment for the Seams frontend, gateway, workers, and tests.',
  '# Google OIDC values may be updated by the intended-behaviour setup scripts.',
];

export function resolveRepoPath(inputPath) {
  const resolved = path.resolve(repoRoot, inputPath || defaultEnvFile);
  const relative = path.relative(repoRoot, resolved);
  if (relative.startsWith('..') || path.isAbsolute(relative)) {
    throw new Error(`env file must stay inside the repository: ${inputPath}`);
  }
  return resolved;
}

export function readEnvFile(envFilePath) {
  if (!fs.existsSync(envFilePath)) return {};
  const vars = {};
  const source = fs.readFileSync(envFilePath, 'utf8');
  for (const line of source.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (!match) continue;
    vars[match[1]] = unquoteEnvValue(match[2].trim());
  }
  return vars;
}

export function updateEnvFile(envFilePath, updates) {
  const existingLines = fs.existsSync(envFilePath)
    ? fs.readFileSync(envFilePath, 'utf8').split(/\r?\n/)
    : defaultEnvFileHeader;
  const updateKeys = new Set(Object.keys(updates));
  const writtenKeys = new Set();
  const lines = [];

  for (const line of existingLines) {
    const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)=/);
    if (!match || !updateKeys.has(match[1])) {
      lines.push(line);
      continue;
    }
    if (writtenKeys.has(match[1])) continue;
    lines.push(`${match[1]}=${formatEnvValue(updates[match[1]])}`);
    writtenKeys.add(match[1]);
  }
  for (const key of updateKeys) {
    if (writtenKeys.has(key)) continue;
    lines.push(`${key}=${formatEnvValue(updates[key])}`);
  }
  const output = `${lines.filter(keepOutputLine).join('\n')}\n`;
  fs.writeFileSync(envFilePath, output, { mode: 0o600 });
  fs.chmodSync(envFilePath, 0o600);
}

export function firstNonEmptyString(values) {
  for (const value of values) {
    const normalized = String(value || '').trim();
    if (normalized) return normalized;
  }
  return '';
}

export function resolveGoogleClientId({
  explicitClientId = '',
  processEnv = process.env,
  fileEnv = {},
} = {}) {
  return (
    firstNonEmptyString([
      explicitClientId,
      processEnv.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      processEnv.GOOGLE_OIDC_CLIENT_ID,
      fileEnv.SEAMS_INTENDED_GOOGLE_CLIENT_ID,
      fileEnv.GOOGLE_OIDC_CLIENT_ID,
    ]) || defaultGoogleClientId
  );
}

export function describeUsableGoogleIdToken({
  token,
  clientId = defaultGoogleClientId,
  minimumTtlSeconds = defaultGoogleTokenMinimumTtlSeconds,
  nowMs = Date.now(),
}) {
  const normalizedToken = firstNonEmptyString([token]);
  if (!normalizedToken) return { status: 'unusable', reason: 'missing' };
  const segments = normalizedToken.split('.');
  if (segments.length !== 3) return { status: 'unusable', reason: 'not a compact JWT' };
  const payload = parseTokenPayload(segments[1]);
  if (!isTokenPayload(payload)) return { status: 'unusable', reason: 'not decodable' };
  const aud = payload.aud;
  const audiences = Array.isArray(aud) ? aud.map(String) : [String(aud || '')];
  if (!audiences.includes(clientId)) {
    return { status: 'unusable', reason: 'for a different audience' };
  }
  const exp = Number(payload.exp);
  if (!Number.isFinite(exp)) return { status: 'unusable', reason: 'missing exp' };
  const minimumExpiryMs = nowMs + minimumTtlSeconds * 1000;
  if (exp * 1000 <= minimumExpiryMs) {
    return { status: 'unusable', reason: 'expired or near expiry' };
  }
  return {
    status: 'usable',
    expiresAtIso: new Date(exp * 1000).toISOString(),
  };
}

export function resolveGoogleIdToken({
  processToken = '',
  fileToken = '',
  clientId = defaultGoogleClientId,
  minimumTtlSeconds = defaultGoogleTokenMinimumTtlSeconds,
  nowMs = Date.now(),
} = {}) {
  const inheritedToken = firstNonEmptyString([processToken]);
  const envFileToken = firstNonEmptyString([fileToken]);
  const inheritedStatus = describeUsableGoogleIdToken({
    token: inheritedToken,
    clientId,
    minimumTtlSeconds,
    nowMs,
  });
  if (inheritedStatus.status === 'usable') return inheritedToken;

  const envFileStatus = describeUsableGoogleIdToken({
    token: envFileToken,
    clientId,
    minimumTtlSeconds,
    nowMs,
  });
  if (envFileStatus.status === 'usable') return envFileToken;

  return firstNonEmptyString([inheritedToken, envFileToken]);
}

function keepOutputLine(line, index, all) {
  return line || index < all.length - 1;
}

function unquoteEnvValue(value) {
  if (isQuotedEnvValue(value)) return value.slice(1, -1);
  return value;
}

function isQuotedEnvValue(value) {
  return (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  );
}

function parseTokenPayload(segment) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    return undefined;
  }
}

function isTokenPayload(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function formatEnvValue(value) {
  const normalized = String(value || '');
  if (/^[A-Za-z0-9_./:@+=,-]+$/.test(normalized)) return normalized;
  return JSON.stringify(normalized);
}
