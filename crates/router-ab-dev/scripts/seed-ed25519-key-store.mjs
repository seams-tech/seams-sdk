#!/usr/bin/env node
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { Pool } from 'pg';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const webServerEnvPath = path.join(repoRoot, 'apps/web-server/.env');

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});

async function main() {
  loadEnvFile(webServerEnvPath);
  const postgresUrl = requiredEnv('POSTGRES_URL');
  const seed = parseSeed(await readStdin());
  const relayerVerifyingShareB64u = await deriveRelayerVerifyingShareB64u(
    seed.relayerSigningShareB64u,
  );
  const record = {
    nearAccountId: seed.nearAccountId,
    rpId: seed.rpId,
    publicKey: seed.publicKey,
    relayerSigningShareB64u: seed.relayerSigningShareB64u,
    relayerVerifyingShareB64u,
    keyVersion: seed.keyVersion,
    recoveryExportCapable: seed.recoveryExportCapable,
  };
  const namespace = resolveEd25519KeyStoreNamespace(process.env);
  const pool = new Pool({ connectionString: postgresUrl });
  try {
    await pool.query(
      `
        INSERT INTO threshold_ed25519_keys (namespace, relayer_key_id, record_json)
        VALUES ($1, $2, $3::jsonb)
        ON CONFLICT (namespace, relayer_key_id)
        DO UPDATE SET record_json = EXCLUDED.record_json
      `,
      [namespace, seed.relayerKeyId, JSON.stringify(record)],
    );
  } finally {
    await pool.end();
  }
  console.log(
    `[router-ab-local-seed] threshold_ed25519_keys namespace=${namespace || '<empty>'} relayerKeyId=${seed.relayerKeyId}`,
  );
}

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  const source = fs.readFileSync(filePath, 'utf8');
  for (const line of source.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const equals = trimmed.indexOf('=');
    if (equals <= 0) continue;
    const key = trimmed.slice(0, equals).trim();
    if (!key || Object.prototype.hasOwnProperty.call(process.env, key)) continue;
    process.env[key] = unquoteEnvValue(trimmed.slice(equals + 1).trim());
  }
}

function unquoteEnvValue(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}

function requiredEnv(key) {
  const value = String(process.env[key] || '').trim();
  if (!value) {
    throw new Error(
      `Missing ${key}; local Router A/B Ed25519 key-store seeding must target the same Postgres store as apps/web-server`,
    );
  }
  return value;
}

function resolveEd25519KeyStoreNamespace(env) {
  const explicit = String(env.THRESHOLD_ED25519_KEYSTORE_PREFIX || '').trim();
  if (explicit) return explicit;
  const base = String(env.THRESHOLD_PREFIX || '').trim();
  if (!base) return '';
  const prefix = base.endsWith(':') ? base : `${base}:`;
  return `${prefix}key:`;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    process.stdin.on('error', reject);
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

async function deriveRelayerVerifyingShareB64u(signingShareB64u) {
  const modulePath = path.join(
    repoRoot,
    'packages/sdk-server-ts/dist/esm/core/ThresholdService/ed25519HssWasm.js',
  );
  const { deriveThresholdEd25519VerifyingShareFromSigningShare } = await import(
    pathToFileURL(modulePath).href
  );
  const derived = await deriveThresholdEd25519VerifyingShareFromSigningShare({ signingShareB64u });
  return requiredString(derived?.verifyingShareB64u, 'derived.relayerVerifyingShareB64u');
}

function parseSeed(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid Ed25519 key-store seed JSON: ${errorMessage(error)}`);
  }
  if (!isObject(parsed)) {
    throw new Error('Ed25519 key-store seed must be an object');
  }
  const relayerKeyId = requiredString(parsed.relayerKeyId, 'relayerKeyId');
  const normalized = {
    relayerKeyId,
    nearAccountId: requiredString(parsed.nearAccountId, 'nearAccountId'),
    rpId: requiredString(parsed.rpId, 'rpId'),
    publicKey: requiredString(parsed.publicKey, 'publicKey'),
    relayerSigningShareB64u: requiredString(
      parsed.relayerSigningShareB64u,
      'relayerSigningShareB64u',
    ),
    keyVersion: requiredString(parsed.keyVersion, 'keyVersion'),
    recoveryExportCapable: parsed.recoveryExportCapable === true,
  };
  if (!normalized.recoveryExportCapable) {
    throw new Error('recoveryExportCapable must be true');
  }
  if (normalized.publicKey !== relayerKeyId) {
    throw new Error('publicKey must match relayerKeyId');
  }
  return normalized;
}

function isObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredString(value, field) {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function errorMessage(error) {
  return error && typeof error === 'object' && 'message' in error
    ? String(error.message || '')
    : String(error || '');
}
