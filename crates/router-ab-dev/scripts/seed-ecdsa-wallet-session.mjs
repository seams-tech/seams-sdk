#!/usr/bin/env node
import { Pool } from 'pg';
import { readFileSync } from 'node:fs';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = fileURLToPath(new URL('../../..', import.meta.url));
const webServerEnvPath = path.join(repoRoot, 'apps/web-server/.env');

async function main() {
  loadEnvFile(webServerEnvPath);
  const seed = parseSeed(readStdin());
  const postgresUrl = requiredEnv('POSTGRES_URL');
  const walletSessionNamespace = resolveEcdsaWalletSessionNamespace(process.env);
  const walletBudgetNamespace = resolveWalletSigningBudgetSessionNamespace(process.env);
  const walletBudgetSessionId = walletSigningBudgetSessionId(seed.signingGrantId);
  const walletSessionRecord = {
    expiresAtMs: seed.thresholdExpiresAtMs,
    relayerKeyId: seed.relayerKeyId,
    walletId: seed.walletId,
    walletKeyId: seed.walletKeyId,
    ecdsaThresholdKeyId: seed.ecdsaThresholdKeyId,
    signingRootId: seed.signingRootId,
    signingRootVersion: seed.signingRootVersion,
    walletKeyVersion: seed.walletKeyVersion,
    derivationVersion: seed.derivationVersion,
    participantIds: seed.participantIds,
  };
  const walletBudgetSessionRecord = {
    kind: 'wallet_signing_budget_session',
    expiresAtMs: seed.thresholdExpiresAtMs,
    relayerKeyId: 'wallet-signing-budget',
    walletId: seed.walletId,
    budgetScope: { kind: 'wallet_key', walletKeyId: seed.walletKeyId },
    binding: { curve: 'ecdsa', thresholdSessionId: seed.thresholdSessionId },
    participantIds: seed.participantIds,
  };
  const pool = new Pool({ connectionString: postgresUrl });
  try {
    await pool.query('BEGIN');
    await pool.query(
      `
        DELETE FROM threshold_wallet_session_budget_reservations
        WHERE namespace = $1 AND session_id = $2
      `,
      [walletBudgetNamespace, walletBudgetSessionId],
    );
    await pool.query(
      `
        DELETE FROM threshold_wallet_session_consumptions
        WHERE namespace = $1 AND session_id = $2 AND idempotency_key = $3
      `,
      [
        walletSessionNamespace,
        routerAbEcdsaPrepareReplayScope(seed.thresholdSessionId),
        seed.prepareRequestId,
      ],
    );
    await upsertWalletSession({
      pool,
      namespace: walletSessionNamespace,
      sessionId: seed.thresholdSessionId,
      record: walletSessionRecord,
      expiresAtMs: seed.thresholdExpiresAtMs,
      remainingUses: seed.remainingUses,
    });
    await upsertWalletSession({
      pool,
      namespace: walletBudgetNamespace,
      sessionId: walletBudgetSessionId,
      record: walletBudgetSessionRecord,
      expiresAtMs: seed.thresholdExpiresAtMs,
      remainingUses: seed.remainingUses,
    });
    await pool.query('COMMIT');
  } catch (error) {
    await pool.query('ROLLBACK').catch(() => undefined);
    throw error;
  } finally {
    await pool.end();
  }
  console.log(
    `[router-ab-local-seed] threshold_ecdsa walletSessionNamespace=${walletSessionNamespace || '<empty>'} walletBudgetNamespace=${walletBudgetNamespace || '<empty>'} walletId=${seed.walletId} walletKeyId=${seed.walletKeyId}`,
  );
}

function requiredEnv(key) {
  const value = String(process.env[key] || '').trim();
  if (!value) {
    throw new Error(
      `Missing ${key}; local Router A/B ECDSA wallet-session seeding must target the same Postgres store as apps/web-server`,
    );
  }
  return value;
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

function resolveEcdsaWalletSessionNamespace(env) {
  const explicit = String(env.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX || '').trim();
  if (explicit) return ensureTrailingColon(explicit);
  const base = String(env.THRESHOLD_PREFIX || '').trim();
  if (!base) return 'w3a:threshold-ecdsa:wallet-session:';
  return `${ensureTrailingColon(base)}threshold-ecdsa:wallet-session:`;
}

function resolveWalletSigningBudgetSessionNamespace(env) {
  const explicit = String(env.THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX || '').trim();
  if (explicit) return ensureTrailingColon(explicit);
  const base = String(env.THRESHOLD_PREFIX || '').trim();
  if (!base) return 'w3a:threshold-wallet-budget:sess:';
  return `${ensureTrailingColon(base)}budget:`;
}

function ensureTrailingColon(value) {
  const normalized = String(value || '').trim();
  return normalized.endsWith(':') ? normalized : `${normalized}:`;
}

function readStdin() {
  return readFileSync(0, 'utf8');
}

function parseSeed(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`invalid seed JSON: ${errorMessage(error)}`);
  }
  if (!isObject(parsed)) throw new Error('seed JSON must be an object');
  return {
    walletId: requiredString(parsed.walletId, 'walletId'),
    walletKeyId: requiredString(parsed.walletKeyId, 'walletKeyId'),
    ecdsaThresholdKeyId: requiredString(parsed.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
    signingRootId: requiredString(parsed.signingRootId, 'signingRootId'),
    signingRootVersion: requiredString(parsed.signingRootVersion, 'signingRootVersion'),
    walletKeyVersion: requiredString(parsed.walletKeyVersion, 'walletKeyVersion'),
    derivationVersion: requiredPositiveSafeInteger(parsed.derivationVersion, 'derivationVersion'),
    relayerKeyId: requiredString(parsed.relayerKeyId, 'relayerKeyId'),
    thresholdSessionId: requiredString(parsed.thresholdSessionId, 'thresholdSessionId'),
    prepareRequestId: requiredString(parsed.prepareRequestId, 'prepareRequestId'),
    signingGrantId: requiredString(parsed.signingGrantId, 'signingGrantId'),
    thresholdExpiresAtMs: requiredPositiveSafeInteger(
      parsed.thresholdExpiresAtMs,
      'thresholdExpiresAtMs',
    ),
    participantIds: requiredParticipantIds(parsed.participantIds),
    remainingUses: requiredPositiveSafeInteger(parsed.remainingUses, 'remainingUses'),
  };
}

async function upsertWalletSession(input) {
  await input.pool.query(
    `
      INSERT INTO threshold_ed25519_sessions
        (namespace, kind, session_id, record_json, expires_at_ms, remaining_uses)
      VALUES ($1, $2, $3, $4::jsonb, $5, $6)
      ON CONFLICT (namespace, kind, session_id)
      DO UPDATE SET
        record_json = EXCLUDED.record_json,
        expires_at_ms = EXCLUDED.expires_at_ms,
        remaining_uses = EXCLUDED.remaining_uses
    `,
    [
      input.namespace,
      'wallet_session',
      input.sessionId,
      JSON.stringify(input.record),
      input.expiresAtMs,
      input.remainingUses,
    ],
  );
}

function walletSigningBudgetSessionId(signingGrantId) {
  return `wallet-signing:${requiredString(signingGrantId, 'signingGrantId')}`;
}

function routerAbEcdsaPrepareReplayScope(thresholdSessionId) {
  return `router-ab-normal-signing:ecdsa-hss:prepare:${requiredString(
    thresholdSessionId,
    'thresholdSessionId',
  )}`;
}

function isObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredString(value, field) {
  if (typeof value !== 'string') throw new Error(`${field} must be a string`);
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function requiredPositiveSafeInteger(value, field) {
  const normalized = Number(value);
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return normalized;
}

function requiredParticipantIds(value) {
  if (!Array.isArray(value) || value.length < 2) {
    throw new Error('participantIds must contain at least two participants');
  }
  const ids = value.map((entry) => requiredPositiveSafeInteger(entry, 'participantIds entry'));
  const unique = new Set(ids);
  if (unique.size !== ids.length) throw new Error('participantIds must be unique');
  return ids;
}

function errorMessage(error) {
  return error && typeof error === 'object' && 'message' in error
    ? String(error.message || '')
    : String(error || '');
}

main().catch((error) => {
  console.error(errorMessage(error));
  process.exit(1);
});
