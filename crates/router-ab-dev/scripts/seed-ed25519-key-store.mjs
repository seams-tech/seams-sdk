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
    walletId: seed.walletId,
    nearAccountId: seed.nearAccountId,
    nearEd25519SigningKeyId: seed.nearEd25519SigningKeyId,
    rpId: seed.rpId,
    publicKey: seed.publicKey,
    relayerSigningShareB64u: seed.relayerSigningShareB64u,
    relayerVerifyingShareB64u,
    keyVersion: seed.keyVersion,
    recoveryExportCapable: seed.recoveryExportCapable,
  };
  const walletSessionRecord = {
    expiresAtMs: seed.thresholdExpiresAtMs,
    relayerKeyId: seed.relayerKeyId,
    userId: seed.walletId,
    walletId: seed.walletId,
    nearAccountId: seed.nearAccountId,
    nearEd25519SigningKeyId: seed.nearEd25519SigningKeyId,
    rpId: seed.rpId,
    participantIds: seed.participantIds,
  };
  const walletBudgetSessionId = walletSigningBudgetSessionId(seed.signingGrantId);
  const walletBudgetSessionRecord = {
    kind: 'wallet_signing_budget_session',
    expiresAtMs: seed.thresholdExpiresAtMs,
    relayerKeyId: 'wallet-signing-budget',
    walletId: seed.walletId,
    budgetScope: { kind: 'passkey_rp', rpId: seed.rpId },
    binding: { curve: 'ed25519', thresholdSessionId: seed.thresholdSessionId },
    participantIds: seed.participantIds,
  };
  const keyNamespace = resolveEd25519KeyStoreNamespace(process.env);
  const walletSessionNamespace = resolveEd25519WalletSessionNamespace(process.env);
  const walletBudgetNamespace = resolveWalletSigningBudgetSessionNamespace(process.env);
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
        WHERE namespace = $1 AND session_id = $2
      `,
      [walletSessionNamespace, routerAbEd25519PrepareReplayScope(seed.thresholdSessionId)],
    );
    await pool.query(
      `
        INSERT INTO threshold_ed25519_keys (namespace, relayer_key_id, record_json)
        VALUES ($1, $2, $3::jsonb)
        ON CONFLICT (namespace, relayer_key_id)
        DO UPDATE SET record_json = EXCLUDED.record_json
      `,
      [keyNamespace, seed.relayerKeyId, JSON.stringify(record)],
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
  } finally {
    await pool.query('ROLLBACK').catch(() => undefined);
    await pool.end();
  }
  console.log(
    `[router-ab-local-seed] threshold_ed25519_keys namespace=${keyNamespace || '<empty>'} walletSessionNamespace=${walletSessionNamespace || '<empty>'} walletBudgetNamespace=${walletBudgetNamespace || '<empty>'} relayerKeyId=${seed.relayerKeyId}`,
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
  return resolveEd25519NamespaceFromBase(env.THRESHOLD_PREFIX, 'key');
}

function resolveEd25519WalletSessionNamespace(env) {
  const explicit = String(env.THRESHOLD_ED25519_WALLET_SESSION_PREFIX || '').trim();
  if (explicit) return explicit;
  return resolveEd25519NamespaceFromBase(env.THRESHOLD_PREFIX, 'wallet-session');
}

function resolveWalletSigningBudgetSessionNamespace(env) {
  const explicit = String(env.THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX || '').trim();
  if (explicit) return explicit;
  const base = resolveEd25519NamespaceFromBase(env.THRESHOLD_PREFIX, 'wallet-session');
  return base ? `${base}budget:` : 'w3a:threshold-wallet-budget:sess:';
}

function resolveEd25519NamespaceFromBase(basePrefix, kind) {
  const base = String(basePrefix || '').trim();
  if (!base) return '';
  const prefix = base.endsWith(':') ? base : `${base}:`;
  return `${prefix}threshold-ed25519:${kind}:`;
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
    walletId: requiredString(parsed.walletId, 'walletId'),
    nearAccountId: requiredString(parsed.nearAccountId, 'nearAccountId'),
    nearEd25519SigningKeyId: requiredString(
      parsed.nearEd25519SigningKeyId,
      'nearEd25519SigningKeyId',
    ),
    rpId: requiredString(parsed.rpId, 'rpId'),
    thresholdSessionId: requiredString(parsed.thresholdSessionId, 'thresholdSessionId'),
    signingGrantId: requiredString(parsed.signingGrantId, 'signingGrantId'),
    publicKey: requiredString(parsed.publicKey, 'publicKey'),
    relayerSigningShareB64u: requiredString(
      parsed.relayerSigningShareB64u,
      'relayerSigningShareB64u',
    ),
    keyVersion: requiredString(parsed.keyVersion, 'keyVersion'),
    thresholdExpiresAtMs: requiredPositiveSafeInteger(
      parsed.thresholdExpiresAtMs,
      'thresholdExpiresAtMs',
    ),
    participantIds: requiredParticipantIds(parsed.participantIds),
    remainingUses: requiredPositiveSafeInteger(parsed.remainingUses, 'remainingUses'),
    recoveryExportCapable: parsed.recoveryExportCapable === true,
  };
  if (!normalized.recoveryExportCapable) {
    throw new Error('recoveryExportCapable must be true');
  }
  if (normalized.publicKey !== relayerKeyId) {
    throw new Error('publicKey must match relayerKeyId');
  }
  if (normalized.nearEd25519SigningKeyId !== relayerKeyId) {
    throw new Error('nearEd25519SigningKeyId must match relayerKeyId');
  }
  return normalized;
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

function routerAbEd25519PrepareReplayScope(thresholdSessionId) {
  return `router-ab-normal-signing:ed25519:prepare:${requiredString(
    thresholdSessionId,
    'thresholdSessionId',
  )}`;
}

function isObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function requiredString(value, field) {
  const normalized = String(value || '').trim();
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
  if (unique.size !== ids.length) {
    throw new Error('participantIds must be unique');
  }
  return ids;
}

function errorMessage(error) {
  return error && typeof error === 'object' && 'message' in error
    ? String(error.message || '')
    : String(error || '');
}
