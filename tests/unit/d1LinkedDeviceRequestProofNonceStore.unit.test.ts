import { expect, test } from '@playwright/test';
import { parseLinkDeviceSessionId } from '@shared/signing-lanes/ids';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  D1LinkedDeviceRequestProofNonceStoreV1,
  type D1LinkedDeviceSessionScopeV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1/deviceLinking';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  type TemporaryD1Database,
} from '../helpers/sqliteD1';

const scope: D1LinkedDeviceSessionScopeV1 = {
  namespace: 'signer',
  orgId: 'org_proof_nonce_test',
  projectId: 'project_proof_nonce_test',
  envId: 'env_proof_nonce_test',
};
const linkSessionId = parseLinkDeviceSessionId('link-session:proof-nonce').value;
const nonce = base64UrlEncode(new Uint8Array(32).fill(1));
const digest = parseDigestB64u(base64UrlEncode(new Uint8Array(32).fill(2)));

let temporary: TemporaryD1Database | undefined;

test.afterEach(() => {
  if (temporary) cleanupTemporaryD1Database(temporary.tempDir);
  temporary = undefined;
});
test('consumes a proof nonce atomically and classifies exact duplicates as replay', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const store = new D1LinkedDeviceRequestProofNonceStoreV1({ database: temporary.database, scope });
  const input = {
    linkSessionId,
    requestNonceB64u: nonce,
    proofDigestB64u: digest,
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
    consumedAtMs: 1_100,
  } as const;
  await expect(store.consumeRequestProofNonceV1(input)).resolves.toEqual({ outcome: 'consumed' });
  await expect(
    store.consumeRequestProofNonceV1({ ...input, proofDigestB64u: digest }),
  ).resolves.toEqual({
    outcome: 'already_used',
  });
});

test('rejects a tampered durable nonce row instead of treating it as replay', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const store = new D1LinkedDeviceRequestProofNonceStoreV1({ database: temporary.database, scope });
  const input = {
    linkSessionId,
    requestNonceB64u: nonce,
    proofDigestB64u: digest,
    issuedAtMs: 1_000,
    expiresAtMs: 2_000,
    consumedAtMs: 1_100,
  } as const;
  await store.consumeRequestProofNonceV1(input);
  await temporary.database
    .prepare(
      `UPDATE linked_device_request_proof_nonces
          SET proof_digest_b64u = ?
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ? AND request_nonce_b64u = ?`,
    )
    .bind(
      'tampered',
      scope.namespace,
      scope.orgId,
      scope.projectId,
      scope.envId,
      String(linkSessionId),
      nonce,
    )
    .run();
  await expect(store.consumeRequestProofNonceV1(input)).rejects.toThrow(
    'proof_digest_b64u is invalid',
  );
});

test('prunes expired rows in a bounded, scoped batch while retaining live nonces', async () => {
  temporary = createTemporaryD1Database();
  await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-signer'));
  const store = new D1LinkedDeviceRequestProofNonceStoreV1({ database: temporary.database, scope });
  const insert = temporary.database.prepare(
    `INSERT INTO linked_device_request_proof_nonces (
       namespace, org_id, project_id, env_id,
       link_session_id, request_nonce_b64u, proof_digest_b64u,
       issued_at_ms, expires_at_ms, consumed_at_ms
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  );
  for (let index = 0; index < 65; index += 1) {
    const cleanupSessionId = parseLinkDeviceSessionId(
      `link-session:proof-nonce-cleanup-${index}`,
    ).value;
    await insert
      .bind(
        ...Object.values(scope),
        String(cleanupSessionId),
        base64UrlEncode(new Uint8Array(32).fill(index + 3)),
        digest,
        1,
        10 + index,
        2,
      )
      .run();
  }
  const liveSessionId = parseLinkDeviceSessionId('link-session:proof-nonce-live').value;
  const liveNonce = base64UrlEncode(new Uint8Array(32).fill(99));
  await insert
    .bind(...Object.values(scope), String(liveSessionId), liveNonce, digest, 1, 1_000_000, 2)
    .run();
  const otherScope = {
    ...scope,
    orgId: 'org_proof_nonce_other_scope',
  } as const;
  const otherSessionId = parseLinkDeviceSessionId('link-session:proof-nonce-other').value;
  await insert
    .bind(
      ...Object.values(otherScope),
      String(otherSessionId),
      base64UrlEncode(new Uint8Array(32).fill(100)),
      digest,
      1,
      10,
      2,
    )
    .run();

  const input = {
    linkSessionId: parseLinkDeviceSessionId('link-session:proof-nonce-cleanup-request').value,
    requestNonceB64u: base64UrlEncode(new Uint8Array(32).fill(101)),
    proofDigestB64u: digest,
    issuedAtMs: 90_000,
    expiresAtMs: 200_000,
    consumedAtMs: 100_000,
  } as const;
  await expect(store.consumeRequestProofNonceV1(input)).resolves.toEqual({ outcome: 'consumed' });

  const scopedExpired = await temporary.database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM linked_device_request_proof_nonces
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND expires_at_ms <= ?`,
    )
    .bind(...Object.values(scope), input.consumedAtMs)
    .first<{ readonly count?: unknown }>();
  expect(Number(scopedExpired?.count)).toBe(1);

  const live = await temporary.database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM linked_device_request_proof_nonces
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?
          AND link_session_id = ? AND request_nonce_b64u = ?`,
    )
    .bind(...Object.values(scope), String(liveSessionId), liveNonce)
    .first<{ readonly count?: unknown }>();
  expect(Number(live?.count)).toBe(1);

  const otherScopeExpired = await temporary.database
    .prepare(
      `SELECT COUNT(*) AS count
         FROM linked_device_request_proof_nonces
        WHERE namespace = ? AND org_id = ? AND project_id = ? AND env_id = ?`,
    )
    .bind(...Object.values(otherScope))
    .first<{ readonly count?: unknown }>();
  expect(Number(otherScopeExpired?.count)).toBe(1);
});
