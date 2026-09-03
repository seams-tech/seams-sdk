import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync, sign as signEd25519 } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';
import {
  finalize_ecdsa_client_bootstrap_v1,
  EcdsaRoleLocalPresignSessionV1,
  initSync as initEcdsaClientSync,
  RouterAbEcdsaClientCeremonyV1,
  prepare_ecdsa_client_bootstrap_v1,
} from '../../../wasm/router_ab_ecdsa_client/pkg/router_ab_ecdsa_client.js';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(packageRoot, '../..');
const internalAuthHeader = 'x-router-ab-internal-service-auth';
const internalAuthSecret = 'private-d1-integration-auth';
const roleD1Binding = 'DERIVER_ROLE_PRIVATE_DB';
const managedBackupR2Binding = 'TENANT_ROOT_MANAGED_BACKUP_BUCKET';
const signingWorkerD1Binding = 'SIGNING_WORKER_PRIVATE_DB';
const tenantRootCreationDoBinding = 'ROUTER_TENANT_ROOT_CREATION_DO';
const tenantRootCreationDoClass = 'RouterAbTenantRootCreationDurableObject';
const tenantRootCreationPath = '/router-ab/internal/tenant-root/creation/v1/create';
const tenantRootRoleCreationPath =
  '/router-ab/internal/deriver/tenant-root/creation/v1/create-role-share';
const deriverAMigrationsPath = join(packageRoot, 'migrations/deriver-a');
const deriverBMigrationsPath = join(packageRoot, 'migrations/deriver-b');
const signingWorkerMigrationsPath = join(packageRoot, 'migrations/signing-worker');
const ecdsaRegistrationPath = '/router-ab/ecdsa-derivation/register';
const ecdsaActivationPath = '/router-ab/ecdsa-derivation/activate';
const ecdsaSigningPreparePath = '/router-ab/ecdsa-derivation/sign/prepare';
const ecdsaSigningPath = '/router-ab/ecdsa-derivation/sign';
const ecdsaPresignSessionInitPath =
  '/router-ab/signing-worker/ecdsa-derivation/presignature-session/init';
const ecdsaPresignSessionStepPath =
  '/router-ab/signing-worker/ecdsa-derivation/presignature-session/step';
const tenantRootRefreshPath = '/router-ab/internal/tenant-root/refresh/v1/execute';
const ed25519ExecutePath = '/router-ab/router/ed25519-yao/execute';
const ecdsaClientWasmPath = resolve(
  repoRoot,
  'wasm/router_ab_ecdsa_client/pkg/router_ab_ecdsa_client_bg.wasm',
);
let capturedSigningWorkerDelivery;
let signingWorkerDeliveryTarget = 'fixture-signing-worker';
let ecdsaClientWasmInitialized = false;

function loadFixture() {
  const output = execFileSync(
    'cargo',
    [
      'run',
      '--quiet',
      '--manifest-path',
      join(repoRoot, 'crates/router-ab-dev/Cargo.toml'),
      '--example',
      'cloudflare_private_d1_fixture',
    ],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  return JSON.parse(output);
}

function configureRouterJwt(fixture) {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const keyId = 'private-d1-router-jwt-v1';
  const publicJwk = publicKey.export({ format: 'jwk' });
  fixture.router_env.ROUTER_JWT_JWKS_JSON = JSON.stringify({
    keys: [
      {
        alg: 'EdDSA',
        crv: 'Ed25519',
        kid: keyId,
        kty: 'OKP',
        use: 'sig',
        x: publicJwk.x,
      },
    ],
  });
  return { keyId, privateKey };
}

function encodeJwtSegment(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function signRouterJwt(jwtSigner, fixture, claims) {
  const header = encodeJwtSegment({ alg: 'EdDSA', kid: jwtSigner.keyId, typ: 'JWT' });
  const payload = encodeJwtSegment({
    iss: fixture.router_env.ROUTER_JWT_ISSUER,
    aud: fixture.router_env.ROUTER_JWT_AUDIENCE,
    ...claims,
  });
  const signingInput = `${header}.${payload}`;
  const signature = signEd25519(null, Buffer.from(signingInput, 'utf8'), jwtSigner.privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

function ensureEcdsaClientWasm() {
  if (ecdsaClientWasmInitialized) return;
  initEcdsaClientSync({ module: readFileSync(ecdsaClientWasmPath) });
  ecdsaClientWasmInitialized = true;
}

function strictWorker(name, role, bindings) {
  return {
    name,
    modules: true,
    scriptPath: join(packageRoot, `build/${role}/worker/shim.mjs`),
    modulesRules: [
      { type: 'ESModule', include: ['**/*.js', '**/*.mjs'] },
      { type: 'CompiledWasm', include: ['**/*.wasm'] },
    ],
    compatibilityDate: '2026-06-12',
    bindings,
  };
}

function deriverAWorker(fixture) {
  return {
    ...strictWorker('deriver-a', 'deriver-a', {
      ...fixture.deriver_a_env,
      ROUTER_AB_TENANT_ROOT_ROLE_D1_INTEGRATION: 'enabled',
    }),
    d1Databases: { [roleD1Binding]: 'deriver-a-private-d1' },
    r2Buckets: { [managedBackupR2Binding]: 'deriver-a-managed-backup' },
    durableObjects: {
      [tenantRootCreationDoBinding]: {
        className: tenantRootCreationDoClass,
        scriptName: 'router',
        useSQLite: true,
      },
    },
    serviceBindings: { DERIVER_B: 'deriver-b' },
  };
}

function deriverBWorker(fixture) {
  return {
    ...strictWorker('deriver-b', 'deriver-b', {
      ...fixture.deriver_b_env,
      ROUTER_AB_TENANT_ROOT_ROLE_D1_INTEGRATION: 'enabled',
    }),
    d1Databases: { [roleD1Binding]: 'deriver-b-private-d1' },
    r2Buckets: { [managedBackupR2Binding]: 'deriver-b-managed-backup' },
    durableObjects: {
      [tenantRootCreationDoBinding]: {
        className: tenantRootCreationDoClass,
        scriptName: 'router',
        useSQLite: true,
      },
    },
    serviceBindings: { DERIVER_A: 'deriver-a' },
  };
}

function signingWorker(name, databaseId, fixture) {
  return {
    ...strictWorker(name, 'signing-worker', fixture.signing_worker_env),
    d1Databases: { [signingWorkerD1Binding]: databaseId },
    durableObjects: {
      SIGNING_WORKER_PRESIGN_SESSION_DO: {
        className: 'RouterAbSigningWorkerPresignSessionDurableObject',
        useSQLite: true,
      },
    },
  };
}

function routerWorker(fixture) {
  return {
    ...strictWorker('router', 'router', fixture.router_env),
    durableObjects: {
      [tenantRootCreationDoBinding]: {
        className: tenantRootCreationDoClass,
        useSQLite: true,
      },
    },
    serviceBindings: {
      DERIVER_A: 'deriver-a',
      DERIVER_B: 'deriver-b',
      SIGNING_WORKER: captureSigningWorkerDelivery,
      TENANT_ROOT_CONTROL_PLANE: 'tenant-root-control-plane',
    },
  };
}

function tenantRootControlPlaneWorker(fixture) {
  return {
    ...strictWorker(
      'tenant-root-control-plane',
      'tenant-root-control-plane',
      fixture.tenant_root_control_plane_env,
    ),
    durableObjects: {
      [tenantRootCreationDoBinding]: {
        className: tenantRootCreationDoClass,
        scriptName: 'router',
        useSQLite: true,
      },
    },
  };
}

async function captureSigningWorkerDelivery(request, miniflare) {
  capturedSigningWorkerDelivery = await request.clone().text();
  const worker = await miniflare.getWorker(signingWorkerDeliveryTarget);
  return worker.fetch(request);
}

async function applyMigrations(miniflare, binding, workerName, migrationsPath) {
  const database = await miniflare.getD1Database(binding, workerName);
  const migrationFiles = (await readdir(migrationsPath))
    .filter((file) => file.endsWith('.sql'))
    .sort();
  for (const migrationFile of migrationFiles) {
    const sql = await readFile(join(migrationsPath, migrationFile), 'utf8');
    // D1's exec() splits on newlines and treats each line as a statement, so a
    // multi-line CREATE TABLE arrives truncated. Split on statement boundaries
    // and collapse each one to a single line instead.
    for (const statement of splitSqlStatements(sql)) {
      await database.exec(statement);
    }
  }
  return database;
}

/// Splits a migration into single-line statements.
///
/// D1's exec() treats every newline as a statement boundary, so each statement
/// must be collapsed onto one line. Splitting on ";" alone is not enough: a
/// trigger body is itself a semicolon-terminated statement wrapped in
/// BEGIN ... END, and a semicolon inside a string literal is not a boundary
/// either.
function splitSqlStatements(sql) {
  const collapsed = sql
    .split('\n')
    .map((line) => line.replace(/--.*$/u, '').trim())
    .filter((line) => line.length > 0)
    .join(' ')
    .replace(/\s+/gu, ' ');

  const statements = [];
  let current = '';
  let inString = false;
  let blockDepth = 0;
  for (let index = 0; index < collapsed.length; index += 1) {
    const char = collapsed[index];
    current += char;
    if (char === "'") {
      // Doubled quotes escape a quote inside a literal.
      if (inString && collapsed[index + 1] === "'") {
        current += collapsed[index + 1];
        index += 1;
        continue;
      }
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (/\bBEGIN$/iu.test(current) && /^[\s(]|^$/u.test(collapsed[index + 1] ?? ' ')) {
      blockDepth += 1;
      continue;
    }
    if (/\bEND$/iu.test(current) && blockDepth > 0) {
      blockDepth -= 1;
      continue;
    }
    if (char === ';' && blockDepth === 0) {
      const statement = current.trim();
      if (statement.length > 1) statements.push(statement);
      current = '';
    }
  }
  const tail = current.trim();
  if (tail.length > 0) statements.push(tail.endsWith(';') ? tail : `${tail};`);
  return statements;
}

function authenticatedJsonRequest(body, additionalHeaders = {}) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [internalAuthHeader]: internalAuthSecret,
      ...additionalHeaders,
    },
    body: JSON.stringify(body),
  };
}

async function responseBytes(response) {
  return Buffer.from(await response.arrayBuffer());
}

async function expectOk(response, label) {
  const bytes = await responseBytes(response);
  assert.equal(response.status, 200, `${label}: ${bytes.toString('utf8')}`);
  return bytes;
}

async function postWorkerJson(worker, path, body, additionalHeaders = {}) {
  return worker.fetch(
    `https://private.test${path}`,
    authenticatedJsonRequest(body, additionalHeaders),
  );
}

async function testTenantRootRoleSchema(database, expectedRole) {
  const tableInfo = await database.prepare('PRAGMA table_info(tenant_root_role_shares)').all();
  assert.deepEqual(
    tableInfo.results.map((column) => column.name),
    [
      'tenant_identity_digest_hex',
      'custody_lineage_b64u',
      'tenant_root_share_epoch',
      'role',
      'lifecycle',
      'ciphertext_json',
      'revision',
      'created_at_ms',
      'updated_at_ms',
    ],
    'role-private tenant-root D1 must expose metadata and one outer ciphertext only',
  );

  await assert.rejects(
    database
      .prepare(
        `INSERT INTO tenant_root_role_shares (
           tenant_identity_digest_hex, custody_lineage_b64u, tenant_root_share_epoch,
           role, lifecycle, ciphertext_json, revision, created_at_ms, updated_at_ms
         ) VALUES (?, ?, 1, ?, 'pending', '{}', 1, 10, 10)`,
      )
      .bind(
        'a'.repeat(64),
        'A'.repeat(22),
        expectedRole === 'deriver_a' ? 'deriver_b' : 'deriver_a',
      )
      .run(),
    'each Deriver database must reject the other role',
  );

  const replayTableInfo = await database
    .prepare('PRAGMA table_info(tenant_root_command_replays)')
    .all();
  assert.deepEqual(
    replayTableInfo.results.map((column) => column.name),
    [
      'replay_key_digest_hex',
      'tenant_identity_digest_hex',
      'custody_lineage_b64u',
      'session_id_hex',
      'nonce_hex',
      'role',
      'command_digest_hex',
      'status',
      'receipt_b64u',
      'receipt_digest_hex',
      'reserved_at_ms',
      'executed_at_ms',
      'terminal_at_ms',
      'admission_digest_hex',
      'refresh_state_b64u',
      'refresh_state_digest_hex',
    ],
    'role-private command replay D1 must expose only public binding and receipt fields',
  );
  await assert.rejects(
    database
      .prepare(
        `INSERT INTO tenant_root_command_replays (
           replay_key_digest_hex, tenant_identity_digest_hex, custody_lineage_b64u,
           session_id_hex, nonce_hex, role, command_digest_hex, status, reserved_at_ms
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', 10)`,
      )
      .bind(
        'a'.repeat(64),
        'b'.repeat(64),
        'A'.repeat(22),
        'c'.repeat(32),
        'd'.repeat(64),
        expectedRole === 'deriver_a' ? 'deriver_b' : 'deriver_a',
        'e'.repeat(64),
      )
      .run(),
    'each Deriver command-replay table must reject the other role',
  );
}

async function testTenantRootCommandReplayCasGuard(database, expectedRole) {
  const replayKeyDigestHex = 'a'.repeat(64);
  await assert.rejects(
    database.prepare('DELETE FROM tenant_root_command_cas_guard').run(),
    'command-replay CAS guard row must be immutable',
  );
  const guard = await database
    .prepare('SELECT guard_id FROM tenant_root_command_cas_guard')
    .first();
  assert.equal(guard.guard_id, 1, 'command-replay CAS guard row must survive deletion attempts');

  await database
    .prepare(
      `INSERT INTO tenant_root_command_replays (
         replay_key_digest_hex, tenant_identity_digest_hex, custody_lineage_b64u,
         session_id_hex, nonce_hex, role, command_digest_hex, status, reserved_at_ms
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', 10)`,
    )
    .bind(
      replayKeyDigestHex,
      'b'.repeat(64),
      'C'.repeat(22),
      'd'.repeat(32),
      'e'.repeat(64),
      expectedRole,
      'f'.repeat(64),
    )
    .run();
  const before = await database
    .prepare(
      `SELECT status, executed_at_ms
       FROM tenant_root_command_replays WHERE replay_key_digest_hex = ?`,
    )
    .bind(replayKeyDigestHex)
    .first();
  await assert.rejects(
    database.batch([
      database
        .prepare(
          `UPDATE tenant_root_command_replays
           SET status = 'executed', executed_at_ms = 11
           WHERE replay_key_digest_hex = ?`,
        )
        .bind(replayKeyDigestHex),
      database
        .prepare(
          `INSERT INTO tenant_root_command_cas_guard (guard_id)
           SELECT 1 WHERE changes() <> ?`,
        )
        .bind(2),
    ]),
    'wrong lifecycle/checkpoint change counts must roll back the mutation',
  );
  const after = await database
    .prepare(
      `SELECT status, executed_at_ms
       FROM tenant_root_command_replays WHERE replay_key_digest_hex = ?`,
    )
    .bind(replayKeyDigestHex)
    .first();
  assert.deepEqual(
    after,
    before,
    'wrong lifecycle/checkpoint change counts must not commit partial replay state',
  );
}

async function testTenantRootCreationOperatingPath(topology, fixture, databases) {
  const router = await topology.getWorker('router');
  const backupBucketA = await topology.getR2Bucket(managedBackupR2Binding, 'deriver-a');
  const backupBucketB = await topology.getR2Bucket(managedBackupR2Binding, 'deriver-b');

  const firstBytes = await expectOk(
    await postWorkerJson(router, tenantRootCreationPath, fixture.tenant_root_creation.fresh),
    'fresh-lineage tenant-root creation operating path',
  );
  const first = JSON.parse(firstBytes.toString('utf8'));
  assert.equal(first.revision, 1, 'tenant-root genesis must start at revision 1');
  assert.deepEqual(
    first.status.kind,
    'ready',
    'Router must not return before both role installations are checkpointed',
  );

  const [activeRowsA, activeRowsB] = await Promise.all([
    databases.deriverA
      .prepare(
        `SELECT tenant_identity_digest_hex, custody_lineage_b64u, ciphertext_json
         FROM tenant_root_role_shares
         WHERE tenant_root_share_epoch = 1 AND role = 'deriver_a' AND lifecycle = 'active'`,
      )
      .all(),
    databases.deriverB
      .prepare(
        `SELECT tenant_identity_digest_hex, custody_lineage_b64u, ciphertext_json
         FROM tenant_root_role_shares
         WHERE tenant_root_share_epoch = 1 AND role = 'deriver_b' AND lifecycle = 'active'`,
      )
      .all(),
  ]);
  assert.equal(
    activeRowsA.results.length,
    1,
    'Deriver A must persist exactly one active initial tenant-root row',
  );
  assert.equal(
    activeRowsB.results.length,
    1,
    'Deriver B must persist exactly one active initial tenant-root row',
  );
  const identityDigestHex = Buffer.from(first.identity_digest_b64u, 'base64url').toString('hex');
  const activeA = activeRowsA.results[0];
  const activeB = activeRowsB.results[0];
  assert.equal(activeA.tenant_identity_digest_hex, identityDigestHex);
  assert.equal(activeB.tenant_identity_digest_hex, identityDigestHex);
  assert.equal(activeA.custody_lineage_b64u, first.custody_lineage_b64u);
  assert.equal(activeB.custody_lineage_b64u, first.custody_lineage_b64u);
  assert.notEqual(
    activeA.ciphertext_json,
    activeB.ciphertext_json,
    'Deriver A and B must independently encrypt their active shares for the same tenant root',
  );

  const replayBytes = await expectOk(
    await postWorkerJson(router, tenantRootCreationPath, fixture.tenant_root_creation.fresh),
    'tenant-root creation exact retry',
  );
  assert.deepEqual(
    replayBytes,
    firstBytes,
    'the same signed grant must replay the exact completed response bytes',
  );

  const [backupsA, backupsB] = await Promise.all([backupBucketA.list(), backupBucketB.list()]);
  assert.equal(backupsA.objects.length, 1, 'Deriver A must persist one managed backup');
  assert.equal(backupsB.objects.length, 1, 'Deriver B must persist one managed backup');
  assert.match(
    backupsA.objects[0].key,
    /^tenant-root-managed-backup\/v1\/deriver-a\//u,
    'Deriver A must write only under its role-private prefix',
  );
  assert.match(
    backupsB.objects[0].key,
    /^tenant-root-managed-backup\/v1\/deriver-b\//u,
    'Deriver B must write only under its role-private prefix',
  );

  return {
    identity_digest_b64u: first.identity_digest_b64u,
    custody_lineage_b64u: first.custody_lineage_b64u,
  };
}

async function testEcdsaRegistrationAndActivation(topology, fixture, tenantRoot, jwtSigner) {
  ensureEcdsaClientWasm();
  const router = await topology.getWorker('router');
  const accountId = 'ecdsa-live-account';
  const clientId = 'ecdsa-live-client';
  const sessionId = 'ecdsa-live-session';
  const lifecycleId = 'ecdsa-live-lifecycle';
  const signerSetId = 'signer-set-v1';
  const rootShareEpoch = 'epoch-1';
  const selectedServerId = 'signing-worker-local';
  const expiresAtMs = Date.now() + 120_000;
  const applicationBindingDigestB64u = Buffer.alloc(32, 0x42).toString('base64url');
  const prepared = JSON.parse(
    prepare_ecdsa_client_bootstrap_v1(
      JSON.stringify({
        kind: 'prepare_ecdsa_client_bootstrap_v1',
        algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
        context: { applicationBindingDigestB64u },
        participants: {
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
        },
        secretSource: {
          kind: 'threshold_prf_x_client_base',
          xClientBaseB64u: Buffer.alloc(32, 0x11).toString('base64url'),
        },
      }),
    ),
  );
  const ceremony = new RouterAbEcdsaClientCeremonyV1();
  try {
    const registrationRequest = JSON.parse(
      ceremony.build_registration_request(
        JSON.stringify({
          registration_purpose: 'wallet_registration',
          context: { application_binding_digest_b64u: applicationBindingDigestB64u },
          lifecycle: {
            lifecycle_id: lifecycleId,
            work_kind: 'registration_prepare',
            primitive_request_kind: 'registration',
            root_share_epoch: rootShareEpoch,
            account_id: accountId,
            session_id: sessionId,
            signer_set_id: signerSetId,
            selected_server_id: selectedServerId,
          },
          signer_set: {
            signer_set_id: signerSetId,
            policy: 'all_2',
            signer_a: { role: 'signer_a', signer_id: 'signer-a', key_epoch: rootShareEpoch },
            signer_b: { role: 'signer_b', signer_id: 'signer-b', key_epoch: rootShareEpoch },
            selected_server: {
              server_id: selectedServerId,
              key_epoch: rootShareEpoch,
              recipient_encryption_key:
                fixture.signing_worker_env.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
            },
          },
          router_id: 'local-router',
          client_id: clientId,
          replay_nonce: 'ecdsa-live-replay-nonce',
          expires_at_ms: expiresAtMs,
          deriver_recipient_keys: {
            deriver_a: {
              role: 'signer_a',
              key_epoch: rootShareEpoch,
              public_key: fixture.router_env.DERIVER_A_ENVELOPE_HPKE_PUBLIC_KEY,
            },
            deriver_b: {
              role: 'signer_b',
              key_epoch: rootShareEpoch,
              public_key: fixture.router_env.DERIVER_B_ENVELOPE_HPKE_PUBLIC_KEY,
            },
          },
        }),
      ),
    );
    const binding = JSON.parse(ceremony.registration_binding());
    const nowSeconds = Math.floor(Date.now() / 1000);
    const token = signRouterJwt(jwtSigner, fixture, {
      sub: clientId,
      exp: Math.ceil(expiresAtMs / 1000),
      nbf: nowSeconds - 1,
      iat: nowSeconds - 1,
      sid: sessionId,
      org_id: 'org-miniflare',
      project_id: 'project-r120',
      environment: 'test',
      account_id: accountId,
      routerAbRequestPolicy: {
        policyVersion: 'router-ab-ecdsa-registration-v1',
        workKind: 'registration_prepare',
        requestDigest: {
          bytes: Array.from(Buffer.from(binding.requestDigestB64u, 'base64url')),
        },
      },
    });
    const registrationBytes = await expectOk(
      await postWorkerJson(
        router,
        ecdsaRegistrationPath,
        { registration_request: registrationRequest, tenant_root: tenantRoot },
        { authorization: `Bearer ${token}` },
      ),
      'live Router ECDSA registration',
    );
    const registration = JSON.parse(registrationBytes.toString('utf8'));
    assert.equal(registration.result, 'forwarded');
    assert.equal(
      registration.response.bundles.signerA.transcriptDigestB64u,
      binding.transcriptDigestB64u,
      'Deriver A client proof must bind the live registration transcript',
    );
    assert.equal(
      registration.response.bundles.signerB.transcriptDigestB64u,
      binding.transcriptDigestB64u,
      'Deriver B client proof must bind the live registration transcript',
    );
    ceremony.verify_encrypted_proof_bundles(
      JSON.stringify({
        kind: 'finalize_encrypted_client_proof_bundles_v2',
        bundles: registration.response.bundles,
      }),
    );

    const activationBody = {
      activation_correlation_id:
        registration.pending_activation.activation_context.lifecycle.lifecycle_id,
      pending: registration.pending_activation,
      client_activation: {
        registrationRequestDigestB64u: binding.requestDigestB64u,
        proofTranscriptDigestB64u: binding.transcriptDigestB64u,
        contextBinding32B64u: prepared.clientBootstrap.contextBinding32B64u,
        derivationClientSharePublicKey33B64u:
          prepared.clientBootstrap.derivationClientSharePublicKey33B64u,
        clientShareRetryCounter: prepared.clientBootstrap.clientShareRetryCounter,
        participantId: prepared.clientBootstrap.participantId,
      },
    };
    const activationBytes = await expectOk(
      await postWorkerJson(router, ecdsaActivationPath, activationBody, {
        authorization: `Bearer ${token}`,
      }),
      'live Router ECDSA activation',
    );
    const activation = JSON.parse(activationBytes.toString('utf8'));
    assert.equal(activation.activated, true);
    assert.equal(
      activation.lifecycle_id,
      lifecycleId,
      'live ECDSA activation must return the requested lifecycle id',
    );
    const identity = activation.ecdsa_activation.public_identity;
    assert.equal(
      activation.ecdsa_activation.context.application_binding_digest_b64u,
      applicationBindingDigestB64u,
      'live ECDSA activation must preserve the application binding context',
    );
    assert.equal(
      activation.ecdsa_activation.signing_worker.server_id,
      selectedServerId,
      'live ECDSA activation must identify the selected SigningWorker',
    );
    assert.equal(
      activation.ecdsa_activation.activation_epoch,
      rootShareEpoch,
      'live ECDSA activation must preserve the active root-share epoch',
    );
    assert.equal(
      identity.context_binding_b64u,
      prepared.clientBootstrap.contextBinding32B64u,
      'live ECDSA identity must bind the client bootstrap context',
    );
    assert.equal(
      identity.derivation_client_share_public_key33_b64u,
      prepared.clientBootstrap.derivationClientSharePublicKey33B64u,
      'live ECDSA identity must bind the client share public key',
    );
    const expectedEthereumAddress = `0x${Buffer.from(
      identity.ethereum_address20_b64u,
      'base64url',
    ).toString('hex')}`;
    const finalized = JSON.parse(
      finalize_ecdsa_client_bootstrap_v1(
        JSON.stringify({
          kind: 'finalize_ecdsa_client_bootstrap_v1',
          pendingStateBlob: prepared.pendingStateBlob,
          relayerPublicIdentity: {
            relayerKeyId: selectedServerId,
            relayerPublicKey33B64u: identity.server_public_key33_b64u,
            groupPublicKey33B64u: identity.threshold_public_key33_b64u,
            ethereumAddress: expectedEthereumAddress,
            relayerShareRetryCounter: identity.server_share_retry_counter,
          },
        }),
      ),
    );
    assert.equal(
      finalized.publicFacts.contextBinding32B64u,
      identity.context_binding_b64u,
      'live ECDSA identity must preserve the stable context binding',
    );
    assert.equal(
      finalized.publicFacts.derivationClientSharePublicKey33B64u,
      identity.derivation_client_share_public_key33_b64u,
      'live ECDSA identity must preserve the client share public key',
    );
    assert.equal(
      finalized.publicFacts.relayerPublicKey33B64u,
      identity.server_public_key33_b64u,
      'live ECDSA identity must preserve the server share public key',
    );
    assert.equal(
      finalized.publicFacts.groupPublicKey33B64u,
      identity.threshold_public_key33_b64u,
      'live ECDSA identity must equal the independently recomposed aggregate public key',
    );
    assert.equal(
      finalized.publicFacts.ethereumAddress,
      expectedEthereumAddress,
      'live ECDSA identity must equal the independently recomposed aggregate Ethereum address',
    );

    const replayBytes = await expectOk(
      await postWorkerJson(router, ecdsaActivationPath, activationBody, {
        authorization: `Bearer ${token}`,
      }),
      'live Router ECDSA activation exact retry',
    );
    assert.deepEqual(
      replayBytes,
      activationBytes,
      'exact live activation retry must replay byte-identical response bytes',
    );
    const replayIdentity = JSON.parse(replayBytes.toString('utf8')).ecdsa_activation
      .public_identity;
    assert.deepEqual(
      replayIdentity,
      identity,
      'exact live activation retry must preserve the complete public identity',
    );
    return {
      activation,
      activationBody,
      activationBytes,
      identity,
      identityBytes: Buffer.from(JSON.stringify(identity), 'utf8'),
      finalized,
      token,
      accountId,
      selectedServerId,
    };
  } finally {
    ceremony.free();
  }
}

function base64urlBytes(value) {
  return Buffer.from(value).toString('base64url');
}

function hashBase64url(value) {
  return createHash('sha256').update(value).digest('base64url');
}

function buildEcdsaNormalSigningScope(ecdsa) {
  const receipt = ecdsa.activation.ecdsa_activation;
  assert.equal(
    receipt.material_activation.material_owner,
    ecdsa.accountId,
    'ECDSA activation material must name the live signing account',
  );
  assert.equal(
    receipt.material_activation.signing_worker,
    ecdsa.selectedServerId,
    'ECDSA activation material must name the live SigningWorker',
  );
  return {
    wallet_id: ecdsa.accountId,
    ecdsa_threshold_key_id: 'ecdsa-live-threshold-key',
    signing_root_id: 'project:local',
    signing_root_version: 'v1',
    context: receipt.context,
    public_identity: receipt.public_identity,
    material_activation: receipt.material_activation,
    signing_worker: receipt.signing_worker,
    activation_epoch: receipt.activation_epoch,
  };
}

function parseEcdsaPresignProgress(bytes, sessionId, label) {
  const progress = JSON.parse(bytes.toString('utf8'));
  assert.equal(progress.presign_session_id, sessionId, `${label} must preserve the session id`);
  return progress;
}

async function runEcdsaPresignSession(topology, ecdsa) {
  const signingWorker = await topology.getWorker('fixture-signing-worker');
  const scope = buildEcdsaNormalSigningScope(ecdsa);
  const groupPublicKey = Buffer.from(
    scope.public_identity.threshold_public_key33_b64u,
    'base64url',
  );
  assert.equal(groupPublicKey.length, 33, 'ECDSA aggregate public key must be compressed secp256k1');
  const presignSessionId = `ecdsa-live-presign-${Date.now()}`;
  const expiresAtMs = Date.now() + 120_000;
  const client = new EcdsaRoleLocalPresignSessionV1(
    ecdsa.finalized.stateBlob.stateBlobB64u,
    groupPublicKey,
    presignSessionId,
  );
  try {
    let clientProgress = client.poll();
    assert.equal(clientProgress.stage, 'triples');
    assert.equal(clientProgress.outgoing.length, 1, 'ECDSA client triples must start with one message');
    const initResponse = await postWorkerJson(signingWorker, ecdsaPresignSessionInitPath, {
      scope,
      presign_session_id: presignSessionId,
      expires_at_ms: expiresAtMs,
    });
    const initBytes = await expectOk(initResponse, 'SigningWorker ECDSA presign session init');
    const init = parseEcdsaPresignProgress(
      initBytes,
      presignSessionId,
      'ECDSA presign session init',
    );
    assert.equal(init.kind, 'continue');
    assert.equal(init.stage, 'triples');
    assert.equal(init.event, 'none');
    assert.equal(
      init.outgoing_messages_b64u.length,
      1,
      'ECDSA SigningWorker triples must start with one message',
    );
    let workerOutgoing = init.outgoing_messages_b64u.map((message) =>
      Buffer.from(message, 'base64url'),
    );

    for (let round = 0; round < 9; round += 1) {
      assert.equal(
        clientProgress.outgoing.length,
        1,
        `ECDSA client triples round ${round + 1} must emit one message`,
      );
      const stepResponse = await postWorkerJson(signingWorker, ecdsaPresignSessionStepPath, {
        scope,
        presign_session_id: presignSessionId,
        requested_stage: 'triples',
        outgoing_messages_b64u: clientProgress.outgoing.map(base64urlBytes),
        expires_at_ms: expiresAtMs,
      });
      const stepBytes = await expectOk(
        stepResponse,
        `SigningWorker ECDSA presign triples round ${round + 1}`,
      );
      const step = parseEcdsaPresignProgress(
        stepBytes,
        presignSessionId,
        `ECDSA presign triples round ${round + 1}`,
      );
      assert.equal(step.kind, 'continue');
      for (const message of workerOutgoing) {
        client.message(message);
      }
      clientProgress = client.poll();
      if (round === 8) {
        assert.equal(step.stage, 'triples_done');
        assert.equal(step.event, 'triples_done');
        assert.equal(step.outgoing_messages_b64u.length, 0);
        assert.equal(clientProgress.stage, 'triples_done');
        assert.equal(clientProgress.event, 'triples_done');
        assert.equal(clientProgress.outgoing.length, 0);
      } else {
        assert.equal(step.stage, 'triples');
        assert.equal(step.event, 'none');
        assert.equal(step.outgoing_messages_b64u.length, 1);
        workerOutgoing = step.outgoing_messages_b64u.map((message) =>
          Buffer.from(message, 'base64url'),
        );
      }
    }

    client.start_presign();
    clientProgress = client.poll();
    assert.equal(clientProgress.stage, 'presign');
    assert.equal(clientProgress.outgoing.length, 1);
    const firstPresignResponse = await postWorkerJson(signingWorker, ecdsaPresignSessionStepPath, {
      scope,
      presign_session_id: presignSessionId,
      requested_stage: 'presign',
      outgoing_messages_b64u: clientProgress.outgoing.map(base64urlBytes),
      expires_at_ms: expiresAtMs,
    });
    const firstPresignBytes = await expectOk(
      firstPresignResponse,
      'SigningWorker ECDSA presign first presign round',
    );
    const firstPresign = parseEcdsaPresignProgress(
      firstPresignBytes,
      presignSessionId,
      'ECDSA presign first presign round',
    );
    assert.equal(firstPresign.kind, 'continue');
    assert.equal(firstPresign.stage, 'presign');
    assert.equal(firstPresign.event, 'none');
    assert.equal(
      firstPresign.outgoing_messages_b64u.length,
      2,
      'ECDSA presign first round must release both worker protocol messages',
    );
    for (const message of firstPresign.outgoing_messages_b64u) {
      client.message(Buffer.from(message, 'base64url'));
    }
    clientProgress = client.poll();
    assert.equal(clientProgress.stage, 'done');
    assert.equal(clientProgress.outgoing.length, 1);

    const completeResponse = await postWorkerJson(signingWorker, ecdsaPresignSessionStepPath, {
      scope,
      presign_session_id: presignSessionId,
      requested_stage: 'presign',
      outgoing_messages_b64u: clientProgress.outgoing.map(base64urlBytes),
      expires_at_ms: expiresAtMs,
    });
    const completeBytes = await expectOk(
      completeResponse,
      'SigningWorker ECDSA presign completion',
    );
    const complete = parseEcdsaPresignProgress(
      completeBytes,
      presignSessionId,
      'ECDSA presign completion',
    );
    assert.equal(complete.kind, 'complete');
    const clientBigR = Buffer.from(client.presignature_big_r_33());
    assert.equal(clientBigR.length, 33, 'ECDSA client presignature must expose a compressed R point');
    assert.equal(
      complete.server_big_r33_b64u,
      base64urlBytes(clientBigR),
      'ECDSA client and SigningWorker presignatures must bind the same R point',
    );
    assert.equal(
      complete.server_presignature_id,
      `presig-${hashBase64url(clientBigR)}`,
      'ECDSA presignature id must be derived from the shared R point',
    );
    return {
      client,
      scope,
      groupPublicKey,
      clientBigR,
      serverPresignatureId: complete.server_presignature_id,
      expiresAtMs,
    };
  } catch (error) {
    client.free();
    throw error;
  }
}

function buildEcdsaAuthorizedOperation(operationId, operationDigests) {
  return {
    kind: 'reusable_wallet_session_authorized_operation_v1',
    authorized_operation_id: operationId,
    operation_id: operationId,
    capability_kind: 'evm_ecdsa_mpc_signing',
    operation_kind: 'evm.sign_transaction',
    lane_digest_b64u: operationDigests.lane_digest_b64u,
    intent_digest_b64u: operationDigests.intent_digest_b64u,
    display_digest_b64u: operationDigests.display_digest_b64u,
    operation_fingerprint_digest: hashBase64url(`ecdsa-live-fingerprint:${operationId}`),
  };
}

async function testEcdsaNormalSigning(topology, ecdsa) {
  const router = await topology.getWorker('router');
  const presign = await runEcdsaPresignSession(topology, ecdsa);
  try {
    const operationId = 'ecdsa-live-normal-sign-operation';
    const signingDigestBytes = createHash('sha256')
      .update('ecdsa-live-normal-signing-digest')
      .digest();
    const operationDigests = {
      lane_digest_b64u: hashBase64url('ecdsa-live-lane-digest'),
      intent_digest_b64u: base64urlBytes(signingDigestBytes),
      display_digest_b64u: hashBase64url('ecdsa-live-display-digest'),
    };
    const expiresAtMs = Math.min(presign.expiresAtMs, Date.now() + 120_000);
    const materialActivation = presign.scope.material_activation;
    const authorization = {
      kind: 'reusable_wallet_session',
      wallet_session_id: 'ecdsa-live-normal-wallet-session',
    };
    const acceptedBinding = {
      kind: 'gateway_owner_wallet_session',
      subject_id: ecdsa.accountId,
      account_id: ecdsa.accountId,
      authorization_id: 'ecdsa-live-normal-authorization',
      wallet_session_id: authorization.wallet_session_id,
      quota_id: 'ecdsa-live-normal-quota',
      threshold_session_id: 'ecdsa-live-normal-threshold-session',
      org_id: 'org-miniflare',
      project_id: 'project-r120',
      environment: 'test',
      signing_worker_id: ecdsa.selectedServerId,
      expires_at_ms: expiresAtMs,
    };
    const authorizedOperation = buildEcdsaAuthorizedOperation(operationId, operationDigests);
    const clientContribution = Buffer.alloc(32, 0x44);
    const clientCommitment = createHash('sha256')
      .update('router-ab-ecdsa-derivation/client-rerandomization-commitment/v1')
      .update(clientContribution)
      .digest('base64url');
    const prepareRequest = {
      scope: presign.scope,
      request_id: 'ecdsa-live-normal-sign-request',
      operation_id: operationId,
      operation_digests: operationDigests,
      authorization,
      material_activation: materialActivation,
      client_presignature_id: presign.serverPresignatureId,
      expires_at_ms: expiresAtMs,
      signing_digest_b64u: operationDigests.intent_digest_b64u,
      client_rerandomization_commitment32_b64u: clientCommitment,
      authorized_operation: {
        binding: acceptedBinding,
        authorized_operation: authorizedOperation,
      },
    };
    const prepareResponse = await postWorkerJson(
      router,
      ecdsaSigningPreparePath,
      prepareRequest,
    );
    const prepareBytes = await expectOk(prepareResponse, 'live ECDSA normal-signing prepare');
    const prepared = JSON.parse(prepareBytes.toString('utf8'));
    assert.equal(prepared.request_id, prepareRequest.request_id);
    assert.deepEqual(
      prepared.scope.public_identity,
      ecdsa.identity,
      'ECDSA normal-signing prepare must preserve the activated public identity',
    );
    assert.equal(
      prepared.server_presignature_id,
      presign.serverPresignatureId,
      'ECDSA normal-signing prepare must consume the exact presignature selected by the client',
    );
    assert.equal(
      prepared.server_big_r33_b64u,
      base64urlBytes(presign.clientBigR),
      'ECDSA normal-signing prepare must return the client presignature R point',
    );
    const serverContribution = Buffer.from(
      prepared.signing_worker_rerandomization_contribution32_b64u,
      'base64url',
    );
    assert.equal(serverContribution.length, 32);
    const clientSignatureShare = presign.client.compute_signature_share(
      presign.groupPublicKey,
      presign.clientBigR,
      signingDigestBytes,
      clientContribution,
      serverContribution,
    );
    assert.equal(clientSignatureShare.length, 32, 'ECDSA client signature share must be 32 bytes');
    const finalizeRequest = {
      scope: presign.scope,
      request_id: prepareRequest.request_id,
      operation_id: operationId,
      operation_digests: operationDigests,
      authorization,
      material_activation: materialActivation,
      expires_at_ms: expiresAtMs,
      signing_digest_b64u: prepareRequest.signing_digest_b64u,
      server_presignature_id: prepared.server_presignature_id,
      client_signature_share32_b64u: base64urlBytes(clientSignatureShare),
      client_rerandomization_contribution32_b64u: base64urlBytes(clientContribution),
      authorized_operation: {
        binding: acceptedBinding,
        authorized_operation: authorizedOperation,
      },
    };
    const finalizeResponse = await postWorkerJson(router, ecdsaSigningPath, finalizeRequest);
    const finalizeBytes = await expectOk(finalizeResponse, 'live ECDSA normal-signing finalize');
    const signed = JSON.parse(finalizeBytes.toString('utf8'));
    assert.equal(signed.request_id, finalizeRequest.request_id);
    assert.deepEqual(
      signed.scope.public_identity,
      ecdsa.identity,
      'ECDSA normal-signing finalize must preserve the activated public identity',
    );
    const signature = Buffer.from(signed.signature65_b64u, 'base64url');
    assert.equal(signature.length, 65, 'ECDSA normal-signing must return a recoverable signature');
    return { prepare: prepared, response: signed };
  } finally {
    presign.client.free();
  }
}

function buildEd25519ExecuteRequest(fixture, fixtureKey, tenantRoot) {
  const source = fixture[fixtureKey];
  assert.ok(source && typeof source === 'object', `${fixtureKey} fixture is required`);
  assert.ok(source.gateway_request, `${fixtureKey} gateway request is required`);
  assert.ok(
    source.application && typeof source.application === 'object',
    `${fixtureKey} server-resolved application facts are required`,
  );
  assert.ok(
    Array.isArray(source.participant_ids),
    `${fixtureKey} server-resolved participant ids are required`,
  );
  assert.equal(
    source.participant_ids.length,
    2,
    `${fixtureKey} must resolve exactly two Ed25519 participants`,
  );
  return {
    tenant_root: tenantRoot,
    application: source.application,
    participant_ids: source.participant_ids,
    target: source.gateway_request,
  };
}

function parseEd25519ActivationResult(bytes, label) {
  const result = JSON.parse(bytes.toString('utf8'));
  assert.equal(
    result.status,
    'succeeded',
    `${label} must succeed: ${JSON.stringify(result.error ?? result)}`,
  );
  assert.equal(result.result.operation, 'registration', `${label} must register a key`);
  const activation = result.result.result;
  assert.ok(activation && activation.public_receipt, `${label} must return a public receipt`);
  const publicReceipt = activation.public_receipt;
  assert.ok(
    Array.isArray(publicReceipt.registered_public_key) &&
      publicReceipt.registered_public_key.length === 32,
    `${label} must return a 32-byte Ed25519 public key`,
  );
  assert.ok(
    publicReceipt.registered_public_key.some((byte) => byte !== 0),
    `${label} Ed25519 public key must be nonzero`,
  );
  return { result, publicReceipt };
}

async function captureValidActivationDelivery(
  topology,
  fixture,
  tenantRoot,
  fixtureKey = 'activation',
  requireDelivery = true,
) {
  capturedSigningWorkerDelivery = undefined;
  const router = await topology.getWorker('router');
  const envelope = buildEd25519ExecuteRequest(fixture, fixtureKey, tenantRoot);
  const response = await postWorkerJson(
    router,
    ed25519ExecutePath,
    envelope,
  );
  const bytes = await expectOk(response, 'Router activation fixture execution');
  const { publicReceipt, result } = parseEd25519ActivationResult(
    bytes,
    'Router activation fixture execution',
  );
  if (requireDelivery) {
    assert.ok(capturedSigningWorkerDelivery, 'Router must deliver the activation package pair');
  }
  return {
    envelope,
    responseBytes: bytes,
    publicReceipt,
    result,
    delivery: capturedSigningWorkerDelivery,
  };
}

async function testTenantRootRefreshOperatingPath(topology, tenantRoot) {
  const router = await topology.getWorker('router');
  const response = await postWorkerJson(router, tenantRootRefreshPath, tenantRoot);
  const bytes = await expectOk(response, 'live tenant-root refresh');
  const refresh = JSON.parse(bytes.toString('utf8'));
  assert.equal(
    typeof refresh.activation_receipt_digest_b64u,
    'string',
    'tenant-root refresh must return its activation receipt digest',
  );
  assert.ok(
    Number.isInteger(refresh.lifecycle_revision) && refresh.lifecycle_revision > 0,
    'tenant-root refresh must advance the lifecycle revision',
  );
  return refresh;
}

async function captureEcdsaActivationAfterRefresh(topology, ecdsa) {
  const router = await topology.getWorker('router');
  const response = await postWorkerJson(router, ecdsaActivationPath, ecdsa.activationBody, {
    authorization: `Bearer ${ecdsa.token}`,
  });
  const bytes = await expectOk(response, 'ECDSA activation after tenant-root refresh');
  const activation = JSON.parse(bytes.toString('utf8'));
  assert.equal(activation.activated, true);
  return {
    bytes,
    activation,
    identityBytes: Buffer.from(
      JSON.stringify(activation.ecdsa_activation.public_identity),
      'utf8',
    ),
  };
}

async function testTenantRootSelectorIsolation(topology, fixture, tenantRoot) {
  const router = await topology.getWorker('router');
  const envelope = buildEd25519ExecuteRequest(fixture, 'activation', tenantRoot);
  const alternateTenantRoot = {
    identity_digest_b64u: tenantRoot.identity_digest_b64u,
    custody_lineage_b64u: Buffer.alloc(16, 0x9c).toString('base64url'),
  };
  capturedSigningWorkerDelivery = undefined;
  const rejected = await postWorkerJson(router, ed25519ExecutePath, {
    ...envelope,
    tenant_root: alternateTenantRoot,
  });
  const rejectedBody = await responseBytes(rejected);
  assert.notEqual(
    rejected.status,
    200,
    `an alternate tenant-root selector must not replay the first tenant: ${rejectedBody.toString(
      'utf8',
    )}`,
  );
  assert.equal(
    capturedSigningWorkerDelivery,
    undefined,
    'a rejected tenant-root selector must not reach SigningWorker activation',
  );

}

async function postSigningWorkerDelivery(worker, delivery) {
  return worker.fetch(
    'https://private.test/router-ab/signing-worker/ed25519-yao/activation/packages',
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [internalAuthHeader]: internalAuthSecret,
      },
      body: delivery,
    },
  );
}

async function testConcurrentActivationAndLostResponse(fixture, delivery) {
  const miniflare = new Miniflare({
    workers: [signingWorker('concurrent-signing-worker', 'concurrent-signing-worker-d1', fixture)],
  });
  try {
    await miniflare.ready;
    const database = await applyMigrations(
      miniflare,
      signingWorkerD1Binding,
      'concurrent-signing-worker',
      signingWorkerMigrationsPath,
    );
    const worker = await miniflare.getWorker('concurrent-signing-worker');
    const [firstResponse, concurrentResponse] = await Promise.all([
      postSigningWorkerDelivery(worker, delivery),
      postSigningWorkerDelivery(worker, delivery),
    ]);
    const first = await expectOk(firstResponse, 'first concurrent activation');
    const concurrent = await expectOk(concurrentResponse, 'second concurrent activation');
    assert.deepEqual(
      concurrent,
      first,
      'concurrent identical activation must return the exact committed response bytes',
    );

    const lostResponseReplay = await expectOk(
      await postSigningWorkerDelivery(worker, delivery),
      'lost-response activation replay',
    );
    assert.deepEqual(
      lostResponseReplay,
      first,
      'retry after a lost response must replay the exact committed response bytes',
    );
    const activationRows = await database
      .prepare('SELECT COUNT(*) AS count FROM signing_worker_activations')
      .first();
    assert.equal(activationRows.count, 1, 'concurrent activation must commit one material row');
  } finally {
    await miniflare.dispose();
  }
}

async function main() {
  const fixture = loadFixture();
  const jwtSigner = configureRouterJwt(fixture);
  const topology = new Miniflare({
    workers: [
      routerWorker(fixture),
      deriverAWorker(fixture),
      deriverBWorker(fixture),
      tenantRootControlPlaneWorker(fixture),
      signingWorker('fixture-signing-worker', 'fixture-signing-worker-d1', fixture),
      signingWorker(
        'fixture-signing-worker-after-refresh',
        'fixture-signing-worker-after-refresh-d1',
        fixture,
      ),
    ],
  });
  try {
    await topology.ready;
    const databases = {
      deriverA: await applyMigrations(topology, roleD1Binding, 'deriver-a', deriverAMigrationsPath),
      deriverB: await applyMigrations(topology, roleD1Binding, 'deriver-b', deriverBMigrationsPath),
    };
    await testTenantRootRoleSchema(databases.deriverA, 'deriver_a');
    await testTenantRootRoleSchema(databases.deriverB, 'deriver_b');
    await testTenantRootCommandReplayCasGuard(databases.deriverA, 'deriver_a');
    await testTenantRootCommandReplayCasGuard(databases.deriverB, 'deriver_b');
    const tenantRoot = await testTenantRootCreationOperatingPath(topology, fixture, databases);
    await applyMigrations(
      topology,
      signingWorkerD1Binding,
      'fixture-signing-worker',
      signingWorkerMigrationsPath,
    );
    await applyMigrations(
      topology,
      signingWorkerD1Binding,
      'fixture-signing-worker-after-refresh',
      signingWorkerMigrationsPath,
    );
    const ecdsa = await testEcdsaRegistrationAndActivation(topology, fixture, tenantRoot, jwtSigner);
    const edBeforeRefresh = await captureValidActivationDelivery(topology, fixture, tenantRoot);
    await testTenantRootRefreshOperatingPath(topology, tenantRoot);

    const ecdsaAfterRefresh = await captureEcdsaActivationAfterRefresh(topology, ecdsa);
    assert.deepEqual(
      ecdsaAfterRefresh.bytes,
      ecdsa.activationBytes,
      'ECDSA activation output must remain byte-identical after tenant-root refresh',
    );
    assert.deepEqual(
      ecdsaAfterRefresh.identityBytes,
      ecdsa.identityBytes,
      'ECDSA public identity bytes must remain identical after tenant-root refresh',
    );
    assert.deepEqual(
      ecdsaAfterRefresh.activation.ecdsa_activation.public_identity,
      ecdsa.identity,
      'ECDSA address and public keys must remain identical after tenant-root refresh',
    );

    signingWorkerDeliveryTarget = 'fixture-signing-worker-after-refresh';
    const edAfterRefresh = await captureValidActivationDelivery(
      topology,
      fixture,
      tenantRoot,
      'activation_after_refresh',
    );
    assert.deepEqual(
      edAfterRefresh.publicReceipt.registered_public_key,
      edBeforeRefresh.publicReceipt.registered_public_key,
      'Ed25519 public key must remain identical after tenant-root refresh',
    );
    signingWorkerDeliveryTarget = 'fixture-signing-worker';
    await testEcdsaNormalSigning(topology, ecdsa);
    await testTenantRootSelectorIsolation(topology, fixture, tenantRoot);
    await testConcurrentActivationAndLostResponse(fixture, edBeforeRefresh.delivery);
  } finally {
    await topology.dispose();
  }
  console.log('real workerd D1 tenant-root refresh and signing continuity tests passed');
}

await main();
