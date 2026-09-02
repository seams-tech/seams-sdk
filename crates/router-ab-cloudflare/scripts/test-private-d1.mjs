import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

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
let capturedSigningWorkerDelivery;
let dropNextTenantRootPeerResponse = false;
const tenantRootRoleIntegrationPath = '/router-ab/deriver/tenant-root-role-d1/integration';

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
    serviceBindings: { DERIVER_B: forwardDeriverBWithOptionalLostResponse },
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
  const worker = await miniflare.getWorker('fixture-signing-worker');
  return worker.fetch(request);
}

async function forwardDeriverBWithOptionalLostResponse(request, miniflare) {
  const worker = await miniflare.getWorker('deriver-b');
  const response = await worker.fetch(request);
  if (
    dropNextTenantRootPeerResponse &&
    new URL(request.url).pathname === tenantRootRoleCreationPath &&
    response.ok
  ) {
    dropNextTenantRootPeerResponse = false;
    return new Response('simulated lost Deriver B response', { status: 503 });
  }
  return response;
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

function authenticatedJsonRequest(body) {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      [internalAuthHeader]: internalAuthSecret,
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

async function postWorkerJson(worker, path, body) {
  return worker.fetch(`https://private.test${path}`, authenticatedJsonRequest(body));
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

/// The rotation lifecycle scenario cannot run until activation evidence exists.
///
/// `tenant_root_role_d1_integration_activation` is still a stub that always
/// fails, so this asserts the exact gap instead of skipping silently: when
/// activation lands, this assertion breaks and forces the real lifecycle
/// assertions below to be re-enabled.
const TENANT_ROOT_LIFECYCLE_PENDING_ACTIVATION_MESSAGE =
  'tenant-root role-private D1 integration requires a verified activation evidence bundle';

async function assertTenantRootRoleLifecyclePendingActivation(worker, expectedRole) {
  const response = await postWorkerJson(worker, tenantRootRoleIntegrationPath, {
    kind: 'run_lifecycle',
  });
  const body = (await responseBytes(response)).toString('utf8');
  assert.equal(
    response.status,
    500,
    `${expectedRole} rotation lifecycle unexpectedly succeeded; re-enable runTenantRootRoleLifecycle: ${body}`,
  );
  assert.ok(
    body.includes(TENANT_ROOT_LIFECYCLE_PENDING_ACTIVATION_MESSAGE),
    `${expectedRole} rotation lifecycle failed for an unexpected reason: ${body}`,
  );
}

// eslint-disable-next-line no-unused-vars -- re-enabled once activation evidence lands.
async function runTenantRootRoleLifecycle(worker, expectedRole) {
  const response = await postWorkerJson(worker, tenantRootRoleIntegrationPath, {
    kind: 'run_lifecycle',
  });
  const bytes = await expectOk(response, `${expectedRole} Rust role-store lifecycle`);
  const receipt = JSON.parse(bytes.toString('utf8'));
  const commandReceiptDigestHex = createHash('sha256')
    .update('{"kind":"r120_role_command_completed"}')
    .digest('hex');
  assert.deepEqual(receipt, {
    role: expectedRole,
    retiredEpoch: 1,
    retiredRevision: 3,
    activeEpoch: 2,
    activeRevision: 2,
    cleanupEpoch: 3,
    commandReceiptDigestHex,
  });
}

async function testTenantRootCreationOperatingPath(topology, fixture, databases) {
  const router = await topology.getWorker('router');
  dropNextTenantRootPeerResponse = true;
  const interrupted = await postWorkerJson(
    router,
    tenantRootCreationPath,
    fixture.tenant_root_creation.interrupted,
  );
  const interruptedBody = (await responseBytes(interrupted)).toString('utf8');
  assert.notEqual(
    interrupted.status,
    200,
    `simulated lost peer response must interrupt the creation: ${interruptedBody}`,
  );
  assert.equal(dropNextTenantRootPeerResponse, false, 'the simulated loss must be consumed once');

  const strandedA = await databases.deriverA
    .prepare("SELECT COUNT(*) AS count FROM tenant_root_role_shares WHERE lifecycle = 'pending'")
    .first();
  const strandedB = await databases.deriverB
    .prepare("SELECT COUNT(*) AS count FROM tenant_root_role_shares WHERE lifecycle = 'pending'")
    .first();
  assert.equal(strandedA.count, 0, 'A must not persist after losing the peer response');
  assert.equal(strandedB.count, 1, 'B must persist before its response is lost');

  const backupBucketA = await topology.getR2Bucket(managedBackupR2Binding, 'deriver-a');
  const backupBucketB = await topology.getR2Bucket(managedBackupR2Binding, 'deriver-b');
  assert.equal((await backupBucketA.list()).objects.length, 0);
  assert.equal((await backupBucketB.list()).objects.length, 1);

  const cleanup = await postWorkerJson(
    router,
    tenantRootCreationPath,
    fixture.tenant_root_creation.interrupted,
  );
  const cleanupBody = (await responseBytes(cleanup)).toString('utf8');
  assert.notEqual(cleanup.status, 200, 'the abandoned lineage must require a fresh grant');
  assert.match(cleanupBody, /fresh grant is required/u);
  assert.equal(
    (
      await databases.deriverB
        .prepare(
          "SELECT COUNT(*) AS count FROM tenant_root_role_shares WHERE lifecycle = 'pending'",
        )
        .first()
    ).count,
    0,
    "authorized cleanup must remove B's exact pending row",
  );
  assert.equal(
    (await backupBucketB.list()).objects.length,
    0,
    "authorized cleanup must remove B's exact managed backup",
  );

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

  const deriverA = await topology.getWorker('deriver-a');
  const deriverB = await topology.getWorker('deriver-b');
  await assertTenantRootRoleLifecyclePendingActivation(deriverA, 'deriver_a');
  await assertTenantRootRoleLifecyclePendingActivation(deriverB, 'deriver_b');

  const pendingA = await databases.deriverA
    .prepare(
      `SELECT tenant_identity_digest_hex, custody_lineage_b64u, ciphertext_json
       FROM tenant_root_role_shares WHERE role = 'deriver_a' AND lifecycle = 'pending'`,
    )
    .first();
  const pendingB = await databases.deriverB
    .prepare(
      `SELECT tenant_identity_digest_hex, custody_lineage_b64u, ciphertext_json
       FROM tenant_root_role_shares WHERE role = 'deriver_b' AND lifecycle = 'pending'`,
    )
    .first();
  assert.equal(pendingA.tenant_identity_digest_hex, pendingB.tenant_identity_digest_hex);
  assert.equal(pendingA.custody_lineage_b64u, pendingB.custody_lineage_b64u);
  assert.notEqual(
    pendingA.ciphertext_json,
    pendingB.ciphertext_json,
    'Deriver A and B must independently encrypt their shares for the same tenant root',
  );
}

async function testRolePrivateD1RetryAndConvergence(topology, fixture, databases) {
  const deriverA = await topology.getWorker('deriver-a');
  const deriverB = await topology.getWorker('deriver-b');
  const request = fixture.role_retry;
  const prepareAPath = '/router-ab/deriver-a/ed25519-yao/prepare-pair';
  const prepareBPath = '/router-ab/deriver-b/ed25519-yao/prepare-pair';

  const firstA = await expectOk(
    await postWorkerJson(deriverA, prepareAPath, request.prepare_a),
    'first Deriver A preparation',
  );
  const retryA = await expectOk(
    await postWorkerJson(deriverA, prepareAPath, request.prepare_a),
    'identical Deriver A retry',
  );
  assert.deepEqual(retryA, firstA, 'identical role retry must return the exact receipt bytes');

  const aRows = await databases.deriverA
    .prepare('SELECT COUNT(*) AS count FROM yao_pair_sessions')
    .first();
  const bRowsBefore = await databases.deriverB
    .prepare('SELECT COUNT(*) AS count FROM yao_pair_sessions')
    .first();
  assert.equal(aRows.count, 1, 'Deriver A must commit one private-D1 role row');
  assert.equal(
    bRowsBefore.count,
    0,
    'Deriver B must remain incomplete during the partial response',
  );

  const firstB = await expectOk(
    await postWorkerJson(deriverB, prepareBPath, request.prepare_b),
    'Deriver B convergence preparation',
  );
  const retryB = await expectOk(
    await postWorkerJson(deriverB, prepareBPath, request.prepare_b),
    'identical Deriver B retry',
  );
  const convergedA = await expectOk(
    await postWorkerJson(deriverA, prepareAPath, request.prepare_a),
    'Deriver A retry after peer convergence',
  );
  assert.deepEqual(retryB, firstB, 'Deriver B retry must return the exact receipt bytes');
  assert.deepEqual(convergedA, firstA, 'partial-role convergence must preserve Deriver A result');

  const conflict = await postWorkerJson(deriverA, prepareAPath, request.conflicting_prepare_a);
  const conflictBody = await responseBytes(conflict);
  assert.equal(conflict.status, 409, conflictBody.toString('utf8'));
  assert.equal(
    conflictBody.toString('utf8'),
    '{"status":"rejected","code":"terminal_role_failure"}',
    'same-session conflicting fingerprint must fail before execution',
  );
}

async function captureValidActivationDelivery(topology, fixture) {
  capturedSigningWorkerDelivery = undefined;
  const router = await topology.getWorker('router');
  const response = await postWorkerJson(
    router,
    '/router-ab/router/ed25519-yao/execute',
    fixture.activation.gateway_request,
  );
  await expectOk(response, 'Router activation fixture execution');
  assert.ok(capturedSigningWorkerDelivery, 'Router must deliver the activation package pair');
  return capturedSigningWorkerDelivery;
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
  const topology = new Miniflare({
    workers: [
      routerWorker(fixture),
      deriverAWorker(fixture),
      deriverBWorker(fixture),
      tenantRootControlPlaneWorker(fixture),
      signingWorker('fixture-signing-worker', 'fixture-signing-worker-d1', fixture),
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
    await testTenantRootCreationOperatingPath(topology, fixture, databases);
    await applyMigrations(
      topology,
      signingWorkerD1Binding,
      'fixture-signing-worker',
      signingWorkerMigrationsPath,
    );
    await testRolePrivateD1RetryAndConvergence(topology, fixture, databases);
    const delivery = await captureValidActivationDelivery(topology, fixture);
    await testConcurrentActivationAndLostResponse(fixture, delivery);
  } finally {
    await topology.dispose();
  }
  console.log('real workerd D1 role retry and concurrent activation tests passed');
}

await main();
