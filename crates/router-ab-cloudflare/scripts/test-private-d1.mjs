import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare } from 'miniflare';

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const repoRoot = resolve(packageRoot, '../..');
const internalAuthHeader = 'x-router-ab-internal-service-auth';
const internalAuthSecret = 'private-d1-integration-auth';
const roleD1Binding = 'DERIVER_ROLE_PRIVATE_DB';
const signingWorkerD1Binding = 'SIGNING_WORKER_PRIVATE_DB';
const roleSchemaPath = join(packageRoot, 'migrations/deriver-a/0001_role_private_storage.sql');
const signingWorkerSchemaPath = join(
  packageRoot,
  'migrations/signing-worker/0001_private_storage.sql',
);
let capturedSigningWorkerDelivery;

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
    ...strictWorker('deriver-a', 'deriver-a', fixture.deriver_a_env),
    d1Databases: { [roleD1Binding]: 'deriver-a-private-d1' },
    serviceBindings: { DERIVER_B: 'deriver-b' },
  };
}

function deriverBWorker(fixture) {
  return {
    ...strictWorker('deriver-b', 'deriver-b', fixture.deriver_b_env),
    d1Databases: { [roleD1Binding]: 'deriver-b-private-d1' },
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
    serviceBindings: {
      DERIVER_A: 'deriver-a',
      DERIVER_B: 'deriver-b',
      SIGNING_WORKER: captureSigningWorkerDelivery,
    },
  };
}

async function captureSigningWorkerDelivery(request, miniflare) {
  capturedSigningWorkerDelivery = await request.clone().text();
  const worker = await miniflare.getWorker('fixture-signing-worker');
  return worker.fetch(request);
}

async function applySchema(miniflare, binding, workerName, schemaPath) {
  const database = await miniflare.getD1Database(binding, workerName);
  const statements = (await readFile(schemaPath, 'utf8'))
    .split(';')
    .map((statement) => statement.trim())
    .filter(Boolean)
    .map((statement) => database.prepare(statement));
  await database.batch(statements);
  return database;
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

  const aRows = await databases.deriverA.prepare('SELECT COUNT(*) AS count FROM yao_pair_sessions').first();
  const bRowsBefore = await databases.deriverB.prepare('SELECT COUNT(*) AS count FROM yao_pair_sessions').first();
  assert.equal(aRows.count, 1, 'Deriver A must commit one private-D1 role row');
  assert.equal(bRowsBefore.count, 0, 'Deriver B must remain incomplete during the partial response');

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

  const conflict = await postWorkerJson(
    deriverA,
    prepareAPath,
    request.conflicting_prepare_a,
  );
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
    const database = await applySchema(
      miniflare,
      signingWorkerD1Binding,
      'concurrent-signing-worker',
      signingWorkerSchemaPath,
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
      signingWorker('fixture-signing-worker', 'fixture-signing-worker-d1', fixture),
    ],
  });
  try {
    await topology.ready;
    const databases = {
      deriverA: await applySchema(topology, roleD1Binding, 'deriver-a', roleSchemaPath),
      deriverB: await applySchema(topology, roleD1Binding, 'deriver-b', roleSchemaPath),
    };
    await applySchema(
      topology,
      signingWorkerD1Binding,
      'fixture-signing-worker',
      signingWorkerSchemaPath,
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
