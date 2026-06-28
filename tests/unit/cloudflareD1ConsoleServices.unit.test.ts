import { expect, test } from '@playwright/test';
import type { SigningRootKekProvider } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type { RouterAbNormalSigningAdmissionInput } from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import {
  createCloudflareD1ConsoleOnlyServiceBundle,
  createCloudflareD1ConsoleServiceBundle,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1ConsoleServices';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type { CfExecutionContext } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import localD1DevWorker from '../../packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker';
import type { SponsoredEvmCallExecutorConfig } from '../../packages/sdk-server-ts/src/sponsorship/evmExecutorTypes';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';

type LocalD1WorkflowEnv = Parameters<typeof localD1DevWorker.fetch>[1];
type JsonRecord = Record<string, unknown>;

class FakeD1PreparedStatement implements D1PreparedStatementLike {
  constructor(private readonly query: string) {}

  bind(): D1PreparedStatementLike {
    return this;
  }

  async first<T = unknown>(): Promise<T | null> {
    return firstFakeD1Row<T>(this.query);
  }

  async all<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
    };
  }

  async run<T = unknown>(): Promise<D1ResultLike<T>> {
    return {
      success: true,
      results: [] as readonly T[],
      meta: { changes: 0, rows_written: 0 },
    };
  }
}

class FakeD1Database implements D1DatabaseLike {
  readonly queries: string[] = [];

  prepare(query: string): D1PreparedStatementLike {
    this.queries.push(query);
    return new FakeD1PreparedStatement(query);
  }

  async batch<T = unknown>(): Promise<readonly T[]> {
    return [];
  }

  async exec(): Promise<unknown> {
    return null;
  }
}

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

class MemoryDurableObjectStorage implements TestDurableObjectStorageLike {
  private readonly values = new Map<string, unknown>();
  private transactionTail: Promise<void> = Promise.resolve();

  async get(key: string): Promise<unknown> {
    return this.values.get(key) ?? null;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.values.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.values.delete(key);
  }

  async transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T> {
    const run = runSerializedStorageTransaction(this.transactionTail, this, fn);
    this.transactionTail = settleStorageTransaction(run);
    return await run;
  }
}

class MemoryDurableObjectStub implements CloudflareDurableObjectStubLike {
  private readonly durableObject: ThresholdStoreDurableObject;

  constructor() {
    this.durableObject = new ThresholdStoreDurableObject(
      { storage: new MemoryDurableObjectStorage() },
      {},
    );
  }

  fetch(request: RequestInfo, init?: RequestInit): Promise<Response> {
    return this.durableObject.fetch(
      request instanceof Request ? request : new Request(request, init),
    );
  }
}

class MemoryDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  private readonly objects = new Map<string, CloudflareDurableObjectStubLike>();

  idFromName(name: string): string {
    return name;
  }

  get(id: unknown): CloudflareDurableObjectStubLike {
    const key = String(id);
    const existing = this.objects.get(key);
    if (existing) return existing;
    const stub = new MemoryDurableObjectStub();
    this.objects.set(key, stub);
    return stub;
  }
}

function createSponsoredEvmCallExecutorConfig(): SponsoredEvmCallExecutorConfig {
  return {
    executorsByChain: new Map([
      [
        42_431,
        {
          chainId: 42_431,
          rpcUrl: 'https://rpc.example.test',
          sponsorAddress: '0x2222222222222222222222222222222222222222',
          sponsorPrivateKeyHex:
            '0x1111111111111111111111111111111111111111111111111111111111111111',
          maxPriorityFeePerGasFloor: 2_000_000_000n,
          maxFeePerGasFloor: 40_000_000_000n,
        },
      ],
    ]),
  };
}

function createLocalSponsoredEvmExecutorsJson(): string {
  return JSON.stringify({
    '42431': {
      sponsorPrivateKeyHex:
        '0x1111111111111111111111111111111111111111111111111111111111111111',
      rpcUrl: 'https://rpc.example.test',
    },
  });
}

async function runSerializedStorageTransaction<T>(
  previous: Promise<void>,
  storage: TestDurableObjectStorageLike,
  fn: (txn: TestDurableObjectStorageLike) => Promise<T>,
): Promise<T> {
  await previous;
  return await fn(storage);
}

function settleStorageTransaction<T>(promise: Promise<T>): Promise<void> {
  return promise.then(noop, noop);
}

function noop(): void {}

function firstFakeD1Row<T>(query: string): T | null {
  if (query.includes('sqlite_master') && query.includes('console_runtime_snapshot_outbox')) {
    return { table_count: 40 } as T;
  }
  if (query.includes('sqlite_master') && query.includes('signer_email_otp_registration_attempts')) {
    return { table_count: 21 } as T;
  }
  return null;
}

function createFakeExecutionContext(): CfExecutionContext {
  return {
    waitUntil,
    passThroughOnException,
  };
}

function waitUntil(_promise: Promise<unknown>): void {}

function passThroughOnException(): void {}

function createKekProvider(): SigningRootKekProvider {
  return {
    kind: 'worker_secret',
    workerSecretsByKekId: {
      'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
    encoding: 'base64url',
  };
}

function createAdmissionInput(): RouterAbNormalSigningAdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'alice.testnet',
    rpId: 'example.localhost',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
    requestId: 'request-1',
    expiresAtMs: Date.now() + 60_000,
    signingWorkerId: 'signing-worker-a',
    runtimePolicyScope: {
      orgId: 'org_1',
      projectId: 'project_1',
      envId: 'env_1',
      signingRootVersion: 'root-v1',
    },
  };
}

function createLocalD1WorkflowEnv(input: {
  readonly consoleDatabase: D1DatabaseLike;
  readonly signerDatabase: D1DatabaseLike;
}): LocalD1WorkflowEnv {
  return {
    CONSOLE_DB: input.consoleDatabase,
    SIGNER_DB: input.signerDatabase,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-workflow-smoke',
    SEAMS_LOCAL_CONSOLE_USER_ID: 'local-workflow-user',
    SEAMS_LOCAL_CONSOLE_ORG_ID: 'org-local-workflow',
    SEAMS_LOCAL_CONSOLE_PROJECT_ID: 'project-local-workflow',
    SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID: 'env-local-workflow',
    SEAMS_LOCAL_CONSOLE_ROLES:
      'owner,admin,platform_admin,billing_admin,ops,developer,security_admin',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    ACCOUNT_ID_DERIVATION_SECRET: 'local-workflow-account-id-derivation-secret',
  };
}

function createLocalWorkflowRequest(input: {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly body?: JsonRecord;
  readonly headers?: HeadersInit;
}): Request {
  const headers = new Headers(input.headers);
  let body: string | undefined;
  if (input.body) {
    body = JSON.stringify(input.body);
    if (!headers.has('content-type')) headers.set('content-type', 'application/json');
  }
  return new Request(`http://127.0.0.1:8787${input.path}`, {
    method: input.method,
    headers,
    body,
  });
}

async function callLocalWorkflowWorker(
  env: LocalD1WorkflowEnv,
  input: {
    readonly method: 'GET' | 'POST';
    readonly path: string;
    readonly body?: JsonRecord;
    readonly headers?: HeadersInit;
  },
): Promise<Response> {
  return await localD1DevWorker.fetch(
    createLocalWorkflowRequest(input),
    env,
    createFakeExecutionContext(),
  );
}

async function readJsonRecord(response: Response): Promise<JsonRecord> {
  const parsed: unknown = await response.json();
  if (!isJsonRecord(parsed)) {
    throw new Error(`Expected JSON object response, got ${typeof parsed}`);
  }
  return parsed;
}

function jsonRecordField(record: JsonRecord, key: string): JsonRecord {
  const value = record[key];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object field ${key}`);
  }
  return value;
}

function jsonArrayField(record: JsonRecord, key: string): readonly unknown[] {
  const value = record[key];
  if (!Array.isArray(value)) {
    throw new Error(`Expected JSON array field ${key}`);
  }
  return value;
}

function jsonRecordAt(items: readonly unknown[], index: number): JsonRecord {
  const value = items[index];
  if (!isJsonRecord(value)) {
    throw new Error(`Expected JSON object at array index ${index}`);
  }
  return value;
}

function booleanField(record: JsonRecord, key: string): boolean {
  const value = record[key];
  if (typeof value !== 'boolean') {
    throw new Error(`Expected boolean field ${key}`);
  }
  return value;
}

function numberField(record: JsonRecord, key: string): number {
  const value = Number(record[key]);
  if (!Number.isFinite(value)) {
    throw new Error(`Expected finite numeric field ${key}`);
  }
  return value;
}

function isJsonRecord(value: unknown): value is JsonRecord {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

test('Cloudflare D1 service bundle wires DO-backed normal-signing admission into relay options', async () => {
  const database = new FakeD1Database();
  const sponsorshipPricing = {
    async estimateSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
    async finalizeSponsoredExecutionSpend() {
      return {
        spendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
  };
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
      thresholdStore: new MemoryDurableObjectNamespace(),
      kekProvider: createKekProvider(),
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsorshipPricing,
    },
  });

  const admission = bundle.routerApiRouterOptions.routerAbNormalSigningAdmission;
  const input = createAdmissionInput();

  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('signedDelegate');
  expect(bundle.routerApiRouterOptions.sponsorship).toMatchObject({
    spendCaps: bundle.spendCaps,
    pricing: sponsorshipPricing,
    prepaidReservations: bundle.prepaidReservations,
  });
  expect(bundle.routerApiRouterOptions).not.toHaveProperty('sponsoredEvmCall');
  expect(bundle.routerApiRouterOptions.bootstrapTokenStore).toBe(bundle.bootstrapTokens);
  expect(bundle.routerApiRouterOptions.orgProjectEnv).toBe(bundle.orgProjectEnv);
  expect(bundle.routerApiRouterOptions.wallets).toBe(bundle.wallets);
  expect(bundle.routerApiRouterOptions.observabilityIngestion).toBe(bundle.observabilityIngestion);
  expect(typeof bundle.routerApiRouterOptions.apiKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.routerApiRouterOptions.publishableKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.routerApiRouterOptions.apiKeyUsageMeter.recordEvent).toBe('function');
  expect(typeof bundle.routerApiRouterOptions.bootstrapGrantBroker.authenticatePublishableKey).toBe(
    'function',
  );
});

test('Cloudflare D1 console-only bundle omits signer custody bindings', async () => {
  const database = new FakeD1Database();
  const bundle = await createCloudflareD1ConsoleOnlyServiceBundle({
    bindings: {
      consoleDatabase: database,
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
    },
  });

  expect(bundle).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle).not.toHaveProperty('routerApiRouterOptions');
  expect(bundle).not.toHaveProperty('bootstrapTokens');
  expect(bundle).not.toHaveProperty('spendCaps');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageRouteResolver');
  expect(bundle.consoleRouterOptions).not.toHaveProperty('tenantStorageNamespace');
  expect(bundle.consoleRouterOptions.keyExports).toBe(bundle.keyExports);
  expect(bundle.consoleRouterOptions.billing).toBe(bundle.billing);
  expect(bundle.consoleRouterOptions.sponsoredCalls).toBe(bundle.sponsoredCalls);
});

test('D1 relay storage options expose sponsored EVM only with executor config', async () => {
  const database = new FakeD1Database();
  const sponsoredEvmCallConfig = createSponsoredEvmCallExecutorConfig();
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: database,
      signerMetadataDatabase: database,
      thresholdStore: new MemoryDurableObjectNamespace(),
      kekProvider: createKekProvider(),
    },
    route: {
      namespace: 'seams',
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });

  expect(bundle.routerApiRouterOptions.sponsoredEvmCall).toMatchObject({
    billing: bundle.billing,
    ledger: bundle.sponsoredCalls,
    runtimeSnapshots: bundle.runtimeSnapshots,
    config: sponsoredEvmCallConfig,
  });
  expect(bundle.routerApiRouterOptions.sponsoredEvmCall?.publishableKeyAuth).toBe(
    bundle.routerApiRouterOptions.publishableKeyAuth,
  );
});

test('local D1 Worker ready smoke validates D1 tables and DO admission', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/readyz'),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    backend: 'cloudflare_d1_do',
    namespace: 'seams-local-test',
    schemas: {
      consoleTables: 40,
      signerTables: 21,
    },
    admission: {
      durableObject: 'configured',
      quotaReservation: 'accepted',
    },
  });
});

test('local D1 Worker routes smoke requests through the Router API handler', async () => {
  const database = new FakeD1Database();
  const env = {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
  };
  const ctx = createFakeExecutionContext();

  const health = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/healthz'),
    env,
    ctx,
  );
  expect(health.status).toBe(200);
  await expect(health.json()).resolves.toMatchObject({
    ok: true,
    thresholdEd25519: { configured: true },
    cors: {
      allowedOrigins: [
        'http://127.0.0.1:9090',
        'http://localhost:9090',
        'http://127.0.0.1:8787',
        'http://localhost:8787',
      ],
    },
  });

  const emailRecovery = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/email-recovery/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    env,
    ctx,
  );
  expect(emailRecovery.status).toBe(404);

  const ed25519Prepare = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/wallets/register/prepare', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    env,
    ctx,
  );
  expect(ed25519Prepare.status).toBe(404);

  const sponsored = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'project_local:local',
        walletId: 'wallet_local_1',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 1,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'intent_local_1',
      }),
    }),
    env,
    ctx,
  );
  expect(sponsored.status).toBe(404);

  const bootstrapGrant = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/v1/registration/bootstrap-grants', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'https://localhost:8443',
      },
      body: JSON.stringify({
        environmentId: 'project_local:local',
        rpId: 'localhost',
        flow: 'registration_v1',
      }),
    }),
    env,
    ctx,
  );
  expect(bootstrapGrant.status).toBe(401);
  await expect(bootstrapGrant.json()).resolves.toMatchObject({
    ok: false,
    code: 'publishable_key_missing',
  });
});

test('local D1 Worker mounts sponsored EVM Router API route when local executor config is present', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/sponsorships/evm/call', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        environmentId: 'local',
        walletId: 'local.sponsored.testnet',
        walletAddress: '0x1111111111111111111111111111111111111111',
        chainId: 42_431,
        call: {
          to: '0x2222222222222222222222222222222222222222',
          data: '0x12345678',
          gasLimit: '21000',
          value: '0',
        },
        idempotencyKey: 'local-sponsored-route-mounted',
      }),
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      SPONSORED_EVM_EXECUTORS_JSON: createLocalSponsoredEvmExecutorsJson(),
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(401);
  await expect(response.json()).resolves.toMatchObject({
    ok: false,
    code: 'publishable_key_missing',
  });
});

test('local D1 Worker runs a representative signer smoke through relay prefix', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/relay/auth/passkey/options', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://127.0.0.1:8787',
      },
      body: JSON.stringify({
        user_id: 'alice.testnet',
        rp_id: 'localhost',
      }),
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
  });
  expect(
    database.queries.some((query) => query.includes('INSERT INTO signer_webauthn_challenges')),
  ).toBe(true);
});

test('local D1 Worker serves console routes through D1 console services', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:8787/console/readyz', {
      headers: {
        'x-console-user-id': 'local-user',
        'x-console-org-id': 'local-org',
        'x-console-roles': 'owner,admin',
      },
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    service: 'console',
  });
});

test('local D1 Worker serves dashboard Google options at the root auth path', async () => {
  const database = new FakeD1Database();
  const response = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/auth/google/options', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
    {
      CONSOLE_DB: database,
      SIGNER_DB: database,
      THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
      SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
      GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
    },
    createFakeExecutionContext(),
  );

  expect(response.status).toBe(200);
  await expect(response.json()).resolves.toMatchObject({
    ok: true,
    configured: true,
    clientId: 'local-google-client.apps.googleusercontent.com',
  });
});

test('local D1 Worker routes dashboard session exchange and state at root paths', async () => {
  const database = new FakeD1Database();
  const env = {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: new MemoryDurableObjectNamespace(),
    SEAMS_TENANT_STORAGE_NAMESPACE: 'seams-local-test',
    GOOGLE_OIDC_CLIENT_ID: 'local-google-client.apps.googleusercontent.com',
  };
  const ctx = createFakeExecutionContext();

  const exchange = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/exchange', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        session_kind: 'cookie',
        exchange: {
          type: 'oidc_jwt',
          provider: 'google',
          token: 'not-a-jwt',
        },
      }),
    }),
    env,
    ctx,
  );
  expect(exchange.status).toBe(400);
  await expect(exchange.json()).resolves.toMatchObject({
    ok: false,
    code: 'invalid_body',
    message: 'id_token must be a JWT (3 segments)',
  });

  const state = await localD1DevWorker.fetch(
    new Request('http://127.0.0.1:9090/session/state'),
    env,
    ctx,
  );
  expect(state.status).toBe(401);
  await expect(state.json()).resolves.toMatchObject({
    authenticated: false,
    code: 'unauthorized',
  });
});

test('local D1 Worker serves dashboard onboarding state through D1 services', async () => {
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const response = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/onboarding/state',
    });

    expect(response.status).toBe(200);
    await expect(readJsonRecord(response)).resolves.toMatchObject({
      ok: true,
      state: {
        orgId: 'org-local-workflow',
        hasOrganization: false,
        hasProject: false,
        hasEnvironment: false,
        onboardingComplete: false,
        currentStep: 'organization',
      },
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});

test('local D1 Worker runs dashboard, signer, billing, and reconciliation smoke on real D1', async () => {
  test.setTimeout(60_000);
  const consoleTemp = createTemporaryD1Database();
  const signerTemp = createTemporaryD1Database();

  try {
    await applyD1MigrationFiles(consoleTemp.database, listD1MigrationFiles('d1-console'));
    await applyD1MigrationFiles(signerTemp.database, listD1MigrationFiles('d1-signer'));
    const env = createLocalD1WorkflowEnv({
      consoleDatabase: consoleTemp.database,
      signerDatabase: signerTemp.database,
    });

    const readyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/readyz',
    });
    expect(readyResponse.status).toBe(200);
    await expect(readJsonRecord(readyResponse)).resolves.toMatchObject({
      ok: true,
      backend: 'cloudflare_d1_do',
      namespace: 'seams-local-workflow-smoke',
      schemas: {
        consoleTables: 40,
        signerTables: 21,
      },
      admission: {
        durableObject: 'configured',
        quotaReservation: 'accepted',
      },
    });

    const consoleReadyResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/readyz',
    });
    expect(consoleReadyResponse.status).toBe(200);
    await expect(readJsonRecord(consoleReadyResponse)).resolves.toMatchObject({
      ok: true,
      service: 'console',
    });

    const supportCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(supportCreditResponse.status).toBe(201);
    const supportCredit = jsonRecordField(await readJsonRecord(supportCreditResponse), 'result');
    expect(booleanField(supportCredit, 'created')).toBe(true);
    expect(numberField(jsonRecordField(supportCredit, 'adjustment'), 'amountMinor')).toBe(5000);

    const duplicateCreditResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'local_workflow_smoke_credit',
        note: 'Seed local D1 workflow smoke prepaid balance',
        idempotencyKey: 'local-workflow-smoke-credit',
      },
    });
    expect(duplicateCreditResponse.status).toBe(200);
    const duplicateCredit = jsonRecordField(
      await readJsonRecord(duplicateCreditResponse),
      'result',
    );
    expect(booleanField(duplicateCredit, 'created')).toBe(false);

    const overviewResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overviewResponse.status).toBe(200);
    const overview = jsonRecordField(await readJsonRecord(overviewResponse), 'overview');
    expect(numberField(overview, 'creditBalanceMinor')).toBe(5000);

    const activityResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/account/activity?limit=5',
    });
    expect(activityResponse.status).toBe(200);
    const activity = jsonRecordField(await readJsonRecord(activityResponse), 'activity');
    const entries = jsonArrayField(activity, 'entries');
    expect(entries).toHaveLength(1);
    expect(numberField(jsonRecordAt(entries, 0), 'amountMinor')).toBe(5000);

    const signerResponse = await callLocalWorkflowWorker(env, {
      method: 'POST',
      path: '/relay/auth/passkey/options',
      headers: {
        origin: 'http://127.0.0.1:8787',
      },
      body: {
        user_id: 'local.workflow.testnet',
        rp_id: 'localhost',
      },
    });
    expect(signerResponse.status).toBe(200);
    await expect(readJsonRecord(signerResponse)).resolves.toMatchObject({
      ok: true,
    });

    const sponsoredHistoryResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions',
    });
    expect(sponsoredHistoryResponse.status).toBe(200);
    const sponsoredHistoryPage = jsonRecordField(
      await readJsonRecord(sponsoredHistoryResponse),
      'page',
    );
    expect(jsonArrayField(sponsoredHistoryPage, 'items')).toHaveLength(0);

    const reconciliationResponse = await callLocalWorkflowWorker(env, {
      method: 'GET',
      path: '/console/billing/sponsored-executions/reconciliation',
    });
    expect(reconciliationResponse.status).toBe(200);
    const reconciliationPage = jsonRecordField(
      await readJsonRecord(reconciliationResponse),
      'page',
    );
    expect(jsonArrayField(reconciliationPage, 'items')).toHaveLength(0);
    expect(jsonRecordField(reconciliationPage, 'summary')).toMatchObject({
      matchedCount: 0,
      missingBillingDebitCount: 0,
      amountMismatchCount: 0,
      unexpectedBillingDebitCount: 0,
    });
  } finally {
    cleanupTemporaryD1Database(consoleTemp.tempDir);
    cleanupTemporaryD1Database(signerTemp.tempDir);
  }
});
