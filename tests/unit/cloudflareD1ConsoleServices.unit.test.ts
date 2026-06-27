import { expect, test } from '@playwright/test';
import type { SigningRootKekProvider } from '../../packages/sdk-server-ts/src/core/ThresholdService/signingRootKekProvider';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type { RouterAbNormalSigningAdmissionInput } from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';
import { createCloudflareD1ConsoleServiceBundle } from '../../packages/sdk-server-ts/src/router/cloudflare/d1ConsoleServices';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type { CfExecutionContext } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import localD1DevWorker from '../../packages/sdk-server-ts/src/router/cloudflare/d1LocalDevWorker';

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
  prepare(query: string): D1PreparedStatementLike {
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
    return { table_count: 20 } as T;
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

test('Cloudflare D1 service bundle wires DO-backed normal-signing admission into relay options', async () => {
  const database = new FakeD1Database();
  const sponsorshipPricing = {
    async estimateSponsoredExecutionSpend() {
      return {
        estimatedSpendMinor: 1,
        pricingVersion: 'test-pricing-v1',
      };
    },
    async finalizeSponsoredExecutionSpend() {
      return {
        settledSpendMinor: 1,
        pricingVersion: 'test-pricing-v1',
        usedEstimatedFallback: false,
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
      signedDelegateRoute: '/d1-signed-delegate',
      sponsorshipPricing,
      sponsoredEvmCallConfig: null,
    },
  });

  const admission = bundle.relayRouterOptions.routerAbNormalSigningAdmission;
  const input = createAdmissionInput();

  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  expect(bundle.relayRouterOptions.signedDelegate).toMatchObject({
    route: '/d1-signed-delegate',
    billing: bundle.billing,
    ledger: bundle.sponsoredCalls,
    runtimeSnapshots: bundle.runtimeSnapshots,
  });
  expect(bundle.relayRouterOptions.sponsorship).toMatchObject({
    spendCaps: bundle.spendCaps,
    pricing: sponsorshipPricing,
    prepaidReservations: bundle.prepaidReservations,
  });
  expect(bundle.relayRouterOptions.sponsoredEvmCall).toMatchObject({
    apiKeys: bundle.apiKeys,
    billing: bundle.billing,
    ledger: bundle.sponsoredCalls,
    runtimeSnapshots: bundle.runtimeSnapshots,
    config: null,
  });
  expect(bundle.relayRouterOptions.bootstrapTokenStore).toBe(bundle.bootstrapTokens);
  expect(bundle.relayRouterOptions.orgProjectEnv).toBe(bundle.orgProjectEnv);
  expect(bundle.relayRouterOptions.wallets).toBe(bundle.wallets);
  expect(bundle.relayRouterOptions.observabilityIngestion).toBe(bundle.observabilityIngestion);
  expect(typeof bundle.relayRouterOptions.apiKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.relayRouterOptions.publishableKeyAuth.authenticate).toBe('function');
  expect(typeof bundle.relayRouterOptions.apiKeyUsageMeter.recordEvent).toBe('function');
  expect(typeof bundle.relayRouterOptions.bootstrapGrantBroker.authenticatePublishableKey).toBe(
    'function',
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
      signerTables: 20,
    },
    admission: {
      durableObject: 'configured',
      quotaReservation: 'accepted',
    },
  });
});

test('local D1 Worker exposes relay smoke routes under relay prefix', async () => {
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
    thresholdEd25519: { configured: false },
    cors: { allowedOrigins: ['http://127.0.0.1:8787', 'http://localhost:8787'] },
  });

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
  expect(sponsored.status).toBe(503);
  await expect(sponsored.json()).resolves.toMatchObject({
    ok: false,
    code: 'sponsored_evm_call_disabled',
  });
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
