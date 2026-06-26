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

class FakeD1PreparedStatement implements D1PreparedStatementLike {
  bind(): D1PreparedStatementLike {
    return this;
  }

  async first<T = unknown>(): Promise<T | null> {
    return null;
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
  prepare(): D1PreparedStatementLike {
    return new FakeD1PreparedStatement();
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
    },
  });

  const admission = bundle.relayRouterOptions.routerAbNormalSigningAdmission;
  const input = createAdmissionInput();

  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
  await expect(admission.evaluate(input)).resolves.toEqual({ ok: true });
});
