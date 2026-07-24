import { expect, test } from '@playwright/test';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import type { FetchHandler } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { RouterApiRuntimeDurableObject } from '../../packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker';

class Signal {
  readonly promise: Promise<void>;
  private releasePromise!: () => void;

  constructor() {
    this.promise = new Promise(this.captureRelease.bind(this));
  }

  release(): void {
    this.releasePromise();
  }

  private captureRelease(resolve: () => void): void {
    this.releasePromise = resolve;
  }
}

class RecordingRuntimeStorage {
  readonly writes: unknown[] = [];
  reads = 0;

  async get(): Promise<unknown> {
    this.reads += 1;
    return null;
  }

  async put(_key: string, value: unknown): Promise<void> {
    this.writes.push(value);
  }
}

class SerializedRuntimeState {
  readonly storage = new RecordingRuntimeStorage();
  blockConcurrencyWhileCalls = 0;
  private tail: Promise<void> = Promise.resolve();

  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T> {
    this.blockConcurrencyWhileCalls += 1;
    const run = runAfter(this.tail, callback);
    this.tail = settle(run);
    return run;
  }
}

class RuntimeConcurrencyProbe {
  readonly enteredPaths: string[] = [];
  readonly firstEntered = new Signal();
  readonly secondEntered = new Signal();
  private readonly initialization = new Signal();
  private readonly requests = new Signal();
  private activeRequests = 0;
  maxActiveRequests = 0;

  async createHandler(): Promise<FetchHandler> {
    await this.initialization.promise;
    return this.handle.bind(this);
  }

  finishInitialization(): void {
    this.initialization.release();
  }

  finishRequests(): void {
    this.requests.release();
  }

  private async handle(request: Request): Promise<Response> {
    const path = new URL(request.url).pathname;
    this.enteredPaths.push(path);
    this.activeRequests += 1;
    this.maxActiveRequests = Math.max(this.maxActiveRequests, this.activeRequests);
    this.signalEntry(path);
    await this.requests.promise;
    this.activeRequests -= 1;
    return new Response(path);
  }

  private signalEntry(path: string): void {
    switch (path) {
      case '/first':
        this.firstEntered.release();
        return;
      case '/second':
        this.secondEntered.release();
        return;
      default:
        throw new Error(`unexpected probe request path ${path}`);
    }
  }
}

class UnusedD1Database implements D1DatabaseLike {
  prepare(): D1PreparedStatementLike {
    throw new Error('D1 is outside the runtime concurrency test');
  }

  async batch<T>(): Promise<readonly T[]> {
    throw new Error('D1 is outside the runtime concurrency test');
  }

  async exec(): Promise<unknown> {
    throw new Error('D1 is outside the runtime concurrency test');
  }
}

class UnusedDurableObjectStub implements CloudflareDurableObjectStubLike {
  async fetch(): Promise<Response> {
    throw new Error('Durable Object stubs are outside the runtime concurrency test');
  }
}

class UnusedDurableObjectNamespace implements CloudflareDurableObjectNamespaceLike {
  idFromName(name: string): unknown {
    return name;
  }

  get(): CloudflareDurableObjectStubLike {
    return new UnusedDurableObjectStub();
  }
}

class UnusedServiceBinding {
  async fetch(): Promise<Response> {
    throw new Error('service bindings are outside the runtime concurrency test');
  }
}

async function runAfter<T>(previous: Promise<void>, callback: () => Promise<T>): Promise<T> {
  await previous;
  return await callback();
}

function settle<T>(promise: Promise<T>): Promise<void> {
  return promise.then(ignore, ignore);
}

function ignore(): void {}

async function drainMicrotasks(): Promise<void> {
  for (let turn = 0; turn < 5; turn += 1) {
    await Promise.resolve();
  }
}

function createRuntimeEnv(): ConstructorParameters<typeof RouterApiRuntimeDurableObject>[1] {
  const database = new UnusedD1Database();
  const namespace = new UnusedDurableObjectNamespace();
  const service = new UnusedServiceBinding();
  return {
    CONSOLE_DB: database,
    SIGNER_DB: database,
    THRESHOLD_STORE: namespace,
    ROUTER_API_RUNTIME: namespace,
    MPC_ROUTER: service,
    DERIVER_A: service,
    DERIVER_B: service,
    SIGNING_WORKER: service,
  };
}

async function verifyConcurrentRequestsBypassInitializationGate(): Promise<void> {
  const state = new SerializedRuntimeState();
  const probe = new RuntimeConcurrencyProbe();
  const runtime = new RouterApiRuntimeDurableObject(
    state,
    createRuntimeEnv(),
    probe.createHandler.bind(probe),
  );

  const firstResponse = runtime.fetch(new Request('https://gateway.example.test/first'));
  await drainMicrotasks();

  expect(state.blockConcurrencyWhileCalls).toBe(1);
  expect(probe.enteredPaths).toEqual([]);
  expect(state.storage.writes).toHaveLength(0);

  probe.finishInitialization();
  await probe.firstEntered.promise;

  const secondResponse = runtime.fetch(new Request('https://gateway.example.test/second'));
  await drainMicrotasks();

  let concurrencyAssertionError: unknown = null;
  try {
    expect(probe.enteredPaths).toEqual(['/first', '/second']);
    expect(probe.maxActiveRequests).toBe(2);
  } catch (error: unknown) {
    concurrencyAssertionError = error;
  }

  probe.finishRequests();
  const responses = await Promise.all([firstResponse, secondResponse]);
  if (concurrencyAssertionError) throw concurrencyAssertionError;

  expect(await Promise.all(responses.map(readResponseText))).toEqual(['/first', '/second']);
  expect(state.blockConcurrencyWhileCalls).toBe(1);
  expect(state.storage.reads).toBe(1);
  expect(state.storage.writes).toHaveLength(2);
}

async function readResponseText(response: Response): Promise<string> {
  return await response.text();
}

test(
  'Gateway runtime serializes initialization once while distinct requests overlap',
  verifyConcurrentRequestsBypassInitializationGate,
);
