import { expect, test } from '@playwright/test';
import { WorkerTransport } from '@/core/signingEngine/workerManager/workerTransport';

type WorkerListener = (event: Event | MessageEvent | ErrorEvent) => void;

class NonResponsiveWorker {
  static instances: NonResponsiveWorker[] = [];

  readonly listeners = new Map<string, Set<WorkerListener>>();
  terminated = false;

  constructor(_url: string | URL, _opts?: WorkerOptions) {
    NonResponsiveWorker.instances.push(this);
  }

  addEventListener(type: string, listener: WorkerListener): void {
    const set = this.listeners.get(type) || new Set<WorkerListener>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: WorkerListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  postMessage(_message: unknown, _transfer?: Transferable[]): void {
    // Intentionally no-op: this simulates a worker that never answers.
  }

  terminate(): void {
    this.terminated = true;
  }
}

class ProgressWorker {
  static instances: ProgressWorker[] = [];

  readonly listeners = new Map<string, Set<WorkerListener>>();
  terminated = false;

  constructor(_url: string | URL, _opts?: WorkerOptions) {
    ProgressWorker.instances.push(this);
  }

  addEventListener(type: string, listener: WorkerListener): void {
    const set = this.listeners.get(type) || new Set<WorkerListener>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: WorkerListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  postMessage(message: unknown, _transfer?: Transferable[]): void {
    const id = String((message as { id?: unknown })?.id || '');
    const requestType = String((message as { type?: unknown })?.type || '');
    setTimeout(() => {
      if (requestType === 'getEmailOtpWarmSessionStatus') {
        this.emitMessage({
          id,
          progress: true,
          payload: { code: 'signer.ecdsa.bootstrap.started' },
        });
        this.emitMessage({
          id,
          progress: true,
          payload: { code: 'signer.ecdsa.bootstrap.succeeded' },
        });
        this.emitMessage({
          id,
          ok: true,
          result: {
            ok: true,
            remainingUses: 1,
            expiresAtMs: Date.now() + 60_000,
          },
        });
        return;
      }

      this.emitMessage({
        id,
        progress: true,
        payload: {
          phase: `${requestType}.running`,
          status: 'running',
          message: `Running ${requestType}`,
        },
      });
      this.emitMessage({
        id,
        progress: true,
        payload: {
          phase: `${requestType}.succeeded`,
          status: 'succeeded',
          message: `Completed ${requestType}`,
        },
      });
      this.emitMessage({ id, ok: true, result: new ArrayBuffer(0) });
    }, 0);
  }

  terminate(): void {
    this.terminated = true;
  }

  private emitMessage(data: unknown): void {
    for (const listener of this.listeners.get('message') || []) {
      listener(new MessageEvent('message', { data }));
    }
  }
}

class PrewarmWorker {
  static instances: PrewarmWorker[] = [];
  static responses: Array<'succeeded' | 'failed'> = [];
  static requestCount = 0;

  readonly listeners = new Map<string, Set<WorkerListener>>();

  constructor(_url: string | URL, _opts?: WorkerOptions) {
    PrewarmWorker.instances.push(this);
  }

  addEventListener(type: string, listener: WorkerListener): void {
    const set = this.listeners.get(type) || new Set<WorkerListener>();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: WorkerListener): void {
    this.listeners.get(type)?.delete(listener);
  }

  postMessage(message: unknown, _transfer?: Transferable[]): void {
    const id = String((message as { id?: unknown })?.id || '');
    const requestType = String((message as { type?: unknown })?.type || '');
    if (requestType !== 'prewarmEmailOtpRegistrationCrypto') return;
    PrewarmWorker.requestCount += 1;
    const response = PrewarmWorker.responses.shift() || 'succeeded';
    setTimeout(() => {
      const result =
        response === 'succeeded'
          ? { kind: 'succeeded', elapsedMs: 4 }
          : { kind: 'failed', elapsedMs: 4, failureStage: 'yao_wasm_init' };
      this.emitMessage({ id, ok: true, result });
    }, 0);
  }

  terminate(): void {}

  private emitMessage(data: unknown): void {
    for (const listener of this.listeners.get('message') || []) {
      listener(new MessageEvent('message', { data }));
    }
  }
}

test.describe('WorkerTransport multichain timeout guard', () => {
  test('email OTP Yao prewarm skips, coalesces, and retries after failure', async () => {
    const originalWorker = globalThis.Worker;
    PrewarmWorker.instances.length = 0;
    PrewarmWorker.requestCount = 0;
    PrewarmWorker.responses = ['failed', 'succeeded'];
    (globalThis as unknown as { Worker: typeof Worker }).Worker =
      PrewarmWorker as unknown as typeof Worker;

    try {
      const transport = new WorkerTransport();
      const skipped = await transport.prewarmEmailOtpYao({ kind: 'not_requested' });
      expect(skipped).toMatchObject({ kind: 'not_requested', elapsedMs: 0 });
      expect(PrewarmWorker.instances).toHaveLength(0);

      const first = transport.prewarmEmailOtpYao();
      const coalesced = transport.prewarmEmailOtpYao();
      const [failed, sameFailure] = await Promise.all([first, coalesced]);
      expect(failed).toMatchObject({
        kind: 'failed',
        failureStage: 'yao_wasm_init',
        yaoWasmInitMs: 4,
      });
      expect(sameFailure).toEqual(failed);
      expect(PrewarmWorker.requestCount).toBe(1);

      const retried = await transport.prewarmEmailOtpYao();
      expect(retried).toMatchObject({ kind: 'succeeded', yaoWasmInitMs: 4 });
      expect(PrewarmWorker.requestCount).toBe(2);
    } finally {
      (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
    }
  });

  test('tempo signer request fails with TIMEOUT when worker does not respond', async () => {
    const originalWorker = globalThis.Worker;
    NonResponsiveWorker.instances.length = 0;
    (globalThis as unknown as { Worker: typeof Worker }).Worker =
      NonResponsiveWorker as unknown as typeof Worker;

    try {
      const transport = new WorkerTransport();
      const startMs = Date.now();

      await expect(
        transport.requestOperation({
          kind: 'tempoSigner',
          request: {
            type: 'computeTempoSenderHash',
            payload: { tx: {} },
            timeoutMs: 25,
          },
        }),
      ).rejects.toMatchObject({
        name: 'SignerWorkerOperationError',
        code: 'TIMEOUT',
      });

      const elapsedMs = Date.now() - startMs;
      expect(elapsedMs).toBeGreaterThanOrEqual(20);
      expect(NonResponsiveWorker.instances.length).toBeGreaterThanOrEqual(1);
      expect(NonResponsiveWorker.instances[0]?.terminated).toBe(true);
    } finally {
      (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
    }
  });

  test('email OTP request forwards lightweight worker progress frames', async () => {
    const originalWorker = globalThis.Worker;
    ProgressWorker.instances.length = 0;
    (globalThis as unknown as { Worker: typeof Worker }).Worker =
      ProgressWorker as unknown as typeof Worker;

    try {
      const transport = new WorkerTransport();
      const progress: string[] = [];

      const result = await transport.requestOperation({
        kind: 'emailOtp',
        request: {
          type: 'getEmailOtpWarmSessionStatus',
          payload: { sessionId: 'email-otp-session-1' },
          onEvent: (update) => progress.push(update.code),
        },
      });

      expect(result).toMatchObject({ ok: true, remainingUses: 1 });
      expect(progress).toEqual([
        'signer.ecdsa.bootstrap.started',
        'signer.ecdsa.bootstrap.succeeded',
      ]);
    } finally {
      (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
    }
  });

  test('tempo signer request forwards RPC worker progress frames', async () => {
    const originalWorker = globalThis.Worker;
    ProgressWorker.instances.length = 0;
    (globalThis as unknown as { Worker: typeof Worker }).Worker =
      ProgressWorker as unknown as typeof Worker;

    try {
      const transport = new WorkerTransport();
      const progress: string[] = [];

      const result = await transport.requestOperation({
        kind: 'tempoSigner',
        request: {
          type: 'computeTempoSenderHash',
          payload: { tx: {} },
          onEvent: (update) => progress.push(update.phase),
        },
      });

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(progress).toEqual(['computeTempoSenderHash.running', 'computeTempoSenderHash.succeeded']);
    } finally {
      (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
    }
  });

  test('EVM signer request forwards RPC worker progress frames', async () => {
    const originalWorker = globalThis.Worker;
    ProgressWorker.instances.length = 0;
    (globalThis as unknown as { Worker: typeof Worker }).Worker =
      ProgressWorker as unknown as typeof Worker;

    try {
      const transport = new WorkerTransport();
      const progress: string[] = [];

      const result = await transport.requestOperation({
        kind: 'evmCrypto',
        request: {
          type: 'computeEip1559TxHash',
          payload: { tx: {} },
          onEvent: (update) => progress.push(update.phase),
        },
      });

      expect(result).toBeInstanceOf(ArrayBuffer);
      expect(progress).toEqual(['computeEip1559TxHash.running', 'computeEip1559TxHash.succeeded']);
    } finally {
      (globalThis as unknown as { Worker: typeof Worker }).Worker = originalWorker;
    }
  });
});
