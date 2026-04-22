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

test.describe('WorkerTransport multichain timeout guard', () => {
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
        kind: 'ethSigner',
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
