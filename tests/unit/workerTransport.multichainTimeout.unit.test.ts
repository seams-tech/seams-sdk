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
});
