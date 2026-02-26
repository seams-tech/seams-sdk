import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const IMPORT_PATHS = {
  nearAdapter:
    '/sdk/esm/core/signingEngine/chainAdaptors/near/nearAdapter.js',
  evmAdapter:
    '/sdk/esm/core/signingEngine/chainAdaptors/evm/evmAdapter.js',
  tempoAdapter:
    '/sdk/esm/core/signingEngine/chainAdaptors/tempo/tempoAdapter.js',
  signerGateway:
    '/sdk/esm/core/signingEngine/workerManager/workerTransport.js',
  actions: '/sdk/esm/core/types/actions.js',
} as const;

test.describe('modularity lazy signer loading', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('signing wiring stays dynamic-import based', async () => {
    const nearSigningSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/api/nearSigning.ts'),
      'utf8',
    );
    const evmSigningSource = fs.readFileSync(
      path.resolve(process.cwd(), '../client/src/core/signingEngine/api/evmSigning.ts'),
      'utf8',
    );

    expect(nearSigningSource).toContain("from '../orchestration/near/nearSigningFlow'");
    expect(evmSigningSource).toContain(
      "import('../orchestration/evm/evmSigningFlow')",
    );
    expect(evmSigningSource).toContain(
      "import('../orchestration/tempo/tempoSigningFlow')",
    );
    expect(evmSigningSource).toContain("import('../signers/algorithms/secp256k1')");
    expect(evmSigningSource).toContain("import('../signers/algorithms/webauthnP256')");

    expect(nearSigningSource).not.toContain("import('../orchestration/signWithIntent')");
    expect(nearSigningSource).not.toContain("import('../signers/algorithms/ed25519')");
    expect(nearSigningSource).not.toContain(
      "await import('./chainAdaptors/near/walletOrigin')",
    );
    expect(evmSigningSource).not.toContain("from '../orchestration/tempo/tempoSigningFlow'");
    expect(nearSigningSource).not.toContain("from '../signers/algorithms/ed25519'");
    expect(evmSigningSource).not.toContain("from '../signers/algorithms/secp256k1'");
    expect(evmSigningSource).not.toContain("from '../signers/algorithms/webauthnP256'");
  });

  test('near adapter path does not instantiate multichain wasm workers', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const workerCreations: Array<{ url: string; name: string | null }> = [];

      const isEthWorker = (entry: { url: string; name: string | null }): boolean =>
        entry.name === 'ethSigner-worker' || /eth-signer\.worker\.js/.test(entry.url);
      const isTempoWorker = (entry: { url: string; name: string | null }): boolean =>
        entry.name === 'tempoSigner-worker' || /tempo-signer\.worker\.js/.test(entry.url);
      const countMultichainWorkers = (entries: Array<{ url: string; name: string | null }>): number =>
        entries.filter((entry) => isEthWorker(entry) || isTempoWorker(entry)).length;

      const originalWorker = window.Worker;
      try {
        class RecordingWorker extends originalWorker {
          constructor(url: string | URL, opts?: WorkerOptions) {
            workerCreations.push({
              url: String(url),
              name: typeof opts?.name === 'string' ? opts.name : null,
            });
            super(url, opts);
          }
        }
        (window as any).Worker = RecordingWorker as any;
        const baselineMultichainCount = countMultichainWorkers(workerCreations);

        const { NearAdapter } = await import(paths.nearAdapter);
        const { ActionType } = await import(paths.actions);
        const adapter = new NearAdapter();

        await adapter.buildIntent({
          chain: 'near',
          kind: 'transactionsWithActions',
          payload: {
            rpcCall: {
              nearAccountId: 'alice.near',
              nearRpcUrl: 'https://rpc.testnet.near.org',
            },
            transactions: [
              {
                receiverId: 'bob.near',
                actions: [{ action_type: ActionType.Transfer, deposit: '1' }],
              },
            ],
            signerMode: 'threshold-signer',
          },
        });

        return {
          multichainWorkerDelta: countMultichainWorkers(workerCreations) - baselineMultichainCount,
          workerCreations,
        };
      } finally {
        (window as any).Worker = originalWorker;
      }
    }, { paths: IMPORT_PATHS });

    expect(result.multichainWorkerDelta).toBe(0);
  });

  test('tempo adapter creates workers only when corresponding signer path is used', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const workerCreations: Array<{ url: string; name: string | null }> = [];
      const isEthWorker = (entry: { url: string; name: string | null }): boolean =>
        entry.name === 'ethSigner-worker' || /eth-signer\.worker\.js/.test(entry.url);
      const isTempoWorker = (entry: { url: string; name: string | null }): boolean =>
        entry.name === 'tempoSigner-worker' || /tempo-signer\.worker\.js/.test(entry.url);
      const countEthWorkers = (entries: Array<{ url: string; name: string | null }>): number =>
        entries.filter((entry) => isEthWorker(entry)).length;
      const countTempoWorkers = (entries: Array<{ url: string; name: string | null }>): number =>
        entries.filter((entry) => isTempoWorker(entry)).length;

      type MessageListener = (event: MessageEvent) => void;

      class FakeWorker {
        private messageListeners = new Set<MessageListener>();
        onmessage: ((event: MessageEvent) => void) | null = null;
        onerror: ((event: ErrorEvent) => void) | null = null;

        constructor(url: string | URL, opts?: WorkerOptions) {
          workerCreations.push({
            url: String(url),
            name: typeof opts?.name === 'string' ? opts.name : null,
          });
          queueMicrotask(() => {
            this.emitMessage({ type: 'WORKER_READY', ready: true });
          });
        }

        addEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
          if (type !== 'message') return;
          if (typeof listener === 'function') {
            this.messageListeners.add(listener as MessageListener);
          }
        }

        removeEventListener(type: string, listener: EventListenerOrEventListenerObject): void {
          if (type !== 'message') return;
          if (typeof listener === 'function') {
            this.messageListeners.delete(listener as MessageListener);
          }
        }

        postMessage(message: any): void {
          const type = String(message?.type || '');
          const id = String(message?.id || '');
          if (!id) return;

          let result: ArrayBuffer;
          if (type === 'computeEip1559TxHash' || type === 'computeTempoSenderHash') {
            result = new Uint8Array(32).buffer;
          } else {
            result = new Uint8Array(1).buffer;
          }

          queueMicrotask(() => {
            this.emitMessage({ id, ok: true, result });
          });
        }

        terminate(): void {}

        private emitMessage(data: any): void {
          const event = { data } as MessageEvent;
          for (const listener of this.messageListeners) listener(event);
          this.onmessage?.(event);
        }
      }

      const originalWorker = window.Worker;
      try {
        (window as any).Worker = FakeWorker as any;
        const { EvmAdapter } = await import(paths.evmAdapter);
        const { TempoAdapter } = await import(paths.tempoAdapter);
        const { requestWorkerOperation } = await import(paths.signerGateway);
        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await requestWorkerOperation({ kind: kind as any, request: request as any }),
        };

        const evmAdapter = new EvmAdapter(workerCtx as any);
        const tempoAdapter = new TempoAdapter(workerCtx as any);
        const baseline = {
          eth: countEthWorkers(workerCreations),
          tempo: countTempoWorkers(workerCreations),
        };

        const eip1559Request = {
          chain: 'evm' as const,
          kind: 'eip1559' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111,
            nonce: 1n,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            to: `0x${'11'.repeat(20)}`,
            value: 0n,
            data: '0x',
            accessList: [],
          },
        };

        await evmAdapter.buildIntent(eip1559Request);
        await evmAdapter.buildIntent(eip1559Request);

        const afterEip = {
          eth: countEthWorkers(workerCreations),
          tempo: countTempoWorkers(workerCreations),
        };

        const tempoRequest = {
          chain: 'tempo' as const,
          kind: 'tempoTransaction' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            calls: [{ to: `0x${'22'.repeat(20)}`, value: 0n, input: '0x' }],
            accessList: [],
            nonceKey: 1n,
            nonce: 1n,
            validBefore: null,
            validAfter: null,
            feeToken: null,
            feePayerSignature: { kind: 'none' as const },
          },
        };

        await tempoAdapter.buildIntent(tempoRequest);

        const afterTempo = {
          eth: countEthWorkers(workerCreations),
          tempo: countTempoWorkers(workerCreations),
        };

        return {
          ethWorkersDuringEip: afterEip.eth - baseline.eth,
          tempoWorkersDuringEip: afterEip.tempo - baseline.tempo,
          ethWorkersDuringTempo: afterTempo.eth - afterEip.eth,
          tempoWorkersDuringTempo: afterTempo.tempo - afterEip.tempo,
        };
      } finally {
        (window as any).Worker = originalWorker;
      }
    }, { paths: IMPORT_PATHS });

    expect(result.ethWorkersDuringEip).toBe(1);
    expect(result.tempoWorkersDuringEip).toBe(0);
    expect(result.ethWorkersDuringTempo).toBe(0);
    expect(result.tempoWorkersDuringTempo).toBe(1);
  });
});
