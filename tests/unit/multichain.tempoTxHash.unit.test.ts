import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  tempoSignerWasm: '/_test-sdk/esm/core/signingEngine/chains/tempo/tempoSignerWasm.js',
  signerGateway: '/_test-sdk/esm/core/signingEngine/workerManager/workerTransport.js',
} as const;

test.describe('TempoTransaction sender hash', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('matches Tempo sender hash for fee payer placeholder mode', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const { computeTempoSenderHashWasm } = await import(paths.tempoSignerWasm);
        const { getWorkerTransport } = await import(paths.signerGateway);
        const hex = (bytes: Uint8Array) =>
          `0x${Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('')}`;
        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await getWorkerTransport().requestOperation({
              kind: kind as any,
              request: request as any,
            }),
        };

        const mkTx = (feeToken: string) => ({
          chainId: 42431,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
          accessList: [],
          nonceKey: 0n,
          nonce: 1n,
          validBefore: null,
          validAfter: null,
          feeToken,
          feePayerSignature: { kind: 'placeholder' as const },
          aaAuthorizationList: [],
        });

        const h1 = await computeTempoSenderHashWasm(mkTx('0x' + 'aa'.repeat(20)), workerCtx as any);
        const h2 = await computeTempoSenderHashWasm(mkTx('0x' + 'bb'.repeat(20)), workerCtx as any);

        return { h1: hex(h1), h2: hex(h2) };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.h1).toBe('0x84d4731901604de2e1e4d7c9b6919f29f8f8bb7c3975d3495461b7f32768f870');
    expect(res.h2).toBe('0x722dbe0fd1d92aaeb2ee5663636c62db40a40797816980430ef7ef1771c616c3');
  });

  test('includes feeToken when no fee payer is present', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const { computeTempoSenderHashWasm } = await import(paths.tempoSignerWasm);
        const { getWorkerTransport } = await import(paths.signerGateway);
        const hex = (bytes: Uint8Array) =>
          `0x${Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('')}`;
        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await getWorkerTransport().requestOperation({
              kind: kind as any,
              request: request as any,
            }),
        };

        const mkTx = (feeToken: string) => ({
          chainId: 42431,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
          accessList: [],
          nonceKey: 0n,
          nonce: 1n,
          validBefore: null,
          validAfter: null,
          feeToken,
          feePayerSignature: { kind: 'none' as const },
          aaAuthorizationList: [],
        });

        const h1 = await computeTempoSenderHashWasm(mkTx('0x' + 'aa'.repeat(20)), workerCtx as any);
        const h2 = await computeTempoSenderHashWasm(mkTx('0x' + 'bb'.repeat(20)), workerCtx as any);

        return { h1: hex(h1), h2: hex(h2) };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.h1).not.toBe(res.h2);
  });

  test('matches Tempo sender hash when account-level user token pays fees', async ({ page }) => {
    const res = await page.evaluate(
      async ({ paths }) => {
        const { computeTempoSenderHashWasm } = await import(paths.tempoSignerWasm);
        const { getWorkerTransport } = await import(paths.signerGateway);
        const hex = (bytes: Uint8Array) =>
          `0x${Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join('')}`;
        const workerCtx = {
          requestWorkerOperation: async ({ kind, request }: { kind: string; request: unknown }) =>
            await getWorkerTransport().requestOperation({
              kind: kind as any,
              request: request as any,
            }),
        };

        const tx = {
          chainId: 42431,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
          accessList: [],
          nonceKey: 0n,
          nonce: 1n,
          validBefore: null,
          validAfter: null,
          feeToken: null,
          feePayerSignature: { kind: 'none' as const },
          aaAuthorizationList: [],
        };

        const senderHash = await computeTempoSenderHashWasm(tx, workerCtx as any);

        return { senderHash: hex(senderHash) };
      },
      { paths: IMPORT_PATHS },
    );

    expect(res.senderHash).toBe(
      '0x226686cf8fa936405a8799f1ae86379e031579465c7a4d466e900e14be92c3ac',
    );
  });
});
