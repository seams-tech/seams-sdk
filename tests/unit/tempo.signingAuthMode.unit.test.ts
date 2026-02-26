import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  signEvmWithTouchConfirm:
    '/sdk/esm/core/signingEngine/orchestration/evm/evmSigningFlow.js',
  signTempoWithTouchConfirm:
    '/sdk/esm/core/signingEngine/orchestration/tempo/tempoSigningFlow.js',
} as const;

test.describe('tempo signing auth-mode resolution', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('does not fail before confirmer when threshold warm session cache is unavailable (EVM)', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
      let confirmCalls = 0;
      let capturedAuthMode: string | null = null;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      try {
        await signEvmWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false,
              code: 'expired',
              message: 'expired',
            }),
            orchestrateSigningConfirmation: async (params: any) => {
              confirmCalls += 1;
              capturedAuthMode = String(params?.signingAuthMode || '');
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111n,
              nonce: 7n,
              maxPriorityFeePerGas: 1_500_000_000n,
              maxFeePerGas: 3_000_000_000n,
              gasLimit: 21_000n,
              to: '0x' + '22'.repeat(20),
              value: 12_345n,
              data: '0x',
              accessList: [],
            },
          } as any,
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          keyRefsByAlgorithm: {
            secp256k1: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            },
          } as any,
        });
        return { ok: true, confirmCalls, capturedAuthMode };
      } catch (error: any) {
        return {
          ok: false,
          confirmCalls,
          capturedAuthMode,
          message: String(error?.message || error),
        };
      }
    }, { paths: IMPORT_PATHS });

    expect(result.ok).toBe(true);
    expect(result.confirmCalls).toBe(1);
    expect(result.capturedAuthMode).toBe('warmSession');
  });

  test('uses warmSession mode when threshold warm cache is available', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
      let capturedAuthMode: string | null = null;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      const signed = await signEvmWithTouchConfirm({
        ctx: { indexedDB: {} } as any,
        workerCtx: workerCtx as any,
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 10_000,
          }),
          orchestrateSigningConfirmation: async (params: any) => {
            capturedAuthMode = String(params?.signingAuthMode || '');
            return {
              sessionId: 'intent',
              intentDigest: String(params?.intentDigest || ''),
            };
          },
        } as any,
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111n,
            nonce: 7n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: 12_345n,
            data: '0x',
            accessList: [],
          },
        } as any,
        engines: {
          secp256k1: {
            algorithm: 'secp256k1',
            sign: async () => {
              const sig = new Uint8Array(65);
              sig[64] = 0;
              return sig;
            },
          },
        } as any,
        keyRefsByAlgorithm: {
          secp256k1: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
            thresholdSessionId: 'session-1',
          },
        } as any,
      });

      return {
        capturedAuthMode,
        kind: signed.kind,
        chain: signed.chain,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.capturedAuthMode).toBe('warmSession');
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('runs reconnect hook after confirmer and before signing (EVM)', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
      const order: string[] = [];

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      const signed = await signEvmWithTouchConfirm({
        ctx: { indexedDB: {} } as any,
        workerCtx: workerCtx as any,
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: false,
            code: 'not_found',
            message: 'missing',
          }),
          orchestrateSigningConfirmation: async () => {
            order.push('confirm');
            return {
              sessionId: 'intent',
              intentDigest: '0x' + '11'.repeat(32),
            };
          },
        } as any,
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111n,
            nonce: 7n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: 12_345n,
            data: '0x',
            accessList: [],
          },
        } as any,
        ensureThresholdEcdsaKeyRefReady: async () => {
          order.push('reconnect');
          return {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
            thresholdSessionId: 'session-1',
          } as any;
        },
        engines: {
          secp256k1: {
            algorithm: 'secp256k1',
            sign: async () => {
              order.push('sign');
              const sig = new Uint8Array(65);
              sig[64] = 0;
              return sig;
            },
          },
        } as any,
      });

      return {
        chain: signed.chain,
        kind: signed.kind,
        order,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
    expect(result.order).toEqual(['confirm', 'reconnect', 'sign']);
  });

  test('ignores confirmation behavior for auth-mode and still uses warmSession when cache is available (EVM)', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
      let capturedAuthMode: string | null = null;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeEip1559TxHash') return new Uint8Array(32).buffer;
          if (type === 'encodeEip1559SignedTxFromSignature65')
            return new Uint8Array([0x02, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      const signed = await signEvmWithTouchConfirm({
        ctx: { indexedDB: {} } as any,
        workerCtx: workerCtx as any,
        touchConfirm: {
          peekPrfFirstForThresholdSession: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 10_000,
          }),
          orchestrateSigningConfirmation: async (params: any) => {
            capturedAuthMode = String(params?.signingAuthMode || '');
            return {
              sessionId: 'intent',
              intentDigest: String(params?.intentDigest || ''),
            };
          },
        } as any,
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 11155111n,
            nonce: 7n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: '0x' + '22'.repeat(20),
            value: 12_345n,
            data: '0x',
            accessList: [],
          },
        } as any,
        confirmationConfigOverride: { behavior: 'requireClick' },
        engines: {
          secp256k1: {
            algorithm: 'secp256k1',
            sign: async () => {
              const sig = new Uint8Array(65);
              sig[64] = 0;
              return sig;
            },
          },
        } as any,
        keyRefsByAlgorithm: {
          secp256k1: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: 'https://relayer.example',
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
            thresholdSessionId: 'session-1',
          },
        } as any,
      });

      return {
        capturedAuthMode,
        kind: signed.kind,
        chain: signed.chain,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.capturedAuthMode).toBe('warmSession');
    expect(result.chain).toBe('evm');
    expect(result.kind).toBe('eip1559');
  });

  test('does not fail before confirmer when threshold warm session cache is unavailable (Tempo)', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
      let confirmCalls = 0;

      const workerCtx = {
        requestWorkerOperation: async ({ request }: { request: any }) => {
          const type = String(request?.type || '');
          if (type === 'computeTempoSenderHash') return new Uint8Array(32).buffer;
          if (type === 'encodeTempoSignedTx') return new Uint8Array([0x76, 0xaa]).buffer;
          throw new Error(`Unexpected worker operation: ${type}`);
        },
      };

      try {
        await signTempoWithTouchConfirm({
          ctx: { indexedDB: {} } as any,
          workerCtx: workerCtx as any,
          touchConfirm: {
            peekPrfFirstForThresholdSession: async () => ({
              ok: false,
              code: 'expired',
              message: 'expired',
            }),
            orchestrateSigningConfirmation: async () => {
              confirmCalls += 1;
              return {
                sessionId: 'intent',
                intentDigest: '0x' + '11'.repeat(32),
              };
            },
          } as any,
          nearAccountId: 'alice.testnet',
          request: {
            chain: 'tempo',
            kind: 'tempoTransaction',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 11155111n,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21_000n,
              calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
              accessList: [],
              nonceKey: 1n,
              nonce: 1n,
              validBefore: null,
              validAfter: null,
              feePayerSignature: { kind: 'none' },
            },
          } as any,
          engines: {
            secp256k1: {
              algorithm: 'secp256k1',
              sign: async () => {
                const sig = new Uint8Array(65);
                sig[64] = 0;
                return sig;
              },
            },
          } as any,
          keyRefsByAlgorithm: {
            secp256k1: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relayer.example',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              thresholdSessionId: 'session-1',
            },
          } as any,
        });
        return { ok: true, confirmCalls };
      } catch (error: any) {
        return {
          ok: false,
          confirmCalls,
          message: String(error?.message || error),
        };
      }
    }, { paths: IMPORT_PATHS });

    expect(result.ok).toBe(true);
    expect(result.confirmCalls).toBe(1);
  });
});
