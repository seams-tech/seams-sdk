import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  signEvmWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/evm/evmSigningFlow.js',
  signTempoWithTouchConfirm: '/sdk/esm/core/signingEngine/orchestration/tempo/tempoSigningFlow.js',
  nonceBackend: '/sdk/esm/core/rpcClients/evm/nonceBackend.js',
  nonceCoordinator: '/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js',
} as const;

test.describe('managed nonce signing flow integration', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('concurrent EVM signs use distinct reserved nonces for the same sender', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signEvmWithTouchConfirm } = await import(paths.signEvmWithTouchConfirm);
        const { createEvmNonceBackend } = await import(paths.nonceBackend);
        const {
          createNonceCoordinator,
          evmNonceLeaseToManagedReservation,
          evmReserveNonceInputToLane,
        } = await import(paths.nonceCoordinator);

        const backend = createEvmNonceBackend({
          chains: [
            {
              network: 'arc-testnet',
              rpcUrl: 'https://rpc.example.test',
              explorerUrl: 'https://explorer.example.test',
              chainId: 11155111,
            },
          ],
          fetchImpl: async () =>
            new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x7' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
        });
        const nonceCoordinator = createNonceCoordinator({
          evmNonceBackend: backend,
        });

        const reservationBase = {
          chain: 'evm' as const,
          networkKey: 'arc-testnet',
          chainId: 11155111,
          sender: `0x${'11'.repeat(20)}` as `0x${string}`,
          nearAccountId: 'alice.testnet',
        };

        const preparedNonces: string[] = [];
        let operationCounter = 0;
        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeEip1559TxHash') {
              return new Uint8Array(32).buffer;
            }
            if (type === 'encodeEip1559SignedTxFromSignature65') {
              return new Uint8Array([0x02, 0xaa]).buffer;
            }
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const touchConfirm = {
          getWarmSessionStatus: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 30_000,
          }),
          orchestrateSigningConfirmation: async () => ({
            sessionId: 'intent',
            intentDigest: '0x' + '11'.repeat(32),
          }),
        } as any;

        const baseRequest = {
          chain: 'evm' as const,
          kind: 'eip1559' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 11155111,
            nonce: 0n,
            maxPriorityFeePerGas: 1_500_000_000n,
            maxFeePerGas: 3_000_000_000n,
            gasLimit: 21_000n,
            to: `0x${'22'.repeat(20)}` as `0x${string}`,
            value: 1n,
            data: '0x' as const,
            accessList: [],
          },
        };
        const warmAuthPlan = {
          kind: 'warmSession',
          method: 'passkey',
          accountId: 'alice.testnet',
          intent: 'transaction_sign',
          curve: 'ecdsa',
          sessionId: 'session-1',
          expiresAtMs: Date.now() + 30_000,
          remainingUses: 2,
        };
        const thresholdEcdsaOperation = {
          intent: {
            walletId: 'alice.testnet',
            curve: 'ecdsa',
            chain: 'evm',
            authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
            operationUsesNeeded: 1,
          },
          lane: {
            accountId: 'alice.testnet',
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'evm',
            walletSigningSessionId: 'wallet-session-1',
            thresholdSessionId: 'session-1',
          },
          readiness: {
            status: 'ready',
            remainingUses: 2,
            expiresAtMs: Date.now() + 30_000,
          },
          budgetAdmission: {
            budgetIdentity: {
              walletSigningSessionId: 'wallet-session-1',
              projectionVersion: 'projection-1',
              status: {
                status: 'active',
                remainingUses: 2,
                expiresAtMs: Date.now() + 30_000,
                projectionVersion: 'projection-1',
              },
            },
          },
          authPlan: warmAuthPlan,
        };

        const runSign = async () =>
          await signEvmWithTouchConfirm({
            ctx: { indexedDB: {}, nonceCoordinator } as any,
            workerCtx: workerCtx as any,
            touchConfirm,
            nearAccountId: 'alice.testnet',
            request: baseRequest,
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
            thresholdEcdsaBoundary: {
              kind: 'admitted',
              operation: thresholdEcdsaOperation,
            },
            prepareRequestWithManagedNonce: async () => {
              operationCounter += 1;
              const operationId = `op-managed-evm-${operationCounter}`;
              const lease = await nonceCoordinator.reserve({
                lane: evmReserveNonceInputToLane(reservationBase),
                operation: {
                  operationId,
                  operationFingerprint: `sha256:${operationId}`,
                  intent: 'transaction_sign',
                  accountId: 'alice.testnet',
                  chainFamily: 'evm',
                },
              });
              const reservation = evmNonceLeaseToManagedReservation(lease);
              const nonce = reservation.nonce;
              preparedNonces.push(String(nonce));
              return {
                request: {
                  ...baseRequest,
                  tx: { ...baseRequest.tx, nonce },
                },
                reservation,
              };
            },
            releaseNonceReservation: async (reservation: any) => {
              await nonceCoordinator.release({
                leaseId: reservation.leaseId,
                operationId: reservation.operationId,
                reason: 'cancelled',
              });
            },
          });

        const [first, second] = await Promise.all([runSign(), runSign()]);
        const sorted = [...preparedNonces].sort((a, b) => Number(a) - Number(b));
        return {
          sorted,
          resultKinds: [first.kind, second.kind],
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sorted).toEqual(['7', '8']);
    expect(result.resultKinds).toEqual(['eip1559', 'eip1559']);
  });

  test('concurrent Tempo signs use distinct reserved nonces for the same sender + nonceKey', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const { signTempoWithTouchConfirm } = await import(paths.signTempoWithTouchConfirm);
        const { createEvmNonceBackend } = await import(paths.nonceBackend);
        const {
          createNonceCoordinator,
          evmNonceLeaseToManagedReservation,
          evmReserveNonceInputToLane,
        } = await import(paths.nonceCoordinator);

        const backend = createEvmNonceBackend({
          chains: [
            {
              network: 'tempo-testnet',
              rpcUrl: 'https://rpc.example.test',
              explorerUrl: 'https://explorer.example.test',
              chainId: 42431,
            },
          ],
          fetchImpl: async () =>
            new Response(JSON.stringify({ jsonrpc: '2.0', id: '1', result: '0x7' }), {
              status: 200,
              headers: { 'content-type': 'application/json' },
            }),
        });
        const nonceCoordinator = createNonceCoordinator({
          evmNonceBackend: backend,
        });

        const reservationBase = {
          chain: 'tempo' as const,
          networkKey: 'tempo-testnet',
          chainId: 42431,
          sender: `0x${'11'.repeat(20)}` as `0x${string}`,
          nonceKey: 1n,
          nearAccountId: 'alice.testnet',
        };

        const preparedNonces: string[] = [];
        let operationCounter = 0;
        const workerCtx = {
          requestWorkerOperation: async ({ request }: { request: any }) => {
            const type = String(request?.type || '');
            if (type === 'computeTempoSenderHash') {
              return new Uint8Array(32).buffer;
            }
            if (type === 'encodeTempoSignedTx') {
              return new Uint8Array([0x76, 0xaa]).buffer;
            }
            throw new Error(`Unexpected worker operation: ${type}`);
          },
        };

        const touchConfirm = {
          getWarmSessionStatus: async () => ({
            ok: true,
            remainingUses: 2,
            expiresAtMs: Date.now() + 30_000,
          }),
          orchestrateSigningConfirmation: async () => ({
            sessionId: 'intent',
            intentDigest: '0x' + '11'.repeat(32),
          }),
        } as any;

        const baseRequest = {
          chain: 'tempo' as const,
          kind: 'tempoTransaction' as const,
          senderSignatureAlgorithm: 'secp256k1' as const,
          tx: {
            chainId: 42431,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21_000n,
            calls: [
              { to: `0x${'22'.repeat(20)}` as `0x${string}`, value: 0n, input: '0x' as const },
            ],
            accessList: [],
            nonceKey: 1n,
            nonce: 0n,
            validBefore: null,
            validAfter: null,
            feePayerSignature: { kind: 'none' as const },
            aaAuthorizationList: [],
          },
        };
        const warmAuthPlan = {
          kind: 'warmSession',
          method: 'passkey',
          accountId: 'alice.testnet',
          intent: 'transaction_sign',
          curve: 'ecdsa',
          sessionId: 'session-1',
          expiresAtMs: Date.now() + 30_000,
          remainingUses: 2,
        };
        const thresholdEcdsaOperation = {
          intent: {
            walletId: 'alice.testnet',
            curve: 'ecdsa',
            chain: 'tempo',
            authSelectionPolicy: { kind: 'account_class', authMethod: 'passkey' },
            operationUsesNeeded: 1,
          },
          lane: {
            accountId: 'alice.testnet',
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            walletSigningSessionId: 'wallet-session-1',
            thresholdSessionId: 'session-1',
          },
          readiness: {
            status: 'ready',
            remainingUses: 2,
            expiresAtMs: Date.now() + 30_000,
          },
          budgetAdmission: {
            budgetIdentity: {
              walletSigningSessionId: 'wallet-session-1',
              projectionVersion: 'projection-1',
              status: {
                status: 'active',
                remainingUses: 2,
                expiresAtMs: Date.now() + 30_000,
                projectionVersion: 'projection-1',
              },
            },
          },
          authPlan: warmAuthPlan,
        };

        const runSign = async () =>
          await signTempoWithTouchConfirm({
            ctx: { indexedDB: {}, nonceCoordinator } as any,
            workerCtx: workerCtx as any,
            touchConfirm,
            nearAccountId: 'alice.testnet',
            request: baseRequest,
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
            thresholdEcdsaBoundary: {
              kind: 'admitted',
              operation: thresholdEcdsaOperation,
            },
            prepareRequestWithManagedNonce: async () => {
              operationCounter += 1;
              const operationId = `op-managed-tempo-${operationCounter}`;
              const lease = await nonceCoordinator.reserve({
                lane: evmReserveNonceInputToLane(reservationBase),
                operation: {
                  operationId,
                  operationFingerprint: `sha256:${operationId}`,
                  intent: 'transaction_sign',
                  accountId: 'alice.testnet',
                  chainFamily: 'tempo',
                },
              });
              const reservation = evmNonceLeaseToManagedReservation(lease);
              const nonce = reservation.nonce;
              preparedNonces.push(String(nonce));
              return {
                request: {
                  ...baseRequest,
                  tx: { ...baseRequest.tx, nonce },
                },
                reservation,
              };
            },
            releaseNonceReservation: async (reservation: any) => {
              await nonceCoordinator.release({
                leaseId: reservation.leaseId,
                operationId: reservation.operationId,
                reason: 'cancelled',
              });
            },
          });

        const [first, second] = await Promise.all([runSign(), runSign()]);
        const sorted = [...preparedNonces].sort((a, b) => Number(a) - Number(b));
        return {
          sorted,
          resultKinds: [first.kind, second.kind],
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.sorted).toEqual(['7', '8']);
    expect(result.resultKinds).toEqual(['tempoTransaction', 'tempoTransaction']);
  });
});
