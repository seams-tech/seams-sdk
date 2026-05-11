import { expect, test } from '@playwright/test';
import {
  runThresholdEcdsaTempoFlow,
  setupThresholdEcdsaTempoHarness,
} from '../helpers/thresholdEcdsaTempoFlow';
import { corsHeadersForRoute } from './thresholdEd25519.testUtils';

test.describe('threshold-ecdsa tempo signing', () => {
  test.setTimeout(180_000);

  test('keygen -> connect session -> sign tempoTransaction', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await runThresholdEcdsaTempoFlow(page, {
        relayerUrl: harness.baseUrl,
      });

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.keygen?.ok).toBe(true);
      expect(result.keygen?.ecdsaThresholdKeyId).toBeTruthy();
      expect(result.keygen?.thresholdEcdsaPublicKeyB64u).toBeTruthy();
      expect(result.keygen?.ethereumAddress).toMatch(/^0x[0-9a-f]{40}$/);
      expect(result.session?.kind).toBe('connected');
      if (!result.session || result.session.kind !== 'connected') {
        throw new Error('Expected connected ECDSA session');
      }
      expect(result.session.sessionId).toBeTruthy();
      expect(result.budgetStatus?.kind).toBe('active');
      if (!result.budgetStatus || result.budgetStatus.kind !== 'active') {
        throw new Error('Expected active wallet budget status');
      }
      expect(result.budgetStatus).toMatchObject({
        ok: true,
        walletSigningSessionId: result.session.walletSigningSessionId,
        thresholdSessionId: result.session.sessionId,
        status: 'active',
      });
      expect(result.signed?.chain).toBe('tempo');
      expect(result.signed?.kind).toBe('tempoTransaction');
      if (!result.signed || result.signed.kind !== 'tempoTransaction') {
        throw new Error('Expected tempoTransaction signed result');
      }
      expect(result.signed.senderHashHex.startsWith('0x')).toBeTruthy();
      expect(result.signed.rawTxHex.startsWith('0x')).toBeTruthy();
    } finally {
      await harness.close();
    }
  });

  test('executeEvmFamilyTransaction rejects stale finalized payload replay', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    const txHash = `0x${'66'.repeat(32)}`;
    try {
      await page.route('**://rpc.moderato.tempo.xyz/**', async (route) => {
        const request = route.request();
        let payload: Record<string, unknown> = {};
        try {
          payload = JSON.parse(request.postData() || '{}') as Record<string, unknown>;
        } catch {}
        const id = payload.id ?? Date.now();
        const method = String(payload.method || '');
        if (method === 'eth_sendRawTransaction') {
          await route.fulfill({
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeadersForRoute(route),
            },
            body: JSON.stringify({ jsonrpc: '2.0', id, result: txHash }),
          });
          return;
        }
        if (method === 'eth_getTransactionReceipt') {
          await route.fulfill({
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeadersForRoute(route),
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                transactionHash: txHash,
                blockNumber: '0x1234',
                status: '0x1',
              },
            }),
          });
          return;
        }
        if (method === 'eth_getTransactionByHash') {
          await route.fulfill({
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeadersForRoute(route),
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: {
                to: '0x1111111111111111111111111111111111111111',
                input: '0xdeadbeef',
              },
            }),
          });
          return;
        }
        if (method === 'eth_getTransactionCount') {
          await route.fulfill({
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              ...corsHeadersForRoute(route),
            },
            body: JSON.stringify({
              jsonrpc: '2.0',
              id,
              result: '0x1',
            }),
          });
          return;
        }
        await route.fulfill({
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeadersForRoute(route),
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32601, message: `unexpected method: ${method}` },
          }),
        });
      });

      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempopayload${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const request = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                to: '0x2222222222222222222222222222222222222222',
                value: 0n,
                data: '0xcafebabe',
                accessList: [],
              },
            };
            const chainTarget = (globalThis as any).__w3aChainTargetForTempoRequest(request);
            const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
              request,
            });
            if (!requestBootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(
                  requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                ),
              };
            }

            try {
              await pm.tempo.executeEvmFamilyTransaction({
                nearAccountId: accountId,
                subjectId: accountId,
                request,
                chainTarget,
                payloadExpectation: {
                  to: request.tx.to,
                  input: request.tx.data,
                },
                options: {
                  confirmationConfig,
                },
              });
              return {
                ok: false,
                error: 'expected tx_payload_mismatch but execution resolved',
              };
            } catch (error: unknown) {
              const err = error as {
                code?: unknown;
                message?: unknown;
                details?: { reason?: unknown; observedInput?: unknown; observedTo?: unknown };
              };
              return {
                ok: String(err.code || '') === 'tx_payload_mismatch',
                code: String(err.code || ''),
                message: String(err.message || ''),
                reason: String(err.details?.reason || ''),
                observedInput: String(err.details?.observedInput || ''),
                observedTo: String(err.details?.observedTo || ''),
              };
            }
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'stale payload replay regression failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, JSON.stringify(result)).toBe(true);
      expect(result.code).toBe('tx_payload_mismatch');
      expect(result.reason).toBe('mismatch');
      const observedInput = result.observedInput;
      const observedTo = result.observedTo;
      expect(observedInput).toBeTruthy();
      expect(observedTo).toBeTruthy();
      expect(observedInput?.toLowerCase()).toBe('0xdeadbeef');
      expect(observedTo?.toLowerCase()).toBe('0x1111111111111111111111111111111111111111');
    } finally {
      await harness.close();
    }
  });

  test('back-to-back managed EVM sends reserve distinct nonces after broadcast acceptance', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempoevmnonce${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 6,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const request = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };
            const chainTarget = (globalThis as any).__w3aChainTargetForTempoRequest(request);
            const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 6,
              request,
            });
            if (!requestBootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(
                  requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                ),
              };
            }

            const signed1 = await pm.tempo.signTempo({
              nearAccountId: accountId,
              subjectId: accountId,
              request,
              chainTarget,
              options: { confirmationConfig },
            });
            const nonce1Raw = String((signed1 as any)?.managedNonce?.nonce || '');
            const nonce1 = nonce1Raw ? BigInt(nonce1Raw) : null;
            if (signed1?.kind !== 'eip1559' || nonce1 === null) {
              return {
                ok: false,
                error: 'first sign missing managed nonce snapshot',
              };
            }

            await pm.tempo.reportBroadcastAccepted({
              nearAccountId: accountId,
              signedResult: signed1,
              txHash: ('0x' + '11'.repeat(32)) as `0x${string}`,
            });

            const signed2 = await pm.tempo.signTempo({
              nearAccountId: accountId,
              subjectId: accountId,
              request,
              chainTarget,
              options: { confirmationConfig },
            });
            const nonce2Raw = String((signed2 as any)?.managedNonce?.nonce || '');
            const nonce2 = nonce2Raw ? BigInt(nonce2Raw) : null;
            if (signed2?.kind !== 'eip1559' || nonce2 === null) {
              return {
                ok: false,
                error: 'second sign missing managed nonce snapshot',
              };
            }

            await pm.tempo.reportBroadcastAccepted({
              nearAccountId: accountId,
              signedResult: signed2,
              txHash: ('0x' + '12'.repeat(32)) as `0x${string}`,
            });

            return {
              ok: nonce2 > nonce1,
              nonce1: nonce1.toString(),
              nonce2: nonce2.toString(),
              delta: (nonce2 - nonce1).toString(),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'managed nonce e2e flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.nonce1).toBeTruthy();
      expect(result.nonce2).toBeTruthy();
      expect(Number(result.delta || '0')).toBeGreaterThanOrEqual(1);
    } finally {
      await harness.close();
    }
  });

  test('dropped nonce-gap recovers deterministically on ARC and Tempo lanes', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempononcegap${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 8,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const baseTx = {
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };

            const requests = [
              {
                lane: 'arc',
                request: {
                  chain: 'evm' as const,
                  ...baseTx,
                  tx: {
                    ...baseTx.tx,
                    chainId: 11155111,
                    to: '0x' + '22'.repeat(20),
                  },
                },
                txHash: ('0x' + '11'.repeat(32)) as `0x${string}`,
              },
              {
                lane: 'tempo',
                request: {
                  chain: 'evm' as const,
                  ...baseTx,
                  tx: {
                    ...baseTx.tx,
                    chainId: 42431,
                    to: '0x' + '33'.repeat(20),
                  },
                },
                txHash: ('0x' + '22'.repeat(32)) as `0x${string}`,
              },
            ];
            const requestsWithTargets = requests.map((lane) => ({
              ...lane,
              chainTarget: (globalThis as any).__w3aChainTargetForTempoRequest(lane.request),
            }));

            const laneResults: Array<{
              lane: string;
              nonce1: string;
              nonce2: string;
              reused: boolean;
              reconciledBlocked: boolean;
            }> = [];

            for (const lane of requestsWithTargets) {
              const laneBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest({
                pm,
                accountId,
                relayerUrl,
                ttlMs: 120_000,
                remainingUses: 8,
                request: lane.request,
              });
              if (!laneBootstrap?.session?.ok) {
                return {
                  ok: false,
                  error: String(
                    laneBootstrap?.session?.message ||
                      `${lane.lane} request ECDSA bootstrap failed`,
                  ),
                };
              }
              const signed1 = await pm.tempo.signTempo({
                nearAccountId: accountId,
                subjectId: accountId,
                request: lane.request,
                chainTarget: lane.chainTarget,
                options: { confirmationConfig },
              });
              const nonce1Raw = String((signed1 as any)?.managedNonce?.nonce || '');
              const nonce1 = nonce1Raw ? BigInt(nonce1Raw) : null;
              if (signed1?.kind !== 'eip1559' || nonce1 === null) {
                return {
                  ok: false,
                  error: `${lane.lane} first sign missing managed nonce snapshot`,
                };
              }

              await pm.tempo.reportBroadcastAccepted({
                nearAccountId: accountId,
                signedResult: signed1,
                txHash: lane.txHash,
              });

              const reconciled = await pm.tempo.reconcileNonceLane({
                nearAccountId: accountId,
                signedResult: signed1,
              });

              await pm.tempo.reportDroppedOrReplaced({
                nearAccountId: accountId,
                signedResult: signed1,
                reason: 'dropped',
                txHash: lane.txHash,
              });

              const signed2 = await pm.tempo.signTempo({
                nearAccountId: accountId,
                subjectId: accountId,
                request: lane.request,
                chainTarget: lane.chainTarget,
                options: { confirmationConfig },
              });
              const nonce2Raw = String((signed2 as any)?.managedNonce?.nonce || '');
              const nonce2 = nonce2Raw ? BigInt(nonce2Raw) : null;
              if (signed2?.kind !== 'eip1559' || nonce2 === null) {
                return {
                  ok: false,
                  error: `${lane.lane} second sign missing managed nonce snapshot`,
                };
              }

              laneResults.push({
                lane: lane.lane,
                nonce1: nonce1.toString(),
                nonce2: nonce2.toString(),
                reused: nonce1 === nonce2,
                reconciledBlocked: Boolean(reconciled?.blocked),
              });
            }

            return {
              ok: laneResults.every((entry) => entry.reused && !entry.reconciledBlocked),
              laneResults,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'nonce-gap recovery flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(Array.isArray(result.laneResults)).toBe(true);
      expect(result.laneResults).toHaveLength(2);
      for (const laneResult of result.laneResults as Array<{
        lane: string;
        nonce1: string;
        nonce2: string;
        reused: boolean;
      }>) {
        expect(laneResult.reused, `${laneResult.lane} did not recover dropped nonce`).toBe(true);
        expect(laneResult.nonce1).toBe(laneResult.nonce2);
      }
    } finally {
      await harness.close();
    }
  });

  test('unresolved nonce-gap is detectable and recovers after explicit drop resolution', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempounresolvedgap${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 8,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const request = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '44'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };
            const chainTarget = (globalThis as any).__w3aChainTargetForTempoRequest(request);
            const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 8,
              request,
            });
            if (!requestBootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(
                  requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                ),
              };
            }

            const signed1 = await pm.tempo.signTempo({
              nearAccountId: accountId,
              subjectId: accountId,
              request,
              chainTarget,
              options: { confirmationConfig },
            });
            const nonce1Raw = String((signed1 as any)?.managedNonce?.nonce || '');
            const nonce1 = nonce1Raw ? BigInt(nonce1Raw) : null;
            if (signed1?.kind !== 'eip1559' || nonce1 === null) {
              return {
                ok: false,
                error: 'first sign missing managed nonce snapshot',
              };
            }

            const txHash1 = ('0x' + '77'.repeat(32)) as `0x${string}`;
            await pm.tempo.reportBroadcastAccepted({
              nearAccountId: accountId,
              signedResult: signed1,
              txHash: txHash1,
            });

            const laneBefore = await pm.tempo.reconcileNonceLane({
              nearAccountId: accountId,
              signedResult: signed1,
            });

            const signed2 = await pm.tempo.signTempo({
              nearAccountId: accountId,
              subjectId: accountId,
              request,
              chainTarget,
              options: { confirmationConfig },
            });
            const nonce2Raw = String((signed2 as any)?.managedNonce?.nonce || '');
            const nonce2 = nonce2Raw ? BigInt(nonce2Raw) : null;
            if (signed2?.kind !== 'eip1559' || nonce2 === null) {
              return {
                ok: false,
                error: 'second sign missing managed nonce snapshot',
              };
            }

            await pm.tempo.reportBroadcastRejected({
              nearAccountId: accountId,
              signedResult: signed2,
              error: { message: 'manual test rejection before broadcast' },
            });

            await pm.tempo.reportDroppedOrReplaced({
              nearAccountId: accountId,
              signedResult: signed1,
              reason: 'dropped',
              txHash: txHash1,
            });

            const laneAfter = await pm.tempo.reconcileNonceLane({
              nearAccountId: accountId,
              signedResult: signed1,
            });

            const signed3 = await pm.tempo.signTempo({
              nearAccountId: accountId,
              subjectId: accountId,
              request,
              chainTarget,
              options: { confirmationConfig },
            });
            const nonce3Raw = String((signed3 as any)?.managedNonce?.nonce || '');
            const nonce3 = nonce3Raw ? BigInt(nonce3Raw) : null;
            if (signed3?.kind !== 'eip1559' || nonce3 === null) {
              return {
                ok: false,
                error: 'third sign missing managed nonce snapshot',
              };
            }

            const unresolvedBefore = Array.isArray(laneBefore?.unresolvedInFlightNonces)
              ? laneBefore.unresolvedInFlightNonces.map((value: unknown) => String(value || ''))
              : [];
            const unresolvedAfter = Array.isArray(laneAfter?.unresolvedInFlightNonces)
              ? laneAfter.unresolvedInFlightNonces.map((value: unknown) => String(value || ''))
              : [];

            return {
              ok:
                unresolvedBefore.includes(nonce1.toString()) &&
                !Boolean(laneBefore?.blocked) &&
                nonce2 > nonce1 &&
                !unresolvedAfter.includes(nonce1.toString()) &&
                nonce3 === nonce1,
              nonce1: nonce1.toString(),
              nonce2: nonce2.toString(),
              nonce3: nonce3.toString(),
              laneBefore,
              laneAfter,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'unresolved nonce-gap flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.nonce1).toBeTruthy();
      expect(result.nonce2).toBeTruthy();
      expect(result.nonce3).toBeTruthy();
      expect(result.nonce3).toBe(result.nonce1);
    } finally {
      await harness.close();
    }
  });

  test('rapid Tempo + EVM requests serialize without signing_in_progress', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempoqueue${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const tempoRequest = {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
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
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            };

            const evmRequest = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };
            const tempoChainTarget = (globalThis as any).__w3aChainTargetForTempoRequest(
              tempoRequest,
            );
            const evmChainTarget = (globalThis as any).__w3aChainTargetForTempoRequest(evmRequest);
            for (const request of [tempoRequest, evmRequest]) {
              const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest(
                {
                  pm,
                  accountId,
                  relayerUrl,
                  ttlMs: 120_000,
                  remainingUses: 4,
                  request,
                },
              );
              if (!requestBootstrap?.session?.ok) {
                return {
                  ok: false,
                  error: String(
                    requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                  ),
                };
              }
            }

            const [tempoResult, evmResult] = await Promise.allSettled([
              pm.tempo.signTempo({
                nearAccountId: accountId,
                subjectId: accountId,
                request: tempoRequest,
                chainTarget: tempoChainTarget,
                options: { confirmationConfig },
              }),
              pm.tempo.signTempo({
                nearAccountId: accountId,
                subjectId: accountId,
                request: evmRequest,
                chainTarget: evmChainTarget,
                options: { confirmationConfig },
              }),
            ]);

            const settled = [tempoResult, evmResult].map((entry, idx) => {
              if (entry.status === 'fulfilled') {
                return {
                  index: idx,
                  status: 'fulfilled' as const,
                  chain: String(entry.value?.chain || ''),
                  kind: String(entry.value?.kind || ''),
                };
              }
              return {
                index: idx,
                status: 'rejected' as const,
                error: String((entry.reason as any)?.message || entry.reason || ''),
              };
            });

            const rejectionMessages = settled
              .filter((entry) => entry.status === 'rejected')
              .map((entry) => String((entry as { error?: string }).error || ''));

            const containsInFlightMessage = rejectionMessages.some((message) =>
              /signing_in_progress|already in progress/i.test(message),
            );

            return {
              ok: rejectionMessages.length === 0 && !containsInFlightMessage,
              settled,
              rejectionMessages,
              containsInFlightMessage,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'rapid threshold sign flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.settled).toEqual([
        expect.objectContaining({
          index: 0,
          status: 'fulfilled',
          chain: 'tempo',
          kind: 'tempoTransaction',
        }),
        expect.objectContaining({
          index: 1,
          status: 'fulfilled',
          chain: 'evm',
          kind: 'eip1559',
        }),
      ]);
      expect(JSON.stringify(result.rejectionMessages || [])).not.toMatch(
        /signing_in_progress|already in progress/i,
      );
    } finally {
      await harness.close();
    }
  });

  test('same-account Tempo/EVM signing succeeds in both orderings', async ({ page }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempoevmorder${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 10,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const tempoRequest = {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
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
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            };

            const evmRequest = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };

            let acceptedCounter = 0;
            const requestsByChain = {
              tempo: tempoRequest,
              evm: evmRequest,
            } as const;
            const chainTargetsByChain = {
              tempo: (globalThis as any).__w3aChainTargetForTempoRequest(tempoRequest),
              evm: (globalThis as any).__w3aChainTargetForTempoRequest(evmRequest),
            } as const;
            for (const request of [tempoRequest, evmRequest]) {
              const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest(
                {
                  pm,
                  accountId,
                  relayerUrl,
                  ttlMs: 120_000,
                  remainingUses: 10,
                  request,
                },
              );
              if (!requestBootstrap?.session?.ok) {
                return {
                  ok: false,
                  error: String(
                    requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                  ),
                };
              }
            }

            const runOrder = async (order: Array<'tempo' | 'evm'>) => {
              const out: Array<{
                requestedChain: 'tempo' | 'evm';
                resultChain: string;
                kind: string;
              }> = [];
              for (const requestedChain of order) {
                const signed = await pm.tempo.signTempo({
                  nearAccountId: accountId,
                  subjectId: accountId,
                  request: requestsByChain[requestedChain],
                  chainTarget: chainTargetsByChain[requestedChain],
                  options: { confirmationConfig },
                });
                out.push({
                  requestedChain,
                  resultChain: String(signed?.chain || ''),
                  kind: String(signed?.kind || ''),
                });
                if (requestedChain === 'evm') {
                  acceptedCounter += 1;
                  const txHashByte = (16 + acceptedCounter).toString(16).padStart(2, '0');
                  await pm.tempo.reportBroadcastAccepted({
                    nearAccountId: accountId,
                    signedResult: signed,
                    txHash: ('0x' + txHashByte.repeat(32)) as `0x${string}`,
                  });
                }
              }
              return out;
            };

            const tempoThenEvm = await runOrder(['tempo', 'evm']);
            const evmThenTempo = await runOrder(['evm', 'tempo']);

            const orderOk = (
              entries: Array<{
                requestedChain: 'tempo' | 'evm';
                resultChain: string;
                kind: string;
              }>,
              expected: Array<'tempo' | 'evm'>,
            ) =>
              entries.length === 2 &&
              entries[0]?.requestedChain === expected[0] &&
              entries[1]?.requestedChain === expected[1] &&
              entries[0]?.resultChain === expected[0] &&
              entries[1]?.resultChain === expected[1] &&
              entries[0]?.kind === (expected[0] === 'tempo' ? 'tempoTransaction' : 'eip1559') &&
              entries[1]?.kind === (expected[1] === 'tempo' ? 'tempoTransaction' : 'eip1559');

            return {
              ok:
                orderOk(tempoThenEvm, ['tempo', 'evm']) && orderOk(evmThenTempo, ['evm', 'tempo']),
              tempoThenEvm,
              evmThenTempo,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'cross-chain ordering flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, JSON.stringify(result)).toBe(true);
      expect(result.tempoThenEvm).toEqual([
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
      ]);
      expect(result.evmThenTempo).toEqual([
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
      ]);
    } finally {
      await harness.close();
    }
  });

  test('second request reaches confirmation before first settles under enforce deployment mode', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaTempoHarness(page);
    let deployCalls = 0;
    try {
      await page.route(`${harness.baseUrl}/smart-account/deployment/manifest`, async (route) => {
        await route.fulfill({
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeadersForRoute(route),
          },
          body: JSON.stringify({
            ok: true,
            manifest: {
              version: 'smart_account_deployment_manifest_v1',
              chain: 'evm',
              accountAddress: '0x' + '22'.repeat(20),
            },
            evmDeploymentPlan: {
              version: 'evm_smart_account_deployment_plan_v1',
              chainId: 11155111,
              accountAddress: '0x' + '22'.repeat(20),
            },
          }),
        });
      });
      await page.route(`${harness.baseUrl}/smart-account/deployment/observe`, async (route) => {
        await route.fulfill({
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeadersForRoute(route),
          },
          body: JSON.stringify({ ok: true }),
        });
      });
      await page.route(`${harness.baseUrl}/smart-account/deploy`, async (route) => {
        deployCalls += 1;
        if (deployCalls === 1) {
          await new Promise((resolve) => setTimeout(resolve, 900));
        }
        await route.fulfill({
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            ...corsHeadersForRoute(route),
          },
          body: JSON.stringify({
            ok: true,
            deploymentTxHash: `0xdeploy${deployCalls.toString(16).padStart(2, '0')}`,
          }),
        });
      });

      const result = await page.evaluate(
        async ({ relayerUrl }) => {
          try {
            const sdkMod = await import('/sdk/esm/index.js');
            const { SeamsPasskey } = sdkMod as any;

            const accountId = `tempoqueueenforce${Date.now()}.w3a-v1.testnet`;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

            const pm = new SeamsPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeployRoute: '/smart-account/deploy',
                smartAccountDeploymentMode: 'enforce',
              },
              ...(managedRegistration
                ? {
                    registration: {
                      mode: 'managed' as const,
                      environmentId: String(managedRegistration.environmentId || ''),
                      publishableKey: String(managedRegistration.publishableKey || ''),
                    },
                  }
                : {}),
              iframeWallet: {
                walletOrigin: '',
                walletServicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const registration = await pm.registration.registerPasskeyInternal(
              accountId,
              {
                signerOptions: {
                  tempo: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                  evm: {
                    enabled: false,
                    participantIds: [1, 2],
                    signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
                  },
                },
              },
              confirmationConfig,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registerPasskeyInternal failed'),
              };
            }

            const bootstrap = await (globalThis as any).__w3aBootstrapFreshTempoEcdsaSession({
              pm,
              accountId,
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 4,
            });
            if (!bootstrap?.session?.ok) {
              return {
                ok: false,
                error: String(bootstrap?.session?.message || 'bootstrapEcdsaSession failed'),
              };
            }

            const tempoRequest = {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
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
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            };

            const evmRequest = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };

            type ProgressEvent = {
              label: 'first' | 'second';
              phase: string;
              status: string;
              atMs: number;
            };
            const progressEvents: ProgressEvent[] = [];
            const settledAtMs: Partial<Record<'first' | 'second', number>> = {};
            const startedAtMs = performance.now();
            const chainTargetFor = (request: typeof tempoRequest | typeof evmRequest) =>
              (globalThis as any).__w3aChainTargetForTempoRequest(request);
            for (const request of [tempoRequest, evmRequest]) {
              const requestBootstrap = await (globalThis as any).__w3aBootstrapFreshEcdsaForRequest(
                {
                  pm,
                  accountId,
                  relayerUrl,
                  ttlMs: 120_000,
                  remainingUses: 4,
                  request,
                },
              );
              if (!requestBootstrap?.session?.ok) {
                return {
                  ok: false,
                  error: String(
                    requestBootstrap?.session?.message || 'request ECDSA bootstrap failed',
                  ),
                };
              }
            }

            const runSign = async (
              label: 'first' | 'second',
              request: typeof tempoRequest | typeof evmRequest,
            ) => {
              try {
                const value = await pm.tempo.signTempo({
                  nearAccountId: accountId,
                  subjectId: accountId,
                  request,
                  chainTarget: chainTargetFor(request),
                  options: {
                    confirmationConfig,
                    onEvent: (ev: { phase?: unknown; status?: unknown }) => {
                      progressEvents.push({
                        label,
                        phase: String(ev?.phase || ''),
                        status: String(ev?.status || ''),
                        atMs: Math.max(0, performance.now() - startedAtMs),
                      });
                    },
                  },
                });
                settledAtMs[label] = Math.max(0, performance.now() - startedAtMs);
                return {
                  status: 'fulfilled' as const,
                  chain: String(value?.chain || ''),
                  kind: String(value?.kind || ''),
                };
              } catch (error: unknown) {
                settledAtMs[label] = Math.max(0, performance.now() - startedAtMs);
                return {
                  status: 'rejected' as const,
                  error: String(
                    error && typeof error === 'object' && 'message' in error
                      ? (error as { message?: unknown }).message
                      : error || '',
                  ),
                };
              }
            };

            const firstPromise = runSign('first', tempoRequest);
            await new Promise((resolve) => setTimeout(resolve, 20));
            const secondPromise = runSign('second', evmRequest);
            const [first, second] = await Promise.all([firstPromise, secondPromise]);

            const secondUserConfirmationAtMs = progressEvents.find(
              (event) =>
                event.label === 'second' && event.phase === 'signing.confirmation.displayed',
            )?.atMs;
            const firstSettledAtMs = settledAtMs.first;

            const secondConfirmedBeforeFirstSettled =
              typeof secondUserConfirmationAtMs === 'number' &&
              typeof firstSettledAtMs === 'number' &&
              secondUserConfirmationAtMs < firstSettledAtMs;

            return {
              ok:
                first.status === 'fulfilled' &&
                second.status === 'fulfilled' &&
                secondConfirmedBeforeFirstSettled,
              first,
              second,
              secondUserConfirmationAtMs,
              firstSettledAtMs,
              secondConfirmedBeforeFirstSettled,
              progressEvents,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'enforce deployment concurrency flow failed',
              ),
            };
          }
        },
        { relayerUrl: harness.baseUrl },
      );

      expect(result.ok, result.error || JSON.stringify(result)).toBe(true);
      expect(result.first).toEqual(
        expect.objectContaining({
          status: 'fulfilled',
          chain: 'tempo',
        }),
      );
      expect(result.second).toEqual(
        expect.objectContaining({
          status: 'fulfilled',
          chain: 'evm',
        }),
      );
      expect(result.secondConfirmedBeforeFirstSettled).toBe(true);
      expect(typeof result.secondUserConfirmationAtMs).toBe('number');
      expect(typeof result.firstSettledAtMs).toBe('number');
    } finally {
      await harness.close();
    }
  });
});
