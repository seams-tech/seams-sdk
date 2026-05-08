import { expect, test } from '@playwright/test';
import { EvmSigner } from '@/core/SeamsPasskey/evm';
import { NearSigner } from '@/core/SeamsPasskey/near';
import { TempoSigner } from '@/core/SeamsPasskey/tempo';
import { createSigningFlowEvent, SigningEventPhase } from '@/core/types/sdkSentEvents';
import { thresholdEcdsaChainTargetFromChainFamily, toWalletSubjectId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const TEST_SUBJECT_ID = toWalletSubjectId('alice.testnet');
const allowThresholdEcdsaOperation = async () => undefined;
const applyThresholdEcdsaPostSignPolicy = async () => undefined;
const TEMPO_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});
const EVM_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});

function createTestSigningEvent(
  phase: SigningEventPhase,
  status: 'started' | 'waiting_for_user' | 'running' | 'succeeded' | 'failed' | 'cancelled',
  data?: Record<string, unknown>,
) {
  return createSigningFlowEvent({
    phase,
    status,
    flowId: `signing:test:${phase}`,
    accountId: 'alice.testnet',
    interaction: { kind: 'none', overlay: 'none' },
    ...(data ? { data } : {}),
  });
}

function createNearSignerWithRouter(router: Record<string, unknown>) {
  return new NearSigner({
    getContext: () =>
      ({
        configs: {
          relayer: { delegateActionRoute: '/signed-delegate' },
        },
      }) as any,
    walletIframe: {
      shouldUseWalletIframe: () => true,
      requireRouter: async () => router as any,
    },
  });
}

test.describe('SeamsPasskey chain signer modules', () => {
  test('NearSigner.executeAction calls afterCall(true) on success in iframe mode', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const onErrors: Error[] = [];
    const expectedResult = { success: true, transactionId: 'tx-1' };
    const signer = createNearSignerWithRouter({
      executeAction: async () => expectedResult,
    });

    const result = await signer.executeAction({
      nearAccountId: 'alice.testnet',
      receiverId: 'contract.testnet',
      actionArgs: { type: 'FunctionCall', methodName: 'ping' } as any,
      options: {
        afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
        onError: async (err: Error) => onErrors.push(err),
      } as any,
    });

    expect(result).toEqual(expectedResult);
    expect(onErrors).toEqual([]);
    expect(afterCalls).toEqual([{ ok: true, result: expectedResult }]);
  });

  test('NearSigner.executeAction calls onError + afterCall(false) on router failure', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const onErrors: Error[] = [];
    const signer = createNearSignerWithRouter({
      executeAction: async () => {
        throw new Error('router execute failed');
      },
    });

    await expect(
      signer.executeAction({
        nearAccountId: 'alice.testnet',
        receiverId: 'contract.testnet',
        actionArgs: { type: 'FunctionCall', methodName: 'ping' } as any,
        options: {
          afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
          onError: async (err: Error) => onErrors.push(err),
        } as any,
      }),
    ).rejects.toThrow('router execute failed');

    expect(onErrors.length).toBe(1);
    expect(onErrors[0]?.message).toContain('router execute failed');
    expect(afterCalls).toEqual([{ ok: false, result: undefined }]);
  });

  test('NearSigner.signAndSendTransactions emits completion event and defaults executionWait', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const progressEvents: any[] = [];
    const routerArgs: any[] = [];
    const signer = createNearSignerWithRouter({
      signAndSendTransactions: async (args: any) => {
        routerArgs.push(args);
        args.options?.onEvent?.({
          phase: SigningEventPhase.STEP_15_COMPLETED,
          message: 'Transaction complete: tx-a, tx-b',
        });
        return [
          { success: true, transactionId: 'tx-a' },
          { success: true, transactionId: 'tx-b' },
        ];
      },
    });

    const result = await signer.signAndSendTransactions({
      nearAccountId: 'alice.testnet',
      transactions: [{ receiverId: 'contract.testnet', actions: [] }] as any,
      options: {
        onEvent: (event: any) => progressEvents.push(event),
        afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
      } as any,
    });

    expect(result).toHaveLength(2);
    expect(routerArgs).toHaveLength(1);
    expect(routerArgs[0]?.options?.executionWait?.mode).toBe('sequential');
    expect(afterCalls).toEqual([{ ok: true, result }]);
    expect(progressEvents.at(-1)?.phase).toBe(SigningEventPhase.STEP_15_COMPLETED);
    expect(progressEvents.at(-1)?.message).toContain('tx-a');
    expect(progressEvents.at(-1)?.message).toContain('tx-b');
  });

  test('NearSigner.signAndSendDelegateAction reports afterCall(false) when relay returns ok=false', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const signer = createNearSignerWithRouter({});
    const signResult = {
      signedDelegate: { delegate_action: {}, signature: '' },
      hash: 'abc123',
      nearAccountId: 'alice.testnet',
    } as any;
    const relayResult = { ok: false, status: 500 } as any;

    (signer as any).signDelegateAction = async () => signResult;
    (signer as any).sendDelegateActionViaRelayer = async () => relayResult;

    const combined = await signer.signAndSendDelegateAction({
      nearAccountId: 'alice.testnet',
      delegate: { senderId: 'alice.testnet', receiverId: 'contract.testnet', actions: [] } as any,
      relayerUrl: 'https://relay.example.test',
      options: {
        afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
      } as any,
    });

    expect(combined).toEqual({ signResult, relayResult });
    expect(afterCalls).toEqual([{ ok: false, result: undefined }]);
  });

  test('TempoSigner forwards shouldAbort in non-iframe mode', async () => {
    let capturedArgs: any = null;
    const expectedResult = { chain: 'evm', txHashHex: '0x1', rawTxHex: '0x2' } as any;
    const shouldAbort = () => false;
    const signer = new TempoSigner({
      getContext: () =>
        ({
          signingEngine: {
            assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
            applyThresholdEcdsaPostSignPolicy,
            signTempo: async (args: any) => {
              capturedArgs = args;
              return expectedResult;
            },
          },
        }) as any,
      walletIframe: {
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('should not call router in non-iframe mode');
        },
      },
    });

    const result = await signer.signTempo({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
      request: {
        chain: 'tempo',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {},
      } as any,
      options: {
        confirmationConfig: { uiMode: 'modal' },
        shouldAbort,
      },
    });

    expect(result).toEqual(expectedResult);
    expect(capturedArgs?.shouldAbort).toBe(shouldAbort);
    expect(capturedArgs?.confirmationConfigOverride?.uiMode).toBe('modal');
  });

  test('TempoSigner and EvmSigner force chain during bootstrap', async () => {
    const tempoCalls: any[] = [];
    const evmCalls: any[] = [];
    const configs = {
      registration: { mode: 'self' },
      network: {
        chains: [
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://rpc.tempo.test',
            explorerUrl: 'https://explorer.tempo.test',
            chainId: 42431,
          },
          {
            network: 'arc-testnet',
            rpcUrl: 'https://rpc.arc.test',
            explorerUrl: 'https://explorer.arc.test',
            chainId: 5042002,
          },
        ],
      },
    };

    const tempoSigner = new TempoSigner({
      getContext: () => ({ configs }) as any,
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () =>
          ({
            bootstrapEcdsaSession: async (args: any) => {
              tempoCalls.push(args);
              return { ok: true };
            },
          }) as any,
      },
    });
    const evmSigner = new EvmSigner({
      getContext: () => ({ configs }) as any,
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () =>
          ({
            bootstrapEcdsaSession: async (args: any) => {
              evmCalls.push(args);
              return { ok: true };
            },
          }) as any,
      },
    });

    await tempoSigner.bootstrapEcdsaSession({
      nearAccountId: 'alice.testnet',
      options: { chainTarget: TEMPO_CHAIN_TARGET, relayerUrl: 'https://relay.example.test' },
    });
    await evmSigner.bootstrapEcdsaSession({
      nearAccountId: 'alice.testnet',
      options: { chainTarget: EVM_CHAIN_TARGET, relayerUrl: 'https://relay.example.test' },
    });

    expect(tempoCalls[0]?.options?.chainTarget).toEqual(TEMPO_CHAIN_TARGET);
    expect(evmCalls[0]?.options?.chainTarget).toEqual(EVM_CHAIN_TARGET);
  });

  test('TempoSigner.reportBroadcastRejected forwards args in non-iframe mode', async () => {
    let capturedArgs: any = null;
    const signer = new TempoSigner({
      getContext: () =>
        ({
          signingEngine: {
            assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
            applyThresholdEcdsaPostSignPolicy,
            reportTempoBroadcastRejected: async (args: any) => {
              capturedArgs = args;
            },
          },
        }) as any,
      walletIframe: {
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('should not call router in non-iframe mode');
        },
      },
    });

    const signedResult = {
      chain: 'evm',
      kind: 'eip1559',
      txHashHex: '0x1',
      rawTxHex: '0x2',
    } as any;
    const onEvent = () => undefined;

    await signer.reportBroadcastRejected({
      nearAccountId: 'alice.testnet',
      signedResult,
      error: { code: 'nonce too low', message: 'nonce too low' },
      options: { onEvent },
    });

    expect(capturedArgs?.nearAccountId).toBe('alice.testnet');
    expect(capturedArgs?.signedResult).toEqual(signedResult);
    expect(capturedArgs?.error?.code).toContain('nonce');
    expect(capturedArgs?.onEvent).toBe(onEvent);
  });

  test('TempoSigner.reportBroadcastRejected serializes errors in iframe mode', async () => {
    const routerCalls: any[] = [];
    const signer = new TempoSigner({
      getContext: () => ({}) as any,
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () =>
          ({
            reportTempoBroadcastRejected: async (args: any) => {
              routerCalls.push(args);
            },
          }) as any,
      },
    });

    const error: any = new Error('replacement transaction underpriced');
    error.code = 'nonce_conflict_retryable';

    await signer.reportBroadcastRejected({
      nearAccountId: 'alice.testnet',
      signedResult: {
        chain: 'tempo',
        kind: 'tempoTransaction',
        senderHashHex: '0x3',
        rawTxHex: '0x4',
      } as any,
      error,
    });

    expect(routerCalls).toHaveLength(1);
    expect(routerCalls[0]?.nearAccountId).toBe('alice.testnet');
    expect(routerCalls[0]?.error?.code).toBe('nonce_conflict_retryable');
    expect(String(routerCalls[0]?.error?.message || '')).toContain('underpriced');
  });

  test('TempoSigner.executeEvmFamilyTransaction runs sign->broadcast->finalize lifecycle', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const events: any[] = [];
    const txHash = `0x${'ab'.repeat(32)}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              transactionHash: txHash,
              blockNumber: '0x1234',
              status: '0x1',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (method === 'eth_getTransactionByHash') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              to: '0x1111111111111111111111111111111111111111',
              input: '0xdeadbeef',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async (args: any) => {
                calls.signTempo += 1;
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
                    'succeeded',
                    {
                      sessionId: 'warm-session-1',
                    },
                  ),
                );
                args.onEvent?.(
                  createTestSigningEvent(SigningEventPhase.STEP_10_COMMIT_QUEUED, 'running'),
                );
                args.onEvent?.(
                  createTestSigningEvent(SigningEventPhase.STEP_10_COMMIT_STARTED, 'running'),
                );
                args.onEvent?.(
                  createTestSigningEvent(SigningEventPhase.STEP_11_TRANSACTION_SIGNED, 'succeeded'),
                );
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                };
              },
              reportTempoBroadcastAccepted: async (args: any) => {
                calls.reportBroadcastAccepted += 1;
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
                    'succeeded',
                    {
                      txHash,
                    },
                  ),
                );
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async () => {
                calls.reconcileNonceLane += 1;
                return {
                  chainNextNonce: '0',
                  unresolvedInFlightNonces: [],
                  blocked: false,
                };
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      const result = await signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
        request: {
          chain: 'evm',
          kind: 'eip1559',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 42431,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21000n,
            to: '0x1111111111111111111111111111111111111111',
            value: 0n,
            data: '0xdeadbeef',
            accessList: [],
          },
        },
        options: {
          onEvent: (event: any) => events.push(event),
        },
      });

      expect(result.txHash).toBe(txHash);
      expect(result.payloadVerification.verified).toBe(true);
      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportFinalized).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
      expect(events.map((event) => event.phase)).toEqual([
        SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
        SigningEventPhase.STEP_10_COMMIT_QUEUED,
        SigningEventPhase.STEP_10_COMMIT_STARTED,
        SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
        SigningEventPhase.STEP_12_BROADCAST_STARTED,
        SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
        SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
        SigningEventPhase.STEP_13_RECEIPT_FINALIZED,
        SigningEventPhase.STEP_15_COMPLETED,
      ]);
      expect(events.at(0)).toMatchObject({
        flow: 'signing',
        data: { sessionId: 'warm-session-1' },
      });
      expect(events.at(-1)).toMatchObject({
        flow: 'signing',
        status: 'succeeded',
        data: { operation: 'execute', txHash },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction reports broadcast rejection when send fails', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
    };
    const events: any[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: { code: -32000, message: 'insufficient funds for gas * price + value' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                };
              },
              reportTempoBroadcastAccepted: async () => {
                calls.reportBroadcastAccepted += 1;
              },
              reportTempoBroadcastRejected: async (args: any) => {
                calls.reportBroadcastRejected += 1;
                args.onEvent?.(
                  createTestSigningEvent(SigningEventPhase.STEP_12_BROADCAST_REJECTED, 'failed'),
                );
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          options: {
            onEvent: (event: any) => events.push(event),
          },
        }),
      ).rejects.toThrow('insufficient funds');

      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(0);
      expect(calls.reportBroadcastRejected).toBe(1);
      expect(calls.reportFinalized).toBe(0);
      expect(events.map((event) => event.phase)).toEqual([
        SigningEventPhase.STEP_12_BROADCAST_STARTED,
        SigningEventPhase.STEP_12_BROADCAST_REJECTED,
      ]);
      expect(events.at(-1)).toMatchObject({
        flow: 'signing',
        status: 'failed',
        message: 'Transaction broadcast failed',
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction reports dropped/replaced when nonce lane advances', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const txHash = `0x${'ef'.repeat(32)}`;
    const sender = '0x1111111111111111111111111111111111111111';
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionCount') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: '0x2' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionByHash') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getBlockByNumber') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { number: '0x1', baseFeePerGas: '0x1' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                  managedNonce: {
                    sender,
                    nonce: '1',
                  },
                };
              },
              reportTempoBroadcastAccepted: async () => {
                calls.reportBroadcastAccepted += 1;
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async () => {
                calls.reconcileNonceLane += 1;
                return {
                  chainNextNonce: '2',
                  unresolvedInFlightNonces: [],
                  blocked: false,
                };
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          finalization: {
            timeoutMs: 200,
            pollIntervalMs: 1,
          },
        }),
      ).rejects.toMatchObject({
        code: 'tx_dropped_or_replaced',
        reason: 'dropped',
      });

      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportDroppedOrReplaced).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction rejects on payload mismatch and reconciles nonce lane', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const events: any[] = [];
    const txHash = `0x${'12'.repeat(32)}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              transactionHash: txHash,
              blockNumber: '0x10',
              status: '0x1',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (method === 'eth_getTransactionByHash') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              to: '0x2222222222222222222222222222222222222222',
              input: '0xbeef',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                };
              },
              reportTempoBroadcastAccepted: async (args: any) => {
                calls.reportBroadcastAccepted += 1;
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
                    'succeeded',
                    {
                      txHash,
                    },
                  ),
                );
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async (args: any) => {
                calls.reconcileNonceLane += 1;
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
                    'running',
                  ),
                );
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
                    'succeeded',
                  ),
                );
                return {
                  chainNextNonce: '0',
                  unresolvedInFlightNonces: [],
                  blocked: false,
                };
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          options: {
            onEvent: (event: any) => events.push(event),
          },
        }),
      ).rejects.toMatchObject({
        code: 'tx_payload_mismatch',
      });

      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(1);
      expect(events.map((event) => event.phase)).toEqual([
        SigningEventPhase.STEP_12_BROADCAST_STARTED,
        SigningEventPhase.STEP_12_BROADCAST_ACCEPTED,
        SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
        SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
        SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED,
      ]);
      expect(events.at(-1)).toMatchObject({
        flow: 'signing',
        status: 'succeeded',
        message: 'Nonce state updated',
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction maps post-finalization check failures to canonical code', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const txHash = `0x${'56'.repeat(32)}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              transactionHash: txHash,
              blockNumber: '0x99',
              status: '0x1',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      if (method === 'eth_getTransactionByHash') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: {
              to: '0x1111111111111111111111111111111111111111',
              input: '0xdeadbeef',
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                };
              },
              reportTempoBroadcastAccepted: async () => {
                calls.reportBroadcastAccepted += 1;
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async () => {
                calls.reconcileNonceLane += 1;
                return {
                  chainNextNonce: '0',
                  unresolvedInFlightNonces: [],
                  blocked: false,
                };
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          postFinalizationCheck: async () => {
            throw new Error('greeting mismatch');
          },
        }),
      ).rejects.toMatchObject({
        code: 'post_finalization_state_mismatch',
      });

      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportFinalized).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction aborts finalization poll when shouldAbort flips true', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const txHash = `0x${'77'.repeat(32)}`;
    const rpcCalls = {
      receipt: 0,
    };
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt') {
        rpcCalls.receipt += 1;
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionByHash') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getBlockByNumber') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { number: '0x1', baseFeePerGas: '0x1' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      let cancelRequested = false;
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                };
              },
              reportTempoBroadcastAccepted: async () => {
                calls.reportBroadcastAccepted += 1;
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async () => {
                calls.reconcileNonceLane += 1;
                return {
                  chainNextNonce: '0',
                  unresolvedInFlightNonces: [],
                  blocked: false,
                };
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });
      setTimeout(() => {
        cancelRequested = true;
      }, 25);

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          finalization: {
            timeoutMs: 10_000,
            pollIntervalMs: 5_000,
          },
          options: {
            shouldAbort: () => cancelRequested,
          },
        }),
      ).rejects.toMatchObject({
        code: 'cancelled',
      });

      expect(rpcCalls.receipt).toBeGreaterThan(0);
      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('TempoSigner.executeEvmFamilyTransaction surfaces finalization timeout when nonce cleanup stalls', async () => {
    const calls = {
      signTempo: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const events: any[] = [];
    const txHash = `0x${'88'.repeat(32)}`;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (
      _input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      let body: Record<string, unknown> = {};
      try {
        body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
      } catch {}
      const id = body.id ?? Date.now();
      const method = String(body.method || '');
      if (method === 'eth_sendRawTransaction') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: txHash }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getTransactionReceipt' || method === 'eth_getTransactionByHash') {
        return new Response(JSON.stringify({ jsonrpc: '2.0', id, result: null }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (method === 'eth_getBlockByNumber') {
        return new Response(
          JSON.stringify({
            jsonrpc: '2.0',
            id,
            result: { number: '0x1', baseFeePerGas: '0x1' },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response(
        JSON.stringify({
          jsonrpc: '2.0',
          id,
          error: { code: -32601, message: `unsupported method: ${method}` },
        }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;

    try {
      const signer = new TempoSigner({
        getContext: () =>
          ({
            configs: {
              network: {
                chains: [
                  {
                    network: 'tempo-testnet',
                    rpcUrl: 'https://rpc.tempo.test',
                    explorerUrl: 'https://explorer.tempo.test',
                    chainId: 42431,
                  },
                ],
              },
            },
            signingEngine: {
              assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
              applyThresholdEcdsaPostSignPolicy,
              signTempo: async () => {
                calls.signTempo += 1;
                return {
                  chain: 'evm',
                  kind: 'eip1559',
                  txHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x02${'34'.repeat(31)}`,
                  managedNonce: {
                    sender: '0x1111111111111111111111111111111111111111',
                    nonce: '15',
                  },
                };
              },
              reportTempoBroadcastAccepted: async () => {
                calls.reportBroadcastAccepted += 1;
              },
              reportTempoBroadcastRejected: async () => {
                calls.reportBroadcastRejected += 1;
              },
              reportTempoFinalized: async () => {
                calls.reportFinalized += 1;
              },
              reportTempoDroppedOrReplaced: async () => {
                calls.reportDroppedOrReplaced += 1;
              },
              reconcileTempoNonceLane: async (args: any) => {
                calls.reconcileNonceLane += 1;
                args.onEvent?.(
                  createTestSigningEvent(
                    SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
                    'running',
                  ),
                );
                await new Promise(() => {});
              },
            },
          }) as any,
        walletIframe: {
          shouldUseWalletIframe: () => false,
          requireRouter: async () => {
            throw new Error('router should not be called');
          },
        },
      });

      await expect(
        signer.executeEvmFamilyTransaction({
      nearAccountId: 'alice.testnet',
      subjectId: TEST_SUBJECT_ID,
      chainTarget: TEMPO_CHAIN_TARGET,
          request: {
            chain: 'evm',
            kind: 'eip1559',
            senderSignatureAlgorithm: 'secp256k1',
            tx: {
              chainId: 42431,
              maxPriorityFeePerGas: 1n,
              maxFeePerGas: 2n,
              gasLimit: 21000n,
              to: '0x1111111111111111111111111111111111111111',
              value: 0n,
              data: '0xdeadbeef',
              accessList: [],
            },
          },
          finalization: {
            timeoutMs: 30,
            pollIntervalMs: 1,
          },
          options: {
            onEvent: (event: any) => events.push(event),
          },
        }),
      ).rejects.toThrow(
        /Timed out waiting for tx receipt|Timed out waiting for transaction finalization/,
      );

      expect(calls.signTempo).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(1);
      expect(events.map((event) => event.phase)).toContain(
        SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED,
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
