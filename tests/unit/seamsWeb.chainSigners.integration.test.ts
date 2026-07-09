import { expect, test } from '@playwright/test';
import { SeamsWeb } from '@/SeamsWeb';
import { getWalletSession } from '@/SeamsWeb/operations/auth/login';
import { toSerializableTempoError } from '@/SeamsWeb/operations/tempo';
import { createEvmSignerCapability } from '@/SeamsWeb/publicApi/evm';
import { createTempoSignerCapability } from '@/SeamsWeb/publicApi/tempo';
import { IndexedDBManager } from '@/core/indexedDB';
import { createSigningFlowEvent, SigningEventPhase } from '@/core/types/sdkSentEvents';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const TEST_SUBJECT_ID = toWalletId('alice.testnet');
const TEST_NEAR_ACCOUNT = nearAccountRefFromAccountId('alice.testnet');
const TEST_WALLET_SESSION = walletSessionRefFromSession({
  walletId: 'alice.testnet',
  walletSessionUserId: 'alice.testnet',
});
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

function b64u(bytes: number[]): string {
  return Buffer.from(bytes).toString('base64url');
}

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

function createSeamsWebNearWithRouter(router: Record<string, unknown>) {
  const seams = new SeamsWeb({
    chains: [{ network: 'near-testnet', rpcUrl: 'https://rpc.testnet.near.org' }],
    relayer: { url: 'https://relay.example.test' },
    iframeWallet: { walletOrigin: 'https://wallet.example.test' },
  });
  (seams as any).walletIframe = {
    shouldUseWalletIframe: () => true,
    requireRouter: async () => router as any,
  };
  return seams.near;
}

function createLocalWalletIframe() {
  return {
    shouldUseWalletIframe: () => false,
    requireRouter: async () => {
      throw new Error('local capability test should not require wallet iframe router');
    },
  } as any;
}

function createLocalTempoCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createTempoSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: createLocalWalletIframe,
  } as any);
}

function createLocalEvmCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createEvmSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: createLocalWalletIframe,
  } as any);
}

test.describe('SeamsWeb chain signer modules', () => {
  test('NEAR capability.executeAction calls afterCall(true) on success in iframe mode', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const onErrors: Error[] = [];
    const expectedResult = { success: true, transactionId: 'tx-1' };
    const signer = createSeamsWebNearWithRouter({
      executeAction: async () => expectedResult,
    });

    const result = await signer.executeAction({
      walletSession: TEST_WALLET_SESSION,
      nearAccount: TEST_NEAR_ACCOUNT,
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

  test('NEAR capability.executeAction calls onError + afterCall(false) on router failure', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const onErrors: Error[] = [];
    const signer = createSeamsWebNearWithRouter({
      executeAction: async () => {
        throw new Error('router execute failed');
      },
    });

    await expect(
      signer.executeAction({
        walletSession: TEST_WALLET_SESSION,
        nearAccount: TEST_NEAR_ACCOUNT,
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

  test('NEAR capability.signAndSendTransaction emits completion event', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const progressEvents: any[] = [];
    const routerArgs: any[] = [];
    const signer = createSeamsWebNearWithRouter({
      signAndSendTransaction: async (args: any) => {
        routerArgs.push(args);
        args.options?.onEvent?.({
          phase: SigningEventPhase.STEP_15_COMPLETED,
          message: 'Transaction complete: tx-a',
        });
        return { success: true, transactionId: 'tx-a' };
      },
    });

    const result = await signer.signAndSendTransaction({
      walletSession: TEST_WALLET_SESSION,
      nearAccount: TEST_NEAR_ACCOUNT,
      receiverId: 'contract.testnet',
      actions: [] as any,
      options: {
        onEvent: (event: any) => progressEvents.push(event),
        afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
      } as any,
    });

    expect(result).toEqual({ success: true, transactionId: 'tx-a' });
    expect(routerArgs).toHaveLength(1);
    expect(afterCalls).toEqual([{ ok: true, result }]);
    expect(progressEvents.at(-1)?.phase).toBe(SigningEventPhase.STEP_15_COMPLETED);
    expect(progressEvents.at(-1)?.message).toContain('tx-a');
  });

  test('NEAR capability.signAndSendDelegateAction reports afterCall(false) when relay returns ok=false', async () => {
    const afterCalls: Array<{ ok: boolean; result?: unknown }> = [];
    const signer = createSeamsWebNearWithRouter({});
    const signResult = {
      signedDelegate: { delegate_action: {}, signature: '' },
      hash: 'abc123',
      nearAccountId: 'alice.testnet',
    } as any;
    const relayResult = { ok: false, status: 500 } as any;

    (signer as any).signDelegateAction = async () => signResult;
    (signer as any).sendDelegateActionViaRelayer = async () => relayResult;

    const combined = await signer.signAndSendDelegateAction({
      walletSession: TEST_WALLET_SESSION,
      nearAccount: TEST_NEAR_ACCOUNT,
      delegate: { senderId: 'alice.testnet', receiverId: 'contract.testnet', actions: [] } as any,
      relayerUrl: 'https://relay.example.test',
      options: {
        afterCall: async (ok: boolean, out?: unknown) => afterCalls.push({ ok, result: out }),
      } as any,
    });

    expect(combined).toEqual({ signResult, relayResult });
    expect(afterCalls).toEqual([{ ok: false, result: undefined }]);
  });

  test('Tempo capability forwards shouldAbort in non-iframe mode', async () => {
    let capturedArgs: any = null;
    const expectedResult = { chain: 'evm', txHashHex: '0x1', rawTxHex: '0x2' } as any;
    const shouldAbort = () => false;
    const signer = createLocalTempoCapability({
      getContext: () =>
        ({
          signingEngine: {
            assertThresholdEcdsaOperationAllowed: allowThresholdEcdsaOperation,
            applyThresholdEcdsaPostSignPolicy,
            signEvmFamily: async (args: any) => {
              capturedArgs = args;
              return expectedResult;
            },
          },
        }) as any,
    });

    const result = await signer.signTempo({
      walletSession: walletSessionRefFromSession({
        walletId: 'alice.testnet',
        walletSessionUserId: 'alice.testnet',
      }),
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

  test('Tempo capability and EVM capability local paths force chain during bootstrap', async () => {
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

    const tempoSigner = createLocalTempoCapability({
      getContext: () =>
        ({
          configs,
          signingEngine: {
            bootstrapEcdsaSession: async (args: any) => {
              tempoCalls.push(args);
              return { ok: true };
            },
          },
        }) as any,
    });
    const evmSigner = createLocalEvmCapability({
      getContext: () =>
        ({
          configs,
          signingEngine: {
            bootstrapEcdsaSession: async (args: any) => {
              evmCalls.push(args);
              return { ok: true };
            },
          },
        }) as any,
    });

    await tempoSigner.bootstrapEcdsaSession({
      kind: 'reuse_warm_ecdsa_bootstrap',
      walletSession: walletSessionRefFromSession({
        walletId: 'alice.testnet',
        walletSessionUserId: 'alice.testnet',
      }),
      chainTarget: TEMPO_CHAIN_TARGET,
      relayerUrl: 'https://relay.example.test',
    });
    await evmSigner.bootstrapEcdsaSession({
      kind: 'reuse_warm_ecdsa_bootstrap',
      walletSession: walletSessionRefFromSession({
        walletId: 'alice.testnet',
        walletSessionUserId: 'alice.testnet',
      }),
      chainTarget: EVM_CHAIN_TARGET,
      relayerUrl: 'https://relay.example.test',
    });

    expect(tempoCalls[0]?.chainTarget).toEqual(TEMPO_CHAIN_TARGET);
    expect(evmCalls[0]?.chainTarget).toEqual(EVM_CHAIN_TARGET);
  });

  test('wallet session does not expose profile-only threshold ECDSA owner address', async () => {
    const clientDb = IndexedDBManager as unknown as Record<string, unknown>;
    const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
    const originalGetProfileContinuitySnapshot = clientDb.getProfileContinuitySnapshot;
    const originalListAccountSignersByProfile = clientDb.listAccountSignersByProfile;
    const ownerAddress = `0x${'11'.repeat(20)}`;
    const chainAccountAddress = `0x${'22'.repeat(20)}`;

    clientDb.resolveProfileAccountContext = async () => ({
      profileId: 'profile-1',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    });
    clientDb.getProfileContinuitySnapshot = async () => ({
      profile: {
        profileId: 'profile-1',
        createdAt: 1,
        updatedAt: 1,
      },
      chainAccounts: [
        {
          profileId: 'profile-1',
          chainIdKey: 'evm:5042002',
          accountAddress: chainAccountAddress,
          accountModel: 'threshold-ecdsa',
          status: 'active',
          isPrimary: true,
          createdAt: 1,
          updatedAt: 1,
        },
      ],
      accountSigners: [],
    });
    clientDb.listAccountSignersByProfile = async () => [
      {
        profileId: 'profile-1',
        chainIdKey: 'evm:5042002',
        accountAddress: chainAccountAddress,
        signerId: ownerAddress,
        signerSlot: 1,
        signerType: 'threshold',
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
        status: 'active',
        addedAt: 1,
        updatedAt: 1,
        metadata: {
          ownerAddress,
        },
      },
    ];

    try {
      const walletSession = await getWalletSession(
        {
          configs: {
            network: {
              chains: [
                {
                  network: 'arc-testnet',
                  chainId: 5042002,
                },
              ],
            },
            signing: {
              sessionDefaults: {
                ttlMs: 60_000,
                remainingUses: 3,
              },
            },
          },
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => null,
            listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
          },
        } as any,
        'alice.testnet',
      );

      expect(walletSession.login.thresholdEcdsaEthereumAddress).toBeNull();
      expect(walletSession.login.thresholdEcdsaEthereumAddress).not.toBe(chainAccountAddress);
      expect(walletSession.login.thresholdEcdsaEthereumAddress).not.toBe(ownerAddress);
    } finally {
      clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
      clientDb.getProfileContinuitySnapshot = originalGetProfileContinuitySnapshot;
      clientDb.listAccountSignersByProfile = originalListAccountSignersByProfile;
    }
  });

  test('wallet session exposes registered threshold ECDSA owner address from complete profile key facts', async () => {
    const clientDb = IndexedDBManager as unknown as Record<string, unknown>;
    const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
    const originalGetProfileContinuitySnapshot = clientDb.getProfileContinuitySnapshot;
    const originalListAccountSignersByProfile = clientDb.listAccountSignersByProfile;
    const ownerAddress = `0x${'33'.repeat(20)}`;
    const publicKeyB64u = b64u([2, ...Array(32).fill(7)]);

    clientDb.resolveProfileAccountContext = async () => ({
      profileId: 'profile-registered-ecdsa',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    });
    clientDb.getProfileContinuitySnapshot = async () => ({
      profile: {
        profileId: 'profile-registered-ecdsa',
        createdAt: 1,
        updatedAt: 1,
      },
      chainAccounts: [
        {
          profileId: 'profile-registered-ecdsa',
          chainIdKey: 'evm:5042002',
          accountAddress: ownerAddress,
          accountModel: 'threshold-ecdsa',
          status: 'active',
          isPrimary: true,
          createdAt: 1,
          updatedAt: 1,
        },
      ],
      accountSigners: [],
    });
    clientDb.listAccountSignersByProfile = async () => [
      {
        profileId: 'profile-registered-ecdsa',
        chainIdKey: 'evm:5042002',
        accountAddress: ownerAddress,
        signerId: ownerAddress,
        signerSlot: 1,
        signerType: 'threshold',
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
        status: 'active',
        addedAt: 1,
        updatedAt: 1,
        metadata: {
          ownerAddress,
          thresholdOwnerAddress: ownerAddress,
          keyScope: 'evm-family',
          keyHandle: 'ehss-key-registered',
          walletId: 'alice.testnet',
          rpId: 'wallet.example.test',
          ecdsaThresholdKeyId: 'ehss-registered',
          signingRootId: 'project:dev',
          signingRootVersion: 'default',
          thresholdEcdsaPublicKeyB64u: publicKeyB64u,
          participantIds: [1, 2],
          chainTarget: EVM_CHAIN_TARGET,
          sharedEvmFamilyKey: {
            walletId: 'alice.testnet',
            rpId: 'wallet.example.test',
            keyHandle: 'ehss-key-registered',
            ecdsaThresholdKeyId: 'ehss-registered',
            signingRootId: 'project:dev',
            signingRootVersion: 'default',
            participantIds: [1, 2],
            thresholdOwnerAddress: ownerAddress,
            thresholdEcdsaPublicKeyB64u: publicKeyB64u,
          },
        },
      },
    ];

    try {
      const walletSession = await getWalletSession(
        {
          configs: {
            network: {
              chains: [
                {
                  network: 'arc-testnet',
                  chainId: 5042002,
                },
              ],
            },
            signing: {
              sessionDefaults: {
                ttlMs: 60_000,
                remainingUses: 3,
              },
            },
          },
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => null,
            listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
          },
        } as any,
        'alice.testnet',
      );

      expect(walletSession.login.thresholdEcdsaEthereumAddress).toBe(ownerAddress);
      expect(walletSession.login.thresholdEcdsaPublicKeyB64u).toBe(publicKeyB64u);
    } finally {
      clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
      clientDb.getProfileContinuitySnapshot = originalGetProfileContinuitySnapshot;
      clientDb.listAccountSignersByProfile = originalListAccountSignersByProfile;
    }
  });

  test('wallet session ignores conflicting threshold ECDSA record addresses without complete profile fallback', async () => {
    const clientDb = IndexedDBManager as unknown as Record<string, unknown>;
    const originalResolveProfileAccountContext = clientDb.resolveProfileAccountContext;
    const originalGetProfileContinuitySnapshot = clientDb.getProfileContinuitySnapshot;
    const originalListAccountSignersByProfile = clientDb.listAccountSignersByProfile;
    const originalWarn = console.warn;
    const ownerAddress = `0x${'aa'.repeat(20)}`;
    const chainAccountAddress = `0x${'bb'.repeat(20)}`;

    clientDb.resolveProfileAccountContext = async () => ({
      profileId: 'profile-conflict',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    });
    clientDb.getProfileContinuitySnapshot = async () => ({
      profile: {
        profileId: 'profile-conflict',
        createdAt: 1,
        updatedAt: 1,
      },
      chainAccounts: [
        {
          profileId: 'profile-conflict',
          chainIdKey: 'evm:5042002',
          accountAddress: chainAccountAddress,
          accountModel: 'threshold-ecdsa',
          status: 'active',
          isPrimary: true,
          createdAt: 1,
          updatedAt: 1,
        },
      ],
      accountSigners: [],
    });
    clientDb.listAccountSignersByProfile = async () => [
      {
        profileId: 'profile-conflict',
        chainIdKey: 'evm:5042002',
        accountAddress: chainAccountAddress,
        signerId: ownerAddress,
        signerSlot: 1,
        signerType: 'threshold',
        signerKind: 'threshold-ecdsa',
        signerAuthMethod: 'passkey',
        signerSource: 'passkey_registration',
        status: 'active',
        addedAt: 1,
        updatedAt: 1,
        metadata: {
          ownerAddress,
        },
      },
    ];
    console.warn = (() => undefined) as typeof console.warn;

    try {
      const walletSession = await getWalletSession(
        {
          configs: {
            network: {
              chains: [
                {
                  network: 'arc-testnet',
                  chainId: 5042002,
                },
              ],
            },
            signing: {
              sessionDefaults: {
                ttlMs: 60_000,
                remainingUses: 3,
              },
            },
          },
          signingEngine: {
            assertSealedRefreshStartupParity: async () => undefined,
            getLastUser: async () => null,
            getUserBySignerSlot: async () => null,
            getWarmThresholdEd25519SessionStatus: async () => null,
            listThresholdEcdsaSessionRecordsForWalletTarget: () =>
              [
                { source: 'login', ethereumAddress: `0x${'11'.repeat(20)}` },
                { source: 'manual-bootstrap', ethereumAddress: `0x${'22'.repeat(20)}` },
              ] as any,
          },
        } as any,
        'alice.testnet',
      );

      expect(walletSession.login.thresholdEcdsaEthereumAddress).toBeNull();
      expect(walletSession.login.thresholdEcdsaEthereumAddress).not.toBe(ownerAddress);
    } finally {
      console.warn = originalWarn;
      clientDb.resolveProfileAccountContext = originalResolveProfileAccountContext;
      clientDb.getProfileContinuitySnapshot = originalGetProfileContinuitySnapshot;
      clientDb.listAccountSignersByProfile = originalListAccountSignersByProfile;
    }
  });

  test('Tempo capability.reportBroadcastRejected forwards args in non-iframe mode', async () => {
    let capturedArgs: any = null;
    const signer = createLocalTempoCapability({
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
    });

    const signedResult = {
      chain: 'evm',
      kind: 'eip1559',
      txHashHex: '0x1',
      rawTxHex: '0x2',
    } as any;
    const onEvent = () => undefined;

    await signer.reportBroadcastRejected({
      walletSession: TEST_WALLET_SESSION,
      signedResult,
      error: { code: 'nonce too low', message: 'nonce too low' },
      options: { onEvent },
    });

    expect(capturedArgs?.walletId).toBe('alice.testnet');
    expect(capturedArgs?.signedResult).toEqual(signedResult);
    expect(capturedArgs?.error?.code).toContain('nonce');
    expect(capturedArgs?.onEvent).toBe(onEvent);
  });

  test('toSerializableTempoError keeps retry metadata for iframe payloads', async () => {
    const error: any = new Error('replacement transaction underpriced');
    error.code = 'nonce_conflict_retryable';

    const serialized = toSerializableTempoError(error);

    expect(serialized?.code).toBe('nonce_conflict_retryable');
    expect(String(serialized?.message || '')).toContain('underpriced');
  });

  test('Tempo capability.executeEvmFamilyTransaction runs sign->broadcast->finalize lifecycle', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async (args: any) => {
                calls.signEvmFamily += 1;
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
      });

      const result = await signer.executeEvmFamilyTransaction({
        walletSession: TEST_WALLET_SESSION,
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
      expect(result.payloadVerification.kind).toBe('matched');
      expect(calls.signEvmFamily).toBe(1);
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

  test('Tempo capability.executeEvmFamilyTransaction verifies finalized EIP-2718 call payloads', async () => {
    const calls = {
      signEvmFamily: 0,
      reportBroadcastAccepted: 0,
      reportBroadcastRejected: 0,
      reportFinalized: 0,
      reportDroppedOrReplaced: 0,
      reconcileNonceLane: 0,
    };
    const txHash = `0x${'76'.repeat(32)}`;
    const tempoCallTo = '0xbb442b54c85efba2d7b81ea52990ad638cdba483';
    const tempoCallInput = '0xa41368620000000000000000000000000000000000000000000000000000000000000020';
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
              type: '0x76',
              to: null,
              input: null,
              calls: [
                {
                  to: tempoCallTo,
                  value: '0x0',
                  input: tempoCallInput,
                  data: null,
                },
              ],
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
                return {
                  chain: 'tempo',
                  kind: 'tempoTransaction',
                  senderHashHex: `0x${'cd'.repeat(32)}`,
                  rawTxHex: `0x76${'34'.repeat(31)}`,
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
      });

      const result = await signer.executeEvmFamilyTransaction({
        walletSession: TEST_WALLET_SESSION,
        chainTarget: TEMPO_CHAIN_TARGET,
        request: {
          chain: 'tempo',
          kind: 'tempoTransaction',
          senderSignatureAlgorithm: 'secp256k1',
          tx: {
            chainId: 42431,
            maxPriorityFeePerGas: 1n,
            maxFeePerGas: 2n,
            gasLimit: 21000n,
            calls: [
              {
                to: tempoCallTo,
                value: 0n,
                input: tempoCallInput,
              },
            ],
            accessList: [],
            nonceKey: 0n,
          },
        },
      });

      expect(result.txHash).toBe(txHash);
      expect(result.payloadVerification).toMatchObject({
        kind: 'matched',
        observed: {
          kind: 'tempo_eip2718_calls',
          calls: [
            {
              to: tempoCallTo,
              input: tempoCallInput,
              data: null,
            },
          ],
        },
      });
      expect(calls.signEvmFamily).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportFinalized).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('Tempo capability.executeEvmFamilyTransaction reports broadcast rejection when send fails', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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

      expect(calls.signEvmFamily).toBe(1);
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

  test('Tempo capability.executeEvmFamilyTransaction reports dropped/replaced when nonce lane advances', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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

      expect(calls.signEvmFamily).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportDroppedOrReplaced).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('Tempo capability.executeEvmFamilyTransaction rejects on payload mismatch and reconciles nonce lane', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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

      expect(calls.signEvmFamily).toBe(1);
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

  test('Tempo capability.executeEvmFamilyTransaction maps post-finalization check failures to canonical code', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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

      expect(calls.signEvmFamily).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportFinalized).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('Tempo capability.executeEvmFamilyTransaction aborts finalization poll when shouldAbort flips true', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });
      setTimeout(() => {
        cancelRequested = true;
      }, 25);

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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
      expect(calls.signEvmFamily).toBe(1);
      expect(calls.reportBroadcastAccepted).toBe(1);
      expect(calls.reportBroadcastRejected).toBe(0);
      expect(calls.reportFinalized).toBe(0);
      expect(calls.reportDroppedOrReplaced).toBe(0);
      expect(calls.reconcileNonceLane).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('Tempo capability.executeEvmFamilyTransaction surfaces finalization timeout when nonce cleanup stalls', async () => {
    const calls = {
      signEvmFamily: 0,
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
      const signer = createLocalTempoCapability({
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
              signEvmFamily: async () => {
                calls.signEvmFamily += 1;
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
      });

      await expect(
        signer.executeEvmFamilyTransaction({
          walletSession: TEST_WALLET_SESSION,
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

      expect(calls.signEvmFamily).toBe(1);
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
