import { expect, test } from '@playwright/test';
import {
  createEvmSignerCapability,
  createNearSignerCapability,
  createTempoSignerCapability,
} from '@/core/signing/chainAdaptors/capabilityFactories';
import { ActionPhase } from '@/core/types/sdkSentEvents';

function createNearSignerWithRouter(router: Record<string, unknown>) {
  return createNearSignerCapability({
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

test.describe('TatchiPasskey chain signer modules', () => {
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
    expect(progressEvents.at(-1)?.phase).toBe(ActionPhase.STEP_8_ACTION_COMPLETE);
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

  test('TempoSigner forwards shouldAbort and keyRef in non-iframe mode', async () => {
    let capturedArgs: any = null;
    const expectedResult = { chain: 'tempo', kind: 'eip1559', txHashHex: '0x1', rawTxHex: '0x2' } as any;
    const shouldAbort = () => false;
    const signer = createTempoSignerCapability({
      getContext: () =>
        ({
          webAuthnManager: {
            signingActions: {
              signTempo: async (args: any) => {
                capturedArgs = args;
                return expectedResult;
              },
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
      request: {
        chain: 'tempo',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {},
      } as any,
      options: {
        confirmationConfig: { uiMode: 'modal' },
        thresholdEcdsaKeyRef: {
          kind: 'threshold-ecdsa-secp256k1',
          nearAccountId: 'alice.testnet',
          keyId: 'k1',
        } as any,
        shouldAbort,
      },
    });

    expect(result).toEqual(expectedResult);
    expect(capturedArgs?.shouldAbort).toBe(shouldAbort);
    expect(capturedArgs?.thresholdEcdsaKeyRef?.kind).toBe('threshold-ecdsa-secp256k1');
    expect(capturedArgs?.confirmationConfigOverride?.uiMode).toBe('modal');
  });

  test('TempoSigner and EvmSigner force chain during bootstrap', async () => {
    const tempoCalls: any[] = [];
    const evmCalls: any[] = [];

    const tempoSigner = createTempoSignerCapability({
      getContext: () => ({}) as any,
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () =>
          ({
            bootstrapThresholdEcdsaSession: async (args: any) => {
              tempoCalls.push(args);
              return { ok: true };
            },
          }) as any,
      },
    });
    const evmSigner = createEvmSignerCapability({
      getContext: () => ({}) as any,
      walletIframe: {
        shouldUseWalletIframe: () => true,
        requireRouter: async () =>
          ({
            bootstrapThresholdEcdsaSession: async (args: any) => {
              evmCalls.push(args);
              return { ok: true };
            },
          }) as any,
      },
    });

    await tempoSigner.bootstrapThresholdEcdsaSession({
      nearAccountId: 'alice.testnet',
      options: { chain: 'evm', relayerUrl: 'https://relay.example.test' },
    });
    await evmSigner.bootstrapThresholdEcdsaSession({
      nearAccountId: 'alice.testnet',
      options: { chain: 'tempo', relayerUrl: 'https://relay.example.test' },
    });

    expect(tempoCalls[0]?.options?.chain).toBe('tempo');
    expect(evmCalls[0]?.options?.chain).toBe('evm');
  });
});
