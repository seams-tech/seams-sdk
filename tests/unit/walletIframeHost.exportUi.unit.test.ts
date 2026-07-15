import { expect, test } from '@playwright/test';
import { createWalletIframeHandlers } from '@/SeamsWeb/walletIframe/host/wallet-iframe-handlers';
import type { ChildToParentEnvelope } from '@/SeamsWeb/walletIframe/shared/messages';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  nearAccountRefFromAccountId,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEd25519SigningLaneIdentity,
  exactEcdsaSigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

type Deferred<T> = {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
};

const EXPORT_WALLET_ID = toWalletId('wallet-export-host');
const EXPORT_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const EXPORT_KEY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: EXPORT_WALLET_ID,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: EXPORT_WALLET_ID,
    signingRootId: 'signing-root-export-host',
    signingRootVersion: 'root-v1',
  }),
  ecdsaThresholdKeyId: 'ecdsa-threshold-export-host',
  signingRootId: 'signing-root-export-host',
  signingRootVersion: 'root-v1',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const EXPORT_LANE = exactEcdsaSigningLaneIdentity({
  signer: buildEvmFamilyEcdsaSignerBinding({
    walletId: EXPORT_WALLET_ID,
    chainTarget: EXPORT_CHAIN_TARGET,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ecdsa-key-handle-export-host'),
    key: EXPORT_KEY,
  }),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'cred-export-host',
  },
  signingGrantId: 'grant-export-host',
  thresholdSessionId: 'threshold-export-host',
});
const EXPORT_WALLET_SESSION = walletSessionRefFromSession({
  walletId: EXPORT_WALLET_ID,
  walletSessionUserId: EXPORT_WALLET_ID,
});
const EXPORT_NEAR_ACCOUNT = nearAccountRefFromAccountId('wallet-export-host.testnet');
const EXPORT_ED25519_LANE = exactEd25519SigningLaneIdentity({
  signer: nearEd25519SignerBindingFromBoundaryFields({
    walletId: EXPORT_WALLET_ID,
    nearAccountId: EXPORT_NEAR_ACCOUNT.accountId,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      'ed25519ks_wallet_export_host',
    ),
    signerSlot: 1,
  }),
  auth: {
    kind: 'passkey',
    rpId: toRpId('example.test'),
    credentialIdB64u: 'cred-ed25519-export-host',
  },
  signingGrantId: 'grant-ed25519-export-host',
  thresholdSessionId: 'threshold-ed25519-export-host',
});

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

function makeExportKeypairReq(requestId: string): any {
  return {
    type: 'PM_EXPORT_KEYPAIR_UI',
    requestId,
    payload: {
      kind: 'ecdsa',
      walletSession: EXPORT_WALLET_SESSION,
      chainTarget: EXPORT_CHAIN_TARGET,
      laneIdentity: EXPORT_LANE,
      options: {
        variant: 'drawer',
        theme: 'dark',
      },
    },
  };
}

function makeEd25519ExportKeypairReq(requestId: string): any {
  return {
    type: 'PM_EXPORT_KEYPAIR_UI',
    requestId,
    payload: {
      kind: 'ed25519',
      walletSession: EXPORT_WALLET_SESSION,
      nearAccount: EXPORT_NEAR_ACCOUNT,
      laneIdentity: EXPORT_ED25519_LANE,
      options: {
        variant: 'drawer',
        theme: 'dark',
      },
    },
  };
}

test.describe('wallet iframe host export UI handlers', () => {
  test('forwards the exact Ed25519 wallet, NEAR account, and passkey lane', async () => {
    const posts: ChildToParentEnvelope[] = [];
    let exportedInput: any;
    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          keys: {
            exportKeypairWithUI: async (input: any) => {
              exportedInput = input;
            },
          },
        }) as any,
      post: (message) => posts.push(message),
      postProgress: () => undefined,
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    await handlers.PM_EXPORT_KEYPAIR_UI!(
      makeEd25519ExportKeypairReq('req-ed25519-export') as any,
    );

    expect(exportedInput).toEqual(
      expect.objectContaining({
        kind: 'ed25519',
        walletSession: EXPORT_WALLET_SESSION,
        nearAccount: EXPORT_NEAR_ACCOUNT,
        laneIdentity: EXPORT_ED25519_LANE,
      }),
    );
    expect(exportedInput.chainTarget).toBeUndefined();
    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'req-ed25519-export',
      }),
    ]);
  });

  test('PM_EXPORT_KEYPAIR_UI waits for export operation before PM_RESULT', async () => {
    const posts: ChildToParentEnvelope[] = [];
    const progress: unknown[] = [];
    const deferred = createDeferred<void>();
    let exportCalls = 0;
    let exportedInput: any;

    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          keys: {
            exportKeypairWithUI: async (input: any) => {
              exportCalls += 1;
              exportedInput = input;
              input.options?.onEvent?.({
                version: 2,
                flow: 'key_export',
                step: 1,
                phase: 'key_export.started',
                status: 'running',
                message: 'Preparing key export',
                flowId: 'key-export:test',
                requestId: 'req-await',
                accountId: 'alice.testnet',
              });
              return await deferred.promise;
            },
          },
        }) as any,
      post: (msg) => posts.push(msg),
      postProgress: (_requestId, payload) => progress.push(payload),
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    const requestPromise = handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-await') as any);
    await Promise.resolve();

    expect(exportCalls).toBe(1);
    expect(exportedInput.laneIdentity).toEqual(
      expect.objectContaining({
        kind: 'exact_signing_lane',
        signingGrantId: 'grant-export-host',
        thresholdSessionId: 'threshold-export-host',
      }),
    );
    expect(progress).toEqual([
      expect.objectContaining({
        flow: 'key_export',
        phase: 'key_export.started',
      }),
    ]);
    expect(posts).toEqual([]);

    deferred.resolve(undefined);
    await requestPromise;

    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'req-await',
      }),
    ]);
  });

  test('PM_EXPORT_KEYPAIR_UI throws on non-cancellation export errors', async () => {
    const posts: ChildToParentEnvelope[] = [];

    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          keys: {
            exportKeypairWithUI: async () => {
              throw new Error('No key material found for account alice.testnet device 1');
            },
          },
        }) as any,
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    await expect(
      handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-error') as any),
    ).rejects.toThrow('No key material found for account alice.testnet device 1');

    expect(posts).toEqual([]);
  });

  test('PM_EXPORT_KEYPAIR_UI treats TouchID cancellation as non-fatal', async () => {
    const posts: ChildToParentEnvelope[] = [];

    const handlers = createWalletIframeHandlers({
      getSeamsWeb: () =>
        ({
          keys: {
            exportKeypairWithUI: async () => {
              throw new Error(
                'NotAllowedError: The operation either timed out or was not allowed.',
              );
            },
          },
        }) as any,
      post: (msg) => posts.push(msg),
      postProgress: () => undefined,
      isCancelled: () => false,
      respondIfCancelled: () => false,
    });

    await handlers.PM_EXPORT_KEYPAIR_UI!(makeExportKeypairReq('req-cancel') as any);

    expect(posts).toEqual([
      expect.objectContaining({
        type: 'PM_RESULT',
        requestId: 'req-cancel',
      }),
    ]);
  });
});
