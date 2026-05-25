import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const TEST_SUBJECT_ID = toWalletSubjectId('alice.testnet');
const TEST_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const TEST_KEY_IDENTITY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  subjectId: TEST_SUBJECT_ID,
  rpId: 'wallet.example.test',
  ecdsaThresholdKeyId: 'ecdsa-key-1',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
});
const TEST_KEY_HANDLE = toEvmFamilyEcdsaKeyHandle('ehss-key-existing-1');
const TEST_LANE_POLICY = buildEvmFamilyEcdsaSessionLanePolicy({
  chainTarget: TEST_CHAIN_TARGET,
  thresholdSessionId: 'ecdsa-session-1',
  walletSigningSessionId: 'wallet-session-1',
  thresholdSessionKind: 'jwt',
  ttlMs: 300_000,
  remainingUses: 5,
});

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('threshold-ecdsa authorization bootstrap request shape', () => {
  test('authorization bootstrap rejects raw exact-session identity without shared key policy', async () => {
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    const result = await bootstrapEcdsaSession({
      indexedDB: {} as any,
      touchIdPrompt: {
        getRpId: () => 'wallet.example.test',
      } as any,
      relayerUrl: 'https://relay.example',
      userId: 'alice.testnet',
      chainTarget: TEST_CHAIN_TARGET,
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      sessionId: 'ecdsa-session-1',
      walletSigningSessionId: 'wallet-session-1',
      bootstrapAuth: { kind: 'app_session', jwt: appSessionJwt },
      clientRootShare32B64u,
      workerCtx: {
        requestWorkerOperation: async () => {
          throw new Error('raw exact-session bootstrap should fail before worker use');
        },
      },
    });

    expect(result.ok).toBe(false);
    expect(result.code).toBe('invalid_args');
    expect(result.message).toContain('shared key identity and lane policy');
  });

  test('authorization bootstrap does not spend managed registration grants on unlock warm-up', async () => {
    const requests: string[] = [];
    const originalFetch = globalThis.fetch;
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      requests.push(url);
      return new Response(
        JSON.stringify({
          ok: false,
          code: 'unauthorized',
          message: 'stop after first network boundary',
        }),
        {
          status: 401,
          headers: { 'Content-Type': 'application/json' },
        },
      );
    };

    try {
      await bootstrapEcdsaSession({
        indexedDB: {} as any,
        touchIdPrompt: {
          getRpId: () => 'wallet.example.test',
        } as any,
        relayerUrl: 'https://relay.example',
        userId: 'alice.testnet',
        chainTarget: TEST_CHAIN_TARGET,
        sessionKind: 'jwt',
        keyHandle: TEST_KEY_HANDLE,
        key: TEST_KEY_IDENTITY,
        lanePolicy: TEST_LANE_POLICY,
        bootstrapAuth: { kind: 'app_session', jwt: appSessionJwt },
        runtimeScopeBootstrap: {
          environmentId: 'env-test',
          publishableKey: 'pk_test_should_not_be_spent',
        },
        clientRootShare32B64u,
        workerCtx: {
          requestWorkerOperation: async () => {
            throw new Error('authorization bootstrap should not derive a local verifier hint');
          },
        },
      });

      expect(requests.some((url) => url.includes('/v1/registration/bootstrap-grants'))).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
