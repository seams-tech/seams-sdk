import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../server/src/core/ThresholdService/ethSignerWasm';
import { verifyEcdsaClientRootProof } from '../../server/src/core/ThresholdService/ecdsaClientRootProof';
import type { EcdsaHssClientRootProof } from '../../server/src/core/types';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';

const TEST_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const TEST_KEY_IDENTITY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
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
  test('client root proof rejects verification against an HSS client-share public key', async () => {
    const digest32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index));
    const clientRootPrivateKey32 = new Uint8Array(32).fill(1);
    const hssClientSharePrivateKey32 = new Uint8Array(32).fill(2);
    const clientRootPublicKey33 = await secp256k1PrivateKey32ToPublicKey33(clientRootPrivateKey32);
    const hssClientSharePublicKey33 =
      await secp256k1PrivateKey32ToPublicKey33(hssClientSharePrivateKey32);
    const signature65 = await signSecp256k1Recoverable(digest32, clientRootPrivateKey32);
    const rootProof: EcdsaHssClientRootProof = {
      version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
      digest32B64u: base64UrlEncode(digest32),
      signature65B64u: base64UrlEncode(signature65),
      clientRootPublicKey33B64u: base64UrlEncode(clientRootPublicKey33) as EcdsaHssClientRootProof['clientRootPublicKey33B64u'],
    };

    await expect(verifyEcdsaClientRootProof(rootProof)).resolves.toMatchObject({ ok: true });
    await expect(
      verifyEcdsaClientRootProof({
        ...rootProof,
        clientRootPublicKey33B64u: base64UrlEncode(
          hssClientSharePublicKey33,
        ) as EcdsaHssClientRootProof['clientRootPublicKey33B64u'],
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'unauthorized',
      message: 'Invalid client root proof',
    });
  });

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
    const bootstrapBodies: Array<Record<string, unknown>> = [];
    const originalFetch = globalThis.fetch;
    const clientRootShare32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const clientRootShare32B64u = base64UrlEncode(clientRootShare32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      requests.push(url);
      if (url.includes('/threshold-ecdsa/hss/bootstrap')) {
        bootstrapBodies.push(JSON.parse(String(init?.body || '{}')) as Record<string, unknown>);
      }
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
          requestWorkerOperation: async ({ kind, request }: any) => {
            if (
              kind === 'hssClient' &&
              request.type === WorkerRequestType.BuildThresholdEcdsaHssRoleLocalClientBootstrap
            ) {
              return {
                type: WorkerResponseType.BuildThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
                payload: {
                  walletId: 'alice.testnet',
                  rpId: 'wallet.example.test',
                  ecdsaThresholdKeyId: TEST_KEY_IDENTITY.ecdsaThresholdKeyId,
                  signingRootId: TEST_KEY_IDENTITY.signingRootId,
                  signingRootVersion: TEST_KEY_IDENTITY.signingRootVersion,
                  keyPurpose: 'evm-signing',
                  keyVersion: 'v1',
                  contextBinding32B64u: base64UrlEncode(new Uint8Array(32).fill(7)),
                  clientShare32B64u: clientRootShare32B64u,
                  clientPublicKey33B64u: base64UrlEncode(
                    Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
                  ),
                  mappedPrivateShare32B64u: clientRootShare32B64u,
                  verifyingShare33B64u: base64UrlEncode(
                    Uint8Array.from([2, ...Array.from({ length: 32 }, () => 9)]),
                  ),
                  clientShareRetryCounter: 0,
                },
              };
            }
            if (kind === 'ethSigner' && request.type === 'signSecp256k1Recoverable') {
              return new Uint8Array(65).fill(10).buffer;
            }
            if (kind === 'ethSigner' && request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return Uint8Array.from([2, ...Array.from({ length: 32 }, () => 11)]).buffer;
            }
            throw new Error(`unexpected worker request ${kind}:${String(request.type)}`);
          },
        },
      });

      expect(requests.some((url) => url.includes('/v1/registration/bootstrap-grants'))).toBe(false);
      expect(bootstrapBodies).toHaveLength(1);
      expect(bootstrapBodies[0]?.clientRootProof).toMatchObject({
        version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
        clientRootPublicKey33B64u: base64UrlEncode(
          Uint8Array.from([2, ...Array.from({ length: 32 }, () => 11)]),
        ),
      });
      expect(bootstrapBodies[0]?.passkeyBootstrapAuthorization).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
