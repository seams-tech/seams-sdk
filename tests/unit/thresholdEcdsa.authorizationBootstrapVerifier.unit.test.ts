import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';
import { verifyEcdsaClientRootProof } from '../../packages/sdk-server-ts/src/core/ThresholdService/ecdsaClientRootProof';
import type { EcdsaHssClientRootProof } from '../../packages/sdk-server-ts/src/core/types';
import { bootstrapEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/bootstrapSession';
import { activateEcdsaSession } from '@/core/signingEngine/threshold/ecdsa/activation';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  buildEvmFamilyEcdsaSessionLanePolicy,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { WorkerRequestType, WorkerResponseType } from '@/core/types/signer-worker';
import {
  HssClientCustomRequestType,
  HssClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import {
  ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
  routerAbEcdsaHssContextBindingB64uV1,
} from '@shared/utils/routerAbEcdsaHss';
import { ROUTER_AB_PUBLIC_KEYSET_VERSION_V2 } from '@shared/utils/routerAbPublicKeyset';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';

const TEST_CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const TEST_KEY_IDENTITY = buildEvmFamilyEcdsaKeyIdentity({
  walletId: 'alice.testnet',
  walletKeyId: 'wallet-key-alice',
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
  signingGrantId: 'wallet-session-1',
  thresholdSessionKind: 'jwt',
  ttlMs: 300_000,
  remainingUses: 5,
});

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

function address20B64u(address: string): string {
  const hex = address.startsWith('0x') ? address.slice(2) : address;
  return Buffer.from(hex, 'hex').toString('base64url');
}

test.describe('threshold-ecdsa authorization bootstrap request shape', () => {
  test('activation rejects disabled Router A/B normal signing before bootstrap side effects', async () => {
    let fetchCalled = false;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      fetchCalled = true;
      throw new Error('activation should fail before network use');
    };

    try {
      await expect(
        activateEcdsaSession(
          {
            credentialStore: {} as any,
            touchIdPrompt: {
              getRpId: () => 'wallet.example.test',
            } as any,
            workerCtx: {
              requestWorkerOperation: async () => {
                throw new Error('activation should fail before worker use');
              },
            },
            routerAbNormalSigning: { mode: 'disabled' },
            getOrCreateActiveThresholdEcdsaSessionId: () => {
              throw new Error('activation should fail before session id allocation');
            },
          },
          {
            kind: 'key_enrollment_bootstrap',
            walletId: 'frost-vermillion-k7p9m2',
            chainTarget: TEST_CHAIN_TARGET,
            relayerUrl: 'https://relay.example',
            authKind: 'passkey_prf_b64u',
            passkeyPrfFirstB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
            passkeyCredentialIdB64u: 'credential-id',
          },
        ),
      ).rejects.toThrow('Router A/B ECDSA-HSS normal signing must be enabled for activation');
      expect(fetchCalled).toBe(false);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('activation stores role-local material in the worker before publishing a signable key ref', async () => {
    const originalFetch = globalThis.fetch;
    const storedMaterials: Array<{ materialHandle: string; bindingDigest: string }> = [];
    const contextBinding32B64u = await routerAbEcdsaHssContextBindingB64uV1({
      application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
    });
    const clientPublicKey33B64u = base64UrlEncode(
      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
    );
    const serverPublicKey33B64u = base64UrlEncode(
      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 10)]),
    );
    const groupPublicKey33B64u = base64UrlEncode(
      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 12)]),
    );
    const clientVerifyingShareB64u = clientPublicKey33B64u;
    const ownerAddress = '0x1111111111111111111111111111111111111111';

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      if (url.endsWith('/router-ab/keyset')) {
        return new Response(
          JSON.stringify({
            keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
            signer_envelope_hpke: {
              current: {
                deriver_a: {
                  role: 'signer_a',
                  key_epoch: 'epoch-a',
                  public_key:
                    'x25519:1111111111111111111111111111111111111111111111111111111111111111',
                },
                deriver_b: {
                  role: 'signer_b',
                  key_epoch: 'epoch-b',
                  public_key:
                    'x25519:2222222222222222222222222222222222222222222222222222222222222222',
                },
              },
            },
            signer_peer_verifying_keys: {
              deriver_a: {
                role: 'signer_a',
                verifying_key_hex:
                  'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
              },
              deriver_b: {
                role: 'signer_b',
                verifying_key_hex:
                  'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
              },
            },
            signing_worker_server_output_hpke: {
              key_epoch: 'signing-worker-epoch',
              public_key:
                'x25519:3333333333333333333333333333333333333333333333333333333333333333',
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url.endsWith('/router-ab/ecdsa-hss/bootstrap')) {
        const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        const participantIds = Array.isArray(body.participantIds)
          ? body.participantIds.map((participantId) => Number(participantId))
          : [1, 2];
        const expiresAtMs = Date.now() + 300_000;
        const normalSigning = {
          kind: ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_STATE_KIND_V1,
          scope: {
            wallet_key_id: body.walletKeyId,
            context: {
              wallet_id: body.walletId,
              ecdsa_threshold_key_id: body.ecdsaThresholdKeyId,
              signing_root_id: body.signingRootId,
              signing_root_version: body.signingRootVersion,
            },
            public_identity: {
              context_binding_b64u: contextBinding32B64u,
              client_public_key33_b64u: clientPublicKey33B64u,
              server_public_key33_b64u: serverPublicKey33B64u,
              threshold_public_key33_b64u: groupPublicKey33B64u,
              ethereum_address20_b64u: address20B64u(ownerAddress),
              client_share_retry_counter: 0,
              server_share_retry_counter: 0,
            },
            signing_worker: {
              server_id: 'signing-worker-local',
              key_epoch: 'signing-worker-epoch',
              recipient_encryption_key:
                'x25519:3333333333333333333333333333333333333333333333333333333333333333',
            },
            activation_epoch: body.sessionId,
          },
        };
        const jwt = jwtWithPayload({
          kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
          sub: body.walletId,
          walletId: body.walletId,
          walletKeyId: body.walletKeyId,
          rpId: body.rpId,
          keyScope: ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1,
          keyHandle: TEST_KEY_HANDLE,
          relayerKeyId: body.relayerKeyId,
          thresholdSessionId: body.sessionId,
          signingGrantId: body.signingGrantId,
          thresholdExpiresAtMs: expiresAtMs,
          participantIds,
          routerAbEcdsaHssNormalSigning: normalSigning,
        });
        return new Response(
          JSON.stringify({
            ok: true,
            value: {
              formatVersion: 'ecdsa-hss-role-local',
              walletId: body.walletId,
              walletKeyId: body.walletKeyId,
              rpId: body.rpId,
              ecdsaThresholdKeyId: body.ecdsaThresholdKeyId,
              relayerKeyId: body.relayerKeyId,
              contextBinding32B64u,
              publicIdentity: {
                hssClientSharePublicKey33B64u: clientPublicKey33B64u,
                relayerPublicKey33B64u: serverPublicKey33B64u,
                groupPublicKey33B64u,
                ethereumAddress: ownerAddress,
              },
              clientShareRetryCounter: 0,
              relayerShareRetryCounter: 0,
              publicTranscriptDigest32B64u: base64UrlEncode(new Uint8Array(32).fill(13)),
              keyHandle: TEST_KEY_HANDLE,
              signingRootId: body.signingRootId,
              signingRootVersion: body.signingRootVersion,
              thresholdEcdsaPublicKeyB64u: groupPublicKey33B64u,
              ethereumAddress: ownerAddress,
              relayerVerifyingShareB64u: serverPublicKey33B64u,
              participantIds,
              thresholdSessionId: body.sessionId,
              signingGrantId: body.signingGrantId,
              expiresAtMs,
              expiresAt: new Date(expiresAtMs).toISOString(),
              remainingUses: body.remainingUses,
              jwt,
            },
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      throw new Error(`unexpected fetch ${url}`);
    };

    try {
      const result = await activateEcdsaSession(
        {
          credentialStore: {} as any,
          touchIdPrompt: {
            getRpId: () => 'wallet.example.test',
          } as any,
          workerCtx: {
            requestWorkerOperation: async ({ kind, request }: any) => {
              if (
                kind === 'hssClient' &&
                request.type === WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap
              ) {
                return {
                  type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
                  payload: {
                    pendingStateBlob: {
                      kind: 'ecdsa_role_local_pending_state_blob_v1',
                      curve: 'secp256k1',
                      encoding: 'base64url',
                      producer: 'signer_core',
                      stateBlobB64u: base64UrlEncode(new Uint8Array(96).fill(6)),
                    },
                    clientBootstrap: {
                      contextBinding32B64u,
                      hssClientSharePublicKey33B64u: clientPublicKey33B64u,
                      clientShareRetryCounter: 0,
                      participantId: 1,
                    },
                    publicFacts: {
                      hssClientSharePublicKey33B64u: clientPublicKey33B64u,
                      clientVerifyingShareB64u,
                    },
                  },
                };
              }
              if (
                kind === 'hssClient' &&
                request.type === WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap
              ) {
                return {
                  type: WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
                  payload: {
                    stateBlob: {
                      kind: 'ecdsa_role_local_state_blob_v1',
                      curve: 'secp256k1',
                      encoding: 'base64url',
                      producer: 'signer_core',
                      stateBlobB64u: base64UrlEncode(new Uint8Array(128).fill(9)),
                    },
                    publicFacts: {
                      contextBinding32B64u,
                      hssClientSharePublicKey33B64u: clientPublicKey33B64u,
                      clientVerifyingShareB64u,
                      relayerPublicKey33B64u: serverPublicKey33B64u,
                      groupPublicKey33B64u,
                      ethereumAddress: ownerAddress,
                    },
                  },
                };
              }
              if (
                kind === 'hssClient' &&
                request.type === HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial
              ) {
                storedMaterials.push({
                  materialHandle: String(request.payload.materialHandle),
                  bindingDigest: String(request.payload.bindingDigest),
                });
                return {
                  type: HssClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess,
                  payload: {
                    materialHandle: request.payload.materialHandle,
                    bindingDigest: request.payload.bindingDigest,
                  },
                };
              }
              if (kind === 'ethSigner' && request.type === 'secp256k1PrivateKey32ToPublicKey33') {
                const publicKey33 = Uint8Array.from([2, ...Array.from({ length: 32 }, () => 9)]);
                return publicKey33.buffer;
              }
              if (kind === 'ethSigner' && request.type === 'signSecp256k1Recoverable') {
                return new Uint8Array(65).fill(11).buffer;
              }
              throw new Error(`unexpected worker request ${kind}:${String(request.type)}`);
            },
          },
          routerAbNormalSigning: {
            mode: 'enabled',
            signingWorkerId: 'signing-worker-local',
          },
          getOrCreateActiveThresholdEcdsaSessionId: () => 'ecdsa-session-1',
        },
        {
          kind: 'session_bootstrap',
          keyHandle: TEST_KEY_HANDLE,
          key: TEST_KEY_IDENTITY,
          lanePolicy: TEST_LANE_POLICY,
          relayerUrl: 'https://relay.example',
          authKind: 'passkey_prf_b64u',
          passkeyPrfFirstB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
          passkeyCredentialIdB64u: 'credential-id',
          walletSessionRouteAuth: {
            kind: 'app_session',
            jwt: jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' }),
          },
        },
      );

      expect(result.thresholdEcdsaKeyRef.backendBinding?.materialKind).toBe(
        'role_local_worker_handle',
      );
      if (result.thresholdEcdsaKeyRef.backendBinding?.materialKind !== 'role_local_worker_handle') {
        throw new Error('expected role-local worker handle');
      }
      expect(
        result.thresholdEcdsaKeyRef.backendBinding.roleLocalMaterialHandle.materialHandle,
      ).toContain('router-ab-ecdsa-role-local:ecdsa-session-1:');
      expect(storedMaterials).toEqual([
        {
          materialHandle:
            result.thresholdEcdsaKeyRef.backendBinding.roleLocalMaterialHandle.materialHandle,
          bindingDigest:
            result.thresholdEcdsaKeyRef.backendBinding.roleLocalMaterialHandle.bindingDigest,
        },
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

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
    const passkeyPrfFirst32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const passkeyPrfFirstB64u = base64UrlEncode(passkeyPrfFirst32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    const result = await bootstrapEcdsaSession({
      credentialStore: {} as any,
      touchIdPrompt: {
        getRpId: () => 'wallet.example.test',
      } as any,
      relayerUrl: 'https://relay.example',
      userId: 'alice.testnet',
      walletKeyId: TEST_KEY_IDENTITY.walletKeyId,
      chainTarget: TEST_CHAIN_TARGET,
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      sessionId: 'ecdsa-session-1',
      signingGrantId: 'wallet-session-1',
      bootstrapAuth: { kind: 'app_session', jwt: appSessionJwt },
      authKind: 'passkey_prf_b64u',
      passkeyPrfFirstB64u,
      passkeyCredentialIdB64u: 'credential-id',
      workerCtx: {
        requestWorkerOperation: async () => {
          throw new Error('raw exact-session bootstrap should fail before worker use');
        },
      },
    });

    if (result.ok) {
      throw new Error('expected exact-session bootstrap to reject incomplete identity');
    }
    expect(result.code).toBe('invalid_args');
    expect(result.message).toContain('shared key identity and lane policy');
  });

  test('authorization bootstrap does not spend managed registration grants on unlock warm-up', async () => {
    const requests: string[] = [];
    const bootstrapBodies: Array<Record<string, unknown>> = [];
    const originalFetch = globalThis.fetch;
    const passkeyPrfFirst32 = Uint8Array.from(Array.from({ length: 32 }, (_, index) => index + 1));
    const passkeyPrfFirstB64u = base64UrlEncode(passkeyPrfFirst32);
    const appSessionJwt = jwtWithPayload({ kind: 'app_session_v1', sub: 'alice.testnet' });

    globalThis.fetch = async (input, init) => {
      const url = String(input);
      requests.push(url);
      if (url.includes('/router-ab/ecdsa-hss/bootstrap')) {
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
        credentialStore: {} as any,
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
        authKind: 'passkey_prf_b64u',
        passkeyPrfFirstB64u,
        passkeyCredentialIdB64u: 'credential-id',
        workerCtx: {
          requestWorkerOperation: async ({ kind, request }: any) => {
            if (
              kind === 'hssClient' &&
              request.type === WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap
            ) {
              expect(request.payload).toMatchObject({
                kind: 'prepare_ecdsa_client_bootstrap_v1',
                algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
                secretSource: {
                  kind: 'webauthn_prf_first',
                  prfFirstB64u: passkeyPrfFirstB64u,
                  rpId: 'wallet.example.test',
                },
              });
              return {
                type: WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess,
                payload: {
                  pendingStateBlob: {
                    kind: 'ecdsa_role_local_pending_state_blob_v1',
                    curve: 'secp256k1',
                    encoding: 'base64url',
                    producer: 'signer_core',
                    stateBlobB64u: base64UrlEncode(new Uint8Array(96).fill(6)),
                  },
                  clientBootstrap: {
                    contextBinding32B64u: base64UrlEncode(new Uint8Array(32).fill(7)),
                    hssClientSharePublicKey33B64u: base64UrlEncode(
                      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
                    ),
                    clientShareRetryCounter: 0,
                    participantId: 1,
                  },
                  publicFacts: {
                    hssClientSharePublicKey33B64u: base64UrlEncode(
                      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
                    ),
                    clientVerifyingShareB64u: base64UrlEncode(
                      Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
                    ),
                  },
                },
              };
            }
            if (kind === 'ethSigner' && request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              const publicKey33 = Uint8Array.from([2, ...Array.from({ length: 32 }, () => 9)]);
              return publicKey33.buffer;
            }
            if (kind === 'ethSigner' && request.type === 'signSecp256k1Recoverable') {
              return new Uint8Array(65).fill(11).buffer;
            }
            throw new Error(`unexpected worker request ${kind}:${String(request.type)}`);
          },
        },
      });

      expect(requests.some((url) => url.includes('/v1/registration/bootstrap-grants'))).toBe(false);
      expect(bootstrapBodies).toHaveLength(1);
      expect(bootstrapBodies[0]?.clientRootProof).toMatchObject({
        version: 'ecdsa-hss:role-local:first-bootstrap-root-proof:v2',
      });
      expect(bootstrapBodies[0]?.passkeyBootstrapAuthorization).toBeUndefined();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
