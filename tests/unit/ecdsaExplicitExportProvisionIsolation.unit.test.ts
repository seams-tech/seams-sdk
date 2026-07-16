import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1,
  ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
  routerAbEcdsaDerivationContextBindingB64uV1,
  routerAbEcdsaDerivationStableKeyContextFromSdkFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { ROUTER_AB_PUBLIC_KEYSET_VERSION_V2 } from '@shared/utils/routerAbPublicKeyset';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyEcdsaSessionLanePolicy,
  buildEvmFamilyEcdsaWalletKey,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaExportActivation,
  provisionPasskeyEcdsaExplicitExportSession,
  type ProvisionThresholdEcdsaSessionDeps,
} from '@/core/signingEngine/session/passkey/ecdsaSessionProvision';
import { buildEcdsaSessionIdentity } from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
} from '@/core/signingEngine/workerManager/workerTypes';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

const CHAIN_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'sepolia',
});
const WALLET_ID = 'ephemeral-export-provision.testnet';
const KEY_HANDLE = 'ederivation-key-export-provision';
const ECDSA_THRESHOLD_KEY_ID = 'ecdsa-export-provision-key';
const SIGNING_ROOT_ID = 'project:dev';
const SIGNING_ROOT_VERSION = 'default';
const SESSION_ID = 'ecdsa-export-session';
const SIGNING_GRANT_ID = 'ecdsa-export-grant';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const CLIENT_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...Array.from({ length: 32 }, () => 8)]),
);
const SERVER_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...Array.from({ length: 32 }, () => 10)]),
);
const GROUP_PUBLIC_KEY_B64U = base64UrlEncode(
  Uint8Array.from([2, ...Array.from({ length: 32 }, () => 12)]),
);
const WALLET_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
});

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

function address20B64u(address: string): string {
  return Buffer.from(address.slice(2), 'hex').toString('base64url');
}

function parseJsonRecord(value: string): Record<string, unknown> {
  const parsed: unknown = JSON.parse(value);
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('mock Router A/B request body must be an object');
  }
  return Object.fromEntries(Object.entries(parsed));
}

function webauthnAuthentication(): WebAuthnAuthenticationCredential {
  return {
    id: 'credential-id-b64u',
    rawId: 'credential-id-b64u',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data-json-b64u',
      authenticatorData: 'authenticator-data-b64u',
      signature: 'signature-b64u',
      userHandle: undefined,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: undefined,
          second: undefined,
        },
      },
    },
  };
}

function unexpectedDependencyUse(name: string): never {
  throw new Error(`dedicated export provision unexpectedly used ${name}`);
}

test('dedicated ECDSA export provision returns ephemeral material without persistence', async () => {
  const stableKeyContext = await routerAbEcdsaDerivationStableKeyContextFromSdkFactsV1({
    walletId: WALLET_ID,
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  });
  const applicationBindingDigestB64u = stableKeyContext.application_binding_digest_b64u;
  const contextBinding32B64u = await routerAbEcdsaDerivationContextBindingB64uV1(stableKeyContext);
  const originalFetch = globalThis.fetch;
  let transactionPersistenceCalls = 0;

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
              verifying_key_hex: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            },
            deriver_b: {
              role: 'signer_b',
              verifying_key_hex: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
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
    if (url.endsWith('/router-ab/ecdsa-derivation/bootstrap')) {
      const body = parseJsonRecord(String(init?.body || '{}'));
      const participantIds = [1, 2];
      const expiresAtMs = Date.now() + 300_000;
      const normalSigning = {
        kind: ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_STATE_KIND_V1,
        scope: {
          wallet_key_id: body.evmFamilySigningKeySlotId,
          wallet_id: body.walletId,
          ecdsa_threshold_key_id: body.ecdsaThresholdKeyId,
          signing_root_id: body.signingRootId,
          signing_root_version: body.signingRootVersion,
          context: { application_binding_digest_b64u: applicationBindingDigestB64u },
          public_identity: {
            context_binding_b64u: contextBinding32B64u,
            derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_B64U,
            server_public_key33_b64u: SERVER_PUBLIC_KEY_B64U,
            threshold_public_key33_b64u: GROUP_PUBLIC_KEY_B64U,
            ethereum_address20_b64u: address20B64u(OWNER_ADDRESS),
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
        kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
        sub: body.walletId,
        walletId: body.walletId,
        evmFamilySigningKeySlotId: body.evmFamilySigningKeySlotId,
        rpId: body.rpId,
        keyScope: ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1,
        keyHandle: KEY_HANDLE,
        relayerKeyId: body.relayerKeyId,
        thresholdSessionId: body.sessionId,
        signingGrantId: body.signingGrantId,
        thresholdExpiresAtMs: expiresAtMs,
        participantIds,
        routerAbEcdsaDerivationNormalSigning: normalSigning,
      });
      return new Response(
        JSON.stringify({
          ok: true,
          value: {
            formatVersion: 'ecdsa-derivation-role-local',
            walletId: body.walletId,
            evmFamilySigningKeySlotId: body.evmFamilySigningKeySlotId,
            rpId: body.rpId,
            ecdsaThresholdKeyId: body.ecdsaThresholdKeyId,
            relayerKeyId: body.relayerKeyId,
            applicationBindingDigestB64u,
            contextBinding32B64u,
            publicIdentity: {
              derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
              relayerPublicKey33B64u: SERVER_PUBLIC_KEY_B64U,
              groupPublicKey33B64u: GROUP_PUBLIC_KEY_B64U,
              ethereumAddress: OWNER_ADDRESS,
            },
            clientShareRetryCounter: 0,
            relayerShareRetryCounter: 0,
            publicTranscriptDigest32B64u: base64UrlEncode(new Uint8Array(32).fill(13)),
            keyHandle: KEY_HANDLE,
            signingRootId: body.signingRootId,
            signingRootVersion: body.signingRootVersion,
            thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
            ethereumAddress: OWNER_ADDRESS,
            relayerVerifyingShareB64u: SERVER_PUBLIC_KEY_B64U,
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

  const deps: ProvisionThresholdEcdsaSessionDeps = {
    queueByWallet: new Map(),
    activationDeps: {
      credentialStore: {
        resolveProfileAccountContext: async () => unexpectedDependencyUse('credential lookup'),
        listProfileAuthenticators: async () => unexpectedDependencyUse('authenticator lookup'),
        listAccountSigners: async () => unexpectedDependencyUse('account signer lookup'),
        selectProfileAuthenticatorsForPrompt: async () =>
          unexpectedDependencyUse('authenticator selection'),
      },
      touchIdPrompt: {
        getRpId: () => 'wallet.example.test',
        getAuthenticationCredentialsSerializedForChallengeB64u: async () =>
          unexpectedDependencyUse('passkey prompt'),
      },
      touchConfirm: {
        putWarmSessionMaterial: async () => unexpectedDependencyUse('warm material'),
      },
      getSignerWorkerContext: () => ({
        requestWorkerOperation: async ({ kind, request }) => {
          if (
            kind === 'ecdsaDerivationClient' &&
            request.type ===
              EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap
          ) {
            return {
              type: EcdsaDerivationClientCustomResponseType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
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
                  derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
                  clientShareRetryCounter: 0,
                  participantId: 1,
                },
                publicFacts: {
                  derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
                  clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
                },
              },
            };
          }
          if (
            kind === 'ecdsaDerivationClient' &&
            request.type ===
              EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap
          ) {
            return {
              type: EcdsaDerivationClientCustomResponseType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess,
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
                  applicationBindingDigestB64u,
                  derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
                  clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
                  relayerPublicKey33B64u: SERVER_PUBLIC_KEY_B64U,
                  groupPublicKey33B64u: GROUP_PUBLIC_KEY_B64U,
                  ethereumAddress: OWNER_ADDRESS,
                },
              },
            };
          }
          if (
            kind === 'ecdsaDerivationClient' &&
            request.type ===
              EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial
          ) {
            return {
              type: EcdsaDerivationClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess,
              payload: {
                materialHandle: request.payload.materialHandle,
                bindingDigest: request.payload.bindingDigest,
              },
            };
          }
          if (kind === 'evmCrypto' && request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            return Uint8Array.from([2, ...Array.from({ length: 32 }, () => 9)]).buffer;
          }
          if (kind === 'evmCrypto' && request.type === 'signSecp256k1Recoverable') {
            return new Uint8Array(65).fill(11).buffer;
          }
          throw new Error(`unexpected worker request ${kind}:${String(request.type)}`);
        },
      }),
      routerAbNormalSigning: {
        mode: 'enabled',
        signingWorkerId: 'signing-worker-local',
      },
      getOrCreateActiveThresholdEcdsaSessionId: () =>
        unexpectedDependencyUse('transaction session allocation'),
      defaultRelayerUrl: 'https://relay.example',
      persistThresholdEcdsaBootstrapForWalletTarget: async () => {
        transactionPersistenceCalls += 1;
        unexpectedDependencyUse('bootstrap publication');
      },
      upsertThresholdEcdsaSessionFromBootstrap: () => {
        transactionPersistenceCalls += 1;
        unexpectedDependencyUse('runtime lane upsert');
      },
    },
    touchConfirm: {
      putWarmSessionMaterial: async () => unexpectedDependencyUse('seal material publication'),
    },
    persistEcdsaRoleLocalReadyRecord: async () =>
      unexpectedDependencyUse('role-local durable publication'),
    resolveSealTransport: () => unexpectedDependencyUse('seal transport resolution'),
  };

  try {
    const walletKey = buildEvmFamilyEcdsaWalletKey({
      walletId: WALLET_ID,
      evmFamilySigningKeySlotId: WALLET_KEY_SLOT_ID,
      keyHandle: KEY_HANDLE,
      chainTarget: CHAIN_TARGET,
      keyScope: 'evm-family',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      participantIds: [1, 2],
      thresholdOwnerAddress: OWNER_ADDRESS,
      thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_B64U,
    });
    const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
      chainTarget: CHAIN_TARGET,
      thresholdSessionId: SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
      thresholdSessionKind: 'jwt',
      ttlMs: 300_000,
      remainingUses: 1,
    });
    const result = await provisionPasskeyEcdsaExplicitExportSession(
      deps,
      buildEcdsaExportActivation({
        walletKey,
        lanePolicy,
        source: 'login',
        relayerUrl: 'https://relay.example',
        sessionIdentity: buildEcdsaSessionIdentity({
          thresholdSessionId: SESSION_ID,
          signingGrantId: SIGNING_GRANT_ID,
        }),
        sessionKind: 'jwt',
        sessionBudgetUses: 1,
        requestId: 'ecdsa-export-provision-request',
        runtimePolicy: { kind: 'default_policy' },
        passkeyPrfFirstB64u: base64UrlEncode(new Uint8Array(32).fill(1)),
        webauthnAuthentication: webauthnAuthentication(),
      }),
    );

    expect(result).toMatchObject({
      kind: 'explicit_key_export_ecdsa_activation_result',
      purpose: 'explicit_key_export',
      material: {
        walletId: WALLET_ID,
        thresholdSessionId: SESSION_ID,
        signingGrantId: SIGNING_GRANT_ID,
      },
    });
    expect(transactionPersistenceCalls).toBe(0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
