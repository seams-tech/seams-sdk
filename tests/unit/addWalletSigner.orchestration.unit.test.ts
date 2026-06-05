import { expect, test } from '@playwright/test';
import { addWalletSigner, registerWallet } from '../../client/src/web/SeamsWeb/operations/registration/registration';
import { createEvmSignerCapability } from '../../client/src/web/SeamsWeb/publicApi/evm';
import { createNearSignerCapability } from '../../client/src/web/SeamsWeb/publicApi/near';
import { IndexedDBManager } from '../../client/src/core/indexedDB';
import { UserVerificationPolicy } from '../../client/src/core/types/authenticatorOptions';
import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  walletIdFromString,
} from '../../shared/src/utils/registrationIntent';
import { thresholdEcdsaChainTargetKey } from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaHssClientSharePublicKey33B64u } from '../../shared/src/threshold/ecdsaHssRoleLocalBootstrap';

const RELAYER_URL = 'https://relay.example.test';
const WALLET_SUBJECT_ID = walletIdFromString('wallet_matrix');
const RP_ID = 'wallet.example.test';
const AUTHENTICATION_PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const REGISTRATION_PRF_FIRST_B64U = Buffer.alloc(32, 12).toString('base64url');
const CLIENT_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const MISMATCHED_CLIENT_PUBLIC_KEY_B64U =
  'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U = 'AwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB';
const GROUP_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const CONTEXT_BINDING_32_B64U = 'DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org_matrix',
  projectId: 'project_matrix',
  envId: 'dev',
  signingRootVersion: 'root_v1',
} as const;

function createLocalEvmCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createEvmSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: () =>
      ({
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('local EVM capability test should not require wallet iframe router');
        },
      }) as any,
  } as any);
}

function createLocalNearCapability(deps: { getContext: () => any }) {
  const context = deps.getContext();
  return createNearSignerCapability({
    signingEngine: context.signingEngine,
    nearClient: context.nearClient ?? {},
    configs: context.configs,
    getTheme: () => context.theme ?? 'light',
    getWalletIframe: () =>
      ({
        shouldUseWalletIframe: () => false,
        requireRouter: async () => {
          throw new Error('local NEAR capability test should not require wallet iframe router');
        },
      }) as any,
  } as any);
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function credentialWithPrf() {
  return {
    id: 'credential-id',
    rawId: 'credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: AUTHENTICATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function registrationCredentialWithPrf() {
  return {
    id: 'registration-credential-id',
    rawId: 'registration-credential-id',
    type: 'public-key',
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      attestationObject: 'attestation-object',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: REGISTRATION_PRF_FIRST_B64U,
        },
      },
    },
  };
}

function createContext(captures: Record<string, unknown>): any {
  const prepareWalletRegistrationEcdsaPreparedClientBootstrap = async (
    args: Record<string, unknown>,
  ) => {
    captures.ecdsaClientBootstrapArgs = args;
    const clientBootstrap = {
      ...(args.prepare as Record<string, unknown>),
      hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
      clientShareRetryCounter: 0,
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    };
    return {
      materialSource: 'passkey_prf_first',
      clientBootstrap,
      pendingStateBlob: {
        kind: 'ecdsa_role_local_pending_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'pending-state',
      },
      preparePublicFacts: {
        hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
      },
      passkeyPrfFirstB64u: String(args.passkeyPrfFirstB64u || ''),
      credentialIdB64u: String(args.credentialIdB64u || ''),
    };
  };
  return {
    configs: {
      network: {
        chains: [
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://tempo.example.test',
            explorerUrl: 'https://tempo.explorer.test',
            chainId: 42431,
          },
          {
            network: 'arc-testnet',
            rpcUrl: 'https://arc.example.test',
            explorerUrl: 'https://arc.explorer.test',
            chainId: 5042002,
          },
        ],
        relayer: {
          url: RELAYER_URL,
        },
      },
      registration: {
        mode: 'managed',
        environmentId: 'env_matrix',
        publishableKey: 'pk_matrix',
      },
      signing: {
        sessionDefaults: {
          ttlMs: 600_000,
          remainingUses: 1,
        },
        thresholdEcdsa: {
          provisioningDefaults: {
            tempo: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
            evm: {
              enabled: true,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
          },
        },
      },
      webauthn: {
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      },
    },
    signingRuntime: {
      services: {
        ecdsaRegistrationBootstrap: {
          preparePasskeyClientBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
          finalizeClientBootstrap: async () => ({
            stateBlob: {
              kind: 'ecdsa_role_local_state_blob_v1',
              curve: 'secp256k1',
              encoding: 'base64url',
              producer: 'signer_core',
              stateBlobB64u: 'ready-state',
            },
            publicFacts: {
              hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
              clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
              relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
              groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
            },
          }),
        },
        ecdsaWalletRecords: {
          storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
            captures.storedEcdsa = input;
            return { storedSigners: [] };
          },
          finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
          storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEcdsaRegistration = input;
            return { storedSigners: [] };
          },
        },
        ecdsaRegistrationSessions: {
          finalizeWalletRegistrationEcdsaSessions: async (input: Record<string, unknown>) => {
            const bootstrap = input.bootstrap as { keyHandle?: unknown };
            const walletKeys = input.walletKeys as Array<{ keyHandle?: unknown }>;
            for (const walletKey of walletKeys) {
              if (String(walletKey.keyHandle || '') !== String(bootstrap.keyHandle || '')) {
                throw new Error('ECDSA registration bootstrap keyHandle mismatch');
              }
            }
            captures.persistedEcdsaSessions = input;
          },
        },
        warmSessions: {
          hydrateSigningSession: async (input: Record<string, unknown>) => {
            captures.hydratedSession = input;
          },
        },
        registrationAccounts: {
          storeWalletEd25519RegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEd25519Registration = input;
            return { signerSlot: input.signerSlot };
          },
          storeWalletEmailOtpEd25519RegistrationData: async (input: Record<string, unknown>) => {
            captures.storedEd25519Registration = input;
            return { signerSlot: input.signerSlot };
          },
          finalizeWalletEd25519SignerRegistration: async (input: Record<string, unknown>) => {
            captures.storedEd25519 = input;
            return { signerSlot: input.signerSlot };
          },
          getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
            nearAccountId,
            signerSlot,
          }),
          activateAuthenticatedWalletState: async () => undefined,
          rollbackUserRegistration: async () => undefined,
        },
      },
    },
    signingEngine: {
      getRpId: () => RP_ID,
      requestRegistrationCredentialConfirmation: async (args: Record<string, unknown>) => {
        captures.registrationCredentialArgs = args;
        return {
          credential: registrationCredentialWithPrf(),
        };
      },
      getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
        captures.authenticationArgs = args;
        return credentialWithPrf();
      },
      storeWalletEd25519RegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEd25519Registration = input;
        return { signerSlot: input.signerSlot };
      },
      storeWalletEmailOtpEd25519RegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEd25519Registration = input;
        return { signerSlot: input.signerSlot };
      },
      preparePasskeyEcdsaBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
      prepareEmailOtpEcdsaBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
      finalizeWalletRegistrationEcdsaSessions: async (input: Record<string, unknown>) => {
        const bootstrap = input.bootstrap as { keyHandle?: unknown };
        const walletKeys = input.walletKeys as Array<{ keyHandle?: unknown }>;
        for (const walletKey of walletKeys) {
          if (String(walletKey.keyHandle || '') !== String(bootstrap.keyHandle || '')) {
            throw new Error('ECDSA registration bootstrap keyHandle mismatch');
          }
        }
        captures.persistedEcdsaSessions = input;
      },
      finalizeWalletEcdsaRegistration: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaRegistrationData: async (input: Record<string, unknown>) => {
        captures.storedEcdsaRegistration = input;
        return { storedSigners: [] };
      },
      storeWalletEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },
      storeWalletEmailOtpEcdsaSignerRecords: async (input: Record<string, unknown>) => {
        captures.storedEcdsa = input;
        return { storedSigners: [] };
      },
      prepareThresholdEd25519HssClientCeremonyFromCredential: async (
        input: Record<string, unknown>,
      ) => {
        captures.ed25519MaterialArgs = input;
        return {
          ok: true,
          signingRootId: 'root',
          nearAccountId: 'alice.testnet',
          keyPurpose: 'near-ed25519-signing',
          keyVersion: 'v1',
          participantIds: [1, 2],
          derivationVersion: 1,
          contextBindingB64u: 'client-context-binding',
          yClientB64u: 'y-client',
          tauClientB64u: 'tau-client',
        };
      },
      deriveThresholdEd25519HssClientOutputMask: async (input: Record<string, unknown>) => {
        captures.ed25519MaskArgs = input;
        return { clientOutputMaskB64u: 'client-output-mask' };
      },
      prepareThresholdEd25519HssClientRequest: async (input: Record<string, unknown>) => {
        captures.ed25519RequestArgs = input;
        return { clientRequestMessageB64u: 'client-request' };
      },
      buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact: async (
        input: Record<string, unknown>,
      ) => {
        captures.ed25519ArtifactArgs = input;
        return { stagedEvaluatorArtifactB64u: 'staged-artifact' };
      },
      finalizeWalletEd25519SignerRegistration: async (input: Record<string, unknown>) => {
        captures.storedEd25519 = input;
        return { signerSlot: input.signerSlot };
      },
      hydrateSigningSession: async (input: Record<string, unknown>) => {
        captures.hydratedSession = input;
      },
      readPersistedAvailableSigningLanes: async (input: Record<string, unknown>) => {
        const authMethod = input.authMethod === 'email_otp' ? 'email_otp' : 'passkey';
        const walletId = String(input.walletId || WALLET_SUBJECT_ID);
        const chainTargets =
          (captures.intent as any)?.signerSelection?.ecdsa?.chainTargets ||
          (captures.finalizeBody as any)?.ecdsa?.walletKeys?.map(
            (walletKey: { chainTarget: unknown }) => walletKey.chainTarget,
          ) ||
          [];
        const lanesByTarget: Record<string, unknown> = {};
        const candidatesByTarget: Record<string, unknown[]> = {};
        for (const chainTarget of chainTargets) {
          const targetKey = thresholdEcdsaChainTargetKey(chainTarget as any);
          const lane = {
            curve: 'ecdsa',
            chainTarget,
            source: 'runtime_session_record',
            state: 'ready',
            authMethod,
            thresholdSessionId: 'session-ecdsa',
            walletSigningSessionId: 'wallet-session-ecdsa',
            remainingUses: 1,
            expiresAtMs: Date.now() + 60_000,
            key: {
              walletId,
              chainTarget,
              keyHandle: 'ehss-registration-key',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
            },
            publicFacts: {
              keyHandle: 'ehss-registration-key',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
              participantIds: [1, 2],
            },
          };
          lanesByTarget[targetKey] = lane;
          candidatesByTarget[targetKey] = [lane];
        }
        const ed25519Lane = {
          curve: 'ed25519',
          chain: 'near',
          source: 'runtime_session_record',
          state: 'ready',
          authMethod,
          thresholdSessionId: 'threshold-session-id',
          walletSigningSessionId: 'wallet-session-ed25519',
          remainingUses: 1,
          expiresAtMs: Date.now() + 60_000,
        };
        return {
          walletId,
          generation: Date.now(),
          ecdsa: {
            targets: chainTargets,
            lanesByTarget,
            candidatesByTarget,
          },
          lanes: { ed25519: { near: ed25519Lane } },
          candidates: { ed25519: { near: [ed25519Lane] } },
        };
      },
      getUserBySignerSlot: async (nearAccountId: unknown, signerSlot: unknown) => ({
        nearAccountId,
        signerSlot,
      }),
      activateAuthenticatedWalletState: async () => undefined,
    },
    nearClient: {
      viewAccount: async () => {
        throw new Error('does not exist');
      },
    },
  };
}

function installRegisterWalletFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/v1/registration/bootstrap-grants') {
      captures.bootstrapGrantBody = body;
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === '/wallets/register/intent') {
      const intent = {
        version: 'registration_intent_v1' as const,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        authMethod: body.authMethod,
        signerSelection: body.signerSelection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'registration-nonce',
      };
      const digest = await computeRegistrationIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        registrationIntentDigestB64u: digest,
        registrationIntentGrant: 'registration-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === '/wallets/register/start') {
      captures.startBody = body;
      const mode = body.intent.signerSelection.mode;
      return jsonResponse({
        ok: true,
        registrationCeremonyId: 'registration-ceremony',
        intent: body.intent,
        ...(mode === 'ed25519_only' || mode === 'ed25519_and_ecdsa'
          ? {
              ed25519: {
                ceremonyHandle: 'registration-ed25519-handle',
                preparedSession: {
                  contextBindingB64u: 'prepared-context-binding',
                  evaluatorDriverStateB64u: 'evaluator-driver-state',
                },
                clientOtOfferMessageB64u: 'client-ot-offer',
              },
            }
          : {}),
        ...(mode === 'ecdsa_only' || mode === 'ed25519_and_ecdsa'
          ? {
              ecdsa: {
                kind: 'evm_family_ecdsa_keygen',
                chainTargets: body.intent.signerSelection.ecdsa.chainTargets,
                prepare: {
                  formatVersion: 'ecdsa-hss-role-local',
                  walletSessionUserId: String(WALLET_SUBJECT_ID),
                  walletId: String(WALLET_SUBJECT_ID),
                  rpId: RP_ID,
                  subjectId: String(WALLET_SUBJECT_ID),
                  ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                  signingRootId: 'project_matrix:dev',
                  signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                  keyScope: 'evm-family',
                  relayerKeyId: 'relayer-ecdsa',
                  requestId: 'request-ecdsa',
                  sessionId: 'session-ecdsa',
                  walletSigningSessionId: 'wallet-session-ecdsa',
                  ttlMs: 600_000,
                  remainingUses: 1,
                  participantIds: [1, 2],
                  runtimePolicyScope: RUNTIME_POLICY_SCOPE,
                },
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/hss/respond') {
      captures.respondBody = body;
      const ecdsaBootstrap = body.ecdsa
        ? {
            ...body.ecdsa.clientBootstrap,
            publicIdentity: {
              hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
              relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
              groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
            },
            publicTranscriptDigest32B64u: 'transcript-digest',
            keyHandle: 'ehss-registration-key',
            thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x3333333333333333333333333333333333333333',
            relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
            expiresAtMs: Date.now() + 60_000,
            expiresAt: new Date(Date.now() + 60_000).toISOString(),
            jwt: 'threshold-ecdsa-session-jwt',
          }
        : null;
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      return jsonResponse({
        ok: true,
        registrationCeremonyId: body.registrationCeremonyId,
        ...(body.ed25519
          ? {
              ed25519: {
                contextBindingB64u: 'server-context-binding',
                serverInputDeliveryB64u: 'server-input-delivery',
              },
            }
          : {}),
        ...(body.ecdsa
          ? {
              ecdsa: {
                bootstrap: patchRegistrationBootstrap
                  ? patchRegistrationBootstrap(ecdsaBootstrap!)
                  : ecdsaBootstrap,
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/finalize') {
      captures.finalizeBody = body;
      const sessionPolicy = body.ed25519?.sessionPolicy;
      const responseBody: Record<string, unknown> = {
        ok: true,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
      };
      if (body.ed25519) {
        responseBody.ed25519 = {
          nearAccountId:
            (captures.intent as any)?.signerSelection?.ed25519?.nearAccountId || 'combined.testnet',
          publicKey: 'ed25519:public-key',
          relayerKeyId: 'relayer-ed25519',
          keyVersion: 'threshold-ed25519-hss-v1',
          recoveryExportCapable: true,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
          session: {
            sessionKind: 'jwt',
            sessionId: sessionPolicy.sessionId,
            walletSigningSessionId: sessionPolicy.walletSigningSessionId,
            expiresAtMs: Date.now() + 60_000,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            jwt: 'threshold-session-jwt',
          },
        };
      }
      if (body.ecdsa) {
        const chainTargets = (captures.intent as any)?.signerSelection?.ecdsa?.chainTargets || [
          { kind: 'evm', namespace: 'eip155', chainId: 1 },
        ];
        const patchRegistrationWalletKey = captures.patchRegistrationWalletKey as
          | ((walletKey: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        responseBody.ecdsa = {
          walletKeys: chainTargets.map((chainTarget: unknown) => {
            const walletKey = {
              keyScope: 'evm-family',
              chainTarget,
              walletSessionUserId: String(WALLET_SUBJECT_ID),
              walletId: String(WALLET_SUBJECT_ID),
              rpId: RP_ID,
              subjectId: String(WALLET_SUBJECT_ID),
              keyHandle: 'ehss-registration-key',
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
              thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
              relayerKeyId: 'relayer-ecdsa',
              relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
              participantIds: [1, 2],
            };
            return patchRegistrationWalletKey ? patchRegistrationWalletKey(walletKey) : walletKey;
          }),
        };
      }
      return jsonResponse(responseBody);
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

async function withMockedIndexedDb<T>(run: () => Promise<T>): Promise<T> {
  const indexedDB = IndexedDBManager as unknown as Record<string, unknown>;
  const originalListProfileAuthenticators = indexedDB.listProfileAuthenticators;
  const originalResolveProfileAccountContext = indexedDB.resolveProfileAccountContext;
  const originalGetKeyMaterial = IndexedDBManager.getKeyMaterial;
  const originalStoreKeyMaterial = IndexedDBManager.storeKeyMaterial;
  const keyMaterialWrites: unknown[] = [];
  indexedDB.listProfileAuthenticators = async () => [
    {
      credentialId: 'credential-id',
      transports: ['internal'],
    },
  ];
  indexedDB.resolveProfileAccountContext = async (accountRef: unknown) => ({
    profileId: 'near-profile:later.testnet',
    accountRef,
  });
  (IndexedDBManager as any).getKeyMaterial = async () => null;
  (IndexedDBManager as any).storeKeyMaterial = async (record: unknown) => {
    keyMaterialWrites.push(record);
  };
  try {
    return await run();
  } finally {
    indexedDB.listProfileAuthenticators = originalListProfileAuthenticators;
    indexedDB.resolveProfileAccountContext = originalResolveProfileAccountContext;
    (IndexedDBManager as any).getKeyMaterial = originalGetKeyMaterial;
    (IndexedDBManager as any).storeKeyMaterial = originalStoreKeyMaterial;
  }
}

test('near.registerNearWallet wraps combined registration for configured ECDSA targets', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const signer = createLocalNearCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerNearWallet({
        nearAccountId: 'wrapper.testnet',
        options: {},
      }),
    );
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'wrapper.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect((captures.intent as any)?.signerSelection).toMatchObject({
      mode: 'ed25519_and_ecdsa',
      ed25519: {
        nearAccountId: 'wrapper.testnet',
        signerSlot: 1,
        createNearAccount: true,
      },
      ecdsa: {
        participantIds: [1, 2],
        chainTargets: [
          { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
          { kind: 'evm', namespace: 'eip155', chainId: 5042002, networkSlug: 'arc-testnet' },
        ],
      },
    });
    expect(captures.bootstrapGrantBody).toMatchObject({
      newAccountId: 'wrapper.testnet',
      rpId: RP_ID,
    });
    expect((captures.storedEcdsa as any)?.walletKeys).toMatchObject([
      {
        chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
        thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
      },
      {
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 5042002,
          networkSlug: 'arc-testnet',
        },
        thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
      },
    ]);
  } finally {
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

test('near.registerNearWallet respects per-call disabled ECDSA provisioning', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const signer = createLocalNearCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerNearWallet({
        nearAccountId: 'ed-only-wrapper.testnet',
        options: {
          signerOptions: {
            tempo: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
            evm: {
              enabled: false,
              signingSession: { kind: 'jwt', ttlMs: 600_000, remainingUses: 1 },
            },
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'ed-only-wrapper.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect((captures.intent as any)?.signerSelection).toMatchObject({
      mode: 'ed25519_only',
      ed25519: {
        nearAccountId: 'ed-only-wrapper.testnet',
        signerSlot: 1,
        createNearAccount: true,
      },
    });
  } finally {
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

test('evm.registerEvmWallet wraps ECDSA-only wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const signer = createLocalEvmCapability({
      getContext: () => createContext(captures),
    });
    const result = await withMockedIndexedDb(() =>
      signer.registerEvmWallet({
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
        participantIds: [1, 2],
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect((captures.intent as any)?.signerSelection).toMatchObject({
      mode: 'ecdsa_only',
      ecdsa: {
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1, networkSlug: 'ethereum' }],
        participantIds: [1, 2],
      },
    });
    expect(captures.bootstrapGrantBody).toMatchObject({
      rpId: RP_ID,
    });
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet orchestrates ECDSA-only wallet registration without NEAR profile work', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey' },
        wallet: { kind: 'server_generated' },
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa_only',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/start',
      '/wallets/register/hss/respond',
      '/wallets/register/finalize',
    ]);
    expect(captures.bootstrapGrantBody).not.toHaveProperty('newAccountId');
    expect(captures.registrationCredentialArgs).toMatchObject({
      nearAccountId: WALLET_SUBJECT_ID,
      challengeB64u: captures.digest,
    });
    expect(captures.ecdsaClientBootstrapArgs).toMatchObject({
      passkeyPrfFirstB64u: REGISTRATION_PRF_FIRST_B64U,
      credentialIdB64u: 'registration-credential-id',
    });
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        expectedKeyHandles: ['ehss-registration-key'],
      },
    });
    expect(captures.storedEcdsaRegistration).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      walletKeys: [
        {
          keyHandle: 'ehss-registration-key',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'registration-credential-id' },
    });
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      publicIdentity: {
        ...(bootstrap.publicIdentity as Record<string, unknown>),
        hssClientSharePublicKey33B64u: MISMATCHED_CLIENT_PUBLIC_KEY_B64U,
      },
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey' },
        wallet: { kind: 'server_generated' },
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa_only',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/hssClientSharePublicKey33B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet rejects mismatched ECDSA wallet key before registration persistence', async () => {
  const captures: Record<string, unknown> = {
    patchRegistrationWalletKey: (walletKey: Record<string, unknown>) => ({
      ...walletKey,
      keyHandle: 'mismatched-key-handle',
    }),
  };
  const fetchMock = installRegisterWalletFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey' },
        wallet: { kind: 'server_generated' },
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa_only',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/keyHandle mismatch/),
    });
    expect(captures.finalizeBody).toBeDefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsaRegistration).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('registerWallet orchestrates combined Ed25519 and ECDSA wallet registration', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installRegisterWalletFetch(captures);
  const originalWindow = (globalThis as any).window;
  (globalThis as any).window = { isSecureContext: true };
  try {
    const result = await withMockedIndexedDb(() =>
      registerWallet({
        context: createContext(captures),
        authMethod: { kind: 'passkey' },
        wallet: { kind: 'server_generated' },
        rpId: RP_ID,
        signerSelection: {
          mode: 'ed25519_and_ecdsa',
          ed25519: {
            nearAccountId: 'combined.testnet',
            signerSlot: 1,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
            derivationVersion: 1,
            createNearAccount: true,
          },
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
        authenticatorOptions: {
          userVerification: UserVerificationPolicy.Preferred,
          originPolicy: {
            single: true,
            all_subdomains: false,
            multiple: [],
          },
        },
      }),
    );

    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/start',
      '/wallets/register/hss/respond',
      '/wallets/register/finalize',
    ]);
    expect(captures.registrationCredentialArgs).toMatchObject({
      nearAccountId: WALLET_SUBJECT_ID,
      challengeB64u: captures.digest,
    });
    expect(captures.respondBody).toMatchObject({
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
        },
      },
      ecdsa: {
        clientBootstrap: {
          hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        },
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      ed25519: {
        evaluationResult: {
          stagedEvaluatorArtifactB64u: 'staged-artifact',
        },
        sessionKind: 'jwt',
      },
      ecdsa: {
        expectedKeyHandles: ['ehss-registration-key'],
      },
    });
    expect(captures.storedEd25519Registration).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      signerSlot: 1,
      relayerKeyId: 'relayer-ed25519',
    });
    expect(captures.storedEcdsa).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      walletKeys: [
        {
          keyHandle: 'ehss-registration-key',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
  } finally {
    (globalThis as any).window = originalWindow;
    fetchMock.restore();
  }
});

function installAddSignerFetch(captures: Record<string, unknown>) {
  const originalFetch = globalThis.fetch;
  const paths: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input));
    const path = url.pathname;
    paths.push(path);
    const body = init?.body ? JSON.parse(String(init.body)) : {};
    if (path === '/v1/registration/bootstrap-grants') {
      return jsonResponse({
        ok: true,
        grant: {
          token: 'bootstrap-grant',
          orgId: RUNTIME_POLICY_SCOPE.orgId,
          projectId: RUNTIME_POLICY_SCOPE.projectId,
          envId: RUNTIME_POLICY_SCOPE.envId,
          signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/intent`) {
      const intent = {
        version: 'add_signer_intent_v1' as const,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: body.signerSelection,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        nonceB64u: 'add-signer-nonce',
      };
      const digest = await computeAddSignerIntentDigestB64u(intent);
      captures.intent = intent;
      captures.digest = digest;
      return jsonResponse({
        ok: true,
        intent,
        addSignerIntentDigestB64u: digest,
        addSignerIntentGrant: 'add-signer-grant',
        expiresAtMs: Date.now() + 60_000,
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/start`) {
      captures.startBody = body;
      if (body.intent?.signerSelection?.mode === 'ecdsa') {
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: 'add-signer-ceremony',
          intent: body.intent,
          ecdsa: {
            kind: 'evm_family_ecdsa_keygen',
            chainTargets: body.intent.signerSelection.ecdsa.chainTargets,
            prepare: {
              formatVersion: 'ecdsa-hss-role-local',
              walletSessionUserId: String(WALLET_SUBJECT_ID),
              walletId: String(WALLET_SUBJECT_ID),
              rpId: RP_ID,
              subjectId: String(WALLET_SUBJECT_ID),
              ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
              signingRootId: 'project_matrix:dev',
              signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
              keyScope: 'evm-family',
              relayerKeyId: 'relayer-ecdsa',
              requestId: 'request-ecdsa',
              sessionId: 'session-ecdsa',
              walletSigningSessionId: 'wallet-session-ecdsa',
              ttlMs: 600_000,
              remainingUses: 1,
              participantIds: [1, 2],
              runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            },
          },
        });
      }
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: 'add-signer-ceremony',
        intent: body.intent,
        ed25519: {
          ceremonyHandle: 'ed25519-ceremony',
          preparedSession: {
            contextBindingB64u: 'server-context-binding',
            evaluatorDriverStateB64u: 'evaluator-driver-state',
          },
          clientOtOfferMessageB64u: 'client-ot-offer',
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`) {
      captures.respondBody = body;
      if (body.ecdsa) {
        const ecdsaBootstrap = {
          ...body.ecdsa.clientBootstrap,
          publicIdentity: {
            hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
            groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          },
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'ehss-key-matrix',
          thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
          expiresAtMs: Date.now() + 60_000,
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
          jwt: 'threshold-ecdsa-session-jwt',
        };
        const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
          | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: body.addSignerCeremonyId,
          ecdsa: {
            bootstrap: patchAddSignerBootstrap
              ? patchAddSignerBootstrap(ecdsaBootstrap)
              : ecdsaBootstrap,
          },
        });
      }
      return jsonResponse({
        ok: true,
        addSignerCeremonyId: body.addSignerCeremonyId,
        ed25519: {
          contextBindingB64u: 'server-context-binding',
          serverInputDeliveryB64u: 'server-input-delivery',
        },
      });
    }
    if (path === `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`) {
      captures.finalizeBody = body;
      if (body.ecdsa) {
        return jsonResponse({
          ok: true,
          walletId: WALLET_SUBJECT_ID,
          rpId: RP_ID,
          ecdsa: {
            walletKeys: [
              {
                keyScope: 'evm-family',
                chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 1 },
                walletSessionUserId: String(WALLET_SUBJECT_ID),
                walletId: String(WALLET_SUBJECT_ID),
                rpId: RP_ID,
                subjectId: String(WALLET_SUBJECT_ID),
                keyHandle: 'ehss-key-matrix',
                ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                signingRootId: 'project_matrix:dev',
                signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
                thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
                relayerKeyId: 'relayer-ecdsa',
                relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
                participantIds: [1, 2],
              },
            ],
          },
        });
      }
      const sessionPolicy = body.ed25519.sessionPolicy;
      return jsonResponse({
        ok: true,
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        ed25519: {
          nearAccountId: 'later.testnet',
          publicKey: 'ed25519:public-key',
          relayerKeyId: 'relayer-ed25519',
          keyVersion: 'threshold-ed25519-hss-v1',
          recoveryExportCapable: true,
          clientParticipantId: 1,
          relayerParticipantId: 2,
          participantIds: [1, 2],
          session: {
            sessionKind: 'jwt',
            sessionId: sessionPolicy.sessionId,
            walletSigningSessionId: sessionPolicy.walletSigningSessionId,
            expiresAtMs: Date.now() + 60_000,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            jwt: 'threshold-session-jwt',
          },
        },
      });
    }
    return jsonResponse({ ok: false, message: `unexpected path ${path}` }, 404);
  }) as typeof fetch;
  return {
    paths,
    restore: () => {
      globalThis.fetch = originalFetch;
    },
  };
}

test('addWalletSigner orchestrates later ECDSA from an Ed25519 wallet', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: true,
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    expect(captures.authenticationArgs).toMatchObject({
      challengeB64u: captures.digest,
      includeSecondPrfOutput: false,
    });
    expect(captures.startBody).toMatchObject({
      auth: {
        kind: 'webauthn_assertion',
        credential: {
          clientExtensionResults: null,
        },
      },
    });
    expect(captures.ecdsaClientBootstrapArgs).toMatchObject({
      passkeyPrfFirstB64u: AUTHENTICATION_PRF_FIRST_B64U,
      credentialIdB64u: 'credential-id',
    });
    expect(captures.finalizeBody).toMatchObject({
      ecdsa: {
        expectedKeyHandles: ['ehss-key-matrix'],
      },
    });
    expect(captures.storedEcdsa).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      walletKeys: [
        {
          keyHandle: 'ehss-key-matrix',
          thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
        },
      ],
    });
    expect(captures.persistedEcdsaSessions).toMatchObject({
      auth: { kind: 'passkey', credentialIdB64u: 'credential-id' },
    });
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner rejects invalid ECDSA respond bootstrap before finalize', async () => {
  const captures: Record<string, unknown> = {
    patchAddSignerBootstrap: (bootstrap: Record<string, unknown>) => ({
      ...bootstrap,
      contextBinding32B64u: 'mismatched-context-binding',
    }),
  };
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 1 }],
            participantIds: [1, 2],
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: false,
      error: expect.stringMatching(/contextBinding32B64u mismatch/),
    });
    expect(captures.finalizeBody).toBeUndefined();
    expect(captures.persistedEcdsaSessions).toBeUndefined();
    expect(captures.storedEcdsa).toBeUndefined();
  } finally {
    fetchMock.restore();
  }
});

test('addWalletSigner orchestrates later Ed25519 from an ECDSA wallet', async () => {
  const captures: Record<string, unknown> = {};
  const fetchMock = installAddSignerFetch(captures);
  try {
    const result = await withMockedIndexedDb(() =>
      addWalletSigner({
        context: createContext(captures),
        walletId: WALLET_SUBJECT_ID,
        rpId: RP_ID,
        signerSelection: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_near_account',
            nearAccountId: 'later.testnet',
            signerSlot: 2,
            participantIds: [1, 2],
            keyPurpose: 'near_tx',
            keyVersion: 'threshold-ed25519-hss-v1',
            derivationVersion: 1,
          },
        },
        options: {},
      }),
    );

    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'later.testnet',
      operationalPublicKey: 'ed25519:public-key',
    });
    expect(fetchMock.paths).toEqual([
      '/v1/registration/bootstrap-grants',
      `/wallets/${WALLET_SUBJECT_ID}/signers/intent`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/start`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/hss/respond`,
      `/wallets/${WALLET_SUBJECT_ID}/signers/finalize`,
    ]);
    expect(captures.ed25519MaterialArgs).toMatchObject({
      signingRootId: 'project_matrix:dev',
      nearAccountId: 'later.testnet',
      keyPurpose: 'near_tx',
      keyVersion: 'threshold-ed25519-hss-v1',
      participantIds: [1, 2],
      derivationVersion: 1,
    });
    expect(captures.respondBody).toMatchObject({
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'client-request',
        },
      },
    });
    expect(captures.finalizeBody).toMatchObject({
      ed25519: {
        evaluationResult: {
          stagedEvaluatorArtifactB64u: 'staged-artifact',
        },
        sessionKind: 'jwt',
      },
    });
    expect(captures.storedEd25519).toMatchObject({
      walletId: WALLET_SUBJECT_ID,
      nearAccountId: 'later.testnet',
      operationalPublicKey: 'ed25519:public-key',
      signerSlot: 2,
      relayerKeyId: 'relayer-ed25519',
    });
    expect(captures.hydratedSession).toMatchObject({
      sessionId: (captures.finalizeBody as any).ed25519.sessionPolicy.sessionId,
      prfFirstB64u: AUTHENTICATION_PRF_FIRST_B64U,
      transport: {
        curve: 'ed25519',
        walletId: 'later.testnet',
        thresholdSessionAuthToken: 'threshold-session-jwt',
      },
    });
  } finally {
    fetchMock.restore();
  }
});
