import { expect, test } from '@playwright/test';
import {
  addWalletSigner,
  registerWallet,
} from '../../packages/sdk-web/src/SeamsWeb/operations/registration/registration';
import { createEvmSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/evm';
import { createNearSignerCapability } from '../../packages/sdk-web/src/SeamsWeb/publicApi/near';
import { IndexedDBManager } from '../../packages/sdk-web/src/core/indexedDB';
import { finalizeWalletRegistrationEcdsaSessions as finalizeWalletRegistrationEcdsaSessionsOperation } from '../../packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { UserVerificationPolicy } from '../../packages/sdk-web/src/core/types/authenticatorOptions';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearAllThresholdEcdsaSessionRecords,
  persistStoredThresholdEd25519SessionMaterialHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '../../packages/shared-ts/src/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { thresholdEcdsaChainTargetKey } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '../../packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap';

const RELAYER_URL = 'https://relay.example.test';
const WALLET_SUBJECT_ID = walletIdFromString('wallet-matrix.testnet');
const RP_ID = 'wallet.example.test';
const AUTHENTICATION_PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const REGISTRATION_PRF_FIRST_B64U = Buffer.alloc(32, 12).toString('base64url');
const CLIENT_PUBLIC_KEY_B64U =
  'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const MISMATCHED_CLIENT_PUBLIC_KEY_B64U =
  'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' as EcdsaHssClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U =
  'AwEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB' as EcdsaRelayerHssPublicKey33B64u;
const GROUP_PUBLIC_KEY_33_B64U = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC';
const CONTEXT_BINDING_32_B64U = 'DQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0';
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org_matrix',
  projectId: 'project_matrix',
  envId: 'dev',
  signingRootVersion: 'root_v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  signingWorkerId: 'signing-worker-test',
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

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtWithPayload(payload: Record<string, unknown>): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u(payload)}.sig`;
}

function ethereumAddress20B64u(address: string): string {
  return Buffer.from(address.replace(/^0x/i, ''), 'hex').toString('base64url');
}

function ecdsaWalletSessionJwtForBootstrap(bootstrap: Record<string, unknown>): string {
  const publicIdentity = bootstrap.publicIdentity as Record<string, unknown>;
  const sessionId = String(bootstrap.sessionId || '').trim();
  const signingGrantId = String(bootstrap.signingGrantId || '').trim();
  const walletId = String(bootstrap.walletId || '').trim();
  const rpId = String(bootstrap.rpId || '').trim();
  const ecdsaThresholdKeyId = String(bootstrap.ecdsaThresholdKeyId || '').trim();
  const signingRootId = String(bootstrap.signingRootId || '').trim();
  const signingRootVersion = String(bootstrap.signingRootVersion || '').trim();
  const keyHandle = String(bootstrap.keyHandle || '').trim();
  const relayerKeyId = String(bootstrap.relayerKeyId || '').trim();
  const expiresAtMs = Number(bootstrap.expiresAtMs);
  const participantIds = Array.isArray(bootstrap.participantIds) ? bootstrap.participantIds : [];
  return jwtWithPayload({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: walletId,
    walletId,
    thresholdSessionId: sessionId,
    signingGrantId,
    keyScope: 'evm-family',
    keyHandle,
    relayerKeyId,
    rpId,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: expiresAtMs,
    participantIds,
    routerAbEcdsaHssNormalSigning: {
      kind: 'router_ab_ecdsa_hss_normal_signing_v1',
      scope: {
        context: {
          wallet_id: walletId,
          rp_id: rpId,
          key_scope: 'evm-family',
          ecdsa_threshold_key_id: ecdsaThresholdKeyId,
          signing_root_id: signingRootId,
          signing_root_version: signingRootVersion,
          key_purpose: 'evm-signing',
          key_version: 'v1',
        },
        public_identity: {
          context_binding_b64u: String(bootstrap.contextBinding32B64u || '').trim(),
          client_public_key33_b64u: String(
            publicIdentity.hssClientSharePublicKey33B64u || '',
          ).trim(),
          server_public_key33_b64u: String(
            publicIdentity.relayerPublicKey33B64u || '',
          ).trim(),
          threshold_public_key33_b64u: String(
            publicIdentity.groupPublicKey33B64u || '',
          ).trim(),
          ethereum_address20_b64u: ethereumAddress20B64u(
            String(publicIdentity.ethereumAddress || bootstrap.ethereumAddress || ''),
          ),
          client_share_retry_counter: Number(bootstrap.clientShareRetryCounter),
          server_share_retry_counter: Number(bootstrap.relayerShareRetryCounter),
        },
        signing_worker: {
          server_id: 'signing-worker-test',
          key_epoch: 'worker-epoch-test',
          recipient_encryption_key:
            'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        },
        activation_epoch: sessionId,
      },
    },
  });
}

function ed25519WalletSessionJwt(args: {
  walletId: string;
  sessionId: string;
  signingGrantId: string;
  relayerKeyId: string;
  expiresAtMs: number;
  participantIds: readonly number[];
}): string {
  return jwtWithPayload({
    kind: ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
    sub: args.walletId,
    walletId: args.walletId,
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: args.relayerKeyId,
    rpId: RP_ID,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: args.expiresAtMs,
    participantIds: args.participantIds,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
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

function incrementCaptureCounter(captures: Record<string, unknown>, key: string): void {
  captures[key] = Number(captures[key] || 0) + 1;
}

function expectSingleRegistrationTouchIdPrompt(captures: Record<string, unknown>): void {
  expect(captures.registrationCredentialPrompts).toBe(1);
  expect(captures.authenticationCredentialPrompts || 0).toBe(0);
}

function expectRegistrationSuccess(result: { success: boolean; error?: unknown }): void {
  if (!result.success) {
    throw new Error(String(result.error || 'registration returned success:false'));
  }
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
  const thresholdEcdsaSessionStore = { recordsByLane: new Map() };
  const ecdsaRegistrationBootstrap = {
    preparePasskeyClientBootstrap: prepareWalletRegistrationEcdsaPreparedClientBootstrap,
    finalizeClientBootstrap: async () => ({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1' as const,
        curve: 'secp256k1' as const,
        encoding: 'base64url' as const,
        producer: 'signer_core' as const,
        stateBlobB64u: 'ready-state',
      },
      publicFacts: {
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
        hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
        clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereumAddress: '0x3333333333333333333333333333333333333333' as `0x${string}`,
      },
    }),
    storeClientSigningMaterial: async () => ({
      handle: {
        kind: 'role_local_worker_session' as const,
        materialHandle: 'registration-ecdsa-role-local-material',
        bindingDigest: 'registration-ecdsa-role-local-binding',
      },
    }),
  };
  const hydrateSigningSession = async (input: Record<string, unknown>) => {
    captures.hydratedSession = input;
    const transport = input.transport as Record<string, unknown> | undefined;
    if (transport?.curve !== 'ed25519') return;
    persistStoredThresholdEd25519SessionMaterialHandle({
      thresholdSessionId: String(input.sessionId || ''),
      ed25519WorkerMaterialHandle: 'registration-ed25519-worker-material',
      ed25519WorkerMaterialBindingDigest: 'registration-ed25519-worker-binding',
      clientVerifyingShareB64u: 'registration-ed25519-client-verifying-share',
    });
  };
  const finalizeWalletRegistrationEcdsaSessionsForTest = async (
    input: Record<string, unknown>,
  ) => {
    await finalizeWalletRegistrationEcdsaSessionsOperation(
      {
        registrationBootstrap: ecdsaRegistrationBootstrap,
        bootstrapStore: {
          upsertProfile: async () => undefined,
          activateAccountSigner: async (activationInput: any) => ({
            signer: activationInput.signer,
            signerSlot: 1,
          }),
        },
        sessionStore: thresholdEcdsaSessionStore,
        warmSessions: { hydrateSigningSession },
        signingSessionSeal: {},
      },
      input as any,
    );
    captures.persistedEcdsaSessions = input;
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
        routerAb: {
          normalSigning: { mode: 'enabled', signingWorkerId: 'signing-worker-test' },
        },
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
        ecdsaRegistrationBootstrap,
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
          finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
        },
        warmSessions: {
          hydrateSigningSession,
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
        incrementCaptureCounter(captures, 'registrationCredentialPrompts');
        captures.registrationCredentialArgs = args;
        return {
          credential: registrationCredentialWithPrf(),
        };
      },
      getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
        incrementCaptureCounter(captures, 'authenticationCredentialPrompts');
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
      finalizeWalletRegistrationEcdsaSessions: finalizeWalletRegistrationEcdsaSessionsForTest,
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
      hydrateSigningSession,
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
            signingGrantId: 'wallet-session-ecdsa',
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
          signingGrantId: 'wallet-session-ed25519',
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
    if (path === '/v2/router-ab/keyset') {
      return jsonResponse({
        keyset_version: 'router_ab_keyset_v2',
        signer_envelope_hpke: {
          current: {
            deriver_a: {
              role: 'signer_a',
              key_epoch: 'epoch-a',
              public_key: 'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            },
            deriver_b: {
              role: 'signer_b',
              key_epoch: 'epoch-b',
              public_key: 'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
            },
          },
        },
        signer_peer_verifying_keys: {
          deriver_a: {
            role: 'signer_a',
            verifying_key_hex: '1111111111111111111111111111111111111111111111111111111111111111',
          },
          deriver_b: {
            role: 'signer_b',
            verifying_key_hex: '2222222222222222222222222222222222222222222222222222222222222222',
          },
        },
        signing_worker_server_output_hpke: {
          key_epoch: 'epoch-signing-worker',
          public_key: 'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        },
      });
    }
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
      const selection = body.signerSelection;
      const walletId =
        selection?.mode === 'ed25519_only' || selection?.mode === 'ed25519_and_ecdsa'
          ? selection.ed25519.nearAccountId
          : WALLET_SUBJECT_ID;
      const intent = {
        version: 'registration_intent_v1' as const,
        walletId,
        rpId: RP_ID,
        authMethod: body.authMethod,
        signerSelection: selection,
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
    if (path === '/wallets/register/prepare') {
      captures.prepareBody = body;
      return jsonResponse({
        ok: true,
        state: 'prepared',
        registrationPreparationId: 'registration-preparation-id',
        expiresAtMs: Date.now() + 60_000,
        ed25519: {
          ceremonyHandle: 'registration-ed25519-handle',
          preparedSession: {
            contextBindingB64u: 'prepared-context-binding',
            evaluatorDriverStateB64u: 'evaluator-driver-state',
          },
          clientOtOfferMessageB64u: 'client-ot-offer',
        },
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
                  walletSessionUserId: String(body.intent.walletId),
                  walletId: String(body.intent.walletId),
                  rpId: RP_ID,
                  subjectId: String(body.intent.walletId),
                  ecdsaThresholdKeyId: 'ecdsa-threshold-key-id',
                  signingRootId: 'project_matrix:dev',
                  signingRootVersion: RUNTIME_POLICY_SCOPE.signingRootVersion,
                  keyScope: 'evm-family',
                  relayerKeyId: 'relayer-ecdsa',
                  registrationPreparationId: body.registrationPreparationId,
                  requestId: 'request-ecdsa',
                  sessionId: 'session-ecdsa',
                  signingGrantId: 'wallet-session-ecdsa',
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
      const registrationEcdsaExpiresAtMs = Date.now() + 60_000;
      let ecdsaBootstrap = body.ecdsa
        ? ({
            ...body.ecdsa.clientBootstrap,
            publicIdentity: {
              hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
              relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
              groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
              ethereumAddress: '0x3333333333333333333333333333333333333333',
            },
            publicTranscriptDigest32B64u: 'transcript-digest',
            keyHandle: 'ehss-registration-key',
            relayerShareRetryCounter: 1,
            thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x3333333333333333333333333333333333333333',
            relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
            expiresAtMs: registrationEcdsaExpiresAtMs,
            expiresAt: new Date(registrationEcdsaExpiresAtMs).toISOString(),
          } as Record<string, unknown>)
        : null;
      const patchRegistrationBootstrap = captures.patchRegistrationBootstrap as
        | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
        | undefined;
      if (ecdsaBootstrap && patchRegistrationBootstrap) {
        ecdsaBootstrap = patchRegistrationBootstrap(ecdsaBootstrap);
      }
      if (ecdsaBootstrap) {
        ecdsaBootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(ecdsaBootstrap);
      }
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
                bootstrap: ecdsaBootstrap,
              },
            }
          : {}),
      });
    }
    if (path === '/wallets/register/finalize') {
      captures.finalizeBody = body;
      const sessionPolicy = body.ed25519?.sessionPolicy;
      const responseWalletId = String((captures.intent as any)?.walletId || WALLET_SUBJECT_ID);
      const responseBody: Record<string, unknown> = {
        ok: true,
        walletId: responseWalletId,
        rpId: RP_ID,
      };
      if (body.ed25519) {
        const nearAccountId =
          (captures.intent as any)?.signerSelection?.ed25519?.nearAccountId || 'combined.testnet';
        const ed25519SessionExpiresAtMs = Date.now() + 60_000;
        responseBody.ed25519 = {
          nearAccountId,
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
            signingGrantId: sessionPolicy.signingGrantId,
            expiresAtMs: ed25519SessionExpiresAtMs,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
            jwt: ed25519WalletSessionJwt({
              walletId: nearAccountId,
              sessionId: sessionPolicy.sessionId,
              signingGrantId: sessionPolicy.signingGrantId,
              relayerKeyId: 'relayer-ed25519',
              expiresAtMs: ed25519SessionExpiresAtMs,
              participantIds: [1, 2],
            }),
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
              walletSessionUserId: responseWalletId,
              walletId: responseWalletId,
              rpId: RP_ID,
              subjectId: responseWalletId,
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
  clearAllStoredThresholdEd25519SessionRecords();
  clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
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
    clearAllStoredThresholdEd25519SessionRecords();
    clearAllThresholdEcdsaSessionRecords({ recordsByLane: new Map() });
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
    expectRegistrationSuccess(result);
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
    expectSingleRegistrationTouchIdPrompt(captures);
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

    expectRegistrationSuccess(result);
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
    expectSingleRegistrationTouchIdPrompt(captures);
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

    expectRegistrationSuccess(result);
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
    expectSingleRegistrationTouchIdPrompt(captures);
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

    expectRegistrationSuccess(result);
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
    expectSingleRegistrationTouchIdPrompt(captures);
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
  const originalConsoleInfo = console.info;
  const consoleInfoCalls: unknown[][] = [];
  (globalThis as any).window = { isSecureContext: true };
  console.info = (...args: unknown[]) => {
    consoleInfoCalls.push(args);
  };
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

    expectRegistrationSuccess(result);
    expect(result).toMatchObject({
      success: true,
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      thresholdEcdsaEthereumAddress: '0x3333333333333333333333333333333333333333',
    });
    expect(fetchMock.paths).toEqual([
      '/v2/router-ab/keyset',
      '/v1/registration/bootstrap-grants',
      '/wallets/register/intent',
      '/wallets/register/prepare',
      '/wallets/register/start',
      '/wallets/register/hss/respond',
      '/wallets/register/finalize',
    ]);
    expect(captures.registrationCredentialArgs).toMatchObject({
      nearAccountId: 'combined.testnet',
      challengeB64u: captures.digest,
    });
    expectSingleRegistrationTouchIdPrompt(captures);
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
      walletId: 'combined.testnet',
      nearAccountId: 'combined.testnet',
      operationalPublicKey: 'ed25519:public-key',
      signerSlot: 1,
      relayerKeyId: 'relayer-ed25519',
    });
    expect(captures.storedEcdsa).toMatchObject({
      walletId: 'combined.testnet',
      walletKeys: [
        {
          keyHandle: 'ehss-registration-key',
          thresholdOwnerAddress: '0x3333333333333333333333333333333333333333',
        },
      ],
    });
    const timingSummaries = consoleInfoCalls
      .filter((call) => call[0] === '[Registration] wallet timing summary')
      .map((call) => call[1]);
    expect(timingSummaries).toHaveLength(1);
    expect(timingSummaries[0]).toMatchObject({
      kind: 'registration_timing_summary_v1',
      status: 'succeeded',
      authMethod: 'passkey',
      signerMode: 'ed25519_and_ecdsa',
      timings: {
        inputValidationMs: expect.any(Number),
        registrationWarmupMs: expect.any(Number),
        registrationWarmupWaitMs: expect.any(Number),
        registrationWarmupAuthenticatedWalletStateMs: expect.any(Number),
        registrationWarmupNoncePrefetchMs: expect.any(Number),
        registrationWarmupKeyMaterialReadMs: expect.any(Number),
        registrationWarmupUiConfirmPrewarmMs: expect.any(Number),
        registrationWarmupSignerWorkerPrewarmMs: expect.any(Number),
        managedRegistrationGrantMs: expect.any(Number),
        registrationIntentMs: expect.any(Number),
        registrationIntentDigestMs: expect.any(Number),
        authProofMs: expect.any(Number),
        passkeyAuthConfirmationMs: expect.any(Number),
        passkeyAuthPrfExtractionMs: expect.any(Number),
        passkeyAuthCredentialRedactionMs: expect.any(Number),
        passkeyAuthWorkerReadyMs: expect.any(Number),
        passkeyAuthWorkerRequestRoundTripMs: expect.any(Number),
        passkeyAuthWorkerResponseValidationMs: expect.any(Number),
        passkeyAuthRequestSetupMs: expect.any(Number),
        passkeyAuthPromptUserMs: expect.any(Number),
        passkeyAuthPromptElementDefineMs: expect.any(Number),
        passkeyAuthPromptMountMs: expect.any(Number),
        passkeyAuthPromptHostFirstUpdateMs: expect.any(Number),
        passkeyAuthPromptHostInteractiveMs: expect.any(Number),
        passkeyAuthPromptConfirmEventMs: expect.any(Number),
        passkeyAuthPromptDecisionWaitMs: expect.any(Number),
        passkeyAuthCredentialCreateStartMs: expect.any(Number),
        passkeyAuthCredentialCreateMs: expect.any(Number),
        passkeyAuthCredentialSerializeMs: expect.any(Number),
        passkeyAuthDuplicateRetryCount: expect.any(Number),
        passkeyAuthMainThreadTotalMs: expect.any(Number),
        ed25519ClientMaterialMs: expect.any(Number),
        walletRegisterPrepareMs: expect.any(Number),
        walletRegisterPrepareWaitMs: expect.any(Number),
        walletRegisterStartMs: expect.any(Number),
        ed25519ClientRequestMs: expect.any(Number),
        ecdsaClientBootstrapMs: expect.any(Number),
        walletRegisterHssRespondMs: expect.any(Number),
        ed25519EvaluationArtifactMs: expect.any(Number),
        walletRegisterFinalizeMs: expect.any(Number),
        ed25519CompletionParseMs: expect.any(Number),
        localWalletRegistrationPersistenceMs: expect.any(Number),
        thresholdEd25519SessionPersistenceMs: expect.any(Number),
        ecdsaRegistrationPersistenceMs: expect.any(Number),
        walletStateActivationMs: expect.any(Number),
        immediateSigningLaneAssertionMs: expect.any(Number),
        auth: {
          kind: 'passkey',
          passkeyAuthConfirmationMs: expect.any(Number),
          passkeyAuthPrfExtractionMs: expect.any(Number),
          passkeyAuthCredentialRedactionMs: expect.any(Number),
          passkeyAuthWorkerReadyMs: expect.any(Number),
          passkeyAuthWorkerRequestRoundTripMs: expect.any(Number),
          passkeyAuthWorkerResponseValidationMs: expect.any(Number),
          passkeyAuthRequestSetupMs: expect.any(Number),
          passkeyAuthPromptUserMs: expect.any(Number),
          passkeyAuthPromptElementDefineMs: expect.any(Number),
          passkeyAuthPromptMountMs: expect.any(Number),
          passkeyAuthPromptHostFirstUpdateMs: expect.any(Number),
          passkeyAuthPromptHostInteractiveMs: expect.any(Number),
          passkeyAuthPromptConfirmEventMs: expect.any(Number),
          passkeyAuthPromptDecisionWaitMs: expect.any(Number),
          passkeyAuthCredentialCreateStartMs: expect.any(Number),
          passkeyAuthCredentialCreateMs: expect.any(Number),
          passkeyAuthCredentialSerializeMs: expect.any(Number),
          passkeyAuthDuplicateRetryCount: expect.any(Number),
          passkeyAuthMainThreadTotalMs: expect.any(Number),
          emailOtpEnrollmentMaterialMs: 0,
          emailOtpRecoveryCodeBackupMs: 0,
        },
        ed25519: {
          kind: 'ed25519_enabled',
        },
        ecdsa: {
          kind: 'ecdsa_enabled',
        },
      },
    });
  } finally {
    console.info = originalConsoleInfo;
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
              signingGrantId: 'wallet-session-ecdsa',
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
        const addSignerEcdsaExpiresAtMs = Date.now() + 60_000;
        let ecdsaBootstrap = {
          ...body.ecdsa.clientBootstrap,
          publicIdentity: {
            hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_B64U,
            relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
            groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
            ethereumAddress: '0x1111111111111111111111111111111111111111',
          },
          publicTranscriptDigest32B64u: 'transcript-digest',
          keyHandle: 'ehss-key-matrix',
          relayerShareRetryCounter: 1,
          thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
          ethereumAddress: '0x1111111111111111111111111111111111111111',
          relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
          expiresAtMs: addSignerEcdsaExpiresAtMs,
          expiresAt: new Date(addSignerEcdsaExpiresAtMs).toISOString(),
        } as Record<string, unknown>;
        const patchAddSignerBootstrap = captures.patchAddSignerBootstrap as
          | ((bootstrap: Record<string, unknown>) => Record<string, unknown>)
          | undefined;
        if (patchAddSignerBootstrap) {
          ecdsaBootstrap = patchAddSignerBootstrap(ecdsaBootstrap);
        }
        ecdsaBootstrap.jwt = ecdsaWalletSessionJwtForBootstrap(ecdsaBootstrap);
        return jsonResponse({
          ok: true,
          addSignerCeremonyId: body.addSignerCeremonyId,
          ecdsa: {
            bootstrap: ecdsaBootstrap,
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
      const ed25519SessionExpiresAtMs = Date.now() + 60_000;
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
            signingGrantId: sessionPolicy.signingGrantId,
            expiresAtMs: ed25519SessionExpiresAtMs,
            participantIds: [1, 2],
            remainingUses: 1,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
            jwt: ed25519WalletSessionJwt({
              walletId: 'later.testnet',
              sessionId: sessionPolicy.sessionId,
              signingGrantId: sessionPolicy.signingGrantId,
              relayerKeyId: 'relayer-ed25519',
              expiresAtMs: ed25519SessionExpiresAtMs,
              participantIds: [1, 2],
            }),
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

    expectRegistrationSuccess(result);
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

    expectRegistrationSuccess(result);
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
        walletSessionJwt: expect.any(String),
      },
    });
  } finally {
    fetchMock.restore();
  }
});
