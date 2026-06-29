import { expect, test } from '@playwright/test';
import { requireWalletKeyId } from '@shared/signing-lanes';
import { getWalletSession, unlock } from '@/SeamsWeb/operations/auth/login';
import { IndexedDBManager } from '@/core/indexedDB';
import { toAccountId } from '@/core/types/accountIds';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  clearStoredThresholdEd25519SessionRecordForLaneKey,
  getStoredThresholdEd25519SessionRecordForAccount,
  thresholdEd25519SessionRecordKeyFromRecord,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  walletIdFromWalletProfile,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildRouterAbEd25519WorkerMaterialBinding } from '@/core/signingEngine/threshold/ed25519/workerMaterialBinding';
import {
  parseEd25519ClientVerifyingShareB64u,
  parseEd25519HssKeyVersion,
  parseEd25519RelayerKeyId,
} from '@/core/signingEngine/session/keyMaterialBrands';

const ACCOUNT_ID = toAccountId('alice.testnet');
const IMPLICIT_WALLET_ID = 'frost-vermillion-k7p9m2';
const IMPLICIT_NEAR_ACCOUNT_ID = toAccountId('a'.repeat(64));
const IMPLICIT_ED25519_KEY_SCOPE_ID = IMPLICIT_WALLET_ID;
const TEMPO_ECDSA_THRESHOLD_KEY_ID = 'ehss-login-tempo';
const EVM_ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_THRESHOLD_KEY_ID = TEMPO_ECDSA_THRESHOLD_KEY_ID;
const ECDSA_KEY_HANDLE = 'ehss-key-login-tempo';
const ECDSA_PRF_FIRST_B64U = Buffer.alloc(32, 7).toString('base64url');
const ECDSA_CLIENT_ROOT_SHARE32_B64U = 'oSWxVelT4exizVyl5Q9RgldZH2hte7-Kf3h2qkA4mlY';
const ECDSA_PUBLIC_KEY33_B64U = Buffer.alloc(33, 9).toString('base64url');
const WALLET_SIGNING_SESSION_ID = 'wsess-login-1';
const SUBJECT_ID = walletIdFromWalletProfile({ walletId: ACCOUNT_ID });
const LOGIN_RUNTIME_POLICY_SCOPE = {
  orgId: 'org_local',
  projectId: 'proj_local',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;
const TEMPO_CHAIN_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const EVM_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
} as const satisfies ThresholdEcdsaChainTarget;
const SEPOLIA_CHAIN_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'ethereum-sepolia',
} as const satisfies ThresholdEcdsaChainTarget;
const THRESHOLD_OWNER_ADDRESS = `0x${'aa'.repeat(20)}`;
const ED25519_CLIENT_VERIFYING_SHARE_B64U = 'ed25519-client-verifying-share';
const ED25519_KEY_VERSION = 'threshold-ed25519-hss-v1';

function canonicalEcdsaRecord(overrides?: Record<string, unknown>): Record<string, unknown> {
  const chainTarget = (overrides?.chainTarget as Record<string, unknown> | undefined) || {
    kind: 'tempo',
    chainId: 42431,
    networkSlug: 'tempo-testnet',
  };
  const targetKeyId =
    chainTarget.kind === 'evm' ? EVM_ECDSA_THRESHOLD_KEY_ID : TEMPO_ECDSA_THRESHOLD_KEY_ID;
  return {
    source: 'login',
    nearAccountId: ACCOUNT_ID,
    walletId: ACCOUNT_ID,
    subjectId: SUBJECT_ID,
    keyHandle: ECDSA_KEY_HANDLE,
    ecdsaThresholdKeyId: targetKeyId,
    thresholdSessionId: 'canonical-ecdsa-session-1',
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    chainTarget,
    relayerUrl: 'https://relay.example',
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    relayerKeyId: parseEd25519RelayerKeyId('rk-1'),
    clientVerifyingShareB64u: 'AQ',
    participantIds: [1, 2],
    ethereumAddress: `0x${'aa'.repeat(20)}`,
    walletKeyId: requireWalletKeyId('wallet-key-login-threshold-warm'),
    rpId: 'example.localhost',
    thresholdSessionKind: 'jwt',
    walletSessionJwt: 'jwt-ecdsa',
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    updatedAtMs: Date.now(),
    ...(overrides || {}),
  };
}

function ecdsaKeyIdForChainTarget(chainTarget: Record<string, unknown>): string {
  return chainTarget.kind === 'evm' ? EVM_ECDSA_THRESHOLD_KEY_ID : TEMPO_ECDSA_THRESHOLD_KEY_ID;
}

function bootstrapKey(args: Record<string, unknown>): Record<string, unknown> {
  const key = args.key as Record<string, unknown> | undefined;
  if (!key) throw new Error('test bootstrap requires ECDSA key identity');
  return key;
}

function bootstrapLanePolicy(args: Record<string, unknown>): Record<string, unknown> {
  const lanePolicy = args.lanePolicy as Record<string, unknown> | undefined;
  if (!lanePolicy) throw new Error('test bootstrap requires ECDSA lane policy');
  return lanePolicy;
}

function bootstrapChainTarget(args: Record<string, unknown>): ThresholdEcdsaChainTarget {
  const chainTarget = bootstrapLanePolicy(args).chainTarget as
    | ThresholdEcdsaChainTarget
    | undefined;
  if (!chainTarget) throw new Error('test bootstrap requires lane policy chain target');
  return chainTarget;
}

function bootstrapEcdsaThresholdKeyId(args: Record<string, unknown>): string {
  return String(bootstrapKey(args).ecdsaThresholdKeyId || '');
}

function bootstrapKeyHandle(args: Record<string, unknown>): string {
  return String(args.keyHandle || ECDSA_KEY_HANDLE);
}

function partialEcdsaProfileSigners(): Array<Record<string, unknown>> {
  return [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
    status: 'active',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    metadata: {
      keyHandle: ECDSA_KEY_HANDLE,
      ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(chainTarget),
      chainTarget,
    },
  }));
}

function completeEcdsaProfileSigners(): Array<Record<string, unknown>> {
  return [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
    status: 'active',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    metadata: {
      keyHandle: ECDSA_KEY_HANDLE,
      chainTarget,
      thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
      sharedEvmFamilyKey: {
        walletId: String(ACCOUNT_ID),
        subjectId: String(SUBJECT_ID),
        rpId: 'example.localhost',
        keyScope: 'evm-family',
        keyHandle: ECDSA_KEY_HANDLE,
        ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(chainTarget),
        signingRootId: 'proj_local:dev',
        signingRootVersion: 'default',
        participantIds: [1, 2],
        thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
        thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
      },
    },
  }));
}

function ecdsaKeyIdentityTargetRecord(
  chainTarget: ThresholdEcdsaChainTarget,
): Record<string, unknown> {
  const ecdsaThresholdKeyId = ecdsaKeyIdForChainTarget(chainTarget);
  return {
    keyHandle: ECDSA_KEY_HANDLE,
    ecdsaThresholdKeyId,
    chainTarget,
    targetKey: thresholdEcdsaChainTargetKey(chainTarget),
    accountAddress: THRESHOLD_OWNER_ADDRESS,
    ownerAddress: THRESHOLD_OWNER_ADDRESS,
    relayerKeyId: parseEd25519RelayerKeyId('rk-1'),
    thresholdEcdsaPublicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
    key: {
      walletId: String(ACCOUNT_ID),
      subjectId: String(SUBJECT_ID),
      rpId: 'example.localhost',
      keyScope: 'evm-family',
      ecdsaThresholdKeyId,
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
    },
  };
}

function loginReadySigningLanes(args: {
  walletId: unknown;
  authMethod: 'email_otp' | 'passkey';
}): Record<string, unknown> {
  const expiresAtMs = Date.now() + 60_000;
  const walletId = toWalletId(String(args.walletId || ACCOUNT_ID));
  const auth =
    args.authMethod === 'passkey'
      ? {
          kind: 'passkey',
          rpId: 'example.localhost',
          credentialIdB64u: 'cred-1',
        }
      : {
          kind: 'email_otp',
          providerSubjectId: String(walletId),
        };
  const ed25519Lane = {
    auth,
    curve: 'ed25519',
    chain: 'near',
    walletId,
    nearAccountId: ACCOUNT_ID,
    nearEd25519SigningKeyId: String(ACCOUNT_ID),
    state: 'ready',
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    thresholdSessionId: 'tsess-login-ed25519',
    remainingUses: 3,
    expiresAtMs,
    updatedAtMs: Date.now(),
    source: 'runtime_session_record',
  };
  const ecdsaLanesByTarget = Object.fromEntries(
    [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => {
      const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
      const lane = {
        auth,
        curve: 'ecdsa',
        chainTarget,
        state: 'ready',
        signingGrantId: WALLET_SIGNING_SESSION_ID,
        thresholdSessionId: `tehss-login-${targetKey}`,
        remainingUses: 3,
        expiresAtMs,
        updatedAtMs: Date.now(),
        source: 'runtime_session_record',
        key: ecdsaKeyIdentityTargetRecord(chainTarget).key,
        publicFacts: {
          keyHandle: ECDSA_KEY_HANDLE,
          publicKeyB64u: ECDSA_PUBLIC_KEY33_B64U,
          participantIds: [1, 2],
          thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
        },
      };
      return [targetKey, lane];
    }),
  );
  return {
    walletId,
    generation: Date.now(),
    ecdsa: {
      targets: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET],
      lanesByTarget: ecdsaLanesByTarget,
      candidatesByTarget: Object.fromEntries(
        Object.entries(ecdsaLanesByTarget).map(([targetKey, lane]) => [targetKey, [lane]]),
      ),
    },
    lanes: {
      ed25519: {
        near: ed25519Lane,
      },
    },
    candidates: {
      ed25519: {
        near: [ed25519Lane],
      },
    },
  };
}

async function persistReadyEd25519WarmRecord(args: {
  sessionId: string;
  walletId?: string;
  nearAccountId?: ReturnType<typeof toAccountId>;
  nearEd25519SigningKeyId?: string;
  signingGrantId?: string;
  walletSessionJwt?: string;
  expiresAtMs?: number;
  remainingUses?: number;
}): Promise<void> {
  const nearAccountId = args.nearAccountId || ACCOUNT_ID;
  const walletId = args.walletId || String(nearAccountId);
  const nearEd25519SigningKeyId = args.nearEd25519SigningKeyId || String(nearAccountId);
  const materialCreatedAtMs = Date.now();
  const material = await buildRouterAbEd25519WorkerMaterialBinding({
    nearAccountId,
    signerSlot: 1,
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    relayerKeyId: parseEd25519RelayerKeyId('rk-1'),
    participantIds: [1, 2],
    clientVerifyingShareB64u: parseEd25519ClientVerifyingShareB64u(
      ED25519_CLIENT_VERIFYING_SHARE_B64U,
    ),
    createdAtMs: materialCreatedAtMs,
  });
  upsertStoredThresholdEd25519SessionRecord({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    rpId: 'example.localhost',
    relayerUrl: 'https://relay.example',
    relayerKeyId: 'rk-1',
    participantIds: [1, 2],
    signerSlot: 1,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId || WALLET_SIGNING_SESSION_ID,
    walletSessionJwt: args.walletSessionJwt || 'jwt-ed25519',
    expiresAtMs: args.expiresAtMs || Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 3,
    runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: {
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-local',
    },
    signingRootId: 'proj_local:dev',
    signingRootVersion: 'default',
    clientVerifyingShareB64u: ED25519_CLIENT_VERIFYING_SHARE_B64U,
    ed25519WorkerMaterialHandle: `ed25519-worker-material:${args.sessionId}:${material.materialBindingDigest}`,
    ed25519WorkerMaterialBindingDigest: material.materialBindingDigest,
    sealedWorkerMaterialRef: `ed25519-worker-material-v1:${material.materialBindingDigest}`,
    sealedWorkerMaterialB64u: 'sealed-worker-material',
    materialFormatVersion: 'ed25519_worker_material_v1',
    materialKeyId: material.materialBinding.materialKeyId,
    materialCreatedAtMs,
    keyVersion: ED25519_KEY_VERSION,
    source: 'login',
  });
}

function createBaseContext(args?: {
  signingEngine?: Record<string, unknown>;
  configs?: Record<string, unknown>;
}): any {
  const now = Date.now();
  const signingEngine = {
      assertSealedRefreshStartupParity: async () => undefined,
      getRpId: () => 'example.localhost',
      getUserBySignerSlot: async () => ({
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        operationalPublicKey: 'ed25519:alice',
      }),
      getLastUser: async () => ({
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        operationalPublicKey: 'ed25519:alice',
      }),
      nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
      getAuthenticatorsByUser: async () => [{ credentialId: 'cred-1', signerSlot: 1 }],
      getAuthenticationCredentialsSerialized: async () => ({
        id: 'cred-1',
        rawId: 'cred-1',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: {},
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: ECDSA_PRF_FIRST_B64U,
            },
          },
        },
      }),
      readPersistedAvailableSigningLanes: async (input: Record<string, unknown>) =>
        loginReadySigningLanes({
          walletId: input.walletId,
          authMethod: input.authMethod === 'email_otp' ? 'email_otp' : 'passkey',
        }),
      connectEd25519Session: async () => {
        await persistReadyEd25519WarmRecord({
          sessionId: 'session-1',
          signingGrantId: WALLET_SIGNING_SESSION_ID,
          walletSessionJwt: 'jwt-ed25519',
          expiresAtMs: now + 60_000,
          remainingUses: 3,
        });
        return {
          ok: true,
          sessionId: 'session-1',
          signingGrantId: WALLET_SIGNING_SESSION_ID,
          jwt: 'jwt-ed25519',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
        };
      },
      listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
        canonicalEcdsaRecord({
          chainTarget: args.chainTarget,
          ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
            args.chainTarget as Record<string, unknown>,
          ),
        }),
      ],
      bootstrapEcdsaSession: async (args: Record<string, unknown>) => ({
        thresholdEcdsaKeyRef: {
          type: 'threshold-ecdsa-secp256k1',
          userId: 'alice.testnet',
          relayerUrl: 'https://relay.example',
          keyHandle: bootstrapKeyHandle(args),
          ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
          signingRootId: 'proj_local:dev',
          signingRootVersion: 'default',
          backendBinding: {
            relayerKeyId: 'rk-1',
            clientVerifyingShareB64u: 'AQ',
          },
          participantIds: [1, 2],
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'session-1',
          signingGrantId: WALLET_SIGNING_SESSION_ID,
          walletSessionJwt: 'jwt-ecdsa',
        },
        keygen: {
          ok: true,
          ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
          relayerKeyId: 'rk-1',
          clientVerifyingShareB64u: 'AQ',
          participantIds: [1, 2],
        },
        session: {
          ok: true,
          sessionId: 'session-1',
          signingGrantId: WALLET_SIGNING_SESSION_ID,
          jwt: 'jwt-ecdsa',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          clientVerifyingShareB64u: 'AQ',
        },
      }),
      clearVolatileWarmSigningMaterial: async () => undefined,
      getWarmThresholdEd25519SessionStatus: async (nearAccountId: string) => {
        const record = getStoredThresholdEd25519SessionRecordForAccount(
          toAccountId(String(nearAccountId || ACCOUNT_ID)),
        );
        return {
          sessionId: record?.thresholdSessionId || 'session-1',
          status: 'active',
          remainingUses: record?.remainingUses ?? 3,
          expiresAtMs: record?.expiresAtMs ?? now + 60_000,
          createdAtMs: record?.updatedAtMs ?? now,
        };
      },
      scheduleRouterAbEcdsaHssLoginPresignaturePrefill: async () => ({
        status: 'scheduled',
        reason: 'scheduled',
      }),
      requestWorkerOperation: async (call: {
        kind: string;
        request: { type: string; payload?: unknown };
      }) => {
        const payload =
          call.request.payload &&
          typeof call.request.payload === 'object' &&
          !Array.isArray(call.request.payload)
            ? (call.request.payload as Record<string, unknown>)
            : {};
        if (
          call.request.type === 'thresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization'
        ) {
          return {
            ok: true,
            unsealAuthorization: {
              kind: 'passkey_prf_material_authorization_handle_v1',
              handle: 'unseal-handle',
              purpose: 'unseal',
              rpId: String(payload.rpId || 'example.localhost'),
              credentialIdB64u: String(payload.credentialIdB64u || 'cred-1'),
              materialBindingDigest: String(payload.materialBindingDigest || ''),
              expiresAtMs: Number(payload.expiresAtMs || Date.now() + 60_000),
            },
            remainingUses: 1,
          };
        }
        if (call.request.type === 'thresholdEd25519RestoreWorkerMaterial') {
          const expectedMaterialBinding =
            payload.expectedMaterialBinding &&
            typeof payload.expectedMaterialBinding === 'object' &&
            !Array.isArray(payload.expectedMaterialBinding)
              ? (payload.expectedMaterialBinding as Record<string, unknown>)
              : {};
          const unsealAuthorization =
            payload.unsealAuthorization &&
            typeof payload.unsealAuthorization === 'object' &&
            !Array.isArray(payload.unsealAuthorization)
              ? (payload.unsealAuthorization as Record<string, unknown>)
              : {};
          const materialBindingDigest = String(
            unsealAuthorization.materialBindingDigest ||
              expectedMaterialBinding.materialBindingDigest ||
              '',
          );
          return {
            ok: true,
            materialHandle: `restored-worker-material:${materialBindingDigest}`,
            materialBindingDigest,
            clientVerifyingShareB64u: String(
              expectedMaterialBinding.clientVerifyingShareB64u || '',
            ),
            sealedWorkerMaterialRef: `ed25519-worker-material-v1:${materialBindingDigest}`,
            sealedWorkerMaterialB64u: 'sealed-worker-material',
            materialFormatVersion: 'ed25519_worker_material_v1',
            materialKeyId: String(expectedMaterialBinding.materialKeyId || ''),
            signerSlot: Number(expectedMaterialBinding.signerSlot || 1),
          };
        }
        if (call.request.type === 'thresholdEd25519ValidateWorkerMaterial') {
          const expectedMaterialBinding =
            payload.expectedMaterialBinding &&
            typeof payload.expectedMaterialBinding === 'object' &&
            !Array.isArray(payload.expectedMaterialBinding)
              ? (payload.expectedMaterialBinding as Record<string, unknown>)
              : {};
          const materialHandle = String(payload.materialHandle || '').trim();
          const materialHandleDigest = materialHandle.split(':').pop() || '';
          return {
            materialHandle,
            bindingDigest: String(
              expectedMaterialBinding.materialBindingDigest || materialHandleDigest,
            ),
            clientVerifyingShareB64u: String(
              expectedMaterialBinding.clientVerifyingShareB64u || '',
            ),
          };
        }
        throw new Error(`unexpected worker operation ${call.kind}:${call.request.type}`);
      },
      getNonceCoordinator: () => ({
        getDiagnostics: () => null,
        recoverDurableLeases: async () => undefined,
      }),
      setLastUser: async () => undefined,
      updateLastLogin: async () => undefined,
      ...(args?.signingEngine || {}),
  };
  const baseConfigs = {
    signing: {
      mode: { mode: 'threshold-signer' },
      sessionDefaults: { ttlMs: 60_000, remainingUses: 3 },
      routerAb: {
        normalSigning: {
          mode: 'enabled' as const,
          signingWorkerId: 'signing-worker-local',
        },
      },
    },
    network: {
      relayer: { url: 'https://relay.example' },
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
  const configOverrides = args?.configs || {};
  const signingOverrides =
    configOverrides.signing &&
    typeof configOverrides.signing === 'object' &&
    !Array.isArray(configOverrides.signing)
      ? (configOverrides.signing as Record<string, unknown>)
      : {};
  const routerAbOverrides =
    signingOverrides.routerAb &&
    typeof signingOverrides.routerAb === 'object' &&
    !Array.isArray(signingOverrides.routerAb)
      ? (signingOverrides.routerAb as Record<string, unknown>)
      : {};
  const normalSigningOverrides =
    routerAbOverrides.normalSigning &&
    typeof routerAbOverrides.normalSigning === 'object' &&
    !Array.isArray(routerAbOverrides.normalSigning)
      ? (routerAbOverrides.normalSigning as Record<string, unknown>)
      : {};
  return {
    signingEngine,
    signingRuntime: {
      services: {
        registrationAccounts: {
          getUserBySignerSlot: (...methodArgs: unknown[]) =>
            (signingEngine.getUserBySignerSlot as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          getLastUser: () => signingEngine.getLastUser(),
          nearAuthenticatorsByAccount: (...methodArgs: unknown[]) =>
            (
              signingEngine.nearAuthenticatorsByAccount as (
                ...args: unknown[]
              ) => Promise<unknown>
            )(...methodArgs),
          setLastUser: (...methodArgs: unknown[]) =>
            (signingEngine.setLastUser as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          updateLastLogin: (...methodArgs: unknown[]) =>
            (signingEngine.updateLastLogin as (...args: unknown[]) => Promise<unknown>)(
              ...methodArgs,
            ),
          getAllUsers: async () => [],
        },
      },
    },
    configs: {
      ...baseConfigs,
      ...configOverrides,
      signing: {
        ...baseConfigs.signing,
        ...signingOverrides,
        routerAb: {
          ...baseConfigs.signing.routerAb,
          ...routerAbOverrides,
          normalSigning: {
            ...baseConfigs.signing.routerAb.normalSigning,
            ...normalSigningOverrides,
          },
        },
      },
    },
  };
}

async function withMockedMostRecentProjection<T>(
  fn: () => Promise<T>,
  options?: {
    includeThresholdEcdsaProfiles?: boolean;
    profileContinuitySnapshot?: Record<string, unknown> | null;
    walletAccountSigners?: Array<Record<string, unknown>>;
    nearAccountId?: string;
  },
): Promise<T> {
  const mockNearAccountId = String(options?.nearAccountId || ACCOUNT_ID);
  const mockNearAccount = toAccountId(mockNearAccountId);
  let seededWalletBinding = false;
  const continuityPort = IndexedDBManager as unknown as {
    getProfileContinuitySnapshot?: unknown;
  };
  const profileLookupPort = IndexedDBManager as unknown as {
    resolveProfileAccountContext?: unknown;
  };
  const keyMaterialPort = IndexedDBManager as unknown as {
    getKeyMaterial?: unknown;
  };
  const signerPort = IndexedDBManager as unknown as {
    listAccountSignersByProfile?: unknown;
  };
  const originalContinuity = continuityPort.getProfileContinuitySnapshot;
  const originalProfileLookup = profileLookupPort.resolveProfileAccountContext;
  const originalKeyMaterial = keyMaterialPort.getKeyMaterial;
  const originalListAccountSignersByProfile = signerPort.listAccountSignersByProfile;
  const resolveMockAccountSigners = (): Array<Record<string, unknown>> => {
    if (options?.walletAccountSigners) {
      return options.walletAccountSigners;
    }
    if (options && 'profileContinuitySnapshot' in options) {
      return Array.isArray(options.profileContinuitySnapshot?.accountSigners)
        ? (options.profileContinuitySnapshot.accountSigners as Array<Record<string, unknown>>)
        : [];
    }
    return options?.includeThresholdEcdsaProfiles ? partialEcdsaProfileSigners() : [];
  };
  continuityPort.getProfileContinuitySnapshot = async () => {
    if (options && 'profileContinuitySnapshot' in options) {
      return options.profileContinuitySnapshot;
    }
    return options?.includeThresholdEcdsaProfiles
      ? {
          chainAccounts: [
            {
              chainIdKey: 'evm:11155111',
              accountAddress: `0x${'11'.repeat(20)}`,
              accountModel: 'threshold-ecdsa',
            },
          ],
          accountSigners: resolveMockAccountSigners(),
        }
      : { chainAccounts: [] };
  };
  signerPort.listAccountSignersByProfile = async () => resolveMockAccountSigners();
  if (!getStoredThresholdEd25519SessionRecordForAccount(mockNearAccount)) {
    seededWalletBinding = true;
    upsertStoredThresholdEd25519SessionRecord({
      walletId: mockNearAccountId,
      nearAccountId: mockNearAccount,
      nearEd25519SigningKeyId: mockNearAccountId,
      rpId: 'example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      signerSlot: 1,
      thresholdSessionKind: 'jwt',
      thresholdSessionId: `binding-only-ed25519-session:${mockNearAccountId}`,
      signingGrantId: WALLET_SIGNING_SESSION_ID,
      walletSessionJwt: 'binding-only-ed25519-jwt',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 0,
      runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-local',
      },
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      keyVersion: ED25519_KEY_VERSION,
      source: 'login',
    });
  }
  profileLookupPort.resolveProfileAccountContext = async (accountRef: {
    chainIdKey: string;
    accountAddress: string;
  }) =>
    accountRef.chainIdKey === 'near:testnet' &&
    String(accountRef.accountAddress || '').trim() === mockNearAccountId
      ? { profileId: `near-profile:${mockNearAccountId}`, accountRef }
      : null;
  keyMaterialPort.getKeyMaterial = async () => ({
    profileId: `near-profile:${mockNearAccountId}`,
    signerSlot: 1,
    chainIdKey: 'near:testnet',
    keyKind: 'threshold_share_v1',
    algorithm: 'ed25519',
    publicKey: 'ed25519:threshold',
    payload: {
      relayerKeyId: 'rk-1',
      keyVersion: 'threshold-ed25519-hss-v1',
      participants: [
        { id: 1, role: 'client' },
        { id: 2, role: 'relayer', relayerKeyId: 'rk-1' },
      ],
    },
    timestamp: Date.now(),
    schemaVersion: 1,
  });
  try {
    return await fn();
  } finally {
    const seededRecord = seededWalletBinding
      ? getStoredThresholdEd25519SessionRecordForAccount(mockNearAccount)
      : null;
    if (
      seededRecord &&
      String(seededRecord.thresholdSessionId || '') ===
        `binding-only-ed25519-session:${mockNearAccountId}`
    ) {
      const laneKey = thresholdEd25519SessionRecordKeyFromRecord(seededRecord);
      if (laneKey) clearStoredThresholdEd25519SessionRecordForLaneKey(laneKey);
    }
    continuityPort.getProfileContinuitySnapshot = originalContinuity;
    profileLookupPort.resolveProfileAccountContext = originalProfileLookup;
    keyMaterialPort.getKeyMaterial = originalKeyMaterial;
    signerPort.listAccountSignersByProfile = originalListAccountSignersByProfile;
  }
}

test.describe('unlock threshold warm-session requirements', () => {
  test('anonymous wallet-session read does not restore a prior NEAR profile', async () => {
    let lastUserReads = 0;
    const context = createBaseContext({
      signingEngine: {
        getLastUser: async () => {
          lastUserReads += 1;
          return {
            nearAccountId: 'alice.testnet',
            signerSlot: 1,
            operationalPublicKey: 'ed25519:alice',
          };
        },
      },
    });

    const session = await getWalletSession(context);

    expect(lastUserReads).toBe(0);
    expect(session.login.isLoggedIn).toBe(false);
    expect(session.login.walletId).toBeNull();
    expect(session.login.nearAccountId).toBeNull();
    expect(session.signingSession).toBeNull();
  });

  test('wallet-session read rejects implicit NEAR account id as a wallet id', async () => {
    const now = Date.now();
    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: toWalletId(IMPLICIT_WALLET_ID),
      nearAccountId: IMPLICIT_NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: IMPLICIT_ED25519_KEY_SCOPE_ID,
      rpId: 'example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'implicit-ed25519-session',
      signingGrantId: 'implicit-ed25519-grant',
      walletSessionJwt: 'jwt-implicit-ed25519',
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-local',
      },
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      source: 'login',
    });
    const context = createBaseContext();

    try {
      const session = await getWalletSession(context, IMPLICIT_NEAR_ACCOUNT_ID);

      expect(session.login.isLoggedIn).toBe(false);
      expect(session.login.walletId).toBeNull();
      expect(session.login.nearAccountId).toBeNull();
      expect(session.signingSession).toBeNull();
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('does not report logged in when only a pending Ed25519 session record exists', async () => {
    const now = Date.now();
    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: ACCOUNT_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ACCOUNT_ID,
      rpId: 'example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'pending-ed25519-session',
      signingGrantId: 'pending-ed25519-grant',
      walletSessionJwt: 'jwt-pending-ed25519',
      expiresAtMs: now + 60_000,
      remainingUses: 3,
      runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-local',
      },
      signingRootId: 'proj_local:dev',
      signingRootVersion: 'default',
      source: 'login',
    });
    const context = createBaseContext({
      signingEngine: {
        getWarmThresholdEd25519SessionStatus: async () => null,
        listWarmThresholdEcdsaSessionStatuses: async () => [],
        readPersistedAvailableSigningLanes: async () => null,
      },
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
          chains: [],
        },
      },
    });

    try {
      const session = await withMockedMostRecentProjection(
        async () => await getWalletSession(context, ACCOUNT_ID),
        { profileContinuitySnapshot: null },
      );

      expect(session.login.isLoggedIn).toBe(false);
      expect(session.login.publicKey).toBeNull();
      expect(session.signingSession?.status || null).not.toBe('active');
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('passkey wallet unlock lets threshold warm-up own the no-session-exchange assertion', async () => {
    let credentialPrompts = 0;
    const connectCalls: Array<Record<string, unknown>> = [];
    const context = createBaseContext({
      signingEngine: {
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialPrompts += 1;
          expect(args.subjectId).toBe(ACCOUNT_ID);
          expect(String(args.challengeB64u || '')).toMatch(/^[A-Za-z0-9_-]{43}$/);
          expect(args.allowCredentials).toEqual([
            {
              id: 'cred-1',
              type: 'public-key',
              transports: [],
            },
          ]);
          return {
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: {},
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls.push(args);
          await persistReadyEd25519WarmRecord({
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success, String(result.error || '')).toBe(true);
    expect(credentialPrompts).toBe(1);
    expect(connectCalls).toHaveLength(1);
    expect((connectCalls[0]?.auth as Record<string, unknown> | undefined)?.kind).toBe(
      'threshold_session_policy_webauthn',
    );
  });

  test('implicit passkey unlock warms Ed25519 and ECDSA under the server-allocated wallet id', async () => {
    clearAllStoredThresholdEd25519SessionRecords();
    const nearAccountId = IMPLICIT_NEAR_ACCOUNT_ID;
    const walletId = IMPLICIT_WALLET_ID;
    const nearEd25519SigningKeyId = IMPLICIT_ED25519_KEY_SCOPE_ID;
    await persistReadyEd25519WarmRecord({
      sessionId: 'implicit-seed-ed25519-session',
      signingGrantId: 'implicit-seed-ed25519-grant',
      walletSessionJwt: 'jwt-implicit-seed',
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 3,
    });

    const clearCalls: string[] = [];
    const laneReadCalls: Array<Record<string, unknown>> = [];
    const listCalls: Array<Record<string, unknown>> = [];
    const connectCalls: Array<Record<string, unknown>> = [];
    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        getUserBySignerSlot: async () => ({
          nearAccountId,
          signerSlot: 1,
          operationalPublicKey: 'ed25519:implicit',
        }),
        getLastUser: async () => ({
          nearAccountId,
          signerSlot: 1,
          operationalPublicKey: 'ed25519:implicit',
        }),
        nearAuthenticatorsByAccount: async () => [{ credentialId: 'cred-implicit', signerSlot: 1 }],
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          expect(args.subjectId).toBe(String(nearAccountId));
          return {
            id: 'cred-implicit',
            rawId: 'cred-implicit',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: {},
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        clearVolatileWarmSigningMaterial: async (inputWalletId: unknown) => {
          clearCalls.push(String(inputWalletId));
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => {
          listCalls.push(args);
          return [];
        },
        readPersistedAvailableSigningLanes: async (input: Record<string, unknown>) => {
          laneReadCalls.push(input);
          if (bootstrapCalls.length === 0) return null;
          return loginReadySigningLanes({
            walletId: input.walletId,
            authMethod: input.authMethod === 'email_otp' ? 'email_otp' : 'passkey',
          });
        },
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls.push(args);
          await persistReadyEd25519WarmRecord({
            sessionId: 'implicit-login-ed25519-session',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-implicit-ed25519',
            walletId,
            nearAccountId,
            nearEd25519SigningKeyId,
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'implicit-login-ed25519-session',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-implicit-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls.push(args);
          const chainTarget =
            (args.chainTarget as ThresholdEcdsaChainTarget | undefined) || bootstrapChainTarget(args);
          const ecdsaThresholdKeyId = ecdsaKeyIdForChainTarget(
            chainTarget as unknown as Record<string, unknown>,
          );
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: walletId,
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `implicit-ecdsa-${bootstrapCalls.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-implicit-ecdsa',
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `implicit-ecdsa-${bootstrapCalls.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-implicit-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
              runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
            passkeyCredentialIdB64u: 'cred-implicit',
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, nearAccountId),
        { nearAccountId: String(nearAccountId), profileContinuitySnapshot: null },
      );

      expect(result.success, String(result.error || '')).toBe(true);
      expect(connectCalls).toHaveLength(1);
      expect(connectCalls[0]?.walletId).toBe(walletId);
      expect(connectCalls[0]?.nearAccountId).toBe(String(nearAccountId));
      expect(connectCalls[0]?.nearEd25519SigningKeyId).toBe(nearEd25519SigningKeyId);
      expect(clearCalls).toEqual([walletId]);
      expect(listCalls.length).toBeGreaterThan(0);
      expect(listCalls.every((call) => String(call.walletId) === walletId)).toBe(true);
      expect(bootstrapCalls.length).toBeGreaterThan(0);
      expect(
        bootstrapCalls.every((call) => {
          const key = call.key as Record<string, unknown> | undefined;
          return String(call.walletId || key?.walletId || '') === walletId;
        }),
      ).toBe(true);
      expect(laneReadCalls.some((call) => String(call.walletId) === walletId)).toBe(true);
      expect(getStoredThresholdEd25519SessionRecordForAccount(nearAccountId)?.walletId).toBe(
        toWalletId(walletId),
      );
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('returns active signingSession in threshold-signer warm mode', async () => {
    let bootstrapCalls = 0;
    let bootstrapArgs: Record<string, unknown> | null = null;
    const bootstrapChains: string[] = [];
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs = args;
          bootstrapChains.push(String(bootstrapChainTarget(args).kind || ''));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
        scheduleRouterAbEcdsaHssLoginPresignaturePrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });
    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success, String(result.error || '')).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect('thresholdEcdsaKeyRef' in (result as unknown as Record<string, unknown>)).toBe(false);
    expect(bootstrapCalls).toBe(2);
    expect(bootstrapChains).toEqual(['tempo', 'evm']);
    expect(String(bootstrapArgs?.['kind'] || '')).toBe(
      'wallet_session_reconnect_ecdsa_bootstrap',
    );
    expect(String(bootstrapArgs?.['source'] || '')).toBe('login');
    expect(bootstrapArgs?.['routeAuth']).toEqual({
      kind: 'wallet_session',
      jwt: 'jwt-ed25519',
    });
    const sharedKey = bootstrapArgs?.['key'] as Record<string, unknown> | undefined;
    const lanePolicy = bootstrapArgs?.['lanePolicy'] as Record<string, unknown> | undefined;
    expect(String(lanePolicy?.thresholdSessionId || '')).toMatch(/^threshold-ecdsa-login-/);
    expect(lanePolicy?.signingGrantId).toBe(WALLET_SIGNING_SESSION_ID);
    expect(sharedKey?.keyScope).toBe('evm-family');
    expect(sharedKey?.ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
    expect(lanePolicy?.chainTarget).toEqual(EVM_CHAIN_TARGET);
    expect('chainTarget' in ((bootstrapArgs || {}) as Record<string, unknown>)).toBe(false);
    expect(bootstrapArgs?.['passkeyPrfFirstB64u']).toBe(ECDSA_PRF_FIRST_B64U);
    expect(prefillCalls).toBe(0);
  });

  test('wallet unlock surfaces stale ECDSA owner identity without retrying bootstrap', async () => {
    const returnedOwnerAddress = `0x${'bb'.repeat(20)}`;
    const bootstrapKinds: string[] = [];
    const exactOwnerAddresses: string[] = [];
    const staleOwnerError = new Error(
      'threshold-ecdsa exact activation owner address mismatches server bootstrap result',
    ) as Error & { code: string };
    staleOwnerError.code = 'stale_ecdsa_key_identity';
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const kind = String(args.kind || '');
          bootstrapKinds.push(kind);
          if (kind === 'wallet_session_reconnect_ecdsa_bootstrap') {
            exactOwnerAddresses.push(String(bootstrapKey(args).thresholdOwnerAddress || ''));
            if (bootstrapKinds.length === 1) {
              throw staleOwnerError;
            }
          } else {
            expect(kind).toBe('passkey_fresh_ecdsa_bootstrap');
            expect(args.chainTarget).toEqual(TEMPO_CHAIN_TARGET);
            expect('key' in args).toBe(false);
            expect(args.routeAuth).toEqual({
              kind: 'wallet_session',
              jwt: 'jwt-ed25519',
            });
            expect(args.runtimeScopeBootstrap).toEqual({
              environmentId: 'proj_local:dev',
              publishableKey: 'pk_test_local',
            });
          }
          const lanePolicy = (args.lanePolicy || {}) as Record<string, unknown>;
          const sessionIdentity = (args.sessionIdentity || {}) as Record<string, unknown>;
          const thresholdSessionId = String(
            lanePolicy.thresholdSessionId ||
              sessionIdentity.thresholdSessionId ||
              `session-stale-inventory-${bootstrapKinds.length}`,
          );
          const signingGrantId = String(
            lanePolicy.signingGrantId ||
              sessionIdentity.signingGrantId ||
              WALLET_SIGNING_SESSION_ID,
          );
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId,
              signingGrantId,
              walletSessionJwt: 'jwt-ecdsa',
              ethereumAddress: returnedOwnerAddress,
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: returnedOwnerAddress,
            },
            session: {
              ok: true,
              sessionId: thresholdSessionId,
              signingGrantId,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
              runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain(
      'threshold-ecdsa exact activation owner address mismatches server bootstrap result',
    );
    expect(bootstrapKinds).toEqual(['wallet_session_reconnect_ecdsa_bootstrap']);
    expect(exactOwnerAddresses).toEqual([THRESHOLD_OWNER_ADDRESS]);
  });

  test('wallet unlock provisions fresh passkey sessions even when restored sessions exist', async () => {
    let restoreCalls = 0;
    let connectCalls = 0;
    let clearCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        discoverPersistedSessionsForWallet: async () => {
          restoreCalls += 1;
          return {
            listed: 1,
            discovered: 1,
            truncated: 0,
          };
        },
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls += 1;
          expect(args.source).toBe('login');
          expect(args.remainingUses).toBe(3);
          await persistReadyEd25519WarmRecord({
            sessionId: 'fresh-passkey-session-1',
            signingGrantId: 'fresh-wallet-session-1',
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'fresh-passkey-session-1',
            signingGrantId: 'fresh-wallet-session-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success, String(result.error || '')).toBe(true);
    expect(connectCalls).toBe(1);
    expect(restoreCalls).toBe(0);
    expect(clearCalls).toBe(1);
  });

  test('wallet unlock requires explicit authenticated ECDSA key-facts inventory before incomplete local warm-up', async () => {
    const originalFetch = globalThis.fetch;
    let connectCalls = 0;
    let fetchCalls = 0;
    let clearCalls = 0;
    let bootstrapCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async () => {
          connectCalls += 1;
          return {
            ok: true,
            sessionId: 'fresh-ed25519-session',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-fresh',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('bootstrap should not run before authenticated inventory');
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(String(result.error || '')).toContain(
        'explicit authenticated ECDSA key-facts inventory',
      );
      expect(connectCalls).toBe(0);
      expect(fetchCalls).toBe(0);
      expect(clearCalls).toBe(1);
      expect(bootstrapCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock resolves explicit app-session ECDSA key-facts inventory before warm-up', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryBodies: unknown[] = [];
    const bootstrapTargets: string[] = [];
    let clearCalls = 0;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/wallets/alice.testnet/signers/ecdsa/key-facts/inventory')) {
        expect(init?.headers).toMatchObject({
          Authorization: 'Bearer app-session-inventory-jwt',
        });
        const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        inventoryBodies.push(body);
        expect(body).toMatchObject({
          rpId: 'example.localhost',
          auth: {
            kind: 'app_session',
            policy: {
              permission: 'ecdsa_key_facts_inventory',
              walletId: 'alice.testnet',
            },
          },
        });
        return new Response(
          JSON.stringify({
            ok: true,
            ecdsaKeyIdentityTargets: [
              ecdsaKeyIdentityTargetRecord(TEMPO_CHAIN_TARGET),
              ecdsaKeyIdentityTargetRecord(EVM_CHAIN_TARGET),
            ],
            diagnostics: {},
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const chainTarget = bootstrapChainTarget(args);
          bootstrapTargets.push(thresholdEcdsaChainTargetKey(chainTarget));
          expect(bootstrapKey(args).thresholdOwnerAddress).toBe(THRESHOLD_OWNER_ADDRESS);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `session-inventory-${bootstrapTargets.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `session-inventory-${bootstrapTargets.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
            ecdsaKeyFactsInventory: {
              mode: 'app_session',
              appSessionJwt: 'app-session-inventory-jwt',
              policyTtlMs: 60_000,
            },
          }),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(true);
      expect(inventoryBodies).toHaveLength(1);
      expect(bootstrapTargets.sort()).toEqual(['evm:eip155:5042002', 'tempo:42431']);
      expect(clearCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock uses WebAuthn ECDSA key-facts inventory assertion as the only prompt', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryBodies: unknown[] = [];
    const credentialChallenges: string[] = [];
    const bootstrapTargets: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/wallets/alice.testnet/signers/ecdsa/key-facts/inventory')) {
        const body = JSON.parse(String(init?.body || '{}')) as Record<string, unknown>;
        inventoryBodies.push(body);
        const auth = body.auth as Record<string, unknown>;
        expect(auth.kind).toBe('webauthn_assertion');
        expect(String(auth.expectedChallengeDigestB64u || '')).toBe(
          credentialChallenges[credentialChallenges.length - 1],
        );
        expect(String(auth.serverNonceB64u || '')).toBeTruthy();
        return new Response(
          JSON.stringify({
            ok: true,
            ecdsaKeyIdentityTargets: [
              ecdsaKeyIdentityTargetRecord(TEMPO_CHAIN_TARGET),
              ecdsaKeyIdentityTargetRecord(EVM_CHAIN_TARGET),
            ],
            diagnostics: {},
          }),
          {
            status: 200,
            headers: { 'Content-Type': 'application/json' },
          },
        );
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialChallenges.push(String(args.challengeB64u || ''));
          return {
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: {},
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const chainTarget = bootstrapChainTarget(args);
          bootstrapTargets.push(thresholdEcdsaChainTargetKey(chainTarget));
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `session-webauthn-inventory-${bootstrapTargets.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: bootstrapEcdsaThresholdKeyId(args),
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `session-webauthn-inventory-${bootstrapTargets.length}`,
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
            ecdsaKeyFactsInventory: { mode: 'webauthn' },
          }),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(true);
      expect(credentialChallenges).toHaveLength(1);
      expect(inventoryBodies).toHaveLength(1);
      expect(bootstrapTargets.sort()).toEqual(['evm:eip155:5042002', 'tempo:42431']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock does not fetch role-local inventory during normal unlock', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    let bootstrapCalls = 0;
    globalThis.fetch = (async () => {
      fetchCalls += 1;
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('bootstrap should not run before authenticated inventory');
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain(
        'explicit authenticated ECDSA key-facts inventory',
      );
      expect(fetchCalls).toBe(0);
      expect(bootstrapCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey unlock first-bootstraps missing ECDSA lanes from the current assertion', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapKinds: string[] = [];
    const inventoryRequests: unknown[] = [];
    let credentialPrompts = 0;
    const loginCredential = {
      id: 'cred-first-bootstrap',
      rawId: 'cred-first-bootstrap',
      type: 'public-key',
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: 'client-data-json',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: undefined,
        clientExtensionResults: { shouldRedact: true },
      },
      clientExtensionResults: {
        prf: {
          results: {
            first: ECDSA_PRF_FIRST_B64U,
          },
        },
      },
    };
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://relay.example/wallet/unlock/challenge') {
        return new Response(
          JSON.stringify({
            ok: true,
            challengeId: 'challenge-first-bootstrap',
            challengeB64u: 'challenge-first-bootstrap-b64u',
            expiresAtMs: Date.now() + 60_000,
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/session/exchange') {
        return new Response(
          JSON.stringify({
            ok: true,
            session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            jwt: 'app-jwt-first-bootstrap',
          }),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      if (url === 'https://relay.example/router-ab/ecdsa-hss/key-identities') {
        inventoryRequests.push(url);
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        getAuthenticationCredentialsSerialized: async () => {
          credentialPrompts += 1;
          return loginCredential;
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const kind = String(args.kind || '');
          const callIndex = bootstrapKinds.length;
          bootstrapKinds.push(kind);
          if (kind === 'passkey_fresh_ecdsa_bootstrap') {
            expect(args.webauthnAuthentication).toEqual(loginCredential);
            expect(args.routeAuth).toEqual(
              callIndex === 0
                ? {
                    kind: 'app_session',
                    jwt: 'app-jwt-first-bootstrap',
                  }
                : {
                    kind: 'wallet_session',
                    jwt: 'jwt-ecdsa',
                  },
            );
            expect(args.passkeyPrfFirstB64u).toBe(ECDSA_PRF_FIRST_B64U);
            expect(args.runtimeScopeBootstrap).toEqual({
              environmentId: 'proj_local:dev',
              publishableKey: 'pk_test_local',
            });
          } else {
            expect(kind).toBe('wallet_session_reconnect_ecdsa_bootstrap');
            expect(bootstrapKey(args).ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          }
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-ecdsa-first-bootstrap',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-ecdsa-first-bootstrap',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
              runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
        { profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] } },
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapKinds).toEqual([
        'passkey_fresh_ecdsa_bootstrap',
        'wallet_session_reconnect_ecdsa_bootstrap',
      ]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey unlock without server session first-bootstraps from the prompt-first assertion', async () => {
    const bootstrapKinds: string[] = [];
    const bootstrapSigningGrantIds: string[] = [];
    let connectArgs: Record<string, unknown> | null = null;
    let credentialPrompts = 0;
    const loginCredential = {
      id: 'cred-local-first-bootstrap',
      rawId: 'cred-local-first-bootstrap',
      type: 'public-key',
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: 'client-data-json',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: undefined,
      },
      clientExtensionResults: {
        prf: {
          results: {
            first: ECDSA_PRF_FIRST_B64U,
          },
        },
      },
    };
    const context = createBaseContext({
      configs: {
        registration: {
          mode: 'managed',
          environmentId: 'proj_local:dev',
          publishableKey: 'pk_test_local',
        },
      },
      signingEngine: {
        getAuthenticationCredentialsSerialized: async (args: Record<string, unknown>) => {
          credentialPrompts += 1;
          expect(args.subjectId).toBe(ACCOUNT_ID);
          expect(String(args.challengeB64u || '')).toMatch(/^[A-Za-z0-9_-]{43}$/);
          return loginCredential;
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectArgs = args;
          await persistReadyEd25519WarmRecord({
            sessionId: 'session-local-first-bootstrap',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-ed25519-local-first-bootstrap',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'session-local-first-bootstrap',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-local-first-bootstrap',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const kind = String(args.kind || '');
          bootstrapKinds.push(kind);
          const lanePolicy = args.lanePolicy as Record<string, unknown> | undefined;
          const sessionIdentity = args.sessionIdentity as Record<string, unknown> | undefined;
          const signingGrantId = String(
            lanePolicy?.signingGrantId || sessionIdentity?.signingGrantId || '',
          );
          bootstrapSigningGrantIds.push(signingGrantId);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: `session-local-first-bootstrap-${bootstrapKinds.length}`,
              signingGrantId: signingGrantId || WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: `session-local-first-bootstrap-${bootstrapKinds.length}`,
              signingGrantId: signingGrantId || WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
              runtimePolicyScope: LOGIN_RUNTIME_POLICY_SCOPE,
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] } },
    );

    expect(result.success, String(result.error || '')).toBe(true);
    expect(credentialPrompts).toBe(1);
    expect(connectArgs).not.toBeNull();
    expect(bootstrapKinds).toEqual([
      'passkey_fresh_ecdsa_bootstrap',
      'wallet_session_reconnect_ecdsa_bootstrap',
    ]);
    expect(bootstrapSigningGrantIds.every(Boolean)).toBe(true);
  });

  test('passkey unlock uses complete active wallet-scoped ECDSA key facts without inventory fetch', async () => {
    const originalFetch = globalThis.fetch;
    const inventoryRequests: unknown[] = [];
    const bootstrapKinds: string[] = [];
    let credentialPrompts = 0;
    const connectAuthKinds: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url === 'https://relay.example/router-ab/ecdsa-hss/key-identities') {
        inventoryRequests.push(url);
      }
      return new Response(JSON.stringify({ ok: false, message: 'unexpected route' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        getAuthenticationCredentialsSerialized: async () => {
          credentialPrompts += 1;
          return {
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: {},
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                },
              },
            },
          };
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async (args: Record<string, unknown>) => {
          const auth = args.auth as Record<string, unknown> | undefined;
          connectAuthKinds.push(String(auth?.kind || ''));
          expect(auth?.kind).toBe('threshold_session_policy_webauthn');
          await persistReadyEd25519WarmRecord({
            sessionId: 'session-profile-complete-ed25519',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-ed25519-profile-complete',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'session-profile-complete-ed25519',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-profile-complete',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapKinds.push(String(args.kind || ''));
          expect(args.keyHandle).toBe(ECDSA_KEY_HANDLE);
          expect(bootstrapKey(args).ecdsaThresholdKeyId).toBe(ECDSA_THRESHOLD_KEY_ID);
          expect(bootstrapKey(args).thresholdOwnerAddress).toBe(THRESHOLD_OWNER_ADDRESS);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: ECDSA_KEY_HANDLE,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-profile-complete',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-profile-complete',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: { chainAccounts: [], accountSigners: [] },
          walletAccountSigners: completeEcdsaProfileSigners(),
        },
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapKinds).toEqual([
        'wallet_session_reconnect_ecdsa_bootstrap',
        'wallet_session_reconnect_ecdsa_bootstrap',
      ]);
      expect(connectAuthKinds).toEqual(['threshold_session_policy_webauthn']);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock completes configured ECDSA targets from one shared local key record', async () => {
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => {
          const chainTarget = args.chainTarget as Record<string, unknown>;
          if (chainTarget.kind !== 'tempo') return [];
          return [canonicalEcdsaRecord({ chainTarget })];
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(bootstrapArgs).toHaveLength(2);
    expect(bootstrapArgs.map((args) => bootstrapEcdsaThresholdKeyId(args))).toEqual([
      ECDSA_THRESHOLD_KEY_ID,
      ECDSA_THRESHOLD_KEY_ID,
    ]);
    expect(bootstrapArgs.every((args) => Boolean(args.key && args.lanePolicy))).toBe(true);
  });

  test('wallet unlock fails before ECDSA warm-up when stored shared key ids conflict', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => {
          const chainTarget = args.chainTarget as Record<string, unknown>;
          return [
            canonicalEcdsaRecord({
              chainTarget,
              ecdsaThresholdKeyId:
                chainTarget.kind === 'evm' ? 'ehss-conflicting-evm-key' : ECDSA_THRESHOLD_KEY_ID,
            }),
          ];
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('ECDSA bootstrap should not start for ambiguous shared keys');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('duplicate shared key handles');
    expect(bootstrapCalls).toBe(0);
  });

  test('wallet unlock clears volatile material after rejecting profile-only owner metadata', async () => {
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    let clearVolatileCalls = 0;
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, ecdsaKeyIdentityTargets: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearVolatileCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [
              {
                chainIdKey: 'tempo:42431',
                accountAddress: `0x${'aa'.repeat(20)}`,
                accountModel: 'tempo-native',
                status: 'active',
                isPrimary: true,
              },
            ],
            accountSigners: [
              {
                chainIdKey: 'tempo:42431',
                accountAddress: `0x${'aa'.repeat(20)}`,
                signerId: `0x${'aa'.repeat(20)}`,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: {
                    kind: 'tempo',
                    chainId: 42431,
                    networkSlug: 'tempo-testnet',
                  },
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: `0x${'aa'.repeat(20)}`,
                },
              },
            ],
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(bootstrapArgs).toHaveLength(0);
      expect(clearVolatileCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock clears volatile material after rejecting profile metadata without key handles', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapArgs: Array<Record<string, unknown>> = [];
    let clearVolatileCalls = 0;
    globalThis.fetch = (async () => {
      throw new Error('inventory fetch should not run for blocked profile metadata');
    }) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          clearVolatileCalls += 1;
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                clientAdditiveShare32B64u: 'Ag',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
              chainIdKey: thresholdEcdsaChainTargetKey(chainTarget),
              accountAddress: THRESHOLD_OWNER_ADDRESS,
              signerId: THRESHOLD_OWNER_ADDRESS,
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              status: 'active',
              metadata: {
                ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                chainTarget,
                subjectId: ACCOUNT_ID,
                rpId: 'example.localhost',
                signingRootId: 'proj_local:dev',
                signingRootVersion: 'default',
                participantIds: [1, 2],
                thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
              },
            })),
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(bootstrapArgs).toHaveLength(0);
      expect(clearVolatileCalls).toBe(1);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('mutation ledger clears volatile material after ECDSA preflight rejection', async () => {
    const now = Date.now();
    const originalFetch = globalThis.fetch;
    const blockedLedger: string[] = [];
    globalThis.fetch = (async () => {
      blockedLedger.push('inventory');
      throw new Error('blocked profile metadata should not fetch inventory');
    }) as typeof fetch;
    const blockedContext = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        connectEd25519Session: async () => {
          blockedLedger.push('connect-ed25519');
          throw new Error('blocked profile metadata should not provision Ed25519');
        },
        clearVolatileWarmSigningMaterial: async () => {
          blockedLedger.push('clear');
        },
        bootstrapEcdsaSession: async () => {
          blockedLedger.push('bootstrap-ecdsa');
          throw new Error('blocked profile metadata should not bootstrap ECDSA');
        },
      },
    });

    try {
      const blockedResult = await withMockedMostRecentProjection(
        async () => await unlock(blockedContext, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: [TEMPO_CHAIN_TARGET, EVM_CHAIN_TARGET].map((chainTarget) => ({
              chainIdKey: thresholdEcdsaChainTargetKey(chainTarget),
              accountAddress: THRESHOLD_OWNER_ADDRESS,
              signerId: THRESHOLD_OWNER_ADDRESS,
              signerKind: 'threshold-ecdsa',
              signerAuthMethod: 'passkey',
              status: 'active',
              metadata: {
                ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                chainTarget,
                subjectId: ACCOUNT_ID,
                rpId: 'example.localhost',
                signingRootId: 'proj_local:dev',
                signingRootVersion: 'default',
                participantIds: [1, 2],
                thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
              },
            })),
          },
        },
      );

      expect(blockedResult.success).toBe(false);
      expect(String(blockedResult.error || '')).toContain('requires complete local key facts');
      expect(blockedLedger).toEqual(['clear']);
    } finally {
      globalThis.fetch = originalFetch;
    }

    const inventoryLedger: string[] = [];
    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: ACCOUNT_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ACCOUNT_ID,
      rpId: 'example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'stored-ed25519-inventory-session',
      walletSessionJwt: 'jwt-ed25519-restored',
      expiresAtMs: now + 60_000,
      remainingUses: 1,
      source: 'manual-connect',
    });
    globalThis.fetch = (async () => {
      inventoryLedger.push('inventory');
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const inventoryContext = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        clearVolatileWarmSigningMaterial: async () => {
          inventoryLedger.push('clear');
        },
        connectEd25519Session: async () => {
          inventoryLedger.push('connect-ed25519');
          return {
            ok: true,
            sessionId: 'fresh-ed25519-after-inventory',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519-fresh',
            remainingUses: 3,
            expiresAtMs: now + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        getWarmThresholdEd25519SessionStatus: async () => ({
          sessionId: 'fresh-ed25519-after-inventory',
          status: 'active',
          authMethod: 'passkey',
          remainingUses: 3,
          expiresAtMs: now + 60_000,
          createdAtMs: now,
        }),
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          inventoryLedger.push(
            `bootstrap:${thresholdEcdsaChainTargetKey(bootstrapChainTarget(args))}`,
          );
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-ecdsa-after-inventory',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-ecdsa-after-inventory',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: now + 60_000,
            },
          };
        },
      },
    });

    try {
      const inventoryResult = await withMockedMostRecentProjection(
        async () => await unlock(inventoryContext, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: partialEcdsaProfileSigners(),
          },
        },
      );

      expect(inventoryResult.success).toBe(false);
      expect(String(inventoryResult.error || '')).toContain(
        'explicit authenticated ECDSA key-facts inventory',
      );
      expect(inventoryLedger).toEqual(['clear']);
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
      globalThis.fetch = originalFetch;
    }
  });

  test('wallet unlock blocks stale configured ECDSA profile signers before inventory lookup', async () => {
    const originalFetch = globalThis.fetch;
    const bootstrapChains: string[] = [];
    const inventoryRequests: unknown[] = [];
    globalThis.fetch = (async () => {
      inventoryRequests.push('unexpected');
      return new Response(JSON.stringify({ ok: false, message: 'unexpected inventory fetch' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }) as typeof fetch;
    const context = createBaseContext({
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
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
            {
              network: 'ethereum-sepolia',
              rpcUrl: 'https://rpc.sepolia.test',
              explorerUrl: 'https://explorer.sepolia.test',
              chainId: 11155111,
            },
          ],
        },
      },
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapChains.push(thresholdEcdsaChainTargetKey(bootstrapChainTarget(args)));
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
              ethereumAddress: THRESHOLD_OWNER_ADDRESS,
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        {
          profileContinuitySnapshot: {
            chainAccounts: [],
            accountSigners: [
              {
                chainIdKey: thresholdEcdsaChainTargetKey(TEMPO_CHAIN_TARGET),
                accountAddress: THRESHOLD_OWNER_ADDRESS,
                signerId: THRESHOLD_OWNER_ADDRESS,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  keyHandle: ECDSA_KEY_HANDLE,
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: TEMPO_CHAIN_TARGET,
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
                },
              },
              {
                chainIdKey: thresholdEcdsaChainTargetKey(SEPOLIA_CHAIN_TARGET),
                accountAddress: THRESHOLD_OWNER_ADDRESS,
                signerId: THRESHOLD_OWNER_ADDRESS,
                signerKind: 'threshold-ecdsa',
                signerAuthMethod: 'passkey',
                status: 'active',
                metadata: {
                  ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
                  chainTarget: SEPOLIA_CHAIN_TARGET,
                  subjectId: ACCOUNT_ID,
                  rpId: 'example.localhost',
                  signingRootId: 'proj_local:dev',
                  signingRootVersion: 'default',
                  participantIds: [1, 2],
                  thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
                },
              },
            ],
          },
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain(
        'explicit authenticated ECDSA key-facts inventory',
      );
      expect(inventoryRequests).toHaveLength(0);
      expect(bootstrapChains).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('caps passkey unlock warm sessions at three uses', async () => {
    let ed25519RemainingUses: unknown = null;
    const ecdsaRemainingUses: unknown[] = [];
    const ecdsaSigningGrantIds: unknown[] = [];
    const context = createBaseContext({
      configs: {
        signing: {
          mode: { mode: 'threshold-signer' },
          sessionDefaults: { ttlMs: 60_000, remainingUses: 6 },
        },
      },
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          ed25519RemainingUses = args.remainingUses;
          await persistReadyEd25519WarmRecord({
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: Number(args.remainingUses),
          });
          return {
            ok: true,
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519',
            remainingUses: Number(args.remainingUses),
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const lanePolicy = bootstrapLanePolicy(args);
          ecdsaRemainingUses.push(lanePolicy.remainingUses);
          ecdsaSigningGrantIds.push(lanePolicy.signingGrantId);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: Number(bootstrapLanePolicy(args).remainingUses),
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          signingSession: { ttlMs: 60_000, remainingUses: 6 },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(ed25519RemainingUses).toBe(3);
    expect(ecdsaRemainingUses).toEqual([3, 3]);
    expect(ecdsaSigningGrantIds).toEqual([
      WALLET_SIGNING_SESSION_ID,
      WALLET_SIGNING_SESSION_ID,
    ]);
  });

  test('uses three unlock budget uses under the dev default', async () => {
    let ed25519RemainingUses: unknown = null;
    const ecdsaRemainingUses: unknown[] = [];
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          ed25519RemainingUses = args.remainingUses;
          await persistReadyEd25519WarmRecord({
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: Number(args.remainingUses),
          });
          return {
            ok: true,
            sessionId: 'session-1',
            signingGrantId: WALLET_SIGNING_SESSION_ID,
            jwt: 'jwt-ed25519',
            remainingUses: Number(args.remainingUses),
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          const lanePolicy = bootstrapLanePolicy(args);
          ecdsaRemainingUses.push(lanePolicy.remainingUses);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: Number(lanePolicy.remainingUses),
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(ed25519RemainingUses).toBe(3);
    expect(ecdsaRemainingUses).toEqual([3, 3]);
  });

  test('fails closed when threshold warm-up cannot connect Ed25519 session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    let bootstrapCalls = 0;
    let prefillCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: false,
          code: 'unauthorized',
          message: 'session bootstrap rejected',
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
        scheduleRouterAbEcdsaHssLoginPresignaturePrefill: async () => {
          prefillCalls += 1;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold Ed25519 warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
    expect(bootstrapCalls).toBe(0);
    expect(prefillCalls).toBe(0);
  });

  test('fails closed when threshold warm-up cannot bootstrap ECDSA session', async () => {
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => {
          throw new Error('ecdsa bootstrap rejected');
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold ECDSA warm-up failed');
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('fails closed on stale integrated-key ECDSA warm-up during unlock', async () => {
    let bootstrapCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    let setLastUserCalls = 0;
    let updateLastLoginCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs.push(args);
          throw new Error(
            'threshold-ecdsa bootstrap client verifying share does not match integrated key record',
          );
        },
        setLastUser: async () => {
          setLastUserCalls += 1;
        },
        updateLastLogin: async () => {
          updateLastLoginCalls += 1;
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('threshold ECDSA warm-up failed');
    expect(String(result.error || '')).toContain(
      'threshold-ecdsa bootstrap client verifying share does not match integrated key record',
    );
    expect(bootstrapCalls).toBe(1);
    expect(bootstrapEcdsaThresholdKeyId(bootstrapArgs[0] || {})).toBe(ECDSA_THRESHOLD_KEY_ID);
    expect(setLastUserCalls).toBe(0);
    expect(updateLastLoginCalls).toBe(0);
  });

  test('fails closed when no canonical key id exists', async () => {
    let bootstrapCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ ok: true, ecdsaKeyIdentityTargets: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })) as typeof fetch;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapCalls += 1;
          bootstrapArgs.push(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId: 'ehss-login-fresh',
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: 'ehss-login-fresh',
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'session-1',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
          };
        },
      },
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('requires complete local key facts');
      expect(bootstrapCalls).toBe(0);
      expect(bootstrapArgs).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('login does not invoke ECDSA presign prefill automatically', async () => {
    let prefillCalls = 0;
    let prefillArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        scheduleRouterAbEcdsaHssLoginPresignaturePrefill: async (args: Record<string, unknown>) => {
          prefillCalls += 1;
          prefillArgs = args;
          return { status: 'scheduled', reason: 'scheduled' };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(prefillCalls).toBe(0);
    expect(prefillArgs).toBeNull();
  });

  test('fails closed when one-prompt ECDSA bootstrap share is unavailable', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async () => ({
          ok: true,
          sessionId: 'session-1',
          signingGrantId: WALLET_SIGNING_SESSION_ID,
          jwt: 'jwt-ed25519',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        }),
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain(
      'threshold ECDSA warm-up missing passkey PRF.first',
    );
    expect(bootstrapCalls).toBe(0);
  });

  test('login warm-up lets fresh Ed25519 provisioning mint its own session id even when canonical ECDSA state exists', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
          canonicalEcdsaRecord({
            chainTarget: args.chainTarget,
            ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
              args.chainTarget as Record<string, unknown>,
            ),
            thresholdSessionId: 'canonical-ecdsa-session-1',
            signingGrantId: 'canonical-wallet-session-1',
          }),
        ],
        connectEd25519Session: async (args: Record<string, unknown>) => {
          capturedConnectArgs = args;
          await persistReadyEd25519WarmRecord({
            sessionId: 'canonical-ecdsa-session-1',
            signingGrantId: 'wallet-session-fresh-1',
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'canonical-ecdsa-session-1',
            signingGrantId: 'wallet-session-fresh-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(capturedConnectArgs).not.toBeNull();
    const requestedSessionId = String(capturedConnectArgs?.['sessionId'] || '').trim();
    expect(requestedSessionId).toMatch(/^threshold-login-/);
    expect(requestedSessionId).not.toBe('canonical-ecdsa-session-1');
  });

  test('NEAR-only threshold warm-up does not bootstrap ECDSA sessions', async () => {
    let bootstrapCalls = 0;
    const context = createBaseContext({
      signingEngine: {
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('should not be called for NEAR-only warm-up');
        },
        listThresholdEcdsaSessionRecordsForWalletTarget: () => [],
      },
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
          chains: [],
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () => await unlock(context, ACCOUNT_ID),
      { includeThresholdEcdsaProfiles: false },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(bootstrapCalls).toBe(0);
  });

  test('Ed25519-only unlock selection carries Router A/B normal-signing state', async () => {
    const connectCalls: Array<Record<string, unknown>> = [];
    let bootstrapCalls = 0;
    const context = createBaseContext({
      configs: {
        signing: {
          routerAb: {
            normalSigning: {
              mode: 'enabled',
              signingWorkerId: 'signing-worker-local',
            },
          },
        },
      },
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          connectCalls.push(args);
          await persistReadyEd25519WarmRecord({
            sessionId: 'ed25519-only-session-1',
            signingGrantId: 'wallet-session-ed25519-only-1',
            walletSessionJwt: 'jwt-ed25519-only',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'ed25519-only-session-1',
            signingGrantId: 'wallet-session-ed25519-only-1',
            jwt: 'jwt-ed25519-only',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
          };
        },
        bootstrapEcdsaSession: async () => {
          bootstrapCalls += 1;
          throw new Error('ECDSA bootstrap should not run for Ed25519-only unlock');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ed25519_only', ed25519: true },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.success).toBe(true);
    expect(result.signingSession?.status).toBe('active');
    expect(connectCalls).toHaveLength(1);
    expect(connectCalls[0]?.routerAbNormalSigning).toEqual({
      kind: 'router_ab_ed25519_normal_signing_v1',
      signingWorkerId: 'signing-worker-local',
    });
    expect(bootstrapCalls).toBe(0);
  });

  test('ECDSA-only unlock selection warms ECDSA without connecting Ed25519', async () => {
    let credentialPrompts = 0;
    let connectCalls = 0;
    const bootstrapArgs: Record<string, unknown>[] = [];
    const walletOnlyUserData = {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
    };
    const loginCredential = {
      id: 'cred-ecdsa-only',
      rawId: 'cred-ecdsa-only',
      type: 'public-key',
      authenticatorAttachment: undefined,
      response: {
        clientDataJSON: 'client-data-json',
        authenticatorData: 'authenticator-data',
        signature: 'signature',
        userHandle: undefined,
        clientExtensionResults: {},
      },
      clientExtensionResults: {
        prf: {
          results: {
            first: ECDSA_PRF_FIRST_B64U,
          },
        },
      },
    };
    const context = createBaseContext({
      signingEngine: {
        getUserBySignerSlot: async () => walletOnlyUserData,
        getLastUser: async () => walletOnlyUserData,
        getAuthenticationCredentialsSerialized: async () => {
          credentialPrompts += 1;
          return loginCredential;
        },
        connectEd25519Session: async () => {
          connectCalls += 1;
          throw new Error('Ed25519 connect should not run for ECDSA-only unlock');
        },
        bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
          bootstrapArgs.push(args);
          const lanePolicy = bootstrapLanePolicy(args);
          const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: 'https://relay.example',
              keyHandle: bootstrapKeyHandle(args),
              ecdsaThresholdKeyId,
              signingRootId: 'proj_local:dev',
              signingRootVersion: 'default',
              backendBinding: {
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: String(lanePolicy.thresholdSessionId || 'session-ecdsa-only'),
              signingGrantId: String(lanePolicy.signingGrantId || ''),
              walletSessionJwt: 'jwt-ecdsa-only',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId,
              relayerKeyId: 'rk-1',
              clientVerifyingShareB64u: 'AQ',
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: String(lanePolicy.thresholdSessionId || 'session-ecdsa-only'),
              signingGrantId: String(lanePolicy.signingGrantId || ''),
              jwt: 'jwt-ecdsa-only',
              remainingUses: Number(lanePolicy.remainingUses || 0),
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: 'AQ',
            },
            passkeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
        }),
      { includeThresholdEcdsaProfiles: true },
    );

    expect(result.error || '').toBe('');
    expect(result.success).toBe(true);
    expect(result.operationalPublicKey).toBe(null);
    expect(result.signingSession?.status).toBe('active');
    expect(credentialPrompts).toBe(1);
    expect(connectCalls).toBe(0);
    expect(bootstrapArgs).toHaveLength(2);
    expect(
      bootstrapArgs.every(
        (args) =>
          args.kind === 'passkey_fresh_ecdsa_bootstrap' ||
          args.kind === 'wallet_session_reconnect_ecdsa_bootstrap',
      ),
    ).toBe(true);
    const signingGrantIds = bootstrapArgs.map((args) =>
      String(bootstrapLanePolicy(args).signingGrantId || ''),
    );
    expect(new Set(signingGrantIds).size).toBe(1);
    expect(
      signingGrantIds.every((signingGrantId) =>
        signingGrantId.startsWith('wallet-ecdsa-login-'),
      ),
    ).toBe(true);
    expect(bootstrapArgs.every((args) => args.passkeyPrfFirstB64u === ECDSA_PRF_FIRST_B64U)).toBe(
      true,
    );
    expect(bootstrapArgs.some((args) => args.webauthnAuthentication === loginCredential)).toBe(
      true,
    );
  });

  test('Ed25519 unlock selection requires a NEAR operational key', async () => {
    let connectCalls = 0;
    const walletOnlyUserData = {
      nearAccountId: 'alice.testnet',
      signerSlot: 1,
    };
    const context = createBaseContext({
      signingEngine: {
        getUserBySignerSlot: async () => walletOnlyUserData,
        getLastUser: async () => walletOnlyUserData,
        connectEd25519Session: async () => {
          connectCalls += 1;
          throw new Error('Ed25519 connect should not run without an operational key');
        },
      },
    });

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          unlockSelection: { mode: 'ed25519_only', ed25519: true },
        }),
      { includeThresholdEcdsaProfiles: false },
    );

    expect(result.success).toBe(false);
    expect(result.error || '').toContain('No NEAR operational key found');
    expect(connectCalls).toBe(0);
  });

  test('NEAR-only warm-up does not reuse a stored Ed25519 threshold session id', async () => {
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const context = createBaseContext({
      signingEngine: {
        connectEd25519Session: async (args: Record<string, unknown>) => {
          capturedConnectArgs = args;
          await persistReadyEd25519WarmRecord({
            sessionId: 'fresh-near-only-session-1',
            signingGrantId: 'wallet-session-near-only-1',
            walletSessionJwt: 'jwt-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
          });
          return {
            ok: true,
            sessionId: 'fresh-near-only-session-1',
            signingGrantId: 'wallet-session-near-only-1',
            jwt: 'jwt-ed25519',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
          };
        },
      },
      configs: {
        network: {
          relayer: { url: 'https://relay.example' },
          chains: [],
        },
      },
    });

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      walletId: ACCOUNT_ID,
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ACCOUNT_ID,
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId: 'stored-ed25519-session-1',
      walletSessionJwt: 'jwt-stale',
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
      source: 'manual-connect',
    });

    try {
      const result = await withMockedMostRecentProjection(
        async () => await unlock(context, ACCOUNT_ID),
        { includeThresholdEcdsaProfiles: false },
      );

      expect(result.success).toBe(true);
      expect(capturedConnectArgs).not.toBeNull();
      const requestedSessionId = String(capturedConnectArgs?.['sessionId'] || '').trim();
      expect(requestedSessionId).toMatch(/^threshold-login-/);
      expect(requestedSessionId).not.toBe('stored-ed25519-session-1');
    } finally {
      clearAllStoredThresholdEd25519SessionRecords();
    }
  });

  test('fails fast when /session/exchange route is requested without session.exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
            route: '/session/exchange',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('fails fast when server session is requested without exchange payload', async () => {
    const context = createBaseContext();

    const result = await withMockedMostRecentProjection(
      async () =>
        await unlock(context, ACCOUNT_ID, {
          session: {
            kind: 'jwt',
          },
        }),
    );

    expect(result.success).toBe(false);
    expect(String(result.error || '')).toContain('session.exchange is required');
  });

  test('supports one-step passkey_assertion session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-1',
              challengeB64u: 'challenge-passkey-b64u-1',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-1',
            rawId: 'cred-1',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-1');
      expect(captured).toHaveLength(2);
      expect(captured[0]!.url).toBe('https://relay.example/wallet/unlock/challenge');
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');

      const unlockOptionsBody = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      expect(unlockOptionsBody.unlockBackend).toBe('passkey');
      expect(unlockOptionsBody.userId).toBe('alice.testnet');
      expect(unlockOptionsBody.rpId).toBe('example.localhost');

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.challengeId).toBe('challenge-passkey-1');
      const credential = (exchange.webauthn_authentication || {}) as Record<string, unknown>;
      expect(credential.clientExtensionResults).toBeNull();
      expect(
        ((credential.response || {}) as Record<string, unknown>).clientExtensionResults,
      ).toBeNull();
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('passkey_assertion warm-up reuses app session authorization and local PRF credential', async () => {
    const originalFetch = globalThis.fetch;
    let credentialPrompts = 0;
    let capturedConnectArgs: Record<string, unknown> | null = null;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-warm',
              challengeB64u: 'challenge-passkey-warm-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-warm',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const loginCredential = {
        id: 'cred-warm',
        rawId: 'cred-warm',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: { shouldRedact: true },
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: ECDSA_PRF_FIRST_B64U,
            },
          },
        },
      };
      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => {
            credentialPrompts += 1;
            return loginCredential;
          },
          connectEd25519Session: async (args: Record<string, unknown>) => {
            capturedConnectArgs = args;
            await persistReadyEd25519WarmRecord({
              sessionId: 'session-passkey-warm',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ed25519',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
            });
            return {
              ok: true,
              sessionId: 'session-passkey-warm',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ed25519',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(credentialPrompts).toBe(1);
      expect(capturedConnectArgs).not.toBeNull();
      const connectArgs = capturedConnectArgs as Record<string, any> | null;
      expect(connectArgs?.auth).toMatchObject({
        kind: 'app_session_jwt',
        appSessionJwt: 'app-jwt-passkey-warm',
        localSecretSource: {
          kind: 'webauthn_prf_first_credential',
          credential: loginCredential,
          secretSource: {
            kind: 'webauthn_prf_first',
            prfFirstB64u: ECDSA_PRF_FIRST_B64U,
            rpId: 'example.localhost',
            credentialIdB64u: 'cred-warm',
          },
        },
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('uses app session JWT from OIDC exchange before existing-key ECDSA warm-up', async () => {
    const originalFetch = globalThis.fetch;
    let bootstrapCalls = 0;
    let bootstrapArgs: Record<string, unknown> | null = null;
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-oidc-1',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getAuthenticationCredentialsSerialized: async () => {
            throw new Error('OIDC unlock must not request a passkey assertion');
          },
          listThresholdEcdsaSessionRecordsForWalletTarget: (args: Record<string, unknown>) => [
            canonicalEcdsaRecord({
              chainTarget: args.chainTarget,
              ecdsaThresholdKeyId: ecdsaKeyIdForChainTarget(
                args.chainTarget as Record<string, unknown>,
              ),
              thresholdSessionId: 'canonical-ecdsa-session-1',
              signingGrantId: 'canonical-wallet-session-1',
            }),
          ],
          bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
            bootstrapCalls += 1;
            bootstrapArgs = args;
            const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                keyHandle: bootstrapKeyHandle(args),
                ecdsaThresholdKeyId,
                signingRootId: 'proj_local:dev',
                signingRootVersion: 'default',
                backendBinding: {
                  relayerKeyId: 'rk-1',
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: 'jwt',
                thresholdSessionId: 'session-1',
                signingGrantId: WALLET_SIGNING_SESSION_ID,
                walletSessionJwt: 'jwt-ecdsa',
              },
              keygen: {
                ok: true,
                ecdsaThresholdKeyId,
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: 'session-1',
                signingGrantId: WALLET_SIGNING_SESSION_ID,
                jwt: 'jwt-ecdsa',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                clientVerifyingShareB64u: 'AQ',
              },
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: {
                type: 'oidc_jwt',
                token: 'oidc-token-1',
              },
            },
            unlockSelection: { mode: 'ecdsa_only', ecdsa: true },
          }),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-oidc-1');
      expect(bootstrapCalls).toBe(2);
      const bootstrap = bootstrapArgs as Record<string, unknown> | null;
      const lanePolicy = bootstrapLanePolicy(bootstrap || {});
      expect(String(lanePolicy.thresholdSessionId || '')).toMatch(/^threshold-ecdsa-login-/);
      expect(String(lanePolicy.signingGrantId || '')).toMatch(/^wallet-ecdsa-login-/);
      expect(bootstrapEcdsaThresholdKeyId(bootstrap || {})).toBe(EVM_ECDSA_THRESHOLD_KEY_ID);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('forwards passkey_assertion expectedOrigin override to session exchange', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-2',
              challengeB64u: 'challenge-passkey-b64u-2',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
              jwt: 'app-jwt-passkey-2',
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-2',
            rawId: 'cred-2',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'jwt',
              exchange: {
                type: 'passkey_assertion',
                expectedOrigin: 'https://wallet.example.localhost',
              },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBe('app-jwt-passkey-2');
      expect(captured).toHaveLength(2);

      const exchangeBody = JSON.parse(String(captured[1]!.init?.body || '{}')) as Record<
        string,
        unknown
      >;
      const exchange = (exchangeBody.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.expected_origin).toBe('https://wallet.example.localhost');
      expect(captured[1]!.init?.credentials).toBe('omit');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('supports cookie-mode passkey_assertion exchange with include credentials', async () => {
    const originalFetch = globalThis.fetch;
    const captured: Array<{ url: string; init?: RequestInit }> = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        captured.push({ url, init });
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-cookie',
              challengeB64u: 'challenge-passkey-cookie-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => ({
            id: 'cred-cookie',
            rawId: 'cred-cookie',
            type: 'public-key',
            authenticatorAttachment: undefined,
            response: {
              clientDataJSON: 'client-data-json',
              authenticatorData: 'authenticator-data',
              signature: 'signature',
              userHandle: undefined,
              clientExtensionResults: { shouldRedact: true },
            },
            clientExtensionResults: {
              prf: {
                results: {
                  first: ECDSA_PRF_FIRST_B64U,
                  second: 'prf-second',
                },
              },
            },
          }),
        },
        configs: {
          signing: {
            sessionDefaults: { ttlMs: 0, remainingUses: 0 },
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
      );

      expect(result.success).toBe(true);
      expect(result.jwt).toBeUndefined();
      expect(captured).toHaveLength(2);
      expect(captured[1]!.url).toBe('https://relay.example/session/exchange');
      expect(captured[1]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('cookie-mode passkey_assertion warm-up uses cookie authorization for JWT Wallet Sessions', async () => {
    const originalFetch = globalThis.fetch;
    let capturedConnectArgs: Record<string, unknown> | null = null;
    const capturedBootstrapArgs: Record<string, unknown>[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url === 'https://relay.example/wallet/unlock/challenge') {
          return new Response(
            JSON.stringify({
              ok: true,
              challengeId: 'challenge-passkey-cookie-warm',
              challengeB64u: 'challenge-passkey-cookie-warm-b64u',
              expiresAtMs: Date.now() + 60_000,
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        if (url === 'https://relay.example/session/exchange') {
          return new Response(
            JSON.stringify({
              ok: true,
              session: { kind: 'app_session_v1', userId: 'alice.testnet' },
            }),
            { status: 200, headers: { 'Content-Type': 'application/json' } },
          );
        }
        return new Response(JSON.stringify({ ok: false, message: 'not found' }), {
          status: 404,
          headers: { 'Content-Type': 'application/json' },
        });
      }) as typeof fetch;

      const loginCredential = {
        id: 'cred-cookie-warm',
        rawId: 'cred-cookie-warm',
        type: 'public-key',
        authenticatorAttachment: undefined,
        response: {
          clientDataJSON: 'client-data-json',
          authenticatorData: 'authenticator-data',
          signature: 'signature',
          userHandle: undefined,
          clientExtensionResults: { shouldRedact: true },
        },
        clientExtensionResults: {
          prf: {
            results: {
              first: ECDSA_PRF_FIRST_B64U,
            },
          },
        },
      };
      const context = createBaseContext({
        signingEngine: {
          getRpId: () => 'example.localhost',
          getAuthenticationCredentialsSerialized: async () => loginCredential,
          connectEd25519Session: async (args: Record<string, unknown>) => {
            capturedConnectArgs = args;
            await persistReadyEd25519WarmRecord({
              sessionId: 'session-cookie-warm',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              walletSessionJwt: 'jwt-ed25519-cookie-authorized',
              expiresAtMs: Date.now() + 60_000,
              remainingUses: 3,
            });
            return {
              ok: true,
              sessionId: 'session-cookie-warm',
              signingGrantId: WALLET_SIGNING_SESSION_ID,
              jwt: 'jwt-ed25519-cookie-authorized',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              ecdsaHssPasskeyPrfFirstB64u: ECDSA_PRF_FIRST_B64U,
            };
          },
          bootstrapEcdsaSession: async (args: Record<string, unknown>) => {
            capturedBootstrapArgs.push(args);
            const lanePolicy = bootstrapLanePolicy(args);
            const ecdsaThresholdKeyId = bootstrapEcdsaThresholdKeyId(args);
            return {
              thresholdEcdsaKeyRef: {
                type: 'threshold-ecdsa-secp256k1',
                userId: 'alice.testnet',
                relayerUrl: 'https://relay.example',
                keyHandle: bootstrapKeyHandle(args),
                ecdsaThresholdKeyId,
                signingRootId: 'proj_local:dev',
                signingRootVersion: 'default',
                backendBinding: {
                  relayerKeyId: 'rk-1',
                  clientVerifyingShareB64u: 'AQ',
                },
                participantIds: [1, 2],
                thresholdSessionKind: String(lanePolicy.thresholdSessionKind || ''),
                thresholdSessionId: 'session-cookie-ecdsa',
                signingGrantId: WALLET_SIGNING_SESSION_ID,
              },
              keygen: {
                ok: true,
                ecdsaThresholdKeyId,
                relayerKeyId: 'rk-1',
                clientVerifyingShareB64u: 'AQ',
                participantIds: [1, 2],
              },
              session: {
                ok: true,
                sessionId: 'session-cookie-ecdsa',
                signingGrantId: WALLET_SIGNING_SESSION_ID,
                jwt: 'jwt-ecdsa-cookie-authorized',
                remainingUses: 3,
                expiresAtMs: Date.now() + 60_000,
                clientVerifyingShareB64u: 'AQ',
              },
            };
          },
        },
      });

      const result = await withMockedMostRecentProjection(
        async () =>
          await unlock(context, ACCOUNT_ID, {
            session: {
              kind: 'cookie',
              exchange: { type: 'passkey_assertion' },
            },
          }),
        { includeThresholdEcdsaProfiles: true },
      );

      expect(result.success).toBe(true);
      expect(capturedConnectArgs).not.toBeNull();
      const connectArgs = capturedConnectArgs as Record<string, any> | null;
      expect(connectArgs?.auth).toMatchObject({
        kind: 'app_session_cookie',
        localSecretSource: {
          kind: 'webauthn_prf_first_credential',
          credential: loginCredential,
          secretSource: {
            kind: 'webauthn_prf_first',
            prfFirstB64u: ECDSA_PRF_FIRST_B64U,
            rpId: 'example.localhost',
            credentialIdB64u: 'cred-cookie-warm',
          },
        },
      });
      expect(capturedBootstrapArgs).toHaveLength(2);
      expect(
        capturedBootstrapArgs.every(
          (args) => bootstrapLanePolicy(args).thresholdSessionKind === 'jwt',
        ),
      ).toBe(true);
      expect(
        capturedBootstrapArgs.every((args) => {
          return (
            args.routeAuth &&
            typeof args.routeAuth === 'object' &&
            (args.routeAuth as { kind?: unknown }).kind === 'wallet_session'
          );
        }),
      ).toBe(true);
      expect(capturedBootstrapArgs.every((args) => args.webauthnAuthentication === undefined)).toBe(
        true,
      );
      expect(
        capturedBootstrapArgs.every(
          (args) => args.passkeyPrfFirstB64u === ECDSA_PRF_FIRST_B64U,
        ),
      ).toBe(true);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
