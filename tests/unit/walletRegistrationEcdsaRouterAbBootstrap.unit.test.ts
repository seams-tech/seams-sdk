import { expect, test } from '@playwright/test';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseRouterAbEcdsaHssNormalSigningStateV1,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import type {
  EcdsaHssClientSharePublicKey33B64u,
  EcdsaRelayerHssPublicKey33B64u,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  parseWalletRegistrationEcdsaHssRespond,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { ThresholdEcdsaRoleLocalWorkerShareHandle } from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaHssRoleLocalBootstrapValue } from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEcdsaHssThresholdKeyId } from '@/core/signingEngine/session/identity/emailOtpHssIdentity';
import {
  clearAllThresholdEcdsaSessionRecords,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';

const WALLET_ID = 'router-ab-registration.testnet';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const KEY_HANDLE = 'router-ab-ecdsa-key';
const ECDSA_THRESHOLD_KEY_ID = 'ecdsa-threshold-key-1';
const RELAYER_KEY_ID = 'relayer-key-1';
const SIGNING_ROOT_ID = 'signing-root-1';
const SIGNING_ROOT_VERSION = 'signing-root-v1';
const THRESHOLD_SESSION_ID = 'threshold-ecdsa-session-1';
const WALLET_SIGNING_SESSION_ID = 'signing-grant-1';
const EXPIRES_AT_MS = 1_900_000_000_000;
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const NOW_MS = 1_800_000_000_000;
const CREDENTIAL_ID_B64U = 'credential-router-ab-registration';
const ROLE_LOCAL_SIGNING_MATERIAL_HANDLE = {
  kind: 'role_local_worker_session',
  materialHandle:
    'router-ab-ecdsa-role-local:threshold-ecdsa-session-1:router-ab-ecdsa-key:session-1',
  bindingDigest: b64u(15, 32),
} satisfies ThresholdEcdsaRoleLocalWorkerShareHandle;

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
};

function b64u(byte: number, length: number): string {
  return Buffer.from(new Uint8Array(length).fill(byte)).toString('base64url');
}

function publicKey33(prefix: number, byte: number): string {
  return Buffer.from(Uint8Array.from([prefix, ...new Uint8Array(32).fill(byte)])).toString(
    'base64url',
  );
}

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function jwtWithPayload(payload: Record<string, unknown>): string {
  return `${jsonB64u({ alg: 'none', typ: 'JWT' })}.${jsonB64u(payload)}.sig`;
}

const CONTEXT_BINDING_32_B64U = b64u(9, 32);
const READY_STATE_BLOB_32_B64U = b64u(10, 32);
const CLIENT_PUBLIC_KEY_33_B64U = publicKey33(2, 11) as EcdsaHssClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U = publicKey33(3, 12) as EcdsaRelayerHssPublicKey33B64u;
const GROUP_PUBLIC_KEY_33_B64U = publicKey33(2, 13);
const OWNER_ADDRESS_20_B64U = Buffer.from(OWNER_ADDRESS.slice(2), 'hex').toString('base64url');

function routerAbEcdsaHssNormalSigningState(): RouterAbEcdsaHssNormalSigningStateV1 {
  const state = parseRouterAbEcdsaHssNormalSigningStateV1({
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      context: {
        wallet_id: WALLET_ID,
        rp_id: RP_ID,
        key_scope: 'evm-family',
        ecdsa_threshold_key_id: ECDSA_THRESHOLD_KEY_ID,
        signing_root_id: SIGNING_ROOT_ID,
        signing_root_version: SIGNING_ROOT_VERSION,
        key_purpose: 'evm-signing',
        key_version: 'v1',
      },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_32_B64U,
        client_public_key33_b64u: CLIENT_PUBLIC_KEY_33_B64U,
        server_public_key33_b64u: RELAYER_PUBLIC_KEY_33_B64U,
        threshold_public_key33_b64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereum_address20_b64u: OWNER_ADDRESS_20_B64U,
        client_share_retry_counter: 0,
        server_share_retry_counter: 1,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: THRESHOLD_SESSION_ID,
    },
  });
  if (!state) throw new Error('Router A/B ECDSA-HSS normal signing fixture failed');
  return state;
}

function walletSessionJwt(
  args: {
    state?: RouterAbEcdsaHssNormalSigningStateV1;
    mode?: 'normal_signing' | 'missing_normal_signing' | 'issuer_binding_only';
  } = {},
): string {
  const payload: Record<string, unknown> = {
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    keyScope: 'evm-family',
    keyHandle: KEY_HANDLE,
    relayerKeyId: RELAYER_KEY_ID,
    rpId: RP_ID,
    thresholdExpiresAtMs: EXPIRES_AT_MS,
    participantIds: [1, 2],
  };
  if (args.mode === 'issuer_binding_only') {
    payload.routerAbEcdsaHssIssuerBinding = {
      stableKeyContext: {
        walletId: WALLET_ID,
        rpId: RP_ID,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        signingRootId: SIGNING_ROOT_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      },
      publicIdentity: {
        hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereumAddress: OWNER_ADDRESS,
      },
      signingWorkerId: 'signing-worker-1',
      activationEpoch: THRESHOLD_SESSION_ID,
    };
  } else if (args.mode !== 'missing_normal_signing') {
    payload.routerAbEcdsaHssNormalSigning = args.state || routerAbEcdsaHssNormalSigningState();
  }
  return jwtWithPayload(payload);
}

function clientBootstrap(): WalletRegistrationEcdsaClientBootstrap {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: WALLET_ID,
    rpId: RP_ID,
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    keyScope: 'evm-family',
    relayerKeyId: RELAYER_KEY_ID,
    requestId: 'registration-request-1',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    ttlMs: 300_000,
    remainingUses: 3,
    participantIds: [1, 2],
    hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
    clientShareRetryCounter: 0,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
  };
}

function serverBootstrap(
  args: {
    jwtMode?: 'normal_signing' | 'missing_normal_signing' | 'issuer_binding_only';
    state?: RouterAbEcdsaHssNormalSigningStateV1;
  } = {},
): ThresholdEcdsaHssRoleLocalBootstrapValue {
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: toWalletId(WALLET_ID),
    rpId: RP_ID,
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(ECDSA_THRESHOLD_KEY_ID),
    relayerKeyId: RELAYER_KEY_ID,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    publicIdentity: {
      hssClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
      relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
      groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
      ethereumAddress: OWNER_ADDRESS,
    },
    clientShareRetryCounter: 0,
    relayerShareRetryCounter: 1,
    publicTranscriptDigest32B64u: b64u(14, 32),
    keyHandle: KEY_HANDLE,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress: OWNER_ADDRESS,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    expiresAtMs: EXPIRES_AT_MS,
    expiresAt: new Date(EXPIRES_AT_MS).toISOString(),
    remainingUses: 3,
    jwt: walletSessionJwt({ mode: args.jwtMode, state: args.state }),
    routerAbEcdsaHssNormalSigning: args.state || routerAbEcdsaHssNormalSigningState(),
  };
}

function walletKey(): WalletRegistrationEcdsaWalletKey {
  return {
    keyScope: 'evm-family',
    chainTarget: EVM_TARGET,
    walletId: WALLET_ID,
    rpId: RP_ID,
    keyHandle: KEY_HANDLE,
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    thresholdEcdsaPublicKeyB64u: GROUP_PUBLIC_KEY_33_B64U,
    thresholdOwnerAddress: OWNER_ADDRESS,
    relayerKeyId: RELAYER_KEY_ID,
    relayerVerifyingShareB64u: RELAYER_PUBLIC_KEY_33_B64U,
    participantIds: [1, 2],
  };
}

function buildRegistrationBootstrap(
  args: {
    signingMaterialHandle?: ThresholdEcdsaRoleLocalWorkerShareHandle;
  } = {},
) {
  const parsed = parseWalletRegistrationEcdsaHssRespond({
    clientBootstrap: clientBootstrap(),
    serverBootstrap: serverBootstrap(),
  });
  return buildWalletRegistrationEcdsaSessionBootstrap({
    walletId: WALLET_ID,
    relayerUrl: RELAYER_URL,
    chainTarget: EVM_TARGET,
    keygenSessionId: 'registration-keygen-session-1',
    readyStateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: READY_STATE_BLOB_32_B64U,
    },
    signingMaterialHandle: args.signingMaterialHandle,
    clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_33_B64U,
    serverBootstrap: parsed,
    walletKey: walletKey(),
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: CREDENTIAL_ID_B64U,
    },
  });
}

function createEcdsaSessionStore(): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
    now: () => NOW_MS,
  };
}

test.describe('wallet registration Router A/B ECDSA bootstrap', () => {
  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords(createEcdsaSessionStore());
  });

  test('persists Router A/B JWT state into a ready ECDSA lane', async () => {
    const store = createEcdsaSessionStore();
    const bootstrap = buildRegistrationBootstrap();
    expect(bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaHssNormalSigning).toEqual(
      routerAbEcdsaHssNormalSigningState(),
    );

    upsertThresholdEcdsaSessionFromBootstrap(store, {
      walletId: toWalletId(WALLET_ID),
      chainTarget: EVM_TARGET,
      bootstrap,
      source: 'registration',
    });

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: store,
        statusReader: {
          getWarmSessionStatus: async () => ({
            ok: true,
            remainingUses: 3,
            expiresAtMs: EXPIRES_AT_MS,
          }),
        },
        getEmailOtpWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
      {
        walletId: WALLET_ID,
        authMethod: 'passkey',
        ecdsaChainTargets: [EVM_TARGET],
      },
    );

    expect(lanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(EVM_TARGET)]).toMatchObject({
      authMethod: 'passkey',
      curve: 'ecdsa',
      state: 'ready',
      source: 'runtime_session_record',
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId: WALLET_SIGNING_SESSION_ID,
      remainingUses: 3,
    });
  });

  test('uses worker-owned role-local material handles for signable registration key refs', () => {
    const bootstrap = buildRegistrationBootstrap({
      signingMaterialHandle: ROLE_LOCAL_SIGNING_MATERIAL_HANDLE,
    });
    const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
    if (binding?.materialKind !== 'role_local_worker_handle') {
      throw new Error('expected role-local worker handle backend binding');
    }
    expect(binding.roleLocalMaterialHandle).toEqual(ROLE_LOCAL_SIGNING_MATERIAL_HANDLE);
    expect(binding.stateBlob).toBeUndefined();
    expect(binding.clientVerifyingShareB64u).toBe(CLIENT_PUBLIC_KEY_33_B64U);
    expect(binding.ecdsaRoleLocalReadyRecord.stateBlob.stateBlobB64u).toBe(
      READY_STATE_BLOB_32_B64U,
    );
  });

  test('rejects a Wallet Session JWT missing Router A/B ECDSA normal-signing state', () => {
    expect(() =>
      parseWalletRegistrationEcdsaHssRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: serverBootstrap({ jwtMode: 'missing_normal_signing' }),
      }),
    ).toThrow(/missing routerAbEcdsaHssNormalSigning/);
  });

  test('rejects issuer-binding-only Wallet Session JWTs for signable registration', () => {
    expect(() =>
      parseWalletRegistrationEcdsaHssRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: serverBootstrap({ jwtMode: 'issuer_binding_only' }),
      }),
    ).toThrow(/issuer-binding-only/);
  });

  test('keeps persisted ECDSA runtime records without Router A/B state invisible', async () => {
    const store = createEcdsaSessionStore();
    const bootstrap = buildRegistrationBootstrap();
    const { routerAbEcdsaHssNormalSigning, ...keyRefWithoutRouterAb } =
      bootstrap.thresholdEcdsaKeyRef;
    void routerAbEcdsaHssNormalSigning;
    upsertThresholdEcdsaSessionFromBootstrap(store, {
      walletId: toWalletId(WALLET_ID),
      chainTarget: EVM_TARGET,
      bootstrap: {
        ...bootstrap,
        thresholdEcdsaKeyRef: keyRefWithoutRouterAb,
      },
      source: 'registration',
    });
    let passkeyStatusReads = 0;

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: store,
        statusReader: {
          getWarmSessionStatus: async () => {
            passkeyStatusReads += 1;
            return { ok: true, remainingUses: 3, expiresAtMs: EXPIRES_AT_MS };
          },
        },
        getEmailOtpWarmSessionStatus: async () => ({
          ok: false,
          code: 'not_found',
          message: 'missing',
        }),
      },
      {
        walletId: WALLET_ID,
        authMethod: 'passkey',
        ecdsaChainTargets: [EVM_TARGET],
      },
    );

    expect(passkeyStatusReads).toBe(0);
    expect(lanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(EVM_TARGET)]).toMatchObject({
      curve: 'ecdsa',
      state: 'missing',
    });
  });
});
