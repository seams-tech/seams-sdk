import { expect, test } from '@playwright/test';
import { ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import {
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  parseRouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type {
  DerivationClientSharePublicKey33B64u,
  EcdsaRelayerDerivationPublicKey33B64u,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import {
  buildWalletRegistrationEcdsaSessionBootstrap,
  parseWalletRegistrationEcdsaDerivationRespond,
  type WalletRegistrationEcdsaClientBootstrap,
  type WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import type { ThresholdEcdsaDerivationRoleLocalBootstrapValue } from '@/core/rpcClients/relayer/thresholdEcdsa';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toEcdsaDerivationThresholdKeyId } from '@/core/signingEngine/session/identity/emailOtpEcdsaDerivationIdentity';
import {
  clearAllThresholdEcdsaSessionRecords,
  getInMemoryEcdsaRoleLocalHandle,
  listThresholdEcdsaRuntimeLanesForWallet,
  parseRawThresholdEcdsaSessionRecord,
  upsertThresholdEcdsaSessionFromBootstrap,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import {
  buildEcdsaRoleLocalPublicFacts,
  thresholdEcdsaRecordHasRoleLocalSigningMaterial,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import {
  clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation,
  markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import { buildThresholdEcdsaSecp256k1KeyRefFromRecord } from '@/core/signingEngine/session/identity/thresholdEcdsaSignerAdapter';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalMaterialHandle,
  type EcdsaRoleLocalWorkerHandle,
} from '@/core/signingEngine/session/keyMaterialBrands';

const WALLET_ID = 'router-ab-registration.testnet';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const KEY_HANDLE = 'router-ab-ecdsa-key';
const ECDSA_THRESHOLD_KEY_ID = 'ecdsa-threshold-key-1';
const RELAYER_KEY_ID = 'relayer-key-1';
const SIGNING_ROOT_ID = 'project-registration:local';
const SIGNING_ROOT_VERSION = 'signing-root-v1';
const THRESHOLD_SESSION_ID = 'threshold-ecdsa-session-1';
const ACTIVATION_EPOCH = 'root-share-epoch-1';
const WALLET_SIGNING_SESSION_ID = 'signing-grant-1';
const EXPIRES_AT_MS = 1_900_000_000_000;
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const NOW_MS = 1_800_000_000_000;
const CREDENTIAL_ID_B64U = 'credential-router-ab-registration';
const APPLICATION_BINDING_DIGEST_B64U = '_GFCif_z_CIBtKY-QsAe-qAvAdMeemgOPJSAQGMOnb8';
const CONTEXT_BINDING_32_B64U = 'OyVzuOm6z7oD9lROMqtIK1MZuxTy-l6AMUji9knVQ6w';
const ROLE_LOCAL_MATERIAL_HANDLE =
  'router-ab-ecdsa-role-local:threshold-ecdsa-session-1:router-ab-ecdsa-key:session-1:fixture-binding';
const ROLE_LOCAL_SIGNING_MATERIAL_HANDLE = {
  kind: 'ecdsa_role_local_worker_handle_v1',
  materialHandle: parseEcdsaRoleLocalMaterialHandle(ROLE_LOCAL_MATERIAL_HANDLE),
  bindingDigest: parseEcdsaRoleLocalBindingDigest(CONTEXT_BINDING_32_B64U),
  durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(ROLE_LOCAL_MATERIAL_HANDLE),
} satisfies EcdsaRoleLocalWorkerHandle;

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

const CLIENT_PUBLIC_KEY_33_B64U = publicKey33(2, 11) as DerivationClientSharePublicKey33B64u;
const RELAYER_PUBLIC_KEY_33_B64U = publicKey33(3, 12) as EcdsaRelayerDerivationPublicKey33B64u;
const GROUP_PUBLIC_KEY_33_B64U = publicKey33(2, 13);
const OWNER_ADDRESS_20_B64U = Buffer.from(OWNER_ADDRESS.slice(2), 'hex').toString('base64url');
const EVM_FAMILY_SIGNING_KEY_SLOT_ID = `wallet-key:evm-family:${WALLET_ID}:${encodeURIComponent(SIGNING_ROOT_ID)}:${SIGNING_ROOT_VERSION}`;
const SIGNING_WORKER_RECIPIENT_KEY =
  'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

function routerAbEcdsaDerivationNormalSigningState(): RouterAbEcdsaDerivationNormalSigningStateV1 {
  const state = parseRouterAbEcdsaDerivationNormalSigningStateV1({
    kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
    scope: {
      wallet_key_id: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
      wallet_id: WALLET_ID,
      ecdsa_threshold_key_id: ECDSA_THRESHOLD_KEY_ID,
      signing_root_id: SIGNING_ROOT_ID,
      signing_root_version: SIGNING_ROOT_VERSION,
      context: {
        application_binding_digest_b64u: APPLICATION_BINDING_DIGEST_B64U,
      },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_32_B64U,
        derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_33_B64U,
        server_public_key33_b64u: RELAYER_PUBLIC_KEY_33_B64U,
        threshold_public_key33_b64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereum_address20_b64u: OWNER_ADDRESS_20_B64U,
        client_share_retry_counter: 0,
        server_share_retry_counter: 1,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key: SIGNING_WORKER_RECIPIENT_KEY,
      },
      activation_epoch: ACTIVATION_EPOCH,
    },
  });
  if (!state) throw new Error('Router A/B ECDSA derivation normal signing fixture failed');
  return state;
}

function publicCapability() {
  return parseRouterAbEcdsaDerivationPublicCapabilityV1({
    kind: 'router_ab_ecdsa_derivation_public_capability_v1',
    context: {
      application_binding_digest_b64u: APPLICATION_BINDING_DIGEST_B64U,
    },
    public_identity: {
      context_binding_b64u: CONTEXT_BINDING_32_B64U,
      derivation_client_share_public_key33_b64u: CLIENT_PUBLIC_KEY_33_B64U,
      server_public_key33_b64u: RELAYER_PUBLIC_KEY_33_B64U,
      threshold_public_key33_b64u: GROUP_PUBLIC_KEY_33_B64U,
      ethereum_address20_b64u: OWNER_ADDRESS_20_B64U,
      client_share_retry_counter: 0,
      server_share_retry_counter: 1,
    },
    signer_set: {
      signer_set_id: 'signer-set-v1',
      policy: 'all_2',
      signer_a: {
        role: 'signer_a',
        signer_id: 'signer-a',
        key_epoch: 'epoch-1',
      },
      signer_b: {
        role: 'signer_b',
        signer_id: 'signer-b',
        key_epoch: 'epoch-1',
      },
      selected_server: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key: SIGNING_WORKER_RECIPIENT_KEY,
      },
    },
    deriver_recipient_keys: {
      deriver_a: {
        role: 'signer_a',
        key_epoch: 'epoch-1',
        public_key: 'x25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      },
      deriver_b: {
        role: 'signer_b',
        key_epoch: 'epoch-1',
        public_key: 'x25519:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
      },
    },
    router_id: 'router-1',
    client_id: WALLET_ID,
    activation_epoch: ACTIVATION_EPOCH,
    registration_request_digest_b64u: b64u(16, 32),
    proof_transcript_digest_b64u: b64u(17, 32),
  });
}

function walletSessionJwt(
  args: {
    state?: RouterAbEcdsaDerivationNormalSigningStateV1;
    mode?: 'normal_signing' | 'missing_normal_signing' | 'issuer_binding_only';
  } = {},
): string {
  const payload: Record<string, unknown> = {
    kind: ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    keyScope: 'evm-family',
    keyHandle: KEY_HANDLE,
    relayerKeyId: RELAYER_KEY_ID,
    rpId: RP_ID,
    thresholdExpiresAtMs: EXPIRES_AT_MS,
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org-registration',
      projectId: 'project-registration',
      envId: 'local',
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
  };
  if (args.mode === 'issuer_binding_only') {
    payload.routerAbEcdsaDerivationIssuerBinding = {
      stableKeyContext: {
        applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
        contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      },
      publicIdentity: {
        derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
        relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
        groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
        ethereumAddress: OWNER_ADDRESS,
      },
      signingWorkerId: 'signing-worker-1',
      activationEpoch: ACTIVATION_EPOCH,
    };
  } else if (args.mode !== 'missing_normal_signing') {
    payload.routerAbEcdsaDerivationNormalSigning =
      args.state || routerAbEcdsaDerivationNormalSigningState();
  }
  return jwtWithPayload(payload);
}

function clientBootstrap(): WalletRegistrationEcdsaClientBootstrap {
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
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
    derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
    clientShareRetryCounter: 0,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
  };
}

function serverBootstrap(
  args: {
    jwtMode?: 'normal_signing' | 'missing_normal_signing' | 'issuer_binding_only';
    state?: RouterAbEcdsaDerivationNormalSigningStateV1;
  } = {},
): ThresholdEcdsaDerivationRoleLocalBootstrapValue {
  return {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: toWalletId(WALLET_ID),
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(ECDSA_THRESHOLD_KEY_ID),
    relayerKeyId: RELAYER_KEY_ID,
    applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    publicIdentity: {
      derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
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
    activationEpoch: ACTIVATION_EPOCH,
    signingGrantId: WALLET_SIGNING_SESSION_ID,
    expiresAtMs: EXPIRES_AT_MS,
    expiresAt: new Date(EXPIRES_AT_MS).toISOString(),
    remainingUses: 3,
    jwt: walletSessionJwt({ mode: args.jwtMode, state: args.state }),
    routerAbEcdsaDerivationNormalSigning: args.state || routerAbEcdsaDerivationNormalSigningState(),
  };
}

function walletKey(): WalletRegistrationEcdsaWalletKey {
  return {
    keyScope: 'evm-family',
    chainTarget: EVM_TARGET,
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
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

async function buildRegistrationBootstrap() {
  const parsed = parseWalletRegistrationEcdsaDerivationRespond({
    clientBootstrap: clientBootstrap(),
    serverBootstrap: serverBootstrap(),
    activationEpoch: ACTIVATION_EPOCH,
  });
  const capability = publicCapability();
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    chainTarget: EVM_TARGET,
    keyHandle: KEY_HANDLE,
    ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    applicationBindingDigestB64u: APPLICATION_BINDING_DIGEST_B64U,
    participantIds: [1, 2],
    clientParticipantId: 1,
    relayerParticipantId: 2,
    contextBinding32B64u: CONTEXT_BINDING_32_B64U,
    derivationClientSharePublicKey33B64u: CLIENT_PUBLIC_KEY_33_B64U,
    relayerPublicKey33B64u: RELAYER_PUBLIC_KEY_33_B64U,
    groupPublicKey33B64u: GROUP_PUBLIC_KEY_33_B64U,
    ethereumAddress: OWNER_ADDRESS,
    publicCapability: capability,
  });
  return await buildWalletRegistrationEcdsaSessionBootstrap({
    walletId: WALLET_ID,
    relayerUrl: RELAYER_URL,
    chainTarget: EVM_TARGET,
    keygenSessionId: 'registration-keygen-session-1',
    clientVerifyingShareB64u: CLIENT_PUBLIC_KEY_33_B64U,
    serverBootstrap: parsed,
    walletKey: walletKey(),
    publicCapability: capability,
    authMethod: {
      kind: 'passkey',
      credentialIdB64u: CREDENTIAL_ID_B64U,
      rpId: RP_ID,
    },
    material: {
      kind: 'worker_handle',
      handle: ROLE_LOCAL_SIGNING_MATERIAL_HANDLE,
      publicFacts,
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

async function buildRawPersistedRegistrationRecord(): Promise<Record<string, unknown>> {
  const store = createEcdsaSessionStore();
  const bootstrap = await buildRegistrationBootstrap();
  const record = upsertThresholdEcdsaSessionFromBootstrap(store, {
    walletId: toWalletId(WALLET_ID),
    chainTarget: EVM_TARGET,
    bootstrap,
    source: 'registration',
  });
  return structuredClone(record) as unknown as Record<string, unknown>;
}

function requireRawRecordField(
  record: Record<string, unknown>,
  field: string,
): Record<string, unknown> {
  const value = record[field];
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`expected ${field} to be an object`);
  }
  return value as Record<string, unknown>;
}

test.describe('wallet registration Router A/B ECDSA bootstrap', () => {
  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords(createEcdsaSessionStore());
    clearRouterAbEcdsaDerivationWorkerMaterialRuntimeValidation();
  });

  test('persists worker-owned registration material as a restorable ECDSA lane', async () => {
    const store = createEcdsaSessionStore();
    const bootstrap = await buildRegistrationBootstrap();
    expect(bootstrap.thresholdEcdsaKeyRef.routerAbEcdsaDerivationNormalSigning).toEqual(
      routerAbEcdsaDerivationNormalSigningState(),
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
            ok: false,
            code: 'not_found',
            message: 'missing',
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

    expect(lanes.diagnostics?.invalidLanes).toEqual([]);
    expect(lanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(EVM_TARGET)]).toMatchObject({
      curve: 'ecdsa',
      state: 'restorable',
    });
  });

  test('uses worker-owned role-local material handles for signable registration key refs', async () => {
    const bootstrap = await buildRegistrationBootstrap();
    const binding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
    if (binding?.materialKind !== 'role_local_worker_handle') {
      throw new Error('expected role-local worker handle backend binding');
    }
    expect(binding.roleLocalMaterialHandle).toEqual(ROLE_LOCAL_SIGNING_MATERIAL_HANDLE);
    expect(binding.stateBlob).toBeUndefined();
    expect(binding.clientVerifyingShareB64u).toBe(CLIENT_PUBLIC_KEY_33_B64U);
    expect(binding.ecdsaRoleLocalReadyRecord).toBeUndefined();
  });

  test('keeps volatile worker handles out of the durable session store', async () => {
    const store = createEcdsaSessionStore();
    const bootstrap = await buildRegistrationBootstrap();

    const runtimeRecord = upsertThresholdEcdsaSessionFromBootstrap(store, {
      walletId: toWalletId(WALLET_ID),
      chainTarget: EVM_TARGET,
      bootstrap,
      source: 'registration',
    });
    const durableRecord = Array.from(store.recordsByLane.values())[0];

    expect(getInMemoryEcdsaRoleLocalHandle(runtimeRecord)).toEqual(
      ROLE_LOCAL_SIGNING_MATERIAL_HANDLE,
    );
    expect(durableRecord).not.toHaveProperty('roleLocalMaterialHandle');
    expect(durableRecord?.roleLocalDurableMaterialRef).toBe(
      ROLE_LOCAL_SIGNING_MATERIAL_HANDLE.durableMaterialRef,
    );
    if (!durableRecord) throw new Error('expected durable threshold ECDSA session record');
    expect(thresholdEcdsaRecordHasRoleLocalSigningMaterial(runtimeRecord)).toBe(true);
    expect(thresholdEcdsaRecordHasRoleLocalSigningMaterial(durableRecord)).toBe(true);
    const reloadedDurableRecord = parseRawThresholdEcdsaSessionRecord(
      structuredClone(durableRecord),
    );
    expect(getInMemoryEcdsaRoleLocalHandle(reloadedDurableRecord)).toEqual(
      ROLE_LOCAL_SIGNING_MATERIAL_HANDLE,
    );
    const durableKeyRef = buildThresholdEcdsaSecp256k1KeyRefFromRecord({
      record: reloadedDurableRecord,
    });
    expect(durableKeyRef.backendBinding).toMatchObject({
      materialKind: 'role_local_worker_handle',
      roleLocalMaterialHandle: ROLE_LOCAL_SIGNING_MATERIAL_HANDLE,
    });
    const [runtimeLane] = listThresholdEcdsaRuntimeLanesForWallet(store, WALLET_ID);
    expect(runtimeLane).toBeDefined();
    expect(markRouterAbEcdsaDerivationWorkerMaterialRuntimeValidated(runtimeRecord)).toBe(true);
    const available = await readPersistedAvailableSigningLanesForTargets(
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
    expect(available.diagnostics?.invalidLanes).toEqual([]);
    expect(
      available.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(EVM_TARGET)],
    ).toMatchObject([{ state: 'ready', source: 'runtime_session_record' }]);
  });

  test('rejects role-local public facts bound to another wallet', async () => {
    const rawRecord = await buildRawPersistedRegistrationRecord();
    const publicFacts = requireRawRecordField(rawRecord, 'ecdsaRoleLocalPublicFacts');
    publicFacts.walletId = 'substituted-wallet.testnet';

    expect(() => parseRawThresholdEcdsaSessionRecord(rawRecord)).toThrow(
      /role-local publicFacts walletId mismatch/,
    );
  });

  test('rejects an embedded public capability bound to different public facts', async () => {
    const rawRecord = await buildRawPersistedRegistrationRecord();
    const publicFacts = requireRawRecordField(rawRecord, 'ecdsaRoleLocalPublicFacts');
    const publicCapability = requireRawRecordField(publicFacts, 'publicCapability');
    const capabilityContext = requireRawRecordField(publicCapability, 'context');
    capabilityContext.application_binding_digest_b64u = b64u(99, 32);

    expect(() => parseRawThresholdEcdsaSessionRecord(rawRecord)).toThrow(
      /publicCapability\.context\.application_binding_digest_b64u mismatch/,
    );
  });

  test('rejects an embedded public capability bound to another wallet', async () => {
    const rawRecord = await buildRawPersistedRegistrationRecord();
    const publicFacts = requireRawRecordField(rawRecord, 'ecdsaRoleLocalPublicFacts');
    const publicCapability = requireRawRecordField(publicFacts, 'publicCapability');
    publicCapability.client_id = 'substituted-wallet.testnet';

    expect(() => parseRawThresholdEcdsaSessionRecord(rawRecord)).toThrow(
      /publicCapability\.client_id mismatch/,
    );
  });

  test('rejects normal-signing state bound to different role-local public facts', async () => {
    const rawRecord = await buildRawPersistedRegistrationRecord();
    const normalSigning = requireRawRecordField(rawRecord, 'routerAbEcdsaDerivationNormalSigning');
    const scope = requireRawRecordField(normalSigning, 'scope');
    const publicIdentity = requireRawRecordField(scope, 'public_identity');
    publicIdentity.context_binding_b64u = b64u(98, 32);

    expect(() => parseRawThresholdEcdsaSessionRecord(rawRecord)).toThrow(
      /normalSigning\.public_identity\.context_binding_b64u mismatch/,
    );
  });

  test('rejects an Email OTP auth method substituted into a passkey record', async () => {
    const rawRecord = await buildRawPersistedRegistrationRecord();
    rawRecord.ecdsaRoleLocalAuthMethod = {
      kind: 'email_otp',
      authSubjectId: 'google:substituted-subject',
    };

    expect(() => parseRawThresholdEcdsaSessionRecord(rawRecord)).toThrow(
      /passkey source requires passkey auth/,
    );
  });

  test('rejects a Wallet Session JWT missing Router A/B ECDSA normal-signing state', () => {
    expect(() =>
      parseWalletRegistrationEcdsaDerivationRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: serverBootstrap({ jwtMode: 'missing_normal_signing' }),
        activationEpoch: ACTIVATION_EPOCH,
      }),
    ).toThrow(/missing routerAbEcdsaDerivationNormalSigning/);
  });

  test('rejects issuer-binding-only Wallet Session JWTs for signable registration', () => {
    expect(() =>
      parseWalletRegistrationEcdsaDerivationRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: serverBootstrap({ jwtMode: 'issuer_binding_only' }),
        activationEpoch: ACTIVATION_EPOCH,
      }),
    ).toThrow(/issuer-binding-only/);
  });

  test('rejects a server signing grant that differs from the prepared client bootstrap', () => {
    const substituted = serverBootstrap();
    substituted.signingGrantId = 'substituted-signing-grant';
    expect(() =>
      parseWalletRegistrationEcdsaDerivationRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: substituted,
        activationEpoch: ACTIVATION_EPOCH,
      }),
    ).toThrow(/signingGrantId mismatch/);
  });

  test('rejects a server use count that differs from the prepared client bootstrap', () => {
    const substituted = serverBootstrap();
    substituted.remainingUses = 9;
    expect(() =>
      parseWalletRegistrationEcdsaDerivationRespond({
        clientBootstrap: clientBootstrap(),
        serverBootstrap: substituted,
        activationEpoch: ACTIVATION_EPOCH,
      }),
    ).toThrow(/remainingUses mismatch/);
  });

  test('keeps persisted ECDSA runtime records without Router A/B state invisible', async () => {
    const store = createEcdsaSessionStore();
    const bootstrap = await buildRegistrationBootstrap();
    const { routerAbEcdsaDerivationNormalSigning, ...keyRefWithoutRouterAb } =
      bootstrap.thresholdEcdsaKeyRef;
    void routerAbEcdsaDerivationNormalSigning;
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
