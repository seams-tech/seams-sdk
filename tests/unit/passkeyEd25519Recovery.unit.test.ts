import { expect, test } from '@playwright/test';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  upsertThresholdEd25519SessionFact,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  reconnectPasskeyEd25519CapabilityForSigning,
  restorePasskeyEd25519SealedRecordForAccount,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';
import {
  normalizeSealedRecoveryRecord,
  type PasskeyEd25519SealedRecoveryRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord';

const ACCOUNT_ID = 'ed25519-reconnect-race.testnet';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'ed25519:relayer-key';
const PARTICIPANT_IDS = [1, 2, 3];
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-ed25519-reconnect',
  projectId: 'project-ed25519-reconnect',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'local-signing-worker',
} as const;
const TEST_WEBAUTHN_CREDENTIAL = {
  id: 'credential-id',
  rawId: 'credential-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: Buffer.alloc(32, 7).toString('base64url'),
        second: undefined,
      },
    },
  },
};

function writeEd25519Record(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
  withWorkerMaterial?: boolean;
  withStorageRefOnlyWorkerMaterial?: boolean;
  signingWorkerId?: string;
}) {
  const workerMaterialFields = args.withWorkerMaterial
    ? {
        clientVerifyingShareB64u: 'client-verifier-reconnect',
        ed25519WorkerMaterialHandle: 'runtime-handle-reconnect',
        ed25519WorkerMaterialBindingDigest: 'material-binding-reconnect',
        sealedWorkerMaterialRef: 'sealed-ref-reconnect',
        sealedWorkerMaterialB64u: 'sealed-blob-reconnect',
        materialFormatVersion: 'ed25519_sealed_worker_material_v1',
        materialKeyId: 'material-key-reconnect',
        materialCreatedAtMs: 1_800_000_100_000,
      }
    : args.withStorageRefOnlyWorkerMaterial
      ? {
          clientVerifyingShareB64u: 'client-verifier-reconnect',
          ed25519WorkerMaterialBindingDigest: 'material-binding-reconnect',
          sealedWorkerMaterialRef: 'sealed-ref-reconnect',
          materialFormatVersion: 'ed25519_sealed_worker_material_v1',
          materialKeyId: 'material-key-reconnect',
          materialCreatedAtMs: 1_800_000_100_000,
        }
      : {};
  const record = upsertThresholdEd25519SessionFact({
    walletId: ACCOUNT_ID,
    nearAccountId: ACCOUNT_ID,
    nearEd25519SigningKeyId: ACCOUNT_ID,
    rpId: RP_ID,
    passkeyCredentialIdB64u: 'credential-id-b64u',
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: PARTICIPANT_IDS,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: {
      ...ROUTER_AB_NORMAL_SIGNING,
      signingWorkerId: args.signingWorkerId || ROUTER_AB_NORMAL_SIGNING.signingWorkerId,
    },
    signerSlot: 1,
    ...workerMaterialFields,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: `jwt:${args.thresholdSessionId}`,
    expiresAtMs: Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 1,
    source: 'login',
  });
  if (!record) throw new Error('expected Ed25519 test record');
  return record;
}

function makePasskeyEd25519SealedRecord(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
}): PasskeyEd25519SealedRecoveryRecord {
  const now = Date.now();
  const normalized = normalizeSealedRecoveryRecord({
    v: 1,
    alg: 'shamir3pass-v1',
    storageScope: 'iframe_origin_indexeddb',
    authMethod: 'passkey',
    secretKind: 'signing_session_secret32',
    storeKey: `passkey:ed25519:near:${args.thresholdSessionId}`,
    signingGrantId: args.signingGrantId,
    thresholdSessionIds: {
      ed25519: args.thresholdSessionId,
    },
    sealedSecretB64u: 'sealed-secret-ed25519',
    curve: 'ed25519',
    walletId: ACCOUNT_ID,
    relayerUrl: RELAYER_URL,
    shamirPrimeB64u: 'prime-b64u',
    keyVersion: 'signing-session-seal-kek-test-r1',
    ed25519Restore: {
      nearAccountId: ACCOUNT_ID,
      nearEd25519SigningKeyId: ACCOUNT_ID,
      rpId: RP_ID,
      credentialIdB64u: 'credential-id-b64u',
      relayerKeyId: RELAYER_KEY_ID,
      participantIds: PARTICIPANT_IDS,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      signerSlot: 1,
      sessionKind: 'jwt',
      walletSessionJwt: `jwt:${args.thresholdSessionId}`,
      clientVerifyingShareB64u: 'client-verifier-sealed',
      ed25519WorkerMaterialBindingDigest: 'material-binding-sealed',
      sealedWorkerMaterialRef: 'sealed-ref-sealed',
      sealedWorkerMaterialB64u: 'sealed-worker-material',
      materialFormatVersion: 'ed25519_sealed_worker_material_v1',
      materialKeyId: 'material-key-sealed',
      materialCreatedAtMs: 1_800_000_200_000,
      routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    },
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 60_000,
    remainingUses: args.remainingUses ?? 3,
    updatedAtMs: now,
  });
  if (
    normalized.kind !== 'accepted' ||
    normalized.record.authMethod !== 'passkey' ||
    normalized.record.curve !== 'ed25519'
  ) {
    throw new Error('expected passkey Ed25519 sealed recovery record');
  }
  return normalized.record;
}

test.describe('passkey Ed25519 reconnect recovery', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('retains exact Ed25519 lane records when another account record becomes current', () => {
    const planned = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-planned',
      signingGrantId: 'wsess-ed25519-planned',
    });
    const competing = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-competing',
      signingGrantId: 'wsess-ed25519-competing',
    });

    expect(getStoredThresholdEd25519SessionRecordForAccount(ACCOUNT_ID)?.thresholdSessionId).toBe(
      competing.thresholdSessionId,
    );
    expect(
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(planned.thresholdSessionId)
        ?.signingGrantId,
    ).toBe(planned.signingGrantId);
  });

  test('keeps exhausted sealed restore as an exact passkey reauth anchor', async () => {
    const thresholdSessionId = 'tsess-ed25519-exhausted-sealed';
    const signingGrantId = 'wsess-ed25519-exhausted-sealed';
    const sealedRecord = makePasskeyEd25519SealedRecord({
      thresholdSessionId,
      signingGrantId,
      remainingUses: 3,
    });
    const restoredStatuses: unknown[] = [];
    let deleteCalls = 0;

    const result = await restorePasskeyEd25519SealedRecordForAccount({
      walletId: ACCOUNT_ID,
      record: sealedRecord,
      purpose: {
        walletId: ACCOUNT_ID,
        authMethod: 'passkey',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId,
        thresholdSessionId,
        reason: 'transaction',
      },
      transport: {
        curve: 'ed25519',
        authMethod: 'passkey',
        walletId: ACCOUNT_ID,
        relayerUrl: RELAYER_URL,
        signingGrantId,
        walletSessionJwt: `jwt:${thresholdSessionId}`,
        signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
        shamirPrimeB64u: 'prime-b64u',
      },
      shamirPrimeB64u: 'prime-b64u',
      rehydrateWarmSessionMaterial: async () => ({
        ok: false,
        code: 'exhausted',
        message: 'signing grant exhausted',
      }),
      deletePersistedRecord: async () => {
        deleteCalls += 1;
      },
      recordSessionMaterialRestored: async (status) => {
        restoredStatuses.push(status);
      },
      readWarmSessionStatusFromWorker: async () => {
        throw new Error('exhausted restore should stop before worker status readback');
      },
      updatePersistedPolicy: async () => {
        throw new Error('exhausted restore policy is recorded by UiConfirm durable policy');
      },
    });

    expect(result).toEqual({
      ok: false,
      code: 'exhausted',
      message: 'signing grant exhausted',
    });
    expect(deleteCalls).toBe(0);
    expect(restoredStatuses).toEqual([result]);
    const restoredRecord =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    expect(restoredRecord).toMatchObject({
      thresholdSessionId,
      signingGrantId,
      materialState: 'restore_available',
      remainingUses: 0,
      source: 'login',
    });
  });

  test('does not downgrade current runtime material when publishing a matching sealed record', async () => {
    const thresholdSessionId = 'tsess-ed25519-current-material';
    const signingGrantId = 'wsess-ed25519-current-material';
    const currentRecord = writeEd25519Record({
      thresholdSessionId,
      signingGrantId,
      remainingUses: 3,
      withWorkerMaterial: true,
    });
    expect(currentRecord.materialState).toBe('material_ready');
    const sealedRecord = makePasskeyEd25519SealedRecord({
      thresholdSessionId,
      signingGrantId,
      remainingUses: 3,
    });
    const restoredStatuses: unknown[] = [];
    const expiresAtMs = Date.now() + 60_000;

    const result = await restorePasskeyEd25519SealedRecordForAccount({
      walletId: ACCOUNT_ID,
      record: sealedRecord,
      purpose: {
        walletId: ACCOUNT_ID,
        authMethod: 'passkey',
        curve: 'ed25519',
        chain: 'near',
        signingGrantId,
        thresholdSessionId,
        reason: 'transaction',
      },
      transport: {
        curve: 'ed25519',
        authMethod: 'passkey',
        walletId: ACCOUNT_ID,
        relayerUrl: RELAYER_URL,
        signingGrantId,
        walletSessionJwt: `jwt:${thresholdSessionId}`,
        signingSessionSealKeyVersion: 'signing-session-seal-kek-test-r1',
        shamirPrimeB64u: 'prime-b64u',
      },
      shamirPrimeB64u: 'prime-b64u',
      rehydrateWarmSessionMaterial: async () => ({
        ok: true,
        sessionId: thresholdSessionId,
        remainingUses: 2,
        expiresAtMs,
      }),
      deletePersistedRecord: async () => {
        throw new Error('successful restore must not delete the sealed record');
      },
      recordSessionMaterialRestored: async (status) => {
        restoredStatuses.push(status);
      },
      readWarmSessionStatusFromWorker: async () => ({
        ok: true,
        sessionId: thresholdSessionId,
        remainingUses: 2,
        expiresAtMs,
      }),
      updatePersistedPolicy: async () => undefined,
    });

    expect(result).toEqual({
      ok: true,
      sessionId: thresholdSessionId,
      remainingUses: 2,
      expiresAtMs,
    });
    expect(restoredStatuses).toEqual([result]);
    const restoredRecord =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
    expect(restoredRecord).toMatchObject({
      thresholdSessionId,
      signingGrantId,
      materialState: 'material_ready',
      ed25519WorkerMaterialHandle: 'runtime-handle-reconnect',
      ed25519WorkerMaterialBindingDigest: 'material-binding-reconnect',
      sealedWorkerMaterialRef: 'sealed-ref-reconnect',
      sealedWorkerMaterialB64u: 'sealed-blob-reconnect',
      materialKeyId: 'material-key-reconnect',
    });
  });

  test('returns the exact planned reconnect record after a concurrent current-record update', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-old',
      signingGrantId: 'wsess-ed25519-old',
      remainingUses: 0,
    });
    const plannedSessionId = 'tsess-ed25519-planned-reconnect';
    const plannedSigningGrantId = 'wsess-ed25519-planned-reconnect';
    const competingSessionId = 'tsess-ed25519-competing-current';

    const result = await reconnectPasskeyEd25519CapabilityForSigning({
      nearAccountId: ACCOUNT_ID,
      record: oldRecord,
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: TEST_WEBAUTHN_CREDENTIAL as any,
        rpId: RP_ID,
      }),
      remainingUses: 1,
      sessionId: plannedSessionId,
      signingGrantId: plannedSigningGrantId,
      provisionThresholdEd25519Session: async (request) => {
        expect(request.kind).toBe('exact_ed25519_provisioning');
        expect(request.sessionId).toBe(plannedSessionId);
        expect(request.signingGrantId).toBe(plannedSigningGrantId);
        writeEd25519Record({
          thresholdSessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
        });
        writeEd25519Record({
          thresholdSessionId: competingSessionId,
          signingGrantId: 'wsess-ed25519-competing-current',
        });
        return {
          ok: true,
          sessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          jwt: `jwt:${plannedSessionId}`,
        };
      },
      restorePasskeyEd25519SigningMaterial: async () => undefined,
    });

    expect(result.sessionId).toBe(plannedSessionId);
    expect(result.record?.thresholdSessionId).toBe(plannedSessionId);
    expect(result.record?.signingGrantId).toBe(plannedSigningGrantId);
    expect(getStoredThresholdEd25519SessionRecordForAccount(ACCOUNT_ID)?.thresholdSessionId).toBe(
      competingSessionId,
    );
  });

  test('retains sealed worker material facts across a planned reconnect session remint', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-material-old',
      signingGrantId: 'wsess-ed25519-material-old',
      remainingUses: 0,
      withWorkerMaterial: true,
    });
    const plannedSessionId = 'tsess-ed25519-material-planned';
    const plannedSigningGrantId = 'wsess-ed25519-material-planned';

    await reconnectPasskeyEd25519CapabilityForSigning({
      nearAccountId: ACCOUNT_ID,
      record: oldRecord,
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: TEST_WEBAUTHN_CREDENTIAL as any,
        rpId: RP_ID,
      }),
      remainingUses: 1,
      sessionId: plannedSessionId,
      signingGrantId: plannedSigningGrantId,
      provisionThresholdEd25519Session: async () => {
        writeEd25519Record({
          thresholdSessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
        });
        return {
          ok: true,
          sessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          jwt: `jwt:${plannedSessionId}`,
        };
      },
      restorePasskeyEd25519SigningMaterial: async ({ thresholdSessionId }) => {
        const plannedRecord =
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
        expect(plannedRecord?.clientVerifyingShareB64u).toBe('client-verifier-reconnect');
        expect(plannedRecord?.ed25519WorkerMaterialBindingDigest).toBe(
          'material-binding-reconnect',
        );
        expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
        expect(plannedRecord?.sealedWorkerMaterialB64u).toBe('sealed-blob-reconnect');
        expect(plannedRecord?.materialKeyId).toBe('material-key-reconnect');
      },
    });

    const plannedRecord =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(plannedSessionId);
    expect(plannedRecord?.signingGrantId).toBe(plannedSigningGrantId);
    expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
  });

  test('retains sealed worker material facts when reconnect remints a different SigningWorker route', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-material-worker-old',
      signingGrantId: 'wsess-ed25519-material-worker-old',
      remainingUses: 0,
      withWorkerMaterial: true,
      signingWorkerId: 'signing-worker-before-remint',
    });
    const plannedSessionId = 'tsess-ed25519-material-worker-planned';
    const plannedSigningGrantId = 'wsess-ed25519-material-worker-planned';

    await reconnectPasskeyEd25519CapabilityForSigning({
      nearAccountId: ACCOUNT_ID,
      record: oldRecord,
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: TEST_WEBAUTHN_CREDENTIAL as any,
        rpId: RP_ID,
      }),
      remainingUses: 1,
      sessionId: plannedSessionId,
      signingGrantId: plannedSigningGrantId,
      provisionThresholdEd25519Session: async () => {
        writeEd25519Record({
          thresholdSessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          signingWorkerId: 'signing-worker-after-remint',
        });
        return {
          ok: true,
          sessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          jwt: `jwt:${plannedSessionId}`,
        };
      },
      restorePasskeyEd25519SigningMaterial: async ({ thresholdSessionId }) => {
        const plannedRecord =
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
        expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
        expect(plannedRecord?.sealedWorkerMaterialB64u).toBe('sealed-blob-reconnect');
        expect(plannedRecord?.materialKeyId).toBe('material-key-reconnect');
        expect(plannedRecord?.routerAbNormalSigning?.signingWorkerId).toBe(
          'signing-worker-after-remint',
        );
      },
    });

    const plannedRecord =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(plannedSessionId);
    expect(plannedRecord?.signingGrantId).toBe(plannedSigningGrantId);
    expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
  });

  test('retains storage-ref sealed worker material facts across a planned reconnect', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-storage-ref-old',
      signingGrantId: 'wsess-ed25519-storage-ref-old',
      remainingUses: 0,
      withStorageRefOnlyWorkerMaterial: true,
    });
    const plannedSessionId = 'tsess-ed25519-storage-ref-planned';
    const plannedSigningGrantId = 'wsess-ed25519-storage-ref-planned';

    await reconnectPasskeyEd25519CapabilityForSigning({
      nearAccountId: ACCOUNT_ID,
      record: oldRecord,
      policySecretSource: buildThresholdEd25519WebAuthnPrfSecretSource({
        credential: TEST_WEBAUTHN_CREDENTIAL as any,
        rpId: RP_ID,
      }),
      remainingUses: 1,
      sessionId: plannedSessionId,
      signingGrantId: plannedSigningGrantId,
      provisionThresholdEd25519Session: async () => {
        writeEd25519Record({
          thresholdSessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
        });
        return {
          ok: true,
          sessionId: plannedSessionId,
          signingGrantId: plannedSigningGrantId,
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          jwt: `jwt:${plannedSessionId}`,
        };
      },
      restorePasskeyEd25519SigningMaterial: async ({ thresholdSessionId }) => {
        const plannedRecord =
          getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
        expect(plannedRecord?.materialState).toBe('restore_available');
        expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
        expect(plannedRecord?.sealedWorkerMaterialB64u).toBeUndefined();
        expect(plannedRecord?.materialKeyId).toBe('material-key-reconnect');
      },
    });

    const plannedRecord =
      getStoredThresholdEd25519SessionRecordByThresholdSessionId(plannedSessionId);
    expect(plannedRecord?.signingGrantId).toBe(plannedSigningGrantId);
    expect(plannedRecord?.sealedWorkerMaterialRef).toBe('sealed-ref-reconnect');
    expect(plannedRecord?.sealedWorkerMaterialB64u).toBeUndefined();
  });
});
