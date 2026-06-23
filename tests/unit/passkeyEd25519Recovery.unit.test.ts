import { expect, test } from '@playwright/test';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  getStoredThresholdEd25519SessionRecordForAccount,
  upsertStoredThresholdEd25519SessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import { reconnectPasskeyEd25519CapabilityForSigning } from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';

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
  signingWorkerId?: string;
}) {
  const record = upsertStoredThresholdEd25519SessionRecord({
    walletId: ACCOUNT_ID,
    nearAccountId: ACCOUNT_ID,
    ed25519KeyScopeId: ACCOUNT_ID,
    rpId: RP_ID,
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: PARTICIPANT_IDS,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: {
      ...ROUTER_AB_NORMAL_SIGNING,
      signingWorkerId: args.signingWorkerId || ROUTER_AB_NORMAL_SIGNING.signingWorkerId,
    },
    signerSlot: 1,
    ...(args.withWorkerMaterial
      ? {
          clientVerifyingShareB64u: 'client-verifier-reconnect',
          ed25519WorkerMaterialHandle: 'runtime-handle-reconnect',
          ed25519WorkerMaterialBindingDigest: 'material-binding-reconnect',
          sealedWorkerMaterialRef: 'sealed-ref-reconnect',
          sealedWorkerMaterialB64u: 'sealed-blob-reconnect',
          materialFormatVersion: 'ed25519_sealed_worker_material_v1',
          materialKeyId: 'material-key-reconnect',
          materialCreatedAtMs: 1_800_000_100_000,
          keyVersion: 'threshold-ed25519-hss-v1',
        }
      : {}),
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
        expect(plannedRecord?.keyVersion).toBe('threshold-ed25519-hss-v1');
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
});
