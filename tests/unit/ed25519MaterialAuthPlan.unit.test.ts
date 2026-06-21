import { expect, test } from '@playwright/test';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
  type ThresholdEd25519SessionRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import type { WarmSessionCapabilityReader } from '../../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types';
import { signingAuthPlanForEd25519MaterialReadiness } from '../../packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519MaterialAuthPlan';
import {
  SigningAuthPlanKind,
  type SigningAuthPlan,
} from '../../packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types';

const SESSION_ID = 'tsess-ed25519-auth-plan';
const SIGNING_GRANT_ID = 'sg-ed25519-auth-plan';
const BASE_RECORD = {
  nearAccountId: 'ed25519-auth-plan.testnet',
  rpId: 'localhost',
  relayerUrl: 'https://localhost:9444',
  relayerKeyId: 'ed25519:auth-plan-relayer',
  participantIds: [1, 2],
  runtimePolicyScope: {
    orgId: 'org-ed25519-auth-plan',
    projectId: 'project-ed25519-auth-plan',
    envId: 'dev',
    signingRootVersion: 'default',
  },
  routerAbNormalSigning: {
    kind: 'router_ab_ed25519_normal_signing_v1',
    signingWorkerId: 'signing-worker-auth-plan',
  },
  thresholdSessionKind: 'jwt',
  thresholdSessionId: SESSION_ID,
  signingGrantId: SIGNING_GRANT_ID,
  walletSessionJwt: 'jwt-ed25519-auth-plan',
  expiresAtMs: Date.now() + 60_000,
  remainingUses: 3,
  signerSlot: 1,
  source: 'registration',
} as const;

const WARM_AUTH_PLAN: SigningAuthPlan = {
  kind: SigningAuthPlanKind.WarmSession,
  method: 'passkey',
  accountId: BASE_RECORD.nearAccountId,
  intent: 'transaction_sign',
  curve: 'ed25519',
  sessionId: SESSION_ID,
  expiresAtMs: BASE_RECORD.expiresAtMs,
  remainingUses: BASE_RECORD.remainingUses,
};

const PASSKEY_RECONNECT = {
  prepare: async () => ({
    sessionId: SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
    sessionPolicyDigest32: 'session-policy-digest',
  }),
  reconnect: async () => {
    throw new Error('unused');
  },
};

function writeRecord(args: {
  materialHandle?: string;
  sealedWorkerMaterial?: boolean;
}): ThresholdEd25519SessionRecord {
  const record = upsertStoredThresholdEd25519SessionRecord({
    ...BASE_RECORD,
    participantIds: [...BASE_RECORD.participantIds],
    clientVerifyingShareB64u: 'client-verifier-auth-plan',
    ...(args.materialHandle ? { ed25519WorkerMaterialHandle: args.materialHandle } : {}),
    ed25519WorkerMaterialBindingDigest: 'material-binding-auth-plan',
    ...(args.sealedWorkerMaterial
      ? {
          sealedWorkerMaterialRef: 'sealed-ref-auth-plan',
          sealedWorkerMaterialB64u: 'sealed-blob-auth-plan',
          materialFormatVersion: 'ed25519_sealed_worker_material_v1',
          materialKeyId: 'material-key-auth-plan',
        }
      : {}),
    materialCreatedAtMs: 1_800_000_000_000,
    keyVersion: 'threshold-ed25519-hss-v1',
  });
  if (!record) throw new Error('expected Ed25519 record');
  return record;
}

function coordinatorFor(record: ThresholdEd25519SessionRecord): WarmSessionCapabilityReader {
  return {
    getWarmSession: async () => {
      throw new Error('unused');
    },
    resolveEd25519RecordByThresholdSessionId: () => record,
    resolveEcdsaRecordByThresholdSessionId: () => null,
    resolveEd25519AuthByThresholdSessionId: () => null,
    resolveEcdsaAuthByThresholdSessionId: () => null,
    resolveEmailOtpSigningSessionAuthLane: () => null,
    getEd25519CapabilityByThresholdSessionId: async () => null,
    getEcdsaCapabilityByThresholdSessionId: async () => null,
    resolveEcdsaSealTransportByThresholdSessionId: () => null,
  };
}

function resolvePlan(record: ThresholdEd25519SessionRecord): SigningAuthPlan {
  return signingAuthPlanForEd25519MaterialReadiness({
    signingSessionCoordinator: coordinatorFor(record),
    sessionId: SESSION_ID,
    signingAuthPlan: WARM_AUTH_PLAN,
    passkeyEd25519Reconnect: PASSKEY_RECONNECT,
  });
}

test.describe('Ed25519 material auth planning', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('keeps warm-session auth for an unvalidated loaded material handle', () => {
    const record = writeRecord({ materialHandle: 'runtime-handle-auth-plan' });
    expect(resolvePlan(record)).toBe(WARM_AUTH_PLAN);
  });

  test('keeps warm-session auth for sealed material when a loaded handle hint exists', () => {
    const record = writeRecord({
      materialHandle: 'runtime-handle-auth-plan',
      sealedWorkerMaterial: true,
    });
    expect(resolvePlan(record)).toBe(WARM_AUTH_PLAN);
  });

  test('requires passkey reauth for sealed material without a loaded handle hint', () => {
    const record = writeRecord({ sealedWorkerMaterial: true });
    expect(resolvePlan(record)).toEqual({
      kind: SigningAuthPlanKind.PasskeyReauth,
      method: 'passkey',
    });
  });
});
