import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildNearTransactionSigningLane,
  readSigningCapabilityRecord,
} from '@/core/signingEngine/session/operationState/lanes';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
  clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation,
  clearRouterAbEd25519WorkerMaterialRuntimeValidation,
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
  markRouterAbEd25519WorkerMaterialRuntimeValidated,
  resolveRouterAbEd25519WorkerMaterialRuntimeValidation,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';

const accountId = toAccountId('strict-ed25519-capability.testnet');
const ed25519WalletId = walletIdFromString('strict-ed25519-wallet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('strict-ed25519-key-scope');
const signingGrantId = SigningSessionIds.signingGrant('wsess-strict-ed25519');
const thresholdSessionId = SigningSessionIds.thresholdEd25519Session('tsess-strict-ed25519');
const ecdsaWalletId = toWalletId('strict-ecdsa-capability.testnet');
const ecdsaSigningGrantId = SigningSessionIds.signingGrant('wsess-strict-ecdsa');
const ecdsaThresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-strict-ecdsa');
const ecdsaChainTarget: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 4242,
  networkSlug: 'tempo-strict',
};
const ecdsaThresholdKeyId = 'ecdsa-strict-threshold-key';
const ecdsaSigningRootId = 'proj_strict:dev';
const ecdsaSigningRootVersion = '1';
const ecdsaWalletKeyId = deriveEvmFamilySigningKeySlotId({
  walletId: ecdsaWalletId,
  signingRootId: ecdsaSigningRootId,
  signingRootVersion: ecdsaSigningRootVersion,
  chainTargetKey: thresholdEcdsaChainTargetKey(ecdsaChainTarget),
});
const ecdsaKeyHandle = toEvmFamilyEcdsaKeyHandle('tempo:4242:ecdsa-strict-threshold-key');
const ecdsaOwnerAddress = `0x${'42'.repeat(20)}`;
const ecdsaClientPublicKeyB64u = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ecdsaRelayerPublicKeyB64u = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ecdsaContextBindingB64u = base64UrlEncode(new Uint8Array(32).fill(7));
const ecdsaApplicationBindingDigestB64u = base64UrlEncode(new Uint8Array(32).fill(9));
const ecdsaStateBlobB64u = base64UrlEncode(new Uint8Array(64).fill(8));
const passkeyAuth = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-strict-capability',
};
const emailOtpAuth = {
  kind: 'email_otp' as const,
  providerSubjectId: 'google:strict-capability',
};

function makeTestWalletSessionJwt(payload: Record<string, unknown>): string {
  return [
    base64UrlEncode(new TextEncoder().encode(JSON.stringify({ alg: 'none', typ: 'JWT' }))),
    base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload))),
    'test-signature',
  ].join('.');
}

function runWithDateNow<TValue>(nowMs: number, run: () => TValue): TValue {
  const originalDateNow = Date.now;
  Date.now = () => nowMs;
  try {
    return run();
  } finally {
    Date.now = originalDateNow;
  }
}

function makeLane() {
  return buildNearTransactionSigningLane({
    walletId: ed25519WalletId,
    nearAccountId: accountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    auth: passkeyAuth,
    signingGrantId,
    thresholdSessionId,
    storageSource: 'login',
  });
}

function makeEd25519Record(
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  return {
    walletId: ed25519WalletId,
    nearAccountId: accountId,
    nearEd25519SigningKeyId,
    rpId: 'localhost',
    passkeyCredentialIdB64u: 'credential-ed25519-strict-capability',
    relayerUrl: 'https://router.example.test',
    relayerKeyId: 'ed25519:strict-capability-relayer',
    participantIds: [1, 2],
    signingRootId: 'proj_strict:dev',
    signingRootVersion: '1',
    runtimePolicyScope: {
      orgId: 'org_strict',
      projectId: 'proj_strict',
      envId: 'dev',
      signingRootVersion: '1',
    },
    ed25519WorkerMaterialHandle: 'hss-material-handle-strict',
    ed25519WorkerMaterialBindingDigest: 'sha256:strict-material-binding',
    clientVerifyingShareB64u: 'strict-client-verifier',
    sealedWorkerMaterialRef: 'sealed-worker-material-ref-strict',
    sealedWorkerMaterialB64u: 'sealed-worker-material-b64u-strict',
    materialFormatVersion: 'ed25519-worker-material-v1',
    materialKeyId: 'strict-material-key',
    materialCreatedAtMs: 1_900_000_000_000,
    materialState: 'material_ready',
    signerSlot: 1,
    keyVersion: 'threshold-ed25519-hss-v1',
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-strict',
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId,
    signingGrantId,
    walletSessionJwt: makeTestWalletSessionJwt({
      kind: 'router_ab_ed25519_wallet_session_v1',
      sub: ed25519WalletId,
      walletId: ed25519WalletId,
      nearAccountId: accountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signingGrantId,
      version: 1,
    }),
    expiresAtMs: 2_000_000_000_000,
    remainingUses: 3,
    updatedAtMs: 1_900_000_000_000,
    source: 'login',
    ...overrides,
  };
}

function ecdsaOwnerAddress20B64u(): string {
  const hex = ecdsaOwnerAddress.replace(/^0x/i, '');
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? []);
  return base64UrlEncode(bytes);
}

function makeEcdsaKey() {
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: ecdsaWalletId,
    evmFamilySigningKeySlotId: ecdsaWalletKeyId,
    ecdsaThresholdKeyId,
    signingRootId: ecdsaSigningRootId,
    signingRootVersion: ecdsaSigningRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: ecdsaOwnerAddress,
  });
}

function makeEcdsaLane() {
  const key = makeEcdsaKey();
  return buildEcdsaEmailOtpSigningLane({
    key,
    keyHandle: ecdsaKeyHandle,
    walletId: ecdsaWalletId,
    auth: emailOtpAuth,
    chainTarget: ecdsaChainTarget,
    signingGrantId: ecdsaSigningGrantId,
    thresholdSessionId: ecdsaThresholdSessionId,
  });
}

function makeEcdsaRouterAbNormalSigning(): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: ecdsaWalletKeyId,
      wallet_id: ecdsaWalletId,
      ecdsa_threshold_key_id: ecdsaThresholdKeyId,
      signing_root_id: ecdsaSigningRootId,
      signing_root_version: ecdsaSigningRootVersion,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: ecdsaContextBindingB64u,
        client_public_key33_b64u: ecdsaClientPublicKeyB64u,
        server_public_key33_b64u: ecdsaRelayerPublicKeyB64u,
        threshold_public_key33_b64u: ecdsaClientPublicKeyB64u,
        ethereum_address20_b64u: ecdsaOwnerAddress20B64u(),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-strict',
        key_epoch: 'worker-epoch-strict',
        recipient_encryption_key:
          'x25519:1111111111111111111111111111111111111111111111111111111111111111',
      },
      activation_epoch: ecdsaThresholdSessionId,
    },
  };
}

function makeEcdsaRoleLocalReadyRecord() {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: ecdsaStateBlobB64u,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: ecdsaWalletId,
      evmFamilySigningKeySlotId: ecdsaWalletKeyId,
      chainTarget: ecdsaChainTarget,
      keyHandle: ecdsaKeyHandle,
      ecdsaThresholdKeyId,
      signingRootId: ecdsaSigningRootId,
      signingRootVersion: ecdsaSigningRootVersion,
      applicationBindingDigestB64u: ecdsaApplicationBindingDigestB64u,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: ecdsaContextBindingB64u,
      hssClientSharePublicKey33B64u: ecdsaClientPublicKeyB64u,
      relayerPublicKey33B64u: ecdsaRelayerPublicKeyB64u,
      groupPublicKey33B64u: ecdsaClientPublicKeyB64u,
      ethereumAddress: ecdsaOwnerAddress,
    }),
    authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
      authSubjectId: 'strict-email-otp-auth-subject',
    }),
  });
}

function makeEcdsaRecord(
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: ecdsaWalletId,
    evmFamilySigningKeySlotId: ecdsaWalletKeyId,
    chainTarget: ecdsaChainTarget,
    relayerUrl: 'https://router.example.test',
    keyHandle: ecdsaKeyHandle,
    ecdsaThresholdKeyId,
    signingRootId: ecdsaSigningRootId,
    signingRootVersion: ecdsaSigningRootVersion,
    relayerKeyId: 'ecdsa-strict-relayer-key',
    clientVerifyingShareB64u: ecdsaClientPublicKeyB64u,
    ecdsaRoleLocalReadyRecord: makeEcdsaRoleLocalReadyRecord(),
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org_strict',
      projectId: 'proj_strict',
      envId: 'dev',
      signingRootVersion: ecdsaSigningRootVersion,
    },
    routerAbEcdsaHssNormalSigning: makeEcdsaRouterAbNormalSigning(),
    thresholdSessionKind: 'jwt',
    thresholdSessionId: ecdsaThresholdSessionId,
    signingGrantId: ecdsaSigningGrantId,
    walletSessionJwt: makeTestWalletSessionJwt({
      kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
      sub: ecdsaWalletId,
      thresholdSessionId: ecdsaThresholdSessionId,
      signingGrantId: ecdsaSigningGrantId,
      version: 1,
    }),
    expiresAtMs: 2_000_000_000_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: ecdsaClientPublicKeyB64u,
    ethereumAddress: ecdsaOwnerAddress,
    updatedAtMs: 1_900_000_000_000,
    source: 'email_otp',
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'session',
      retention: 'session',
      walletId: ecdsaWalletId,
      emailHashHex: 'strict-email-otp-auth-email-hash',
      reason: 'login',
      provider: 'google',
      providerUserId: 'strict-email-otp-auth-subject',
    }),
    ...overrides,
  };
}

test.describe('selected signing capability strict persisted records', () => {
  test.beforeEach(() => {
    clearRouterAbEd25519WorkerMaterialRuntimeValidation();
    clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation();
  });

  test('rejects selected Ed25519 records missing worker-owned material handles', () => {
    const lane = makeLane();
    const record = makeEd25519Record();
    delete record.ed25519WorkerMaterialHandle;
    record.materialState = 'restore_available';
    expect(resolveRouterAbEd25519WorkerMaterialRuntimeValidation(record)).toMatchObject({
      ok: false,
      reason: 'worker_material_missing',
      parseReason: 'missing_material_handle',
    });
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEd25519SessionRecordByThresholdSessionId: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message:
        'Selected Ed25519 session record is not Router A/B signable: loaded_material_missing',
    });
  });

  test('accepts selected Ed25519 records only after worker material runtime validation', () => {
    const lane = makeLane();
    const record = makeEd25519Record();
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      record,
      reason: 'loaded_material_missing',
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
      value: {
        curve: 'ed25519',
        thresholdSessionId,
        signingGrantId,
      },
    });

    const result = readSigningCapabilityRecord(
      {
        readEd25519SessionRecordByThresholdSessionId: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: true,
      capability: {
        curve: 'ed25519',
        record,
      },
    });
  });

  test('invalidates selected Ed25519 runtime validation on worker restart', () => {
    const record = makeEd25519Record();
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
    });

    clearRouterAbEd25519WorkerMaterialRuntimeValidation();

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record,
    });
  });

  test('classifies previously validated Ed25519 records as expired after grant expiry', () => {
    const lane = makeLane();
    const record = makeEd25519Record({
      expiresAtMs: Date.now() + 60_000,
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    runWithDateNow(record.expiresAtMs + 1, () => {
      expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
        kind: 'expired',
        reason: 'expired',
        expiresAtMs: record.expiresAtMs,
        record,
      });

      const result = readSigningCapabilityRecord(
        {
          readEd25519SessionRecordByThresholdSessionId: () => record,
        },
        lane,
      );
      expect(result).toMatchObject({
        ok: false,
        code: 'record_mismatch',
        message: 'Selected Ed25519 session record is not Router A/B signable: expired',
      });
    });
  });

  test('classifies previously validated Ed25519 records as exhausted after local spend reaches zero', () => {
    const lane = makeLane();
    const record = makeEd25519Record({
      remainingUses: 1,
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
    record.remainingUses = 0;

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'exhausted',
      reason: 'exhausted',
      remainingUses: 0,
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEd25519SessionRecordByThresholdSessionId: () => record,
      },
      lane,
    );
    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message: 'Selected Ed25519 session record is not Router A/B signable: exhausted',
    });
  });

  test('classifies Ed25519 records that are both expired and exhausted as expired', () => {
    const record = makeEd25519Record({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);
    record.remainingUses = 0;

    runWithDateNow(record.expiresAtMs + 1, () => {
      expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
        kind: 'expired',
        reason: 'expired',
        expiresAtMs: record.expiresAtMs,
        record,
      });
    });
  });

  test('rejects Ed25519 active-state classification with an invalid operation clock', () => {
    const record = makeEd25519Record();
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEd25519PersistedSigningRecord(record, Number.NaN)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record,
    });
  });

  test('invalidates selected Ed25519 runtime validation when Wallet Session auth changes', () => {
    const record = makeEd25519Record();
    const refreshedRecord = makeEd25519Record({
      walletSessionJwt: makeTestWalletSessionJwt({
        kind: 'router_ab_ed25519_wallet_session_v1',
        sub: ed25519WalletId,
        walletId: ed25519WalletId,
        nearAccountId: accountId,
        nearEd25519SigningKeyId,
        thresholdSessionId,
        signingGrantId,
        version: 2,
      }),
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEd25519PersistedSigningRecord(refreshedRecord)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record: refreshedRecord,
    });
  });

  test('invalidates selected Ed25519 runtime validation when material handle changes', () => {
    const record = makeEd25519Record();
    const staleHandleRecord = makeEd25519Record({
      ed25519WorkerMaterialHandle: 'hss-material-handle-stale',
    });
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEd25519PersistedSigningRecord(staleHandleRecord)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record: staleHandleRecord,
    });
  });

  test('derives Ed25519 signing root identity from runtime policy scope', () => {
    const record = makeEd25519Record();
    delete record.signingRootId;
    delete record.signingRootVersion;
    expect(markRouterAbEd25519WorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
      record,
      value: {
        curve: 'ed25519',
        thresholdSessionId,
        signingGrantId,
        signingRootId: 'proj_strict:dev',
        signingRootVersion: '1',
      },
    });
  });

  test('rejects selected Ed25519 records missing signing-root identity', () => {
    const lane = makeLane();
    const record = makeEd25519Record({
      runtimePolicyScope: {
        orgId: 'org_strict',
        projectId: 'proj_strict',
        envId: 'dev',
      } as never,
    });
    delete record.signingRootId;
    delete record.signingRootVersion;

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'missing_signing_root',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEd25519SessionRecordByThresholdSessionId: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message: 'Selected Ed25519 session record is not Router A/B signable: missing_signing_root',
    });
  });

  test('rejects selected Ed25519 records with mismatched persisted signing-root identity', () => {
    const record = makeEd25519Record({
      signingRootId: 'proj_other:dev',
    });

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'signing_root_mismatch',
      record,
    });
  });

  test('rejects selected Ed25519 records with fractional budget fields', () => {
    const remainingUsesRecord = makeEd25519Record({
      remainingUses: 2.5,
    });
    expect(classifyRouterAbEd25519PersistedSigningRecord(remainingUsesRecord)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record: remainingUsesRecord,
    });

    const expiresAtRecord = makeEd25519Record({
      expiresAtMs: 2_000_000_000_000.5,
    });
    expect(classifyRouterAbEd25519PersistedSigningRecord(expiresAtRecord)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record: expiresAtRecord,
    });
  });

  test('rejects selected ECDSA records missing Router A/B normal-signing state', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord();
    delete record.routerAbEcdsaHssNormalSigning;
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'missing_router_ab_state',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message:
        'Selected ECDSA session record is not Router A/B runtime-validated: missing_router_ab_state',
    });
  });

  test('rejects selected ECDSA records missing persisted verifier material', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord({
      clientVerifyingShareB64u: '',
    });
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'missing_client_verifying_share',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message:
        'Selected ECDSA session record is not Router A/B runtime-validated: missing_client_verifying_share',
    });
  });

  test('rejects selected ECDSA records when persisted verifier drifts from Router A/B state', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord({
      clientVerifyingShareB64u: ecdsaRelayerPublicKeyB64u,
    });
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'material_identity_mismatch',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message:
        'Selected ECDSA session record is not Router A/B runtime-validated: material_identity_mismatch',
    });
  });

  test('rejects selected ECDSA records when Router A/B threshold key drifts from the record', () => {
    const record = makeEcdsaRecord({
      routerAbEcdsaHssNormalSigning: {
        ...makeEcdsaRouterAbNormalSigning(),
        scope: {
          ...makeEcdsaRouterAbNormalSigning().scope,
          ecdsa_threshold_key_id: 'other-ecdsa-threshold-key',
        },
      },
    });

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'material_identity_mismatch',
      record,
    });
  });

  test('rejects selected ECDSA records when Router A/B signing root drifts from runtime policy', () => {
    const record = makeEcdsaRecord({
      routerAbEcdsaHssNormalSigning: {
        ...makeEcdsaRouterAbNormalSigning(),
        scope: {
          ...makeEcdsaRouterAbNormalSigning().scope,
          signing_root_version: '2',
        },
      },
    });

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'signing_root_mismatch',
      record,
    });
  });

  test('rejects selected ECDSA records with fractional budget fields', () => {
    const remainingUsesRecord = makeEcdsaRecord({
      remainingUses: 2.5,
    });
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(remainingUsesRecord)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record: remainingUsesRecord,
    });

    const expiresAtRecord = makeEcdsaRecord({
      expiresAtMs: 2_000_000_000_000.5,
    });
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(expiresAtRecord)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record: expiresAtRecord,
    });
  });

  test('keeps selected ECDSA role-local records restore-only until worker material is validated', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord();
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message:
        'Selected ECDSA session record is not Router A/B runtime-validated: loaded_material_missing',
    });
  });

  test('accepts selected ECDSA records only after runtime worker material validation', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord();
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
      record,
      value: {
        curve: 'ecdsa',
        thresholdSessionId: ecdsaThresholdSessionId,
        signingGrantId: ecdsaSigningGrantId,
        signingMaterial: {
          kind: 'router_ab_ecdsa_hss_signing_material_ref_v1',
          clientVerifier33B64u: ecdsaClientPublicKeyB64u,
          serverVerifier33B64u: ecdsaRelayerPublicKeyB64u,
          thresholdVerifier33B64u: ecdsaClientPublicKeyB64u,
        },
      },
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );

    expect(result).toMatchObject({
      ok: true,
      capability: {
        curve: 'ecdsa',
        record,
      },
    });
  });

  test('invalidates selected ECDSA runtime validation on worker restart', () => {
    const record = makeEcdsaRecord();
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'runtime_validated',
      record,
    });

    clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation();

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record,
    });
  });

  test('classifies previously validated ECDSA records as expired after grant expiry', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord({
      expiresAtMs: Date.now() + 60_000,
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    runWithDateNow(record.expiresAtMs + 1, () => {
      expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
        kind: 'expired',
        reason: 'expired',
        expiresAtMs: record.expiresAtMs,
        record,
      });

      const result = readSigningCapabilityRecord(
        {
          readEmailOtpEcdsaSessionRecord: () => record,
        },
        lane,
      );
      expect(result).toMatchObject({
        ok: false,
        code: 'record_mismatch',
        message: 'Selected ECDSA session record is not Router A/B runtime-validated: expired',
      });
    });
  });

  test('classifies previously validated ECDSA records as exhausted after local spend reaches zero', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord({
      remainingUses: 1,
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);
    record.remainingUses = 0;

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'exhausted',
      reason: 'exhausted',
      remainingUses: 0,
      record,
    });

    const result = readSigningCapabilityRecord(
      {
        readEmailOtpEcdsaSessionRecord: () => record,
      },
      lane,
    );
    expect(result).toMatchObject({
      ok: false,
      code: 'record_mismatch',
      message: 'Selected ECDSA session record is not Router A/B runtime-validated: exhausted',
    });
  });

  test('classifies ECDSA records that are both expired and exhausted as expired', () => {
    const record = makeEcdsaRecord({
      expiresAtMs: Date.now() + 60_000,
      remainingUses: 1,
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);
    record.remainingUses = 0;

    runWithDateNow(record.expiresAtMs + 1, () => {
      expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
        kind: 'expired',
        reason: 'expired',
        expiresAtMs: record.expiresAtMs,
        record,
      });
    });
  });

  test('rejects ECDSA active-state classification with an invalid operation clock', () => {
    const record = makeEcdsaRecord();
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record, Number.NaN)).toMatchObject({
      kind: 'invalid',
      reason: 'invalid_budget',
      record,
    });
  });

  test('invalidates selected ECDSA runtime validation when Wallet Session auth changes', () => {
    const record = makeEcdsaRecord();
    const refreshedRecord = makeEcdsaRecord({
      walletSessionJwt: makeTestWalletSessionJwt({
        kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
        sub: ecdsaWalletId,
        thresholdSessionId: ecdsaThresholdSessionId,
        signingGrantId: ecdsaSigningGrantId,
        version: 2,
      }),
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(refreshedRecord)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record: refreshedRecord,
    });
  });

  test('invalidates selected ECDSA runtime validation when the signing grant changes', () => {
    const record = makeEcdsaRecord();
    const refreshedSigningGrantId = SigningSessionIds.signingGrant('wsess-strict-ecdsa-refreshed');
    const refreshedRecord = makeEcdsaRecord({
      signingGrantId: refreshedSigningGrantId,
      walletSessionJwt: makeTestWalletSessionJwt({
        kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
        sub: ecdsaWalletId,
        thresholdSessionId: ecdsaThresholdSessionId,
        signingGrantId: refreshedSigningGrantId,
        version: 1,
      }),
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(refreshedRecord)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record: refreshedRecord,
    });
  });

  test('invalidates selected ECDSA runtime validation when Router A/B activation epoch changes', () => {
    const record = makeEcdsaRecord();
    const routerAbEcdsaHssNormalSigning = makeEcdsaRouterAbNormalSigning();
    routerAbEcdsaHssNormalSigning.scope.activation_epoch = SigningSessionIds.thresholdEcdsaSession(
      'tsess-strict-ecdsa-rotated',
    );
    const refreshedRecord = makeEcdsaRecord({
      routerAbEcdsaHssNormalSigning,
    });
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);

    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(refreshedRecord)).toMatchObject({
      kind: 'restore_available',
      reason: 'loaded_material_missing',
      record: refreshedRecord,
    });
  });
});
