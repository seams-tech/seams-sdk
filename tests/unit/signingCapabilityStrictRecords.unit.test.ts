import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaHss';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildNearTransactionSigningLane,
  readSigningCapabilityRecord,
} from '@/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  classifyRouterAbEd25519PersistedSigningRecord,
} from '@/core/signingEngine/session/routerAbSigningWalletSession';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';

const accountId = toAccountId('strict-ed25519-capability.testnet');
const walletSigningSessionId = SigningSessionIds.walletSigningSession('wsess-strict-ed25519');
const thresholdSessionId = SigningSessionIds.thresholdEd25519Session('tsess-strict-ed25519');
const ecdsaWalletId = toAccountId('strict-ecdsa-capability.testnet');
const ecdsaWalletSigningSessionId =
  SigningSessionIds.walletSigningSession('wsess-strict-ecdsa');
const ecdsaThresholdSessionId = SigningSessionIds.thresholdEcdsaSession('tsess-strict-ecdsa');
const ecdsaChainTarget: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 4242,
  networkSlug: 'tempo-strict',
};
const ecdsaThresholdKeyId = 'ecdsa-strict-threshold-key';
const ecdsaSigningRootId = 'proj_strict:dev';
const ecdsaSigningRootVersion = '1';
const ecdsaKeyHandle = toEvmFamilyEcdsaKeyHandle('tempo:4242:ecdsa-strict-threshold-key');
const ecdsaOwnerAddress = `0x${'42'.repeat(20)}`;
const ecdsaClientPublicKeyB64u = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ecdsaRelayerPublicKeyB64u = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ecdsaContextBindingB64u = base64UrlEncode(new Uint8Array(32).fill(7));
const ecdsaStateBlobB64u = base64UrlEncode(new Uint8Array(64).fill(8));

function makeLane() {
  return buildNearTransactionSigningLane({
    accountId,
    authMethod: 'passkey',
    walletSigningSessionId,
    thresholdSessionId,
    storageSource: 'login',
  });
}

function makeEd25519Record(
  overrides: Partial<ThresholdEd25519SessionRecord> = {},
): ThresholdEd25519SessionRecord {
  return {
    nearAccountId: accountId,
    rpId: 'localhost',
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
    ed25519HssMaterialHandle: 'hss-material-handle-strict',
    ed25519HssMaterialBindingDigest: 'sha256:strict-material-binding',
    clientVerifyingShareB64u: 'strict-client-verifier',
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: 'signing-worker-strict',
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId,
    walletSigningSessionId,
    walletSessionJwt: 'router-ab-wallet-session-jwt',
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
    rpId: 'localhost',
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
    chainTarget: ecdsaChainTarget,
    walletSigningSessionId: ecdsaWalletSigningSessionId,
    thresholdSessionId: ecdsaThresholdSessionId,
  });
}

function makeEcdsaRouterAbNormalSigning(): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      context: {
        wallet_id: ecdsaWalletId,
        rp_id: 'localhost',
        key_scope: 'evm-family',
        ecdsa_threshold_key_id: ecdsaThresholdKeyId,
        signing_root_id: ecdsaSigningRootId,
        signing_root_version: ecdsaSigningRootVersion,
        key_purpose: 'evm-family-signing',
        key_version: 'strict-test',
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
      rpId: 'localhost',
      chainTarget: ecdsaChainTarget,
      keyHandle: ecdsaKeyHandle,
      ecdsaThresholdKeyId,
      signingRootId: ecdsaSigningRootId,
      signingRootVersion: ecdsaSigningRootVersion,
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
    authMetadata: { rpId: 'localhost' },
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
    walletSigningSessionId: ecdsaWalletSigningSessionId,
    walletSessionJwt: 'router-ab-ecdsa-wallet-session-jwt',
    expiresAtMs: 2_000_000_000_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: ecdsaClientPublicKeyB64u,
    ethereumAddress: ecdsaOwnerAddress,
    updatedAtMs: 1_900_000_000_000,
    source: 'email_otp',
    emailOtpAuthContext: {
      policy: 'session',
      authMethod: 'email_otp',
      retention: 'session',
      reason: 'login',
      authSubjectId: 'strict-email-otp-auth-subject',
    },
    ...overrides,
  };
}

test.describe('selected signing capability strict persisted records', () => {
  test('rejects selected Ed25519 records missing worker-owned material handles', () => {
    const lane = makeLane();
    const record = makeEd25519Record();
    delete record.ed25519HssMaterialHandle;
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'pending_material',
      reason: 'missing_material_handle',
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
        'Selected Ed25519 session record is not Router A/B signable: missing_material_handle',
    });
  });

  test('rejects selected Ed25519 records that only carry stale raw client material', () => {
    const lane = makeLane();
    const record = makeEd25519Record({
      xClientBaseB64u: 'stale-raw-client-base',
    });
    delete record.ed25519HssMaterialHandle;
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'invalid',
      reason: 'raw_material_without_handle',
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
        'Selected Ed25519 session record is not Router A/B signable: raw_material_without_handle',
    });
  });

  test('accepts selected Ed25519 records only when Router A/B signing material is complete', () => {
    const lane = makeLane();
    const record = makeEd25519Record();
    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'signable',
      record,
      value: {
        curve: 'ed25519',
        thresholdSessionId,
        walletSigningSessionId,
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

  test('derives Ed25519 signing root identity from runtime policy scope', () => {
    const record = makeEd25519Record();
    delete record.signingRootId;
    delete record.signingRootVersion;

    expect(classifyRouterAbEd25519PersistedSigningRecord(record)).toMatchObject({
      kind: 'signable',
      record,
      value: {
        curve: 'ed25519',
        thresholdSessionId,
        walletSigningSessionId,
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
      message:
        'Selected Ed25519 session record is not Router A/B signable: missing_signing_root',
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
      message: 'Selected ECDSA session record is not Router A/B signable: missing_router_ab_state',
    });
  });

  test('accepts selected ECDSA records only when Router A/B signing state is complete', () => {
    const lane = makeEcdsaLane();
    const record = makeEcdsaRecord();
    expect(classifyRouterAbEcdsaHssPersistedSigningRecord(record)).toMatchObject({
      kind: 'signable',
      record,
      value: {
        curve: 'ecdsa',
        thresholdSessionId: ecdsaThresholdSessionId,
        walletSigningSessionId: ecdsaWalletSigningSessionId,
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
});
