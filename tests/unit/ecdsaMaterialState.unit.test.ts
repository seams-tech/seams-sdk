import { expect, test } from '@playwright/test';
import { base64UrlEncode } from '@shared/utils/base64';
import { ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND } from '@shared/utils/sessionTokens';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { buildEcdsaMaterialStateForCandidate } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState';
import { resolveEvmFamilyEcdsaPlannerReadiness } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/authPlanning';
import {
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaLaneCandidate } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import type { ThresholdEcdsaSessionRecord } from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import type { RouterAbEcdsaHssNormalSigningStateV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaHss';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import {
  buildEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation,
  markRouterAbEcdsaHssWorkerMaterialRuntimeValidated,
} from '../../packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession';
import {
  buildEcdsaEmailOtpSigningLane,
  buildEvmTransactionSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { requireResolvedEvmFamilyEcdsaSigningLane } from '../../packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes';

const EVM_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};

const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const CONTEXT_BINDING_32_B64U = base64UrlEncode(new Uint8Array(32).fill(8));
const STATE_BLOB_B64U = base64UrlEncode(new Uint8Array(64).fill(9));
const OWNER_ADDRESS = `0x${'aa'.repeat(20)}`;
const SIGNING_ROOT_ID = 'project:env';
const SIGNING_ROOT_VERSION = 'v1';
const WALLET_KEY_ID = 'wallet-key-material-state';
const PASSKEY_CREDENTIAL_ID = 'credential-material-state';
const PASSKEY_AUTH = {
  kind: 'passkey',
  rpId: toRpId('example.localhost'),
  credentialIdB64u: PASSKEY_CREDENTIAL_ID,
} as const;
const EMAIL_OTP_AUTH = {
  kind: 'email_otp',
  providerSubjectId: 'email:alice',
} as const;

const TEMPO_CHAIN_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 1,
  networkSlug: 'tempo-1',
};

function ethereumAddress20B64u(address: string): string {
  const hex = address.replace(/^0x/i, '');
  const bytes = new Uint8Array(hex.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) ?? []);
  return base64UrlEncode(bytes);
}

function makeWalletSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  const encode = (value: object): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
    kind: ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    exp: 1_900_000_000,
  })}.signature`;
}

async function readyWarmSessionStatus() {
  return {
    ok: true,
    remainingUses: 3,
    expiresAtMs: 1_900_000_000_000,
  } as const;
}

function makeRouterAbEcdsaHssNormalSigningState(): RouterAbEcdsaHssNormalSigningStateV1 {
  return {
    kind: 'router_ab_ecdsa_hss_normal_signing_v1',
    scope: {
      wallet_key_id: WALLET_KEY_ID,
      wallet_id: 'alice.testnet',
      ecdsa_threshold_key_id: 'ecdsa-key-1',
      signing_root_id: SIGNING_ROOT_ID,
      signing_root_version: SIGNING_ROOT_VERSION,
      context: {
        application_binding_digest_b64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      public_identity: {
        context_binding_b64u: CONTEXT_BINDING_32_B64U,
        client_public_key33_b64u: VALID_PUBLIC_KEY_B64U,
        server_public_key33_b64u: VALID_RELAYER_PUBLIC_KEY_B64U,
        threshold_public_key33_b64u: VALID_PUBLIC_KEY_B64U,
        ethereum_address20_b64u: ethereumAddress20B64u(OWNER_ADDRESS),
        client_share_retry_counter: 0,
        server_share_retry_counter: 0,
      },
      signing_worker: {
        server_id: 'signing-worker-1',
        key_epoch: 'worker-epoch-1',
        recipient_encryption_key:
          'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
      activation_epoch: 'activation-1',
    },
  };
}

function makeCandidate(): EcdsaLaneCandidate {
  const walletId = toWalletId('alice.testnet');
  return {
    kind: 'lane_candidate',
    walletId,
    key: buildEvmFamilyEcdsaKeyIdentity({
      walletId,
      walletKeyId: WALLET_KEY_ID,
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      participantIds: [1, 2],
      thresholdOwnerAddress: OWNER_ADDRESS,
    }),
    auth: PASSKEY_AUTH,
    curve: 'ecdsa',
    chain: 'evm',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
    signingGrantId: 'wallet-session-1',
    thresholdSessionId: 'threshold-session-1',
    state: 'ready',
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'runtime_session_record',
    chainTarget: EVM_CHAIN_TARGET,
  };
}

function makeResolvedLane() {
  const candidate = makeCandidate();
  return requireResolvedEvmFamilyEcdsaSigningLane({
    lane: buildEvmTransactionSigningLane({
      auth: PASSKEY_AUTH,
      key: candidate.key,
      keyHandle: candidate.keyHandle,
      walletId: candidate.walletId,
      chainTarget: candidate.chainTarget,
      signingGrantId: SigningSessionIds.signingGrant(candidate.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(candidate.thresholdSessionId),
      storageSource: 'login',
    }),
    chain: 'evm',
    context: 'ecdsaMaterialState.unit',
  });
}

function makeEmailOtpCandidate(): EcdsaLaneCandidate {
  const passkeyCandidate = makeCandidate();
  return {
    ...passkeyCandidate,
    auth: EMAIL_OTP_AUTH,
  };
}

function makeRoleLocalReadyRecord() {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: STATE_BLOB_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId('alice.testnet'),
      walletKeyId: WALLET_KEY_ID,
      chainTarget: EVM_CHAIN_TARGET,
      keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      ethereumAddress: OWNER_ADDRESS,
    }),
    authMethod: buildEcdsaRoleLocalPasskeyAuthMethod({
      credentialIdB64u: PASSKEY_CREDENTIAL_ID,
      rpId: 'example.localhost',
    }),
  });
}

function makeEmailOtpRoleLocalReadyRecord() {
  return buildEcdsaRoleLocalReadyRecord({
    stateBlob: {
      kind: 'ecdsa_role_local_state_blob_v1',
      curve: 'secp256k1',
      encoding: 'base64url',
      producer: 'signer_core',
      stateBlobB64u: STATE_BLOB_B64U,
    },
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: toWalletId('alice.testnet'),
      walletKeyId: WALLET_KEY_ID,
      chainTarget: EVM_CHAIN_TARGET,
      keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
      ecdsaThresholdKeyId: 'ecdsa-key-1',
      signingRootId: SIGNING_ROOT_ID,
      signingRootVersion: SIGNING_ROOT_VERSION,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      contextBinding32B64u: CONTEXT_BINDING_32_B64U,
      hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
      groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
      ethereumAddress: OWNER_ADDRESS,
    }),
    authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
      authSubjectId: 'email:alice',
    }),
  });
}

function makeRecord(
  overrides: Partial<Exclude<ThresholdEcdsaSessionRecord, { source: 'email_otp' }>> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: toWalletId('alice.testnet'),
    chainTarget: EVM_CHAIN_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
    ecdsaRoleLocalReadyRecord: makeRoleLocalReadyRecord(),
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'env',
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'wallet-session-1',
    walletSessionJwt: makeWalletSessionJwt({
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'wallet-session-1',
    }),
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(),
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
    authMetadata: { walletKeyId: 'example.localhost' },
    ...overrides,
  };
}

function makeEmailOtpRecord(): Extract<ThresholdEcdsaSessionRecord, { source: 'email_otp' }> {
  return {
    walletId: toWalletId('alice.testnet'),
    chainTarget: EVM_CHAIN_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: VALID_PUBLIC_KEY_B64U,
    ecdsaRoleLocalReadyRecord: makeEmailOtpRoleLocalReadyRecord(),
    participantIds: [1, 2],
    runtimePolicyScope: {
      orgId: 'org',
      projectId: 'project',
      envId: 'env',
      signingRootVersion: SIGNING_ROOT_VERSION,
    },
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'wallet-session-1',
    walletSessionJwt: makeWalletSessionJwt({
      thresholdSessionId: 'threshold-session-1',
      signingGrantId: 'wallet-session-1',
    }),
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    routerAbEcdsaHssNormalSigning: makeRouterAbEcdsaHssNormalSigningState(),
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: 1_800_000_000_000,
    source: 'email_otp',
    keyHandle: toEvmFamilyEcdsaKeyHandle('key-handle-1'),
    authMetadata: { walletKeyId: 'example.localhost' },
    emailOtpAuthContext: {
      authMethod: 'email_otp',
      policy: 'per_operation',
      reason: 'sign',
      retention: 'session',
      authSubjectId: 'email:alice',
    },
  };
}

test.describe('ecdsa material state', () => {
  test.afterEach(() => {
    clearRouterAbEcdsaHssWorkerMaterialRuntimeValidation();
  });

  test('rejects an explicit chainTarget that does not match the candidate', () => {
    expect(() =>
      buildEcdsaMaterialStateForCandidate({
        candidate: makeCandidate(),
        record: undefined,
        authMethod: 'passkey',
        source: 'login',
        chainTarget: TEMPO_CHAIN_TARGET,
        materialChainTarget: TEMPO_CHAIN_TARGET,
      }),
    ).toThrow(
      '[SigningEngine][ecdsa] material-state builder chain target must match candidate chain target',
    );
  });

  test('keeps unvalidated ready-state blob records out of ready signer material', async () => {
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record: makeRecord(),
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('reauth_required');
    if (state.kind !== 'reauth_required') return;
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);

    const readiness = await resolveEvmFamilyEcdsaPlannerReadiness({
      deps: {
        touchConfirm: {
          getWarmSessionStatus: readyWarmSessionStatus,
        },
        signingSessionCoordinator: new SigningSessionCoordinator(),
      },
      lane: makeResolvedLane(),
      material: state,
    });

    expect(readiness.readiness.status).toBe('missing_session');
    expect(readiness.remainingUses).toBe(0);
  });

  test('runtime-validated ready material carries a signer session', () => {
    const record = makeRecord();
    expect(markRouterAbEcdsaHssWorkerMaterialRuntimeValidated(record)).toBe(true);
    const state = buildEcdsaMaterialStateForCandidate({
      candidate: makeCandidate(),
      record,
      authMethod: 'passkey',
      source: 'login',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });

    expect(state.kind).toBe('ready_to_sign');
    if (state.kind !== 'ready_to_sign') return;
    expect(state.signerSession.clientShare.kind).toBe('role_local_worker_share');
    expect(state.publicFacts.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
  });

  test('treats Email OTP record policy as reauth readiness until worker material is live', async () => {
    const record = makeEmailOtpRecord();
    const material = buildEcdsaMaterialStateForCandidate({
      candidate: makeEmailOtpCandidate(),
      record,
      authMethod: 'email_otp',
      source: 'email_otp',
      chainTarget: EVM_CHAIN_TARGET,
      materialChainTarget: EVM_CHAIN_TARGET,
    });
    const lane = buildEcdsaEmailOtpSigningLane({
      auth: EMAIL_OTP_AUTH,
      key: makeEmailOtpCandidate().key,
      keyHandle: record.keyHandle,
      walletId: record.walletId,
      chainTarget: EVM_CHAIN_TARGET,
      signingGrantId: SigningSessionIds.signingGrant(record.signingGrantId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(record.thresholdSessionId),
    });

    const readiness = await resolveEvmFamilyEcdsaPlannerReadiness({
      deps: {
        touchConfirm: {
          getWarmSessionStatus: async () => ({
            ok: true,
            remainingUses: 1,
            expiresAtMs: 1_900_000_000_000,
          }),
        },
        signingSessionCoordinator: new SigningSessionCoordinator(),
      },
      lane,
      material,
    });

    expect(readiness.readiness.status).toBe('missing_session');
    expect(readiness.remainingUses).toBe(0);
  });
});
