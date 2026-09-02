import { expect, test } from '@playwright/test';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { canonicalEcdsaAvailableLane } from './helpers/availableSigningLanes.fixtures';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEd25519EmailOtpSigningLane,
  buildEd25519PasskeySigningLane,
  buildEvmTransactionSigningLane,
  buildTempoTransactionSigningLane,
} from '@/core/signingEngine/session/operationState/lanes';
import {
  SigningSessionIds,
  SigningSessionPlanKind,
  type SelectedSigningSessionPlanningLane,
} from '@/core/signingEngine/session/operationState/types';
import {
  planSigningSession,
  type SigningSessionReadiness,
} from '@/core/signingEngine/session/planning/planner';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

type LaneFixture = {
  readonly name: 'near_ed25519' | 'tempo_ecdsa' | 'evm_ecdsa';
  readonly passkeyLane: SelectedSigningSessionPlanningLane;
  readonly emailOtpLane: SelectedSigningSessionPlanningLane;
};

const WALLET_ID = toWalletId('refactor-92-surface-wallet');
const NEAR_ACCOUNT_ID = toAccountId('refactor-92.testnet');
const NEAR_KEY_ID = nearEd25519SigningKeyIdFromString('refactor-92-near-key');
const PASSKEY_AUTH = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'refactor-92-passkey',
};
const EMAIL_OTP_AUTH = {
  kind: 'email_otp' as const,
  providerSubjectId: 'google:refactor-92',
};
const SIGNING_ROOT_ID = 'refactor-92:dev';
const SIGNING_ROOT_VERSION = 'default';
const ECDSA_KEY = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId: WALLET_ID,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: WALLET_ID,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
  }),
  ecdsaThresholdKeyId: 'refactor-92-ecdsa-key',
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'12'.repeat(20)}`,
});
const ECDSA_KEY_HANDLE = toEvmFamilyEcdsaKeyHandle('refactor-92-key-handle');

const NEAR_PASSKEY_LANE = buildEd25519PasskeySigningLane({
  walletId: WALLET_ID,
  nearAccountId: NEAR_ACCOUNT_ID,
  nearEd25519SigningKeyId: NEAR_KEY_ID,
  signerSlot: 1,
  auth: PASSKEY_AUTH,
  walletSessionId: SigningSessionIds.walletSession('refactor-92-near-passkey-session'),
  quotaId: SigningSessionIds.walletSessionQuota('refactor-92-near-passkey-quota'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session('refactor-92-near-passkey-session'),
  storageSource: 'login',
});
const NEAR_EMAIL_OTP_LANE = buildEd25519EmailOtpSigningLane({
  walletId: WALLET_ID,
  nearAccountId: NEAR_ACCOUNT_ID,
  nearEd25519SigningKeyId: NEAR_KEY_ID,
  signerSlot: 1,
  auth: EMAIL_OTP_AUTH,
  walletSessionId: SigningSessionIds.walletSession('refactor-92-near-otp-session'),
  quotaId: SigningSessionIds.walletSessionQuota('refactor-92-near-otp-quota'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session('refactor-92-near-otp-session'),
});
const ECDSA_MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'refactor-92-surface',
  String(WALLET_ID),
);
const ECDSA_CHAIN_TARGET = {
  kind: 'evm' as const,
  namespace: 'eip155' as const,
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};
const ECDSA_AUTHORIZATION = canonicalEcdsaAvailableLane({
  walletId: String(WALLET_ID),
  chainTarget: ECDSA_CHAIN_TARGET,
  thresholdOwnerAddress: `0x${'12'.repeat(20)}`,
  authMethod: 'passkey',
}).authorization;

const TEMPO_PASSKEY_LANE = buildTempoTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: PASSKEY_AUTH,
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
  materialActivation: ECDSA_MATERIAL_ACTIVATION,
  authorization: ECDSA_AUTHORIZATION,
  storageSource: 'login',
});
const TEMPO_EMAIL_OTP_LANE = buildTempoTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: EMAIL_OTP_AUTH,
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
  materialActivation: ECDSA_MATERIAL_ACTIVATION,
  authorization: ECDSA_AUTHORIZATION,
});
const EVM_PASSKEY_LANE = buildEvmTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: PASSKEY_AUTH,
  chainTarget: {
    ...ECDSA_CHAIN_TARGET,
  },
  materialActivation: ECDSA_MATERIAL_ACTIVATION,
  authorization: ECDSA_AUTHORIZATION,
  storageSource: 'login',
});
const EVM_EMAIL_OTP_LANE = buildEvmTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: EMAIL_OTP_AUTH,
  chainTarget: {
    ...ECDSA_CHAIN_TARGET,
  },
  materialActivation: ECDSA_MATERIAL_ACTIVATION,
  authorization: ECDSA_AUTHORIZATION,
});

const LANES: readonly LaneFixture[] = [
  { name: 'near_ed25519', passkeyLane: NEAR_PASSKEY_LANE, emailOtpLane: NEAR_EMAIL_OTP_LANE },
  { name: 'tempo_ecdsa', passkeyLane: TEMPO_PASSKEY_LANE, emailOtpLane: TEMPO_EMAIL_OTP_LANE },
  { name: 'evm_ecdsa', passkeyLane: EVM_PASSKEY_LANE, emailOtpLane: EVM_EMAIL_OTP_LANE },
];

for (const fixture of LANES) {
  test(`Refactor 92 plans same-method operation step-up for expired ${fixture.name}`, () => {
    const passkeyPlan = planSigningSession({
      lane: fixture.passkeyLane,
      readiness: expiredReadiness(fixture.passkeyLane),
    });
    const emailOtpPlan = planSigningSession({
      lane: fixture.emailOtpLane,
      readiness: expiredReadiness(fixture.emailOtpLane),
    });

    if (passkeyPlan.kind !== SigningSessionPlanKind.PasskeyReauth) {
      throw new Error(`Expected passkey reauthentication for ${fixture.name}`);
    }
    if (emailOtpPlan.kind !== SigningSessionPlanKind.EmailOtpReauth) {
      throw new Error(`Expected Email OTP reauthentication for ${fixture.name}`);
    }
    expect(passkeyPlan.lane).toBe(fixture.passkeyLane);
    expect(emailOtpPlan.lane).toBe(fixture.emailOtpLane);
    if (fixture.passkeyLane.curve === 'ed25519') {
      expect(passkeyPlan.reconnect).toEqual({
        lane: fixture.passkeyLane,
        curve: 'ed25519',
        thresholdSessionId: fixture.passkeyLane.thresholdSessionId,
      });
    } else {
      expect(passkeyPlan.reconnect).toEqual({
        lane: fixture.passkeyLane,
        curve: 'ecdsa',
        materialActivation: fixture.passkeyLane.materialActivation,
        authorization: fixture.passkeyLane.authorization,
      });
    }
    expect(emailOtpPlan.challenge).toEqual({
      chainFamily: fixture.emailOtpLane.chainFamily,
      lane: fixture.emailOtpLane,
    });
  });
}

test('Refactor 92 leaves exhausted lanes eligible for step-up without conflating expiry', () => {
  const passkeyPlan = planSigningSession({
    lane: EVM_PASSKEY_LANE,
    readiness: exhaustedReadiness(EVM_PASSKEY_LANE),
  });
  const emailOtpPlan = planSigningSession({
    lane: NEAR_EMAIL_OTP_LANE,
    readiness: exhaustedReadiness(NEAR_EMAIL_OTP_LANE),
  });
  expect(passkeyPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
  expect(emailOtpPlan.kind).toBe(SigningSessionPlanKind.EmailOtpReauth);
});

for (const reason of ['auth_unavailable', 'status_unavailable', 'status_unknown'] as const) {
  test(`Refactor 92 preserves ${reason} as terminal readiness`, () => {
    const plan = planSigningSession({
      lane: NEAR_PASSKEY_LANE,
      readiness: {
        curve: 'ed25519',
        status: reason,
        thresholdSessionId: NEAR_PASSKEY_LANE.thresholdSessionId,
      },
    });
    expect(plan).toEqual({
      kind: SigningSessionPlanKind.NotReady,
      lane: NEAR_PASSKEY_LANE,
      reason,
    });
  });
}

function expiredReadiness(lane: SelectedSigningSessionPlanningLane): SigningSessionReadiness {
  if (lane.curve === 'ecdsa') {
    return {
      curve: 'ecdsa',
      status: 'expired',
      materialActivation: lane.materialActivation,
      authorization: lane.authorization,
      expiresAtMs: 1,
    };
  }
  return {
    curve: 'ed25519',
    status: 'expired',
    thresholdSessionId: lane.thresholdSessionId,
    expiresAtMs: 1,
  };
}

function exhaustedReadiness(lane: SelectedSigningSessionPlanningLane): SigningSessionReadiness {
  if (lane.curve === 'ecdsa') {
    return {
      curve: 'ecdsa',
      status: 'exhausted',
      materialActivation: lane.materialActivation,
      authorization: lane.authorization,
      remainingUses: 0,
      expiresAtMs: 2_000_000_000_000,
    };
  }
  return {
    curve: 'ed25519',
    status: 'exhausted',
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: 0,
    expiresAtMs: 2_000_000_000_000,
  };
}
