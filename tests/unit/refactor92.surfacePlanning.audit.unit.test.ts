import { expect, test } from '@playwright/test';
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
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-near-passkey-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
    'refactor-92-near-passkey-session',
  ),
  storageSource: 'login',
});
const NEAR_EMAIL_OTP_LANE = buildEd25519EmailOtpSigningLane({
  walletId: WALLET_ID,
  nearAccountId: NEAR_ACCOUNT_ID,
  nearEd25519SigningKeyId: NEAR_KEY_ID,
  signerSlot: 1,
  auth: EMAIL_OTP_AUTH,
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-near-otp-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
    'refactor-92-near-otp-session',
  ),
});
const TEMPO_PASSKEY_LANE = buildTempoTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: PASSKEY_AUTH,
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-tempo-passkey-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
    'refactor-92-tempo-passkey-session',
  ),
  storageSource: 'login',
});
const TEMPO_EMAIL_OTP_LANE = buildTempoTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: EMAIL_OTP_AUTH,
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-tempo-otp-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
    'refactor-92-tempo-otp-session',
  ),
});
const EVM_PASSKEY_LANE = buildEvmTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: PASSKEY_AUTH,
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 5042002,
    networkSlug: 'arc-testnet',
  },
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-evm-passkey-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
    'refactor-92-evm-passkey-session',
  ),
  storageSource: 'login',
});
const EVM_EMAIL_OTP_LANE = buildEvmTransactionSigningLane({
  key: ECDSA_KEY,
  keyHandle: ECDSA_KEY_HANDLE,
  walletId: WALLET_ID,
  auth: EMAIL_OTP_AUTH,
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 5042002,
    networkSlug: 'arc-testnet',
  },
  signingGrantId: SigningSessionIds.signingGrant('refactor-92-evm-otp-grant'),
  thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
    'refactor-92-evm-otp-session',
  ),
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
    expect(passkeyPlan.reconnect).toEqual({
      lane: fixture.passkeyLane,
      thresholdSessionId: fixture.passkeyLane.thresholdSessionId,
    });
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

for (const reason of ['auth_unavailable', 'status_unavailable', 'budget_unknown'] as const) {
  test(`Refactor 92 preserves ${reason} as terminal readiness`, () => {
    const plan = planSigningSession({
      lane: NEAR_PASSKEY_LANE,
      readiness: {
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

function expiredReadiness(
  lane: SelectedSigningSessionPlanningLane,
): SigningSessionReadiness {
  return {
    status: 'expired',
    thresholdSessionId: lane.thresholdSessionId,
    expiresAtMs: 1,
  };
}

function exhaustedReadiness(
  lane: SelectedSigningSessionPlanningLane,
): SigningSessionReadiness {
  return {
    status: 'exhausted',
    thresholdSessionId: lane.thresholdSessionId,
    remainingUses: 0,
    expiresAtMs: 2_000_000_000_000,
  };
}
