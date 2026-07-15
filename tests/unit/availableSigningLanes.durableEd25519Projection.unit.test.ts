import { expect, test } from '@playwright/test';
import type { AvailableSigningLanesRuntimeEd25519Record } from '@/core/signingEngine/session/availability/availableSigningLanes';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  AVAILABLE_LANES_ED25519_KEY_SCOPE_ID,
  AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID,
  AVAILABLE_LANES_ED25519_WALLET_ID,
  AVAILABLE_LANES_EXPIRES_AT_MS,
  readAvailableLanesFixture,
  runtimeEd25519RouterAbNormalSigningState,
} from './helpers/availableSigningLanes.fixtures';

const THRESHOLD_SESSION_ID = 'threshold-session-durable-ed25519-projection';

function durableEd25519ProjectionRecord(): AvailableSigningLanesRuntimeEd25519Record {
  return {
    auth: {
      kind: 'passkey',
      rpId: toRpId('wallet.example.localhost'),
      credentialIdB64u: 'credential-durable-ed25519-projection',
    },
    curve: 'ed25519',
    chain: 'near',
    walletId: AVAILABLE_LANES_ED25519_WALLET_ID,
    nearAccountId: AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: AVAILABLE_LANES_ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: 'signing-grant-durable-ed25519-projection',
    source: 'durable_sealed_record',
    remainingUses: 3,
    expiresAtMs: AVAILABLE_LANES_EXPIRES_AT_MS,
    updatedAtMs: 700,
  };
}

function durableEmailOtpEd25519ProjectionRecord(): AvailableSigningLanesRuntimeEd25519Record {
  return {
    auth: {
      kind: 'email_otp',
      providerSubjectId: 'google:durable-ed25519-projection',
    },
    curve: 'ed25519',
    chain: 'near',
    walletId: AVAILABLE_LANES_ED25519_WALLET_ID,
    nearAccountId: AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: AVAILABLE_LANES_ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
    thresholdSessionId: 'threshold-session-durable-email-otp-ed25519-projection',
    signingGrantId: 'signing-grant-durable-email-otp-ed25519-projection',
    source: 'durable_sealed_record',
    remainingUses: 3,
    expiresAtMs: AVAILABLE_LANES_EXPIRES_AT_MS,
    updatedAtMs: 701,
  };
}

test('keeps durable Ed25519 provenance when trusted budget state makes the lane ready', async () => {
  const availableLanes = await readAvailableLanesFixture({
    runtimeEd25519Records: [durableEd25519ProjectionRecord()],
    warmStatusAdvisories: new Map([
      [
        THRESHOLD_SESSION_ID,
        {
          kind: 'warm_status',
          status: 'active',
          thresholdSessionId: THRESHOLD_SESSION_ID,
          remainingUses: 3,
          expiresAtMs: AVAILABLE_LANES_EXPIRES_AT_MS,
        },
      ],
    ]),
  });

  expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
  expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
    state: 'ready',
    source: 'durable_sealed_record',
    signingGrantId: 'signing-grant-durable-ed25519-projection',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    remainingUses: 3,
  });
});

test('discovers the exact durable Email OTP Ed25519 lane after page refresh', async () => {
  const record = durableEmailOtpEd25519ProjectionRecord();
  const availableLanes = await readAvailableLanesFixture({
    runtimeEd25519Records: [record],
    warmStatusAdvisories: new Map([
      [
        record.thresholdSessionId,
        {
          kind: 'durable_policy',
          thresholdSessionId: record.thresholdSessionId,
          remainingUses: 3,
          expiresAtMs: AVAILABLE_LANES_EXPIRES_AT_MS,
          state: 'restorable',
        },
      ],
    ]),
  });

  expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
  expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
    auth: {
      kind: 'email_otp',
      providerSubjectId: 'google:durable-ed25519-projection',
    },
    state: 'restorable',
    source: 'durable_sealed_record',
    thresholdSessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId,
  });
});
