import { expect, test } from '@playwright/test';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertStoredThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';

const WALLET_ID = 'email-otp-ed25519-lane.testnet';
const ECDSA_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

test.describe('persisted Email OTP Ed25519 available signing lanes', () => {
  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('treats inline registration client material as ready without worker status', async () => {
    const thresholdSessionId = 'ed25519-registration-session';
    const signingGrantId = 'signing-grant-ed25519-registration';
    let emailOtpStatusReads = 0;
    let passkeyStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: WALLET_ID,
      rpId: 'localhost',
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'rk-email-otp-ed25519',
      participantIds: [1, 2],
      xClientBaseB64u: 'ed25519-registration-client-base',
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt: 'jwt-ed25519-registration',
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 1,
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    });

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => {
            passkeyStatusReads += 1;
            return { ok: false, code: 'not_found', message: 'missing' };
          },
        },
        getEmailOtpWarmSessionStatus: async () => {
          emailOtpStatusReads += 1;
          return { ok: false, code: 'not_found', message: 'missing' };
        },
      },
      {
        walletId: WALLET_ID,
        authMethod: 'email_otp',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );

    expect(emailOtpStatusReads).toBe(0);
    expect(passkeyStatusReads).toBe(0);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 1,
    });
  });

  test('treats freshly hydrated Email OTP material as ready before client-base caching', async () => {
    const thresholdSessionId = 'ed25519-registration-session-deferred-client-base';
    const signingGrantId = 'signing-grant-ed25519-deferred-client-base';
    let emailOtpStatusReads = 0;

    clearAllStoredThresholdEd25519SessionRecords();
    upsertStoredThresholdEd25519SessionRecord({
      nearAccountId: WALLET_ID,
      rpId: 'localhost',
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'rk-email-otp-ed25519',
      participantIds: [1, 2],
      thresholdSessionKind: 'jwt',
      thresholdSessionId,
      signingGrantId,
      walletSessionJwt: 'jwt-ed25519-registration',
      expiresAtMs: Date.now() + 120_000,
      remainingUses: 3,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      updatedAtMs: Date.now(),
      source: 'email_otp',
    });

    const lanes = await readPersistedAvailableSigningLanesForTargets(
      {
        ecdsaSessions: {
          recordsByLane: new Map(),
          exportArtifactsByLane: new Map(),
        },
        statusReader: {
          getWarmSessionStatus: async () => ({ ok: false, code: 'not_found', message: 'missing' }),
        },
        getEmailOtpWarmSessionStatus: async () => {
          emailOtpStatusReads += 1;
          return {
            ok: true,
            remainingUses: 3,
            expiresAtMs: Date.now() + 120_000,
          };
        },
      },
      {
        walletId: WALLET_ID,
        authMethod: 'email_otp',
        ecdsaChainTargets: [ECDSA_TARGET],
      },
    );

    expect(emailOtpStatusReads).toBe(1);
    expect(lanes.lanes.ed25519.near).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ed25519',
      chain: 'near',
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId,
      thresholdSessionId,
      remainingUses: 3,
    });
  });
});
