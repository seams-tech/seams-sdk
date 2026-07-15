import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearAccountRefFromAccountId,
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { persistWarmSessionEd25519Capability } from '@/core/signingEngine/session/warmCapabilities/persistence';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  listStoredThresholdEd25519SessionLaneRecordsForWallet,
  thresholdEd25519LaneCandidateFromSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '@/core/signingEngine/session/persistence/records';
import { readPersistedAvailableSigningLanesForTargets } from '@/core/signingEngine/session/availability/persistedAvailableSigningLanes';
import { ed25519AvailableLaneIdentityKey } from '@/core/signingEngine/session/availability/availableSigningLanes';
import { resolveExactKeyExportLane } from '@/core/signingEngine/flows/recovery/exportLaneSelection';
import { runtimeEd25519RouterAbNormalSigningState } from './helpers/availableSigningLanes.fixtures';
import type { RestorePersistedSessionForSigningResult } from '@/core/signingEngine/session/sealedRecovery/sealedRecovery.types';

const WALLET_ID = toWalletId('email-otp-export-registration-lane');
const NEAR_ACCOUNT_ID = toAccountId('email-otp-export-registration-lane.testnet');
const NEAR_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString(
  'ed25519-email-otp-export-registration-lane',
);
const PROVIDER_SUBJECT = 'google:email-otp-export-registration-lane';
const THRESHOLD_SESSION_ID = 'threshold-email-otp-export-registration-lane';
const SIGNING_GRANT_ID = 'grant-email-otp-export-registration-lane';
const EXPIRES_AT_MS = Date.now() + 60_000;

function jsonB64u(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function ed25519WalletSessionJwt(): string {
  const header = jsonB64u({ alg: 'none', typ: 'JWT' });
  const payload = jsonB64u({
    kind: 'router_ab_ed25519_wallet_session_v1',
    walletId: String(WALLET_ID),
    nearAccountId: String(NEAR_ACCOUNT_ID),
    nearEd25519SigningKeyId: String(NEAR_SIGNING_KEY_ID),
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: SIGNING_GRANT_ID,
  });
  return `${header}.${payload}.fixture`;
}

function emptyEcdsaSessionStore(): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
  };
}

async function activeWarmSessionStatus() {
  return {
    ok: true as const,
    remainingUses: 3,
    expiresAtMs: EXPIRES_AT_MS,
  };
}

async function unexpectedPasskeyRestore(): Promise<RestorePersistedSessionForSigningResult> {
  throw new Error('Email OTP runtime export lane must not invoke passkey restore');
}

test.describe('Email OTP Ed25519 registration export lane', () => {
  test.beforeEach(clearAllStoredThresholdEd25519SessionRecords);
  test.afterEach(clearAllStoredThresholdEd25519SessionRecords);

  test('persists, inventories, and resolves one exact Email OTP Yao lane', async () => {
    persistWarmSessionEd25519Capability({
      kind: 'jwt_email_otp',
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      rpId: 'wallet.example.localhost',
      relayerUrl: 'https://relay.example.test',
      relayerKeyId: 'ed25519-signing-worker-email-otp-export',
      runtimePolicyScope: {
        orgId: 'org-email-otp-export',
        projectId: 'project-email-otp-export',
        envId: 'test',
        signingRootVersion: 'root-v1',
      },
      participantIds: [1, 2],
      signerSlot: 1,
      routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
      sessionId: THRESHOLD_SESSION_ID,
      signingGrantId: SIGNING_GRANT_ID,
      expiresAtMs: EXPIRES_AT_MS,
      remainingUses: 3,
      jwt: ed25519WalletSessionJwt(),
      emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
        policy: 'session',
        walletId: WALLET_ID,
        emailHashHex: '00'.repeat(32),
        reason: 'login',
        retention: 'session',
        provider: 'google',
        providerUserId: PROVIDER_SUBJECT,
      }),
      source: 'email_otp',
    });

    const runtimeRecords = listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID);
    expect(runtimeRecords).toHaveLength(1);
    const [runtimeRecord] = runtimeRecords;
    if (!runtimeRecord) throw new Error('Expected one persisted Email OTP Ed25519 runtime lane');
    const runtimeCandidate = thresholdEd25519LaneCandidateFromSessionRecord({
      record: runtimeRecord,
    });
    expect(runtimeCandidate).not.toBeNull();
    if (!runtimeCandidate) throw new Error('Expected one exact Email OTP Ed25519 runtime lane');
    expect(
      ed25519AvailableLaneIdentityKey({
        auth: runtimeCandidate.auth,
        curve: 'ed25519',
        chain: 'near',
        walletId: runtimeRecord.walletId,
        nearAccountId: runtimeRecord.nearAccountId,
        nearEd25519SigningKeyId: runtimeRecord.nearEd25519SigningKeyId,
        signerSlot: runtimeCandidate.signerSlot,
        signingGrantId: runtimeCandidate.signingGrantId,
        thresholdSessionId: runtimeCandidate.thresholdSessionId,
      }),
    ).not.toBeNull();

    const persistedLaneReader = readPersistedAvailableSigningLanesForTargets.bind(undefined, {
      ecdsaSessions: emptyEcdsaSessionStore(),
      statusReader: { getWarmSessionStatus: activeWarmSessionStatus },
      getEmailOtpWarmSessionStatus: activeWarmSessionStatus,
    });
    const available = await persistedLaneReader({
      walletId: WALLET_ID,
      ecdsaChainTargets: [],
    });
    expect(listStoredThresholdEd25519SessionLaneRecordsForWallet(WALLET_ID)).toHaveLength(1);

    expect({
      candidates: available.candidates.ed25519.near,
      invalidLanes: available.diagnostics?.invalidLanes,
    }).toEqual({
      invalidLanes: [],
      candidates: [
        expect.objectContaining({
          auth: { kind: 'email_otp', providerSubjectId: PROVIDER_SUBJECT },
          source: 'runtime_session_record',
          state: 'ready',
          thresholdSessionId: THRESHOLD_SESSION_ID,
        }),
      ],
    });

    const selected = await resolveExactKeyExportLane(
      {
        readPersistedAvailableSigningLanesForTargets: persistedLaneReader,
        restorePasskeyPersistedSessionForSigning: unexpectedPasskeyRestore,
      },
      {
        kind: 'ed25519',
        walletSession: walletSessionRefFromSession({
          walletId: WALLET_ID,
          walletSessionUserId: WALLET_ID,
        }),
        nearAccount: nearAccountRefFromAccountId(NEAR_ACCOUNT_ID),
      },
    );

    expect(selected).toEqual({
      kind: 'ed25519',
      laneIdentity: expect.objectContaining({
        auth: { kind: 'email_otp', providerSubjectId: PROVIDER_SUBJECT },
        signingGrantId: SIGNING_GRANT_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
      }),
    });
  });
});
