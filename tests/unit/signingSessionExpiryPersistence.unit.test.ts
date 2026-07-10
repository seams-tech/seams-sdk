import { expect, test } from '@playwright/test';
import {
  buildDiscoveredLaneForRecord,
  syncSealedRefreshPolicyForLanes,
} from '@/core/signingEngine/session/availability/readiness';
import type { UpdateExactSealedSessionPolicyInput } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { clearAllStoredThresholdEd25519SessionRecords } from '@/core/signingEngine/session/persistence/records';
import { seedEd25519WarmSessionRecord } from './helpers/signingSessionRecord.fixtures';

test.describe('signing-session expiry persistence', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('updates an expired passkey Ed25519 seal instead of deleting its reauth anchor', async () => {
    const expiresAtMs = Date.now() - 1_000;
    const record = seedEd25519WarmSessionRecord({
      nearAccountId: 'expired-passkey-ed25519.testnet',
      thresholdSessionId: 'threshold-expired-passkey-ed25519',
      signingGrantId: 'grant-expired-passkey-ed25519',
      expiresAtMs,
      remainingUses: 2,
      source: 'login',
    });
    const lane = buildDiscoveredLaneForRecord(record);
    if (!lane) throw new Error('Expected passkey Ed25519 lane fixture');

    const policyUpdates: UpdateExactSealedSessionPolicyInput[] = [];
    let deleteCalls = 0;
    await syncSealedRefreshPolicyForLanes({
      lanes: [lane],
      status: {
        sessionId: record.signingGrantId,
        status: 'expired',
        expiresAtMs,
        remainingUses: 2,
      },
      updatePolicy: async (update) => {
        policyUpdates.push(update);
      },
      deleteRecord: async () => {
        deleteCalls += 1;
      },
    });

    expect(deleteCalls).toBe(0);
    expect(policyUpdates).toHaveLength(1);
    expect(policyUpdates[0]).toMatchObject({
      thresholdSessionId: 'threshold-expired-passkey-ed25519',
      filter: {
        authMethod: 'passkey',
        curve: 'ed25519',
      },
      expiresAtMs,
      remainingUses: 2,
    });
  });
});
