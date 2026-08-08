import { expect, test } from '@playwright/test';
import {
  buildDiscoveredLaneForRuntime,
  syncSealedRefreshPolicyForLanes,
} from '@/core/signingEngine/session/availability/readiness';
import type { UpdateExactSealedSessionPolicyInput } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { buildPasskeyEd25519SealedSessionRecordFixture } from './helpers/sealedSigningSession.fixtures';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';

test('updates an expired passkey Ed25519 seal and preserves its reauth anchor', async () => {
  const expiresAtMs = Date.now() - 1_000;
  const record = buildPasskeyEd25519SealedSessionRecordFixture({
    nearAccountId: 'expired-passkey-ed25519.testnet',
    thresholdSessionId: 'threshold-expired-passkey-ed25519',
    expiresAtMs,
    remainingUses: 2,
  });
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('Expected exact passkey Ed25519 runtime fixture');

  const policyUpdates: UpdateExactSealedSessionPolicyInput[] = [];
  await syncSealedRefreshPolicyForLanes({
    lanes: [
      buildDiscoveredLaneForRuntime(
        runtime,
        SigningSessionIds.walletSession('wallet-session-expired-passkey-ed25519'),
        SigningSessionIds.walletSessionQuota('quota-expired-passkey-ed25519'),
      ),
    ],
    status: {
      sessionId: 'wallet-session-expired-passkey-ed25519',
      status: 'expired',
      expiresAtMs,
      remainingUses: 2,
    },
    updatePolicy: async (update) => {
      policyUpdates.push(update);
    },
  });

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
