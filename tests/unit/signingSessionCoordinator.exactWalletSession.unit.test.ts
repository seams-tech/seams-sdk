import { expect, test } from '@playwright/test';
import { configureIndexedDB, IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { toAccountId } from '@/core/types/accountIds';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { requireAuthoritativeExpiredWalletSessionAuthorizationBoundary } from '@/core/signingEngine/session/identity/clientSessionPersistenceState';
import { exactEd25519SigningLaneIdentityFromSelectedLane } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { buildNearTransactionSigningLane } from '@/core/signingEngine/session/operationState/lanes';
import {
  SigningSessionIds,
  SigningSessionPlanKind,
} from '@/core/signingEngine/session/operationState/types';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { SIGNING_SESSION_EXPIRY_DETECTION_SOURCES } from '@/core/types/sdkSentEvents';
import type { SigningSessionStatusCheck } from '@/core/signingEngine/session/lifecycle/walletSessionStatus';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { parseWalletSessionId } from '@shared/authorization/capabilityKinds';
import type { ActiveWalletSessionV1 } from '@shared/device-linking';
import {
  buildLinkedDeviceUnlockRuntimeFixture,
  type LinkedDeviceUnlockRuntimeFixture,
} from './helpers/linkedDeviceUnlockRuntime.fixtures';

configureIndexedDB({ mode: 'disabled' });

type ExactSessionRead = Awaited<
  ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
>;

function laneForFixture(fixture: LinkedDeviceUnlockRuntimeFixture) {
  return buildNearTransactionSigningLane({
    walletId: fixture.walletId,
    nearAccountId: toAccountId('linked-runtime.testnet'),
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('near-ed25519-key:linked-runtime'),
    signerSlot: 1,
    auth: {
      kind: 'passkey',
      rpId: toRpId(fixture.authMethod.rpId),
      credentialIdB64u: fixture.authMethod.credentialIdB64u,
    },
    walletSessionId: fixture.operationCredential.walletSessionId,
    quotaId: SigningSessionIds.walletSessionQuota('wallet-quota:linked-runtime'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      'threshold-ed25519:linked-runtime',
    ),
    storageSource: 'registration',
  });
}

function installSelectedAuthority(fixture: LinkedDeviceUnlockRuntimeFixture): void {
  IndexedDBManager.resolveSelectedWalletAuthority = async () => ({
    kind: 'resolved',
    selection: fixture.selection,
    authMethod: fixture.authMethod,
    authority: fixture.authority,
    signerMaterials: fixture.signerMaterials,
    exportRoot: null,
  });
}

function installExactSessionRead(read: () => Promise<ExactSessionRead>): void {
  walletSessionAuthorizations.readExactWithOperationCredential = async () => await read();
}

async function withStubbedExactWalletSessionState(run: () => Promise<void>): Promise<void> {
  const originalResolveSelectedWalletAuthority = IndexedDBManager.resolveSelectedWalletAuthority;
  const originalReadExact = walletSessionAuthorizations.readExactWithOperationCredential;
  try {
    await run();
  } finally {
    IndexedDBManager.resolveSelectedWalletAuthority = originalResolveSelectedWalletAuthority;
    walletSessionAuthorizations.readExactWithOperationCredential = originalReadExact;
  }
}

test.describe('SigningSessionCoordinator exact Wallet Session reads', () => {
  test('plans a warm Ed25519 session from the exact credential-bound session identity', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const lane = laneForFixture(fixture);
    const statusChecks: SigningSessionStatusCheck[] = [];
    const coordinator = new SigningSessionCoordinator({
      getStatus: async (check) => {
        statusChecks.push(check);
        return {
          sessionId: String(check.authorization.walletSessionId),
          status: 'active',
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        };
      },
    });

    await withStubbedExactWalletSessionState(async () => {
      installSelectedAuthority(fixture);
      installExactSessionRead(async () => ({
        kind: 'found',
        record: fixture.activeWalletSession,
        operationCredential: fixture.operationCredential,
      }));

      const resolved = await coordinator.resolveAuthPlanFromReadiness({
        lane,
        readiness: {
          curve: 'ed25519',
          status: 'ready',
          thresholdSessionId: lane.thresholdSessionId,
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        },
        remainingUses: 3,
        expiresAtMs: Date.now() + 60_000,
        usesNeeded: 1,
      });

      expect(statusChecks).toHaveLength(1);
      expect(statusChecks[0]?.authorization).toEqual({
        walletSessionId: fixture.operationCredential.walletSessionId,
        quotaId: lane.quotaId,
      });
      expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.WarmSession);
    });
  });

  test('requires reauthorization when the exact credential names another Wallet Session', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const lane = laneForFixture(fixture);
    let statusReads = 0;
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => {
        statusReads += 1;
        return null;
      },
    });

    await withStubbedExactWalletSessionState(async () => {
      installSelectedAuthority(fixture);
      const siblingSessionId = parseWalletSessionId('wallet-session:sibling');
      if (!siblingSessionId.ok) throw new Error('sibling Wallet Session id fixture is invalid');
      installExactSessionRead(async () => ({
        kind: 'found',
        record: fixture.activeWalletSession,
        operationCredential: {
          ...fixture.operationCredential,
          walletSessionId: siblingSessionId.value,
        },
      }));

      const resolved = await coordinator.resolveAuthPlanFromReadiness({
        lane,
        readiness: {
          curve: 'ed25519',
          status: 'ready',
          thresholdSessionId: lane.thresholdSessionId,
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        },
        remainingUses: 3,
        expiresAtMs: Date.now() + 60_000,
        usesNeeded: 1,
      });

      expect(statusReads).toBe(0);
      expect(resolved.readiness.status).toBe('missing_session');
      expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
    });
  });

  test('fails closed to reauthorization when exact Wallet Session persistence is corrupt', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const lane = laneForFixture(fixture);
    let statusReads = 0;
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => {
        statusReads += 1;
        return null;
      },
    });

    await withStubbedExactWalletSessionState(async () => {
      installSelectedAuthority(fixture);
      installExactSessionRead(async () => {
        throw new Error('Stored Wallet Session authorization v5 is corrupt');
      });

      const resolved = await coordinator.resolveAuthPlanFromReadiness({
        lane,
        readiness: {
          curve: 'ed25519',
          status: 'ready',
          thresholdSessionId: lane.thresholdSessionId,
          remainingUses: 3,
          expiresAtMs: Date.now() + 60_000,
        },
        remainingUses: 3,
        expiresAtMs: Date.now() + 60_000,
        usesNeeded: 1,
      });

      expect(statusReads).toBe(0);
      expect(resolved.readiness.status).toBe('missing_session');
      expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
    });
  });

  test('invalidates an expired Wallet Session through its exact operation credential', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const lane = laneForFixture(fixture);
    const detectedAtMs = Date.now();
    const expiredSession: ActiveWalletSessionV1 = {
      ...fixture.activeWalletSession,
      expiresAtMs: detectedAtMs - 60_000,
    };
    const clearedThresholdSessionIds: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      touchConfirm: {
        clearVolatileWarmSessionMaterial: async (command) => {
          clearedThresholdSessionIds.push(String(command.scope.thresholdSessionId));
        },
      },
      clearEmailOtpWarmSessionMaterial: async () => {
        throw new Error('passkey lane cleanup must not clear Email OTP material');
      },
    });

    await withStubbedExactWalletSessionState(async () => {
      installSelectedAuthority(fixture);
      installExactSessionRead(async () => ({
        kind: 'found',
        record: expiredSession,
        operationCredential: fixture.operationCredential,
      }));

      const result = await coordinator.invalidateExpiredWalletSession({
        state: requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
          source: {
            kind: 'ed25519',
            laneIdentity: exactEd25519SigningLaneIdentityFromSelectedLane(lane),
          },
          expiresAtMs: expiredSession.expiresAtMs,
          detectedAtMs,
        }),
        source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
      });

      expect(result.kind).toBe('invalidated');
      if (result.kind !== 'invalidated') throw new Error('expiry invalidation did not run');
      expect(result.event.walletSessionId).toBe(fixture.operationCredential.walletSessionId);
      expect(clearedThresholdSessionIds).toEqual([String(lane.thresholdSessionId)]);
    });
  });

  test('leaves warm material installed when no exact session authorizes the expiry claim', async () => {
    const fixture = await buildLinkedDeviceUnlockRuntimeFixture();
    const lane = laneForFixture(fixture);
    const detectedAtMs = Date.now();
    const clearedThresholdSessionIds: string[] = [];
    const coordinator = new SigningSessionCoordinator({
      touchConfirm: {
        clearVolatileWarmSessionMaterial: async (command) => {
          clearedThresholdSessionIds.push(String(command.scope.thresholdSessionId));
        },
      },
      clearEmailOtpWarmSessionMaterial: async () => undefined,
    });

    await withStubbedExactWalletSessionState(async () => {
      installSelectedAuthority(fixture);
      installExactSessionRead(async () => ({ kind: 'missing' }));

      const result = await coordinator.invalidateExpiredWalletSession({
        state: requireAuthoritativeExpiredWalletSessionAuthorizationBoundary({
          source: {
            kind: 'ed25519',
            laneIdentity: exactEd25519SigningLaneIdentityFromSelectedLane(lane),
          },
          expiresAtMs: detectedAtMs - 60_000,
          detectedAtMs,
        }),
        source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.serverRejection,
      });

      expect(result).toEqual({
        kind: 'unavailable',
        failures: ['wallet_session_authorization'],
        event: null,
      });
      expect(clearedThresholdSessionIds).toEqual([]);
    });
  });
});
