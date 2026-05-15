import { expect, test } from '@playwright/test';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from '@/core/signingEngine/flows/signEvmFamily/ecdsaReadiness';
import {
  getThresholdEcdsaKeyRefByKey,
  getThresholdEcdsaSessionRecordByKey,
} from '@/core/signingEngine/session/persistence/records';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { toAccountId } from '@/core/types/accountIds';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionUiConfirmFixture,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionStore.fixtures';

test.describe('EVM family threshold reconnect events', () => {
  test('emits numbered v2 reconnect phases when refreshing a stale threshold session', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const walletSigningSessionId = 'wallet-session-reconnect-events';

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect-events.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect-events',
      sessionId: 'stale-reconnect-events-session',
      sessionAuthToken: 'jwt:stale-reconnect-events-session',
      walletSigningSessionId,
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect-events.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: staleBootstrap,
    });
    const fixture = createWarmSessionUiConfirmFixture({
      claimsBySessionId: {
        [staleRecord.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });
    const events: any[] = [];
    const provisionedChainIds: unknown[] = [];
    const lane = {
      kind: 'selected_lane',
      walletId: toAccountId('reconnect-events.testnet'),
      authMethod: 'passkey',
      curve: 'ecdsa',
      chain: 'evm',
      keyKind: 'threshold_ecdsa_secp256k1',
      chainFamily: 'evm',
      subjectId: staleRecord.subjectId,
      chainTarget: staleRecord.chainTarget,
      ecdsaThresholdKeyId: staleRecord.ecdsaThresholdKeyId,
      signingRootId: staleRecord.signingRootId,
      signingRootVersion: staleRecord.signingRootVersion || 'default',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(staleRecord.thresholdSessionId),
      sessionOrigin: 'login',
      storageSource: 'login',
      retention: 'session',
    } as const;

    const readyKeyRef = await ensureEvmFamilyThresholdEcdsaKeyRefReady({
      deps: {
        touchConfirm: fixture.touchConfirm,
        seamsPasskeyConfigs: {
          registration: { mode: 'self' },
        },
        getEmailOtpThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
        getEmailOtpThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        getPasskeyThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
        getPasskeyThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        getThresholdEcdsaSessionRecordByKey: (identity: Parameters<typeof getThresholdEcdsaSessionRecordByKey>[1]) =>
          getThresholdEcdsaSessionRecordByKey(ecdsaStore, identity),
        getThresholdEcdsaKeyRefByKey: (identity: Parameters<typeof getThresholdEcdsaKeyRefByKey>[1]) =>
          getThresholdEcdsaKeyRefByKey(ecdsaStore, identity),
        clearThresholdEcdsaSessionRecordForLane: () => undefined,
        provisionThresholdEcdsaSession: async (request: {
          walletId: string;
          chainTarget: typeof staleRecord.chainTarget;
          sessionIdentity: {
            thresholdSessionId: string;
            walletSigningSessionId: string;
          };
        }) => {
          const chain = request.chainTarget.kind;
          const sessionId = String(request.sessionIdentity.thresholdSessionId);
          const requestedWalletSigningSessionId = String(
            request.sessionIdentity.walletSigningSessionId,
          );
          provisionedChainIds.push(request.chainTarget.chainId);
          const freshBootstrap = createThresholdEcdsaBootstrapFixture({
            nearAccountId: 'reconnect-events.testnet',
            chain,
            ecdsaThresholdKeyId: 'ek-reconnect-events',
            sessionId,
            sessionAuthToken: `jwt:${sessionId}`,
            walletSigningSessionId: requestedWalletSigningSessionId,
          });
          const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
            nearAccountId: String(request.walletId),
            chain,
            source: 'manual-bootstrap',
            bootstrap: freshBootstrap,
          });
          fixture.claimsBySessionId[refreshedRecord.thresholdSessionId] = {
            state: 'warm',
            remainingUses: refreshedRecord.remainingUses || 5,
            expiresAtMs: refreshedRecord.expiresAtMs || Date.now() + 120_000,
          };
          return freshBootstrap;
        },
      } as any,
      lane,
      chainId: 11_155_111,
      keyRef: undefined,
      mode: 'derive_from_lane',
      reconnectSessionIdentity: {
        thresholdSessionId: String(lane.thresholdSessionId),
        walletSigningSessionId: String(lane.walletSigningSessionId),
      },
      operationUsesNeeded: 1,
      sessionBudgetUses: 3,
      onEvent: (event) => events.push(event),
    });

    expect(readyKeyRef.thresholdSessionId).toBe('stale-reconnect-events-session');
    expect(events.map((event) => event.phase)).toEqual([
      SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    ]);
    expect(events.map((event) => event.step)).toEqual([9, 9]);
    expect(events.map((event) => event.status)).toEqual(['running', 'succeeded']);
    expect(events.map((event) => event.data?.chain)).toEqual(['evm', 'evm']);
    expect(provisionedChainIds).toEqual([11_155_111]);
  });
});
