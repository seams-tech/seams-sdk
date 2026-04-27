import { expect, test } from '@playwright/test';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from '@/core/signingEngine/api/evmFamily/ecdsaReadiness';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';
import { toAccountId } from '@/core/types/accountIds';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionTouchConfirmFixture,
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
      sessionJwt: 'jwt:stale-reconnect-events-session',
      walletSigningSessionId,
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'reconnect-events.testnet',
      chain: 'evm',
      source: 'login',
      bootstrap: staleBootstrap,
    });
    const fixture = createWarmSessionTouchConfirmFixture({
      claimsBySessionId: {
        [staleRecord.thresholdSessionId]: {
          state: 'missing',
        },
      },
    });
    const freshBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect-events.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect-events',
      sessionId: 'fresh-reconnect-events-session',
      sessionJwt: 'jwt:fresh-reconnect-events-session',
      walletSigningSessionId,
    });
    const events: any[] = [];
    const lane = {
      accountId: toAccountId('reconnect-events.testnet'),
      authMethod: 'passkey',
      curve: 'ecdsa',
      keyKind: 'threshold_ecdsa_secp256k1',
      chainFamily: 'evm',
      walletSigningSessionId: SigningSessionIds.walletSigningSession(walletSigningSessionId),
      thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(staleRecord.thresholdSessionId),
      sessionOrigin: 'login',
      storageSource: 'login',
      retention: 'session',
    } as const;

    const readyKeyRef = await ensureEvmFamilyThresholdEcdsaKeyRefReady({
      deps: {
        touchConfirm: fixture.touchConfirm,
        tatchiPasskeyConfigs: {
          registration: { mode: 'self' },
        },
        getEmailOtpThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
        getEmailOtpThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        getPasskeyThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
        getPasskeyThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        clearThresholdEcdsaSessionRecordForLane: () => undefined,
        provisionThresholdEcdsaSession: async ({
          nearAccountId,
          chain,
        }: {
          nearAccountId: string;
          chain: 'evm' | 'tempo';
        }) => {
          const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
            nearAccountId: String(nearAccountId),
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
      keyRef: undefined,
      onEvent: (event) => events.push(event),
    });

    expect(readyKeyRef.thresholdSessionId).toBe('fresh-reconnect-events-session');
    expect(events.map((event) => event.phase)).toEqual([
      SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED,
      SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED,
    ]);
    expect(events.map((event) => event.step)).toEqual([9, 9]);
    expect(events.map((event) => event.status)).toEqual(['running', 'succeeded']);
    expect(events.map((event) => event.data?.chain)).toEqual(['evm', 'evm']);
  });
});
