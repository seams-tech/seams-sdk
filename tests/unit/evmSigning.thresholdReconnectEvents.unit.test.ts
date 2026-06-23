import { expect, test } from '@playwright/test';
import { ensureEvmFamilyThresholdEcdsaRecordReady } from '@/core/signingEngine/flows/signEvmFamily/ecdsaReadiness';
import {
  getThresholdEcdsaSessionRecordByKey,
  thresholdEcdsaRecordRpId,
} from '@/core/signingEngine/session/persistence/records';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import { buildEvmFamilyEcdsaKeyIdentityFromRecord } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import {
  buildEcdsaReconnectMaterial,
  buildEcdsaSessionIdentity,
  buildEcdsaSessionProvisionPlan,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  test('emits numbered v2 reconnect phases when ensuring stale threshold session readiness', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);
    const signingGrantId = 'wallet-session-reconnect-events';

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'reconnect-events.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-reconnect-events',
      sessionId: 'stale-reconnect-events-session',
      walletSessionJwt: 'jwt:stale-reconnect-events-session',
      signingGrantId,
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
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: staleRecord,
      rpId: thresholdEcdsaRecordRpId(staleRecord),
    });
    const lane = {
      ...selectedEcdsaLane({
        key,
        keyHandle: staleRecord.keyHandle,
        walletId: toWalletId('reconnect-events.testnet'),
        authMethod: 'passkey',
        signingGrantId,
        thresholdSessionId: staleRecord.thresholdSessionId,
        chainTarget: staleRecord.chainTarget,
      }),
      key,
      keyKind: 'threshold_ecdsa_secp256k1',
      chainFamily: 'evm',
      sessionOrigin: 'login',
      storageSource: 'login',
      retention: 'session',
    } as const;
    const reconnectSessionIdentity = buildEcdsaSessionIdentity({
      thresholdSessionId: String(lane.thresholdSessionId),
      signingGrantId: String(lane.signingGrantId),
    });
    const reconnectPlan = buildEcdsaSessionProvisionPlan({
      kind: 'ecdsa_session_reconnect',
      chainTarget: staleRecord.chainTarget,
      sessionIdentity: reconnectSessionIdentity,
      sessionBudgetUses: 3,
      reconnectMaterial: buildEcdsaReconnectMaterial({
        record: staleRecord,
      }),
    });
    if (reconnectPlan.kind !== 'wallet_session_ecdsa_reconnect') {
      throw new Error(`expected exact-record reconnect plan: ${reconnectPlan.kind}`);
    }

    const readyRecord = await ensureEvmFamilyThresholdEcdsaRecordReady({
      deps: {
        touchConfirm: {
          ...fixture.touchConfirm,
          claimWarmSessionMaterial: async ({ sessionId }: { sessionId: string }) => {
            if (String(sessionId) === staleRecord.thresholdSessionId) {
              return {
                ok: true as const,
                prfFirstB64u: `prf-first:${staleRecord.thresholdSessionId}`,
                remainingUses: 4,
                expiresAtMs: Date.now() + 120_000,
              };
            }
            return await fixture.touchConfirm.claimWarmSessionMaterial({ sessionId, uses: 1 });
          },
        },
        seamsWebConfigs: {
          registration: { mode: 'self' },
        },
        getEmailOtpThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        getPasskeyThresholdEcdsaSessionRecordForSigning: () => staleRecord,
        getThresholdEcdsaSessionRecordByKey: (identity: Parameters<typeof getThresholdEcdsaSessionRecordByKey>[1]) =>
          getThresholdEcdsaSessionRecordByKey(ecdsaStore, identity),
        clearThresholdEcdsaSessionRecordForWalletTarget: () => undefined,
        provisionThresholdEcdsaSession: async (request: {
          walletKey: {
            walletId: string;
          };
          lanePolicy: {
            chainTarget: typeof staleRecord.chainTarget;
          };
          sessionIdentity: {
            thresholdSessionId: string;
            signingGrantId: string;
          };
        }) => {
          const chainTarget = request.lanePolicy.chainTarget;
          const chain = chainTarget.kind;
          const sessionId = String(request.sessionIdentity.thresholdSessionId);
          const requestedSigningGrantId = String(
            request.sessionIdentity.signingGrantId,
          );
          provisionedChainIds.push(chainTarget.chainId);
          const freshBootstrap = createThresholdEcdsaBootstrapFixture({
            nearAccountId: 'reconnect-events.testnet',
            chain,
            ecdsaThresholdKeyId: 'ek-reconnect-events',
            sessionId,
            walletSessionJwt: `jwt:${sessionId}`,
            signingGrantId: requestedSigningGrantId,
          });
          const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
            nearAccountId: String(request.walletKey.walletId),
            chain,
            source: 'login',
            bootstrap: freshBootstrap,
            runtimeValidated: true,
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
      record: staleRecord,
      reconnectPlan,
      reconnectSessionIdentity,
      operationUsesNeeded: 1,
      sessionBudgetUses: 3,
      onEvent: (event: (typeof events)[number]) => events.push(event),
    });

    expect(readyRecord.thresholdSessionId).toBe('stale-reconnect-events-session');
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
