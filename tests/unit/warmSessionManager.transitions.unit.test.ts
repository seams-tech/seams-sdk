import { expect, test } from '@playwright/test';
import {
  createWarmSessionManager,
  type WarmSessionTransitionEvent,
} from '@/core/signingEngine/session/WarmSessionManager';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  createWarmSessionTouchConfirmFixture,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionManager.fixtures';

test.describe('WarmSessionManager transitions and persistence assertions', () => {
  test('emits an Ed25519 provision transition after the persisted capability appears', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const transitions: WarmSessionTransitionEvent[] = [];
    const sessionId = 'ed25519-transition-session';
    const expiresAtMs = Date.now() + 120_000;
    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [sessionId]: {
          state: 'warm',
          remainingUses: 7,
          expiresAtMs,
        },
      }),
      onTransition: (event) => {
        transitions.push(event);
      },
      provisionThresholdEd25519Session: async ({ nearAccountId }) => {
        seedEd25519WarmSessionRecord({
          nearAccountId: String(nearAccountId),
          thresholdSessionId: sessionId,
          thresholdSessionJwt: `jwt:${sessionId}`,
          remainingUses: 7,
          expiresAtMs,
          source: 'login',
        });
        return {
          ok: true,
          sessionId,
          jwt: `jwt:${sessionId}`,
          remainingUses: 7,
          expiresAtMs,
        };
      },
    });

    await manager.provisionEd25519Capability({
      nearAccountId: 'transition-ed25519.testnet',
      relayerKeyId: 'rk-ed25519-transition',
    });

    expect(transitions).toHaveLength(1);
    expect(transitions[0]).toMatchObject({
      type: 'ed25519_capability_provisioned',
      accountId: 'transition-ed25519.testnet',
      thresholdSessionId: sessionId,
      before: {
        capabilities: {
          ed25519: {
            state: 'missing',
            thresholdSessionId: null,
          },
        },
      },
      after: {
        capabilities: {
          ed25519: {
            state: 'ready',
            thresholdSessionId: sessionId,
            prfClaimState: 'warm',
          },
        },
      },
    });
  });

  test('fails closed when Ed25519 provisioning returns success without persisting the capability record', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const sessionId = 'ed25519-unpersisted-session';
    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [sessionId]: {
          state: 'warm',
          remainingUses: 5,
          expiresAtMs: Date.now() + 120_000,
        },
      }),
      provisionThresholdEd25519Session: async () => ({
        ok: true,
        sessionId,
        jwt: `jwt:${sessionId}`,
        remainingUses: 5,
        expiresAtMs: Date.now() + 120_000,
      }),
    });

    await expect(
      manager.provisionEd25519Capability({
        nearAccountId: 'transition-unpersisted.testnet',
        relayerKeyId: 'rk-ed25519-unpersisted',
      }),
    ).rejects.toThrow(
      `[WarmSessionManager] provisioned Ed25519 capability was not persisted for transition-unpersisted.testnet (expected sessionId=${sessionId}, found=missing)`,
    );
  });

  test('emits ECDSA provision and reconnect transitions when a stale capability is reconnected', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const staleBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'transition-ecdsa.testnet',
      chain: 'evm',
      ecdsaThresholdKeyId: 'ek-transition-stale',
      sessionId: 'ecdsa-stale-session',
      sessionJwt: 'jwt:ecdsa-stale-session',
    });
    const staleRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'transition-ecdsa.testnet',
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

    const transitions: WarmSessionTransitionEvent[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: fixture.touchConfirm,
      onTransition: (event) => {
        transitions.push(event);
      },
      getThresholdEcdsaKeyRefForSigning: () => staleBootstrap.thresholdEcdsaKeyRef,
      provisionThresholdEcdsaSession: async ({ nearAccountId, chain }) => {
        const refreshedBootstrap = createThresholdEcdsaBootstrapFixture({
          nearAccountId: String(nearAccountId),
          chain,
          ecdsaThresholdKeyId: 'ek-transition-stale',
          sessionId: 'ecdsa-fresh-session',
          sessionJwt: 'jwt:ecdsa-fresh-session',
        });
        const refreshedRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
          nearAccountId: String(nearAccountId),
          chain,
          source: 'manual-bootstrap',
          bootstrap: refreshedBootstrap,
        });
        fixture.claimsBySessionId[refreshedRecord.thresholdSessionId] = {
          state: 'warm',
          remainingUses: refreshedRecord.remainingUses || 5,
          expiresAtMs: refreshedRecord.expiresAtMs || Date.now() + 120_000,
        };
        return refreshedBootstrap;
      },
    });

    await manager.ensureEcdsaCapabilityReady({
      nearAccountId: 'transition-ecdsa.testnet',
      chain: 'evm',
      usesNeeded: 1,
    });

    expect(transitions.map((event) => event.type)).toEqual([
      'ecdsa_capability_provisioned',
      'ecdsa_capability_reconnected',
    ]);
    expect(transitions[1]).toMatchObject({
      type: 'ecdsa_capability_reconnected',
      accountId: 'transition-ecdsa.testnet',
      chain: 'evm',
      thresholdSessionId: 'ecdsa-fresh-session',
      before: {
        capabilities: {
          ecdsa: {
            evm: {
              state: 'prf_missing',
              thresholdSessionId: 'ecdsa-stale-session',
            },
          },
        },
      },
      after: {
        capabilities: {
          ecdsa: {
            evm: {
              state: 'ready',
              thresholdSessionId: 'ecdsa-fresh-session',
              prfClaimState: 'warm',
            },
          },
        },
      },
    });
  });
});
