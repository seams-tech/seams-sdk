import { expect, test } from '@playwright/test';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '@/core/signingEngine/session/warmCapabilities/transitions';
import { selectedEcdsaLane } from '@/core/signingEngine/session/identity/laneIdentity';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';
import type { WarmSessionEnvelope } from '@/core/signingEngine/session/warmCapabilities/types';

function createEnvelope(): WarmSessionEnvelope {
  return {
    walletId: 'transition-summary.testnet' as any,
    capabilities: {
      ed25519: {
        capability: 'ed25519',
        record: {
          nearAccountId: 'transition-summary.testnet',
          thresholdSessionId: 'ed25519-session',
          thresholdSessionKind: 'jwt',
        } as any,
        auth: {
          capability: 'ed25519',
          record: {} as any,
          walletSessionJwt: 'jwt:ed25519-session',
          walletSessionJwtSource: 'ed25519_record',
        },
        prfClaim: {
          state: 'warm',
          sessionId: 'ed25519-session',
          remainingUses: 4,
          expiresAtMs: 1234,
        },
        state: 'ready',
      },
      ecdsa: {
        evm: {
          capability: 'ecdsa',
          record: null,
          key: null,
          lane: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
        tempo: {
          ...(function () {
            const chainTarget = testEcdsaChainTarget('tempo');
            const key = {
              walletId: 'transition-summary.testnet',
              subjectId: 'wallet-transition',
              rpId: 'example.localhost',
              keyScope: 'evm-family',
              ecdsaThresholdKeyId: 'ek-tempo',
              signingRootId: 'signing-root',
              signingRootVersion: 'default',
              participantIds: [1, 2],
              thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
            } as any;
            const lane = selectedEcdsaLane({
              key,
              keyHandle: 'ek-tempo-handle',
              walletId: 'transition-summary.testnet' as any,
              auth: {
                kind: 'passkey',
                rpId: 'example.localhost' as any,
                credentialIdB64u: 'credential-transition-summary',
              },
              signingGrantId: 'wallet-tempo-session',
              thresholdSessionId: 'tempo-session',
              chainTarget,
            });
            return {
              capability: 'ecdsa' as const,
              record: {
                walletId: 'transition-summary.testnet',
                subjectId: toWalletId(key.walletId),
                rpId: 'example.localhost',
                chainTarget,
                ecdsaThresholdKeyId: key.ecdsaThresholdKeyId,
                signingRootId: key.signingRootId,
                signingRootVersion: key.signingRootVersion,
                participantIds: [1, 2],
                ethereumAddress: `0x${'11'.repeat(20)}`,
                thresholdSessionId: 'tempo-session',
                signingGrantId: 'wallet-tempo-session',
                thresholdSessionKind: 'jwt',
                relayerUrl: 'https://relay.example',
                relayerKeyId: 'relayer-key',
                clientVerifyingShareB64u: 'AQ',
                expiresAtMs: Date.now() + 120_000,
                remainingUses: 2,
                source: 'login',
                updatedAtMs: Date.now(),
              } as any,
              key,
              lane: {
                ...lane,
                key,
              },
            };
          })(),
          auth: {
            capability: 'ecdsa',
            state: 'ready',
            record: {} as any,
            walletSessionJwt: 'jwt:tempo-session',
            walletSessionJwtSource: 'ecdsa_record',
          },
          prfClaim: {
            state: 'unavailable',
            sessionId: 'tempo-session',
            code: 'worker_error',
          },
          state: 'prf_unavailable',
        },
      },
    },
    updatedAtMs: 5678,
  };
}

test.describe('warmSessionTransitions', () => {
  test('summarizes warm-session envelopes into transition snapshots', () => {
    expect(summarizeWarmSessionTransition(createEnvelope())).toMatchObject({
      walletId: 'transition-summary.testnet',
      updatedAtMs: 5678,
      capabilities: {
        ed25519: {
          state: 'ready',
          thresholdSessionId: 'ed25519-session',
          authState: 'present',
          prfClaimState: 'warm',
          remainingUses: 4,
          expiresAtMs: 1234,
        },
        ecdsa: {
          tempo: {
            state: 'prf_unavailable',
            thresholdSessionId: 'tempo-session',
            authState: 'present',
            prfClaimState: 'unavailable',
          },
        },
      },
    });
  });

  test('swallows synchronous transition callback failures', () => {
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    try {
      emitWarmSessionTransition({
        onTransition: () => {
          throw new Error('sync transition failure');
        },
        event: {
          type: 'ed25519_capability_provisioned',
          walletId: 'transition-summary.testnet' as any,
          thresholdSessionId: 'ed25519-session',
          before: summarizeWarmSessionTransition(createEnvelope()),
          after: summarizeWarmSessionTransition(createEnvelope()),
        },
      });
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(warnings[0][0]).toBe('[WarmSessionStore] warm-session transition callback failed');
  });

  test('swallows asynchronous transition callback failures', async () => {
    const warnings: unknown[][] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args);
    };
    try {
      const event: WarmSessionTransitionEvent = {
        type: 'ed25519_capability_provisioned',
        walletId: 'transition-summary.testnet' as any,
        thresholdSessionId: 'ed25519-session',
        before: summarizeWarmSessionTransition(createEnvelope()),
        after: summarizeWarmSessionTransition(createEnvelope()),
      };
      emitWarmSessionTransition({
        onTransition: async () => {
          throw new Error('async transition failure');
        },
        event,
      });
      await Promise.resolve();
      await Promise.resolve();
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings).toHaveLength(1);
    expect(warnings[0][0]).toBe('[WarmSessionStore] warm-session transition callback failed');
  });
});
