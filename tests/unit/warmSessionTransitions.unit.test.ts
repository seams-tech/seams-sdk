import { expect, test } from '@playwright/test';
import {
  emitWarmSessionTransition,
  summarizeWarmSessionTransition,
  type WarmSessionTransitionEvent,
} from '@/core/signingEngine/session/warmSessionTransitions';
import type { WarmSessionEnvelope } from '@/core/signingEngine/session/warmSessionTypes';

function createEnvelope(): WarmSessionEnvelope {
  return {
    accountId: 'transition-summary.testnet' as any,
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
          thresholdSessionJwt: 'jwt:ed25519-session',
          thresholdSessionJwtSource: 'ed25519',
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
          chain: 'evm',
          record: null,
          auth: null,
          prfClaim: null,
          state: 'missing',
        },
        tempo: {
          capability: 'ecdsa',
          chain: 'tempo',
          record: {
            nearAccountId: 'transition-summary.testnet',
            chain: 'tempo',
            thresholdSessionId: 'tempo-session',
            thresholdSessionKind: 'cookie',
          } as any,
          auth: {
            capability: 'ecdsa',
            chain: 'tempo',
            record: {} as any,
            thresholdSessionJwtSource: 'none',
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
      accountId: 'transition-summary.testnet',
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
          accountId: 'transition-summary.testnet' as any,
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
        accountId: 'transition-summary.testnet' as any,
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
