import { expect, test } from '@playwright/test';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  type ThresholdWarmSessionContext,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';

function warmSessionContext(): ThresholdWarmSessionContext {
  return {
    configs: {
      signing: {
        sessionDefaults: { ttlMs: 600_000, remainingUses: 3 },
        routerAb: {
          normalSigning: {
            mode: 'enabled',
            signingWorkerId: 'signing-worker-test',
          },
        },
      },
    },
    signingEngine: {},
  } as ThresholdWarmSessionContext;
}

test.describe('threshold warm-session policy draft', () => {
  test('can bind an Ed25519 policy to a prepared ECDSA signing grant', () => {
    const policy = createThresholdWarmSessionPolicyDraft(warmSessionContext(), {
      kind: 'shared_signing_grant',
      signingGrantId: 'wss_shared_registration_budget',
      ttlMs: 600_000,
      remainingUses: 3,
      participantIds: [1, 2],
    });

    expect(policy).toMatchObject({
      signingGrantId: 'wss_shared_registration_budget',
      ttlMs: 600_000,
      remainingUses: 3,
      participantIds: [1, 2],
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'signing-worker-test',
      },
    });
    if (!policy) throw new Error('expected warm-session policy');

    const envelope = buildThresholdWarmSessionRequestEnvelope({
      rpId: 'wallet.example.test',
      nearAccountId: 'alice.testnet',
      requestedPolicy: policy,
    });

    expect(envelope.session_policy).toMatchObject({
      rpId: 'wallet.example.test',
      nearAccountId: 'alice.testnet',
      signingGrantId: 'wss_shared_registration_budget',
      remainingUses: 3,
    });
  });
});
