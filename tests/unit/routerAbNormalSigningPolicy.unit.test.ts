import { expect, test } from '@playwright/test';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import {
  parseRouterAbNormalSigningServerPolicy,
  validateRouterAbNormalSigningServerPolicy,
} from '@server/core/ThresholdService/routerAbNormalSigningPolicy';

function routerAbState(signingWorkerId: string) {
  return {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId,
  };
}

test.describe('Router A/B normal-signing server policy', () => {
  test('accepts sessions scoped to the configured SigningWorker id', () => {
    const policy = parseRouterAbNormalSigningServerPolicy({
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'local-signing-worker',
    });

    expect(
      validateRouterAbNormalSigningServerPolicy({
        policy,
        requested: routerAbState('local-signing-worker'),
      }),
    ).toEqual({ ok: true, value: null });
  });

  test('rejects mismatched SigningWorker ids', () => {
    const policy = parseRouterAbNormalSigningServerPolicy({
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'local-signing-worker',
    });

    expect(
      validateRouterAbNormalSigningServerPolicy({
        policy,
        requested: routerAbState('other-signing-worker'),
      }),
    ).toEqual({
      ok: false,
      code: 'unauthorized',
      message:
        'sessionPolicy.routerAbNormalSigning.signingWorkerId is not allowed for this threshold server',
    });
  });

  test('rejects sessions missing Router A/B normal-signing policy', () => {
    const policy = parseRouterAbNormalSigningServerPolicy({
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'local-signing-worker',
    });

    expect(
      validateRouterAbNormalSigningServerPolicy({
        policy,
        requested: undefined,
      }),
    ).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'sessionPolicy.routerAbNormalSigning is required for Router A/B normal signing',
    });
  });

  test('fails startup without a configured SigningWorker id', () => {
    expect(() => parseRouterAbNormalSigningServerPolicy({})).toThrow(
      'Missing required server config: ROUTER_AB_NORMAL_SIGNING_WORKER_ID',
    );
  });
});
