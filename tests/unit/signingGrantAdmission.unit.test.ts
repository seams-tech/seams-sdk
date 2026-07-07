import { expect, test } from '@playwright/test';
import {
  buildSigningGrantAdmissionQueueKey,
  classifySigningGrantAdmissionFailure,
  decideSigningGrantAdmissionError,
  routerAbNormalSigningAdmissionErrorFromPayload,
  SigningGrantAdmissionError,
  signingGrantAdmissionAuthorityKeyFromAuth,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/admission';
import {
  SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
  SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';

test.describe('signing grant admission boundary', () => {
  test('parses Router A/B exhausted payloads into typed admission errors', () => {
    const error = routerAbNormalSigningAdmissionErrorFromPayload({
      code: 'wallet_budget_exhausted',
      message: 'signing grant exhausted',
      path: '/router-ab/ecdsa-hss/sign/prepare',
      status: 409,
    });

    expect(error).toBeInstanceOf(SigningGrantAdmissionError);
    expect(error?.failure).toEqual({
      kind: 'exhausted',
      source: 'server_prepare',
      detail:
        'Router A/B signing /router-ab/ecdsa-hss/sign/prepare returned HTTP 409: signing grant exhausted',
    });
    expect(error?.message).toContain(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR);
    expect(decideSigningGrantAdmissionError(error)).toEqual({
      kind: 'request_fresh_step_up',
      reason: 'exhausted',
      failure: error?.failure,
    });
  });

  test('parses Router A/B in-flight payloads into wait-and-retry decisions', () => {
    const error = routerAbNormalSigningAdmissionErrorFromPayload({
      code: 'wallet_budget_reserved',
      message: 'signing grant reserved',
      path: '/router-ab/ed25519/sign/prepare',
      status: 409,
    });

    expect(error).toBeInstanceOf(SigningGrantAdmissionError);
    expect(error?.message).toContain(SIGNING_SESSION_BUDGET_IN_FLIGHT_ERROR);
    expect(decideSigningGrantAdmissionError(error)).toEqual({
      kind: 'wait_and_retry_admission',
      retryAfterMs: 150,
      failure: error?.failure,
    });
  });

  test('classifies existing local admission errors at the shared boundary', () => {
    expect(
      classifySigningGrantAdmissionFailure(new Error(SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR)),
    ).toEqual({
      kind: 'exhausted',
      source: 'local_projection',
      detail: SIGNING_SESSION_BUDGET_EXHAUSTED_ERROR,
    });
  });

  test('builds queue keys from required admission identity fields', () => {
    expect(
      buildSigningGrantAdmissionQueueKey({
        walletId: 'wallet-1',
        curve: 'ecdsa',
        signingGrantId: 'grant-1',
        projectionVersion: 'projection-1',
        authorityKey: signingGrantAdmissionAuthorityKeyFromAuth({
          kind: 'passkey',
          rpId: 'localhost',
          credentialIdB64u: 'credential-1',
        }),
        targetKey: 'tempo:42431',
      }),
    ).toBe(
      'signing-grant-admission:wallet-1:ecdsa:grant-1:projection-1:passkey:localhost:credential-1:tempo:42431',
    );
  });

  test('queues concurrent fresh-admission retries behind the active refresh', async () => {
    const coordinator = new SigningSessionCoordinator();
    const queueKey = buildSigningGrantAdmissionQueueKey({
      walletId: 'wallet-1',
      curve: 'ecdsa',
      signingGrantId: 'grant-1',
      projectionVersion: 'projection-1',
      authorityKey: 'passkey',
      targetKey: 'evm:eip155:5042002',
    });
    const events: string[] = [];
    let releaseRefresh: (() => void) | null = null;
    const refreshStarted = new Promise<void>((resolve) => {
      const first = coordinator.runSigningGrantAdmissionRetry({
        queueKey,
        refresh: async () => {
          events.push('refresh-started');
          resolve();
          await new Promise<void>((release) => {
            releaseRefresh = release;
          });
          events.push('refresh-finished');
          return 'leader';
        },
        retryAfterRefresh: async () => {
          events.push('leader-follower-unexpected');
          return 'leader-follower';
        },
      });
      void first.then((value) => {
        events.push(value);
      });
    });
    await refreshStarted;

    const follower = coordinator.runSigningGrantAdmissionRetry({
      queueKey,
      refresh: async () => {
        events.push('follower-refresh-unexpected');
        return 'follower-refresh';
      },
      retryAfterRefresh: async () => {
        events.push('follower-retried');
        return 'follower';
      },
    });

    expect(events).toEqual(['refresh-started']);
    releaseRefresh?.();
    await expect(follower).resolves.toBe('follower');
    expect(events).toEqual(['refresh-started', 'refresh-finished', 'leader', 'follower-retried']);
  });
});
