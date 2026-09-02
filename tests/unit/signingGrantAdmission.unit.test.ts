import { expect, test } from '@playwright/test';
import {
  buildWalletSessionQuotaAdmissionQueueKey,
  classifyWalletSessionQuotaAdmissionFailure,
  decideWalletSessionQuotaAdmissionError,
  WalletSessionQuotaAdmissionError,
} from '../../packages/wallet/src/core/signingEngine/session/operationState/authorizationAdmission';
import { routerAbNormalSigningAdmissionErrorFromPayload } from '../../packages/wallet/src/core/rpcClients/relayer/routerAbNormalSigning';
import { signingLaneAuthBindingKey } from '../../packages/wallet/src/core/signingEngine/session/identity/signingLaneAuthBinding';
import {
  WALLET_SESSION_QUOTA_EXHAUSTED_ERROR,
  WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR,
} from '../../packages/wallet/src/core/signingEngine/session/operationState/authorizationAdmission';
import { SigningSessionCoordinator } from '../../packages/wallet/src/core/signingEngine/session/SigningSessionCoordinator';

test.describe('wallet-session quota admission boundary', () => {
  test('parses Router A/B exhausted payloads into typed admission errors', () => {
    const error = routerAbNormalSigningAdmissionErrorFromPayload({
      code: 'wallet_budget_exhausted',
      message: 'wallet-session quota exhausted',
      path: '/router-ab/ecdsa-derivation/sign/prepare',
      status: 409,
    });

    expect(error).toBeInstanceOf(WalletSessionQuotaAdmissionError);
    expect(error?.failure).toEqual({
      kind: 'exhausted',
      source: 'server_prepare',
      detail:
        'Router A/B signing /router-ab/ecdsa-derivation/sign/prepare returned HTTP 409: wallet-session quota exhausted',
    });
    expect(error?.message).toContain(WALLET_SESSION_QUOTA_EXHAUSTED_ERROR);
    expect(decideWalletSessionQuotaAdmissionError(error)).toEqual({
      kind: 'request_fresh_step_up',
      reason: 'exhausted',
      failure: error?.failure,
    });
  });

  test('parses Router A/B in-flight payloads into wait-and-retry decisions', () => {
    const error = routerAbNormalSigningAdmissionErrorFromPayload({
      code: 'wallet_budget_reserved',
      message: 'wallet-session quota reserved',
      path: '/router-ab/ed25519/sign/prepare',
      status: 409,
    });

    expect(error).toBeInstanceOf(WalletSessionQuotaAdmissionError);
    expect(error?.message).toContain(WALLET_SESSION_QUOTA_IN_FLIGHT_ERROR);
    expect(decideWalletSessionQuotaAdmissionError(error)).toEqual({
      kind: 'wait_and_retry_admission',
      retryAfterMs: 150,
      failure: error?.failure,
    });
  });

  test('classifies existing local admission errors at the shared boundary', () => {
    expect(
      classifyWalletSessionQuotaAdmissionFailure(new Error(WALLET_SESSION_QUOTA_EXHAUSTED_ERROR)),
    ).toEqual({
      kind: 'exhausted',
      source: 'local_projection',
      detail: WALLET_SESSION_QUOTA_EXHAUSTED_ERROR,
    });
  });

  test('builds queue keys from required admission identity fields', () => {
    expect(
      buildWalletSessionQuotaAdmissionQueueKey({
        walletId: 'wallet-1',
        curve: 'ecdsa',
        walletSessionId: 'wallet-session-1',
        quotaId: 'quota-1',
        projectionVersion: 'projection-1',
        authorityKey: signingLaneAuthBindingKey({
          kind: 'passkey',
          rpId: 'localhost',
          credentialIdB64u: 'credential-1',
        }),
        targetKey: 'tempo:42431',
      }),
    ).toBe(
      'wallet-session-quota-admission:wallet-1:ecdsa:wallet-session-1:quota-1:projection-1:passkey:localhost:credential-1:tempo:42431',
    );
  });

  test('queues concurrent fresh-admission retries behind the active refresh', async () => {
    const coordinator = new SigningSessionCoordinator({});
    const queueKey = buildWalletSessionQuotaAdmissionQueueKey({
      walletId: 'wallet-1',
      curve: 'ecdsa',
      walletSessionId: 'wallet-session-1',
      quotaId: 'quota-1',
      projectionVersion: 'projection-1',
      authorityKey: 'passkey',
      targetKey: 'evm:eip155:5042002',
    });
    const events: string[] = [];
    let releaseRefresh: (() => void) | null = null;
    const refreshStarted = new Promise<void>((resolve) => {
      const first = coordinator.runWalletSessionQuotaAdmissionRetry({
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

    const follower = coordinator.runWalletSessionQuotaAdmissionRetry({
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
