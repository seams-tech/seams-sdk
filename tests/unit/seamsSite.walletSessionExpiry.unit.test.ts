import { expect, test } from '@playwright/test';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  createSigningSessionExpiredEvent,
  parseSdkLifecycleEvent,
  SIGNING_SESSION_EXPIRY_DETECTION_SOURCES,
} from '../../packages/sdk-web/src/core/types/sdkSentEvents';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  DemoWalletSessionLifecycleController,
  type DemoSigningSessionExpiredEvent,
} from '../../apps/seams-site/src/flows/demo/demoWalletSessionLifecycle';

const WALLET_ID = 'wallet-alpha';
const WALLET_SESSION_ID = 'wallet-session-alpha';

test('the public expiry parser preserves the event and strips secret fields', () => {
  const event = createSigningSessionExpiredEvent({
    walletId: toWalletId('refactor-92-demo-wallet'),
    walletSessionId: SigningSessionIds.signingGrant('refactor-92-demo-session'),
    authMethod: SIGNER_AUTH_METHODS.passkey,
    expiresAtMs: 1_000,
    detectedAtMs: 1_001,
    source: SIGNING_SESSION_EXPIRY_DETECTION_SOURCES.operationPreflight,
  });
  const parsed = parseSdkLifecycleEvent({
    ...event,
    jwt: 'secret-jwt',
    otp: '123456',
    prfOutput: 'secret-prf',
    privateKey: 'secret-private-key',
  });
  expect(parsed).toEqual(event);
  expect(parsed).not.toHaveProperty('jwt');
  expect(parsed).not.toHaveProperty('otp');
  expect(parsed).not.toHaveProperty('prfOutput');
  expect(parsed).not.toHaveProperty('privateKey');
});

test('active and restorable Wallet Sessions establish the exact reusable session', () => {
  for (const status of ['active', 'active_restorable'] as const) {
    const controller = new DemoWalletSessionLifecycleController();
    expect(
      controller.observeExactState(activeSession(status), 'restore'),
    ).toEqual({ kind: 'preserve_unlocked' });
    expect(controller.observeExpiredEvent(expiredEvent())).toEqual({
      kind: 'lock_expired',
      identity: exactIdentity(),
      source: 'operation_preflight',
    });
  }
});

test('expiry locks once and ignores events for a different wallet or session', () => {
  const controller = new DemoWalletSessionLifecycleController();
  controller.observeExactState(activeSession('active'), 'restore');

  expect(controller.observeExpiredEvent(expiredEvent('other-wallet'))).toEqual({
    kind: 'preserve_unlocked',
  });
  expect(
    controller.observeExpiredEvent(expiredEvent(WALLET_ID, 'other-session')),
  ).toEqual({ kind: 'preserve_unlocked' });
  expect(controller.observeExpiredEvent(expiredEvent())).toEqual({
    kind: 'lock_expired',
    identity: exactIdentity(),
    source: 'operation_preflight',
  });
  expect(controller.observeExpiredEvent(expiredEvent())).toEqual({
    kind: 'preserve_unlocked',
  });
});

test('restore, visibility, and focus checks lock only an exact expired session', () => {
  for (const source of ['restore', 'visibility', 'focus'] as const) {
    const controller = new DemoWalletSessionLifecycleController();
    expect(
      controller.observeExactState({
        kind: 'expired_session',
        walletId: WALLET_ID,
        walletSessionId: WALLET_SESSION_ID,
        authMethod: 'passkey',
        expiresAtMs: 2_000,
      }, source),
    ).toEqual({
      kind: 'lock_expired',
      identity: exactIdentity(),
      source,
    });
  }
});

test('preflight and server rejection events lock the tracked exact session', () => {
  for (const source of ['operation_preflight', 'server_rejection'] as const) {
    const controller = new DemoWalletSessionLifecycleController();
    controller.observeExactState(activeSession('active'), 'restore');
    expect(controller.observeExpiredEvent(expiredEvent(WALLET_ID, WALLET_SESSION_ID, source))).toEqual({
      kind: 'lock_expired',
      identity: exactIdentity(),
      source,
    });
  }
});

test('a genuinely missing signing session locks the selected wallet', () => {
  expect(
    new DemoWalletSessionLifecycleController().observeExactState({
      kind: 'wallet_unlocked_without_signing_session',
      walletId: WALLET_ID,
      reason: 'not_found',
    }, 'poll'),
  ).toEqual({
    kind: 'lock_missing_session',
    identity: { walletId: WALLET_ID, reason: 'not_found' },
  });
});

test('exhausted and unavailable states preserve the demo identity and wallet', () => {
  const reasons = [
    'exhausted',
    'unavailable',
    'budget_unknown',
    'invalid',
  ] as const;
  for (const reason of reasons) {
    expect(
      new DemoWalletSessionLifecycleController().observeExactState({
        kind: 'wallet_unlocked_without_signing_session',
        walletId: WALLET_ID,
        reason,
      }, 'poll'),
    ).toEqual({ kind: 'preserve_unlocked' });
  }
});

test('missing-session locking is deduplicated and can be released for retry', () => {
  const controller = new DemoWalletSessionLifecycleController();
  const state = {
    kind: 'wallet_unlocked_without_signing_session' as const,
    walletId: WALLET_ID,
    reason: 'not_found' as const,
  };
  const first = controller.observeExactState(state, 'poll');
  expect(first).toEqual({
    kind: 'lock_missing_session',
    identity: { walletId: WALLET_ID, reason: 'not_found' },
  });
  expect(controller.observeExactState(state, 'poll')).toEqual({ kind: 'preserve_unlocked' });
  if (first.kind !== 'lock_missing_session') {
    throw new Error('Expected a missing-session lock action');
  }

  controller.releaseMissingSessionLock(first.identity.walletId);

  expect(controller.observeExactState(state, 'poll')).toEqual(first);
});

test('expiry deduplication uses the exact wallet and session tuple', () => {
  const controller = new DemoWalletSessionLifecycleController();
  expireSelectedSession(controller, 'wallet:a', 'b:c');
  expect(expireSelectedSession(controller, 'wallet:a:b', 'c')).toEqual({
    kind: 'lock_expired',
    identity: {
      walletId: 'wallet:a:b',
      walletSessionId: 'c',
      authMethod: 'passkey',
      expiresAtMs: 2_000,
    },
    source: 'operation_preflight',
  });
});

test('a failed lock releases the exact session reservation for retry', () => {
  const controller = new DemoWalletSessionLifecycleController();
  controller.observeExactState(activeSession('active'), 'restore');
  const first = controller.observeExpiredEvent(expiredEvent());
  expect(first.kind).toBe('lock_expired');
  if (first.kind !== 'lock_expired') throw new Error('Expected an exact-session lock action');

  controller.releaseExpiredSessionLock(first.identity);

  expect(controller.observeExpiredEvent(expiredEvent())).toEqual({
    kind: 'lock_expired',
    identity: exactIdentity(),
    source: 'operation_preflight',
  });
});

test('a confirmed lock suppresses duplicate expiry for the exact session', () => {
  const controller = new DemoWalletSessionLifecycleController();
  controller.observeExactState(activeSession('active'), 'restore');
  const action = controller.observeExpiredEvent(expiredEvent());
  expect(action.kind).toBe('lock_expired');
  if (action.kind !== 'lock_expired') throw new Error('Expected an exact-session lock action');

  controller.confirmExpiredSessionLocked(action.identity);

  expect(controller.observeExpiredEvent(expiredEvent())).toEqual({ kind: 'preserve_unlocked' });
});

test('one session lock does not suppress a different exact session', () => {
  const controller = new DemoWalletSessionLifecycleController();
  const first = expireSelectedSession(controller, WALLET_ID, WALLET_SESSION_ID);
  expect(first.kind).toBe('lock_expired');

  expect(expireSelectedSession(controller, 'wallet-beta', 'wallet-session-beta')).toEqual({
    kind: 'lock_expired',
    identity: {
      walletId: 'wallet-beta',
      walletSessionId: 'wallet-session-beta',
      authMethod: 'passkey',
      expiresAtMs: 2_000,
    },
    source: 'operation_preflight',
  });
});

function expireSelectedSession(
  controller: DemoWalletSessionLifecycleController,
  walletId: string,
  walletSessionId: string,
) {
  controller.observeExactState({
    kind: 'active_session',
    walletId,
    walletSessionId,
    authMethod: 'passkey',
    expiresAtMs: 2_000,
    status: 'active',
  }, 'restore');
  return controller.observeExpiredEvent(expiredEvent(walletId, walletSessionId));
}

function activeSession(status: 'active' | 'active_restorable') {
  return {
    kind: 'active_session' as const,
    walletId: WALLET_ID,
    walletSessionId: WALLET_SESSION_ID,
    authMethod: 'passkey' as const,
    expiresAtMs: 2_000,
    status,
  };
}

function exactIdentity() {
  return {
    walletId: WALLET_ID,
    walletSessionId: WALLET_SESSION_ID,
    authMethod: 'passkey',
    expiresAtMs: 2_000,
  };
}

function expiredEvent(
  walletId = WALLET_ID,
  walletSessionId = WALLET_SESSION_ID,
  source: 'operation_preflight' | 'server_rejection' = 'operation_preflight',
): DemoSigningSessionExpiredEvent {
  const event = parseSdkLifecycleEvent({
    version: 1,
    event: 'signing_session.expired',
    walletId,
    walletSessionId,
    authMethod: 'passkey',
    expiresAtMs: 1_000,
    detectedAtMs: 1_001,
    source,
  });
  if (event === null) throw new Error('Test lifecycle event must be valid');
  return event;
}
