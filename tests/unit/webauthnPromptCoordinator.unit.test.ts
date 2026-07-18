import { expect, test } from '@playwright/test';
import {
  WebAuthnPromptCoordinator,
  WebAuthnPromptCoordinatorError,
} from '@/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnPromptCoordinator';
import { walletIframeRequestIdFromBoundary } from '@/core/types/walletIframeIdentity';

function registrationOwner(suffix = '1') {
  return {
    kind: 'registration_modal' as const,
    requestId: walletIframeRequestIdFromBoundary(`request-${suffix}`),
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

test.describe('WebAuthnPromptCoordinator', () => {
  test('transitions idle to reserved to running and starts inline', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const owner = registrationOwner();
    const reservation = await coordinator.reserveRegistrationPrompt({
      owner,
      expiresAtMs: Date.now() + 10_000,
      cancellation: { kind: 'none' },
    });
    expect(coordinator.snapshot().kind).toBe('reserved');

    const operation = deferred<string>();
    let startedInline = false;
    const result = coordinator.runReserved({
      reservation,
      owner,
      operation: () => {
        startedInline = true;
        return operation.promise;
      },
    });

    expect(startedInline).toBe(true);
    expect(coordinator.snapshot().kind).toBe('running');
    operation.resolve('ok');
    await expect(result).resolves.toBe('ok');
    await Promise.resolve();
    expect(coordinator.snapshot()).toEqual({ kind: 'idle' });
  });

  test('rejects owner mismatch and reservation reuse before invoking WebAuthn', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const owner = registrationOwner();
    const reservation = await coordinator.reserveRegistrationPrompt({
      owner,
      expiresAtMs: Date.now() + 10_000,
      cancellation: { kind: 'none' },
    });
    let calls = 0;

    expect(() =>
      coordinator.runReserved({
        reservation,
        owner: registrationOwner('2'),
        operation: async () => {
          calls += 1;
          return 'wrong';
        },
      }),
    ).toThrow(WebAuthnPromptCoordinatorError);
    expect(calls).toBe(0);

    await coordinator.runReserved({
      reservation,
      owner,
      operation: async () => 'ok',
    });
    expect(() =>
      coordinator.runReserved({
        reservation,
        owner,
        operation: async () => {
          calls += 1;
          return 'reused';
        },
      }),
    ).toThrow(/already consumed/);
    expect(calls).toBe(0);
  });

  test('waits for a running operation before granting a reservation', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const operation = deferred<void>();
    const running = coordinator.runImmediate({
      owner: { kind: 'wallet_request', requestId: 'auth-1', operation: 'authentication' },
      operation: () => operation.promise,
    });
    let reserved = false;
    const reservationPromise = coordinator
      .reserveRegistrationPrompt({
        owner: registrationOwner(),
        expiresAtMs: Date.now() + 10_000,
        cancellation: { kind: 'none' },
      })
      .then((reservation) => {
        reserved = true;
        return reservation;
      });

    await Promise.resolve();
    expect(reserved).toBe(false);
    operation.resolve();
    await running;
    const reservation = await reservationPromise;
    expect(reserved).toBe(true);
    expect(coordinator.snapshot().kind).toBe('reserved');
    coordinator.releaseReservation(reservation);
    expect(coordinator.snapshot().kind).toBe('idle');
    coordinator.releaseReservation(reservation);
    expect(coordinator.snapshot().kind).toBe('idle');
  });

  test('blocks competing operations and rejects expired reservations before invocation', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const owner = registrationOwner();
    const reservation = await coordinator.reserveRegistrationPrompt({
      owner,
      expiresAtMs: Date.now() + 20,
      cancellation: { kind: 'none' },
    });
    expect(() =>
      coordinator.runImmediate({
        owner: { kind: 'wallet_request', requestId: 'auth-2', operation: 'authentication' },
        operation: async () => undefined,
      }),
    ).toThrow(/owns the coordinator/);

    await new Promise((resolve) => setTimeout(resolve, 30));
    let calls = 0;
    expect(() =>
      coordinator.runReserved({
        reservation,
        owner,
        operation: async () => {
          calls += 1;
          return undefined;
        },
      }),
    ).toThrow(/expired/);
    expect(calls).toBe(0);
    expect(coordinator.snapshot().kind).toBe('idle');
  });

  test('aborts reservation acquisition while another prompt is running', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const operation = deferred<void>();
    const running = coordinator.runImmediate({
      owner: { kind: 'wallet_request', requestId: 'auth-3', operation: 'authentication' },
      operation: () => operation.promise,
    });
    const abortController = new AbortController();
    const reservation = coordinator.reserveRegistrationPrompt({
      owner: registrationOwner(),
      expiresAtMs: Date.now() + 10_000,
      cancellation: { kind: 'abort_signal', signal: abortController.signal },
    });
    abortController.abort();

    await expect(reservation).rejects.toThrow(/cancelled/);
    expect(coordinator.snapshot().kind).toBe('running');
    operation.resolve();
    await running;
    expect(coordinator.snapshot().kind).toBe('idle');
  });

  test('returns to idle when a reserved credential operation fails', async () => {
    const coordinator = new WebAuthnPromptCoordinator();
    const owner = registrationOwner();
    const reservation = await coordinator.reserveRegistrationPrompt({
      owner,
      expiresAtMs: Date.now() + 10_000,
      cancellation: { kind: 'none' },
    });
    const operation = coordinator.runReserved({
      reservation,
      owner,
      operation: async () => {
        throw new Error('wallet-origin create failed');
      },
    });

    await expect(operation).rejects.toThrow('wallet-origin create failed');
    await Promise.resolve();
    expect(coordinator.snapshot().kind).toBe('idle');
  });
});
