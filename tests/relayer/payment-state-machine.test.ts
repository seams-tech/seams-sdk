import { test, expect } from '@playwright/test';
import { canTransitionPaymentState, listAllowedPaymentTransitions } from '@seams-internal/console-server/billing';

test.describe('billing payment state machine', () => {
  test('exposes allowed transitions for CREATED', async () => {
    const transitions = listAllowedPaymentTransitions('CREATED');
    expect(transitions).toEqual(['ACTION_REQUIRED', 'PENDING', 'FAILED', 'CANCELED']);
  });

  test('blocks unsupported transitions', async () => {
    const result = canTransitionPaymentState({
      from: 'CREATED',
      to: 'SETTLED',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('transition_not_allowed');
    }
  });

  test('enforces confirmations before CONFIRMING -> SETTLED', async () => {
    const result = canTransitionPaymentState({
      from: 'CONFIRMING',
      to: 'SETTLED',
      observedConfirmations: 11,
      requiredConfirmations: 12,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('confirmation_threshold_not_met');
    }
  });

  test('blocks settle when confirmation timed out', async () => {
    const result = canTransitionPaymentState({
      from: 'CONFIRMING',
      to: 'SETTLED',
      observedConfirmations: 12,
      requiredConfirmations: 12,
      confirmationTimedOut: true,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('confirmation_timeout');
    }
  });

  test('allows settle when confirmations meet threshold', async () => {
    const result = canTransitionPaymentState({
      from: 'CONFIRMING',
      to: 'SETTLED',
      observedConfirmations: 12,
      requiredConfirmations: 12,
    });
    expect(result).toEqual({ ok: true });
  });
});
