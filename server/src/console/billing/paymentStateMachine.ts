export const PAYMENT_STATES = [
  'CREATED',
  'ACTION_REQUIRED',
  'PENDING',
  'CONFIRMING',
  'SETTLED',
  'PARTIALLY_SETTLED',
  'OVERPAID',
  'FAILED',
  'CANCELED',
  'EXPIRED',
  'REFUNDED',
  'DISPUTED',
] as const;

export type PaymentState = (typeof PAYMENT_STATES)[number];

export interface PaymentTransitionInput {
  from: PaymentState;
  to: PaymentState;
  observedConfirmations?: number;
  requiredConfirmations?: number;
  confirmationTimedOut?: boolean;
}

export type PaymentTransitionValidationResult =
  | { ok: true }
  | { ok: false; code: 'transition_not_allowed' | 'confirmation_threshold_not_met' | 'confirmation_timeout'; message: string };

const PAYMENT_STATE_TRANSITIONS: Record<PaymentState, ReadonlyArray<PaymentState>> = {
  CREATED: ['ACTION_REQUIRED', 'PENDING', 'FAILED', 'CANCELED'],
  ACTION_REQUIRED: ['PENDING', 'FAILED', 'CANCELED', 'EXPIRED'],
  PENDING: ['CONFIRMING', 'SETTLED', 'PARTIALLY_SETTLED', 'OVERPAID', 'FAILED', 'CANCELED', 'EXPIRED'],
  CONFIRMING: ['SETTLED', 'PARTIALLY_SETTLED', 'OVERPAID', 'FAILED'],
  SETTLED: ['REFUNDED', 'DISPUTED'],
  PARTIALLY_SETTLED: [],
  OVERPAID: [],
  FAILED: [],
  CANCELED: [],
  EXPIRED: [],
  REFUNDED: [],
  DISPUTED: ['SETTLED', 'REFUNDED'],
};

export function listAllowedPaymentTransitions(state: PaymentState): ReadonlyArray<PaymentState> {
  return PAYMENT_STATE_TRANSITIONS[state];
}

export function canTransitionPaymentState(input: PaymentTransitionInput): PaymentTransitionValidationResult {
  const allowed = PAYMENT_STATE_TRANSITIONS[input.from];
  if (!allowed.includes(input.to)) {
    return {
      ok: false,
      code: 'transition_not_allowed',
      message: `Cannot transition payment from ${input.from} to ${input.to}`,
    };
  }

  if (input.from === 'CONFIRMING' && input.to === 'SETTLED') {
    if (input.confirmationTimedOut) {
      return {
        ok: false,
        code: 'confirmation_timeout',
        message: 'Cannot settle payment after confirmation timeout',
      };
    }

    const observed = Number(input.observedConfirmations ?? 0);
    const required = Number(input.requiredConfirmations ?? Number.POSITIVE_INFINITY);
    if (!Number.isFinite(observed) || !Number.isFinite(required) || observed < required) {
      return {
        ok: false,
        code: 'confirmation_threshold_not_met',
        message: 'Cannot settle payment before chain confirmation threshold is met',
      };
    }
  }

  return { ok: true };
}
