export class ConsoleBillingPrepaidReservationError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleBillingPrepaidReservationError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleBillingPrepaidReservationError(
  error: unknown,
): error is ConsoleBillingPrepaidReservationError {
  return error instanceof ConsoleBillingPrepaidReservationError;
}
