export class ConsoleBillingError extends Error {
  readonly code: string;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(
    code: string,
    status: number,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ConsoleBillingError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleBillingError(error: unknown): error is ConsoleBillingError {
  return error instanceof ConsoleBillingError;
}

