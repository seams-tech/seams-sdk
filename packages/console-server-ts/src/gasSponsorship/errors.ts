export class ConsoleGasSponsorshipError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleGasSponsorshipError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleGasSponsorshipError(error: unknown): error is ConsoleGasSponsorshipError {
  return error instanceof ConsoleGasSponsorshipError;
}
