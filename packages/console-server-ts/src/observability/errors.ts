export class ConsoleObservabilityError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleObservabilityError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleObservabilityError(error: unknown): error is ConsoleObservabilityError {
  return error instanceof ConsoleObservabilityError;
}
