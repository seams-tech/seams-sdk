export class ConsoleAccountError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleAccountError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleAccountError(error: unknown): error is ConsoleAccountError {
  return error instanceof ConsoleAccountError;
}
