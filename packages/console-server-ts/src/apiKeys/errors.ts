export class ConsoleApiKeyError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleApiKeyError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleApiKeyError(error: unknown): error is ConsoleApiKeyError {
  return error instanceof ConsoleApiKeyError;
}
