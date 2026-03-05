export class ConsoleApprovalsError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleApprovalsError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleApprovalsError(error: unknown): error is ConsoleApprovalsError {
  return error instanceof ConsoleApprovalsError;
}
