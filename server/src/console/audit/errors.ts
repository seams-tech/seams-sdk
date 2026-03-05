export class ConsoleAuditError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleAuditError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleAuditError(error: unknown): error is ConsoleAuditError {
  return error instanceof ConsoleAuditError;
}
