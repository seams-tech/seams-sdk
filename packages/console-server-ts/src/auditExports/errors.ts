export class ConsoleAuditExportsError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleAuditExportsError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleAuditExportsError(error: unknown): error is ConsoleAuditExportsError {
  return error instanceof ConsoleAuditExportsError;
}
