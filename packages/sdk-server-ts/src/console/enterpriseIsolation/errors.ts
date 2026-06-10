export class ConsoleEnterpriseIsolationError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleEnterpriseIsolationError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleEnterpriseIsolationError(
  error: unknown,
): error is ConsoleEnterpriseIsolationError {
  return error instanceof ConsoleEnterpriseIsolationError;
}
