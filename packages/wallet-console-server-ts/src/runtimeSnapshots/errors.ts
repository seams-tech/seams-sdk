export class ConsoleRuntimeSnapshotError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleRuntimeSnapshotError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleRuntimeSnapshotError(error: unknown): error is ConsoleRuntimeSnapshotError {
  return error instanceof ConsoleRuntimeSnapshotError;
}
