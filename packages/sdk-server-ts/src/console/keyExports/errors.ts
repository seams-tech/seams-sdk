export class ConsoleKeyExportError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleKeyExportError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleKeyExportError(error: unknown): error is ConsoleKeyExportError {
  return error instanceof ConsoleKeyExportError;
}
