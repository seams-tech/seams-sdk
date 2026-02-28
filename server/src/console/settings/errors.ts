export class ConsoleSettingsError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleSettingsError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleSettingsError(error: unknown): error is ConsoleSettingsError {
  return error instanceof ConsoleSettingsError;
}
