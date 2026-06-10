export class ConsoleOnboardingError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleOnboardingError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleOnboardingError(error: unknown): error is ConsoleOnboardingError {
  return error instanceof ConsoleOnboardingError;
}

