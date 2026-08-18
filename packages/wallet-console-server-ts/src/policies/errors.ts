export class ConsolePolicyError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsolePolicyError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsolePolicyError(error: unknown): error is ConsolePolicyError {
  return error instanceof ConsolePolicyError;
}
