export class ConsoleWalletError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(
    code: string,
    status: number,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'ConsoleWalletError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleWalletError(error: unknown): error is ConsoleWalletError {
  return error instanceof ConsoleWalletError;
}
