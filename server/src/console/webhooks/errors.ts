export class ConsoleWebhookError extends Error {
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
    this.name = 'ConsoleWebhookError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleWebhookError(error: unknown): error is ConsoleWebhookError {
  return error instanceof ConsoleWebhookError;
}
