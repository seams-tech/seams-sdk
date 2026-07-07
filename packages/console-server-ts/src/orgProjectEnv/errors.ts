export class ConsoleOrgProjectEnvError extends Error {
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
    this.name = 'ConsoleOrgProjectEnvError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleOrgProjectEnvError(error: unknown): error is ConsoleOrgProjectEnvError {
  return error instanceof ConsoleOrgProjectEnvError;
}
