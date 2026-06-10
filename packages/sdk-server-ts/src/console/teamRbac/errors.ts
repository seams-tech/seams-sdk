export class ConsoleTeamRbacError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details?: Record<string, unknown>;

  constructor(code: string, status: number, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = 'ConsoleTeamRbacError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleTeamRbacError(error: unknown): error is ConsoleTeamRbacError {
  return error instanceof ConsoleTeamRbacError;
}
