export class ConsoleOrganizationAccessError extends Error {
  readonly code: string;

  readonly status: number;

  readonly details: Readonly<Record<string, unknown>> | null;

  constructor(
    code: string,
    status: number,
    message: string,
    details: Readonly<Record<string, unknown>> | null = null,
  ) {
    super(message);
    this.name = 'ConsoleOrganizationAccessError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export function isConsoleOrganizationAccessError(
  error: unknown,
): error is ConsoleOrganizationAccessError {
  return error instanceof ConsoleOrganizationAccessError;
}
