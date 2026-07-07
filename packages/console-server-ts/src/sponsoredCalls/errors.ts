export class ConsoleSponsoredCallError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = 'ConsoleSponsoredCallError';
    this.code = String(code || 'internal').trim() || 'internal';
    this.status = Number(status) || 500;
  }
}

export function isConsoleSponsoredCallError(error: unknown): error is ConsoleSponsoredCallError {
  return error instanceof ConsoleSponsoredCallError;
}
