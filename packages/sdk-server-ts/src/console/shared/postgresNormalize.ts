export const CONSOLE_DEFAULT_NAMESPACE = 'console-default';

export function ensureConsoleNamespace(input?: string): string {
  const value = String(input || '').trim();
  return value || CONSOLE_DEFAULT_NAMESPACE;
}

export function toConsoleNumber(value: unknown, fallback = 0): number {
  if (typeof value === 'number') return value;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function toConsoleIso(ms: number | null | undefined): string | null {
  if (ms === null || ms === undefined) return null;
  if (!Number.isFinite(ms)) return null;
  return new Date(ms).toISOString();
}
