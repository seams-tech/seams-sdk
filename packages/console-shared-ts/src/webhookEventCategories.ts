export const CONSOLE_WEBHOOK_EVENT_CATEGORIES = [
  'wallet',
  'policy',
  'auth',
  'tx',
  'billing',
  'session',
] as const;

export type ConsoleWebhookEventCategory = (typeof CONSOLE_WEBHOOK_EVENT_CATEGORIES)[number];

export function normalizeConsoleWebhookEventCategory(
  value: unknown,
): ConsoleWebhookEventCategory | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  for (const category of CONSOLE_WEBHOOK_EVENT_CATEGORIES) {
    if (category === normalized) return category;
  }
  return null;
}

export function isConsoleWebhookEventCategory(
  value: unknown,
): value is ConsoleWebhookEventCategory {
  return normalizeConsoleWebhookEventCategory(value) !== null;
}
