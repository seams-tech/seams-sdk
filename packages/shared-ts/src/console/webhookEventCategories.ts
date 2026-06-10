export const CONSOLE_WEBHOOK_EVENT_CATEGORIES = [
  'wallet',
  'policy',
  'auth',
  'tx',
  'billing',
  'session',
] as const;

export type ConsoleWebhookEventCategory = (typeof CONSOLE_WEBHOOK_EVENT_CATEGORIES)[number];

const CONSOLE_WEBHOOK_EVENT_CATEGORY_SET = new Set<string>(CONSOLE_WEBHOOK_EVENT_CATEGORIES);

export function normalizeConsoleWebhookEventCategory(
  value: unknown,
): ConsoleWebhookEventCategory | null {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (!CONSOLE_WEBHOOK_EVENT_CATEGORY_SET.has(normalized)) return null;
  return normalized as ConsoleWebhookEventCategory;
}

export function isConsoleWebhookEventCategory(
  value: unknown,
): value is ConsoleWebhookEventCategory {
  return normalizeConsoleWebhookEventCategory(value) !== null;
}
