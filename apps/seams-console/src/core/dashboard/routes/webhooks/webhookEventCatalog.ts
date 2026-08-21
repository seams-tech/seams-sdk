import {
  CONSOLE_WEBHOOK_EVENT_CATEGORIES,
  type ConsoleWebhookEventCategory,
} from '@seams-internal/wallet-console-shared/webhookEventCategories';

export interface WebhookEventCategoryOption {
  value: ConsoleWebhookEventCategory;
  label: string;
  description: string;
}

/* The category is the first segment of every event type (`wallet.unlocked`
   selects `wallet`), so the token is shown next to the label rather than
   hidden behind prose. */
const WEBHOOK_EVENT_CATEGORY_COPY: Record<
  ConsoleWebhookEventCategory,
  { label: string; description: string }
> = {
  wallet: {
    label: 'Wallet activity',
    description: 'Wallet provisioning, configuration, and state changes.',
  },
  policy: {
    label: 'Policy changes',
    description: 'Policy publish, assignment, and approval events.',
  },
  auth: {
    label: 'Authentication',
    description: 'Authentication and identity lifecycle events.',
  },
  tx: {
    label: 'Transaction lifecycle',
    description: 'Transaction creation, signing, submission, and status transitions.',
  },
  billing: {
    label: 'Billing',
    description: 'Invoices, usage, and payment lifecycle events.',
  },
  session: {
    label: 'Session lifecycle',
    description: 'Session creation, refresh, and teardown events.',
  },
};

export const WEBHOOK_EVENT_CATEGORY_OPTIONS: readonly WebhookEventCategoryOption[] =
  CONSOLE_WEBHOOK_EVENT_CATEGORIES.map((value) => ({
    value,
    label: WEBHOOK_EVENT_CATEGORY_COPY[value].label,
    description: WEBHOOK_EVENT_CATEGORY_COPY[value].description,
  }));

export function webhookEventCategoryLabel(value: ConsoleWebhookEventCategory): string {
  return WEBHOOK_EVENT_CATEGORY_COPY[value].label;
}
