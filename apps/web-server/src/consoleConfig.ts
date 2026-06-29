export interface WebServerConsoleConfig {
  consoleBillingStripeWebhookSecret: string;
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function resolveWebServerConsoleConfig(env: Record<string, unknown>): WebServerConsoleConfig {
  return {
    consoleBillingStripeWebhookSecret: normalizeString(env.CONSOLE_BILLING_STRIPE_WEBHOOK_SECRET),
  };
}

export function toOptionalSecret(secret: string): string | undefined {
  return normalizeString(secret) || undefined;
}
