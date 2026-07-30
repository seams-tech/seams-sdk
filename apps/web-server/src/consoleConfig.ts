export interface WebServerConsoleConfig {
  stripeWebhookSigningSecret: string;
}

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

export function resolveWebServerConsoleConfig(
  env: Record<string, unknown>,
): WebServerConsoleConfig {
  return {
    stripeWebhookSigningSecret: normalizeString(env.STRIPE_WEBHOOK_SECRET),
  };
}

export function toOptionalSecret(secret: string): string | undefined {
  return normalizeString(secret) || undefined;
}
