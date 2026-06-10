import { normalizeCorsOrigin } from '../../core/SessionService';

function normalizeOrigin(input: string): string {
  return normalizeCorsOrigin(input) || String(input || '').trim();
}

export function buildPublishableKeyOriginBlockedMessage(args: {
  origin: string;
  allowedOrigins: string[];
}): string {
  const origin = normalizeOrigin(args.origin) || '<missing-origin>';
  const allowedOrigins = Array.isArray(args.allowedOrigins)
    ? args.allowedOrigins.map((entry) => normalizeOrigin(entry)).filter(Boolean)
    : [];
  const allowedText = allowedOrigins.length > 0 ? allowedOrigins.join(', ') : '(none configured)';
  const localhostWalletHint =
    origin === 'https://localhost:8443' || allowedOrigins.includes('https://localhost')
      ? ' Managed registration runs from the wallet origin; in local dev also allow https://localhost:8443.'
      : '';
  return `Origin ${origin} is not allowed for this publishable key. Allowed origins: ${allowedText}.${localhostWalletHint}`;
}
