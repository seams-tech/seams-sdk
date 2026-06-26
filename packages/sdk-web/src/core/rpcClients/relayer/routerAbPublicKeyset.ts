import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_PATH,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import { buildRelayerJsonGetRequestInit, normalizeRelayerBaseUrl } from './relayerHttp';

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

export async function fetchRouterAbPublicKeysetV2(args: {
  relayerUrl: string;
}): Promise<RouterAbPublicKeysetV2> {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available for Router A/B public keyset prefetch');
  }
  const base = normalizeRelayerBaseUrl(requireNonEmptyString(args.relayerUrl, 'relayerUrl'));
  const response = await fetch(
    `${base}${ROUTER_AB_PUBLIC_KEYSET_PATH}`,
    buildRelayerJsonGetRequestInit(),
  );
  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(
      `Router A/B public keyset returned HTTP ${response.status}${
        errorText ? `: ${errorText}` : ''
      }`,
    );
  }
  return parseRouterAbPublicKeysetV2(await response.json());
}
