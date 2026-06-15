import { stripTrailingSlashes } from '@shared/utils/normalize';
import {
  parseRouterAbPublicKeysetV1,
  ROUTER_AB_PUBLIC_KEYSET_PATH_V1,
  type RouterAbPublicKeysetV1,
} from '@shared/utils/routerAbPublicKeyset';

function requireNonEmptyString(value: unknown, label: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

export async function fetchRouterAbPublicKeysetV1(args: {
  relayerUrl: string;
}): Promise<RouterAbPublicKeysetV1> {
  if (typeof fetch !== 'function') {
    throw new Error('fetch is not available for Router A/B public keyset prefetch');
  }
  const base = stripTrailingSlashes(requireNonEmptyString(args.relayerUrl, 'relayerUrl'));
  const response = await fetch(`${base}${ROUTER_AB_PUBLIC_KEYSET_PATH_V1}`, {
    method: 'GET',
    credentials: 'omit',
    headers: {
      Accept: 'application/json',
    },
  });
  if (!response.ok) {
    const errorText = await response.text().catch(() => '');
    throw new Error(
      `Router A/B public keyset returned HTTP ${response.status}${
        errorText ? `: ${errorText}` : ''
      }`,
    );
  }
  return parseRouterAbPublicKeysetV1(await response.json());
}
