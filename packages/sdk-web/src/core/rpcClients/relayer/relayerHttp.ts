import { stripTrailingSlashes } from '@shared/utils/normalize';

export type RelayerHttpHeaders = Readonly<Record<string, string>>;

export function normalizeRelayerBaseUrl(
  value: unknown,
  options: { trim: boolean } = { trim: true },
): string {
  const raw = String(value ?? '');
  return stripTrailingSlashes(options.trim ? raw.trim() : raw);
}

export function buildBearerAuthorizationHeader(args: {
  token: unknown;
  missingMessage: string;
}): Record<string, string> {
  const token = String(args.token ?? '').trim();
  if (!token) throw new Error(args.missingMessage);
  return { Authorization: `Bearer ${token}` };
}

export function buildRelayerJsonGetRequestInit(): RequestInit {
  return {
    method: 'GET',
    credentials: 'omit',
    headers: {
      Accept: 'application/json',
    },
  };
}

export function buildRelayerJsonPostRequestInit(args: {
  body: unknown;
  headers?: RelayerHttpHeaders;
  bodyJson?: string;
}): RequestInit {
  return {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(args.headers || {}),
    },
    credentials: 'omit',
    body: args.bodyJson ?? JSON.stringify(args.body),
  };
}
