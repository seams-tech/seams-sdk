import {
  ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH,
  parseRouterAbEcdsaDerivationActivationRefreshRequestV1,
  type RouterAbEcdsaDerivationActivationRefreshRequestV1,
} from '@shared/utils/routerAbEcdsaDerivation';

export type RouterAbEcdsaDerivationRefreshAuthorization = {
  kind: 'bearer';
  token: string;
};

export type RouterAbEcdsaDerivationRefreshPortInput = {
  request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
  authorization: RouterAbEcdsaDerivationRefreshAuthorization;
};

export interface RouterAbEcdsaDerivationRefreshPort {
  refresh(input: RouterAbEcdsaDerivationRefreshPortInput): Promise<Response>;
}

export type RouterAbEcdsaDerivationRefreshHttpPortOptions = {
  strictRouterBaseUrl: string;
  fetch?: typeof fetch;
};

function normalizeStrictRouterBaseUrl(value: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error('strictRouterBaseUrl is required');
  const url = new URL(normalized);
  url.pathname = url.pathname.replace(/\/$/, '');
  url.search = '';
  url.hash = '';
  return url.toString().replace(/\/$/, '');
}

function requireBearerAuthorization(value: string | null): RouterAbEcdsaDerivationRefreshAuthorization {
  const normalized = String(value ?? '').trim();
  const separatorIndex = normalized.indexOf(' ');
  if (separatorIndex <= 0) {
    throw new Error('Router A/B ECDSA derivation refresh requires Bearer authorization');
  }
  const scheme = normalized.slice(0, separatorIndex);
  const token = normalized.slice(separatorIndex + 1).trim();
  if (scheme.toLowerCase() !== 'bearer' || !token || token.includes(' ')) {
    throw new Error('Router A/B ECDSA derivation refresh requires Bearer authorization');
  }
  return { kind: 'bearer', token };
}

export class HttpRouterAbEcdsaDerivationRefreshPort
  implements RouterAbEcdsaDerivationRefreshPort
{
  private readonly strictRouterBaseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RouterAbEcdsaDerivationRefreshHttpPortOptions) {
    this.strictRouterBaseUrl = normalizeStrictRouterBaseUrl(options.strictRouterBaseUrl);
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  async refresh(input: RouterAbEcdsaDerivationRefreshPortInput): Promise<Response> {
    const url = `${this.strictRouterBaseUrl}${ROUTER_AB_ECDSA_DERIVATION_REFRESH_PATH}`;
    return this.fetchImpl(url, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${input.authorization.token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(input.request),
    });
  }
}

export async function handleRouterAbEcdsaDerivationRefreshRoute(input: {
  body: unknown;
  authorizationHeader: string | null;
  port: RouterAbEcdsaDerivationRefreshPort | null | undefined;
}): Promise<Response> {
  if (!input.port) {
    return Response.json(
      {
        ok: false,
        code: 'not_configured',
        message: 'Router A/B ECDSA derivation refresh port is not configured',
      },
      { status: 503 },
    );
  }
  let authorization: RouterAbEcdsaDerivationRefreshAuthorization;
  try {
    authorization = requireBearerAuthorization(input.authorizationHeader);
  } catch (error: unknown) {
    return Response.json(
      {
        ok: false,
        code: 'unauthorized',
        message: error instanceof Error ? error.message : 'Bearer authorization is invalid',
      },
      { status: 401 },
    );
  }
  let request: RouterAbEcdsaDerivationActivationRefreshRequestV1;
  try {
    request = parseRouterAbEcdsaDerivationActivationRefreshRequestV1(input.body);
  } catch (error: unknown) {
    return Response.json(
      {
        ok: false,
        code: 'invalid_body',
        message: error instanceof Error ? error.message : 'Refresh request is invalid',
      },
      { status: 400 },
    );
  }
  return input.port.refresh({ request, authorization });
}
