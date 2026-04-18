import type { Response as ExpressResponse } from 'express';
import type { RouteResponse } from './routeExecutionContext';
import type { RoutePolicyFailureCode } from './routeAuthPolicy';
import type { RouteUsageData } from './routeMeteringPolicy';

export interface RouteErrorBody {
  ok: false;
  code:
    | RoutePolicyFailureCode
    | 'internal'
    | 'invalid_body'
    | 'account_provisioning_failed'
    | 'access_key_not_provisioned'
    | 'wallet_id_collision'
    | 'registration_incomplete'
    | 'wallet_identity_mismatch';
  message: string;
}

export function routeJson<TBody>(
  status: number,
  body: TBody,
  options?: {
    headers?: Record<string, string>;
    usage?: RouteUsageData;
  },
): RouteResponse<TBody> {
  return {
    status,
    body,
    ...(options?.headers ? { headers: options.headers } : {}),
    ...(options?.usage ? { usage: options.usage } : {}),
  };
}

export function routeError(
  status: number,
  code: RouteErrorBody['code'],
  message: string,
): RouteResponse<RouteErrorBody> {
  return routeJson(status, { ok: false, code, message });
}

export function sendExpressRouteResponse<TBody>(
  res: ExpressResponse,
  response: RouteResponse<TBody>,
): void {
  for (const [name, value] of Object.entries(response.headers || {})) {
    res.set(name, value);
  }
  res.status(response.status).json(response.body);
}

export function toFetchRouteResponse<TBody>(response: RouteResponse<TBody>): Response {
  return new Response(JSON.stringify(response.body), {
    status: response.status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...(response.headers || {}),
    },
  });
}
