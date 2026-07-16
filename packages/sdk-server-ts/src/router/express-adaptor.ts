import express, {
  type NextFunction,
  type Request as ExpressRequest,
  type RequestHandler,
  type Response as ExpressResponse,
  type Router as ExpressRouter,
} from 'express';
import type { RouterApiServiceBag } from './authServicePort';
import { createCloudflareRouter } from './cloudflare/createCloudflareRouter';
import type { RouterApiOptions } from './routerApi';
import {
  attachRouterApiRouteSurface,
  getRouterApiRouteSurface,
} from './routerApiRouteSurface';

export type {
  RouterApiOptions,
  SessionAdapter,
  RouterApiKeyAuthFailureCode,
  RouterApiKeyAuthRequest,
  RouterApiKeyPrincipal,
  RouterApiKeyAuthResult,
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthFailureCode,
  RouterApiPublishableKeyAuthRequest,
  RouterApiPublishableKeyAuthResult,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiUsageMeterAction,
  RouterApiUsageMeterEvent,
  RouterApiUsageMeterAdapter,
  RouterApiBootstrapGrantMode,
  RouterApiBootstrapGrantFailureCode,
  RouterApiBootstrapGrantClientContext,
  RouterApiBootstrapGrantIssueRequest,
  RouterApiBootstrapGrant,
  RouterApiBootstrapGrantPaymentRequirement,
  RouterApiBootstrapGrantIssueResult,
  RouterApiBootstrapTokenRecord,
  RouterApiBootstrapGrantBroker,
  RouterApiRuntimePolicyScope,
  RouterApiRuntimeSnapshotEnvelope,
  RouterApiRuntimeSnapshotConsumer,
} from './routerApi';
export {
  ROUTER_AB_PUBLIC_KEYSET_PATH,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  ROUTER_AB_PUBLIC_KEYSET_WELL_KNOWN_PATH,
  parseRouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
export type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
export type {
  RouterAbNormalSigningAdmissionAdapter,
  RouterAbNormalSigningAdmissionFailure,
  RouterAbNormalSigningAdmissionFailureCode,
  RouterAbNormalSigningAdmissionInput,
  RouterAbNormalSigningAdmissionResult,
} from './routerAbPrivateSigningWorker';
export {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  InMemoryRouterAbNormalSigningAdmissionStore,
  createCloudflareDurableObjectRouterAbNormalSigningAdmissionStore,
  createInMemoryRouterAbNormalSigningAdmissionAdapter,
  createInMemoryRouterAbNormalSigningAdmissionStore,
  createRouterAbNormalSigningAdmissionAdapter,
} from './routerAbNormalSigningAdmissionStore';
export type {
  CloudflareDurableObjectRouterAbNormalSigningAdmissionStoreOptions,
  InMemoryRouterAbNormalSigningAdmissionStoreOptions,
  RouterAbNormalSigningAbuseDecision,
  RouterAbNormalSigningAbuseProvider,
  RouterAbNormalSigningAdmissionStore,
  RouterAbNormalSigningProjectPolicyDecision,
  RouterAbNormalSigningProjectPolicyProvider,
  RouterAbNormalSigningQuotaDecision,
  RouterAbNormalSigningQuotaStore,
} from './routerAbNormalSigningAdmissionStore';
export type {
  RouterApiCloudflareRouteExtension,
  RouterApiCloudflareRouteExtensionInput,
  RouterApiRouteExtension,
  RouterApiRouteExtensionTransport,
} from './routeExtensions';
export type {
  RouterApiModule,
  RouterApiModuleKind,
  RouterApiModuleOptions,
} from './modules';
export { createRouterApiModule } from './modules';
export type { RouteDefinition } from './routeDefinitions';
export { defineRoute } from './routeDefinitions';
export type {
  InMemoryRouterApiRuntimeSnapshotConsumer,
  RouterApiRuntimeSnapshotPublishedUpdate,
} from './runtimeSnapshotConsumer';
export {
  createInMemoryRouterApiRuntimeSnapshotConsumer,
  validateRuntimeSnapshotExpectation,
} from './runtimeSnapshotConsumer';

function appendExpressRequestHeaders(headers: Headers, req: ExpressRequest): void {
  for (const [name, value] of Object.entries(req.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, item);
      continue;
    }
    if (typeof value === 'string') headers.set(name, value);
  }
}

function resolveExpressRequestUrl(req: ExpressRequest): string {
  const host = req.get('host') || 'localhost';
  const protocol = req.protocol || 'http';
  return `${protocol}://${host}${req.originalUrl || req.url}`;
}

function encodeExpressRequestBody(req: ExpressRequest): BodyInit | undefined {
  const method = req.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD') return undefined;
  if (req.body === undefined || req.body === null) return undefined;
  if (typeof req.body === 'string' || req.body instanceof Uint8Array) return req.body;
  return JSON.stringify(req.body);
}

function buildFetchRequestFromExpress(req: ExpressRequest): Request {
  const headers = new Headers();
  appendExpressRequestHeaders(headers, req);
  const body = encodeExpressRequestBody(req);
  if (body && !headers.has('content-type')) {
    headers.set('content-type', 'application/json; charset=utf-8');
  }
  return new Request(resolveExpressRequestUrl(req), {
    method: req.method,
    headers,
    body,
  });
}

async function isFetchRouterNotFound(response: Response): Promise<boolean> {
  if (response.status !== 404) return false;
  const text = await response.clone().text();
  return text === 'Not Found';
}

async function sendFetchResponseToExpress(
  fetchResponse: Response,
  res: ExpressResponse,
): Promise<void> {
  fetchResponse.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });
  res.status(fetchResponse.status);
  const body = Buffer.from(await fetchResponse.arrayBuffer());
  if (body.length === 0) {
    res.end();
    return;
  }
  res.send(body);
}

function createFetchBackedExpressMiddleware(
  fetchHandler: ReturnType<typeof createCloudflareRouter>,
): RequestHandler {
  return async function fetchBackedExpressMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction,
  ): Promise<void> {
    try {
      const fetchRequest = buildFetchRequestFromExpress(req);
      const fetchResponse = await fetchHandler(fetchRequest);
      if (await isFetchRouterNotFound(fetchResponse)) {
        next();
        return;
      }
      await sendFetchResponseToExpress(fetchResponse, res);
    } catch (error) {
      next(error);
    }
  };
}

export function createRouterApiRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): ExpressRouter {
  const fetchHandler = createCloudflareRouter(service, opts);
  const router = express.Router();
  router.use(createFetchBackedExpressMiddleware(fetchHandler));
  const surface = getRouterApiRouteSurface(fetchHandler);
  if (!surface) return router;
  return attachRouterApiRouteSurface(router, surface);
}
