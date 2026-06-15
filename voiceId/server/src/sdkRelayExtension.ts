import { Readable } from 'node:stream';
import type { Request as ExpressRequest, Response as ExpressResponse } from 'express-serve-static-core';
import type { RelayRouterModule } from '../../../packages/sdk-server-ts/src/router/modules';
import type {
  RelayCloudflareRouteExtensionInput,
  RelayExpressRouteExtensionInput,
  RelayRouteExtension,
} from '../../../packages/sdk-server-ts/src/router/routeExtensions';
import type { RouteDefinition } from '../../../packages/sdk-server-ts/src/router/routeDefinitions';
import type {
  VoiceIdCapabilityRoute,
  VoiceIdServerCapability,
} from './capability.ts';

export type VoiceIdRelayRouteDefinition = RouteDefinition & {
  surface: 'relay';
  method: VoiceIdCapabilityRoute['method'];
};

export type VoiceIdRelayRouteExtension = Extract<
  RelayRouteExtension,
  { kind: 'universal_route_extension' }
> & {
  id: 'voice_id';
};

export type VoiceIdRelayRouterModule = RelayRouterModule & { id: 'voice_id' };

export function createVoiceIdRelayRouterModule(
  capability: VoiceIdServerCapability,
): VoiceIdRelayRouterModule {
  return Object.freeze({
    kind: 'relay_router_module',
    id: 'voice_id',
    routeExtensions: Object.freeze([createVoiceIdRelayRouteExtension(capability)]),
  });
}

export function createVoiceIdRelayRouteExtension(
  capability: VoiceIdServerCapability,
): VoiceIdRelayRouteExtension {
  const routes = Object.freeze(
    capability.routes.map((route) => voiceIdCapabilityRouteToRelayRouteDefinition(route)),
  );

  return {
    kind: 'universal_route_extension',
    id: 'voice_id',
    routes,
    handleCloudflareRoute: async ({ request }: RelayCloudflareRouteExtensionInput) =>
      await capability.fetch(request),
    registerExpressRoutes({ router }: RelayExpressRouteExtensionInput) {
      for (const route of capability.routes) {
        const handler = async (req: ExpressRequest, res: ExpressResponse): Promise<void> => {
          await pipeWebResponseToExpress(
            await capability.fetch(expressRequestToWebRequest(req)),
            res,
          );
        };

        switch (route.method) {
          case 'GET':
            router.get(route.path, handler);
            break;
          case 'POST':
            router.post(route.path, handler);
            break;
        }
      }
    },
  };
}

export function voiceIdCapabilityRouteToRelayRouteDefinition(
  route: VoiceIdCapabilityRoute,
): VoiceIdRelayRouteDefinition {
  const isHealthRoute = route.id === 'voice_id_health';
  const auth: VoiceIdRelayRouteDefinition['auth'] = isHealthRoute
    ? {
        plane: 'public',
        rationale: 'VoiceID health metadata is public diagnostics.',
      }
    : {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'VoiceID routes exchange owner-presence evidence through VoiceID-owned validation.',
      };

  return Object.freeze({
    id: route.id,
    surface: 'relay',
    method: route.method,
    path: route.path,
    auth,
    metering: voiceIdRelayRouteMetering(),
    summary: route.summary,
  });
}

function voiceIdRelayRouteMetering(): VoiceIdRelayRouteDefinition['metering'] {
  return { kind: 'none' };
}

function expressRequestToWebRequest(req: ExpressRequest): Request {
  const method = String(req.method || 'GET').toUpperCase();
  const headers = headersFromExpressRequest(req);
  const url = expressRequestUrl(req);

  if (method === 'GET' || method === 'HEAD') {
    return new Request(url, { method, headers });
  }

  const parsedBody: unknown = req.body;
  if (parsedBody !== undefined) {
    if (!headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    return new Request(url, {
      method,
      headers,
      body: bodyInitFromParsedExpressBody(parsedBody),
    });
  }

  const streamInit: RequestInit & { duplex: 'half' } = {
    method,
    headers,
    body: readableBodyFromExpressRequest(req),
    duplex: 'half',
  };
  return new Request(url, streamInit);
}

function readableBodyFromExpressRequest(req: ExpressRequest): BodyInit {
  return Readable.toWeb(req as unknown as Readable) as unknown as BodyInit;
}

function bodyInitFromParsedExpressBody(body: unknown): BodyInit {
  if (
    typeof body === 'string'
    || body instanceof Blob
    || body instanceof FormData
    || body instanceof URLSearchParams
  ) {
    return body;
  }
  if (body instanceof Uint8Array) {
    return new Uint8Array(body);
  }
  return JSON.stringify(body);
}

function headersFromExpressRequest(req: ExpressRequest): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers ?? {})) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const item of value) {
        headers.append(name, item);
      }
      continue;
    }
    headers.set(name, value);
  }
  return headers;
}

function expressRequestUrl(req: ExpressRequest): string {
  const proto = firstHeaderValue(req, 'x-forwarded-proto') || req.protocol || 'http';
  const host = firstHeaderValue(req, 'x-forwarded-host') || firstHeaderValue(req, 'host') || 'localhost';
  const path = req.originalUrl || req.url || '/';
  return `${proto}://${host}${path.startsWith('/') ? path : `/${path}`}`;
}

function firstHeaderValue(req: ExpressRequest, name: string): string | null {
  const value = (req.headers ?? {})[name.toLowerCase()];
  if (Array.isArray(value)) {
    return value[0] ?? null;
  }
  return value ?? null;
}

async function pipeWebResponseToExpress(
  response: Response,
  res: ExpressResponse,
): Promise<void> {
  res.status(response.status);
  response.headers.forEach((value, name) => {
    res.setHeader(name, value);
  });

  if (response.status === 204 || response.status === 304) {
    res.end();
    return;
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.byteLength === 0) {
    res.end();
    return;
  }
  res.send(Buffer.from(bytes));
}
