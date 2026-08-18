import type { RouterApiServiceBag } from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import { DEFAULT_SESSION_COOKIE_NAME } from '../../framework/routerApi';
import { validateRouterApiRorOptions } from '../../framework/ror/provider';
import { coerceRouterLogger } from '../../framework/logger';
import type { NormalizedRouterLogger } from '../../framework/logger';
import type { CfEnv, CfExecutionContext, FetchHandler } from './cloudflare.types';
import { json, withCors } from '../../framework/http';
import { handleThresholdEd25519 } from '../../transport/fetch/routes/thresholdEd25519';
import { handleThresholdEcdsa } from '../../transport/fetch/routes/thresholdEcdsa';
import type { FetchRouterRuntime } from '../../transport/fetch/fetchRouter.types';
import { isPlainObject } from '@shared/utils/validation';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';
import {
  thresholdEcdsaChainTargetFromValue,
} from '../../../core/thresholdEcdsaChainTarget';
import { parseEvmFamilySigningKeySlotId } from '@shared/signing-lanes';

type SelfHostedCloudflareRouterApiContext = Parameters<typeof handleThresholdEd25519>[0];

type SelfHostedWorker<Env> = {
  fetch(request: Request, env: Env, ctx: CfExecutionContext): Promise<Response>;
};

export type SelfHostedCloudflareSigningWorkerFactoryInput<Env extends CfEnv = CfEnv> = {
  readonly createAuthService: (input: {
    readonly request: Request;
    readonly env: Env;
    readonly ctx: CfExecutionContext;
  }) => RouterApiServiceBag | Promise<RouterApiServiceBag>;
  readonly routerOptions?:
    | RouterApiOptions
    | ((input: {
        readonly request: Request;
        readonly env: Env;
        readonly ctx: CfExecutionContext;
        readonly service: RouterApiServiceBag;
      }) => RouterApiOptions | Promise<RouterApiOptions>);
};

function notFound(): Response {
  return new Response('Not Found', { status: 404 });
}

function requireBodyString(body: unknown, name: string): string | null {
  if (!isPlainObject(body)) return null;
  const value = typeof body[name] === 'string' ? body[name].trim() : '';
  return value || null;
}

function optionalBodyString(body: unknown, name: string): string | undefined {
  return requireBodyString(body, name) || undefined;
}

function requireWalletId(body: unknown, name: string): WalletId | null {
  const value = requireBodyString(body, name);
  if (!value) return null;
  const parsed = parseWalletId(value);
  return parsed.ok ? parsed.value : null;
}

function selfHostedHealthResponse(ctx: SelfHostedCloudflareRouterApiContext): Response | null {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/healthz' && ctx.pathname !== '/readyz') return null;
  if (ctx.pathname === '/healthz' && !ctx.opts.healthz) return null;
  if (ctx.pathname === '/readyz' && !ctx.opts.readyz) return null;

  return json(
    {
      ok: true,
      selfHosted: true,
      threshold: {
        configured: Boolean(ctx.opts.routerAbNormalSigningRouterProxy),
      },
    },
    { status: 200 },
  );
}

function createSelfHostedContext(input: {
  readonly request: Request;
  readonly cfCtx?: CfExecutionContext;
  readonly service: RouterApiServiceBag;
  readonly opts: RouterApiOptions;
  readonly logger: NormalizedRouterLogger;
}): SelfHostedCloudflareRouterApiContext {
  const url = new URL(input.request.url);
  return {
    request: input.request,
    url,
    pathname: url.pathname,
    method: input.request.method.toUpperCase(),
    runtime: input.cfCtx
      ? ({
          kind: 'background',
          waitUntil: (promise) => input.cfCtx?.waitUntil(promise),
        } satisfies FetchRouterRuntime)
      : ({ kind: 'inline' } satisfies FetchRouterRuntime),
    service: input.service,
    opts: input.opts,
    logger: input.logger,
    routeDefinitions: [],
  };
}

export function createSelfHostedCloudflareSigningRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): FetchHandler {
  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const effectiveOpts: RouterApiOptions = { ...opts, sessionCookieName };
  if (effectiveOpts.ror) {
    validateRouterApiRorOptions(effectiveOpts.ror);
  }
  const logger = coerceRouterLogger(effectiveOpts.logger);

  const handler: FetchHandler = async (request, env, cfCtx): Promise<Response> => {
    if (request.method.toUpperCase() === 'OPTIONS') {
      const res = new Response(null, { status: 204 });
      withCors(res.headers, effectiveOpts, request);
      return res;
    }

    const ctx = createSelfHostedContext({
      request,
      cfCtx,
      service,
      opts: effectiveOpts,
      logger,
    });

    try {
      const response =
        selfHostedHealthResponse(ctx) ||
        (await handleThresholdEd25519(ctx)) ||
        (await handleThresholdEcdsa(ctx)) ||
        notFound();
      withCors(response.headers, effectiveOpts, request);
      return response;
    } catch (error: unknown) {
      const res = json(
        { code: 'internal', message: error instanceof Error ? error.message : String(error) },
        { status: 500 },
      );
      withCors(res.headers, effectiveOpts, request);
      return res;
    }
  };

  return handler;
}

export function createSelfHostedCloudflareSigningWorker<Env extends CfEnv = CfEnv>(
  input: SelfHostedCloudflareSigningWorkerFactoryInput<Env>,
): SelfHostedWorker<Env> {
  return {
    async fetch(request: Request, env: Env, ctx: CfExecutionContext): Promise<Response> {
      const service = await input.createAuthService({ request, env, ctx });
      const routerOptions =
        typeof input.routerOptions === 'function'
          ? await input.routerOptions({ request, env, ctx, service })
          : input.routerOptions || {};
      const router = createSelfHostedCloudflareSigningRouter(service, routerOptions);
      return router(request, env, ctx);
    },
  };
}
