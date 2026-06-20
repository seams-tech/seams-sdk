import type { AuthService } from '../../core/AuthService';
import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { RelayRouterOptions } from '../relay';
import { DEFAULT_SESSION_COOKIE_NAME } from '../relay';
import { resolveThresholdOption } from '../routerOptions';
import { validateRelayRouterRorOptions } from '../ror/provider';
import { coerceRouterLogger } from '../logger';
import type { NormalizedRouterLogger } from '../logger';
import type { CfEnv, CfExecutionContext, FetchHandler } from './cloudflare.types';
import { json, withCors } from './http';
import { handleThresholdEd25519 } from './routes/thresholdEd25519';
import { handleThresholdEcdsa } from './routes/thresholdEcdsa';
import { isPlainObject } from '@shared/utils/validation';
import {
  thresholdEcdsaChainTargetFromValue,
  type ThresholdEcdsaChainTarget,
} from '../../core/thresholdEcdsaChainTarget';

type HssWalletId = string & { readonly __hssWalletIdBrand: unique symbol };

type SelfHostedCloudflareRelayContext = Parameters<typeof handleThresholdEd25519>[0];

type SelfHostedWorker<Env> = {
  fetch(request: Request, env: Env, ctx: CfExecutionContext): Promise<Response>;
};

export type SelfHostedSigningRootAdminAuthResult =
  | boolean
  | { ok: true }
  | { ok: false; status?: number; code?: string; message?: string };

export type SelfHostedSigningRootAdminAuthHook = (input: {
  readonly request: Request;
}) => SelfHostedSigningRootAdminAuthResult | Promise<SelfHostedSigningRootAdminAuthResult>;

export type SelfHostedSigningRootAdminRoutes = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  readonly objectName?: string;
  readonly authenticate: SelfHostedSigningRootAdminAuthHook;
};

type SelfHostedEcdsaSigningRootWalletVerifier = {
  readonly verifyEcdsaSigningRootWalletAddress: (input: {
    readonly signingRootId: string;
    readonly signingRootVersion: string;
    readonly walletSessionUserId: string;
    readonly walletId: HssWalletId;
    readonly chainTarget: ThresholdEcdsaChainTarget;
    readonly ecdsaThresholdKeyId: string;
    readonly signingGrantId: string;
    readonly thresholdSessionId: string;
    readonly rpId: string;
    readonly clientPublicKey33B64u: string;
    readonly expectedEthereumAddress?: string;
    readonly walletKeyVersion?: string;
  }) => Promise<unknown>;
};

export type SelfHostedCloudflareSigningRouterOptions = {
  readonly signingRootAdmin?: SelfHostedSigningRootAdminRoutes;
};

export type SelfHostedCloudflareSigningWorkerFactoryInput<Env extends CfEnv = CfEnv> = {
  readonly createAuthService: (input: {
    readonly request: Request;
    readonly env: Env;
    readonly ctx: CfExecutionContext;
  }) => AuthService | Promise<AuthService>;
  readonly routerOptions?:
    | RelayRouterOptions
    | ((input: {
        readonly request: Request;
        readonly env: Env;
        readonly ctx: CfExecutionContext;
        readonly service: AuthService;
      }) => RelayRouterOptions | Promise<RelayRouterOptions>);
  readonly signingRootAdmin?:
    | SelfHostedSigningRootAdminRoutes
    | ((input: {
        readonly request: Request;
        readonly env: Env;
        readonly ctx: CfExecutionContext;
        readonly service: AuthService;
      }) =>
        | SelfHostedSigningRootAdminRoutes
        | null
        | undefined
        | Promise<SelfHostedSigningRootAdminRoutes | null | undefined>);
};

function notFound(): Response {
  return new Response('Not Found', { status: 404 });
}

async function readJson(request: Request): Promise<unknown> {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

function resolveSigningRootAdminStub(input: SelfHostedSigningRootAdminRoutes) {
  const id = input.namespace.idFromName(input.objectName || 'threshold-signing-root-secrets');
  return input.namespace.get(id);
}

async function callSigningRootAdminDo<T>(
  input: SelfHostedSigningRootAdminRoutes,
  body: Record<string, unknown>,
): Promise<T> {
  const response = await resolveSigningRootAdminStub(input).fetch(
    'https://threshold-store.invalid/',
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    },
  );
  const text = await response.text();
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`signing-root Durable Object returned non-JSON response: ${text}`);
  }
  if (!response.ok) {
    return {
      ok: false,
      code: 'signing_root_store_http_error',
      message: `signing-root Durable Object returned HTTP ${response.status}`,
    } as T;
  }
  return parsed as T;
}

async function authorizeSigningRootAdmin(
  request: Request,
  config: SelfHostedSigningRootAdminRoutes,
): Promise<Response | null> {
  const auth = await config.authenticate({ request });
  if (auth === true || (isPlainObject(auth) && auth.ok === true)) return null;
  const status = isPlainObject(auth) && typeof auth.status === 'number' ? auth.status : 401;
  const code = isPlainObject(auth) && typeof auth.code === 'string' ? auth.code : 'unauthorized';
  const message =
    isPlainObject(auth) && typeof auth.message === 'string'
      ? auth.message
      : 'self-host signing-root admin authorization failed';
  return json({ ok: false, code, message }, { status });
}

function requireQueryParam(url: URL, name: string): string | null {
  const value = url.searchParams.get(name)?.trim();
  return value || null;
}

function requireBodyString(body: unknown, name: string): string | null {
  if (!isPlainObject(body)) return null;
  const value = typeof body[name] === 'string' ? body[name].trim() : '';
  return value || null;
}

function optionalBodyString(body: unknown, name: string): string | undefined {
  return requireBodyString(body, name) || undefined;
}

function requireHssWalletId(body: unknown, name: string): HssWalletId | null {
  const value = requireBodyString(body, name);
  return value ? (value as HssWalletId) : null;
}

function resolveSelfHostedWalletVerifier(
  ctx: SelfHostedCloudflareRelayContext,
): SelfHostedEcdsaSigningRootWalletVerifier | null {
  const candidate = ctx.opts.threshold as unknown;
  if (
    isPlainObject(candidate) &&
    typeof candidate.verifyEcdsaSigningRootWalletAddress === 'function'
  ) {
    return candidate as SelfHostedEcdsaSigningRootWalletVerifier;
  }
  return null;
}

function selfHostedSigningRootResultStatus(result: unknown): number {
  if (isPlainObject(result) && result.ok === true) return 200;
  const code = isPlainObject(result) && typeof result.code === 'string' ? result.code : '';
  if (code === 'not_configured' || code === 'not_implemented') return 501;
  if (code === 'unauthorized') return 403;
  if (code === 'invalid_body' || code === 'invalid_request') return 400;
  return 400;
}

function selfHostedHealthResponse(ctx: SelfHostedCloudflareRelayContext): Response | null {
  if (ctx.method !== 'GET') return null;
  if (ctx.pathname !== '/healthz' && ctx.pathname !== '/readyz') return null;
  if (ctx.pathname === '/healthz' && !ctx.opts.healthz) return null;
  if (ctx.pathname === '/readyz' && !ctx.opts.readyz) return null;

  return json(
    {
      ok: true,
      selfHosted: true,
      threshold: { configured: Boolean(ctx.opts.threshold) },
    },
    { status: 200 },
  );
}

async function handleSigningRootAdminRoutes(
  ctx: SelfHostedCloudflareRelayContext,
  config?: SelfHostedSigningRootAdminRoutes,
): Promise<Response | null> {
  if (!ctx.pathname.startsWith('/self-host/signing-root/')) return null;
  if (!config) return notFound();

  const unauthorized = await authorizeSigningRootAdmin(ctx.request, config);
  if (unauthorized) return unauthorized;

  if (ctx.method === 'POST' && ctx.pathname === '/self-host/signing-root/import') {
    const body = await readJson(ctx.request);
    const record =
      isPlainObject(body) && 'record' in body
        ? body.record
        : isPlainObject(body) && 'bundle' in body
          ? body.bundle
          : body;
    const result = await callSigningRootAdminDo(config, {
      op: 'signingRootPut',
      record,
    });
    return json(result);
  }

  if (ctx.method === 'GET' && ctx.pathname === '/self-host/signing-root/status') {
    const signingRootId = requireQueryParam(ctx.url, 'signingRootId');
    const signingRootVersion = requireQueryParam(ctx.url, 'signingRootVersion');
    if (!signingRootId || !signingRootVersion) {
      return json(
        {
          ok: false,
          code: 'invalid_request',
          message: 'signingRootId and signingRootVersion are required',
        },
        { status: 400 },
      );
    }
    const result = await callSigningRootAdminDo(config, {
      op: 'signingRootStatus',
      signingRootId,
      signingRootVersion,
    });
    return json(result);
  }

  if (ctx.method === 'POST' && ctx.pathname === '/self-host/signing-root/delete') {
    const body = await readJson(ctx.request);
    const signingRootId = requireBodyString(body, 'signingRootId');
    const signingRootVersion = requireBodyString(body, 'signingRootVersion');
    if (!signingRootId || !signingRootVersion) {
      return json(
        {
          ok: false,
          code: 'invalid_request',
          message: 'signingRootId and signingRootVersion are required',
        },
        { status: 400 },
      );
    }
    const result = await callSigningRootAdminDo(config, {
      op: 'signingRootDelete',
      signingRootId,
      signingRootVersion,
    });
    return json(result);
  }

  if (ctx.method === 'POST' && ctx.pathname === '/self-host/signing-root/verify-wallet') {
    const body = await readJson(ctx.request);
    const signingRootId = requireBodyString(body, 'signingRootId');
    const signingRootVersion = requireBodyString(body, 'signingRootVersion');
    const walletSessionUserId = requireBodyString(body, 'walletSessionUserId');
    const hssWalletId = requireHssWalletId(body, 'subjectId');
    const chainTarget = isPlainObject(body)
      ? thresholdEcdsaChainTargetFromValue(body.chainTarget)
      : null;
    const ecdsaThresholdKeyId = requireBodyString(body, 'ecdsaThresholdKeyId');
    const signingGrantId = requireBodyString(body, 'signingGrantId');
    const thresholdSessionId = requireBodyString(body, 'thresholdSessionId');
    const rpId = requireBodyString(body, 'rpId');
    const clientPublicKey33B64u = requireBodyString(body, 'clientPublicKey33B64u');
    if (
      !signingRootId ||
      !signingRootVersion ||
      !walletSessionUserId ||
      !hssWalletId ||
      !chainTarget ||
      !ecdsaThresholdKeyId ||
      !signingGrantId ||
      !thresholdSessionId ||
      !rpId ||
      !clientPublicKey33B64u
    ) {
      return json(
        {
          ok: false,
          code: 'invalid_request',
          message:
            'signingRootId, signingRootVersion, walletSessionUserId, subjectId, chainTarget, ecdsaThresholdKeyId, signingGrantId, thresholdSessionId, rpId, and clientPublicKey33B64u are required',
        },
        { status: 400 },
      );
    }
    const verifier = resolveSelfHostedWalletVerifier(ctx);
    if (!verifier) {
      return json(
        {
          ok: false,
          code: 'not_configured',
          message:
            'self-host wallet verification requires a threshold service with signing-root verification support',
        },
        { status: 501 },
      );
    }
    const expectedEthereumAddress = optionalBodyString(body, 'expectedEthereumAddress');
    const walletKeyVersion = optionalBodyString(body, 'walletKeyVersion');
    const result = await verifier.verifyEcdsaSigningRootWalletAddress({
      signingRootId,
      signingRootVersion,
      walletSessionUserId,
      walletId: hssWalletId,
      chainTarget,
      ecdsaThresholdKeyId,
      signingGrantId,
      thresholdSessionId,
      rpId,
      clientPublicKey33B64u,
      ...(expectedEthereumAddress ? { expectedEthereumAddress } : {}),
      ...(walletKeyVersion ? { walletKeyVersion } : {}),
    });
    return json(result, { status: selfHostedSigningRootResultStatus(result) });
  }

  return null;
}

function createSelfHostedContext(input: {
  readonly request: Request;
  readonly env?: CfEnv;
  readonly cfCtx?: CfExecutionContext;
  readonly service: AuthService;
  readonly opts: RelayRouterOptions;
  readonly logger: NormalizedRouterLogger;
}): SelfHostedCloudflareRelayContext {
  const url = new URL(input.request.url);
  return {
    request: input.request,
    url,
    pathname: url.pathname,
    method: input.request.method.toUpperCase(),
    env: input.env,
    cfCtx: input.cfCtx,
    service: input.service,
    opts: input.opts,
    logger: input.logger,
    mePath: '/me',
    routeDefinitions: [],
    signedDelegatePath: '/signed-delegate',
  };
}

export function createSelfHostedCloudflareSigningRouter(
  service: AuthService,
  opts: RelayRouterOptions = {},
  selfHostedOpts: SelfHostedCloudflareSigningRouterOptions = {},
): FetchHandler {
  const threshold = resolveThresholdOption(service, opts);
  const sessionCookieName =
    String(opts.sessionCookieName || '').trim() || DEFAULT_SESSION_COOKIE_NAME;
  const effectiveOpts: RelayRouterOptions = { ...opts, threshold, sessionCookieName };
  if (effectiveOpts.ror) {
    validateRelayRouterRorOptions(effectiveOpts.ror);
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
      env,
      cfCtx,
      service,
      opts: effectiveOpts,
      logger,
    });

    try {
      const response =
        selfHostedHealthResponse(ctx) ||
        (await handleSigningRootAdminRoutes(ctx, selfHostedOpts.signingRootAdmin)) ||
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
      const signingRootAdmin =
        typeof input.signingRootAdmin === 'function'
          ? await input.signingRootAdmin({ request, env, ctx, service })
          : input.signingRootAdmin;
      const router = createSelfHostedCloudflareSigningRouter(service, routerOptions, {
        ...(signingRootAdmin ? { signingRootAdmin } : {}),
      });
      return router(request, env, ctx);
    },
  };
}
