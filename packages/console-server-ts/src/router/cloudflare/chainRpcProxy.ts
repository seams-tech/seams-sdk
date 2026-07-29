import { withCors } from '@seams/sdk-server/cloud-host';

const MAX_RPC_REQUEST_BYTES = 128 * 1024;
const DEFAULT_NEAR_RPC_URLS = Object.freeze([
  'https://test.rpc.fastnear.com/',
  'https://rpc.testnet.near.org/',
]);
const DEFAULT_ARC_RPC_URLS = Object.freeze(['https://rpc.testnet.arc.network/']);

const NEAR_RPC_METHODS = new Set(['query', 'block', 'send_tx', 'EXPERIMENTAL_tx_status']);
const ARC_RPC_METHODS = new Set([
  'eth_call',
  'eth_gasPrice',
  'eth_getBalance',
  'eth_getBlockByNumber',
  'eth_getTransactionByHash',
  'eth_getTransactionCount',
  'eth_getTransactionReceipt',
  'eth_maxPriorityFeePerGas',
  'eth_sendRawTransaction',
]);

const ALLOWED_RPC_HOSTS = new Set([
  'test.rpc.fastnear.com',
  'rpc.testnet.near.org',
  'free.rpc.fastnear.com',
  'rpc.mainnet.near.org',
  'rpc.testnet.arc.network',
]);

export const NEAR_BROWSER_RPC_PROXY_PATH = '/chain-rpc/near';
export const ARC_BROWSER_RPC_PROXY_PATH = '/chain-rpc/arc';

type ChainRpcTarget = 'near' | 'arc';

type JsonRpcRequest = {
  readonly jsonrpc: '2.0';
  readonly id: unknown;
  readonly method: string;
  readonly params: unknown;
};

export type ChainRpcProxyOptions = {
  readonly corsOrigins: readonly string[];
  readonly nearRpcUrls?: string;
  readonly arcRpcUrls?: string;
  readonly fetchImpl?: typeof fetch;
};

export async function handleChainRpcProxyRequest(
  request: Request,
  options: ChainRpcProxyOptions,
): Promise<Response | null> {
  const target = chainRpcTargetFromPath(new URL(request.url).pathname);
  if (!target) return null;

  if (request.method === 'OPTIONS') {
    return corsResponse(request, options.corsOrigins, null, { status: 204 });
  }
  if (request.method !== 'POST') {
    return rpcErrorResponse(request, options.corsOrigins, null, 405, 'method_not_allowed');
  }

  const originProbe = corsResponse(request, options.corsOrigins, null, { status: 204 });
  if (!originProbe.headers.has('Access-Control-Allow-Origin')) {
    return rpcErrorResponse(request, options.corsOrigins, null, 403, 'origin_not_allowed');
  }

  const parsed = await parseJsonRpcRequest(request);
  if (!parsed.ok) {
    return rpcErrorResponse(request, options.corsOrigins, parsed.id, parsed.status, parsed.message);
  }
  if (!allowedMethodsForTarget(target).has(parsed.request.method)) {
    return rpcErrorResponse(
      request,
      options.corsOrigins,
      parsed.request.id,
      403,
      'rpc_method_not_allowed',
    );
  }

  return await forwardJsonRpcRequest({
    request,
    corsOrigins: options.corsOrigins,
    rpcRequest: parsed.request,
    body: parsed.body,
    upstreamUrls: rpcUrlsForTarget(target, options),
    fetchImpl: options.fetchImpl || fetch,
  });
}

function chainRpcTargetFromPath(pathname: string): ChainRpcTarget | null {
  if (pathname === NEAR_BROWSER_RPC_PROXY_PATH) return 'near';
  if (pathname === ARC_BROWSER_RPC_PROXY_PATH) return 'arc';
  return null;
}

function allowedMethodsForTarget(target: ChainRpcTarget): ReadonlySet<string> {
  return target === 'near' ? NEAR_RPC_METHODS : ARC_RPC_METHODS;
}

function rpcUrlsForTarget(
  target: ChainRpcTarget,
  options: ChainRpcProxyOptions,
): readonly string[] {
  const configured = target === 'near' ? options.nearRpcUrls : options.arcRpcUrls;
  const defaults = target === 'near' ? DEFAULT_NEAR_RPC_URLS : DEFAULT_ARC_RPC_URLS;
  const candidates =
    target === 'near'
      ? [defaults[0], ...parseRpcUrls(configured), ...defaults.slice(1)]
      : [...parseRpcUrls(configured), ...defaults];
  const urls: string[] = [];
  for (const candidate of candidates) {
    const url = parseAllowedRpcUrl(candidate);
    if (!url || urls.includes(url)) continue;
    urls.push(url);
  }
  return urls;
}

function parseRpcUrls(source: string | undefined): string[] {
  return String(source || '')
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean);
}

function parseAllowedRpcUrl(source: string): string | null {
  try {
    const url = new URL(source);
    if (url.protocol !== 'https:' || !ALLOWED_RPC_HOSTS.has(url.hostname)) return null;
    return url.toString();
  } catch {
    return null;
  }
}

async function parseJsonRpcRequest(
  request: Request,
): Promise<
  | { readonly ok: true; readonly request: JsonRpcRequest; readonly body: Uint8Array }
  | {
      readonly ok: false;
      readonly id: unknown;
      readonly status: number;
      readonly message: string;
    }
> {
  const contentLength = Number(request.headers.get('content-length') || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_RPC_REQUEST_BYTES) {
    return { ok: false, id: null, status: 413, message: 'rpc_request_too_large' };
  }

  let body: Uint8Array;
  try {
    body = await readBoundedRequestBody(request, MAX_RPC_REQUEST_BYTES);
  } catch {
    return { ok: false, id: null, status: 413, message: 'rpc_request_too_large' };
  }

  let raw: unknown;
  try {
    raw = JSON.parse(new TextDecoder().decode(body));
  } catch {
    return { ok: false, id: null, status: 400, message: 'invalid_json_rpc_request' };
  }
  if (!isRecord(raw) || raw.jsonrpc !== '2.0' || typeof raw.method !== 'string') {
    return {
      ok: false,
      id: isRecord(raw) ? raw.id : null,
      status: 400,
      message: 'invalid_json_rpc_request',
    };
  }
  return {
    ok: true,
    request: {
      jsonrpc: '2.0',
      id: raw.id ?? null,
      method: raw.method,
      params: raw.params ?? [],
    },
    body,
  };
}

async function readBoundedRequestBody(request: Request, maximumBytes: number): Promise<Uint8Array> {
  if (!request.body) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > maximumBytes) {
        await reader.cancel();
        throw new Error('RPC request exceeds the maximum body size');
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function forwardJsonRpcRequest(args: {
  readonly request: Request;
  readonly corsOrigins: readonly string[];
  readonly rpcRequest: JsonRpcRequest;
  readonly body: Uint8Array;
  readonly upstreamUrls: readonly string[];
  readonly fetchImpl: typeof fetch;
}): Promise<Response> {
  for (const [index, upstreamUrl] of args.upstreamUrls.entries()) {
    const hasFallback = index < args.upstreamUrls.length - 1;
    let response: Response;
    try {
      response = await args.fetchImpl(upstreamUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: args.body,
        redirect: 'manual',
      });
    } catch {
      if (hasFallback) continue;
      return rpcErrorResponse(
        args.request,
        args.corsOrigins,
        args.rpcRequest.id,
        502,
        'RPC unavailable; retry shortly',
      );
    }

    const redirected = response.status >= 300 && response.status < 400;
    if ((redirected || response.status === 429 || response.status >= 500) && hasFallback) {
      await response.body?.cancel();
      continue;
    }
    if (redirected) {
      await response.body?.cancel();
      return rpcErrorResponse(
        args.request,
        args.corsOrigins,
        args.rpcRequest.id,
        502,
        'RPC unavailable; retry shortly',
      );
    }
    if (response.status === 429) {
      await response.body?.cancel();
      return rpcErrorResponse(
        args.request,
        args.corsOrigins,
        args.rpcRequest.id,
        429,
        'RPC throttled; retry shortly',
        response.headers.get('retry-after'),
      );
    }
    if (response.status >= 500) {
      await response.body?.cancel();
      return rpcErrorResponse(
        args.request,
        args.corsOrigins,
        args.rpcRequest.id,
        502,
        'RPC unavailable; retry shortly',
        response.headers.get('retry-after'),
      );
    }

    const headers = new Headers({
      'content-type': response.headers.get('content-type') || 'application/json; charset=utf-8',
      'cache-control': 'no-store',
    });
    const retryAfter = response.headers.get('retry-after');
    if (retryAfter) headers.set('retry-after', retryAfter);
    withCors(headers, { corsOrigins: [...args.corsOrigins] }, args.request);
    return new Response(response.body, { status: response.status, headers });
  }

  return rpcErrorResponse(
    args.request,
    args.corsOrigins,
    args.rpcRequest.id,
    502,
    'RPC unavailable; retry shortly',
  );
}

function rpcErrorResponse(
  request: Request,
  corsOrigins: readonly string[],
  id: unknown,
  status: number,
  message: string,
  retryAfter: string | null = null,
): Response {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  if (retryAfter) headers.set('retry-after', retryAfter);
  withCors(headers, { corsOrigins: [...corsOrigins] }, request);
  return new Response(
    JSON.stringify({
      jsonrpc: '2.0',
      id,
      error: { code: status === 429 ? -32005 : -32000, message },
    }),
    { status, headers },
  );
}

function corsResponse(
  request: Request,
  corsOrigins: readonly string[],
  body: BodyInit | null,
  init: ResponseInit,
): Response {
  const headers = new Headers(init.headers);
  withCors(headers, { corsOrigins: [...corsOrigins] }, request);
  return new Response(body, { ...init, headers });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
