import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
  type RouterAbEcdsaHssNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaHss';
import { fetchRouterAbEcdsaHssJson } from './httpRequest';

type RouterAbEcdsaHssPoolFillAuth = {
  walletSessionJwt: string;
};

function resolveRelayerUrl(input: string): string | null {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(input));
  return relayerUrl || null;
}

function resolvePresignAuthHeaders(args: RouterAbEcdsaHssPoolFillAuth):
  | {
      ok: true;
      headers: Record<string, string>;
    }
  | {
      ok: false;
      code: string;
      message: string;
    } {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  const jwt = String(args.walletSessionJwt || '').trim();
  if (!jwt) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing walletSessionJwt for Router A/B ECDSA-HSS presign pool fill',
    };
  }
  headers.Authorization = `Bearer ${jwt}`;
  return { ok: true, headers };
}

export type RouterAbEcdsaHssPoolFillProgress = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  presignatureId?: string;
  bigRB64u?: string;
};

export type RouterAbEcdsaHssPoolFillInitKeySelector = {
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

export type RouterAbEcdsaHssPresignaturePoolFill = {
  kind: 'router_ab_ecdsa_hss_signing_worker_pool';
  scope: RouterAbEcdsaHssNormalSigningScopeV1;
  expiresAtMs: number;
};

function resolveRouterAbEcdsaHssPoolFillInitKeySelector(args: {
  keyHandle?: unknown;
}):
  | { ok: true; value: RouterAbEcdsaHssPoolFillInitKeySelector }
  | { ok: false; code: string; message: string } {
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing keyHandle for Router A/B ECDSA-HSS pool-fill init',
    };
  }
  return { ok: true, value: { keyHandle } };
}

export type RouterAbEcdsaHssPoolFillInitBaseArgs = {
  relayerUrl: string;
  count?: number;
  walletSessionJwt: string;
  requestTag?: string;
  requestTimeoutMs?: number;
} & RouterAbEcdsaHssPoolFillInitKeySelector;

export type RouterAbEcdsaHssPresignaturePoolFillInitArgs = RouterAbEcdsaHssPoolFillInitBaseArgs & {
  poolFill: RouterAbEcdsaHssPresignaturePoolFill;
};

async function postEcdsaPresignInit(
  args: RouterAbEcdsaHssPresignaturePoolFillInitArgs & { path: string },
): Promise<RouterAbEcdsaHssPoolFillProgress & { presignSessionId?: string }> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for Router A/B ECDSA-HSS pool-fill init',
    };
  }
  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for Router A/B ECDSA-HSS pool-fill init',
    };
  }
  const keySelector = resolveRouterAbEcdsaHssPoolFillInitKeySelector(args);
  if (!keySelector.ok) return keySelector;
  const requestTag = String(args.requestTag || '').trim();

  const auth = resolvePresignAuthHeaders(args);
  if (!auth.ok) return auth;

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    presignSessionId: string;
    stage: 'triples' | 'triples_done' | 'presign' | 'done';
    outgoingMessagesB64u: string[];
  }>;

  try {
    const { response, data } = await fetchRouterAbEcdsaHssJson<ResponseBody>({
      url: `${relayerUrl}${args.path}`,
      operation: 'presign/init',
      timeoutMs: args.requestTimeoutMs,
      init: {
        method: 'POST',
        headers: auth.headers,
        credentials: 'omit',
        body: JSON.stringify({
          ...keySelector.value,
          count: Number.isFinite(args.count) ? Math.max(1, Math.floor(Number(args.count))) : 1,
          ...(requestTag ? { requestTag } : {}),
          poolFill: args.poolFill,
        }),
      },
    });
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      presignSessionId: data.presignSessionId,
      stage: data.stage,
      outgoingMessagesB64u: Array.isArray(data.outgoingMessagesB64u)
        ? data.outgoingMessagesB64u
        : [],
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed Router A/B ECDSA-HSS pool-fill init',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function routerAbEcdsaHssPresignaturePoolFillInit(
  args: RouterAbEcdsaHssPresignaturePoolFillInitArgs,
): Promise<RouterAbEcdsaHssPoolFillProgress & { presignSessionId?: string }> {
  return postEcdsaPresignInit({
    ...args,
    path: ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_INIT_PATH,
  });
}

export type RouterAbEcdsaHssPoolFillStepArgs = {
  relayerUrl: string;
  presignSessionId: string;
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
  walletSessionJwt: string;
  requestTag?: string;
  requestTimeoutMs?: number;
};

async function postEcdsaPresignStep(
  args: RouterAbEcdsaHssPoolFillStepArgs & { path: string },
): Promise<RouterAbEcdsaHssPoolFillProgress> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for Router A/B ECDSA-HSS pool-fill step',
    };
  }
  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for Router A/B ECDSA-HSS pool-fill step',
    };
  }
  const presignSessionId = String(args.presignSessionId || '').trim();
  if (!presignSessionId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing presignSessionId for Router A/B ECDSA-HSS pool-fill step',
    };
  }
  const requestTag = String(args.requestTag || '').trim();

  const auth = resolvePresignAuthHeaders(args);
  if (!auth.ok) return auth;

  type ResponseBody = Partial<{
    ok: boolean;
    code: string;
    message: string;
    stage: 'triples' | 'triples_done' | 'presign' | 'done';
    event: 'none' | 'triples_done' | 'presign_done';
    outgoingMessagesB64u: string[];
    presignatureId: string;
    bigRB64u: string;
  }>;

  try {
    const { response, data } = await fetchRouterAbEcdsaHssJson<ResponseBody>({
      url: `${relayerUrl}${args.path}`,
      operation: 'presign/step',
      timeoutMs: args.requestTimeoutMs,
      init: {
        method: 'POST',
        headers: auth.headers,
        credentials: 'omit',
        body: JSON.stringify({
          presignSessionId,
          stage: args.stage,
          outgoingMessagesB64u: Array.isArray(args.outgoingMessagesB64u)
            ? args.outgoingMessagesB64u
            : [],
          ...(requestTag ? { requestTag } : {}),
        }),
      },
    });
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }
    return {
      ok: data.ok === true,
      stage: data.stage,
      event: data.event,
      outgoingMessagesB64u: Array.isArray(data.outgoingMessagesB64u)
        ? data.outgoingMessagesB64u
        : [],
      ...(data.presignatureId ? { presignatureId: data.presignatureId } : {}),
      ...(data.bigRB64u ? { bigRB64u: data.bigRB64u } : {}),
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed Router A/B ECDSA-HSS pool-fill step',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function routerAbEcdsaHssPresignaturePoolFillStep(
  args: RouterAbEcdsaHssPoolFillStepArgs,
): Promise<RouterAbEcdsaHssPoolFillProgress> {
  return postEcdsaPresignStep({
    ...args,
    path: ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL_FILL_STEP_PATH,
  });
}
