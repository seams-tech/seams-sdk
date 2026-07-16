import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { fetchRouterAbEcdsaDerivationJson } from './httpRequest';

type RouterAbEcdsaDerivationPoolFillAuth = {
  walletSessionJwt: string;
};

function resolveRelayerUrl(input: string): string | null {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(input));
  return relayerUrl || null;
}

function resolvePresignAuthHeaders(args: RouterAbEcdsaDerivationPoolFillAuth):
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
      message: 'Missing walletSessionJwt for Router A/B ECDSA derivation presign pool fill',
    };
  }
  headers.Authorization = `Bearer ${jwt}`;
  return { ok: true, headers };
}

export type RouterAbEcdsaDerivationPoolFillProgress = {
  ok: boolean;
  code?: string;
  message?: string;
  stage?: 'triples' | 'triples_done' | 'presign' | 'done';
  event?: 'none' | 'triples_done' | 'presign_done';
  outgoingMessagesB64u?: string[];
  presignatureId?: string;
  bigRB64u?: string;
};

export type RouterAbEcdsaDerivationPoolFillInitKeySelector = {
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
};

export type RouterAbEcdsaDerivationPresignaturePoolFill = {
  kind: 'router_ab_ecdsa_derivation_signing_worker_pool';
  scope: RouterAbEcdsaDerivationNormalSigningScopeV1;
  expiresAtMs: number;
};

function resolveRouterAbEcdsaDerivationPoolFillInitKeySelector(args: {
  keyHandle?: unknown;
}):
  | { ok: true; value: RouterAbEcdsaDerivationPoolFillInitKeySelector }
  | { ok: false; code: string; message: string } {
  const keyHandle = String(args.keyHandle || '').trim();
  if (!keyHandle) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing keyHandle for Router A/B ECDSA derivation pool-fill init',
    };
  }
  return { ok: true, value: { keyHandle } };
}

export type RouterAbEcdsaDerivationPoolFillInitBaseArgs = {
  relayerUrl: string;
  count?: number;
  walletSessionJwt: string;
  requestTag?: string;
  requestTimeoutMs?: number;
} & RouterAbEcdsaDerivationPoolFillInitKeySelector;

export type RouterAbEcdsaDerivationPresignaturePoolFillInitArgs = RouterAbEcdsaDerivationPoolFillInitBaseArgs & {
  poolFill: RouterAbEcdsaDerivationPresignaturePoolFill;
};

async function postEcdsaPresignInit(
  args: RouterAbEcdsaDerivationPresignaturePoolFillInitArgs & { path: string },
): Promise<RouterAbEcdsaDerivationPoolFillProgress & { presignSessionId?: string }> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for Router A/B ECDSA derivation pool-fill init',
    };
  }
  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for Router A/B ECDSA derivation pool-fill init',
    };
  }
  const keySelector = resolveRouterAbEcdsaDerivationPoolFillInitKeySelector(args);
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
    const { response, data } = await fetchRouterAbEcdsaDerivationJson<ResponseBody>({
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
        : e || 'Failed Router A/B ECDSA derivation pool-fill init',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function routerAbEcdsaDerivationPresignaturePoolFillInit(
  args: RouterAbEcdsaDerivationPresignaturePoolFillInitArgs,
): Promise<RouterAbEcdsaDerivationPoolFillProgress & { presignSessionId?: string }> {
  return postEcdsaPresignInit({
    ...args,
    path: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  });
}

export type RouterAbEcdsaDerivationPoolFillStepArgs = {
  relayerUrl: string;
  presignSessionId: string;
  stage: 'triples' | 'presign';
  outgoingMessagesB64u?: string[];
  walletSessionJwt: string;
  requestTag?: string;
  requestTimeoutMs?: number;
};

async function postEcdsaPresignStep(
  args: RouterAbEcdsaDerivationPoolFillStepArgs & { path: string },
): Promise<RouterAbEcdsaDerivationPoolFillProgress> {
  const relayerUrl = resolveRelayerUrl(args.relayerUrl);
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for Router A/B ECDSA derivation pool-fill step',
    };
  }
  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for Router A/B ECDSA derivation pool-fill step',
    };
  }
  const presignSessionId = String(args.presignSessionId || '').trim();
  if (!presignSessionId) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing presignSessionId for Router A/B ECDSA derivation pool-fill step',
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
    const { response, data } = await fetchRouterAbEcdsaDerivationJson<ResponseBody>({
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
        : e || 'Failed Router A/B ECDSA derivation pool-fill step',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}

export async function routerAbEcdsaDerivationPresignaturePoolFillStep(
  args: RouterAbEcdsaDerivationPoolFillStepArgs,
): Promise<RouterAbEcdsaDerivationPoolFillProgress> {
  return postEcdsaPresignStep({
    ...args,
    path: ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  });
}
