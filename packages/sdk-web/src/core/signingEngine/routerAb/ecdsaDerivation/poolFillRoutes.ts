import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_INIT_PATH,
  ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_FILL_STEP_PATH,
  type RouterAbEcdsaDerivationNormalSigningScopeV1,
  type RouterAbEcdsaOperationStepUpPreparationV1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import { fetchRouterAbEcdsaDerivationJson } from './httpRequest';
import type { RouterAbEd25519NormalSigningCredential } from '../../../rpcClients/relayer/routerAbNormalSigning';

type RouterAbEcdsaDerivationPoolFillAuth = {
  credential: RouterAbEd25519NormalSigningCredential;
};

export type RouterAbEcdsaDerivationPoolFillAuthorization =
  | {
      readonly authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'reusable_wallet_session' }
      >;
      readonly operation?: never;
    }
  | {
      readonly authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'operation_step_up' }
      >;
      readonly operation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    };

function resolveRelayerUrl(input: string): string | null {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(input));
  return relayerUrl || null;
}

function resolvePresignAuthHeaders(args: RouterAbEcdsaDerivationPoolFillAuth):
  | {
      ok: true;
      headers: Record<string, string>;
      credentials: RequestCredentials;
    }
  | {
      ok: false;
      code: string;
      message: string;
    } {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  switch (args.credential.kind) {
    case 'wallet_session_jwt': {
      const jwt = String(args.credential.walletSessionJwt || '').trim();
      if (!jwt) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing session JWT for Router A/B ECDSA derivation presign pool fill',
        };
      }
      headers.Authorization = `Bearer ${jwt}`;
      return { ok: true, headers, credentials: 'omit' };
    }
    case 'app_session_jwt': {
      const jwt = String(args.credential.appSessionJwt || '').trim();
      if (!jwt) {
        return {
          ok: false,
          code: 'invalid_args',
          message: 'Missing app session JWT for Router A/B ECDSA derivation presign pool fill',
        };
      }
      headers.Authorization = `Bearer ${jwt}`;
      return { ok: true, headers, credentials: 'omit' };
    }
    case 'app_session_cookie':
      return { ok: true, headers, credentials: 'include' };
  }
}

function poolFillAuthorizationBody(
  input: RouterAbEcdsaDerivationPoolFillAuthorization,
): RouterAbEcdsaDerivationPoolFillAuthorization {
  switch (input.authorization.kind) {
    case 'reusable_wallet_session':
      return { authorization: input.authorization };
    case 'operation_step_up': {
      const operation = input.operation;
      if (!operation) {
        throw new Error('Operation step-up pool fill requires exact operation preparation');
      }
      return {
        authorization: input.authorization,
        operation,
      };
    }
  }
}

export type RouterAbEcdsaDerivationPoolFillProgress = {
  ok: boolean;
  code?: string;
  message?: string;
  materialExpiresAtMs?: number;
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
  credential: RouterAbEd25519NormalSigningCredential;
  requestTag?: string;
  requestTimeoutMs?: number;
} & RouterAbEcdsaDerivationPoolFillInitKeySelector &
  RouterAbEcdsaDerivationPoolFillAuthorization;

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
    materialExpiresAtMs: number;
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
        credentials: auth.credentials,
        body: JSON.stringify({
          ...keySelector.value,
          count: Number.isFinite(args.count) ? Math.max(1, Math.floor(Number(args.count))) : 1,
          ...(requestTag ? { requestTag } : {}),
          poolFill: args.poolFill,
          ...poolFillAuthorizationBody(args),
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
      ...(Number.isSafeInteger(data.materialExpiresAtMs)
        ? { materialExpiresAtMs: data.materialExpiresAtMs }
        : {}),
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
  credential: RouterAbEd25519NormalSigningCredential;
  requestTag?: string;
  requestTimeoutMs?: number;
} & RouterAbEcdsaDerivationPoolFillAuthorization;

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
        credentials: auth.credentials,
        body: JSON.stringify({
          presignSessionId,
          stage: args.stage,
          outgoingMessagesB64u: Array.isArray(args.outgoingMessagesB64u)
            ? args.outgoingMessagesB64u
            : [],
          ...(requestTag ? { requestTag } : {}),
          ...poolFillAuthorizationBody(args),
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
