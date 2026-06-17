import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { toOptionalTrimmedString } from '@shared/utils/validation';

export type ParseOk<T> = { ok: true; value: T };
export type ParseErr = { ok: false; code: string; message: string };
export type ParseResult<T> = ParseOk<T> | ParseErr;

export type RouterAbNormalSigningServerPolicy =
  {
    mode: 'enabled';
    signingWorkerId: string;
  };

export function parseRouterAbNormalSigningServerPolicy(
  config: Record<string, unknown>,
): RouterAbNormalSigningServerPolicy {
  const signingWorkerId = toOptionalTrimmedString(config.ROUTER_AB_NORMAL_SIGNING_WORKER_ID);
  if (!signingWorkerId) {
    throw new Error(
      'Missing required server config: ROUTER_AB_NORMAL_SIGNING_WORKER_ID',
    );
  }
  return {
    mode: 'enabled',
    signingWorkerId,
  };
}

export function validateRouterAbNormalSigningServerPolicy(args: {
  requested: RouterAbEd25519NormalSigningState | undefined;
  policy: RouterAbNormalSigningServerPolicy;
}): ParseResult<null> {
  if (!args.requested) {
    return {
      ok: false,
      code: 'unauthorized',
      message: 'sessionPolicy.routerAbNormalSigning is required for Router A/B normal signing',
    };
  }

  if (args.requested.signingWorkerId !== args.policy.signingWorkerId) {
    return {
      ok: false,
      code: 'unauthorized',
      message:
        'sessionPolicy.routerAbNormalSigning.signingWorkerId is not allowed for this threshold server',
    };
  }
  return { ok: true, value: null };
}
