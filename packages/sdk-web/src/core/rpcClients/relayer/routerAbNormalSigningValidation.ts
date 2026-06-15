import type {
  RouterAbNormalSigningPrepareRequestV2Wire,
  RouterAbNormalSigningPrepareResponseV1Wire,
  RouterAbNormalSigningResponseV1Wire,
  RouterAbNormalSigningScopeV1Wire,
  RouterAbPublicDigest32Wire,
} from './routerAbNormalSigning';

function sameRouterAbScope(
  left: RouterAbNormalSigningScopeV1Wire,
  right: RouterAbNormalSigningScopeV1Wire,
): boolean {
  return (
    left.request_id === right.request_id &&
    left.account_id === right.account_id &&
    left.session_id === right.session_id &&
    left.signing_worker_id === right.signing_worker_id
  );
}

function sameRouterAbBytes(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

export function requireRouterAbNormalSigningPrepareMatchesRequest(args: {
  request: RouterAbNormalSigningPrepareRequestV2Wire;
  signingPayloadDigest: RouterAbPublicDigest32Wire;
  response: RouterAbNormalSigningPrepareResponseV1Wire;
}): void {
  if (!sameRouterAbScope(args.request.scope, args.response.scope)) {
    throw new Error('Router A/B normal-signing prepare response scope mismatch');
  }
  if (args.request.expires_at_ms !== args.response.expires_at_ms) {
    throw new Error('Router A/B normal-signing prepare response expiry mismatch');
  }
  if (args.response.signing_worker.server_id !== args.request.scope.signing_worker_id) {
    throw new Error('Router A/B normal-signing prepare response SigningWorker mismatch');
  }
  if (
    !sameRouterAbBytes(args.signingPayloadDigest.bytes, args.response.signing_payload_digest.bytes)
  ) {
    throw new Error('Router A/B normal-signing prepare response payload digest mismatch');
  }
}

export function requireRouterAbNormalSigningResponseMatchesRequest(args: {
  request: RouterAbNormalSigningPrepareRequestV2Wire;
  signingPayloadDigest: RouterAbPublicDigest32Wire;
  response: RouterAbNormalSigningResponseV1Wire;
}): void {
  if (!sameRouterAbScope(args.request.scope, args.response.scope)) {
    throw new Error('Router A/B normal-signing response scope mismatch');
  }
  if (args.response.signing_worker.server_id !== args.request.scope.signing_worker_id) {
    throw new Error('Router A/B normal-signing response SigningWorker mismatch');
  }
  if (
    !sameRouterAbBytes(args.signingPayloadDigest.bytes, args.response.signing_payload_digest.bytes)
  ) {
    throw new Error('Router A/B normal-signing response payload digest mismatch');
  }
  if (args.response.signature.bytes.length !== 64) {
    throw new Error('Router A/B normal-signing response signature must be 64 bytes');
  }
}
