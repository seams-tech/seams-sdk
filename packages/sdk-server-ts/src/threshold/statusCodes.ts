export type ThresholdRouteResult = { ok: boolean; code?: string };

export type ThresholdEd25519RouteResult = ThresholdRouteResult;
export type ThresholdEcdsaRouteResult = ThresholdRouteResult;

export function thresholdStatusCode(result: ThresholdRouteResult): number {
  if (result.ok) return 200;
  switch (result.code) {
    case 'not_found':
      return 404;
    case 'not_implemented':
      return 501;
    case 'sessions_disabled':
      return 501;
    case 'runtime_snapshots_not_configured':
      return 501;
    case 'threshold_disabled':
      return 503;
    case 'pool_empty':
      return 503;
    case 'missing_signing_root_kek':
      return 503;
    case 'stale_session_state':
      return 409;
    case 'runtime_snapshot_not_found':
      return 409;
    case 'runtime_snapshot_id_mismatch':
      return 409;
    case 'runtime_snapshot_version_mismatch':
      return 409;
    case 'runtime_snapshot_checksum_mismatch':
      return 409;
    case 'internal':
      return 500;
    case 'unauthorized':
      return 401;
    case 'wallet_session_missing':
    case 'wallet_session_signature_invalid':
    case 'wallet_session_claims_invalid':
    case 'wallet_session_expired':
      return 401;
    case 'wallet_session_scope_mismatch':
      return 403;
    case 'wallet_budget_exhausted':
      return 409;
    case 'wallet_session_unavailable':
      return 503;
    case 'rate_limited':
      return 429;
    default:
      return 400;
  }
}

export function thresholdEd25519StatusCode(result: ThresholdEd25519RouteResult): number {
  return thresholdStatusCode(result);
}

export function thresholdEcdsaStatusCode(result: ThresholdEcdsaRouteResult): number {
  return thresholdStatusCode(result);
}
