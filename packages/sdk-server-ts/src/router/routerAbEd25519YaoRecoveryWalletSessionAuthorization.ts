import type { RouterAbEd25519YaoActivationBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { headersToRecord } from './cloudflare/http';
import { deriveJwtExpiresAtIso, type SessionAdapter } from './routerApi';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationResult,
} from './routerAbEd25519YaoRecovery';

function authorizationFailure(input: {
  status: 401 | 403;
  code: string;
  message: string;
}): RouterAbEd25519YaoRecoveryAuthorizationResult {
  return {
    ok: false,
    status: input.status,
    code: input.code,
    message: input.message,
  };
}

function exactParticipants(
  claims: RouterAbEd25519WalletSessionClaims,
  participantIds: readonly [number, number],
): boolean {
  return (
    claims.participantIds.length === 2 &&
    claims.participantIds[0] === participantIds[0] &&
    claims.participantIds[1] === participantIds[1]
  );
}

function claimsMatchBinding(
  claims: RouterAbEd25519WalletSessionClaims,
  binding: RouterAbEd25519YaoActivationBindingV1<'recovery'>,
): boolean {
  const lifecycle = binding.lifecycle;
  return (
    claims.walletId === lifecycle.account_id &&
    claims.thresholdSessionId === lifecycle.session_id &&
    claims.relayerKeyId === lifecycle.selected_server_id &&
    claims.routerAbNormalSigning.signingWorkerId === lifecycle.selected_server_id
  );
}

function claimsMatchAdmission(
  claims: RouterAbEd25519WalletSessionClaims,
  input: Extract<RouterAbEd25519YaoRecoveryAuthorizationInput, { kind: 'admit' }>,
): boolean {
  const body = input.body;
  return (
    claims.walletId === body.application_binding.wallet_id &&
    claims.walletId === body.scope.account_id &&
    claims.nearEd25519SigningKeyId === body.application_binding.near_ed25519_signing_key_id &&
    claims.thresholdSessionId === body.scope.wallet_session_id &&
    claims.relayerKeyId === body.scope.signing_worker_id &&
    claims.routerAbNormalSigning.signingWorkerId === body.scope.signing_worker_id &&
    claims.runtimePolicyScope.signingRootVersion === body.scope.root_share_epoch &&
    exactParticipants(claims, body.participant_ids)
  );
}

function claimsMatchBootstrap(
  claims: RouterAbEd25519WalletSessionClaims,
  input: Extract<RouterAbEd25519YaoRecoveryAuthorizationInput, { kind: 'bootstrap' }>,
): boolean {
  const body = input.body;
  return (
    claims.walletId === body.walletId &&
    claims.nearAccountId === body.nearAccountId &&
    claims.nearEd25519SigningKeyId === body.nearEd25519SigningKeyId &&
    claims.thresholdSessionId === body.thresholdSessionId &&
    claims.signingGrantId === body.signingGrantId &&
    claims.relayerKeyId === body.signingWorkerId &&
    claims.routerAbNormalSigning.signingWorkerId === body.signingWorkerId &&
    exactParticipants(claims, body.participantIds)
  );
}

function requestAdvertisesExpiredBearer(request: Request): boolean {
  const authorization = String(request.headers.get('authorization') || '').trim();
  const match = /^Bearer\s+(.+)$/i.exec(authorization);
  const token = match?.[1]?.trim();
  if (!token) return false;
  const expiresAtIso = deriveJwtExpiresAtIso(token);
  if (!expiresAtIso) return false;
  const expiresAtMs = Date.parse(expiresAtIso);
  return Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now();
}

function claimsAuthorizeRecovery(
  claims: RouterAbEd25519WalletSessionClaims,
  input: RouterAbEd25519YaoRecoveryAuthorizationInput,
): boolean {
  switch (input.kind) {
    case 'bootstrap':
      return claimsMatchBootstrap(claims, input);
    case 'admit':
      return claimsMatchAdmission(claims, input);
    case 'execute':
    case 'activate':
      return claimsMatchBinding(claims, input.body.binding);
  }
}

export class RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter
  implements RouterAbEd25519YaoRecoveryAuthorizationAdapter
{
  constructor(private readonly session: SessionAdapter) {}

  async authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
    const parsed = await this.session.parse(headersToRecord(input.request.headers));
    if (!parsed.ok) {
      if (requestAdvertisesExpiredBearer(input.request)) {
        return authorizationFailure({
          status: 401,
          code: 'wallet_session_expired',
          message: 'Ed25519 Yao recovery Wallet Session expired',
        });
      }
      return authorizationFailure({
        status: 401,
        code: 'recovery_wallet_session_missing',
        message: 'Ed25519 Yao recovery requires a valid Wallet Session JWT',
      });
    }
    const claims = parseRouterAbEd25519WalletSessionClaims(parsed.claims);
    if (!claims) {
      return authorizationFailure({
        status: 401,
        code: 'recovery_wallet_session_invalid',
        message: 'Ed25519 Yao recovery requires Router A/B Ed25519 Wallet Session claims',
      });
    }
    if (claims.thresholdExpiresAtMs <= Date.now()) {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_expired',
        message: 'Ed25519 Yao recovery Wallet Session expired',
      });
    }
    if (!claimsAuthorizeRecovery(claims, input)) {
      return authorizationFailure({
        status: 403,
        code: 'recovery_wallet_session_scope_mismatch',
        message: 'Wallet Session claims do not match the Ed25519 Yao recovery lifecycle',
      });
    }
    return { ok: true, claims };
  }
}
