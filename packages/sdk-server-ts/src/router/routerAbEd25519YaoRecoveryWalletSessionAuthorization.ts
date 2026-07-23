import type { RouterAbEd25519YaoActivationBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import {
  parseRouterAbEd25519WalletSessionClaims,
  type RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';
import { headersToRecord } from './cloudflare/http';
import type { SessionAdapter } from './routerApi';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
} from './walletSessionFailure';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationResult,
} from './routerAbEd25519YaoRecovery';

function authorizationFailure(input: {
  status: 401 | 403 | 409 | 429 | 503;
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
    let parsed: Awaited<ReturnType<SessionAdapter['parse']>>;
    try {
      parsed = await this.session.parse(headersToRecord(input.request.headers));
    } catch {
      return authorizationFailure({
        status: 503,
        code: 'wallet_session_unavailable',
        message: walletSessionFailureMessage('wallet_session_unavailable'),
      });
    }
    if (!parsed.ok) {
      const code = walletSessionFailureCodeFromParseReason(parsed.reason);
      return authorizationFailure({
        status: walletSessionFailureStatus(code),
        code,
        message: walletSessionFailureMessage(code),
      });
    }
    const claims = parseRouterAbEd25519WalletSessionClaims(parsed.claims);
    if (!claims) {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_claims_invalid',
        message: walletSessionFailureMessage('wallet_session_claims_invalid'),
      });
    }
    if (claims.thresholdExpiresAtMs <= Date.now()) {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_expired',
        message: walletSessionFailureMessage('wallet_session_expired'),
      });
    }
    if (!claimsAuthorizeRecovery(claims, input)) {
      return authorizationFailure({
        status: 403,
        code: 'wallet_session_scope_mismatch',
        message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
      });
    }
    return { ok: true, claims };
  }
}
