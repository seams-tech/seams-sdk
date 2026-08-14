import type { RouterAbEd25519YaoActivationBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import { headersToRecord } from '../../../framework/http';
import type { SessionAdapter } from '../../../framework/routerApi';
import {
  walletSessionFailureCodeFromParseReason,
  walletSessionFailureMessage,
  walletSessionFailureStatus,
} from '../../../auth/walletSessionFailure';
import type {
  RouterAbEd25519YaoRecoveryAuthorizationAdapter,
  RouterAbEd25519YaoRecoveryAuthorizationInput,
  RouterAbEd25519YaoRecoveryAuthorizationResult,
} from './routerAbEd25519YaoRecovery';
import {
  deriveWalletRecoveryKeyLifecycleId,
  parseRecoveryCodeReservationId,
  type WalletRecoveryKeySetId,
} from '@shared/wallet-recovery/recoveryCodeReservation';

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

type WalletRecoveryAuthorizationClaims = {
  readonly kind: 'router_ab_ed25519_wallet_recovery_authorization_v1';
  readonly walletId: string;
  readonly reservationId: string;
  readonly keySetId: WalletRecoveryKeySetId;
  readonly lifecycleId: string;
  readonly thresholdSessionId: string;
  readonly rootShareEpoch: string;
  readonly signingWorkerId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly participantIds: readonly [number, number];
  readonly expiresAtMs: number;
};

function parseWalletRecoveryKeySetId(value: unknown): WalletRecoveryKeySetId | null {
  if (typeof value !== 'string' || !/^(near_ed25519|evm_family_ecdsa):\S+$/.test(value)) {
    return null;
  }
  return value as WalletRecoveryKeySetId;
}

function parseWalletRecoveryAuthorizationClaims(
  raw: Record<string, unknown>,
): WalletRecoveryAuthorizationClaims | null {
  if (raw.kind !== 'router_ab_ed25519_wallet_recovery_authorization_v1') return null;
  const walletId = String(raw.walletId || '').trim();
  const reservationId = String(raw.reservationId || '').trim();
  const keySetId = parseWalletRecoveryKeySetId(raw.keySetId);
  const lifecycleId = String(raw.lifecycleId || '').trim();
  const thresholdSessionId = String(raw.thresholdSessionId || '').trim();
  const rootShareEpoch = String(raw.rootShareEpoch || '').trim();
  const signingWorkerId = String(raw.signingWorkerId || '').trim();
  const nearEd25519SigningKeyId = String(raw.nearEd25519SigningKeyId || '').trim();
  const participants = raw.participantIds;
  const expiresAtMs = Number(raw.expiresAtMs);
  if (
    !walletId ||
    !reservationId ||
    !keySetId ||
    !lifecycleId ||
    !thresholdSessionId ||
    !rootShareEpoch ||
    !signingWorkerId ||
    !nearEd25519SigningKeyId ||
    !Array.isArray(participants) ||
    participants.length !== 2 ||
    !Number.isSafeInteger(participants[0]) ||
    !Number.isSafeInteger(participants[1]) ||
    !Number.isSafeInteger(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: 'router_ab_ed25519_wallet_recovery_authorization_v1',
    walletId,
    reservationId,
    keySetId,
    lifecycleId,
    thresholdSessionId,
    rootShareEpoch,
    signingWorkerId,
    nearEd25519SigningKeyId,
    participantIds: [participants[0], participants[1]],
    expiresAtMs,
  };
}

function recoveryClaimsMatchBinding(
  claims: WalletRecoveryAuthorizationClaims,
  binding: RouterAbEd25519YaoActivationBindingV1<'recovery'>,
): boolean {
  const lifecycle = binding.lifecycle;
  return (
    claims.walletId === lifecycle.account_id &&
    claims.lifecycleId === lifecycle.lifecycle_id &&
    claims.thresholdSessionId === lifecycle.session_id &&
    claims.signingWorkerId === lifecycle.selected_server_id
  );
}

async function recoveryClaimsAuthorize(
  claims: WalletRecoveryAuthorizationClaims,
  input: RouterAbEd25519YaoRecoveryAuthorizationInput,
): Promise<boolean> {
  let expectedLifecycleId: string;
  try {
    expectedLifecycleId = await deriveWalletRecoveryKeyLifecycleId({
      reservationId: parseRecoveryCodeReservationId(claims.reservationId),
      keySetId: claims.keySetId,
    });
  } catch {
    return false;
  }
  if (claims.lifecycleId !== expectedLifecycleId) return false;
  switch (input.kind) {
    case 'bootstrap':
      return false;
    case 'admit':
      return (
        claims.walletId === input.body.scope.account_id &&
        claims.walletId === input.body.application_binding.wallet_id &&
        claims.lifecycleId === input.body.scope.lifecycle_id &&
        claims.thresholdSessionId === input.body.scope.threshold_session_id &&
        claims.rootShareEpoch === input.body.scope.root_share_epoch &&
        claims.signingWorkerId === input.body.scope.signing_worker_id &&
        claims.nearEd25519SigningKeyId ===
          input.body.application_binding.near_ed25519_signing_key_id &&
        claims.participantIds[0] === input.body.participant_ids[0] &&
        claims.participantIds[1] === input.body.participant_ids[1]
      );
    case 'execute':
    case 'activate':
      return recoveryClaimsMatchBinding(claims, input.body.binding);
  }
}

export class RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter implements RouterAbEd25519YaoRecoveryAuthorizationAdapter {
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
    const recoveryClaims = parseWalletRecoveryAuthorizationClaims(parsed.claims);
    if (!recoveryClaims) {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_claims_invalid',
        message: walletSessionFailureMessage('wallet_session_claims_invalid'),
      });
    }
    if (recoveryClaims.expiresAtMs <= Date.now()) {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_expired',
        message: walletSessionFailureMessage('wallet_session_expired'),
      });
    }
    if (!(await recoveryClaimsAuthorize(recoveryClaims, input))) {
      return authorizationFailure({
        status: 403,
        code: 'wallet_session_scope_mismatch',
        message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
      });
    }
    return {
      ok: true,
      claims: { kind: 'wallet_recovery', walletId: recoveryClaims.walletId },
    };
  }
}
