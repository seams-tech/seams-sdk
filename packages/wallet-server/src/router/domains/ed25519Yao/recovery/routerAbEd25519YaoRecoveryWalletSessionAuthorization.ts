import type { RouterAbEd25519YaoActivationBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import { headersToRecord } from '../../../framework/http';
import type { SessionAdapter } from '../../../framework/routerApi';
import type { RouterApiAuthorizationSessionService } from '../../../framework/authServicePort';
import { extractBearerCredential } from '../../../auth/routerApiKeyAuth';
import { resolveOpaqueOwnerWalletSessionAdmission } from '../../../auth/commonRouterUtils';
import { parseLinkedDeviceWalletSessionForCurve } from '../../signingOperations/linkedDeviceNormalSigning';
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';
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

async function authorizeOpaqueOwnerRecovery(input: {
  readonly request: RouterAbEd25519YaoRecoveryAuthorizationInput;
  readonly resolveAuthorizationSessions: () => Promise<RouterApiAuthorizationSessionService>;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult | null> {
  const token = extractBearerCredential(headersToRecord(input.request.request.headers));
  if (!token?.startsWith('wst_')) return null;
  let admission: Awaited<ReturnType<typeof resolveOpaqueOwnerWalletSessionAdmission>>;
  try {
    admission = await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions: await input.resolveAuthorizationSessions(),
      token,
      curve: 'ed25519',
      nowMs: Date.now(),
    });
  } catch {
    return authorizationFailure({
      status: 503,
      code: 'wallet_session_unavailable',
      message: walletSessionFailureMessage('wallet_session_unavailable'),
    });
  }
  if (!admission || admission.curve !== 'ed25519') {
    return authorizationFailure({
      status: 401,
      code: 'wallet_session_invalid',
      message: walletSessionFailureMessage('wallet_session_invalid'),
    });
  }
  const binding = admission.binding;
  let matches: boolean;
  switch (input.request.kind) {
    case 'bootstrap':
      matches =
        binding.walletId === input.request.body.walletId &&
        binding.nearAccountId === input.request.body.nearAccountId &&
        binding.nearEd25519SigningKeyId === input.request.body.nearEd25519SigningKeyId &&
        binding.thresholdSessionId === input.request.body.thresholdSessionId &&
        binding.routerAbNormalSigning.signingWorkerId === input.request.body.signingWorkerId &&
        binding.participantIds[0] === input.request.body.participantIds[0] &&
        binding.participantIds[1] === input.request.body.participantIds[1];
      break;
    case 'admit':
      matches =
        binding.walletId === input.request.body.scope.account_id &&
        binding.walletId === input.request.body.application_binding.wallet_id &&
        binding.nearEd25519SigningKeyId ===
          input.request.body.application_binding.near_ed25519_signing_key_id &&
        binding.runtimePolicyScope.signingRootVersion ===
          input.request.body.scope.root_share_epoch &&
        binding.routerAbNormalSigning.signingWorkerId ===
          input.request.body.scope.signing_worker_id &&
        binding.participantIds[0] === input.request.body.participant_ids[0] &&
        binding.participantIds[1] === input.request.body.participant_ids[1];
      break;
    case 'execute':
    case 'activate':
      matches =
        binding.walletId === input.request.body.binding.lifecycle.account_id &&
        binding.runtimePolicyScope.signingRootVersion ===
          input.request.body.binding.lifecycle.root_share_epoch &&
        binding.routerAbNormalSigning.signingWorkerId ===
          input.request.body.binding.lifecycle.selected_server_id;
      break;
  }
  if (!matches) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return {
    ok: true,
    authorization: { kind: 'wallet_session', binding },
  };
}

async function authorizeLinkedDeviceExportBootstrap(input: {
  readonly request: RouterAbEd25519YaoRecoveryAuthorizationInput;
  readonly session: SessionAdapter;
}): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult | null> {
  if (input.request.kind !== 'bootstrap') return null;
  const token = extractBearerCredential(headersToRecord(input.request.request.headers));
  if (!token || token.startsWith('wst_')) return null;
  const linked = await parseLinkedDeviceWalletSessionForCurve({
    curve: 'ed25519',
    session: input.session,
    headers: headersToRecord(input.request.request.headers),
  });
  if (linked.kind !== 'linked_device' || linked.curve !== 'ed25519') {
    return null;
  }
  const claims = linked.claims;
  const expectedWalletKeyId = `wallet-key:ed25519:${input.request.body.walletId}:${input.request.body.nearEd25519SigningKeyId}`;
  if (
    !hasDelegatedWalletPermissionV1(claims.permission, 'export_keys') ||
    claims.walletId !== input.request.body.walletId ||
    String(claims.walletKeyId) !== expectedWalletKeyId
  ) {
    return authorizationFailure({
      status: 403,
      code: 'wallet_session_scope_mismatch',
      message: walletSessionFailureMessage('wallet_session_scope_mismatch'),
    });
  }
  return {
    ok: true,
    authorization: {
      kind: 'linked_device_wallet_session',
      claims,
    },
  };
}

export class RouterAbEd25519YaoRecoveryWalletSessionAuthorizationAdapter implements RouterAbEd25519YaoRecoveryAuthorizationAdapter {
  constructor(
    private readonly session: SessionAdapter,
    private readonly resolveAuthorizationSessions: () => Promise<RouterApiAuthorizationSessionService>,
  ) {}

  async authorize(
    input: RouterAbEd25519YaoRecoveryAuthorizationInput,
  ): Promise<RouterAbEd25519YaoRecoveryAuthorizationResult> {
    const opaque = await authorizeOpaqueOwnerRecovery({
      request: input,
      resolveAuthorizationSessions: this.resolveAuthorizationSessions,
    });
    if (opaque) return opaque;
    const linked = await authorizeLinkedDeviceExportBootstrap({
      request: input,
      session: this.session,
    });
    if (linked) return linked;
    if (input.kind === 'bootstrap') {
      return authorizationFailure({
        status: 401,
        code: 'wallet_session_missing',
        message: walletSessionFailureMessage('wallet_session_missing'),
      });
    }
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
      authorization: { kind: 'wallet_recovery', walletId: recoveryClaims.walletId },
    };
  }
}
