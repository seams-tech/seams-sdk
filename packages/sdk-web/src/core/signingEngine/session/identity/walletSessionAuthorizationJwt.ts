import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseSeamsSessionId,
  parseWalletSessionId,
  type MpcWalletSigningQuotaId,
  type SeamsSessionId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  decodeJwtPayloadRecord,
  getSessionJwtExpiresAtMs,
  isWalletSessionJwt,
  ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND,
  ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND,
} from '@shared/utils/sessionTokens';
import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

export type WalletSessionAuthorizationIdentityClaims = {
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly sessionBinding:
    | { readonly kind: 'unbound' }
    | { readonly kind: 'seams_session'; readonly seamsSessionId: SeamsSessionId };
  readonly expiresAtMs: number;
};

function parseSessionBinding(
  payload: Record<string, unknown> | null,
): WalletSessionAuthorizationIdentityClaims['sessionBinding'] | null {
  if (!payload) return null;
  if (
    payload.kind !== ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND &&
    payload.kind !== ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND
  ) {
    return null;
  }
  const seamsSessionId = parseSeamsSessionId(payload.sid);
  return seamsSessionId.ok
    ? { kind: 'seams_session', seamsSessionId: seamsSessionId.value }
    : { kind: 'unbound' };
}

function parseExpiresAtMs(
  walletSessionJwt: string,
  payload: Record<string, unknown> | null,
): number | null {
  if (!payload) return null;
  const thresholdExpiresAtMsRaw = payload.thresholdExpiresAtMs;
  const thresholdExpiresAtMs =
    thresholdExpiresAtMsRaw === undefined ? null : Number(thresholdExpiresAtMsRaw);
  if (
    thresholdExpiresAtMs !== null &&
    (!Number.isSafeInteger(thresholdExpiresAtMs) || thresholdExpiresAtMs <= 0)
  ) {
    return null;
  }
  const expMs = payload.exp === undefined ? null : getSessionJwtExpiresAtMs(walletSessionJwt);
  if (payload.exp !== undefined && expMs === null) return null;
  if (thresholdExpiresAtMs === null && expMs === null) return null;
  if (
    thresholdExpiresAtMs !== null &&
    expMs !== null &&
    (expMs > thresholdExpiresAtMs || thresholdExpiresAtMs - expMs >= 1_000)
  ) {
    return null;
  }
  return thresholdExpiresAtMs ?? expMs;
}

export function walletSessionAuthorizationIdentityIdsAreDistinct(args: {
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
}): boolean {
  return new Set([args.authorizationId, args.walletSessionId, args.quotaId]).size === 3;
}

export function parseWalletSessionAuthorizationIdentityClaims(
  walletSessionJwt: string,
): WalletSessionAuthorizationIdentityClaims | null {
  if (!isWalletSessionJwt(walletSessionJwt)) return null;
  const payload = decodeJwtPayloadRecord(walletSessionJwt);
  const walletId = parseWalletId(payload?.walletId);
  const authorizationId = parseWalletSessionAuthorizationId(payload?.authorizationId);
  const walletSessionId = parseWalletSessionId(payload?.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(payload?.quotaId);
  const sessionBinding = parseSessionBinding(payload);
  const expiresAtMs = parseExpiresAtMs(walletSessionJwt, payload);
  if (
    !walletId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    sessionBinding === null ||
    expiresAtMs === null ||
    !walletSessionAuthorizationIdentityIdsAreDistinct({
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
    })
  ) {
    return null;
  }
  return {
    walletId: walletId.value,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    sessionBinding,
    expiresAtMs,
  };
}
