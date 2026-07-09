import { base64UrlDecode } from './base64';

export const APP_SESSION_JWT_KIND = 'app_session_v1' as const;
export const THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND = 'threshold_ed25519_session_v1' as const;
export const THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND = 'threshold_ecdsa_session_v2' as const;
export const ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND =
  'router_ab_ed25519_wallet_session_v1' as const;
export const ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND =
  'router_ab_ecdsa_hss_wallet_session_v1' as const;

export type AppSessionJwtKind = typeof APP_SESSION_JWT_KIND;
export type LegacyThresholdSessionJwtKind =
  | typeof THRESHOLD_ED25519_SESSION_AUTH_TOKEN_KIND
  | typeof THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND;
export type WalletSessionJwtKind =
  | typeof ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
  | typeof ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND;
export type SessionJwtKind = AppSessionJwtKind | WalletSessionJwtKind;
export type WalletSessionThresholdExpiresAtMs = number & {
  readonly __brand: 'WalletSessionThresholdExpiresAtMs';
};

export type AppSessionJwtAuth = {
  kind: 'app_session';
  jwt: string;
};

export type WalletSessionJwtAuth = {
  kind: 'wallet_session';
  jwt: string;
};

export type CookieSessionAuth = {
  kind: 'cookie';
};

export type AppOrWalletSessionAuth = AppSessionJwtAuth | WalletSessionJwtAuth;
export type RouteSessionAuth = AppOrWalletSessionAuth | CookieSessionAuth;

export function decodeJwtPayloadRecord(jwtRaw: string): Record<string, unknown> | null {
  const jwt = String(jwtRaw || '').trim();
  const parts = jwt.split('.');
  if (parts.length < 2) return null;
  try {
    const decoded = base64UrlDecode(parts[1] || '');
    const parsed = JSON.parse(new TextDecoder().decode(decoded)) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

export function toWalletSessionThresholdExpiresAtMs(
  value: unknown,
): WalletSessionThresholdExpiresAtMs {
  const normalized = Math.floor(Number(value));
  if (!Number.isSafeInteger(normalized) || normalized <= 0) {
    throw new Error('Wallet Session JWT thresholdExpiresAtMs is invalid');
  }
  return normalized as WalletSessionThresholdExpiresAtMs;
}

export function getSessionJwtKind(jwtRaw: string): string | null {
  const payload = decodeJwtPayloadRecord(jwtRaw);
  if (!payload) return null;
  return typeof payload.kind === 'string' ? payload.kind.trim() || null : null;
}

export function getSessionJwtExpiresAtMs(jwtRaw: string): number | null {
  const payload = decodeJwtPayloadRecord(jwtRaw);
  if (!payload) return null;
  const expRaw = payload.exp;
  if (expRaw === undefined) return null;
  const exp = Number(expRaw);
  if (!Number.isFinite(exp) || exp <= 0) return null;
  return Math.floor(exp * 1000);
}

export function isSessionJwtUnexpired(jwtRaw: string, args?: { skewMs?: number }): boolean {
  const expiresAtMs = getSessionJwtExpiresAtMs(jwtRaw);
  if (!expiresAtMs) return false;
  const skewMs = Math.max(0, Math.floor(Number(args?.skewMs) || 0));
  return expiresAtMs > Date.now() + skewMs;
}

export function isAppSessionJwt(jwtRaw: string): boolean {
  const kind = getSessionJwtKind(jwtRaw);
  return kind === APP_SESSION_JWT_KIND;
}

export function isWalletSessionJwt(tokenRaw: string): boolean {
  const kind = getSessionJwtKind(tokenRaw);
  return (
    kind === ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND ||
    kind === ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND
  );
}

export function requireAppSessionJwt(jwtRaw: string, label = 'appSessionJwt'): string {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) throw new Error(`${label} is required`);
  if (!isAppSessionJwt(jwt)) {
    throw new Error(`${label} must be an app-session JWT`);
  }
  return jwt;
}

export function requireWalletSessionJwt(tokenRaw: string, label = 'walletSessionJwt'): string {
  const token = String(tokenRaw || '').trim();
  if (!token) throw new Error(`${label} is required`);
  if (!isWalletSessionJwt(token)) {
    throw new Error(`${label} must be a Wallet Session JWT`);
  }
  return token;
}

export function appSessionJwtAuth(jwtRaw: string): AppSessionJwtAuth {
  return { kind: 'app_session', jwt: requireAppSessionJwt(jwtRaw) };
}

export function walletSessionJwtAuth(tokenRaw: string): WalletSessionJwtAuth {
  return { kind: 'wallet_session', jwt: requireWalletSessionJwt(tokenRaw) };
}

export function appOrWalletSessionJwtAuth(jwtRaw: string): AppOrWalletSessionAuth {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) throw new Error('session JWT is required');
  const kind = getSessionJwtKind(jwt);
  if (
    kind === ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND ||
    kind === ROUTER_AB_ECDSA_HSS_WALLET_SESSION_JWT_KIND
  ) {
    return walletSessionJwtAuth(jwt);
  }
  if (kind === APP_SESSION_JWT_KIND) {
    return appSessionJwtAuth(jwt);
  }
  throw new Error('session JWT must include a valid session kind');
}
