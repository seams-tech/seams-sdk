import { base64UrlDecode } from './base64';

export const APP_SESSION_JWT_KIND = 'app_session_v1' as const;
export const THRESHOLD_ED25519_SESSION_JWT_KIND = 'threshold_ed25519_session_v1' as const;
export const THRESHOLD_ECDSA_SESSION_JWT_KIND = 'threshold_ecdsa_session_v1' as const;
export const REGISTRATION_CONTINUATION_JWT_KIND = 'registration_continuation_v1' as const;

export type AppSessionJwtKind = typeof APP_SESSION_JWT_KIND;
export type ThresholdSessionJwtKind =
  | typeof THRESHOLD_ED25519_SESSION_JWT_KIND
  | typeof THRESHOLD_ECDSA_SESSION_JWT_KIND;
export type RegistrationContinuationJwtKind = typeof REGISTRATION_CONTINUATION_JWT_KIND;
export type SessionJwtKind =
  | AppSessionJwtKind
  | ThresholdSessionJwtKind
  | RegistrationContinuationJwtKind;

export type AppSessionJwtAuth = {
  kind: 'app_session';
  jwt: string;
};

export type ThresholdSessionJwtAuth = {
  kind: 'threshold_session';
  jwt: string;
};

export type CookieSessionAuth = {
  kind: 'cookie';
};

export type AppOrThresholdSessionAuth = AppSessionJwtAuth | ThresholdSessionJwtAuth;
export type RouteSessionAuth = AppOrThresholdSessionAuth | CookieSessionAuth;

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

export function isThresholdSessionJwt(jwtRaw: string): boolean {
  const kind = getSessionJwtKind(jwtRaw);
  return kind === THRESHOLD_ED25519_SESSION_JWT_KIND || kind === THRESHOLD_ECDSA_SESSION_JWT_KIND;
}

export function requireAppSessionJwt(jwtRaw: string, label = 'appSessionJwt'): string {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) throw new Error(`${label} is required`);
  if (!isAppSessionJwt(jwt)) {
    throw new Error(`${label} must be an app-session JWT`);
  }
  return jwt;
}

export function requireThresholdSessionJwt(jwtRaw: string, label = 'thresholdSessionJwt'): string {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) throw new Error(`${label} is required`);
  if (!isThresholdSessionJwt(jwt)) {
    throw new Error(`${label} must be a threshold-session JWT`);
  }
  return jwt;
}

export function appSessionJwtAuth(jwtRaw: string): AppSessionJwtAuth {
  return { kind: 'app_session', jwt: requireAppSessionJwt(jwtRaw) };
}

export function thresholdSessionJwtAuth(jwtRaw: string): ThresholdSessionJwtAuth {
  return { kind: 'threshold_session', jwt: requireThresholdSessionJwt(jwtRaw) };
}

export function appOrThresholdSessionJwtAuth(jwtRaw: string): AppOrThresholdSessionAuth {
  const jwt = String(jwtRaw || '').trim();
  if (!jwt) throw new Error('session JWT is required');
  const kind = getSessionJwtKind(jwt);
  if (kind === THRESHOLD_ED25519_SESSION_JWT_KIND || kind === THRESHOLD_ECDSA_SESSION_JWT_KIND) {
    return thresholdSessionJwtAuth(jwt);
  }
  if (kind === APP_SESSION_JWT_KIND) {
    return appSessionJwtAuth(jwt);
  }
  throw new Error('session JWT must include a valid session kind');
}
