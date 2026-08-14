import { base64UrlDecode } from './base64';

export const ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND =
  'router_ab_ed25519_wallet_session_v1' as const;
export const ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND =
  'router_ab_ecdsa_derivation_wallet_session_v1' as const;


declare const opaqueWalletSessionTokenBrand: unique symbol;
export type OpaqueWalletSessionToken = string & {
  readonly [opaqueWalletSessionTokenBrand]: true;
};

export type OpaqueWalletSessionAuth = {
  kind: 'opaque_wallet_session';
  walletSessionToken: OpaqueWalletSessionToken;
};

export type WalletSessionRouteAuth = OpaqueWalletSessionAuth;

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


export function requireOpaqueWalletSessionToken(
  tokenRaw: unknown,
  label = 'walletSessionToken',
): OpaqueWalletSessionToken {
  const token = String(tokenRaw || '').trim();
  if (!token) throw new Error(`${label} is required`);
  return token as OpaqueWalletSessionToken;
}

export function opaqueWalletSessionAuth(tokenRaw: unknown): OpaqueWalletSessionAuth {
  return {
    kind: 'opaque_wallet_session',
    walletSessionToken: requireOpaqueWalletSessionToken(tokenRaw),
  };
}
