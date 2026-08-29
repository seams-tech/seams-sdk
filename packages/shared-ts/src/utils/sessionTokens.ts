declare const opaqueWalletSessionTokenBrand: unique symbol;
export type OpaqueWalletSessionToken = string & {
  readonly [opaqueWalletSessionTokenBrand]: true;
};

export type OpaqueWalletSessionAuth = {
  kind: 'opaque_wallet_session';
  walletSessionToken: OpaqueWalletSessionToken;
};

export type WalletSessionRouteAuth = OpaqueWalletSessionAuth;
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
