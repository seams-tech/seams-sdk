export type WalletIframeSurfaceId = string & {
  readonly __walletIframeSurfaceId: unique symbol;
};

export type WalletIframeRequestId = string & {
  readonly __walletIframeRequestId: unique symbol;
};

function requireIdentityString(value: unknown, field: string): string {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${field} must be a non-empty string`);
  }
  return value.trim();
}

export function walletIframeSurfaceIdFromBoundary(value: unknown): WalletIframeSurfaceId {
  return requireIdentityString(value, 'surfaceId') as WalletIframeSurfaceId;
}

export function walletIframeRequestIdFromBoundary(value: unknown): WalletIframeRequestId {
  return requireIdentityString(value, 'requestId') as WalletIframeRequestId;
}
