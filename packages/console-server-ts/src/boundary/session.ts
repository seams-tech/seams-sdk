// Console-owned session port. Structurally identical to the Wallet server's
// SessionAdapter so the currently deployed adapter satisfies it unchanged;
// R105 Phase 4 moves issuance and storage behind this contract.
export type SessionClaims = Record<string, unknown>;

export type SessionParseFailureReason =
  | 'missing'
  | 'signature_invalid'
  | 'claims_invalid'
  | 'expired'
  | 'not_active';

export type SessionParseResult<TClaims extends Record<string, unknown>> =
  | {
      readonly ok: true;
      readonly claims: TClaims;
    }
  | {
      readonly ok: false;
      readonly reason: SessionParseFailureReason;
    };

export interface SessionAdapter {
  signJwt(sub: string, extra?: Record<string, unknown>): Promise<string>;
  /** Local verification against pinned key material; never a JWKS fetch. */
  verifyJwt(
    token: string,
  ): Promise<
    { readonly valid: true; readonly payload: Record<string, unknown> } | { readonly valid: false }
  >;
  parse(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<SessionParseResult<SessionClaims>>;
  buildSetCookie(token: string): string;
  buildClearCookie(): string;
  refresh(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<{ ok: boolean; jwt?: string; code?: string; message?: string }>;
}
