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

export interface ConsoleSessionJwtHooks {
  signToken(input: {
    header: { typ: 'JWT' };
    payload: Record<string, unknown>;
  }): Promise<string> | string;
  verifyToken(
    token: string,
  ):
    | Promise<{ readonly valid: boolean; readonly payload?: unknown }>
    | { readonly valid: boolean; readonly payload?: unknown };
}

export interface ConsoleSessionCookieHooks {
  readonly name: string;
  buildSetHeader(token: string): string;
  buildClearHeader(): string;
}

export interface ConsoleSessionServiceConfig {
  readonly jwt: ConsoleSessionJwtHooks;
  readonly cookie: ConsoleSessionCookieHooks;
}

const RESERVED_JWT_CLAIMS = new Set(['sub', 'iat', 'exp', 'nbf', 'iss', 'aud', 'jti']);

/**
 * Console-owned session_v1 authority. `exp`/`nbf` are enforced here rather
 * than trusted to the verify hook so every composition gets identical time
 * semantics.
 */
export class ConsoleSessionService implements SessionAdapter {
  constructor(private readonly config: ConsoleSessionServiceConfig) {}

  private cookieName(): string {
    return this.config.cookie.name || 'seams-jwt';
  }

  buildSetCookie(token: string): string {
    return this.config.cookie.buildSetHeader(token);
  }

  buildClearCookie(): string {
    return this.config.cookie.buildClearHeader();
  }

  async signJwt(sub: string, extraClaims?: Record<string, unknown>): Promise<string> {
    const payload = { sub, ...(extraClaims || {}) } as Record<string, unknown>;
    return await Promise.resolve(this.config.jwt.signToken({ header: { typ: 'JWT' }, payload }));
  }

  async verifyJwt(
    token: string,
  ): Promise<
    | { readonly valid: true; readonly payload: Record<string, unknown> }
    | { readonly valid: false; readonly reason: Exclude<SessionParseFailureReason, 'missing'> }
  > {
    const out = await Promise.resolve(this.config.jwt.verifyToken(token));
    if (!out?.valid) return { valid: false, reason: 'signature_invalid' };
    const payload = out.payload as Record<string, unknown> | undefined;
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return { valid: false, reason: 'claims_invalid' };
    }
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp !== undefined) {
      const exp = Number(payload.exp);
      if (!Number.isFinite(exp)) return { valid: false, reason: 'claims_invalid' };
      if (now >= exp) return { valid: false, reason: 'expired' };
    }
    if (payload.nbf !== undefined) {
      const nbf = Number(payload.nbf);
      if (!Number.isFinite(nbf)) return { valid: false, reason: 'claims_invalid' };
      if (now < nbf) return { valid: false, reason: 'not_active' };
    }
    return { valid: true, payload };
  }

  private extractToken(headers: Record<string, string | string[] | undefined>): string | null {
    const authHeader = (headers['authorization'] || headers['Authorization']) as string | undefined;
    if (authHeader && /^Bearer\s+/.test(authHeader)) {
      return authHeader.replace(/^Bearer\s+/i, '').trim();
    }
    const cookieHeader = (headers['cookie'] || headers['Cookie']) as string | undefined;
    if (cookieHeader) {
      const name = this.cookieName();
      for (const part of cookieHeader.split(';')) {
        const [key, value] = part.split('=');
        if (key && key.trim() === name) return (value || '').trim();
      }
    }
    return null;
  }

  async parse(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<SessionParseResult<SessionClaims>> {
    const token = this.extractToken(headers);
    if (!token) return { ok: false, reason: 'missing' };
    const verified = await this.verifyJwt(token);
    if (!verified.valid) return { ok: false, reason: verified.reason };
    return { ok: true, claims: verified.payload };
  }

  async refresh(
    headers: Record<string, string | string[] | undefined>,
  ): Promise<{ ok: boolean; jwt?: string; code?: string; message?: string }> {
    const token = this.extractToken(headers);
    if (!token) return { ok: false, code: 'unauthorized', message: 'No session token' };
    const verified = await this.verifyJwt(token);
    if (!verified.valid) {
      if (verified.reason === 'expired') {
        return { ok: false, code: 'session_expired', message: 'Console session expired' };
      }
      return { ok: false, code: 'unauthorized', message: 'Invalid token' };
    }
    const sub = String(verified.payload.sub || '');
    if (!sub) return { ok: false, code: 'invalid_claims', message: 'Missing sub claim' };
    const extra: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(verified.payload)) {
      if (!RESERVED_JWT_CLAIMS.has(key)) extra[key] = value;
    }
    return { ok: true, jwt: await this.signJwt(sub, extra) };
  }
}
