# Bring Your Own Auth (BYO Auth)

Date updated: March 1, 2026

## TL;DR

BYO auth means:

1. Your app keeps its own auth provider (Auth0, Okta, Clerk, Supabase, Firebase, custom OIDC).
2. Relay mints app sessions via `POST /session/exchange`.
3. Wallet lock state is separate and handled with `wallet/*` routes.
4. `POST /auth/passkey/verify` is verification-only. It does not mint app sessions.

Dashboard-specific Google SSO flow and login guard behavior are maintained in `docs/dashboard/sso.md` (canonical dashboard auth reference).

The canonical route planes are:

1. Session plane: `/session/exchange`, `/session/state`, `/session/refresh`, `/session/revoke`
2. Wallet plane: `/wallet/unlock/challenge`, `/wallet/unlock/verify`, `/wallet/state`, `/wallet/lock`

## Mental Model

Treat auth and wallet as two independent concerns:

1. Identity/authentication:
   - Owned by your auth system.
   - Produces a verified assertion (usually OIDC JWT).

2. App session transport:
   - Minted by relay through `/session/exchange`.
   - Transport can be `jwt` or `cookie`.
   - Cookie name is strict and defaults to `tatchi-jwt`.

3. Wallet unlock/lock:
   - Unlock and lock semantics are wallet-state semantics, not app-login semantics.
   - Wallet lock can be forced by revocation/risk workflows.

## How JWT/HttpOnly Sessions Relate to Wallet Unlock/Lock

`sessionKind` (`jwt` vs `cookie`) controls transport only. It does not change wallet semantics.

Wallet lock state is derived from whether relay can validate a current app session:

1. claim kind must be `app_session_v1`
2. `appSessionVersion` must match identity-store current version

If validation fails, wallet is considered locked.

### Transport Mapping

1. `sessionKind="jwt"`:
   - client stores token and sends `Authorization: Bearer <jwt>`
   - required for protected wallet/session routes

2. `sessionKind="cookie"`:
   - relay sets HttpOnly cookie (default name `tatchi-jwt`)
   - client sends `credentials: 'include'` and browser carries cookie

### Operation Matrix

1. `POST /session/exchange` with `exchange.type=oidc_jwt`
   - mints app session (JWT or cookie)
   - wallet becomes unlocked (`GET /wallet/state` => `locked: false`)
   - emits `session.warm.created`

2. `POST /session/exchange` with `exchange.type=passkey_assertion`
   - mints app session (JWT or cookie)
   - wallet becomes unlocked
   - emits `session.warm.created` and `wallet.unlocked`

3. `POST /wallet/unlock/verify`
   - verifies passkey assertion only
   - does not mint app session
   - emits `wallet.unlocked`
   - if no valid app session exists, `GET /wallet/state` may still report `locked: true`

4. `POST /session/revoke`
   - rotates `appSessionVersion` + clears cookie
   - effectively locks wallet by invalidating app session
   - emits `session.revoked`

5. `POST /wallet/lock`
   - same revocation primitive (rotate session version + clear cookie)
   - emits `wallet.locked`

Practical rule: if you want "login + usable unlocked wallet session", use `POST /session/exchange` (OIDC or passkey assertion path), not `POST /wallet/unlock/verify` alone.

## Session Exchange Contract

`POST /session/exchange` supports two exchange types.

OIDC exchange:

```json
{
  "sessionKind": "cookie",
  "exchange": {
    "type": "oidc_jwt",
    "token": "eyJ..."
  }
}
```

Passkey assertion exchange:

```json
{
  "sessionKind": "jwt",
  "exchange": {
    "type": "passkey_assertion",
    "challengeId": "challenge-id",
    "webauthn_authentication": {
      "id": "...",
      "rawId": "...",
      "type": "public-key",
      "response": {
        "clientDataJSON": "...",
        "authenticatorData": "...",
        "signature": "...",
        "userHandle": null
      }
    }
  }
}
```

Success response:

1. `sessionKind="jwt"`: `{ ok: true, session: { kind, userId, expiresAt? }, jwt }`
2. `sessionKind="cookie"`: `Set-Cookie` header, JSON body omits `jwt`

## Relay Setup (Express)

This is the minimum production shape:

1. Configure `AuthService` with `oidcExchange` issuer/JWKS/audience allowlist.
2. Configure `SessionService` for JWT signing + cookie behavior.
3. Mount `createRelayRouter` with `session` and `sessionCookieName`.

```ts
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import { AuthService, SessionService } from '@tatchi-xyz/sdk/server';
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express';

const sessionCookieName = process.env.SESSION_COOKIE_NAME?.trim() || 'tatchi-jwt';

const authService = new AuthService({
  relayerAccount: process.env.RELAYER_ACCOUNT_ID!,
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY!,
  nearRpcUrl: process.env.NEAR_RPC_URL || 'https://test.rpc.fastnear.com',
  networkId: process.env.NETWORK_ID || 'testnet',
  oidcExchange: {
    clockSkewSec: 60,
    issuers: [
      {
        issuer: 'https://YOUR_ISSUER/',
        jwksUrl: 'https://YOUR_ISSUER/.well-known/jwks.json',
        audiences: ['YOUR_AUDIENCE'],
        subjectPrefix: 'oidc:your-issuer:', // optional
      },
    ],
  },
});

const session = new SessionService({
  jwt: {
    signToken: ({ payload }) => {
      const hasExp =
        typeof (payload as any).exp === 'number' && Number.isFinite((payload as any).exp);
      return jwt.sign(payload as any, process.env.JWT_SECRET!, {
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER || 'relay',
        audience: process.env.JWT_AUDIENCE || 'app',
        ...(hasExp ? {} : { expiresIn: Number(process.env.JWT_EXPIRES_SEC || 86400) }),
      });
    },
    verifyToken: async (token) => {
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET!) as Record<string, unknown>;
        return { valid: true, payload };
      } catch {
        return { valid: false };
      }
    },
  },
  cookie: { name: sessionCookieName },
});

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(
  cors({
    origin: [process.env.EXPECTED_ORIGIN!, process.env.EXPECTED_WALLET_ORIGIN!].filter(Boolean),
    credentials: true,
  }),
);

app.use(
  '/',
  createRelayRouter(authService, {
    healthz: true,
    readyz: true,
    session,
    sessionCookieName, // strict stale-cookie matching uses this name
  }),
);

app.listen(3000);
```

## Recommended Exchange Topology

For advanced deployments, use backend-mediated exchange:

1. Frontend obtains provider token from your auth system.
2. Frontend sends token to your backend (same trust domain as your app auth).
3. Backend calls relay `/session/exchange`.
4. Backend forwards `Set-Cookie` (or JWT) to frontend.

```ts
import type { Request, Response } from 'express';

async function verifyProviderToken(inputToken: string): Promise<void> {
  // Your verifier (provider SDK/JWKS checks): iss, aud, exp, nbf, iat, signature.
}

export async function exchangeRelaySession(req: Request, res: Response): Promise<void> {
  const inputToken = String(req.body?.idToken || '').trim();
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'idToken required' });
    return;
  }

  await verifyProviderToken(inputToken);

  const relayRes = await fetch(`${process.env.RELAY_BASE_URL}/session/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionKind: 'cookie',
      exchange: {
        type: 'oidc_jwt',
        token: inputToken,
      },
    }),
  });

  const text = await relayRes.text();
  const json = text ? JSON.parse(text) : {};
  const setCookie = relayRes.headers.get('set-cookie');
  if (setCookie) res.setHeader('Set-Cookie', setCookie);
  res.status(relayRes.status).json(json);
}
```

## SDK Client Example (OIDC -> Relay Session)

Use SDK unlock with session exchange payload:

```ts
await tatchi.auth.unlock(nearAccountId, {
  session: {
    kind: 'cookie', // or 'jwt'
    relayUrl: 'https://relay.example.com',
    exchange: {
      type: 'oidc_jwt',
      token: idTokenFromYourAuthProvider,
    },
  },
});
```

Notes:

1. `session.route` defaults to `/session/exchange`.
2. For `kind: 'cookie'`, SDK calls exchange with `credentials: 'include'`.
3. In `threshold-signer` mode, unlock may also enforce warm session bootstrap based on your signing policy.

## One-Step Passkey Login + App Session Mint

SDK can do passkey assertion exchange in a single unlock call:

```ts
await tatchi.auth.unlock(nearAccountId, {
  session: {
    kind: 'cookie',
    relayUrl: 'https://relay.example.com',
    exchange: {
      type: 'passkey_assertion',
      expectedOrigin: window.location.origin, // optional
    },
  },
});
```

What SDK does internally:

1. `POST /wallet/unlock/challenge`
2. Runs WebAuthn `navigator.credentials.get(...)`
3. `POST /session/exchange` with `exchange.type=passkey_assertion`

## Session and Wallet Lifecycle Operations

Typical app controls:

```ts
// read app session
await fetch('/session/state', { credentials: 'include' });

// refresh session transport
await fetch('/session/refresh', {
  method: 'POST',
  credentials: 'include',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ sessionKind: 'cookie' }),
});

// revoke app session
await fetch('/session/revoke', { method: 'POST', credentials: 'include' });

// force wallet lock
await fetch('/wallet/lock', { method: 'POST', credentials: 'include' });
```

## Webhooks (Optional, Recommended)

Relay can emit lifecycle events:

1. `session.warm.created`
2. `session.warm.refreshed`
3. `session.warm.expired`
4. `session.exchange.failed`
5. `session.revoked`
6. `wallet.unlocked`
7. `wallet.locked`

For consumers:

1. Verify signature + timestamp.
2. Deduplicate by `X-Console-Webhook-Event-Id`.
3. Make handlers idempotent.

## Security Checklist

1. Keep provider token verification in backend unless you intentionally trust direct relay exchange.
2. Configure strict OIDC issuer/audience allowlists in `oidcExchange`.
3. Use HTTPS everywhere and explicit CORS allowlist with credentials.
4. Keep `SESSION_COOKIE_NAME` consistent across:
   - SessionService cookie config
   - router `sessionCookieName`
5. On sign-out/risk events, call both:
   - `POST /session/revoke`
   - `POST /wallet/lock`
6. Do not use `/auth/passkey/verify` for app-session minting.

## Common Error Codes (OIDC Exchange)

Expected failure codes from OIDC verification path include:

1. `not_configured`
2. `invalid_body`
3. `invalid_claims`
4. `invalid_issuer`
5. `invalid_audience`
6. `unknown_kid`
7. `invalid_signature`
8. `expired`
9. `not_yet_valid`

Use these codes for backend observability and user-facing error mapping.

## Related Docs

1. `docs/byo-auth.md`
2. `docs/auth-provider-integrations/README.md`
3. `docs/auth-provider-integrations/auth0.md`
4. `docs/auth-provider-integrations/okta.md`
5. `docs/auth-provider-integrations/quickstarts-clerk-supabase-firebase.md`
