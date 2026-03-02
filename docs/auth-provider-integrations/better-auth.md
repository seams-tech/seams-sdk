# Better Auth BYO Session Exchange Guide

Date updated: March 1, 2026

## Goal

Use Better Auth for app login while delegating wallet warm-session transport to relay `session/*` routes.

This guide keeps app auth and wallet state decoupled:

1. Better Auth proves user identity.
2. Your backend exchanges that proof to relay `POST /session/exchange`.
3. Wallet state transitions remain in relay `wallet/*`.

## Prerequisites

1. Better Auth is already configured in your app/backend.
2. Relay exposes:
- `POST /session/exchange`
- `POST /session/refresh`
- `POST /session/revoke`
- `GET /session/state`
3. Relay OIDC/JWT verifier config trusts your Better Auth issuer/audience.

## Integration Flow

1. User signs in using Better Auth.
2. Backend verifies Better Auth session/token and resolves a stable subject (`sub`).
3. Backend sends the verified token to relay:
- `exchange.type=oidc_jwt`
- `exchange.token=<verified id token or backend-issued exchange JWT>`
4. Relay returns:
- JWT session payload (`sessionKind=jwt`) or
- HttpOnly cookie (`sessionKind=cookie`)
5. Client continues wallet operations via relay using `session/*` and `wallet/*`.

Optional one-step passkey path (no provider token exchange):

1. `POST /wallet/unlock/challenge`
2. collect WebAuthn assertion
3. `POST /session/exchange` with `exchange.type=passkey_assertion`

Route constraint:

- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.

## Backend Exchange Handler (TypeScript Example)

```ts
import type { Request, Response } from 'express';

type BetterAuthClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
  exp?: number;
};

async function verifyBetterAuthToken(inputToken: string): Promise<BetterAuthClaims> {
  // Use your Better Auth server SDK/runtime verifier here.
  // This function must fail closed on invalid issuer/audience/signature/expiry.
  throw new Error('replace with Better Auth verification');
}

export async function createRelaySession(req: Request, res: Response): Promise<void> {
  const bearer = String(req.headers.authorization || '');
  const inputToken = bearer.startsWith('Bearer ') ? bearer.slice('Bearer '.length).trim() : '';
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'missing token' });
    return;
  }

  await verifyBetterAuthToken(inputToken);

  const relayRes = await fetch(`${process.env.RELAY_BASE_URL}/session/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionKind: 'cookie', // or "jwt"
      exchange: {
        type: 'oidc_jwt',
        token: inputToken,
      },
    }),
  });

  const bodyText = await relayRes.text();
  const body = bodyText ? JSON.parse(bodyText) : {};
  if (!relayRes.ok) {
    res.status(relayRes.status).json(body);
    return;
  }

  const setCookie = relayRes.headers.get('set-cookie');
  if (setCookie) res.setHeader('Set-Cookie', setCookie);
  res.status(200).json(body);
}
```

## Claims Mapping Contract

1. `sub` must be stable per user.
2. `iss` must match relay allowlist.
3. `aud` must match relay allowlist.
4. Optional org/tenant claims can be forwarded for scoped webhook emission (`orgId`, `org_id`, `tenantId`, `tenant_id`).

## Session Lifecycle Mapping

1. Better Auth sign-out in your app should call relay `POST /session/revoke` and `POST /wallet/lock`.
2. Wallet lock action should call relay `POST /wallet/lock`.
3. Use relay `POST /session/refresh` for sliding warm-session renewal.
4. Observe lifecycle events through relay webhooks:
- `session.warm.created`
- `session.warm.refreshed`
- `session.warm.expired`
- `session.revoked`
- `wallet.unlocked`
- `wallet.locked`
- `session.exchange.failed`

## Validation Checklist

1. Exchange succeeds for valid Better Auth user token.
2. Invalid issuer/audience/signature is rejected at exchange.
3. `sessionKind=cookie` sets HttpOnly cookie and omits JWT body.
4. `POST /session/revoke` invalidates stale app sessions.
5. Webhook consumer dedupes by `X-Console-Webhook-Event-Id`.
