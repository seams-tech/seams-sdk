# Auth0 BYO Session Exchange Guide

Date updated: March 1, 2026

## Goal

Use Auth0 for primary login while creating relay app sessions through `POST /session/exchange`.

## Prerequisites

1. Auth0 tenant/app is configured for OIDC.
2. Backend verifies Auth0 ID tokens (or issues a backend exchange JWT after verification).
3. Relay verifier allowlist includes your Auth0 issuer/audience.

## Integration Flow

1. User authenticates with Auth0.
2. Backend verifies Auth0 token and resolves stable `sub`.
3. Backend exchanges token with relay `POST /session/exchange`.
4. Relay returns JWT or HttpOnly cookie based on `sessionKind`.
5. Wallet lifecycle uses relay `session/*` and `wallet/*`.

Optional one-step passkey path:

1. `POST /wallet/unlock/challenge`
2. collect WebAuthn assertion
3. `POST /session/exchange` with `exchange.type=passkey_assertion`

Route constraint:

- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.

## Backend Exchange Handler (TypeScript Example)

```ts
import type { Request, Response } from 'express';

type Auth0Claims = {
  sub: string;
  iss: string;
  aud: string | string[];
  exp?: number;
};

async function verifyAuth0Token(inputToken: string): Promise<Auth0Claims> {
  // Verify signature (JWKS), issuer, audience, exp/nbf/iat using your Auth0 verifier.
  throw new Error('replace with Auth0 token verification');
}

export async function createRelaySessionFromAuth0(req: Request, res: Response): Promise<void> {
  const bearer = String(req.headers.authorization || '');
  const inputToken = bearer.startsWith('Bearer ') ? bearer.slice('Bearer '.length).trim() : '';
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'missing token' });
    return;
  }

  await verifyAuth0Token(inputToken);

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

## Claim Mapping Notes

1. Use Auth0 `sub` as stable user subject.
2. Map optional tenant context claims to relay org scoping (`orgId`, `org_id`, `tenantId`, `tenant_id`) when needed.
3. Keep app roles in your backend authorization layer; relay lifecycle webhooks can include role context when configured.

## Lifecycle and Operations

1. App sign-out should call relay `POST /session/revoke` and `POST /wallet/lock`.
2. Wallet lock operations call relay `POST /wallet/lock`.
3. Observe webhook events for lifecycle orchestration and incident handling.
4. Dedupe webhook processing by `X-Console-Webhook-Event-Id`.
