# Google OIDC BYO Session Exchange Guide

Date updated: March 1, 2026

## Goal

Use Google OIDC sign-in for app identity and exchange verified Google tokens into relay app sessions.

## Prerequisites

1. Google OIDC sign-in is configured in your frontend/backend.
2. Backend verifies Google ID token (`iss`, `aud`, signature, expiry).
3. Relay verifier allowlist includes expected Google issuer/audience.

## Integration Flow

1. Client gets Google ID token after user sign-in.
2. Backend verifies token and extracts stable `sub`.
3. Backend exchanges token with relay `POST /session/exchange`.
4. Relay returns app session as JWT or HttpOnly cookie.

Optional one-step passkey path:

1. `POST /wallet/unlock/options`
2. collect WebAuthn assertion
3. `POST /session/exchange` with `exchange.type=passkey_assertion`

Route constraint:

- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.

## Backend Exchange Handler (TypeScript Example)

```ts
import type { Request, Response } from 'express';

type GoogleClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
  email?: string;
  email_verified?: boolean;
};

async function verifyGoogleIdToken(inputToken: string): Promise<GoogleClaims> {
  // Use your Google token verifier (JWKS/signature + claim checks).
  throw new Error('replace with Google token verification');
}

export async function createRelaySessionFromGoogle(req: Request, res: Response): Promise<void> {
  const bearer = String(req.headers.authorization || '');
  const inputToken = bearer.startsWith('Bearer ') ? bearer.slice('Bearer '.length).trim() : '';
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'missing token' });
    return;
  }

  await verifyGoogleIdToken(inputToken);

  const relayRes = await fetch(`${process.env.RELAY_BASE_URL}/session/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionKind: 'cookie',
      exchange: { type: 'oidc_jwt', token: inputToken },
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

## Operational Notes

1. Treat Google sign-out and account-risk events as triggers to call relay `POST /session/revoke`.
2. Keep wallet state operations separate (`POST /wallet/lock` for lock actions).
3. Dedupe lifecycle webhooks using `X-Console-Webhook-Event-Id`.
