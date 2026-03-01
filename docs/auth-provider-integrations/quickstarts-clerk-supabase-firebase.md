# Clerk / Supabase / Firebase Quickstarts (OIDC Exchange Pattern)

Date updated: March 1, 2026

## Goal

Reuse one backend pattern across Clerk, Supabase Auth, and Firebase Auth:

1. Verify provider token in your backend.
2. Exchange verified token via relay `POST /session/exchange`.
3. Keep wallet state transitions in relay `wallet/*`.
4. Optionally use passkey one-step mint (`wallet/unlock/options -> session/exchange(passkey_assertion)`).

## Shared Backend Pattern

```ts
import type { Request, Response } from 'express';

type VerifiedClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
};

async function verifyProviderToken(inputToken: string): Promise<VerifiedClaims> {
  // Replace with Clerk/Supabase/Firebase verifier.
  throw new Error('replace with provider token verification');
}

export async function createRelaySession(req: Request, res: Response): Promise<void> {
  const bearer = String(req.headers.authorization || '');
  const inputToken = bearer.startsWith('Bearer ') ? bearer.slice('Bearer '.length).trim() : '';
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'missing token' });
    return;
  }

  await verifyProviderToken(inputToken);

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

## Provider-Specific Notes

1. Clerk:
- Verify Clerk session/JWT server-side and enforce expected audience/issuer.
- Use Clerk org context mapping in your app backend authorization.

2. Supabase:
- Verify Supabase JWT (`sub`, issuer, audience, expiry) server-side before relay exchange.
- Use Supabase role/tenant claims in backend policy checks.

3. Firebase:
- Verify Firebase ID token with Admin SDK in backend.
- Map Firebase `uid`/`sub` to your stable app user key if needed.

## Ops Checklist

1. Backend fails closed on invalid signature/issuer/audience/expiry.
2. Relay receives only verified tokens.
3. Logout/risk workflows call relay `POST /session/revoke` and `POST /wallet/lock`.
4. Webhook consumers dedupe by `X-Console-Webhook-Event-Id`.
5. `POST /auth/passkey/verify` is verification-only and is not used for app-session minting.
