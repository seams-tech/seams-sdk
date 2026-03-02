# Okta BYO Session Exchange Guide

Date updated: March 1, 2026

## Goal

Use Okta OIDC for enterprise authentication and exchange verified tokens into relay app sessions.

## Prerequisites

1. Okta OIDC app is configured with the correct audience and redirect flow.
2. Backend verifies Okta tokens (issuer, audience, signature, time claims).
3. Relay verifier allowlist includes your Okta issuer/audience.

## Integration Flow

1. User signs in with Okta.
2. Backend verifies Okta token and extracts stable `sub`.
3. Backend calls relay `POST /session/exchange` with `exchange.type=oidc_jwt`.
4. Relay returns app session (`jwt` or `Set-Cookie`).

Optional one-step passkey path:

1. `POST /wallet/unlock/challenge`
2. collect WebAuthn assertion
3. `POST /session/exchange` with `exchange.type=passkey_assertion`

Route constraint:

- `POST /auth/passkey/verify` is verification-only and does not mint app sessions.

## Backend Exchange Handler (TypeScript Example)

```ts
import type { Request, Response } from 'express';

type OktaClaims = {
  sub: string;
  iss: string;
  aud: string | string[];
  groups?: string[];
};

async function verifyOktaToken(inputToken: string): Promise<OktaClaims> {
  // Verify via Okta JWKS and claim checks in your backend.
  throw new Error('replace with Okta token verification');
}

export async function createRelaySessionFromOkta(req: Request, res: Response): Promise<void> {
  const bearer = String(req.headers.authorization || '');
  const inputToken = bearer.startsWith('Bearer ') ? bearer.slice('Bearer '.length).trim() : '';
  if (!inputToken) {
    res.status(400).json({ ok: false, code: 'invalid_body', message: 'missing token' });
    return;
  }

  const claims = await verifyOktaToken(inputToken);

  const relayRes = await fetch(`${process.env.RELAY_BASE_URL}/session/exchange`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      sessionKind: 'cookie',
      exchange: { type: 'oidc_jwt', token: inputToken },
      // Optional custom metadata may be included in your own backend assertion format
      // before exchange; relay currently keys primary identity on verified subject mapping.
      context: { sub: claims.sub },
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

## Enterprise Claim Mapping Notes

1. Keep `sub` as canonical user key.
2. Map enterprise context (for example `groups`, tenant identifiers) in your backend authorization layer.
3. Optionally surface org/tenant claim keys for relay webhook scoping (`orgId`, `org_id`, `tenantId`, `tenant_id`).

## Lifecycle Notes

1. On SSO sign-out or security events, call relay `POST /session/revoke` and `POST /wallet/lock`.
2. Use relay webhooks for lifecycle monitoring and risk workflows.
