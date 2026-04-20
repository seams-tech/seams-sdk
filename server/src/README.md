# Server Package

AuthService provides the server‑side pieces for account creation and WebAuthn verification. Session handling is optional and pluggable — pass a SessionService (or compatible adapter) into the routers. The SDK itself does not bundle a JWT library.

## Quick Start (Express)

```ts
import express from 'express';
import cors from 'cors';
import { AuthService, SessionService } from '@tatchi-xyz/sdk/server';
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express';
import jwt from 'jsonwebtoken';

const service = new AuthService({
  relayerAccount: process.env.RELAYER_ACCOUNT_ID!,
  relayerPrivateKey: process.env.RELAYER_PRIVATE_KEY!,
  nearRpcUrl: process.env.NEAR_RPC_URL || 'https://rpc.testnet.near.org',
  networkId: process.env.NETWORK_ID || 'testnet',
});

const rorRpId = process.env.ROR_RP_ID || 'wallet.example.localhost';
const rorOrigins = [process.env.EXPECTED_ORIGIN!, process.env.EXPECTED_WALLET_ORIGIN!].filter(
  Boolean,
);

const session = new SessionService({
  jwt: {
    signToken: ({ payload }) => {
      // If payload.exp is supplied (e.g., threshold session tokens), do not override it with `expiresIn`.
      const hasExp =
        typeof (payload as any).exp === 'number' && Number.isFinite((payload as any).exp);
      return jwt.sign(payload as any, process.env.JWT_SECRET || 'dev-insecure', {
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER || 'relay',
        audience: process.env.JWT_AUDIENCE || 'app',
        ...(hasExp ? {} : { expiresIn: Number(process.env.JWT_EXPIRES_SEC || 24 * 60 * 60) }),
      });
    },
    verifyToken: async (token: string) => {
      try {
        const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-insecure') as any;
        return { valid: true, payload };
      } catch {
        return { valid: false };
      }
    },
  },
  // Minimal cookie config (defaults to HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=24h)
  cookie: { name: 'tatchi-jwt' },
});

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: [process.env.EXPECTED_ORIGIN!, process.env.EXPECTED_WALLET_ORIGIN!].filter(Boolean),
    credentials: true,
  }),
);
app.use(
  '/',
  createRelayRouter(service, {
    healthz: true,
    readyz: true,
    session,
    ror: {
      rpId: rorRpId,
      provider: {
        getAllowedOrigins: async (input) => (input.rpId === rorRpId ? rorOrigins : []),
      },
    },
  }),
);
app.listen(3000);
```

## Quick Start (Cloudflare Workers)

```ts
import { AuthService, SessionService } from '@tatchi-xyz/sdk/server';
import { createCloudflareRouter } from '@tatchi-xyz/sdk/server/router/cloudflare';
import signerWasm from '@tatchi-xyz/sdk/server/wasm/signer';
import jwt from 'jsonwebtoken';

const service = new AuthService({
  relayerAccount: env.RELAYER_ACCOUNT_ID,
  relayerPrivateKey: env.RELAYER_PRIVATE_KEY,
  nearRpcUrl: env.NEAR_RPC_URL,
  networkId: env.NETWORK_ID || 'testnet',
  signerWasm: { moduleOrPath: signerWasm },
});

const session = new SessionService({
  jwt: {
    signToken: ({ payload }) =>
      jwt.sign(payload as any, env.JWT_SECRET || 'dev-insecure', { algorithm: 'HS256' }),
    verifyToken: async (token: string) => {
      try {
        return { valid: true, payload: jwt.verify(token, env.JWT_SECRET || 'dev-insecure') };
      } catch {
        return { valid: false };
      }
    },
  },
  cookie: { name: 'tatchi-jwt' },
});

export default {
  async fetch(request: Request, env: any, ctx: any) {
    const rorRpId = env.ROR_RP_ID || new URL(env.EXPECTED_WALLET_ORIGIN).hostname;
    const rorOrigins = [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN].filter(Boolean);
    const router = createCloudflareRouter(service, {
      healthz: true,
      readyz: true,
      corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN].filter(Boolean),
      session,
      ror: {
        rpId: rorRpId,
        provider: {
          getAllowedOrigins: async (input) => (input.rpId === rorRpId ? rorOrigins : []),
        },
      },
    });
    return router(request, env, ctx);
  },
};
```

## Routes exposed by the routers

- POST `/registration/bootstrap` — atomic account creation + passkey registration (contract-free). Body:
  - `{ new_account_id, signer_slot?, rp_id, webauthn_registration, expected_origin?, authenticator_options?, threshold_ed25519?, threshold_ecdsa? }`
  - Note: `new_account_id` must be a subaccount of `relayerAccount` (`RELAYER_ACCOUNT_ID`) because the relayer signs the `CreateAccount` transaction.
- POST `/auth/passkey/options` — mint a server-side WebAuthn login challenge (replay-protected). Body:
  - `{ user_id, rp_id, ttl_ms? }` → returns `{ challengeId, challengeB64u, expiresAtMs }`
- POST `/auth/passkey/verify` — WebAuthn verification only (contract-free). Body:
  - `{ challengeId, webauthn_authentication }`
  - The relay verifies signatures using its private authenticator store and persists counters.
  - App-session issuance is handled by `POST /session/exchange` (OIDC/JWT exchange contract).
- POST `/recover-email` — email-based account recovery (TEE/DKIM flow)
- GET `/healthz` — basic server health + feature configuration hints (optional, enabled via router config)
- GET `/readyz` — readiness check (optional, enabled via router config)
- GET `/session/state` — returns `{ authenticated, claims? }` based on Authorization: Bearer or cookie
- POST `/session/revoke` — rotates app-session version and clears session cookie
- GET `/.well-known/webauthn` — Related Origin Requests manifest (wallet-scoped credentials) + sealed-refresh capabilities payload
- POST `/threshold/signing-session-seal/apply-server-seal` — optional signing-session sealed-refresh route
- POST `/threshold/signing-session-seal/remove-server-seal` — optional signing-session sealed-refresh route

Smart-account deployment is an internal relay hook now. If you provide `smartAccountDeploy` to
`createRelayRouter(..., { smartAccountDeploy })` or `createCloudflareRouter(..., { smartAccountDeploy })`,
invoke it from your own registration or provisioning flow instead of expecting a public relay route.

## Sessions

You have two integration styles:

1. Provide a SessionService (hook‑first) or compatible adapter

- Supply `signToken` and `verifyToken` using your preferred JWT library (e.g., jsonwebtoken).
- Optionally provide cookie hooks to customize headers if using cookie mode.

Cookie hooks (optional)

```ts
const session = new SessionService({
  jwt: {
    /* signToken/verifyToken as above */
  },
  cookie: {
    name: 'tatchi-jwt',
    // Customize Set-Cookie attributes (e.g., cross-site):
    buildSetHeader: (token) =>
      [
        `tatchi-jwt=${token}`,
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=None',
        'Domain=.example.localhost',
        'Max-Age=86400',
      ].join('; '),
    buildClearHeader: () =>
      [
        'tatchi-jwt=',
        'Path=/',
        'HttpOnly',
        'Secure',
        'SameSite=None',
        'Domain=.example.localhost',
        'Max-Age=0',
        'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
      ].join('; '),
    // Optional: custom extraction from headers (Bearer or Cookie)
    extractToken: (headers, cookieName) => {
      const auth = (headers['authorization'] || headers['Authorization']) as string | undefined;
      if (auth && /^Bearer\s+/.test(auth)) return auth.replace(/^Bearer\s+/i, '').trim();
      const cookie = (headers['cookie'] || headers['Cookie']) as string | undefined;
      if (!cookie) return null;
      for (const part of cookie.split(';')) {
        const [k, v] = part.split('=');
        if (k && k.trim() === cookieName) return (v || '').trim();
      }
      return null;
    },
  },
});
```

For cookies, configure CORS with explicit origins and `credentials: true`.

Default behavior

- No session is minted by default. The client must opt‑in by calling `unlock(..., { session: { kind: 'jwt' | 'cookie', relayUrl?, route? }})`.
- On the server, sessions are only active if you provide a SessionService (or compatible adapter) to the router options.

Configurable session endpoints

- Express adaptor: `createRelayRouter(service, { session, sessionRoutes })` (defaults to `/session/state`).
- Cloudflare adaptor: `createCloudflareRouter(service, { session, sessionRoutes, corsOrigins })` (same defaults).

Cloudflare CORS note

- The Cloudflare router will only set `Access-Control-Allow-Credentials: true` when echoing a specific Origin. If `corsOrigins` is `'*'`, credentials are not advertised (as required by Fetch/CORS rules). Use explicit origins when using cookie sessions.

## PRF Session Seal Module (optional)

`signingSessionSeal` routes are opt-in and can be composed with helper builders:

```ts
import { createRelayRouter } from '@tatchi-xyz/sdk/server/router/express';
import {
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealPolicyFromEcdsaAuthSessionStore,
  createSigningSessionSealShamir3PassCipherAdapter,
  resolveSigningSessionSealRateLimitFromEnv,
} from '@tatchi-xyz/sdk/server';

const ecdsaAuthSessionStore = /* your threshold-ecdsa auth session store */;
const signingSessionSeal = createSigningSessionSealRoutesOptions({
  sessionPolicy: createSigningSessionSealPolicyFromEcdsaAuthSessionStore(ecdsaAuthSessionStore),
  cipher: createSigningSessionSealShamir3PassCipherAdapter({
    currentKeyVersion: 'kek-s-2026-02',
    keys: [{
      keyVersion: 'kek-s-2026-02',
      // Development/test bootstrap only.
      // Production should load the active seal key material from a KMS/HSM boundary
      // and keep only the selected key version in ordinary app config.
      shamirPrimeB64u: process.env.SIGNING_SESSION_SHAMIR_P_B64U!,
      serverEncryptExponentB64u: process.env.SIGNING_SESSION_SEAL_E_S_B64U!,
      serverDecryptExponentB64u: process.env.SIGNING_SESSION_SEAL_D_S_B64U!,
    }],
  }),
  capabilities: {
    mode: 'sealed_refresh_v1',
    keyVersion: 'kek-s-2026-02',
    shamirPrimeB64u: process.env.SIGNING_SESSION_SHAMIR_P_B64U!,
  },
  rateLimit: resolveSigningSessionSealRateLimitFromEnv({
    limiterKind: 'upstash-redis-rest', // 'in-memory' | 'upstash-redis-rest' | 'redis-tcp'
    upstashUrl: process.env.UPSTASH_REDIS_REST_URL,
    upstashToken: process.env.UPSTASH_REDIS_REST_TOKEN,
    redisUrl: process.env.REDIS_URL,
    keyPrefix: 'threshold:signing-session-seal:rate:',
    limit: 30,
    windowMs: 60_000,
  }),
  logger: console,
});

app.use('/', createRelayRouter(service, {
  session,
  threshold,
  signingSessionSeal,
}));
```

Notes:

- `createSigningSessionSealShamir3PassCipherAdapter(...)` supports pluggable runtimes; wire your `shamir-3-pass-rs` runtime in production.
- Do not log raw ciphertexts; audit helpers intentionally avoid ciphertext fields.
- Use `resolveSigningSessionSealRateLimitFromEnv(...)` to wire in-memory, Upstash REST, or Redis TCP rate limiting without changing route code.
- Keep `capabilities.keyVersion` and `capabilities.shamirPrimeB64u` aligned with your active cipher key material; clients in `sealed_refresh_v1` mode fail closed on parity mismatch.

## Config (required)

```bash
RELAYER_ACCOUNT_ID=relayer.testnet
RELAYER_PRIVATE_KEY=ed25519:...
ROR_RP_ID=wallet.example.localhost
NEAR_RPC_URL=https://rpc.testnet.near.org
NETWORK_ID=testnet
```

Optional session vars (examples use these):

```bash
JWT_SECRET=change-me
JWT_ISSUER=relay
JWT_AUDIENCE=your-app
JWT_EXPIRES_SEC=86400
SESSION_COOKIE_NAME=tatchi-jwt

# Optional: override session route paths
# Session routes are configured in code via router options.
```
