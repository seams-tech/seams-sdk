# Bring Your Own Application Authentication

Application authentication and wallet ownership are separate boundaries.

Use Better Auth, Auth0, Clerk, Firebase, Supabase, an enterprise IdP, or your
own backend to authenticate users in your application. Keep those sessions in
your application. The wallet SDK neither accepts nor mints an application
session JWT.

## Wallet connection

Your application may retain a wallet ID and owner-method locator after a user
connects a wallet. These values select the next wallet ceremony; they grant no
wallet authority.

The wallet server supports two owner methods:

- passkey;
- Email OTP.

The selected method performs a server-prepared ceremony. A successful verifier
creates a server-internal `VerifiedOwnerProof`, which can mint an opaque Wallet
Session or authorize one exact operation. The browser never receives that
proof.

Opaque Wallet Session tokens contain no claims. The server hashes and resolves
them against the authoritative wallet, owner method, budget, expiry, and
revocation state. An application JWT cannot substitute for this token or for a
fresh owner proof.

## Recommended integration

1. Authenticate the user with your application auth provider.
2. Read the wallet locator associated with that application user.
3. Open the wallet SDK with that locator.
4. Let the wallet SDK run passkey or Email OTP owner authentication.
5. Keep application and wallet logout behavior separate.

Google-assisted Email OTP registration verifies the Google identity only to
resolve the stored Email OTP owner identity or begin registration. The user
still completes Email OTP before wallet authority is granted.

## Hosted wallet iframe

The hosted wallet uses an origin-bound, single-use exchange capability. The
wallet host redeems it for its own opaque Wallet Session. The outer application
does not receive that token.

## External owner methods

Customer-configured verification webhooks are deferred to a later refactor.
That system will need explicit server configuration, enrollment, challenge and
operation binding, replay protection, and custody binding before it can produce
`VerifiedOwnerProof`.

Until that work lands, external JWTs, voice identity, application sessions, and
custom provider assertions cannot unlock a wallet or authorize wallet
operations.

Console authentication remains independent and is outside this wallet SDK
boundary.
