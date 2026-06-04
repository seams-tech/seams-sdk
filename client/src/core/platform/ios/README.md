# iOS Platform Adapter Contract

This directory records the native iOS contract for sharing production Seams
passkeys with the web wallet without requiring a wallet iframe.

## RP ID Contract

Production iOS passkeys use the same relying-party identity as the production
web wallet:

- RP ID: `seams.sh`
- Associated Domains entitlement: `webcredentials:seams.sh`
- Local development keeps the current localhost RP ID defaults, currently
  `example.localhost`.

The app must construct `ASAuthorizationPlatformPublicKeyCredentialProvider` with:

```swift
let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(
  relyingPartyIdentifier: "seams.sh"
)
```

The production domain must serve:

```json
{
  "webcredentials": {
    "apps": [
      "TEAMID.com.seams.app"
    ]
  }
}
```

at `https://seams.sh/.well-known/apple-app-site-association`. Replace
`TEAMID.com.seams.app` with the concrete Apple Team ID and bundle identifier.

## AuthenticatorPort Mapping

The native `AuthenticatorPort` implementation maps to AuthenticationServices:

- Registration challenge: `ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest`.
- Assertion challenge: `ASAuthorizationPlatformPublicKeyCredentialAssertionRequest`.
- RP ID: `SEAMS_PRODUCTION_RP_ID` for production, current localhost RP IDs for
  local development.
- User verification: map SDK `required`, `preferred`, and `discouraged` policy
  to the nearest AuthenticationServices request behavior.
- PRF extension: request PRF output only when the platform reports support.

The adapter must normalize the native result into the same boundary shape used
by browser WebAuthn before signer-core receives any material.

## PRF Fallback

Threshold ECDSA and Ed25519 flows that require PRF-derived material must fail
with a typed unsupported-platform result when iOS cannot provide the PRF
extension. The adapter must return that failure before signer-core sees an
empty, random, or placeholder secret source.

## Secure Secret Store

Native secret persistence uses Keychain-backed storage:

- Store sealed refresh secrets and local recovery material with
  `kSecClassGenericPassword`.
- Bind records to the wallet ID, signer kind, signer slot, and RP ID.
- Use an accessibility class that fits the app threat model; production should
  prefer device-bound access.
- Never mirror wallet-origin browser IndexedDB state into native storage.

## Signer-Core Binding

The iOS adapter calls signer-core through native bindings, not browser workers.
Every command must use typed inputs at the boundary and reject malformed command
payloads before calling signer-core:

- NEAR Ed25519 key operations.
- NEAR transaction signing.
- NEP-413 message signing.
- Delegate action signing.
- Threshold ECDSA bootstrap/session connection.
- EVM-family signing.
- Tempo signing.
- Export/recovery commands that are explicitly enabled for native.

## Server Verification Policy

Server routes that verify passkey registration or assertion output must receive
an expected-origin or native-origin policy. The route handler owns choosing the
policy; the verifier must not infer it from an untrusted request body.

Required route coverage:

- registration bootstrap and finalize routes;
- add-signer routes;
- session exchange routes;
- threshold ECDSA bootstrap routes;
- threshold Ed25519 session routes;
- future native-auth routes.

For native iOS, verification must bind:

- configured RP ID (`seams.sh` in production);
- native origin policy for the app identity;
- `rpIdHash` for the configured RP ID;
- registration or assertion challenge;
- wallet/session identity carried by the route contract.

## Native Replay Fixtures

Add replay fixtures for every signer-core command listed in the signer-core
binding section. Each fixture must include:

- normalized native request input;
- signer-core command payload;
- expected signer-core output or typed failure;
- unsupported PRF case where the command requires PRF-derived material;
- malformed native result case proving boundary rejection.
