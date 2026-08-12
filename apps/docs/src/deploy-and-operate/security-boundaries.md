---
title: Origin, iframe, and request boundaries
description: Protect Seams wallet origins with exact message origins, CSP, WebAuthn RP scope, request authentication, and separated custody roles.
---

# Origin, iframe, and request boundaries

Treat the application origin, wallet origin, gateway, and custody roles as
separate principals. Each boundary validates and normalizes its own external
input once.

## Browser boundary

- Use HTTPS outside local development.
- Allow exact application origins; avoid wildcard credentialed CORS.
- Validate every iframe message origin, source window, protocol version, and
  session identity.
- Scope WebAuthn credentials to the intended RP ID and parent-domain policy.
- Keep keys, OTP codes, recovery material, app-session tokens, and threshold
  state out of application-origin messages.

## CSP and framing

Start with a restrictive Content Security Policy. Add the exact wallet origin
to the application `frame-src`. On the wallet origin, restrict scripts,
connections, workers, images, styles, and framing ancestors to the assets and
origins required by the deployed release. Avoid unsafe script exceptions.

Test browser permissions for WebAuthn inside the cross-origin iframe. Add a
Permissions Policy only when the supported-browser smoke demonstrates it is
required, then scope it to the wallet origin.

## Service requests

Authenticate app-to-gateway and gateway-to-role requests with the mechanism
owned by that boundary. Verify audience, issuer, expiry, nonce or replay key,
method, and target before dispatch. Rate-limit public challenges and signing
admission. Never place custody-role secrets in browser configuration.

Strict Router A/B isolation requires independent administration, credentials,
storage, logs, and deployment authority for roles A and B.
