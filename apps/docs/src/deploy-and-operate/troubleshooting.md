---
title: Troubleshooting
description: Diagnose common Seams registration, iframe, session, signing, provisioning, broadcast, and theme failures by lifecycle boundary.
---

# Troubleshooting

Start with the visible symptom, identify the boundary, inspect stable state and
codes, then choose the supported recovery action. Avoid blind retries for
operations whose broadcast state is uncertain.

## Wallet surface does not load

**Boundary:** application-to-wallet iframe. Check the configured wallet origin,
service route, CSP `frame-src`, frame-ancestor policy, asset content types, and
browser console origin errors. Correct the deployment or origin allowlist, then
reload the wallet surface.

## Passkey prompt is unavailable

**Boundary:** browser capability, RP ID, and wallet origin. Inspect the public
capability-selection result, secure-context status, iframe permissions, and RP
scope. Offer a supported auth method or correct the origin configuration. Do
not loop the credential prompt.

## Registration succeeded but a signer is not ready

**Boundary:** provisioning lifecycle. Inspect the successful
`RegistrationResult` branch and current provisioning state. Wait for a pending
state, retry only a retryable failure, and continue after the exact capability
is ready.

## Signing reports a session or subject mismatch

**Boundary:** wallet-session identity. Confirm that the wallet-session reference,
account or chain target, wallet ID, network, and current SDK client all describe
the same wallet lifecycle. Re-authenticate and rebuild exact references from
validated state.

## Transaction status is uncertain

**Boundary:** broadcast and chain finality. Use the operation hash or request ID
to query the configured network and reconcile nonce-lane state. Retry only
after proving the previous transaction was not accepted.

## Appearance differs between app and wallet

**Boundary:** rendering origin. Confirm that app-owned components receive the
React `Theme` tokens and wallet-owned surfaces receive matching SDK appearance
tokens for the active mode. Verify contrast after correcting both channels.

## What to collect for support

Collect release, environment, browser, operation ID, public error code, event
phase/status, and redacted console or network evidence. Exclude credentials,
tokens, assertions, OTPs, recovery data, and key material.
