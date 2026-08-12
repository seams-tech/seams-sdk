---
title: Observability and audit
description: Correlate Seams wallet flows across browser and service boundaries while excluding credentials, secrets, and sensitive proof material.
---

# Observability and audit

Observe the lifecycle through stable operation identities, wallet-flow phases,
result codes, and service receipts. Keep telemetry useful across boundaries
without assembling a second store of sensitive authentication data.

## Record

- release, environment, network, and component identity;
- a generated operation or intent ID;
- wallet ID or another approved pseudonymous subject identifier;
- event version, phase, status, duration, and stable error code;
- policy decision, signing lane, broadcast acceptance, and finalization state;
- administrative change, actor, target, and reviewed reason.

## Exclude

Never log passwords, OTP codes, passkey assertions, challenge responses, private
keys, threshold shares, recovery codes, session or ID tokens, authorization
headers, or complete export payloads. Redact URLs and request bodies that can
carry these values.

## Alert

Alert on registration and unlock failure changes, challenge abuse, origin or
request-auth rejection, signer-lane readiness degradation, repeated policy
denial, broadcast/finalization divergence, custody-role health, and audit-write
failure. Route every alert to the team that owns the failing boundary.

Progress events support UI and telemetry. The operation result remains the
authoritative lifecycle outcome.
