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

For tenant-root operations, correlate the operation ID with approved public
tenant/lineage identifiers, share epoch, lifecycle revision, affected role, and
receipt digest. Distinguish activation success from retirement cleanup failure.
Record cooldown rejection as an admission outcome; it does not mean a refresh
or provider call occurred.

## Exclude

Never log passwords, OTP codes, passkey assertions, challenge responses, private
keys, threshold shares, recovery codes, session or ID tokens, authorization
headers, or complete export payloads. Redact URLs and request bodies that can
carry these values.

Exclude Google service-account credentials, bootstrap tokens, recovery private
keys, and complete backup/import bodies. Use object or receipt digests when
diagnosing backup failures instead of capturing request and response payloads.

## Alert

Alert on registration and unlock failure changes, challenge abuse, origin or
request-auth rejection, signer-lane readiness degradation, repeated policy
denial, broadcast/finalization divergence, custody-role health, and audit-write
failure. Route every alert to the team that owns the failing boundary.

Tenant-root alerts should identify failed backup verification, loss of access
to a recorded KMS version, and stalled refresh or retirement checkpoints.
Expected hourly cooldown responses alone are not custody-health failures.

Progress events support UI and telemetry. The operation result remains the
authoritative lifecycle outcome.
