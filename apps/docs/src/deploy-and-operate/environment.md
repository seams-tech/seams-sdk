---
title: Environment variables
description: Separate public browser configuration, server request credentials, and custody-role secrets across Seams deployment environments.
---

# Environment variables

Assign every value to one owner. Browser-prefixed variables are public after a
build and must never contain a secret.

## Browser-owned values

Typical browser configuration includes the wallet and relayer origins,
project-environment identity, publishable key, chain RPC and explorer URLs,
network identity, and RP ID base. Validate required strings before building
`SeamsConfigsInput`.

## Service-owned values

The gateway or relayer owns request-authentication verification material,
provider credentials, rate-limit and storage bindings, allowed origins, and
network execution configuration. Expose only the minimal public metadata
required by the SDK.

## Custody-role values

Threshold shares, sealing keys, service-to-service credentials, ceremony
signing material, database credentials, and deployment tokens belong only to
their owning protected environment. A single job or operator should not receive
both independent Router roles' private material.

## Change discipline

Keep one reviewed environment contract per deployment lane. Fail startup or
preflight when a required value is missing or belongs to the wrong lane.
Rotate secrets through the owning boundary, then verify revocation of the old
value. Never print secret values during validation.
