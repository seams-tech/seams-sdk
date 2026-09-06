---
title: Rotation ceremonies
description: Understand envelope rewrap, custody-share refresh, signer rotation, and wallet rekey ceremonies.
---

# Rotation ceremonies

Tenant-root refresh replaces the operational shares held by Deriver A and
Deriver B while preserving the effective derivation root. It leaves wallet
public keys and addresses unchanged. For other rotation types, see
[key rotation](/concepts/delegation/key-rotation).

## Admission and execution

1. The authenticated Console boundary resolves the tenant identity and active
   custody lineage. The caller supplies an operation ID, never replacement
   shares or an alternate tenant-root identity.
2. The tenant's Router-owned Durable Object durably admits the operation.
   R120's hourly manual-refresh gate rejects a distinct concurrent request or
   a request inside the cooldown before Deriver/provider work.
3. The control plane issues role-specific commands. Each Deriver reserves
   durable state before writing backup objects, then installs only its own
   refreshed share and returns signed public evidence.
4. Activation requires matching A/B evidence and root continuity. The
   authoritative lifecycle revision advances, and manual completion time and
   the replay receipt commit together.
5. Retirement removes superseded active records and backup objects. A failure
   after activation requires retirement cleanup; the previous epoch does not
   become active again.

Normal signing uses existing signing material throughout this operation. New
tenant derivation ceremonies may be fenced while the active epoch changes.

## Interrupted operations

Retry with the same operation ID. Durable reservations and execution checkpoints
resume the existing attempt; completed IDs return the recorded result. A late
retry cannot reinstall an epoch superseded by a newer refresh. Terminal role
commits also have replayable Router installation checkpoints.

Treat activation and retirement as separate outcomes. An active refresh with
unfinished retirement needs cleanup, even when normal signing works. Avoid
starting unrelated rotations to repair an uncertain response.

## Recovery and destruction

Managed restore verifies a recovered role share and requires a forward refresh
before normal lifecycle admission resumes. Its authorization is separate from
manual tenant refresh and cannot be selected through a tenant bypass flag.

The current Google KMS backup keys are shared across tenants within each role.
Removing an old R2 object does not make every historical ciphertext copy
unrecoverable. Report operational rotation and cleanup accurately; stronger
cryptographic-erasure claims require independently verified key destruction.

## Availability

R120's refresh implementation is complete. Deployment of its hourly throttle
and the full public release proof remain pending. R121's dashboard, fresh
step-up, and public progress surface are planned. This page describes the
server lifecycle, not a currently available dashboard workflow.

Read next: [tenant-root backups](/deploy-and-operate/tenant-root-backups) and
[recovery and portability](/deploy-and-operate/recovery-and-portability).
