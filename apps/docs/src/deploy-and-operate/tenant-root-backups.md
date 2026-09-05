---
title: Tenant-root backups
description: How Seams protects Deriver A and B tenant-root backups in R2 using separate Google Cloud KMS wrapping keys, with restore behavior and cost estimates.
---

# Tenant-root backups

Each tenant has randomly generated server-side derivation-root shares held
separately by Deriver A and Deriver B. Losing a current share prevents future
derivations that require that pair. Production keeps an encrypted recovery copy
of each share in Cloudflare R2, protected by separate Google Cloud KMS keys.
Wallet custody seeds and client signing roots remain in their existing custody
paths; these backups cover the server's tenant-root shares.

## Storage and key ownership

| Material | Deriver A | Deriver B |
| --- | --- | --- |
| Active share | Encrypted in A's private D1 database | Encrypted in B's private D1 database |
| Managed backup | Ciphertext in A's R2 bucket | Ciphertext in B's R2 bucket |
| Backup wrapping key | Google KMS key A | Google KMS key B |
| KMS access | A's service account, authorized on key A | B's service account, authorized on key B |

The production backup keys use Google KMS's software protection level. Each
role currently shares one wrapping-key version across its tenants. Google KMS
keeps the wrapping-key material non-exportable and performs encryption and
decryption through its API. The Worker holds a service-account credential that
can invoke its own key. The backup key itself stays outside Cloudflare.
[Google KMS encryption documentation](https://docs.cloud.google.com/kms/docs/encrypt-decrypt)

Role credentials are separate, while both keys currently live in one Google
Cloud project under common administration. This provides separation between
runtime credentials; an administrator with authority over both keys remains a
shared trust boundary. A stolen role credential can invoke that role's key
until access is revoked.

## Backup, refresh, and restore

During tenant-root creation or refresh, each Deriver encrypts its own backup
through KMS and verifies it by decrypting it and checking its public commitment.
Google KMS processes that role's plaintext share during these API calls. Each
backup is authenticated to its tenant identity, role, custody lineage, epoch,
share commitment, and installation evidence. Activation requires both role
records and their verified backups.

After successful retirement cleanup, each tenant has two current encrypted
share-backup objects: one for A and one for B. R2 also holds supporting evidence
objects. During refresh or interrupted cleanup, current and pending or retired
epoch objects can coexist. Two is the steady-state share-backup count, rather
than a hard limit on all stored objects.

An authorized managed restore decrypts the affected role's backup into that
Deriver, verifies its commitment, and requires both roles to perform a forward
refresh. The backup depends on retained R2 ciphertext, usable KMS versions, and
the authoritative identity and activation records required by the restore flow.
It covers share recovery within that flow; a complete database-loss recovery
also needs those records restored.

Normal ECDSA and Ed25519 signing uses existing online signing material and does
not call this KMS backup adapter. KMS availability and operation charges affect
backup creation, verification, refresh, and restore.

## Cost at 10, 50, and 100 tenants

Prices checked September 5, 2026, in USD: a software key version costs about
$0.06 per month, and encrypt/decrypt operations cost $0.03 per 10,000 calls.
These manually provisioned keys do not use the Autokey free allowance.
[Google Cloud KMS pricing](https://cloud.google.com/kms/pricing)

| Tenants | Current share-backup objects in R2 | Active KMS versions | Fixed KMS cost per month |
| --- | --- | --- | --- |
| 10 | 20 | 2 | About $0.12 |
| 50 | 100 | 2 | About $0.12 |
| 100 | 200 | 2 | About $0.12 |

Encrypting and verifying both shares takes four KMS operations, approximately
$0.000012 for that backup pair. Retries, additional verification, and restore
can add calls. R2 storage, R2 requests, D1, and Worker execution are billed
separately. Retaining additional KMS versions also increases the fixed charge.

R120 implements one successful tenant-admin refresh per tenant per rolling
hour, enforced on the server before provider work. A distinct request during
the cooldown receives HTTP 429 with a server-computed retry time; retrying the
same operation returns its existing result. Mandatory post-restore refresh
retains its separately authorized recovery path. Deployment of the throttle
is pending; it is not yet an enforced production limit.

## Rotation and destruction limits

Refreshing a tenant root changes its A/B shares while preserving the effective
derivation root. The current backup provider continues using the configured
shared KMS versions. Creating a new KMS version is a separate wrapping-key
rotation operation.

Deleting an old R2 object does not prove that every copied ciphertext is
unrecoverable while its KMS version remains usable. Destroying a shared KMS
version affects every backup encrypted under it. The current deployment
therefore claims operational rotation and encrypted backup availability;
per-tenant cryptographic erasure and proactive compromise healing remain
unverified.

For the distinction between tenant-root refresh, lane refresh, and wallet
rekeying, see [key rotation](/concepts/delegation/key-rotation).
