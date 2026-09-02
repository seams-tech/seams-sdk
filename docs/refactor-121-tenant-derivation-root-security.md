# Refactor 121: Tenant Derivation-Root Security Dashboard and CLI

Created: August 28, 2026

Status: proposed follow-up to
[Refactor 120](./refactor-120-rotate-tenant-secrets.md). Implementation starts
after Refactor 120 materializes the tenant-root identity, root algebra,
operational lifecycle, and recovery-sharing contracts. This plan freezes the
tenant-facing artifact, authorization, CLI, download, and restore contracts.

## Outcome

Give a tenant a clear, safe control surface for its derivation-root lifecycle:

- inspect Deriver A and Deriver B operational-share health;
- understand how operational-share rotation works;
- start and monitor an operational-share rotation;
- configure tenant-controlled recovery recipients;
- download the encrypted Deriver A and Deriver B recovery packages separately;
- download and verify the public recovery manifest;
- restore both role shares into a fresh replacement deployment without depending
  on the source deployment;
- verify the stable root commitment and activate fresh operational shares.

The product has two coordinated entry points:

1. a **Derivation root security** page in the dashboard;
2. a `seams derivation-root` CLI for automation, offline custody, and
   source-independent recovery.

The dashboard is the visual control plane. The CLI owns role-local recovery-key
use and share resealing. Neither surface reconstructs the joined tenant root.

## Dependencies and Ownership

This plan consumes Refactor 120's:

- `TenantRootIdentityV1`;
- `TenantRootShareEpoch`;
- active and pending epoch records;
- public root and role-share commitments;
- contributory operational-share rotation;
- independently randomized tenant recovery sharing;
- role-encrypted recovery packages and public manifest;
- role-local restore and mandatory forward refresh;
- lifecycle receipts, failure semantics, and erasure evidence.

Refactor 121 owns:

- the dashboard route and page behavior;
- tenant-facing explanations and action copy;
- console authorization and fresh step-up boundaries;
- public console APIs that expose redacted state and operation commands;
- recovery-recipient enrollment;
- encrypted package download and issued-versus-durable evidence;
- the `seams derivation-root` CLI;
- role-specific restore import envelopes;
- dashboard and CLI progress, audit, accessibility, and error behavior.

[Refactor 122](./refactor-122-deployment-portability.md) may reuse the operational
patterns, CLI transport, and progress UI. These packages restore only the exact
logical tenant root; they do not move wallet inventory, active signer material,
application routing, RP IDs, or wallet authorities. Refactor 121 does not decide
whether Refactor 122 composes deployment portability with this independent root
restore operation.

## Decisions

1. The dashboard route is `/dashboard/derivation-root-security` under **Wallet
   operations**.
2. The page is scoped to the selected organization, project, and environment.
   The server resolves the authoritative `TenantRootIdentityV1`; the browser and
   CLI cannot supply or override it.
3. The page contains three sections: **Operational shares**,
   **Tenant-controlled recovery**, and **Restore derivation root**.
4. “Rotate operational shares” names the manual rotation action. “Rotate root”
   is inaccurate because the stable root does not change.
5. Tenant recovery packages contain a dedicated recovery sharing of the stable
   root. They do not copy the current operational shares.
6. Deriver A and Deriver B produce separate encrypted recovery packages. A
   signed public manifest binds the pair to one recovery set and root
   commitment.
7. The recovery sharing remains valid across operational-share rotations. A
   routine rotation therefore requires no new tenant download.
8. Recovery private keys remain tenant-controlled. The dashboard and console
   services accept public recipient material, ciphertext, commitments, and
   receipts only.
9. The CLI downloads encrypted artifacts without decrypting them.
10. CLI download and restore commands process one role package per invocation.
    One invocation cannot retrieve both role packages or accept both recovery
    private keys. Public-manifest operations remain role-neutral.
11. The CLI opens one role package locally, immediately reseals that role share
    to the destination Deriver's one-use import key, zeroizes temporary
    plaintext, and uploads the role-specific import envelope directly.
12. The hosted dashboard never asks for a recovery private key. It starts and
    monitors restore sessions and shows role-specific CLI commands.
13. Restore targets a new or explicitly empty deployment. It cannot overwrite an
    active tenant root.
14. A completed restore verifies the original public root commitment, performs
    a forward operational-share refresh, activates the fresh epoch, and destroys
    imported recovery plaintext and one-use import keys.
15. Manual rotation, recovery-governance change, recovery-key enrollment,
    backup generation, backup replacement, restore, and source retirement are
    mutually exclusive under one tenant-root operation lock in the affected
    lineage.
16. Normal signing remains available during operational-share rotation. New
    derivation ceremonies for the selected tenant may be briefly fenced as
    defined by Refactor 120.
17. Scheduled rotation and manual rotation use the same protocol. The first page
    shows the configured schedule and next rotation; custom schedule editing is
    outside the first release.
18. Once a tenant downloads both recovery packages and controls both recovery
    private keys, that recovery set cannot be cryptographically revoked by the
    managed service. Replacing the recovery set protects future custody policy;
    it cannot erase copies already held by the tenant.
19. Operational-share refresh does not heal compromise of both shares from one
    tenant recovery set. Recovery-set custody is a separate security boundary.
20. The console database stores operation metadata, public commitments,
    fingerprints, download evidence, and audit receipts. It stores no
    root, decrypted share, recovery private key, or role wrapping key.
21. The CLI and dashboard use the same versioned console contracts and produce
    the same audit events.
22. Restore is disaster recovery for the exact logical `TenantRootIdentityV1`.
    The destination may replace its deployment-local routing metadata; it cannot
    rebind the recovered root to a different tenant, project, environment, or
    signing-root identity.
23. A source that still retains usable shares remains a valid custodian of the
    same root. Destination activation records whether the source was fenced,
    destroyed, or deliberately retained. The product makes no revocation or
    compromise-healing claim without verified source retirement.
24. Offline verification uses a versioned trust bundle with pinned manifest and
    Deriver-signing authorities. The manifest cannot introduce its own trusted
    signer.
25. Recovery package opening and destination resealing run in a native Rust core
    that reuses the frozen Refactor 120 protocol types and zeroizing secret
    containers. Any presentation wrapper receives only redacted results.
26. Recovery governance is an explicit discriminated policy:
    `single_owner_v1` or `two_person_v1`. The tenant selects one before enrolling
    recipients; no optional quorum or environment flag changes it later.
27. `two_person_v1` means the requesting `OWNER` plus one different `OWNER` who
    approves the exact operation digest. A requester cannot approve the same
    operation. `single_owner_v1` permits one freshly stepped-up `OWNER` and the
    dashboard continuously labels the weaker governance boundary.
28. Backup creation under already-enrolled recipients and one-role download
    require fresh console step-up. Restore activation requires destination
    bootstrap reauthentication at most five minutes old. Recipient-pair
    enrollment or replacement and governance-policy changes additionally follow
    the selected recovery governance policy.
29. Approval evidence is server-issued, exact-operation-bound, one-use, and
    consumed transactionally. Caller-supplied MFA booleans and reusable approved
    records are invalid for this feature.
30. Both role recipients must pass proof of private-key control, and their public
    key fingerprints must differ, before backup generation or ciphertext
    download is allowed.
31. The active recovery set remains downloadable until a replacement is fully
    generated and verified. Replacement activates atomically, then the service
    deletes its old ciphertext. Tenant-held old packages remain valid.
32. A browser download records only `download_issued`. The native CLI records
    `durable_verified` after a restrictive file write, sync, reopen, digest, and
    signature check. Product copy never calls a browser response durable.
33. Each Deriver retains only its active encrypted role package, outer-wrapped
    under a role-specific recovery-set retention-key version. The control plane
    retains the public manifest. Replacement or root deletion destroys both
    service retention-key versions and removes active objects; audit receipts
    follow the existing audit-retention policy.
34. The first CLI key provider is `encrypted_file_v1`. Deriver A and B require
    different X25519 keys and different key files. KMS, HSM, and PKCS#11
    providers are future additive adapters after their role-local behavior is
    specified and tested.
35. Recovery packages and destination import envelopes reuse
    `hpke_x25519_hkdf_sha256_aes256gcm_v1`. Package and manifest canonicalization,
    authenticated data, signatures, and trust-chain rules are fixed below.
36. The recovery artifact has no expiry. Online download capabilities expire in
    five minutes. Step-up evidence must be at most five minutes old; operation
    approvals expire after ten minutes.
37. A restore session lasts 24 hours. Its destination bootstrap session lasts 30
    minutes and can be renewed with the bootstrap credential. Each role import
    key and capability lasts 15 minutes; reissuing an unconsumed role key
    invalidates its predecessor.
38. An empty deployment creates a one-time
    `DestinationBootstrapAuthorityV1`. Restore APIs require a short-lived session
    from that authority. Successful activation destroys the bootstrap secret and
    every unused import key.
39. Recovery files can create more than one destination custody lineage. Import
    keys prevent session replay; they cannot make tenant-held recovery artifacts
    globally one-use. Every restored deployment receives a fresh
    `TenantRootCustodyLineageId` and the product reports this clone boundary.
40. Restore records the imported recovery set as `tenant_held_external`. The new
    deployment cannot redownload source packages it never stored. After
    activation, **Replace recovery backup** creates a destination-issued active
    set when the tenant wants managed redownload availability.
41. The first scheduled rotation interval is the Refactor 120 default of 30 days
    with a 24-hour jitter window. The page displays this fixed policy and supports
    operator-triggered earlier rotation.
42. Offline verification distinguishes `cryptographically_valid_offline`,
    `valid_at_trust_snapshot`, and `current_trust_confirmed`. A package does not
    become unverifiable merely because its Deriver signing key later retires.
43. The CLI ships as the native Rust `seams` binary through signed release
    assets on this repository's GitHub Releases page. The first release has no
    package-manager or self-update channel. Recovery execution performs no
    update check and verifies the release checksum manifest against a pinned
    offline release key.
44. `verified_retired` requires both source Deriver destruction receipts,
    permanent provider decrypt-probe failures, revocation of source
    lineage-scoped service credentials, and a canary proving the old derivation
    endpoints reject the lineage. Missing evidence selects an unverified or
    retained-source branch.
45. Restore defaults to `retained_as_backup`. It never fences, retires, or
    revokes the source automatically. `verified_retired` requires a separate,
    explicit destructive action by the tenant after destination activation.
46. Destruction of service-held recovery packages is a separate claim from
    revoking tenant copies. `managed_healing_v1` verifies destruction of each
    role's outer retention-key version so storage history cannot reopen the
    inner package. `operational_rotation_v1` reports only removal from the active
    service path.

## Frozen Product and Artifact Contracts

### Authorization, step-up, and approval capabilities

`TenantRootRecoveryGovernanceV1` is exactly one branch:

```ts
type TenantRootRecoveryGovernanceV1 =
  | {
      readonly kind: 'single_owner_v1';
      readonly acknowledgedByOwnerId: string;
      readonly acknowledgedAt: string;
      readonly warningVersion: 'tenant_root_single_owner_v1';
    }
  | {
      readonly kind: 'two_person_v1';
      readonly selectedByOwnerId: string;
      readonly selectedAt: string;
    };
```

The dangerous approval operations are:

```text
tenant_root_recovery_governance_change_v1
tenant_root_recovery_recipient_pair_enroll_v1
tenant_root_recovery_recipient_pair_replace_v1
tenant_root_source_lineage_retire_v1
```

`single_owner_v1` requires one organization `OWNER` with step-up at most five
minutes old. `two_person_v1` requires a stepped-up requesting `OWNER` and one
different stepped-up `OWNER`. The second owner approves the exact operation
digest within ten minutes. Removing the second owner after approval does not
preserve the capability; authorization is rechecked when it is consumed.

Initial selection of `single_owner_v1` requires its warning acknowledgement.
Initial selection of `two_person_v1` requires both distinct owners. A policy
transition uses the stronger quorum of the current and target branches, so one
owner cannot downgrade a two-person tenant alone.

Backup creation or replacement under the already-approved recipient pair and
one-role download require one stepped-up console actor. Restore activation uses
fresh destination bootstrap reauthentication. Explicit source-lineage retirement
follows the selected recovery governance policy and uses a separate destructive
capability minted only after destination activation. Private-key possession
remains separately necessary for each role import.

Every mutation has a server-generated `TenantRootOperationDigestV1` over:

```text
protocol version and operation kind
TenantRootIdentityDigestV1
TenantRootCustodyLineageId
organization, project, and environment IDs
expected lifecycle revision
recovery governance digest
recovery set or recipient-pair digest when applicable
role for a role-local operation
requester actor ID
idempotency key
issued-at and expiry
expected public root commitment
```

The operation record is RFC 8785 JSON with `deny_unknown_fields` semantics.
`TenantRootOperationDigestV1` is SHA-256 over the ASCII domain
`seams/tenant-root-operation/v1` followed by the canonical UTF-8 bytes. The
console capability is an Ed25519 signature over that domain, digest, capability
nonce, issuer key ID, issued-at, and expiry.

Every signed wall-clock field in this plan is an RFC 3339 UTC string with exactly
millisecond precision and a trailing `Z`. Lifecycle ordering uses the monotonic
revision and epoch; timestamps never resolve a race or choose active state.
Issuers and consumers permit at most 60 seconds of clock skew. A larger skew
fails closed and raises an operational alert instead of extending a capability.

The console store consumes the approval and creates one immutable authorized
operation plus outbox record in one local transaction. The dispatcher sends a
signed capability for that record to the tenant-root Durable Object. The object
consumes its nonce once and returns the same recorded result for exact replay,
so a dispatch retry never needs a second approval. A changed payload, actor,
role, lifecycle revision, or expired capability fails. The existing generic
approval service cannot be reused unchanged: its caller-provided `mfaVerified`
field, reusable approval records, self-approval path, and coarse `KEY_EXPORT`
operation do not meet this contract.

An outbox item that was never accepted before its ten-minute authorization
expiry becomes `authorization_expired` and requires a new approval. Expiry does
not affect exact replay of an operation the Durable Object already accepted.

### Recovery-recipient proof of control

Both recipients are 32-byte X25519 public keys used by
`hpke_x25519_hkdf_sha256_aes256gcm_v1`. Because X25519 is an encryption key, its
proof of control is an encrypted challenge:

1. The console creates a one-use 32-byte random challenge secret and a ten-minute
   challenge record bound to tenant identity, lineage, role, public-key digest,
   actor, and lifecycle revision.
2. It HPKE-encrypts the secret to the submitted public key with those fields as
   authenticated data.
3. The CLI opens the challenge through the selected key provider and returns
   `HMAC-SHA-256(challengeSecret, canonicalConfirmationBytes)`.
4. The server verifies and consumes the challenge, then records the public key
   and SHA-256 fingerprint.

The A and B public-key fingerprints must differ. A create or replace operation
cannot supply recipient keys inline, use a partially verified pair, or download
either ciphertext before both proofs succeed.

### Recovery descriptor, packages, and manifest

`TenantRootRecoverySetId` is 128 random bits encoded as unpadded base64url. The
public `TenantRootRecoverySetDescriptorV1` contains:

```text
format version
TenantRootIdentityV1 and TenantRootIdentityDigestV1
source TenantRootCustodyLineageId
TenantRootRecoverySetId
creation time
stable public root commitment
HPKE suite
Deriver A: role, share ID 1, recipient public key and fingerprint,
           recovery-share commitment, Deriver signing-key ID
Deriver B: role, share ID 2, recipient public key and fingerprint,
           recovery-share commitment, Deriver signing-key ID
```

Its canonical form is RFC 8785 JSON and its descriptor digest is SHA-256 over
the UTF-8 canonical bytes. Both recovery-share commitments must reconstruct the
manifest's stable root commitment before either package is published.

Each `TenantRootRecoveryPackageV1` is a binary file:

```text
8-byte magic "SEAMSRB1"
u32be canonical-header length
canonical RFC 8785 header bytes
32-byte HPKE encapsulated key
u32be ciphertext length
ciphertext
64-byte Ed25519 Deriver signature
```

The header binds the descriptor digest, tenant identity digest, source lineage,
recovery-set ID, role, share ID, recipient fingerprint, recovery-share
commitment, stable root commitment, creation time, HPKE suite, and Deriver
signing-key ID. The HPKE plaintext is exactly one 34-byte
`SigningRootShareWire`. HPKE authenticated data is the domain
`seams/tenant-root-recovery-package/v1` followed by the canonical header bytes.
The role signature covers that domain, header, encapsulated key, ciphertext
length, and ciphertext. `packageDigest` is SHA-256 over the complete file.

`TenantRootRecoveryManifestV1` is RFC 8785 JSON containing the descriptor, both
package lengths and digests, both role signer certificate chains, the control-
plane signer certificate chain, and a control-plane signature over the domain
`seams/tenant-root-recovery-manifest/v1` plus the unsigned canonical manifest.
The manifest cannot introduce a trust root. Canonical Rust fixtures own every
byte, and Rust, CLI, TypeScript, and Worker parsers reject unknown fields,
duplicate JSON keys, non-canonical base64url, role-order changes, and trailing
bytes.

The package MIME type is
`application/vnd.seams.tenant-root-recovery-package.v1`; the manifest MIME type
is `application/vnd.seams.tenant-root-recovery-manifest.v1+json`. Parsers cap a
package at 16 KiB, a manifest at 128 KiB, and an encrypted local key file at 4
KiB before allocation. HTTP downloads send the exact content type,
`X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, and the suggested
attachment filename.

### Recovery-set replacement and download evidence

At most one active and one pending recovery set exist. Initial generation and
replacement use these branches:

```text
not_configured
recipients_pending
preparing_initial
ready
replacing              (active + pending)
failed_initial          (no active set + completed pending cleanup)
failed_replacement      (old active set + completed pending cleanup)
cleanup_incomplete      (exact active/pending material requiring cleanup)
tenant_held_external    (restored from packages absent from this service)
```

During replacement, the old active set remains downloadable. The pending set
becomes active only after both role package signatures, descriptor continuity,
manifest signature, package digests, and service persistence receipts pass.
After activation, deletion of the old service-held packages is mandatory. A
failure leaves `cleanup_incomplete`; it never reactivates a superseded set.

A verified replacement recipient pair is pending metadata until its new
recovery set is ready. Activation switches the pair and set in one lifecycle
compare-and-swap. Failure discards the pending pair and keeps the old pair and
set active. Recovery-key rotation always creates fresh recovery shares and a new
set; it never rewraps the old recovery shares to new recipients.

Each active role package remains in its owning Deriver, outer-wrapped under that
role's recovery-set retention key; the public manifest remains in the control
plane. They stay available until replacement or root deletion so an authorized
tenant can redownload them. Replacement cleanup destroys the two outer key
versions before reporting strong removal; failure selects `cleanup_incomplete`.
A Deriver unwraps only its already tenant-encrypted package directly into the
download response and retains no unwrapped package object. A browser response
records `download_issued` with the exact digest. The CLI writes to a new
restrictive temporary file, syncs it, atomically installs it without overwrite,
reopens it, verifies its digest and signatures, then records
`durable_verified`. Closing a browser download dialog or returning HTTP 200 is
never represented as durable storage.

### Restore bootstrap, import binding, and cloning

An empty deployment is initialized with its canonical
`TenantRootIdentityV1`, a random destination deployment fingerprint, a random
`TenantRootCustodyLineageId`, and one
`DestinationBootstrapAuthorityV1` credential. The credential is a random
32-byte bearer token shown once to the deployment owner. The destination stores
only `SHA-256("seams/destination-bootstrap/v1" || deploymentFingerprint ||
token)` and compares it in constant time. Bootstrap authentication travels only
over TLS, is excluded from logs and request capture, and can mint 30-minute
restore administration sessions. Browser and console source sessions cannot
substitute for it.

Each role import key is an X25519 key created inside its destination Deriver.
The CLI opens one source package, verifies the manifest and role signature,
then HPKE-reseals the 34-byte share wire to that role key. The import envelope's
authenticated data contains:

```text
seams/tenant-root-restore-import/v1
destination deployment fingerprint
destination TenantRootCustodyLineageId
restore-session ID
TenantRootIdentityDigestV1
TenantRootRecoverySetId
manifest digest and source package digest
stable root commitment and role recovery-share commitment
role and share ID
destination import-key ID and public-key digest
issued-at and expiry
```

The destination role accepts one exact envelope. Repeating the same digest
returns the existing installation receipt; changing any byte for the same role
or key is a conflict. The receipt proves the installed share commitment and
contains no share bytes. Activation requires both role receipts, reconstructs
the public root commitment from their commitments, runs the mandatory forward
refresh and continuity canaries, commits the new operational epoch, and destroys
the imported shares, import private keys, unused capabilities, and bootstrap
credential.

The restore session expires after 24 hours. Expiry or pre-activation failure
must clean both imported shares and all role keys; incomplete deletion has a
separate `cleanup_incomplete` state. A role key expires after 15 minutes.
Reissuing it is allowed only before that role installs a share and invalidates
the prior key immediately.

A recovery set is an offline capability, so the tenant can repeat this flow
against another empty deployment. Every destination has a distinct custody
lineage and independent operational epochs. `verified_retired` applies only to
the named source lineage and does not prove that no other clone exists.

Destination bootstrap authority cannot retire a source. The separate retirement
action is sent to the source deployment, requires its current recovery
governance and fresh source-console authorization, and binds the destination
activation receipt. The destination records `verified_retired` only after the
source returns every required destruction and rejection receipt.

### CLI local-key and release contract

The first release supports only `encrypted_file_v1`. It stores one X25519
private key under Argon2id with a random 16-byte salt (`m=65536 KiB`, `t=3`,
`p=1`) and ChaCha20-Poly1305 with a random 12-byte nonce. Authenticated data
binds format version, role, public key, fingerprint, and KDF parameters. A key
file is created atomically without overwrite using mode `0600` on Unix or an
owner-only ACL on Windows. The two roles require different files and public-key
fingerprints.

Key and download outputs use exclusive create, reject symlinks and non-regular
targets, verify ownership and permissions after open, and install a completed
temporary file with a no-replace primitive. Failure removes only the temporary
file created by that invocation.

The passphrase comes from an interactive TTY or a caller-provided dedicated file
descriptor. Arguments, environment variables, config JSON, and stdin shared
with protocol data are rejected. Secret buffers use zeroizing Rust types;
memory locking and crash-dump suppression are attempted and reported when the
host cannot provide them. The CLI never claims that a general-purpose host is a
hardware security boundary.

Failure to obtain memory locking or crash-dump suppression emits a prominent
warning and a false capability flag in JSON, then permits the operation. The
first release has no silent or platform-dependent refusal branch. Operators who
require hardware-backed handling wait for a future qualified provider adapter.

Release artifacts cover the supported macOS, Linux, and Windows targets. A
signed checksum manifest, SBOM, source revision, and minimum compatible protocol
version accompany each release. The binary pins separate offline release and
recovery-verification roots. Recovery commands do not self-update or download
new executable code.

CLI exit codes are stable:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Usage or invalid local input |
| 3 | Authentication, step-up, approval, or capability failure |
| 4 | Artifact, signature, manifest, or trust failure |
| 5 | Local key-provider or decryption failure |
| 6 | Destination identity, lifecycle, or restore-state failure |
| 7 | Retryable network or service failure |
| 8 | Local filesystem safety or durability failure |
| 9 | Internal invariant failure |

`--json` returns an exhaustive success or error union carrying this category,
a stable machine code, retryability, and redacted public identifiers. It never
contains secret inputs or raw server bodies.

### Offline trust and signer retirement

Deriver and manifest signing keys have certificates chained to a pinned offline
recovery-verification root. A manifest includes the required chains; it cannot
add roots. Verification checks that each certificate authorized the exact role
and was valid at the artifact creation time.

Normal signer retirement preserves artifacts signed during the certificate's
valid interval. Compromise revocation carries an `invalidBefore` time and may
invalidate earlier artifacts explicitly. An offline CLI with only embedded
roots reports `cryptographically_valid_offline`. Supplying a saved signed trust
snapshot can produce `valid_at_trust_snapshot`. Online revocation and deployment
checks are required for `current_trust_confirmed`. The dashboard and CLI always
show which result was obtained.

Restore automatically admits `current_trust_confirmed` and a signed
`valid_at_trust_snapshot` issued at or after artifact creation.
`cryptographically_valid_offline` requires an
explicit destination-bootstrap acknowledgement that current revocation status
is unavailable; the activation receipt preserves that fact. A signature,
certificate, role authorization, or `invalidBefore` failure is terminal and has
no override.

Recovery-root rotation uses a bridge bundle signed by both the old and new
offline recovery roots. Historical roots and bridges remain in the trust bundle
for their certificate eras. The CLI updates trust only through an explicit
signed `seams trust update` operation or a supplied snapshot file; recovery
commands never fetch or install trust roots implicitly.

## Product Surface

### Page header

```text
Derivation root security

Your derivation root is split between Deriver A and Deriver B. You can rotate
their operational shares, download a tenant-controlled recovery backup, or
restore the root into a fresh replacement deployment.
```

The header shows the selected environment. It must not imply that the page acts
on an entire organization when the root is environment-scoped.

### Operational shares

Show:

- root status;
- deployment security profile and its permitted claim;
- Deriver A status;
- Deriver B status;
- active `TenantRootShareEpoch`;
- stable public root-commitment fingerprint;
- last completed rotation;
- next scheduled rotation;
- active job phase, if any;
- previous-epoch retirement status;
- link to the redacted audit receipt.

Primary action: **Rotate operational shares**.

Explanation:

> Rotation replaces the operational shares held by Deriver A and Deriver B. The
> derivation root stays the same, so wallet keys, addresses, and client data do
> not change. Neither Deriver reconstructs the root.

Confirmation:

```text
Rotate operational shares?

Deriver A and Deriver B will replace their current shares while keeping the
derivation root unchanged. Normal signing will continue. New derivation
ceremonies may pause briefly.

[Cancel] [Rotate shares]
```

The button starts an asynchronous job and changes to a non-interactive progress
state. Reloading the page resumes from server state. A repeated request with the
same idempotency key returns the existing job.

Progress phases use plain language:

1. Preparing rotation
2. Installing new shares
3. Verifying root continuity
4. Activating new shares
5. Retiring previous shares
6. Rotation complete

A post-activation retirement failure is shown as **Rotation active; retirement
incomplete**. The page must not claim compromise healing until both retirement
receipts pass.

`operational_rotation_v1` always shows: “Operational shares rotate, but this
deployment has not verified cryptographic erasure of retired shares.”
`managed_healing_v1` shows compromise-healing language only after both role
destruction probes and the in-flight-session drain receipt pass.

### Tenant-controlled recovery

Show:

- recovery status from the exact recovery-set lifecycle, including
  `tenant_held_external` after restore;
- recovery governance: single owner or two person;
- recovery-set ID and creation time;
- public root-commitment fingerprint;
- Deriver A recovery-recipient fingerprint;
- Deriver B recovery-recipient fingerprint;
- package A, package B, and manifest download evidence, distinguishing issued
  browser responses from CLI durable verification;
- last verification receipt;
- warning when either recovery package has never been downloaded.

Actions:

- **Configure recovery keys**
- **Create recovery backup**
- **Download Deriver A backup**
- **Download Deriver B backup**
- **Download recovery manifest**
- **Verify recovery files**
- **Replace recovery backup**

The two encrypted role packages remain separate files. The product never offers
a combined archive.

Suggested filenames:

```text
seams-<environment>-<recovery-set>-deriver-a.backup
seams-<environment>-<recovery-set>-deriver-b.backup
seams-<environment>-<recovery-set>-manifest.json
```

The page explains:

> Keep the two recovery private keys separately. Anyone who obtains both backup
> files and both recovery keys can recover the tenant derivation root.

> This recovery backup remains valid after operational-share rotation because it
> uses a separate sharing of the same stable root.

Recovery-recipient replacement includes a serious, explicit warning:

> Replacing this recovery backup cannot revoke copies you previously downloaded.
> Securely destroy old files and recovery keys when you no longer need them.

A restored `tenant_held_external` set adds:

> This deployment can verify that the recovery files restored this root, but it
> does not store those source files for redownload. Keep your files, or replace
> the recovery backup to create a new set in this deployment.

### Restore derivation root

An active deployment shows an explanation and a link to start restore on a fresh
destination. It does not show an overwrite action.

An empty destination shows:

- destination deployment fingerprint;
- restore-session ID and expiry;
- source recovery-set and root-commitment fingerprint after the manifest is
  registered;
- Deriver A import status;
- Deriver B import status;
- continuity verification status;
- forward-refresh and activation status;
- copyable role-specific CLI commands.

Before creating a restore session, the operator authenticates with the
destination's one-time bootstrap authority. The destination resolves the
canonical tenant-root identity and proves that the root slot is empty. It
rejects a manifest for another tenant, project, environment, `signingRootId`, or
`signingRootVersion`. Deployment-local service addresses and instance IDs may
change through an explicit destination binding outside the cryptographic
identity.

Restore flow:

1. **Start restore** uses a 30-minute destination bootstrap session to create an
   empty 24-hour restore session.
2. The tenant registers the public recovery manifest.
3. An authorized operator runs the Deriver A CLI command with package A and
   recovery key A. The command obtains a fresh 15-minute Deriver A import key and
   capability.
4. A second authorized operation does the same for Deriver B with package B and
   recovery key B. The two commands may run from different machines and console
   sessions. One machine can run them sequentially in separate CLI processes;
   two physical devices are not required.
5. Each CLI invocation reseals one share directly to its matching destination
   Deriver.
6. The destination verifies package signatures, recovery-set identity, role,
   root commitment, and both installed share commitments.
7. **Activate restored root** performs a forward refresh and fixed continuity
   canaries.
8. The destination activates the fresh operational epoch, records the source
   recovery set as `tenant_held_external`, and destroys the recovery-share
   imports, one-use keys, and bootstrap authority.

Restore remains possible when the original managed deployment and dashboard are
unavailable. It requires the tenant's saved packages, manifest, recovery keys,
the open-source CLI, and a supported empty destination.

Source independence does not revoke a surviving source. Activation requires an
explicit source-custody disposition: **verified retired**, **unavailable with
retirement unverified**, or **retained as a backup**. The last two branches keep
the source in the security and incident-response model. **Retained as a backup**
is preselected. Source retirement appears only as a separate destructive action
after successful destination activation.

## CLI Contract

The CLI is a versioned package with machine-readable JSON output and human output
that never includes secret material. `--json` writes result objects to stdout;
diagnostics go to stderr.

The native secret-processing core owns package parsing, key-provider access,
opening, validation, destination resealing, and zeroization. The first release's
`--key-file` names one `encrypted_file_v1` file; it never accepts a
credential-bearing URI or raw key value.

### Recovery recipient setup

```text
seams derivation-root recovery-key create \
  --role deriver-a \
  --key-file <deriver-a-key-file>

seams derivation-root recovery-key enroll \
  --environment <environment-id> \
  --role deriver-a \
  --key-file <deriver-a-key-file>
```

The same commands support `deriver-b` as a separate invocation. `create` uses
the `encrypted_file_v1` provider to create one encrypted local key file.
`enroll` fetches a role-specific challenge, proves private-key control inside
the provider, and submits only the public recipient and proof. Neither command
prints private key material.

### Status and rotation

```text
seams derivation-root status --environment <environment-id>
seams derivation-root rotate --environment <environment-id>
seams derivation-root rotation status --job <job-id>
```

`rotate` requires fresh administrative step-up. Interactive mode may open the
browser for authorization. Automation uses a short-lived operation capability
bound to the tenant root, action, idempotency key, actor, and expiry.

### Backup download and verification

```text
seams derivation-root backup download \
  --environment <environment-id> \
  --role deriver-a \
  --output <deriver-a-backup>

seams derivation-root backup download \
  --environment <environment-id> \
  --role deriver-b \
  --output <deriver-b-backup>

seams derivation-root backup manifest download \
  --environment <environment-id> \
  --output <manifest-file>

seams derivation-root backup verify \
  --manifest <manifest-file> \
  --role deriver-a \
  --package <deriver-a-backup>
```

`backup download`:

- creates the output file with restrictive permissions;
- refuses to overwrite an existing path;
- downloads exactly one role package per invocation;
- verifies content digests, Deriver signatures, recovery-set identity, role
  identity, and public root commitment before success;
- records `durable_verified` only after the file is durable and reverified;
- prints file paths, public fingerprints, and verification status;
- never prompts for recovery private keys.

`backup manifest download` downloads the public manifest without either role
package. `backup verify` is offline and processes one ciphertext package against
that manifest. It verifies public structure and integrity without opening the
encrypted role share.

### Restore

```text
seams derivation-root restore start \
  --destination <destination-url> \
  --manifest <manifest-file>

seams derivation-root restore share \
  --destination <destination-url> \
  --session <restore-session-id> \
  --role deriver-a \
  --package <deriver-a-backup> \
  --key-file <deriver-a-key-file>

seams derivation-root restore share \
  --destination <destination-url> \
  --session <restore-session-id> \
  --role deriver-b \
  --package <deriver-b-backup> \
  --key-file <deriver-b-key-file>

seams derivation-root restore status \
  --destination <destination-url> \
  --session <restore-session-id>

seams derivation-root restore activate \
  --destination <destination-url> \
  --session <restore-session-id>
```

`restore start --manifest` is a CLI convenience that calls start and manifest
registration in sequence under one bootstrap session. It returns the created
session if registration fails so the same manifest digest can be retried.
Bootstrap tokens use an interactive TTY or dedicated file descriptor and are
rejected from argv, environment variables, and JSON options.

The role command accepts exactly one role package. The other role fields are
unrepresentable in its parsed command branch. Recovery private key bytes are
never accepted as command-line values, environment variables, or JSON options.
The first release accepts only `encrypted_file_v1`; its passphrase comes from an
interactive TTY or dedicated file descriptor.

The CLI zeroizes:

- opened recovery share bytes;
- recovery-key plaintext returned by a local adapter;
- destination resealing plaintext;
- ephemeral HPKE keys;
- temporary file buffers.

It never writes opened shares to disk, swap-controlled temporary files, logs,
shell history, crash reports, telemetry, or JSON output.

## Authorization and Approvals

Read-only status follows `project.view` for the exact selected environment.

The first release requires:

- `project.edit` plus fresh high-assurance step-up for manual operational-share
  rotation;
- organization `OWNER` plus fresh high-assurance step-up for recovery backup
  creation, replacement, and one-role download;
- the selected `single_owner_v1` or `two_person_v1` branch for recipient-pair and
  governance changes;
- a destination bootstrap session for restore start, manifest registration,
  status, import-key issuance, and activation;
- destination bootstrap reauthentication at most five minutes old for
  activation;
- a short-lived destination- and role-bound capability for each Deriver share
  import;
- independent audit identity for the A and B restore operations.

The A and B imports may be completed by different actors and machines. One actor
may perform both only by running two role-specific CLI processes with separate
key files. No process or session receives both recovery private keys or opened
shares.

Recovery public keys are enrolled before backup generation. Enrollment proves
recipient-key control through a role-specific challenge. The create-backup
request cannot replace a recipient key inline.

Every mutating operation binds:

- tenant root identity;
- organization, project, and environment;
- operation kind;
- expected lifecycle revision;
- actor and authorization session;
- idempotency key;
- creation and expiry time;
- expected root-commitment fingerprint.

The exact digest, expiry, one-use consumption, actor separation, and
self-approval rejection are the frozen contracts above. Authorization adapters
parse server-issued step-up evidence once; core services never accept an MFA
boolean from a request body.

## Console and Role Boundaries

The console API resolves identity and authorization, creates operation records,
and forwards commands to the Refactor 120 control plane. It never calls a raw
Deriver share endpoint from a browser request.

The control plane:

- resolves the active tenant-root lifecycle;
- serializes mutually exclusive operations;
- creates role-specific commands;
- accepts only signed public receipts from each role;
- publishes redacted state for the dashboard and CLI.

Each Deriver:

- reads only its role-private share store;
- produces only its encrypted tenant recovery package;
- accepts only its role-specific destination import envelope;
- rejects wrong-tenant, wrong-root, wrong-role, wrong-recovery-set, expired, and
  replayed commands;
- emits public commitments and redacted receipts.

The dashboard receives no private role binding or direct Deriver service token.

## Public Console API

Exact paths may follow the console router's established naming, but the frozen
surface must contain these operations:

| Operation | Method | Purpose |
| --- | --- | --- |
| Read security status | `GET` | Return redacted root, rotation, governance, backup, download, and restore state for one environment |
| Start rotation | `POST` | Create or return one idempotent operational-share rotation job |
| Read rotation | `GET` | Poll exact lifecycle phase and redacted receipts |
| Set recovery governance | `POST` | Install one approved `single_owner_v1` or `two_person_v1` branch |
| Start recovery-key challenge | `POST` | Create one encrypted proof-of-control challenge for a role recipient |
| Confirm recovery recipient | `POST` | Consume one proof and stage the verified role recipient |
| Commit recipient pair | `POST` | Apply the selected governance policy to the exact verified A/B pair digest |
| Create or replace recovery backup | `POST` | Create one pending dedicated sharing under the active recipient pair |
| Read recovery manifest | `GET` | Return the active signed public manifest and package metadata |
| Download role package | `POST` | Consume a five-minute one-role capability and return one ciphertext |
| Record CLI durable verification | `POST` | Record the authenticated CLI's digest-bound durability result |
| Create bootstrap session | `POST` | Authenticate the empty destination's one-time bootstrap authority |
| Start restore | `POST` | Create an empty 24-hour destination restore session |
| Register restore manifest | `POST` | Bind one recovery set and public root commitment to the session |
| Issue role import key | `POST` | Create one 15-minute role-local destination HPKE key and capability |
| Import role envelope | `POST` | Accept one destination-encrypted A or B import directly from the CLI |
| Read restore | `GET` | Return exact role installation, cleanup, and continuity state |
| Activate restore | `POST` | Reauthenticate bootstrap authority, verify, forward-refresh, run canaries, and activate |
| Retire source lineage | `POST` | On the source deployment, consume a separately approved destructive capability bound to the destination activation receipt |
| Read trust status | `GET` | Return the current signed signer certificate and revocation snapshot |

Every raw response is parsed once into an exhaustive internal branch. Unknown
fields fail. Core functions do not accept partial response objects, optional
identity fields, or caller-selected tenant-root metadata.

Ciphertext downloads use `Cache-Control: no-store`, explicit attachment names,
content digests, and one-use authorization. Request and response bodies are
excluded from logs and observability payloads.

## Domain State

The console and CLI mirror server state rather than inventing local booleans.

`TenantRootRotationJobV1` has exhaustive branches for:

- `preparing`;
- `installing`;
- `verifying`;
- `activating`;
- `retiring`;
- `complete`;
- `failed_before_activation`;
- `cleanup_incomplete`;
- `retirement_incomplete`.

`TenantRootRecoveryBackupV1` uses the exact branches under **Recovery-set
replacement and download evidence**. `recipients_pending` has exact
neither-enrolled, A-enrolled, and B-enrolled variants. `replacing` requires one
complete active set and one exact pending set. `failed_initial` and
`failed_replacement` require completed pending cleanup receipts. No branch
represents one public recipient as valid for both roles.

`TenantRootRestoreSessionV1` has exhaustive branches for:

- `awaiting_manifest`;
- `awaiting_role_imports` with exact A/B installed variants;
- `verifying`;
- `ready_to_activate`;
- `refreshing`;
- `active`;
- `failed_before_activation`;
- `cleanup_incomplete`;
- `expired`.

`failed_before_activation` and `expired` require complete import-key and
installed-share cleanup receipts. Any missing receipt selects
`cleanup_incomplete`. `active` requires the destination lineage, activation
receipt, bootstrap-destruction receipt, exact source-custody disposition, and
`tenant_held_external` recovery-set record.

`TenantRootSourceCustodyDispositionV1` is exactly `verified_retired` with all
named evidence, `unavailable_retirement_unverified` with the attempted checks,
or `retained_as_backup` with an acknowledging actor and incident-response note.
It has no generic boolean such as `sourceRevoked`.

Each branch requires its exact identities, receipts, timestamps, and allowed next
operation. `never` fields reject invalid branch combinations. Type fixtures reject
activation without both role receipts, a role package on the wrong branch, an
active destination entering restore, and a rotation concurrent with restore.

## Audit and Observability

Audit events include:

- recovery governance selected or changed;
- approval capability issued, rejected, consumed, or replayed;
- recovery recipient enrolled or replaced per role;
- recovery backup created;
- Deriver A or B package download issued;
- role package or manifest durably verified by the CLI;
- manifest browser download issued;
- offline verification acknowledged;
- rotation requested, activated, retired, or failed;
- restore session started or expired;
- role A or B import accepted or rejected;
- restored root verified, refreshed, and activated;
- imported recovery material, bootstrap authority, and one-use keys destroyed;
- source disposition and destination custody lineage recorded.

Events contain public IDs, fingerprints, lifecycle revisions, actor identity,
authorization evidence, outcome, and redacted receipt digests. They contain no
ciphertext body, recovery key, share, root, refresh contribution, or import
plaintext.

Operational metrics cover latency, phase duration, failure code, stuck jobs,
download issuance, CLI durable verification, restore expiry, and retirement
backlog. Tenant identity uses the console's approved redacted label policy.

## Accessibility and Interface Behavior

- Use native buttons, links, file inputs, progress elements, headings, and
  dialogs where they fit.
- Every confirmation repeats the exact action in its button label.
- Modal focus moves inside, remains trapped, and returns to the trigger.
- Rotation and restore progress use a stable polite live region. Urgent failures
  use an alert and provide the next safe action.
- Status always includes text and an icon; color never carries status alone.
- File inputs have visible role-specific labels and inline errors linked through
  `aria-describedby`.
- Keyboard users can complete backup download, rotation, and restore
  orchestration.
- The page reflows at 320 CSS pixels and 200% zoom without horizontal scrolling.
- Long IDs show a shortened visual value while the accessible name and copy
  action expose the complete value.
- Progress motion honors `prefers-reduced-motion`.
- Errors identify the failed role and next action: for example, “Deriver B backup
  does not match this recovery manifest. Select the Deriver B file from recovery
  set …”.

## Preparation Phase

Before production implementation:

- [ ] Materialize Refactor 120's tenant identity, lineage, recovery-share,
      commitment, receipt, and lifecycle contracts as Rust types and vectors.
- [ ] Materialize this plan's governance union, operation digest, one-use
      capability, step-up evidence, and self-approval rejection as exact types
      and red tests.
- [ ] Generate canonical descriptor, package, manifest, import-envelope,
      certificate-chain, and trust-snapshot fixtures from Rust.
- [ ] Implement `encrypted_file_v1` vectors, file-permission fixtures,
      passphrase-input rejection, zeroization, memory-lock reporting, and crash
      handling before adding network commands.
- [ ] Freeze role-specific CLI parsed-command branches, exit codes, JSON result
      unions, filenames, MIME types, and interruption behavior.
- [ ] Materialize destination bootstrap, restore-session, import-key,
      source-disposition, cleanup, and clone-lineage states as exhaustive types.
- [ ] Produce signed test release and recovery trust roots, signer certificates,
      revocation snapshots, and release checksum fixtures.
- [ ] Inventory every dashboard, console server, wallet console adapter, Router
      A/B service binding, audit, approval, and CLI boundary listed below.
- [ ] Add red contract fixtures for cross-tenant access, wrong-role restore,
      active-destination restore, mixed recovery sets, stale lifecycle revisions,
      concurrent operations, and secret-bearing logs.
- [ ] Prove recovery succeeds with the source deployment fully unavailable.
- [ ] Prove the same recovery set creates two distinct destination lineages and
      that neither can replay the other's commands or receipts.
- [ ] Stop if a browser, console service, Router, or one CLI invocation must hold
      both decrypted recovery shares.

### Boundary inventory

| Area                       | Current modules to classify                                                                                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Root scalar and share wire | `crates/threshold-prf/src/shamir.rs`, `prf.rs`, suite IDs, commitments, canonical scalar parsing, and Rust vectors                                                                            |
| Shared protocol types      | `crates/router-ab-core/src`, generated TypeScript bindings and fixtures, `packages/shared-ts/src/threshold/signingRootScope.ts`, and every raw parser consuming root identity                 |
| Role crypto                | `crates/router-ab-ed25519-yao/src/crypto.rs` HPKE suite and role keys; new recovery reshare/package/import modules; native zeroizing secret containers                                         |
| Cloudflare custody         | `crates/router-ab-cloudflare/src`, Deriver A/B D1 migrations, Durable Object lifecycle, environment bindings, private service auth, role signer keys, and key-provider adapters               |
| Dashboard routing          | `apps/seams-console/src/core/dashboard/types.ts`, `src/app/dashboardConfig.tsx`, dashboard route resolution and sidebar                                                                       |
| Dashboard components       | `DashboardInlineModal`, `DashboardPageActions`, toaster, status-tone, timestamp, copy, and selected-context helpers                                                                           |
| Dashboard product page     | New route under `apps/seams-console/src/products/wallet` following wallet operation page and API patterns                                                                                     |
| Console route policy       | `packages/console-server-ts/src/router/consoleRouteDefinitions.ts`, `consoleRoutePolicy.ts`, console session claims and project access                                                        |
| Console services           | New root-security request parsers, types, service, errors, and D1 operation metadata under `packages/console-server-ts/src` or the wallet product server boundary selected during preparation |
| Wallet console composition | `packages/wallet-console-server-ts/src/router` Cloudflare adapters, route composition, Router A/B bindings, tenant storage routing, audit metadata, and service construction                  |
| Router A/B control plane   | Refactor 120 lifecycle, role-private stores, Deriver commands, Durable Object coordination, commitments, receipts, and private service authentication                                         |
| Native secret core         | New Rust artifact/key/HPKE module, `threshold-prf` share wires, existing Router A/B HPKE suite, Argon2id key-file boundary, zeroizing buffers, and platform memory/file adapters               |
| CLI                        | New native `seams` command package, console authentication, HTTP client, exact command union, file durability, JSON results, and redaction boundaries                                          |
| Audit and approvals        | Console audit service; approval operation union and service; server-issued step-up evidence; one-use operation capabilities; requester/approver separation                                    |
| Destination bootstrap      | Empty-deployment initialization, bootstrap verifier/session, role import-key endpoints, cleanup, credential destruction, and browser-route exclusion                                           |
| Trust and distribution     | Recovery-verification root, signer certificate chains, revocation snapshot, release root, signed checksums, SBOM, release artifacts, and offline verification                                  |
| Deployment                 | Destination identity and lineage initialization, source-offline configuration, role-private endpoints, CORS exclusion, and verified-retirement probes                                         |
| Tests                      | Dashboard component tests, console route/unit tests, Cloudflare integration tests, CLI process tests, type fixtures, and intended-behaviour contracts                                         |

The inventory is complete only after every raw JSON, file, command-line,
environment, HTTP, D1, Worker binding, Rust/WASM, generated type, log, and audit
boundary has an owner and an authoritative test.

### Known pre-implementation incompatibilities

The inventory already identifies four current shapes that cannot satisfy this
plan unchanged:

1. `SigningRootScope.signingRootVersion` is optional at a shared TypeScript
   boundary. `TenantRootIdentityV1` requires it and must be built by one strict
   server boundary parser.
2. Console route policy currently expresses authenticated, owner, and project
   access without a typed fresh-step-up proof for these operations.
3. The approval service currently knows only `POLICY_PUBLISH` and `KEY_EXPORT`,
   accepts caller-provided `mfaVerified`, permits requester approval, and leaves
   an approved record reusable. Refactor 121 replaces those behaviors for the
   tenant-root operation union; it does not widen `KEY_EXPORT` as a shortcut.
4. No native `seams` CLI boundary exists. Secret parsing, local key storage,
   HPKE opening/resealing, trust verification, and JSON redaction must share one
   Rust core rather than parallel Rust, Wasm, and TypeScript implementations.

## Required Tests and Guards

1. **Protocol contracts** — fixed cross-runtime fixtures for manifest, role
   package, import envelope, commitments, and redacted receipts.
2. **Type fixtures** — invalid lifecycle branches, mixed roles, broad spreads,
   direct literals, missing receipts, and active-destination restore fail to
   compile.
3. **Authorization** — cross-tenant and cross-environment requests fail; read,
   rotate, backup, and restore permissions remain distinct; caller MFA booleans,
   self-approval, same-actor two-person approval, stale step-up, capability
   reuse, changed operation digests, and expired capabilities fail.
4. **Rotation behavior** — repeated requests are idempotent, progress survives
   reload, normal signing remains available, and retirement-incomplete language
   never claims full healing.
5. **Download behavior** — two separate ciphertext files and one manifest are
   produced; cache and attachment headers are correct; download eligibility
   waits for both recipient proofs; browser `download_issued` and CLI
   `durable_verified` remain distinct; no response body reaches logs.
6. **CLI filesystem safety** — exact `encrypted_file_v1` vectors, restrictive
   permissions, distinct role key files, one-role download, sync/reopen/digest,
   no overwrite, partial-download cleanup, signature verification, and stable
   exit codes.
7. **CLI secret safety** — private key bytes are rejected from argv, environment,
   JSON output, diagnostics, telemetry, crash text, and temporary files; each
   restore process opens one role only.
8. **Restore behavior** — source-offline restore, bootstrap reauthentication and
   destruction, separate A/B actors and machines, one-machine sequential
   two-process restore, mixed-set rejection,
   wrong-role rejection, import-key reissue and expiry, exact-envelope replay,
   changed replay rejection, identity and lineage rebinding rejection,
   root-commitment continuity, mandatory forward refresh, source-disposition
   recording, zero automatic source mutation, explicit destructive retirement,
   cleanup receipts, and two distinct clones from one recovery set.
9. **Dashboard behavior** — loading, empty, ready, active-job, failure,
   retirement-incomplete, security-profile, external-recovery, trust, and
   restore states render the server branch exactly; operational-only mode never
   displays compromise-healing copy.
10. **Accessibility** — keyboard-complete flows, visible focus, modal focus
    restoration, accessible names, role-specific file errors, live progress,
    reduced motion, 200% zoom, and 320-pixel reflow.
11. **Audit** — every action and rejection emits one redacted event; mutation
    failure does not suppress audit recording.
12. **Deployment guards** — dashboard and console environments contain no
    Deriver root share, recovery private key, or raw private-role binding; public
    browser routes cannot reach restore-import endpoints.
13. **Trust and release** — package creation-time validation, ordinary signer
    retirement, `invalidBefore` compromise revocation, stale trust snapshots,
    offline status labels, signed release checksums, and no-update recovery
    execution follow the frozen branches.

Source-text guards remain a last resort. Prefer behavioral tests, type fixtures,
canonical vectors, route-policy tests, file-permission tests, and deployment
binding assertions.

## Implementation Plan

### Phase 1: freeze shared contracts

- [ ] Complete the preparation phase.
- [ ] Add exact public status, governance, approval, operation, backup, trust,
      bootstrap, and restore response types.
- [ ] Add boundary parsers and type fixtures.
- [ ] Add canonical recovery artifact, certificate, trust-snapshot, local-key,
      and import-envelope fixtures.

### Phase 2: expose control-plane operations

- [ ] Add redacted status and job APIs.
- [ ] Add rotation authorization and idempotent job creation.
- [ ] Replace generic approval reuse with the exact tenant-root operation union,
      server step-up evidence, actor separation, and transactional consumption.
- [ ] Add recovery governance, encrypted recipient challenge, and pair commit.
- [ ] Add atomic recovery-set replacement, separate download capabilities, and
      issued/durable evidence.
- [ ] Add empty-destination bootstrap sessions, restore sessions, and role import
      endpoints.
- [ ] Add audit and observability events.

### Phase 3: ship backup CLI

- [ ] Add the native Rust `seams` binary and `encrypted_file_v1` provider.
- [ ] Add CLI authentication and selected-environment resolution.
- [ ] Add status and rotation commands.
- [ ] Add safe three-file download with public verification.
- [ ] Add offline verification and machine-readable output.
- [ ] Add filesystem, redaction, interruption, and exit-code tests.
- [ ] Publish signed cross-platform release assets, checksums, SBOM, source
      revision, and minimum protocol version.

### Phase 4: add the dashboard page

- [ ] Add the route, sidebar item, page, and API client.
- [ ] Render operational-share status and rotation explanation.
- [ ] Add rotation confirmation, live progress, retry, and receipts.
- [ ] Add recovery-recipient and separate download flows.
- [ ] Show governance, issued versus durable download evidence, current trust
      level, and `tenant_held_external` recovery state.
- [ ] Add restore-session orchestration and role-specific CLI instructions.
- [ ] Complete accessibility and narrow-layout verification.

### Phase 5: ship source-independent restore

- [ ] Add role-specific CLI opening and destination resealing.
- [ ] Add separate A/B restore capability and actor handling.
- [ ] Add bootstrap authority, exact import AAD, continuity verification, forward
      refresh, activation, credential destruction, and cleanup.
- [ ] Run the restore drill with the source network and credentials unavailable.
- [ ] Run retained-source and verified-source-retirement drills and verify their
      security claims remain distinct.
- [ ] Restore the same artifacts twice and prove destination lineage isolation.
- [ ] Publish the tenant recovery runbook and artifact-storage guidance.

## Definition of Done

Refactor 121 is complete when:

1. The selected tenant environment has one Derivation root security page.
2. The page clearly explains operational-share rotation between Deriver A and B.
3. An authorized tenant can start and monitor an idempotent rotation.
4. Rotation preserves the stable root, wallet keys, addresses, client state, and
   normal-signing availability.
5. The tenant can download separate encrypted A and B recovery packages and a
   verified public manifest through the page or CLI; each CLI package download
   handles one role.
6. The CLI can verify the artifacts offline without recovery private keys.
7. The source deployment is unnecessary for restore after the tenant has saved
   its recovery artifacts.
8. Role A and role B restore occur through separate commands, capabilities,
   import keys, and destination endpoints.
9. No browser, console service, Router, persistence record, log, or CLI invocation
   receives both decrypted recovery shares or the joined root.
10. Restore accepts only an empty destination, verifies the stable public root
    commitment and exact logical root identity, forward-refreshes, and activates
    fresh operational shares.
11. Every high-impact action has exact authorization or destination bootstrap
    reauthentication, audit, idempotency, and failure semantics.
12. The complete dashboard flow is keyboard accessible, screen-reader legible,
    responsive at 320 pixels and 200% zoom, and independent of color and motion.
13. Recovery governance is one explicit union branch; two-person approval rejects
    self-approval and consumes one exact operation capability.
14. Recipient proof of control, role key inequality, package bytes, manifest
    bytes, import AAD, and trust results pass canonical cross-runtime fixtures.
15. Browser download issuance is never presented as durable CLI verification,
    and active encrypted packages remain available for redownload until
    replacement or deletion.
16. Restore destroys its bootstrap credential, imported shares, and import keys,
    or remains in an exact cleanup-incomplete state.
17. The same recovery artifacts can restore multiple empty destinations, and
    every destination receives a distinct replay-isolated custody lineage.
18. A restored deployment labels source artifacts `tenant_held_external` until
    the tenant explicitly creates a replacement recovery backup there.

## Non-Goals

- changing the Refactor 120 root-sharing or rotation cryptography;
- reconstructing or downloading the joined tenant root;
- placing both encrypted packages in one combined archive;
- accepting both recovery private keys in one dashboard or CLI operation;
- restoring over an active tenant root;
- automatic restore based only on a health check;
- custom rotation scheduling in the first release;
- wallet-inventory or application-level migration;
- RP ID or passkey migration;
- revoking wallet signing authorities or application cutover;
- per-wallet owner key export;
- storing tenant recovery private keys for the customer.

## Remaining Evidence Gates

There are no open first-release product-policy decisions in this plan. Phase 1
still waits for the canonical Rust fixtures, exhaustive types, approval red
tests, boundary inventory, and CLI filesystem/key vectors named above.

Release still requires successful source-offline, clone-isolation,
retained-source, verified-retirement, trust-revocation, interrupted-download,
and cleanup-failure drills. These checks may reject the implementation. They do
not create fallback protocols, optional identity fields, combined recovery
operations, or weaker authorization branches.
