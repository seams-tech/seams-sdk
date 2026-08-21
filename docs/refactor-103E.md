# Refactor 103E — Simplify Device Linking

Date created: August 21, 2026

Status: implementation-ready. R103E is a deletion refactor that consolidates
the working R103, R103C, and R103D behavior before R109A and R109B expand the
supported authentication combinations.

## Goal

Device linking should create one wallet authority on Device 2, install its
ordinary signer material, and issue its ordinary Wallet Session. Once active,
Device 2 uses the same signing, export, inventory, reload, unlock, and
auth-method revocation paths as every other wallet authority. Users revoke its
auth methods one at a time; the authority is retired internally after its last
method is revoked and another active method remains for the wallet.

The completed implementation must be easier to understand and smaller than the
current implementation. R103E does not introduce a workflow framework, a second
signing model, or linked-device-specific operating paths.

## Non-negotiable decisions

An implementer should not reopen these design choices:

1. `WalletAuthorityV1` is the only durable answer to who may operate the
   wallet, with which permissions, and through which exact activations.
2. Device linking creates a new authority and fresh per-family shares. It is
   additive and leaves Device 1 unchanged.
3. Device linking never invokes recovery, custody re-establishment, rotation,
   rejoin, hydration, R102 promotion, or wallet-wide candidate selection.
4. D1 `active` is the visibility gate. Pending local installation cannot sign,
   export, appear in inventory, issue a usable session, or unlock.
5. Device 2 uses ordinary signing, export, Wallet Session, reload, unlock,
   inventory, and revocation paths after activation.
6. The Ed25519 Yao Client root uses one-use encrypted link transport only when
   `export_keys` is granted. The wallet custody seed never enters linking.
7. Every source, target, authority, auth method, enrollment, activation, and
   session identity is parsed into its existing brand. R103E adds only
   `WalletAuthorityId`.
8. Current delivery supports Passkey-to-Passkey and Email-OTP-to-Email-OTP.
   R109B adds cross-family combinations through the same verified-factor seam.
9. A persisted incomplete legacy enrollment returns `relink_required` at its
   boundary. Runtime operations do not repair it.
10. The refactor finishes by deleting replaced records, paths, types, fixtures,
    and mocks. Aliasing old names to new behavior does not satisfy completion.
11. Every user-initiated revocation targets one exact `WalletAuthMethodId`, is
    authorized by a different active method under an exact full-owner
    authority, and must leave another active method for the wallet. No ordinary
    route accepts `WalletAuthorityId` as a revocation target.

## Explicitly out of scope

Keep these features out of R103E:

- cross-family source and target authentication combinations;
- adding a second auth method to an existing authority;
- agent or service principals;
- a UI for custom permission grants or signer-family subsets;
- remote recovery, custody-seed transport, signer rotation, or signer repair;
- a permanent migration framework;
- a generic workflow, saga, projection, or authorization framework;
- new public route families when an existing device-linking route can be
  changed in place.

R109A owns multiple auth methods per authority. R109B owns cross-family device
linking. A coding agent must leave an explicit seam for those refactors and
must not implement either feature while completing R103E.

## Why the current structure is slow to change

One Device 2 authority is currently represented across several independently
written records:

- link-session and target-factor ceremony state;
- owner binding and authority digest;
- permission grant;
- Ed25519 and ECDSA signer material;
- Ed25519 export-root material;
- Wallet Session authorization;
- device inventory projection;
- reload, warm-session, and lock state.

Readers reconstruct the relationship between these records after the link has
completed. A missing or mismatched record appears later as `no_candidate`, a
missing capability subject, incomplete inventory coverage, failed reload, or an
unlock error. Recovery and hydration code then attempts to repair the partial
activation during an ordinary operation.

R103E makes authority activation linear and gives every fact one authoritative
owner.

## Smallest domain model

The operating architecture has five concepts.

### 1. `WalletAuthMethod`

Describes one locally usable Passkey or Email OTP factor. It contains one exact
`WalletAuthorityId` reference.

R109A can add another `WalletAuthMethod` that references the same authority. It
does not create another signer activation.

### 2. `WalletAuthority`

Describes what one principal may do with a wallet. It is the authoritative
record for permissions, signer activation references, status, and revocation.

```ts
type WalletAuthorityV1 = WalletAuthorityCommonV1 & (
  | {
      readonly state: 'pending_local_install';
      readonly localInstallPackageSetDigestB64u: DigestB64u;
      readonly activatedAtMs?: never;
      readonly revokedAtMs?: never;
    }
  | {
      readonly state: 'active';
      readonly localInstallPackageSetDigestB64u?: never;
      readonly activatedAtMs: number;
      readonly revokedAtMs?: never;
    }
  | {
      readonly state: 'revoked';
      readonly localInstallPackageSetDigestB64u?: never;
      readonly activatedAtMs: number;
      readonly revokedAtMs: number;
    }
);

type WalletAuthorityCommonV1 = {
  readonly kind: 'wallet_authority_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly principal: WalletAuthorityPrincipalV1;
  readonly provenance: WalletAuthorityProvenanceV1;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly signerActivations: WalletSignerActivationSetV1;
  readonly signerActivationSetDigestB64u: DigestB64u;
  readonly authorityDigestB64u: DigestB64u;
  readonly revocationEpoch: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};
```

`WalletAuthorityProvenanceV1` distinguishes a founding authority from an
authority created by device linking. Provenance is metadata on the authority.
It does not create a parallel authority model.

### 3. `SignerActivation`

The existing ordinary Ed25519 or ECDSA activation for one authority. Ed25519
and ECDSA remain independently administered. `WalletSignerActivationSetV1`
contains exact `MpcMaterialActivationRef` values and represents Ed25519-only,
ECDSA-only, or both.

`ExactAdministeredSignerManifestV1` remains the public-key manifest. It cannot
serve as `WalletSignerActivationSetV1`: its members contain public signer
identity and no `MpcMaterialActivationId`. Remove or rename the misleading
`ExactAdministeredSignerActivationSetV1` alias during the cutover rather than
using it as a material reference.

When `export_keys` is granted and Ed25519 is present, the Ed25519 activation's
local material includes its factor-sealed Yao Client export root. ECDSA export
uses the ordinary ECDSA activation. Both exports require fresh step-up on the
selected `WalletAuthMethod`.

### 4. `WalletSession`

A short-lived authorization issued from one active authority and one verified
auth method. Its capability subjects come directly from the authority's
permissions and exact signer activation references.

### 5. `LinkSession`

Temporary QR transport, source authorization, target-factor ceremony, and
progress state. It owns cancellation and all pre-commit failures. It is removed
after activation and is never read by signing, export, inventory, reload, or
unlock.

### Authoritative ownership table

The implementation must preserve these ownership boundaries:

| Fact | Authoritative owner | Other records may store |
| --- | --- | --- |
| authority lifecycle and permissions | `WalletAuthorityV1` in D1 | `WalletAuthorityId` and verified digest/epoch claims |
| exact signer families and activation refs | `WalletAuthorityV1.signerActivations` | exact activation refs only |
| public wallet signer identity | existing signer manifest records | manifest digest or exact public identity where required by protocol |
| factor credential and lifecycle | `WalletAuthMethodRecord` | `WalletAuthMethodId` only |
| Device 2 client shares | existing factor-sealed IndexedDB material stores | exact activation and auth-method refs |
| server shares | existing signer workers/stores | exact activation refs and acknowledged lifecycle only |
| Ed25519 export root | existing factor-sealed IndexedDB export-root store | package/root identity and digest only |
| runtime authorization | ordinary Wallet Session authorization store | authorization ID, authority ID, digest, epoch, and exact subjects |
| temporary progress and transport | `LinkSession` | nothing after activation cleanup |

Do not duplicate a row from the middle column as a convenience projection.
Cross-subsystem records refer to it by exact branded identity and verify the
relevant digest at their trust boundary.

## Normative shared contract

This section is the implementation contract. Names marked **reuse** already
exist and retain their current serialization. Names marked **add** are the only
new durable domain names introduced by R103E.

### Reused shared types

| Type | Action | Purpose |
| --- | --- | --- |
| `DelegatedWalletPermissionV1` | reuse | `sign`, `export_keys`, `link_devices`, `revoke_devices` |
| `CanonicalDelegatedWalletPermissionSetV1` | reuse | parsed, sorted, non-empty permission set |
| `FULL_OWNER_PERMISSIONS` | reuse | default permissions for ordinary owner-device linking |
| `validateDelegatedWalletAuthorityAttenuationV1` | reuse | source authority cannot grant a permission it lacks |
| `ExactAdministeredSignerManifestV1` | reuse | public signer families and public-key identity |
| `MpcMaterialActivationRef` | reuse | exact activated MPC material identity |
| `WalletAuthMethodId` | reuse | exact Passkey or Email OTP method |
| `WalletSessionAuthorizationId` | reuse | all ordinary Wallet Session authorization |
| `LinkedDeviceEnrollmentId` | reuse | audit provenance for the link attempt |
| `DeviceId` | reuse | one installed wallet-authority principal on a browser/device |
| `LinkDeviceSessionId` | reuse | temporary QR workflow identity |
| `LinkedDeviceEd25519ExportRootRecipientV1` | reuse | one-use Device 2 recipient during link transport |
| `LinkedDeviceEd25519ExportRootPackageV1` | reuse | encrypted Ed25519 Yao Client root during link transport |

The permission-only `DelegatedWalletAuthorityV1` remains a grant value while
R103E is being cut over. It is folded into `WalletAuthorityV1.permissions` and
deleted after all callers consume `CanonicalDelegatedWalletPermissionSetV1`
directly. It must never become a second durable authority record.

### New durable identity

Add exactly one brand to `packages/shared-ts/src/utils/domainIds.ts`:

```ts
export type WalletAuthorityId = DomainId<'WalletAuthorityId'>;
```

Add `parseWalletAuthorityId` beside the other domain parsers and a type fixture
that rejects `WalletId`, `WalletAuthMethodId`, `MpcMaterialActivationId`,
`LinkedDeviceEnrollmentId`, and `WalletSessionAuthorizationId` in its place.
The server allocates an opaque value once when it first commits a pending
authority. Retry requests carry the returned ID. Do not derive the ID from a
wallet, device, enrollment, factor, or link session.

### Principal and provenance

R103E supports human owner devices only. Agent principals belong to the later
agent feature and must not add a branch now.

```ts
type WalletAuthorityPrincipalV1 = {
  readonly kind: 'owner_device';
  readonly deviceId: DeviceId;
};

type WalletAuthorityProvenanceV1 =
  | {
      readonly kind: 'wallet_registration';
      readonly enrollmentId?: never;
      readonly sourceAuthorityId?: never;
      readonly linkSessionId?: never;
    }
  | {
      readonly kind: 'device_link';
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly sourceAuthorityId: WalletAuthorityId;
      readonly linkSessionId: LinkDeviceSessionId;
    };
```

Replace `LinkedDeviceId` with the existing authorization `DeviceId` during the
cutover. They currently describe the same browser/device resource and keeping
both creates another swap-prone identity pair. The persistence parser is the
only place that may read the old linked-device ID column into `DeviceId`; core
code receives `DeviceId` only.

`sourceAuthorityId` is audit provenance. Authorization uses the verified source
authority loaded for the request. No operation inherits permissions by walking
the provenance chain.

### Exact signer activation set

Add one discriminated union. Each branch contains the public signer identity
and its exact material activation reference. A family cannot be present without
both values.

```ts
type WalletEd25519SignerActivationV1 = {
  readonly kind: 'wallet_ed25519_signer_activation_v1';
  readonly signer: ExactAdministeredEd25519SignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

type WalletEcdsaSignerActivationV1 = {
  readonly kind: 'wallet_ecdsa_signer_activation_v1';
  readonly signer: ExactAdministeredEcdsaSignerV1;
  readonly materialActivation: MpcMaterialActivationRef;
};

type WalletSignerActivationSetV1 =
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519'];
      readonly ed25519: WalletEd25519SignerActivationV1;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ecdsa_secp256k1'];
      readonly ed25519?: never;
      readonly ecdsa: WalletEcdsaSignerActivationV1;
    }
  | {
      readonly kind: 'wallet_signer_activation_set_v1';
      readonly keyFamilies: readonly ['ed25519', 'ecdsa_secp256k1'];
      readonly ed25519: WalletEd25519SignerActivationV1;
      readonly ecdsa: WalletEcdsaSignerActivationV1;
    };
```

The builder enforces:

- every signer uses the authority's `walletId`;
- every signer family appears once;
- every `walletKeyId` matches the verified source manifest;
- the registered Ed25519 and ECDSA public keys match the source manifest;
- activation refs are distinct and match their expected capability, key,
  material owner, lifecycle, and worker bindings;
- family order is canonical: Ed25519 before ECDSA.

### Canonical digests

Add one canonical encoder per digest and call it from builders and boundary
parsers. Do not serialize arbitrary JavaScript objects or database JSON.

`signerActivationSetDigestB64u` is the domain-separated digest of the union
version, canonical family order, each public signer identity, and each exact
`MpcMaterialActivationRef`.

`authorityDigestB64u` is the domain-separated digest of:

- authority version and `WalletAuthorityId`;
- `WalletId` and principal `DeviceId`;
- provenance branch and its exact IDs;
- canonical permissions;
- `signerActivationSetDigestB64u`;
- lifecycle state and `revocationEpoch`.

It excludes display metadata and timestamps. The pending-to-active transition
and revocation each produce a new digest. Wallet Session claims carry the
active digest and exact epoch, so either change invalidates an older session.
Every D1/IndexedDB parser recomputes both digests and rejects disagreement.

### Auth method relation

Extend the canonical `WalletAuthMethodRecord` with one required
`walletAuthorityId: WalletAuthorityId`. Keep the existing factor-specific
branches. Make `WalletAuthMethodId` an opaque record identity; credential ID,
email hash, registration authority, wallet ID, and authority ID remain fields
and indexes rather than components that callers concatenate into an ID.

```ts
type WalletAuthMethodCommonV1 = {
  readonly version: 'wallet_auth_method_v2';
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
};

type WalletAuthMethodLifecycleV1 =
  | {
      readonly status: 'pending_local_install';
      readonly activatedAtMs?: never;
      readonly revokedAtMs?: never;
    }
  | {
      readonly status: 'active';
      readonly activatedAtMs: number;
      readonly revokedAtMs?: never;
    }
  | {
      readonly status: 'revoked';
      readonly activatedAtMs: number;
      readonly revokedAtMs: number;
    };
```

The Passkey and Email OTP branches extend the common record and lifecycle
union using their existing required factor fields and `never` exclusions.
The auth method and authority move from pending to active in the same D1
transaction. R109A can create
multiple auth-method records with the same `walletAuthorityId`. Existing
`passkey:*`, `email_otp:*`, and `email_otp_linked:*` IDs are accepted only by
the migration parser. New records use `wallet-auth-method:<random UUID>` from
the existing runtime randomness source. Delete all canonical-ID string
builders and D1 checks that reconstruct an auth-method ID from factor fields
after migration.

### Verified target factor

Passkey and Email OTP converge into one boundary-parsed union. It contains
verified evidence and an exact auth-method draft. The pending authority ID is
allocated later, so the draft cannot be persisted directly. It carries no
signer or permission decisions.

```ts
type VerifiedTargetFactorV1 =
  | {
      readonly kind: 'verified_passkey_target_v1';
      readonly authMethod: PasskeyWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'verified_email_otp_target_v1';
      readonly authMethod: EmailOtpWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    };

type WalletAuthMethodDraftCommonV1 = {
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletId: WalletId;
  readonly createdAtMs: number;
};

type PasskeyWalletAuthMethodDraftV1 = WalletAuthMethodDraftCommonV1 & {
  readonly kind: 'passkey';
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly emailHashHex?: never;
  readonly registrationAuthorityId?: never;
};

type EmailOtpWalletAuthMethodDraftV1 = WalletAuthMethodDraftCommonV1 & {
  readonly kind: 'email_otp';
  readonly emailHashHex: string;
  readonly registrationAuthorityId: string;
  readonly rpId?: never;
  readonly credentialIdB64u?: never;
  readonly credentialPublicKeyB64u?: never;
  readonly counter?: never;
};
```

The Email OTP boundary consumes its existing one-use grant before constructing
this value. The parser must verify wallet, device, enrollment, link session,
target preparation digest, expiry, and one-time consumption. A masked email
hint is display data and never participates in authority identity.

The server allocates `WalletAuthMethodId` during target preparation and binds
it into the Passkey creation options or Email OTP grant. Device 2 returns that
bound ID with its verified result. A raw client request cannot nominate or
replace an auth-method ID.

## Identity rules

Use brands for durable identity classes. Use narrow function fields for
temporary source and target roles.

The required brands are:

| Identity | Meaning |
| --- | --- |
| `WalletId` | one wallet |
| `WalletAuthorityId` | one permissioned wallet authority |
| `WalletAuthMethodId` | one Passkey or Email OTP method |
| `MpcMaterialActivationId` | one exact signer material activation |
| `WalletSessionAuthorizationId` | one runtime authorization |
| `LinkDeviceSessionId` | one temporary link workflow |
| `LinkedDeviceEnrollmentId` | audit provenance for one link attempt |
| `DeviceId` | one installed wallet-authority principal on a browser/device |
| `revocationEpoch` | a validated non-negative integer generation on one authority |

Reuse existing brands when they already carry these meanings. Introduce only
`WalletAuthorityId` if the codebase has no canonical authority identity.

Do not create:

- a separate activation ID for the same `WalletAuthority`;
- linked-device-specific Wallet Session IDs;
- source and target brands for the same auth-method resource;
- new envelope IDs when the existing material record has an exact identity;
- duplicate signer-manifest or signer-activation brands.

At request, database, worker, and local-storage boundaries:

1. parse raw IDs once;
2. recompute and verify authority and package digests;
3. construct the narrow domain record;
4. pass only branded IDs to core code.

Core code never compares raw identity strings or scans wallet-wide records to
infer an authority.

Device 2 creates a fresh `DeviceId` for every new link attempt that reaches
target preparation. It is an installation identity, not a hardware fingerprint
or browser-global identifier. Re-linking the same physical browser therefore
creates a new `DeviceId`, `WalletAuthorityId`, and independently revocable auth
method. R109A factor addition reuses the existing authority and its `DeviceId`.

## Durable ownership and schema

### Server source of truth

Add one `wallet_authorities` table. It replaces
`linked_device_owner_auth_bindings` as the lifecycle, inventory, permission,
and internal authority-retirement source.

Required columns:

```text
scope columns
authority_id                    primary key within scope
wallet_id
device_id
provenance_kind                 wallet_registration | device_link
enrollment_id                   required only for device_link
source_authority_id             required only for device_link
link_session_id                 required only for device_link
lifecycle_state                 pending_local_install | active | revoked
permissions_json                canonical parsed permission set
signer_activations_json         exact WalletSignerActivationSetV1
local_install_package_set_digest_b64u  required only for pending_local_install
signer_activation_set_digest_b64u
authority_digest_b64u
revocation_epoch
record_json                     exact WalletAuthorityV1
created_at_ms
updated_at_ms
activated_at_ms                 required for active and revoked
revoked_at_ms                   required only for revoked
```

Required constraints and indexes:

- primary key `(scope, authority_id)`;
- unique `(scope, wallet_id, device_id)` for non-revoked R103E owner
  authorities, implemented as a partial index so an explicitly revoked device
  can be linked again as a new authority;
- unique non-null `(scope, wallet_id, enrollment_id)`;
- index `(scope, wallet_id, lifecycle_state, updated_at_ms, authority_id)` for
  inventory pagination;
- exact nullability checks for both provenance branches and all lifecycle
  branches;
- `record_json` identity, digest, and lifecycle fields agree with columns;
- `revocation_epoch = 0` for pending and initial active authorities;
- revocation increments the previous epoch by exactly one.

Rebuild `wallet_auth_methods` with required `wallet_authority_id` and a foreign
key to `wallet_authorities`. Index `(scope, wallet_id, wallet_authority_id,
status)`. Remove the foreign-key direction from owner binding to auth method;
the auth method is the child resource.

Existing signer/server-share tables remain the authority for secret material.
They are addressed through each `MpcMaterialActivationRef`. Add
`wallet_authority_id` to those activation rows only when an existing exact
material-owner or lifecycle binding cannot already resolve the authority.
Avoid copying share or protocol records into `wallet_authorities`.

`linked_device_sessions` stores `authority_id` and the local-install
package-set digest after commit. It owns no copy of permissions,
activation refs, or inventory state after that point.

### Browser source of truth

Use one IndexedDB transaction across the existing stores. Add a
`walletAuthorities` store only if there is no existing aggregate store capable
of persisting exact `WalletAuthorityV1` records. The transaction writes:

- `WalletAuthorityV1`;
- the `WalletAuthMethodRecord` that references it;
- one factor-sealed client-material record per activation, keyed by
  `(authorityId, walletAuthMethodId, activationId)`;
- one factor-sealed Ed25519 export-root envelope when required, keyed by
  `(authorityId, walletAuthMethodId, walletKeyId)`;
- the local installation receipt.

R109A writes another set of factor-sealed local records for its new
`WalletAuthMethodId` while reusing the authority and activation IDs. It never
overwrites the original method's sealed records.

The selected wallet record stores only `walletId`, selected
`walletAuthMethodId`, lock generation, and lock state. It does not cache
authority, permissions, signer families, or activation IDs.

### Link-session lifecycle

Replace the current generic completion state with this exact durable union:

```ts
type LinkSessionStateV1 =
  | { readonly state: 'displaying_qr' }
  | { readonly state: 'claimed'; readonly deviceId: DeviceId }
  | { readonly state: 'awaiting_target_factor'; readonly deviceId: DeviceId }
  | { readonly state: 'provisioning'; readonly deviceId: DeviceId }
  | {
      readonly state: 'authority_pending_local_install';
      readonly deviceId: DeviceId;
      readonly authorityId: WalletAuthorityId;
      readonly packageSetDigestB64u: DigestB64u;
    }
  | {
      readonly state: 'active';
      readonly deviceId: DeviceId;
      readonly authorityId: WalletAuthorityId;
      readonly activatedAtMs: number;
    }
  | {
      readonly state: 'failed_before_commit';
      readonly error: LinkPrecommitFailureV1;
    }
  | { readonly state: 'cancelled'; readonly cancelledAtMs: number }
  | { readonly state: 'expired'; readonly expiredAtMs: number };
```

Once `authority_pending_local_install` is durable, local-install or activation
errors leave the session in that state for exact retry. They never create a
fresh authority or package set. `active` is retained only long enough for
Device 2 to acknowledge receipt of its Wallet Session; cleanup then deletes
the link session and one-use transport records.

Allowed transitions are linear:

```text
displaying_qr
  -> claimed
  -> awaiting_target_factor
  -> provisioning
  -> authority_pending_local_install
  -> active
  -> deleted
```

`failed_before_commit`, `cancelled`, and `expired` are reachable only before
`authority_pending_local_install`. A committed pending authority cannot be
cancelled or expired; it must resume to active or be retired by internal
cleanup keyed to its exact authority ID. That cleanup is unavailable to
ordinary user requests. Precommit cancellation/expiry deletes any inactive
worker reservations by their planned activation refs. Cleanup is idempotent
and never touches source-authority material.

## One linear activation

Passkey and Email OTP differ only during target-factor verification. Both
branches produce `VerifiedTargetFactorV1` and enter the same activation
function. The public orchestration returns a typed result; exceptions are
reserved for programming errors and unavailable infrastructure.

```ts
type VerifiedSourceAuthorityV1 = {
  readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
  readonly authMethodId: WalletAuthMethodId;
  readonly verifiedRevocationEpoch: number;
  readonly authorityDigestB64u: DigestB64u;
  readonly verifiedAtMs: number;
};

type VerifiedLinkInputV1 = {
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly targetDeviceId: DeviceId;
  readonly sourceAuthority: VerifiedSourceAuthorityV1;
  readonly targetFactor: VerifiedTargetFactorV1;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly signerManifest: ExactAdministeredSignerManifestV1;
};

async function activateLinkedAuthority(
  input: VerifiedLinkInputV1,
): Promise<LinkedAuthorityActivationResultV1> {
  const plan = buildAuthorityInstallPlan(input);
  const committed = await commitPendingAuthority(plan);
  const receipt = await installLocalAuthority(committed, input.targetFactor);
  const active = await activateInstalledAuthority(receipt);
  await finalizeLocalAuthorityActivation(active);
  return { kind: 'active', session: active.walletSession };
}
```

These are standalone functions with narrow inputs. `AuthorityInstallPlanV1`
is an in-memory value. It is not exported from the orchestration module and is
never persisted or accepted from a caller. The snippet shows the successful
branch. The implementation exhaustively switches over the typed results at
each call before invoking the next narrow function.

### Verify the source authority

The source request boundary constructs `VerifiedSourceAuthorityV1` only after
all of these checks pass:

1. the Wallet Session authenticates the requested `walletId` and exact
   `WalletAuthMethodId`;
2. that auth method is active and references the loaded authority;
3. that authority is active and its `revocationEpoch` matches the session;
4. the recomputed authority digest matches the session claim;
5. the authority has `link_devices`;
6. its exact signer activations reproduce the supplied public manifest;
7. the requested permission set passes
   `validateDelegatedWalletAuthorityAttenuationV1`;
8. the link session is unexpired, unclaimed by another device, and belongs to
   the same wallet and enrollment.

The default request grants `FULL_OWNER_PERMISSIONS` and includes every signer
family present in the source manifest. R103E does not expose a UI or request
field for selecting a subset of signer families. A future restricted grant may
use the same attenuation validator, but it must be a separately specified
product feature.

The verified source authority is an ephemeral proof object. It is not written
to D1, IndexedDB, a link session, or diagnostics.

### Build the install plan

The plan is derived entirely from verified inputs:

- include every signer family present on Device 1 by default;
- require a fresh Device 2 signer activation for each included family;
- include the Ed25519 Yao Client export root only when Ed25519 is present and
  `export_keys` is granted;
- include no signer family that is absent from the source manifest;
- derive Wallet Session capability subjects from the permissions and exact
  activation references.

Callers cannot provide prepared packages or override derived requirements.

Device linking is additive. The plan allocates new Device 2 activation refs,
client shares, and server shares that preserve the source public signer
identities. It never changes Device 1's authority, auth method, activation
refs, local shares, server shares, export root, Wallet Sessions, or revocation
epoch. Recovery, custody re-establishment, rotation, and source-lane promotion
are forbidden calls from this path.

The plan contains exactly:

```ts
type AuthorityInstallPlanV1 = {
  readonly kind: 'authority_install_plan_v1';
  readonly walletId: WalletId;
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly targetDeviceId: DeviceId;
  readonly sourceAuthorityId: WalletAuthorityId;
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
  readonly signerManifest: ExactAdministeredSignerManifestV1;
  readonly targetAuthMethod: PasskeyWalletAuthMethodDraftV1 | EmailOtpWalletAuthMethodDraftV1;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly exportRootRequirement:
    | { readonly kind: 'required'; readonly recipient: LinkedDeviceEd25519ExportRootRecipientV1 }
    | { readonly kind: 'not_required'; readonly recipient?: never };
};
```

`exportRootRequirement` is derived by the builder. The `required` branch is
selected exactly when the manifest contains Ed25519 and the permission set
contains `export_keys`; it carries the already-verified one-use Device 2
recipient. No lifecycle branch accepts this decision from a route body.

### Commit a pending authority

The server atomically writes:

- one `WalletAuthority` with `pending_local_install` status;
- one factor-specific `WalletAuthMethodRecord` with
  `pending_local_install` status;
- exact references to every acknowledged inactive worker-share reservation;
- the immutable package-set digest;
- device and enrollment metadata needed by inventory.

An idempotent retry returns the same authority and package set. A conflicting
retry fails without activating any child record.

The committed response is a boundary-parsed discriminated union. It reuses the
existing family-specific encrypted client package types; do not copy their
ciphertext, AAD, worker binding, or activation fields into another package
shape.

```ts
type CommittedAuthorityPackagesV1 = {
  readonly kind: 'committed_authority_packages_v1';
  readonly authority: Extract<
    WalletAuthorityV1,
    { readonly state: 'pending_local_install' }
  >;
  readonly authMethod: WalletAuthMethodRecord;
  readonly signerPackages: CommittedSignerPackageSetV1;
  readonly ed25519ExportRootPackage:
    | LinkedDeviceEd25519ExportRootPackageV1
    | null;
  readonly packageSetDigestB64u: DigestB64u;
};
```

`CommittedSignerPackageSetV1` mirrors the three branches of
`WalletSignerActivationSetV1`. Each member is the existing encrypted client
package for that family plus the exact activation ref already stored on the
pending authority. The package-set digest covers, in canonical order:

- authority, wallet, enrollment, link-session, device, and auth-method IDs;
- canonical permissions and source manifest digest;
- every exact activation ref and encrypted client package digest;
- the optional export-root package digest;
- the target-factor verification digest.

The commit is one D1 transaction for the pending authority, auth method,
acknowledged material-reservation references, package digest, and link-session
transition. Worker share creation crosses a service boundary. Those calls must
be idempotent by exact activation ref. D1 commits only after every required
worker returns the corresponding inactive reservation. A retry observes and
reuses the same reservations.

### Install locally

One IndexedDB transaction writes:

- the target `WalletAuthMethod` referencing the new authority;
- every factor-sealed client signer share;
- the factor-sealed Ed25519 Yao Client export root when required;
- one installation receipt keyed by `WalletAuthorityId`.

A partial local authority is never visible. Retrying installation uses the
same committed packages.

The receipt is proof of one completed local IndexedDB transaction. It contains
identities and digests, never client shares, export roots, decrypted factor
material, or a generic success flag.

```ts
type LocalAuthorityInstallationReceiptV1 = {
  readonly kind: 'local_authority_installation_receipt_v1';
  readonly authorityId: WalletAuthorityId;
  readonly walletId: WalletId;
  readonly authMethodId: WalletAuthMethodId;
  readonly deviceId: DeviceId;
  readonly packageSetDigestB64u: DigestB64u;
  readonly installedActivationRefs: WalletSignerActivationSetV1;
  readonly installedRecordSetDigestB64u: DigestB64u;
  readonly targetFactorVerificationDigestB64u: DigestB64u;
  readonly installedAtMs: number;
};
```

The local receipt is authenticated with the verified target-factor ceremony's
existing proof mechanism. The server verifies its exact IDs, package digest,
factor verification digest, signer set, expiry, and one-use ceremony binding.
It does not claim that a remote server can inspect browser storage.

### Activate

Device 2 submits the installation receipt. The server validates it against the
package digest and atomically:

- changes the authority to `active`;
- changes its auth method to `active`;
- activates its server shares;
- makes it visible to inventory;
- issues one Wallet Session with the exact capability subjects.

Device 2 uses one final IndexedDB transaction to replace the pending local
authority and auth method with the exact active records returned by the
server, persist the Wallet Session, and delete its local link-session state.
Until this transaction commits, ordinary operations resolve the authority as
pending and fail closed. Device 1
closes the QR surface as soon as the claim has been accepted and releases its
runtime guard on every terminal result.

`active` means the following operations work immediately for every granted and
present family:

- signing;
- key export with fresh step-up;
- linked-device inventory;
- reload;
- lock and subsequent unlock;
- revocation admission.

The transition to `active` fails when any required material or authorization
subject is absent.

Activation is a compare-and-set from `pending_local_install` to `active`.
Every worker activation call is idempotent by exact activation ref. D1 is the
visibility gate: ordinary operations and inventory require an active D1
authority, so a crash after a worker acknowledges activation and before the D1
transaction is safe to retry. The retry observes the already-active worker
share, completes the remaining acknowledgements, and then commits D1.

Wallet Session issuance follows the successful D1 compare-and-set. If the
response is lost, a retry against the active authority deterministically issues
or renews an ordinary Wallet Session. It does not create another authority,
auth method, activation, package set, or lifecycle state.

The active compare-and-set also commits the ordinary Wallet Session
authorization record, including its exact authority digest, revocation epoch,
and capability subjects. Token encoding may happen after the transaction. A
lost token response is therefore a read/re-encode retry against the same
authorization record. The server must never expose an active authority whose
durable session authorization is absent or has different subjects.

If Device 2 crashes after server activation and before its final IndexedDB
transaction, reload resumes by the exact `WalletAuthorityId`, installation
receipt, and package digest. It fetches the already-active authority, auth
method, and Wallet Session, commits the final local transaction, and deletes
the temporary link state. It does not repeat factor verification, create new
material, or select a sibling authority.

### Retry and interruption contract

| Interruption | Required retry behavior |
| --- | --- |
| before pending commit | retry the same link session or start a new unclaimed one |
| after worker reservation, before D1 commit | reuse reservations by activation ref, then commit once |
| after pending commit, before local install | return the same authority and byte-identical package set |
| during local installation | IndexedDB transaction aborts; retry the same package set |
| after local install, before activation | resubmit the same receipt |
| during worker activation | reuse already-activated refs and finish the remaining refs |
| after D1 activation, before session response | issue or renew the ordinary session for the same authority |
| after session persistence, before link cleanup | acknowledge active and delete only temporary link records |

A retry whose authority ID, package digest, factor digest, activation set, or
device differs from the committed values returns `integrity_error`. It never
falls back to wallet-wide selection and never prepares replacement material.

### Typed activation results

Use this control-flow result at the orchestration boundary:

```ts
type LinkedAuthorityActivationResultV1 =
  | { readonly kind: 'active'; readonly session: ActiveWalletSessionV1 }
  | {
      readonly kind: 'pending_local_install';
      readonly authorityId: WalletAuthorityId;
      readonly packageSetDigestB64u: DigestB64u;
    }
  | { readonly kind: 'failed_before_commit'; readonly reason: LinkPrecommitFailureV1 }
  | { readonly kind: 'relink_required'; readonly reason: RelinkRequiredReasonV1 }
  | { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 };
```

The server activation seam returns:

```ts
type ActivateInstalledAuthorityResultV1 =
  | {
      readonly kind: 'active';
      readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
      readonly authMethod: Extract<WalletAuthMethodRecord, { readonly status: 'active' }>;
      readonly walletSession: ActiveWalletSessionV1;
    }
  | {
      readonly kind: 'pending_local_install';
      readonly authorityId: WalletAuthorityId;
      readonly reason: ActivationRetryReasonV1;
    }
  | { readonly kind: 'integrity_error'; readonly reason: LinkIntegrityFailureV1 };

type ResolveActiveWalletAuthorityResultV1 =
  | {
      readonly kind: 'resolved';
      readonly authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>;
      readonly authMethod: Extract<WalletAuthMethodRecord, { readonly status: 'active' }>;
    }
  | { readonly kind: 'unavailable'; readonly reason: WalletAuthorityAdmissionFailureV1 };
```

`activateLinkedAuthority` exhaustively switches over the commit, local-install,
and activation results and maps them to
`LinkedAuthorityActivationResultV1`. Do not cast a broad result to its success
branch and do not convert domain failures to message strings.

`LinkPrecommitFailureV1` is an exhaustive union of invalid input, unauthorized
source, revoked source, permission attenuation failure, target-factor failure,
expired session, cancelled session, claim conflict, and package-preparation
failure. `RelinkRequiredReasonV1` is limited to incomplete migrated enrollment
or missing canonical local material. `LinkIntegrityFailureV1` identifies the
exact mismatched ID or digest. UI strings are mapped from these results at the
UI boundary; message text never drives control flow.

### Existing route and wire cutover

Reuse the current session creation, claim, target-factor, provisioning,
activation/status, inventory, and revocation route URLs. Replace their request
and response parsers in place. Do not add a parallel `/v2` route tree or a
second event stream.

Wire values carry raw strings and version tags. Their boundary parsers must
produce the branded and branch-specific values defined above before invoking
core code. Link-operation bodies may carry a previously returned
`WalletAuthorityId`; they may not nominate a new authority ID, auth-method ID,
activation ref, package digest, permission requirement, or export-root
requirement. The revocation body instead carries one previously returned
`WalletAuthMethodId`. Its parser rejects `WalletAuthorityId` as a target.

Use these HTTP classes consistently while preserving typed response bodies:

| Failure | HTTP status |
| --- | --- |
| malformed or unsupported boundary input | 400 |
| missing or invalid authentication | 401 |
| authenticated source lacks the requested permission | 403 |
| claim, idempotency, lifecycle, receipt conflict, or `would_remove_last_wallet_auth_method` | 409 |
| expired or already-consumed precommit link session | 410 |
| retryable worker or infrastructure unavailability | 503 |
| persisted digest or identity integrity failure | 500 |

The browser switches on the typed response `kind`. It never infers retry,
re-link, or success behavior from HTTP message text.

## Post-link export has no linked-device path

Device linking installs the same material consumed by the ordinary export
flows:

```text
Ed25519 export
  -> selected WalletAuthMethod
  -> active WalletAuthority with export_keys
  -> exact Ed25519 SignerActivation
  -> factor-sealed Yao Client export root
  -> fresh step-up
  -> ordinary Yao export

ECDSA export
  -> selected WalletAuthMethod
  -> active WalletAuthority with export_keys
  -> exact ECDSA SignerActivation
  -> fresh step-up
  -> ordinary ECDSA export
```

Export never installs, hydrates, recovers, rotates, promotes, or searches for
missing linked material. An incomplete active authority is an integrity error
at the activation boundary.

The one-use `LinkedDeviceEd25519ExportRootRecipientV1` and
`LinkedDeviceEd25519ExportRootPackageV1` remain part of link-time transport.
They carry only the Ed25519 Yao Client root encrypted to Device 2's verified
recipient. Device 2 seals that root under its target factor during local
installation. Device 2 never receives the wallet custody seed, an unsealed
ECDSA root share, or a complete private scalar. The transport records are
deleted after activation acknowledgement.

Ed25519 and ECDSA export each consume a fresh step-up proof scoped to the exact
`WalletAuthMethodId`, `WalletAuthorityId`, export capability subject, and
operation ID. A factor proof used to link the device, unlock the wallet, or
export the other family cannot authorize the export.

## Wallet Session issuance and capability subjects

Delete `LinkedDeviceWalletSessionAuthorizationId` and every linked-device
Wallet Session branch. `ActiveWalletSessionV1` uses the existing ordinary
`WalletSessionAuthorizationId` and records the exact authority, auth method,
revocation epoch, and capability subjects.

```ts
type ActiveWalletSessionV1 = {
  readonly kind: 'active_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly authorityRevocationEpoch: number;
  readonly capabilitySubjects: readonly [
    WalletCapabilitySubjectV1,
    ...WalletCapabilitySubjectV1[],
  ];
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};
```

Reuse the existing ordinary capability-subject variants. Build the non-empty
set once from the authority:

- `sign` emits one ordinary signing subject for each present activation;
- `export_keys` emits one ordinary export subject for each present activation;
- `link_devices` emits the existing device-link administration subject;
- `revoke_devices` emits the existing device-revocation subject.

Each signer subject embeds the exact `MpcMaterialActivationRef`. No subject is
emitted for an absent family. Session issuance fails before activation when a
granted permission cannot be represented by the authority's material. Runtime
selection uses the session's authority and exact refs; link provenance and
link-session IDs never participate.

## Reload, lock, and unlock

Reload starts from durable lock state.

```text
selected wallet
  -> durable lock state
  -> selected local WalletAuthMethod
  -> exact active WalletAuthority
  -> exact SignerActivation records
  -> valid WalletSession, when present
```

When the wallet is locked, reload stops before warm-session, Shamir3pass,
signer, export, or Wallet Session rehydration.

Use a monotonic local lock generation. Every asynchronous unlock, link,
rehydration, and warm-session result carries the generation under which it
started. `lockWallet` increments the generation. Older results cannot publish
an unlocked state.

Unlock performs one exact sequence:

1. select a local `WalletAuthMethodId`;
2. verify its Passkey or Email OTP factor;
3. load the referenced active `WalletAuthority`;
4. verify status and revocation epoch;
5. open its exact local signer material;
6. issue or renew its Wallet Session;
7. expose ordinary operations.

Unlock does not read a link session, select sibling authorities, scan
candidates, or repair material.

The admission failures returned to callers are a `Result`-style union:

```ts
type WalletAuthorityAdmissionFailureV1 =
  | { readonly kind: 'wallet_locked' }
  | { readonly kind: 'auth_method_revoked'; readonly authMethodId: WalletAuthMethodId }
  | { readonly kind: 'authority_revoked'; readonly authorityId: WalletAuthorityId }
  | { readonly kind: 'revocation_epoch_mismatch'; readonly authorityId: WalletAuthorityId }
  | { readonly kind: 'local_material_unavailable'; readonly activation: MpcMaterialActivationRef }
  | { readonly kind: 'relink_required'; readonly reason: RelinkRequiredReasonV1 }
  | { readonly kind: 'integrity_error'; readonly reason: WalletAuthorityIntegrityFailureV1 };
```

This exact resolution prevents the shared-OTP revocation bug: successful OTP
verification identifies one local `WalletAuthMethodId`, which resolves one
`WalletAuthorityId` and one `DeviceId`. Admission never accepts the same email
factor as authority for a revoked sibling device.

Before any asynchronous link, unlock, warm-session, or rehydration task writes
local state or publishes an unlocked runtime, it compares its captured lock
generation with the current durable generation. A mismatch returns
`wallet_locked` and discards the result.

## Inventory and revocation

Inventory queries active wallet authorities with linked-device provenance. It
does not build device state from link sessions or independently persisted
projections. R103E has no paused lifecycle branch.

The D1 query is ordered by `(updated_at_ms, authority_id)` and uses both values
as the opaque cursor. It applies `limit` before constructing response records,
returns each authority once, and computes `nextCursor` from the last returned
authority. Inventory validates the persisted `WalletAuthorityV1` parser and
its signer-activation-set digest. It does not re-derive lane-product coverage:
activation already proved the exact set complete.

User-initiated revocation loads one exact `WalletAuthMethodId`. Its fresh
source proof must come from a different active method for the same wallet, and
the source authority must have exact `FULL_OWNER_PERMISSIONS`. The D1
transaction refuses the request unless another active method backed by an
active authority will remain for the wallet.

The transaction revokes only the target method, its verifier, and sessions
issued through that method. When the target authority retains another active
method, its epoch, signer activations, sibling methods, and sibling sessions
remain unchanged. When the target was its final method, the same transaction
retires the now-unusable authority, increments its epoch, and invalidates any
remaining authority sessions. Exact worker-share disablement follows that
retirement idempotently. Ordinary admission rejects the retired authority even
if worker cleanup is delayed.

No user-facing request targets `WalletAuthorityId` or revokes all methods on an
authority at once. The wallet's final active method returns
`would_remove_last_wallet_auth_method` without changing durable state. Method
inventory and revocation do not depend on retained link-session history.

## Relationship to R109A

R109A adds multiple auth methods to one wallet. A new factor creates another
`WalletAuthMethod` that references the intended existing `WalletAuthority`.
Adding the method does not duplicate signer activations or permissions.

R109A may open and reseal the wallet custody seed inside its dedicated
factor-addition ceremony. Device linking never receives that seed.

R109A reuses:

- `WalletAuthMethodId` and `WalletAuthorityId`;
- the Passkey and Email OTP factor union;
- exact auth-method-to-authority resolution;
- Wallet Session issuance;
- durable lock generation.

R109A is reconciled to this model. Multiple auth methods on one device may
reference the same authority. Each method keeps its exact factor envelope and
Wallet Session; permissions and signer activations remain authority-owned.
R109A's primary goal is one authority with both factor families active. It
permits multiple active Passkeys and at most one active Email OTP method per
authority.
R109A also replaces R103E's transitional factor-field draft with the canonical
Passkey and Email OTP provider-identity branches. R103E's authority,
activation, Wallet Session, and lock contracts remain controlling.

## Relationship to R109B

R109B allows source and target devices to use different auth families.

```text
source WalletAuthMethod -> source WalletAuthority -> authorize delegation
target factor           -> new WalletAuthMethod   -> new WalletAuthority
```

All four Passkey and Email OTP combinations converge at
`VerifiedLinkInputV1`.
The shared activation function has no source-auth-kind branch.

Device linking creates fresh independently revocable signer shares for Device
2 while preserving the wallet's public signer identities. The wallet custody
seed never crosses the device-link channel. An `export_keys` permission carries
the Ed25519 Yao Client export root through the one-use target recipient and
seals it under Device 2's verified factor.

R103E should land before R109B removes current same-family restrictions. R109B
then adds factor combinations without adding activation branches.

R103E also supersedes current R109B language that transfers the wallet custody
seed, creates a linked execution authorization, persists an owner binding, or
installs R102 lane products. R109B must retain only source-proof/target-factor
independence, explicit Email OTP base-factor selection, failure UX, and the
four-combination matrix. Its target converges into this plan's new authority,
fresh ordinary activations, optional encrypted Ed25519 export root, and
ordinary Wallet Session.

## Registration and factor addition

Wallet registration creates the founding `DeviceId`, active
`WalletAuthorityV1`, and first active `WalletAuthMethodRecord` when its ordinary
signer activations commit. The founding authority uses
`provenance.kind = 'wallet_registration'`, `FULL_OWNER_PERMISSIONS`, every
registered signer family, and `revocationEpoch = 0`. Registration must not
create an owner-binding projection that R103E later has to infer.

R109A factor addition creates another auth method for an existing authority.
Its local reseal records use the same authority and activation refs with the
new auth-method ID. The authority lifecycle and permissions do not change.
This distinction is normative:

```text
device link      -> new DeviceId + new WalletAuthorityId + fresh activations
factor addition  -> existing WalletAuthorityId + new WalletAuthMethodId
```

## Cutover and data policy

Use a reset for local development and staging data unless preserving those
records is an explicit release requirement. Do not build a permanent migration
framework for disposable environments.

If production data must be preserved, implement one boundary-only migration:

1. create `wallet_authorities` and the v2 auth-method table without switching
   readers;
2. convert a founding auth method only when its ordinary signer records resolve
   to one complete exact activation set;
3. convert a linked enrollment only when its owner binding, active auth method,
   exact activation refs, revocation epoch, public manifest, and optional
   export root all agree;
4. allocate opaque authority and auth-method IDs and persist the old-to-new ID
   map inside the migration transaction only;
5. mark incomplete or conflicting enrollments `relink_required`; never
   synthesize an activation, export root, authority digest, or session subject;
6. verify row counts, unique active device ownership, activation-set digests,
   and foreign keys;
7. switch all readers and writers to the new records;
8. delete owner bindings, projections, old auth-method ID builders, and the
   migration parser after the supported environments have cut over.

Old `passkey:*`, `email_otp:*`, `email_otp_linked:*`, and `LinkedDeviceId`
values are raw migration inputs. The boundary parser returns opaque
`WalletAuthMethodId` and `DeviceId` values. No core function, route, or new
record accepts the legacy serialized forms.

## Delete during the cutover

Remove these paths once the linear activation works:

1. linked-device-specific post-link signer and export execution types that
   duplicate ordinary flow types; retain the one-use link-time recipient and
   encrypted export-root package types;
2. separate linked-device Wallet Session authorization identities;
3. persisted signer, export, session, and inventory projections that duplicate
   `WalletAuthority` references;
4. caller-supplied export-root requirement wrappers; retain the derived
   `exportRootRequirement` branch inside the in-memory install plan;
5. post-link recovery, rotation, rejoin, hydration, and R102 lane promotion;
6. wallet-wide candidate scans and recent-record ranking;
7. auth-kind inference and signer-slot hints in authenticated operations;
8. link-session reads after authority activation;
9. independent active writes for credentials, signer material, export
   material, inventory, and Wallet Session;
10. generic completion states that do not identify the remaining durable step;
11. duplicate signer manifests, activation references, and envelope shapes;
12. mocked transitions that declare linking successful without real material
    installation and ordinary operations.

Compatibility code is allowed only in request and persistence parsers during
the cutover. Existing complete records may be converted into one exact
`WalletAuthority`. Incomplete records return `relink_required`. Ordinary
operations never repair them. Delete the conversion after local and staging
data have been recreated.

### Concrete removal ledger

The implementer must trace imports before deletion, then remove these canonical
duplicates rather than preserving aliases:

- `LinkedDeviceWalletSessionAuthorizationId`, its ref/parser/builders, linked
  authorization domain record, store methods, and renewal paths in
  `packages/shared-ts/src/authorization/capabilityKinds.ts` and
  `packages/wallet-server/src/authorization/`;
- `DelegatedDeviceActivationPlanV1`, its opaque proof/parser, and
  `ExactAdministeredSignerActivationSetV1` in
  `packages/shared-ts/src/device-linking/delegatedActivationPlan.ts` after
  callers use the in-memory plan and exact activation refs;
- `linked_device_session_projection_v1` and
  `linked_device_local_account_projection_v1` parser branches after the new
  authority readers land;
- `LinkedDeviceTargetReadyR102InputV1`, holder promotion, recovery admission,
  and post-link R102 target-ready persistence used to manufacture ordinary
  owner capability;
- `persistLinkedDeviceWalletSessionAuthorization` and its linked-only callers;
- owner source-lane wallet-wide candidate scans used after authenticated exact
  authority resolution;
- `linked_device_owner_auth_bindings` and its inventory/revocation readers
  after the authority migration or environment reset.

Do not delete unrelated account projections, generic passkey custody activity
projections, normal signing vectors, or the one-use Ed25519 export-root
recipient/package transport merely because their names include “projection”
or “linked device.” Deletion is based on duplicated ownership described in
this plan.

## Concurrent implementation structure

R103E is implemented through one small foundation checkpoint followed by four
parallel workstreams. The workstreams share the model defined in this document.
They do not introduce local variants of `WalletAuthority`, activation state, or
identity rules.

### Foundation checkpoint — lead agent

Land the minimum shared contract before parallel implementation begins:

- reuse or add the canonical `WalletAuthorityId` brand;
- define the `WalletAuthority` lifecycle union;
- make `WalletAuthMethod` reference exactly one authority;
- select the existing canonical signer-manifest and activation-set types;
- define `VerifiedTargetFactorV1` and the boundary-parsed
  `VerifiedLinkInputV1` shape;
- add type fixtures for the demonstrated ID swaps.

This checkpoint contains types and parsers only. It does not add adapters,
compatibility services, orchestration, or placeholder implementations. Once it
lands, every workstream compiles against the same contract.

Canonical locations for the checkpoint:

- add `packages/shared-ts/src/authorization/walletAuthority.ts` for the
  authority lifecycle, principal/provenance, activation set, and builders;
- update `packages/shared-ts/src/utils/domainIds.ts` for
  `WalletAuthorityId` only;
- keep permission definitions in
  `packages/shared-ts/src/authorization/delegatedAuthority.ts`;
- keep the public signer manifest in
  `packages/shared-ts/src/device-linking/delegatedActivationPlan.ts` until the
  misleading plan/proof types are deleted, then move only the manifest to the
  nearest existing signer-identity module;
- keep factor-specific auth-method branches in their existing canonical auth
  method module; add the authority relation and lifecycle there;
- place boundary parsers beside the wire/request types they parse, never in the
  core authority module.

Required static fixtures reject:

- every durable ID substituted for `WalletAuthorityId`;
- an active authority without activation time;
- a pending authority without the local-install package digest;
- a revoked authority without both activation and revocation times;
- Ed25519, ECDSA, or both with a missing or extra family member;
- a Passkey record with OTP fields and an OTP record with Passkey fields;
- an active auth method referencing a pending authority in a builder input;
- a revocation input with `WalletAuthorityId` or more than one
  `WalletAuthMethodId` as its target;
- broad object spreads that bypass the branch-specific builders.

### Workstream A — server authority lifecycle

**Ownership**

- `packages/wallet-server/src/core/deviceLinking/`
- `packages/wallet-server/src/router/cloudflare/d1/deviceLinking/`
- linked-only records and methods in
  `packages/wallet-server/src/authorization/`;
- device-linking server routes and D1 migrations;
- focused server tests for activation, inventory, and revocation.

**Deliverables**

- atomically commit `pending_local_install` authority and inactive server
  shares;
- make commit idempotent by `WalletAuthorityId` and package digest;
- verify the local installation receipt and activate the authority;
- issue the exact Wallet Session during activation;
- derive grouped inventory from `WalletAuthority` and its exact auth methods;
- revoke one exact auth method, enforce the wallet-wide remaining-method
  invariant, and retire a zero-method authority internally;
- delete server projections, R102 promotion, and recovery admission superseded
  by this lifecycle.

**Must not edit** browser IndexedDB, browser unlock, SeamsWeb linking
orchestration, or ordinary export/signing flows.

### Workstream B — browser installation, reload, and unlock

**Ownership**

- `packages/wallet/src/core/indexedDB/seamsWalletDB/`
- `packages/wallet/src/core/signingEngine/session/`
- `packages/wallet/src/core/signingEngine/useCases/unlockWallet.ts`
- focused browser persistence, lock, reload, and unlock tests.

**Deliverables**

- install the auth method, signer shares, optional Ed25519 export root, and
  receipt in one IndexedDB transaction;
- resolve runtime state through
  `WalletAuthMethod -> WalletAuthority -> SignerActivation`;
- add monotonic durable lock generation;
- make explicit lock win over stale async and rehydration results;
- remove link-session, candidate-scan, hydration, and repair dependencies from
  reload and unlock.

**Must not edit** server stores and routes, SeamsWeb device-link orchestration,
or export/signing flow implementations.

### Workstream C — linking orchestration and factor convergence

**Ownership**

- `packages/wallet/src/SeamsWeb/operations/devices/`
- `packages/wallet/src/SeamsWeb/walletIframe/host/handlers/deviceLink.ts`
- `packages/wallet/src/SeamsWeb/walletIframe/host/runtime-device-link.ts`
- device-linking ceremony and inventory UI;
- focused orchestration and inventory-client tests.

**Deliverables**

- make Passkey and Email OTP produce the same `VerifiedTargetFactorV1`;
- implement the linear orchestration call sequence;
- resume a committed installation by exact `WalletAuthorityId`;
- persist the Wallet Session returned by activation;
- delete the local link session after activation;
- close Device 1's QR surface on claim acceptance and release guards on every
  terminal result;
- remove linked-device package wrappers that duplicate the shared contract.

**Must not edit** shared domain contracts after the foundation checkpoint,
server persistence, ordinary export/signing, or browser unlock internals.

### Workstream D — ordinary operations and real verification

**Ownership**

- `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`;
- `packages/wallet/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts`;
- `packages/wallet/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
  (move its exact ordinary resolver into the existing export flow and delete
  the recovery-named module);
- `packages/wallet/src/core/signingEngine/flows/signNear/`
- `packages/wallet/src/core/signingEngine/flows/signEvmFamily/`
- `tests/e2e/linked-device.operating-path.test.ts`;
- `tests/playwright.linked-device.config.ts`;
- device-linking test fixtures shared across the four workstreams.

**Deliverables**

- resolve signing and export from the exact active authority and activation;
- require one fresh step-up for both Ed25519 and ECDSA export;
- remove linked-device-specific export/signing execution and fallback paths;
- replace mocked lifecycle transitions with real composed routes and stores;
- prepare interruption, reload, unlock, inventory, and revocation scenarios;
- run the final real two-browser verification after A, B, and C integrate.

**Must not edit** server activation persistence, browser local-install
transactions, or linking orchestration. Product defects found during final
verification are assigned to the owning workstream.

`BrowserSigningSurface.ts` is owned entirely by Workstream D to prevent
parallel conflicts in the current monolith. Workstream C supplies its composed
device-link operation through the agreed port; D performs the minimal surface
wiring. This ownership rule does not justify another facade or framework.

### Ownership and coordination rules

1. Each production file has one owning workstream.
2. Shared contract changes stop after the foundation checkpoint. A required
   contract correction returns to the lead agent as one explicit patch.
3. Workstreams communicate through the committed contract and boundary
   fixtures. They do not import one another's internal helpers.
4. Shared test fixtures belong to Workstream D. Other workstreams request a
   fixture change instead of editing them concurrently.
5. Each workstream produces one focused checkpoint commit before integration.
6. No workstream performs broad formatting, generated-artifact rewrites, or
   unrelated cleanup.
7. Deletion of an old path belongs to the workstream that replaces it.
8. A workstream that discovers overlapping ownership pauses that edit and
   reports the exact file and required change to the lead agent.

### Parallel exit contracts

The four workstreams can complete independently against these exact seams:

```ts
// A provides
commitPendingAuthority(plan): Promise<CommittedAuthorityPackagesV1>;
activateInstalledAuthority(receipt): Promise<ActivateInstalledAuthorityResultV1>;

// B provides
installLocalAuthority(
  committed: CommittedAuthorityPackagesV1,
  factor: VerifiedTargetFactorV1,
): Promise<LocalAuthorityInstallationReceiptV1>;
finalizeLocalAuthorityActivation(
  active: Extract<ActivateInstalledAuthorityResultV1, { readonly kind: 'active' }>,
): Promise<void>;

// C composes
activateLinkedAuthority(input: VerifiedLinkInputV1): Promise<LinkedAuthorityActivationResultV1>;

// D consumes only ordinary active-authority reads
resolveActiveAuthority(
  authMethodId: WalletAuthMethodId,
): Promise<ResolveActiveWalletAuthorityResultV1>;
```

These are behavior contracts. Existing codebase names should be reused when
they already express the same operation.

## Integration and verification order

### Phase 1 — Foundation

Land the shared contract and type fixtures. Confirm all four workstreams can
compile against it.

Exit: no workstream needs to invent a local authority shape, and the foundation
adds no duplicate aliases, adapters, placeholder services, or local variants of
the shared types. Net type-count reduction is a final cutover criterion because
the replacement types land before the obsolete types are deleted.

### Phase 2 — Parallel implementation

Run Workstreams A, B, C, and D concurrently. Each runs its narrowest focused
tests and commits only its owned files.

Exit: each workstream satisfies its exit contracts without compatibility
logic in core code.

### Phase 3 — Linear-path integration

Integrate A, B, and C through the stated seams. Workstream D connects the real
behavior test to the composed implementation. Delete any temporary adapter
that existed only to bridge workstream development.

Exit: one real Device 2 link reaches an authority that can immediately perform
every granted ordinary operation.

### Phase 4 — Delete superseded paths

- delete every path listed in **Delete during the cutover**;
- update R103C, R103D, R109A, and R109B to use this model;
- delete obsolete fixtures, mocked success transitions, and source guards;
- compare device-linking source and type counts with the pre-R103E baseline.

Exit: both counts are lower and every durable fact has one owner.

### Phase 5 — Real operating-path verification

Use fresh wallets and two independent browser profiles. Verify:

1. Passkey-to-Passkey and Email-OTP-to-Email-OTP linking;
2. immediate NEAR and EVM-family signing for present signer families;
3. immediate Ed25519 and ECDSA export with one fresh target-factor step-up per
   export;
4. inventory after link-session deletion;
5. independent lock, reload, and unlock on both devices;
6. retry after interruption between server commit, local install, and
   activation without duplicate material;
7. revoking Device 2's exact auth method from a different active method blocks
   Device 2 unlock and operations, retires its zero-method authority, and
   leaves Device 1 active;
8. revocation of the wallet's final active method is refused without changing
   any method, authority, session, or signer state;
9. two competing revocations against the final two active methods serialize so
   exactly one succeeds and one active method remains;
10. authority-ID and batch revocation requests are rejected at the boundary;
11. re-linking the same physical Device 2 creates a fresh installation identity
   and independently revocable auth method without mutating the earlier one;
12. R109A multi-method wallets and all four R109B factor combinations after
   those refactors land.

Mocks cannot satisfy this gate. The test must use real composed routes, stores,
workers, signer activation, Wallet Session issuance, and ordinary operations.

The canonical operating-path spec is
`tests/e2e/linked-device.operating-path.test.ts` with
`tests/playwright.linked-device.config.ts`. It may stub external chain RPC,
faucet, delivery, and Google token acquisition at their network boundaries.
It may not stub a device-linking route, session event, state transition,
package, receipt, authority record, signer worker, Wallet Session, inventory
response, or ordinary signing/export result.

Run the focused spec against already-running local services:

```bash
SEAMS_LINKED_DEVICE_E2E=1 pnpm -C tests exec playwright test \
  e2e/linked-device.operating-path.test.ts \
  -c playwright.linked-device.config.ts --reporter=line
```

The focused command must not invoke `build:sdk-full`, start another service
stack, or silently substitute stale artifacts. A separate prerequisite check
may fail fast with the exact missing service or artifact.

### Required R103E behavior matrix

Run both current auth combinations against every signer configuration:

| Source factor | Target factor | Ed25519 only | ECDSA only | Both |
| --- | --- | --- | --- | --- |
| Passkey | Passkey | required | required | required |
| Email OTP | Email OTP | required | required | required |

For each cell, assert only the operations supported by its signer families.
Every cell must assert link completion, immediate signing, inventory,
independent lock/reload/unlock, and revocation. When a family is present and
`export_keys` is granted, assert immediate ordinary export with a fresh step-up.
When a family is absent, assert its UI/action is unavailable and no empty
signer menu is rendered. Snapshot Device 1's authority, auth method, activation
refs, revocation epoch, and local record digests before linking and assert they
are unchanged after Device 2 activates and after Device 2's method is revoked
and its zero-method authority retires.

R109B later adds Passkey-to-Email-OTP and Email-OTP-to-Passkey rows. R109A later
adds multiple auth methods referencing one authority. Those future rows do not
block R103E completion and must require no authority or activation redesign.

### Required interruption matrix

Use real stores and idempotent production endpoints to stop and resume after:

1. target-factor verification;
2. one worker reservation before D1 pending commit;
3. D1 pending commit before browser installation;
4. browser installation before server activation;
5. one worker activation before D1 activation;
6. D1 activation before Wallet Session response;
7. browser session persistence before temporary-link cleanup.

After every resume, assert exactly one non-revoked authority for Device 2, one
auth method, one activation per present family, one export root when required,
and one inventory row. Compare exact IDs and digests before and after retry.

### Focused verification by workstream

- Foundation: shared TypeScript typecheck fixtures only.
- A: D1 authority commit/activate/idempotency/inventory/revocation tests.
- B: IndexedDB transaction, lock-generation, reload, and exact unlock tests.
- C: Passkey and Email OTP convergence plus QR close/terminal guard release.
- D: exact authority selection, per-export step-up, and the real Playwright
  operating path.

Classify every failing legacy unit fixture before editing it. Delete fixtures
that encode owner bindings, linked Wallet Sessions, R102 promotion, or mocked
success. Do not add compatibility branches to make those fixtures pass.

## Constraints against overengineering

R103E follows these implementation rules:

1. Net device-linking lines of code decrease.
2. Net device-linking domain type count decreases.
3. Each durable fact has one authoritative record.
4. One writer creates an authority and one read chain resolves it.
5. A new type must prevent a demonstrated invalid state, represent a separately
   persisted resource, or cross a trust boundary.
6. A state is durable only when reload must resume from it.
7. No generic workflow, saga, projection, or plugin framework is introduced.
8. No agent-specific principal branch is added until an agent feature needs it.
9. The working real-browser path is completed before secondary guardrails.
10. Old paths are deleted in the same refactor series.

If the implementation leaves more than one answer to “what makes Device 2
active?”, the design has failed.

## Handoff execution checklist

Follow this order. Do not begin by patching the current failing export or
inventory symptom.

1. **Record the baseline.** List the current device-linking production files,
   exported domain types, D1 tables, and focused tests. Record source/type
   counts for the final deletion comparison.
2. **Land the foundation commit.** Add the authority/auth-method lifecycle,
   exact activation set, digests, `WalletAuthorityId`, parsers, builders, and
   type fixtures. Move no runtime behavior in this commit.
3. **Freeze the contract.** Workstreams A-D compile against that commit. Any
   discovered contract defect is returned to the lead as one small shared
   patch before parallel work resumes.
4. **Implement successful authority activation first.** A, B, and C connect
   the pending commit, one local transaction, activation CAS, final local
   transaction, and link cleanup. Demonstrate one real Passkey link and one
   real Email OTP link before expanding tests.
5. **Switch ordinary readers.** D changes signing, export, reload, unlock,
   inventory, and revocation to exact auth-method/authority/activation reads.
   Revocation accepts only an exact method target and counts wallet-wide active
   methods transactionally. Remove wallet-wide inference at the same time.
6. **Add interruption and failure handling.** Implement only the retry matrix
   specified above. Do not add new lifecycle branches for transport or UI
   convenience.
7. **Cut over registration.** New wallets create their founding authority and
   opaque auth method immediately. Run the chosen reset or one-time migration.
8. **Delete the old model.** Complete the concrete removal ledger, delete stale
   fixtures, and remove the compatibility parser after the supported data has
   cut over.
9. **Run focused verification.** Run workstream tests, then the real linked
   operating-path Playwright spec. Inspect durable IDs and row counts on one
   successful link and one interrupted retry.
10. **Reconcile docs and counts.** Mark R103C/R103D superseded where their
    projection/recovery language conflicts with R103E. Update R109A/R109B to
    consume the authority/auth-method seam. Confirm production source and
    exported type counts decreased from the baseline.

Checkpoint commits should separate: shared contract, server lifecycle,
browser persistence/unlock, orchestration, ordinary operations, test updates,
and legacy deletion. Do not mix a production fix with deletion of unrelated
tests.

When a test fails, classify it using the repository testing policy before
editing production code. The real operating-path failure is a production
regression. A fixture requiring owner bindings, linked Wallet Session IDs,
R102 promotion, recovery admission, or a mocked active transition is obsolete
and should be deleted or rebuilt through the new shared factory.

## Completion criteria

R103E is complete when:

- the architecture contains only the five operating concepts listed above;
- Device 2 activation is one linear, resumable sequence;
- `WalletAuthority` is the single source for permissions, activation
  references, status, and internal retirement;
- users revoke one exact auth method at a time and can never revoke the
  wallet's final active method;
- all ordinary operations follow exact branded references;
- Passkey and Email OTP converge immediately after factor verification;
- key export has no linked-device-specific execution or repair path;
- reload and unlock have no link-session dependency;
- explicit lock survives page refresh and stale async work;
- obsolete repair, projection, duplicate-type, and mocked-success paths are
  deleted;
- the code and type count decrease;
- the real two-browser verification gate passes.
