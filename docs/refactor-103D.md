# Refactor 103D — Additive Delegated Signer Activation

Date created: August 20, 2026

Last reconciled: August 21, 2026 (additive delegated activation implemented)

Status: complete. This document is the canonical activation model for linked
devices and future delegated signer holders. The real two-device Passkey and
Email OTP contract covers activation, signing, fresh-step-up export, inventory,
and revocation; manual two-device verification confirmed the operating path.

Implemented production boundaries include canonical permission parsing,
parent-to-child permission attenuation, exact complete-manifest planning,
additive per-family activation, factor-sealed Ed25519 export-root delivery,
ordinary Device 2 signing and export consumption, durable device inventory,
and local activation before Wallet Session persistence and receipt
acknowledgement. Recovery, rotation, promotion, export hydration, and
wallet-wide selection are absent from the linking path.

## Decision

Device linking adds a delegated authority and the minimum material required by
its permissions to Device 2. Device 1 keeps its existing client shares, server
shares, activations, Wallet Session, unlock state, signing behavior, and export
behavior.

Authority is a reusable canonical permission set rather than a linked-device
role:

```ts
export type DelegatedWalletPermissionV1 =
  | 'sign'
  | 'export_keys'
  | 'link_devices'
  | 'revoke_devices';

export type DelegatedWalletAuthorityV1 = {
  readonly kind: 'delegated_wallet_authority_v1';
  readonly permissions: CanonicalDelegatedWalletPermissionSetV1;
};
```

Every non-empty combination is valid. Server admission checks the individual
permission required by the requested operation.

`full_owner` and `signing_only` are product presets:

```ts
export const FULL_OWNER_PERMISSIONS = [
  'sign',
  'export_keys',
  'link_devices',
  'revoke_devices',
] as const;

export const SIGNING_ONLY_PERMISSIONS = ['sign'] as const;
```

The presets are UI and builder inputs. They are never persisted lifecycle or
authority branches. A customer may select any other canonical combination.

This authority type is suitable for linked human devices and future
agent-delegated wallets. Transport, target-factor, enrollment, and device
metadata stay in their respective boundary types.

Delegation is attenuating. An authority with `link_devices` may grant only a
subset of its own canonical permission set. It cannot manufacture
`export_keys`, revocation, or signing authority that it does not possess.

## Default signer-family selection

The source Device 1 authorization resolves its canonical active signer-family
set. The current linking product includes that complete set:

```text
Device 1 Ed25519 only       -> activate Ed25519 on Device 2
Device 1 ECDSA only         -> activate ECDSA on Device 2
Device 1 Ed25519 and ECDSA  -> activate both on Device 2
```

The approved enrollment manifest must exactly equal the canonical active
signer-family set on Device 1. A missing family, added family, duplicate family,
or public-key disagreement is rejected at the authorization boundary.

Selective family delegation is outside R103D. A future design may add it as an
explicit policy with its own authority and UI. The current request shape does
not accept an arbitrary subset.

## Goal

Every approval binds the complete signer-family manifest active on Device 1.
Linking provisions the material needed by the selected permissions for every
applicable family. New share pairs are independent and reproduce the existing
wallet public key or address.

NEAR/Ed25519 and EVM-family/ECDSA remain independently administered. The
activation coordinator treats each present family as one possible
permission-derived child and creates no records for absent families.

`linked` is provenance for device inventory, audit, and revocation. Ordinary
capability identity, signing, export, and lifecycle types remain shared with
other wallet holders.

## Secret-material model

### Signing material

Each family requiring fresh Device 2 threshold material runs its ordinary
distributed registration protocol:

```text
Device 2 factor-bound recipient
  + existing wallet public identity
  + source-owner authorization
  -> distributed registration
  -> fresh Device 2 client share
  -> corresponding fresh Signing Worker server share
  -> unchanged wallet public key or address
```

Device 1's signing shares are never copied, replaced, recovered, or rotated.

### Ed25519 export authority

The Ed25519 wallet custody seed derives the Ed25519 Yao Client export root. The
root is a client-side secret. It is distinct from the custody seed, Ed25519
private key, and ordinary signing client share.

When `export_keys` is granted and Ed25519 is present:

```text
Device 2 one-use QR recipient public key
  <- Device 1 encrypts its Ed25519 Yao Client export root
  -> Device 2 decrypts inside its crypto worker
  -> Device 2 reseals the root under its verified Passkey or Email OTP factor
```

The wallet custody seed never crosses the linking channel. Device 2 receives no
complete private scalar. The relay and application JavaScript see only the
encrypted export-root package and authenticated public binding facts.

When `export_keys` is absent, the export-root package is forbidden by the
activation-plan builder, boundary parser, and persistence writer.

For an ECDSA-only wallet, no Ed25519 export-root package exists. ECDSA export
uses its existing ordinary threshold material and authorization flow.

## Required domain model

The wire boundary accepts a non-empty permission array. Its parser rejects
unknown values and duplicates, sorts the values canonically, and returns an
opaque `CanonicalDelegatedWalletPermissionSetV1`. Core code cannot directly
construct that branded set.

The activation-plan builder combines the canonical permission set with the
complete Device 1 signer manifest. It produces explicit material requirements:

```ts
type SigningActivationRequirementV1 =
  | {
      readonly kind: 'required';
      readonly activations: ExactAdministeredSignerActivationSetV1;
    }
  | {
      readonly kind: 'not_granted';
      readonly activations?: never;
    };

type Ed25519ExportRootRequirementV1 =
  | {
      readonly kind: 'required';
      readonly package: FactorBoundEd25519ExportRootPackageV1;
    }
  | {
      readonly kind: 'not_granted' | 'family_absent';
      readonly package?: never;
    };

type DelegatedDeviceActivationPlanV1 = OpaqueValidatedPlan<{
  readonly authority: DelegatedWalletAuthorityV1;
  readonly sourceSignerManifest: ExactAdministeredSignerManifestV1;
  readonly signing: SigningActivationRequirementV1;
  readonly ed25519Export: Ed25519ExportRootRequirementV1;
  readonly ecdsaExport: EcdsaExportMaterialRequirementV1;
}>;
```

`ExactAdministeredSignerActivationSetV1` is an exhaustive union for Ed25519
only, ECDSA only, or both. It cannot contain an empty set or duplicate family.
The plan builder compares it with the canonical Device 1 manifest and derives
requirements as follows:

- `sign` requires fresh ordinary Device 2 signing activation for every source
  signer family;
- `export_keys` requires the Ed25519 export root when Ed25519 exists and the
  existing ordinary ECDSA export material when ECDSA exists;
- `link_devices` and `revoke_devices` add admission authority and require no
  signing or export secret by themselves;
- ECDSA material shared by its ordinary signing and export protocols is
  installed once, while admission continues to enforce the exact permission.

The validated plan is opaque outside its builder. This keeps arbitrary
permission combinations flexible while preventing callers from pairing a
permission set with contradictory material requirements.

The production names may reuse existing package types where their bindings are
already exact. New wrappers are justified only when no existing type carries
the required enrollment, device, factor, authority, recipient, and digest
bindings.

## Linear activation

Raw request, transport, worker, and persistence records are parsed before core
activation. Each step is idempotent for the exact enrollment and activation
identities.

```ts
await installSigningRequirement(plan.signing);
await installEd25519ExportRequirement(plan.ed25519Export);
await installEcdsaExportRequirement(plan.ecdsaExport);

await persistWalletSession(plan);
await acknowledgeAggregateActivation(plan);
return { state: 'active' };
```

The actual implementation uses standalone functions and exhaustive switches.
`active` is emitted only after:

1. the target Passkey or Email OTP factor is verified;
2. the activation set exactly matches every signer family active on Device 1;
3. every signing package required by `sign` is installed and factor-bound;
4. every corresponding server share is durably committed;
5. every export package required by `export_keys` is factor-bound and installed;
6. ordinary capability records and linked provenance are persisted;
7. the Device 2 Wallet Session contains the exact capability subjects;
8. the aggregate activation receipt is acknowledged.

Interrupted post-commit work remains `committed_awaiting_activation` and resumes
the same activation identities. Retry cannot create another signer, select a
sibling device, or acknowledge an incomplete permission-derived plan.

## Ordinary signing and export

### Signing

An authority containing `sign` uses the ordinary signing flows. Device 2 signs
with its fresh client share and corresponding fresh server share. The exact
device scope, enrollment, factor, material activation, signer family, public
identity, revocation epoch, and `sign` permission are checked before execution.
Authorities without `sign` are rejected at admission even when another granted
operation uses overlapping ECDSA material.

### Ed25519 export

An authority containing `export_keys` performs the existing ordinary Yao
export:

1. authorize export with the active Device 2 Wallet Session;
2. verify local presence with Device 2's Passkey or Email OTP factor;
3. open the factor-sealed Ed25519 Yao Client export root inside the crypto
   worker;
4. derive the existing Client contributions;
5. run the standard protocol with Deriver A and Deriver B;
6. reconstruct and verify the wallet custody seed inside WASM;
7. return the seed only as the explicit key-export result.

The ordinary export request, admission, execution, result, and UI types are
reused. Link provenance does not create a parallel export domain.

An authority without `export_keys` is rejected at server admission before local
export material is requested. This rule also applies to future agent-delegated
wallets.

### ECDSA export

ECDSA export continues through the existing ordinary threshold export flow for
the exact active Device 2 capability. Its fresh registration material is
independently administered and does not depend on Ed25519 presence or an
Ed25519 export root.

## Excluded operations

Device linking does not call wallet recovery, signer recovery, rotation,
rejoin, or export-time hydration. These operations retain their own explicit
authorization and lifecycle.

R102 holder lanes are excluded from owner-equivalent activation. A holder lane
supports its defined signing role and cannot substitute for an ordinary signer
capability or Ed25519 export root.

Missing material after `active` is an integrity failure. The operation returns
an exact error and does not scan wallet-wide candidates or manufacture the
missing package.

## Non-negotiable invariants

1. Device 1 remains byte-for-byte unchanged across successful Device 2
   activation, apart from link-management and audit records.
2. The approval binds the complete canonical signer-family manifest active on
   Device 1. Permission-derived material covers all applicable families in that
   manifest.
3. Every Device 2 signer activation uses fresh client and server shares and
   preserves the corresponding public key or address.
4. `full_owner` and `signing_only` are presets for canonical permission sets,
   never persisted authority branches.
5. `export_keys` with Ed25519 present requires one factor-bound Ed25519 Yao
   Client export-root package.
6. An authority without `export_keys` cannot carry an export-root package or
   pass export admission.
7. The custody seed never crosses the linking channel.
8. No complete private scalar appears in linked transport or application
   JavaScript.
9. NEAR/Ed25519 and EVM-family/ECDSA remain independently optional and
   independently administered.
10. The target-factor interaction used during linking supplies local activation
    without a duplicate prompt.
11. `active` means every permission-derived package and Wallet Session subject
    is installed and durably committed.
12. Revoking Device 2 invalidates Device 2's capabilities and leaves Device 1
    operational.
13. Recovery, rotation, rejoin, R102 promotion, wallet-wide fallback, and
    export-time hydration cannot enter linking or export selection.
14. A delegating authority grants only a subset of its own permissions.
15. Every protected operation checks its exact permission at server admission;
    possession of overlapping cryptographic material grants no additional
    operation.

## Implementation phases

### Phase 1 — Establish the authority and activation types

- Add `DelegatedWalletPermissionV1`, the canonical permission-set parser, and
  `DelegatedWalletAuthorityV1` to the shared authorization domain.
- Retain `full_owner` and `signing_only` only as named preset builders.
- Add the opaque permission-derived activation plan using existing exact
  signing and sealed-package types where possible.
- Add boundary parsers and type fixtures for forbidden package mixtures,
  missing roots, empty permission sets, duplicate permissions, unknown
  permissions, empty family sets, duplicate families, and broad-spread escape
  hatches.
- Derive the default family set from Device 1's canonical active manifest and
  require exact equality at approval.
- Enforce permission attenuation when an existing delegated authority links
  another holder.

Exit criterion: invalid authority/package/family combinations fail at the type
or boundary-parser layer.

### Phase 2 — Provision permission-derived material additively

- For `sign`, run ordinary distributed registration once for every canonical
  signer family active on Device 1.
- For `export_keys`, prepare every family-specific export requirement from the
  same complete manifest.
- Deliver fresh factor-bound Device 2 client shares and commit matching fresh
  server shares wherever the granted operations require them.
- Verify public-key or address continuity before persistence.
- Persist ordinary capabilities with exact enrollment/device provenance.
- Leave Device 1 signer material and server shares untouched.

Exit criterion: Device 2 has exactly the material required by its permissions
for all applicable families active on Device 1.

### Phase 3 — Deliver permissioned Ed25519 export authority

- Reuse the one-use QR recipient key to encrypt Device 1's Ed25519 Yao Client
  export root for Device 2.
- Bind the ciphertext to wallet, public-key manifest, source authority, target
  device, enrollment, recipient, target factor, and revocation epoch.
- Decrypt inside the Device 2 crypto worker and reseal under its verified
  factor.
- Persist only the sealed package and exact public locator.
- Reject an `export_keys` Ed25519 activation whose root package is absent or
  conflicts with existing material, and reject a root package when that
  permission is absent.

Exit criterion: Device 2 can run ordinary Ed25519 export immediately after
activation without receiving the custody seed during linking.

### Phase 4 — Make committed activation terminal and idempotent

- Reconcile activation children by exact family and material identity.
- Install only missing approved children during retry.
- Persist the target credential, permission-derived capability records, sealed
  export root when required, local projections, and Wallet Session before
  `active`.
- Acknowledge the aggregate receipt after all postconditions pass.
- Return an exact terminal integrity error for unavailable recipient state or
  conflicting committed packages.

Exit criterion: every observed `active` device can immediately perform every
operation in its canonical permission set, is rejected from all other protected
operations, can unlock, and appears in device inventory where authorized.

### Phase 5 — Delete superseded paths and coverage

- Delete linked-device recovery, rotation, rejoin, R102 owner promotion,
  export hydration, and wallet-wide fallback paths.
- Delete linked-specific export request, selector, projection, and execution
  types.
- Delete tests and fixtures that expect share replacement, custody-seed
  transport, or post-activation material repair.
- Preserve intended-behavior contracts, cryptographic vectors, exact-scope
  tests, retry idempotency, Device 1 immutability, and revocation coverage.

Exit criterion: one additive activation path and the ordinary operation flows
serve linked and future delegated authorities.

## Verification matrix

Run Passkey and Email OTP target-factor flows against fresh wallets with
Ed25519-only, ECDSA-only, and dual-family Device 1 manifests. For each:

1. Link Device 2 with the `signing_only` and `full_owner` presets, then cover
   each individual permission and representative custom combinations.
2. Confirm every approval binds exactly the complete Device 1 signer-family
   manifest.
3. Confirm the installed material exactly matches the granted operations, uses
   fresh client/server shares where required, and preserves public identities.
4. Confirm `sign` permits ordinary signing through every present family and its
   absence rejects signing.
5. Confirm `export_keys` permits ordinary Ed25519 and ECDSA export with one
   target-factor interaction each and its absence rejects export.
6. Confirm `link_devices` permits only attenuated child grants and its absence
   rejects linking.
7. Confirm `revoke_devices` permits revocation and its absence rejects it.
8. Confirm Device 1 unlock, signing, export, shares, and activation facts remain
   unchanged.
9. List devices from holders with `link_devices` or `revoke_devices`, revoke
   Device 2, and confirm Device 1 remains active.
10. Lock and unlock both devices independently.
11. Interrupt every activation step and confirm retry resumes the same
    identities without duplicate packages.
12. Assert recovery, rotation, rejoin, R102 promotion, fallback, custody-seed
    transport, and export hydration are absent from the linking trace.

## Completion criteria

R103D is complete when:

- delegated authority is an explicit reusable canonical permission set;
- every approval defaults to the complete canonical signer manifest on Device 1;
- Device 2 receives exactly the material required by its granted permissions;
- `full_owner` enables every permission and `signing_only` enables only `sign`;
- arbitrary non-empty customer-selected permission combinations are supported;
- permission attenuation prevents delegated privilege escalation;
- Device 1 remains operational and unchanged;
- ordinary signing and export flows serve Device 2;
- authority admission blocks unsupported owner operations;
- activation is terminal, idempotent, and exact;
- the superseded recovery, rotation, R102 promotion, fallback, hydration, and
  linked-specific export paths are deleted.
