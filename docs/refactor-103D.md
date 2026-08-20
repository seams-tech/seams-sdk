# Refactor 103D — Additive Delegated Signer Activation

Date created: August 20, 2026

Last reconciled: August 20, 2026 (delegated authority and export-root model)

Status: planned. This document is the canonical activation model for linked
devices and future delegated signer holders.

## Decision

Device linking adds independent signer capabilities for Device 2. Device 1
keeps its existing client shares, server shares, activations, Wallet Session,
unlock state, signing behavior, and export behavior.

Authority is a reusable wallet policy rather than a linked-device-specific
permission:

```ts
export type DelegatedWalletAuthorityV1 =
  | { readonly kind: 'signing_only' }
  | { readonly kind: 'full_owner' };
```

`signing_only` installs ordinary signing material and authorizes signing.
`full_owner` installs the same signing material and, whenever Ed25519 is
present, an additional factor-bound Ed25519 Yao Client export-root package.
The server admits owner operations, including export and device management,
only for `full_owner`.

This authority type is suitable for linked human devices and future
agent-delegated wallets. Transport, target-factor, enrollment, and device
metadata stay in their respective boundary types.

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

For every signer family active on Device 1, linking provisions one independent
ordinary signer capability on Device 2 with fresh client and server shares.
Each new share pair reproduces the existing wallet public key or address.

NEAR/Ed25519 and EVM-family/ECDSA remain independently administered. The
activation coordinator treats each present family as one required child and
creates no records for absent families.

`linked` is provenance for device inventory, audit, and revocation. Ordinary
capability identity, signing, export, and lifecycle types remain shared with
other wallet holders.

## Secret-material model

### Signing material

Each present family runs its ordinary distributed registration protocol:

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

For `full_owner` with Ed25519 present:

```text
Device 2 one-use QR recipient public key
  <- Device 1 encrypts its Ed25519 Yao Client export root
  -> Device 2 decrypts inside its crypto worker
  -> Device 2 reseals the root under its verified Passkey or Email OTP factor
```

The wallet custody seed never crosses the linking channel. Device 2 receives no
complete private scalar. The relay and application JavaScript see only the
encrypted export-root package and authenticated public binding facts.

For `signing_only`, the export-root package is forbidden by the domain type,
boundary parser, and persistence writer.

For an ECDSA-only wallet, no Ed25519 export-root package exists. ECDSA export
uses its existing ordinary threshold material and authorization flow.

## Required domain model

Authority policy and activation delivery remain separate. The delivery union
makes authority-specific package requirements unrepresentable as invalid
states:

```ts
type LinkedDeviceActivationDeliveryV1 =
  | {
      readonly kind: 'signing_only';
      readonly signerActivations: ExactAdministeredSignerActivationSetV1;
      readonly ed25519ExportRoot?: never;
    }
  | {
      readonly kind: 'full_owner';
      readonly signerActivations: ExactAdministeredSignerActivationSetV1;
      readonly ed25519ExportRoot: Ed25519ExportRootRequirementV1;
    };

type Ed25519ExportRootRequirementV1 =
  | {
      readonly kind: 'ed25519_present';
      readonly package: FactorBoundEd25519ExportRootPackageV1;
    }
  | {
      readonly kind: 'ed25519_absent';
      readonly package?: never;
    };
```

`ExactAdministeredSignerActivationSetV1` is an exhaustive union for Ed25519
only, ECDSA only, or both. It cannot contain an empty set or duplicate family.
Branch-specific builders compare it with the canonical Device 1 manifest.

The production names may reuse existing package types where their bindings are
already exact. New wrappers are justified only when no existing type carries
the required enrollment, device, factor, authority, recipient, and digest
bindings.

## Linear activation

Raw request, transport, worker, and persistence records are parsed before core
activation. Each step is idempotent for the exact enrollment and activation
identities.

```ts
await installDelegatedSignerActivations(delivery.signerActivations);

switch (delivery.kind) {
  case 'signing_only':
    break;
  case 'full_owner':
    await installEd25519ExportRootRequirement(
      delivery.ed25519ExportRoot,
    );
    break;
  default:
    assertNever(delivery);
}

await persistWalletSession(delivery);
await acknowledgeAggregateActivation(delivery);
return { state: 'active' };
```

The actual implementation uses standalone functions and exhaustive switches.
`active` is emitted only after:

1. the target Passkey or Email OTP factor is verified;
2. the activation set exactly matches every signer family active on Device 1;
3. every fresh Device 2 client share is installed and factor-bound;
4. every corresponding server share is durably committed;
5. a `full_owner` Ed25519 activation has installed its factor-bound export root;
6. ordinary capability records and linked provenance are persisted;
7. the Device 2 Wallet Session contains the exact capability subjects;
8. the aggregate activation receipt is acknowledged.

Interrupted post-commit work remains `committed_awaiting_activation` and resumes
the same activation identities. Retry cannot create another signer, select a
sibling device, or acknowledge an incomplete authority branch.

## Ordinary signing and export

### Signing

Both authority branches use the same ordinary signing flows. Device 2 signs
with its fresh client share and corresponding fresh server share. The exact
device scope, enrollment, factor, material activation, signer family, public
identity, and revocation epoch are checked before execution.

### Ed25519 export

A `full_owner` Device 2 performs the existing ordinary Yao export:

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

A `signing_only` authority is rejected at server admission before local export
material is requested. This rule also applies to future agent-delegated
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
2. Device 2 receives exactly one ordinary signer activation for every canonical
   signer family active on Device 1.
3. Every Device 2 signer uses fresh client and server shares and preserves the
   corresponding public key or address.
4. `signing_only` and `full_owner` use the same signing activation path.
5. `full_owner` with Ed25519 present additionally requires one factor-bound
   Ed25519 Yao Client export-root package.
6. `signing_only` cannot carry an export-root package and cannot pass export or
   owner-administration admission.
7. The custody seed never crosses the linking channel.
8. No complete private scalar appears in linked transport or application
   JavaScript.
9. NEAR/Ed25519 and EVM-family/ECDSA remain independently optional and
   independently administered.
10. The target-factor interaction used during linking supplies local activation
    without a duplicate prompt.
11. `active` means every authority-specific package and Wallet Session subject
    is installed and durably committed.
12. Revoking Device 2 invalidates Device 2's capabilities and leaves Device 1
    operational.
13. Recovery, rotation, rejoin, R102 promotion, wallet-wide fallback, and
    export-time hydration cannot enter linking or export selection.

## Implementation phases

### Phase 1 — Establish the authority and activation types

- Add `DelegatedWalletAuthorityV1` to the shared authorization domain.
- Replace the single linked signing permission with the authority union.
- Add the authority-discriminated activation delivery using existing exact
  signing and sealed-package types where possible.
- Add boundary parsers and type fixtures for forbidden package mixtures,
  missing roots, empty family sets, duplicate families, and broad-spread escape
  hatches.
- Derive the default family set from Device 1's canonical active manifest and
  require exact equality at approval.

Exit criterion: invalid authority/package/family combinations fail at the type
or boundary-parser layer.

### Phase 2 — Provision fresh signing material additively

- Run ordinary distributed registration once for every canonical signer family
  active on Device 1.
- Deliver fresh factor-bound Device 2 client shares and commit matching fresh
  server shares.
- Verify public-key or address continuity before persistence.
- Persist ordinary capabilities with exact enrollment/device provenance.
- Leave Device 1 signer material and server shares untouched.

Exit criterion: Device 2 signs with independent material for all and only the
families active on Device 1.

### Phase 3 — Deliver full-owner Ed25519 export authority

- Reuse the one-use QR recipient key to encrypt Device 1's Ed25519 Yao Client
  export root for Device 2.
- Bind the ciphertext to wallet, public-key manifest, source authority, target
  device, enrollment, recipient, target factor, and revocation epoch.
- Decrypt inside the Device 2 crypto worker and reseal under its verified
  factor.
- Persist only the sealed package and exact public locator.
- Reject a `full_owner` Ed25519 activation whose root package is absent or
  conflicts with existing material.

Exit criterion: Device 2 can run ordinary Ed25519 export immediately after
activation without receiving the custody seed during linking.

### Phase 4 — Make committed activation terminal and idempotent

- Reconcile activation children by exact family and material identity.
- Install only missing approved children during retry.
- Persist the target credential, ordinary capability records, sealed export
  root when required, local projections, and Wallet Session before `active`.
- Acknowledge the aggregate receipt after all postconditions pass.
- Return an exact terminal integrity error for unavailable recipient state or
  conflicting committed packages.

Exit criterion: every observed `active` device can immediately sign, perform
the operations allowed by its authority, unlock, and appear in device inventory.

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

1. Link Device 2 as `signing_only` and `full_owner` where the UI exposes both.
2. Confirm Device 2 receives exactly the complete Device 1 signer-family set.
3. Confirm fresh client/server shares and unchanged public identities.
4. Sign through every present family on Device 2.
5. Confirm `signing_only` export and owner administration are rejected.
6. Confirm `full_owner` Ed25519 and ECDSA export use ordinary flows with one
   target-factor interaction each.
7. Confirm Device 1 unlock, signing, export, shares, and activation facts remain
   unchanged.
8. List devices from both full-owner devices, revoke Device 2, and confirm
   Device 1 remains active.
9. Lock and unlock both devices independently.
10. Interrupt every activation step and confirm retry resumes the same
    identities without duplicate packages.
11. Assert recovery, rotation, rejoin, R102 promotion, fallback, custody-seed
    transport, and export hydration are absent from the linking trace.

## Completion criteria

R103D is complete when:

- delegated authority is an explicit reusable union;
- linked activation defaults to all canonical signer families on Device 1;
- Device 2 has fresh independent signing material for every present family;
- `full_owner` is the signing activation plus the required Ed25519 export root;
- Device 1 remains operational and unchanged;
- ordinary signing and export flows serve Device 2;
- authority admission blocks unsupported owner operations;
- activation is terminal, idempotent, and exact;
- the superseded recovery, rotation, R102 promotion, fallback, hydration, and
  linked-specific export paths are deleted.
