# Ed25519 Yao Ideal Joint Refresh Delta v1

Status: **normative construction-independent Phase 1 functionality**.

This document freezes the ideal randomness distribution that supplies the
opposite-signed refresh update. It defines the value relation before Phase 6A
selects a P0-P3 mechanism. It does not define a commitment protocol, proof,
entropy source, transport, or corruption claim.

## Domains

Deriver A contributes `(r_y_A, r_tau_A)` and Deriver B contributes
`(r_y_B, r_tau_B)`.

- `r_y_A` and `r_y_B` are 32-byte little-endian elements of `Z_(2^256)`.
- `r_tau_A` and `r_tau_B` are canonical 32-byte little-endian elements of the
  Ed25519 scalar field `Z_l`.
- A role-local contribution may be zero.

The ideal joint result is:

```text
delta_y   = r_y_A   + r_y_B   mod 2^256
delta_tau = r_tau_A + r_tau_B mod l
```

Both joint fields must be nonzero. The ideal distribution samples the two
role-local contributions independently and conditions acceptance on both joint
fields being nonzero. A production realization must resample or emit only the
reviewed uniform public abort before any accepted delta or input-dependent
information is released.

In the ideal functionality, the Client and Router contribute no delta
randomness. The host reference exposes no constructor for the combined value.
`HostOnlyRefreshReferenceInputsV1` accepts only one move-owned
`HostOnlyJointRefreshDeltaCoinsV1`, which contains the distinct A and B
contribution types. Refresh preparation derives and validates the combined
value internally.

The public host-only fixture constructors accept synthetic bytes for both role
types. They enforce domain shape and move ownership; they do not authenticate
which actor supplied a fixture, establish independent sampling, or prevent one
test caller from constructing both contributions. Phase 6B must enforce those
origin and independence properties at separate A/B deployment boundaries.

## Refresh relation

The accepted joint delta changes only the server/account contribution fields:

```text
y_server_A'   = y_server_A   + delta_y   mod 2^256
tau_server_A' = tau_server_A + delta_tau mod l
y_server_B'   = y_server_B   - delta_y   mod 2^256
tau_server_B' = tau_server_B - delta_tau mod l
```

All client contribution fields remain byte-identical. Joined `y`, joined
`tau`, the RFC 8032 derivation, scalar bases, points, and registered public key
remain equal. The current host refresh reference checks every one of these
relations before output sharing.

## Canonical public synthetic fixture

The lifecycle-continuity corpus records the following explicit host-only test
values:

| Field | Deriver A | Deriver B | Joint result |
| --- | --- | --- | --- |
| `delta_y` | `3c` repeated 32 bytes | `69` repeated 32 bytes | `a5` repeated 32 bytes |
| `delta_tau` | canonical scalar `5` | canonical scalar `12` | canonical scalar `17` |

The corpus field order is `deriver_a`, `deriver_b`,
`combined_delta_y_hex`, `combined_delta_tau_hex`. Each role object orders
`delta_y_hex` before `delta_tau_hex`. The stdlib-Python verifier independently
decodes canonical scalars, recomputes both modular sums, rejects zero or
noncanonical results, and then checks the opposite-signed refresh relation.

These values are public synthetic verifier evidence. They are not production
coins, roots, contributions, or protocol messages.

## Rust boundary

The host-only role contribution and pair types are move-owned and
nonserializable. Scalar canonicality is checked separately for A and B. Six
focused Rust tests cover:

1. exact two-role summation;
2. validity of a zero local contribution when the joint result is nonzero;
3. wrapping seed-domain addition;
4. cancellation to zero in the seed domain;
5. cancellation to zero in the scalar domain; and
6. precise A/B noncanonical-scalar rejection.

The former direct combined-delta constructors and public application function
are deleted. Refresh callers cannot bypass the joint derivation boundary.

## Phase 6A/6B obligations

Phase 6A selects a coherent mechanism and exact claim. Phase 6B must bind the
selected mechanism to these role contributions and the accepted refresh
ceremony. P0 may rely on its explicit honest-execution assumption plus reviewed
signed/public records. Any P1-P3 claim requires the selected commitment,
input-consistency, anti-bias, correctness-with-abort, and selective-failure
properties.

Every selected profile must prevent the Client or Router from choosing the
delta, bind each role's accepted contribution to the exact old/next epochs and
package set, and make retry/crash handling incapable of grinding accepted
joint values. Those mechanisms and claims remain open.

## Security exclusions

This ideal relation does not prove contribution entropy, independence in a
deployed protocol, active correctness, anti-bias, erasure, forward security,
mobile-adversary healing, or distributed cutover. It freezes the functionality
that a selected construction must realize.
