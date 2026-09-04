# Refactor 123: Typed Boundaries and Explicit State Ownership

Created: September 3, 2026

Phase 3 specification reconciliation: September 3, 2026

Phase 2 and Phase 4 specification reconciliation: September 3, 2026

Specification recency and R120 source reconciliation: September 3, 2026

`alphabetizeStringify` behavior-preservation phase added: September 3, 2026

Domain-owned equality phase added: September 3, 2026

Status: proposed implementation plan. The first phase is a bounded Refactor 120
merge gate. The remaining phases begin from the merged Refactor 120 tip and land
as independent domain-sized changes.

## Outcome

Remove `isRecord`, its shallow-object aliases, and `structuredClone` from the
repository by replacing the underlying ambiguity with:

- exact, domain-named decoders at untrusted boundaries;
- branded identifiers and normalized value objects;
- discriminated unions for protocol, lifecycle, authorization, persistence,
  and worker state;
- `Result`-style unions for recoverable decoding and domain failures;
- exhaustive switches with `assertNever`;
- branch-specific builders for valid domain values;
- domain-owned comparators and verified, branded digests for equality; and
- explicit ownership for request-local mutable drafts and immutable branch
  values.

After a value crosses an HTTP, D1, IndexedDB, worker, RPC, or JSON boundary,
core code receives a precise domain type. Core functions never accept raw
objects, partial domain records, compatibility shapes, or caller-selected
lifecycle fields.

`structuredClone` disappears because ownership is represented by the design.
Adapters own encoded values, request drafts own their mutable containers,
lifecycle records are immutable, and persistence projections allocate only
their own top-level collections.

## Refactor 120 Baseline

The baseline was captured on September 3, 2026 from
`codex/refactor-120-phase0` at `72d473685a4badc0f8fbc2356153014196afb1e3`.
The live worktree contained uncommitted Refactor 120 work; those edits added or
removed none of the exact symbols counted here.

| Pattern           | References | Files | Important concentration                                                      |
| ----------------- | ---------: | ----: | ---------------------------------------------------------------------------- |
| `isRecord`        |        367 |    76 | registration stores, persistence codecs, IndexedDB, RPC, console APIs, tests |
| `structuredClone` |         41 |    17 | 15 production references and 26 test references                              |
| `isPlainObject`   |        255 |    51 | semantic equivalent of the common shallow `isRecord` predicate               |
| `isRecordValue`   |         36 |     7 | raw-record normalization                                                     |
| `toRecordValue`   |         82 |     8 | raw-record conversion and casting                                            |

Fourteen of the fifteen production `structuredClone` references are
concentrated in the Ed25519 Yao product-registration partition and state store.
The remaining production reference is in a benchmark-planning script.

The Refactor 120 branch diff introduces one new local `isRecord` definition and
one call in the wallet-console service-binding handler. It introduces no new
`structuredClone` call. A repository-wide cleanup is therefore broader than
the Refactor 120 feature itself.

The inventory must be refreshed at the start of implementation. The semantic
audit also searches for:

- `asRecord`, `requireRecord`, `isObject`, and equivalent helpers;
- manual `typeof value === "object"` predicates that return a broad record;
- `Record<string, unknown>` crossing a parser-module boundary;
- `as never` and `as SomeDomainType` casts;
- broad object spreads used to construct lifecycle or protocol state;
- optional identity, auth, session, signing, restore, or lifecycle fields;
- generic cloning hidden behind helper names or JSON round trips.

Exact-symbol deletion alone does not complete this refactor.

## Boundary Rule

Compile-time safety begins after untrusted input has supplied runtime evidence.
The following sources remain `unknown` until a domain decoder accepts them:

- `Request.json()` and `Response.json()`;
- D1, KV, Durable Object, and external store records;
- IndexedDB records from an existing browser database;
- `postMessage`, worker-port, iframe, and custom-event payloads;
- decoded tokens and third-party SDK responses;
- `JSON.parse()`;
- CLI configuration and environment-derived data.

Each boundary follows one path:

```text
unknown input
  -> exact domain decoder
       -> DecodeResult<DomainValue>
            -> domain operation accepting DomainValue
                 -> exact encoder at the next wire or persistence boundary
```

An exact decoder verifies the object category, required keys, forbidden keys,
field representations, discriminant, and branch-specific invariants together.
It normalizes identifiers and encodings once. A successful result contains the
final internal type.

Domain code never invokes a generic predicate that upgrades `unknown` to
`Record<string, unknown>`. Decoder implementations may inspect JavaScript
object shape as part of proving one exact domain value. The broad record does
not escape that function.

## Specification Authority

Refactor numbers record architectural history; they do not form a cumulative
set of requirements. Refactor 123 resolves conflicts in this order:

1. [Intended Behaviours](./intended-behaviours.md) and its owning contract
   tests for supported wallet lifecycle behavior;
2. Refactor 120 and the exact Refactor 103F snapshot that Refactor 120 names as
   its frozen integration baseline;
3. the merged Refactor 120 production source, current domain types, generated
   bindings, immutable migrations, and focused tests as evidence of the
   implemented shape under those contracts;
4. a still-current domain-specific landed plan only for the boundary it owns,
   such as Refactor 107 app-session deletion, Refactor 108 iframe geometry, or
   Refactor 100 client-custody secrecy; and
5. older refactor documents as historical rationale only.

Refactor 82B and Refactor 90 do not independently constrain this cleanup. A
type, helper, lifecycle, compatibility path, or source guard described there is
retained only when the current R120 source, a newer owning spec, or an
authoritative current test still requires it. When an older plan conflicts with
the higher-ranked current authority, the obsolete test or helper is deleted
rather than restored.

The September 3 R120 source audit confirms the current baseline:

- `factorEvidence.ts` already represents `VerifiedOwnerProof` with nominal
  server-only classes and private constructors;
- `walletExecutionAdmission.ts` already owns exact V2 admission and prepared
  execution unions;
- `walletSessionAuthorizationStore.ts` already distinguishes V6 `found`,
  `missing`, `upgrade_required`, `corrupt`, and `persistence_unavailable`
  outcomes;
- pending registration and recovery commits are current discriminated journal
  unions with dedicated parsers and builders; and
- the iframe contract already uses `WALLET_PROTOCOL_VERSION = '2.0.0'` with
  current CONNECT/READY validation.

Refactor 123 reuses those types and builders. It removes broad parsing and
cloning around them without recreating an older authority, session, lane, or
compatibility model.

## Decisions

1. Delete `isRecord` and every shallow alias whose contract is “non-null,
   non-array object.” Such predicates accept `Date`, `Map`, `Set`, typed arrays,
   and class instances and provide no domain evidence.
2. Reuse existing exact parsers, brands, result unions, factories, and naming
   patterns. This refactor adds no general-purpose schema framework.
3. Parse raw input once at the owning boundary. Repeated validation in core
   functions is removed when the boundary is proven.
4. Give identifiers with different meanings different types. Organization,
   project, environment, signing-root identity, session identity, capability
   identity, and lifecycle identity cannot be interchangeable strings.
5. Model mutually exclusive branches with discriminated unions. Optional bags
   and correlated booleans do not represent lifecycle or protocol state.
6. Use `never` fields where public object types must reject invalid branch
   combinations. Use branch-specific builders when direct construction would
   expose invariants.
7. Every switch over a domain union is exhaustive and terminates in
   `assertNever`.
8. Durable and wire formats have explicit raw types only inside their boundary
   modules. Internal domain types do not double as persistence DTOs.
9. Client and server changes to private protocols land atomically. No legacy
   response branch, dual decoder, fallback route, or compatibility alias is
   introduced.
10. Exact owned decoding, immutable branch values, and scalar commit baselines
    replace defensive graph cloning. Full deep-copy helpers do not replace
    `structuredClone`.
11. `ReadonlyMap` and readonly properties alone do not prove ownership. Record
    adapters carry encoded values, exact decoders allocate request-owned
    collections, and no mutable alias crosses the adapter/request boundary.
12. Mutable byte arrays receive an explicit ownership decision. Persisted state
    prefers an existing canonical encoded representation. Runtime byte buffers
    use copy-in/copy-out at ownership boundaries and remain scoped to the
    cryptographic operation that needs them.
13. Tests construct complex state through shared branch-specific factories.
    Inline record literals remain appropriate only for raw invalid-input cases
    and simple value objects.
14. No source-text guard is added during implementation. Type fixtures,
    behavioral tests, and the final inventory provide the initial enforcement.
    A lint restriction requires an observed reintroduction before adoption.
15. Domain equality is explicit. Small values use named field comparators,
    discriminated unions use exhaustive branch comparators, protocol identities
    use their existing versioned branded digest, and persisted values verify any
    stored digest while decoding. No generic serializer, deep-equality helper,
    or caller-selected digest defines equality for core domain values.

## Target Type Patterns

### Domain decoding

```ts
export type DecodeResult<T, E> = { ok: true; value: T } | { ok: false; error: E };

export type TenantRootProtocolDecodeError =
  | { kind: 'invalid_object' }
  | { kind: 'unexpected_field'; field: string }
  | { kind: 'missing_field'; field: TenantRootIdentityField }
  | { kind: 'invalid_field'; field: TenantRootIdentityField };
```

The concrete decoder returns the narrow error union required by its caller.
Generic diagnostic objects never influence domain control flow.

### Domain outcomes

```ts
export type TenantRootResolutionResult =
  | {
      kind: 'resolved';
      lineage: ResolvedTenantRootLineageV1;
    }
  | { kind: 'not_found' }
  | {
      kind: 'rejected';
      code: TenantRootResolutionErrorCode;
      message: string;
    };
```

Transport status remains transport metadata. The parsed discriminant owns
application behavior.

### State transitions

```ts
export type RegistrationTransitionResult =
  | { kind: 'advanced'; state: RegistrationState }
  | { kind: 'unchanged'; state: RegistrationState }
  | { kind: 'rejected'; error: RegistrationTransitionError };
```

Each transition accepts the narrow state branch in which it is valid. It
returns a complete new branch. A domain may install that branch into its owned
request draft or return a copy-on-write aggregate. No broad spread constructs a
lifecycle object.

### Domain equality

Equality follows the domain meaning rather than the JavaScript object graph:

```ts
function equalParticipantBindingV1(
  left: ParticipantBindingV1,
  right: ParticipantBindingV1,
): boolean {
  return (
    left.participantId === right.participantId &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion
  );
}
```

A digest-bearing value is trusted only after its owning boundary has parsed the
value, recomputed the domain-separated digest with the versioned encoder, and
rejected a mismatch:

```ts
type VerifiedRegistrationRequestV1 = {
  readonly request: RegistrationRequestV1;
  readonly digest: RegistrationRequestDigestV1;
};
```

Core code compares two `RegistrationRequestDigestV1` values directly. It does
not stringify either request again. The digest brand prevents comparison with
an unrelated protocol digest. Small transient values use a direct comparator;
they are not hashed solely to avoid writing the comparison.

## Implementation Sequence

The numbered phases in the original outline map to the detailed change sets in
this document as follows. The lettered sections are merge-sized slices, not a
second phase numbering scheme.

| Original phase | Detailed sections      | Scope                                                                     |
| -------------- | ---------------------- | ------------------------------------------------------------------------- |
| Phase 1        | R123-A                 | Refactor 120 merge gate                                                   |
| Phase 2        | R123-B, R123-C, R123-D | Tenant identity, stable JSON helper, server authorization and persistence |
| Phase 3        | R123-F                 | Ed25519 Yao state ownership and clone removal                             |
| Phase 4        | R123-E                 | Browser, RPC, worker, iframe, and UI boundaries                           |
| Phase 5        | R123-H                 | Domain-owned equality and verified digest comparisons                     |
| Phase 6        | R123-G                 | Remaining tests, scripts, and repository cleanup                          |

### R123-A: Refactor 120 merge gate

Keep this phase to five touched files. It closes the only exact `isRecord`
addition made by Refactor 120 and removes the unsafe response casts on the same
private service path.

Files:

- `packages/wallet-console-server-ts/src/serviceBinding/walletConsoleOps.ts`;
- `packages/wallet-console-server-ts/src/serviceBinding/walletConsoleOpsHandler.ts`;
- `packages/wallet-console-server-ts/src/serviceBinding/walletConsoleOpsClient.ts`;
- `tests/unit/walletConsoleServiceBinding.unit.test.ts`;
- `tests/typecheck/tenant-root-identity-resolution.typecheck.ts`.

Work:

1. Define the exact tenant-root resolution request and response unions in the
   existing service-binding contract module.
2. Define request and response decoders returning narrow `DecodeResult` unions.
3. Make handler body reading return `unknown`, then decode in the route before
   invoking domain logic.
4. Make the generic client transport return an `unknown` response body, then
   decode in the operation-specific client method.
5. Remove the local `isRecord`, `hasExactFields`, raw property access, and every
   `as never` on this path.
6. Cover accepted, missing-field, extra-field, wrong-discriminant, and
   wrong-field-type payloads in the existing unit test.
7. Extend the existing type fixture to reject direct invalid response branches
   and caller-selected tenant-root fields.

This phase changes producer and consumer together. It adds no compatibility
shape. It does not touch the Ed25519 Yao state files while the current Refactor
120 worktree is active in adjacent code.

### Phase 2 specification authority

R123-B through R123-D preserve the current contracts owned by:

- [Refactor 120](./refactor-120-rotate-tenant-secrets.md), for the five-field
  server-resolved `TenantRootIdentityV1`, its exact canonical bytes, the
  separation of stable root identity from custody lineage and epoch, and the
  frozen Refactor 103F B4/B5 composition order;
- [Refactor 103F](./refactor-103F-final-cutover.md), for exact V2 admission,
  authoritative material resolution, credential-free registration replay,
  immutable migration history, and one-time cutover deletion;
- [Refactor 107](./refactor-107-remove-app-session.md), only for its landed
  server-internal `VerifiedOwnerProof` seam and deletion of the wallet app
  session plane; Refactor 103F owns the final exact Wallet Session shape and
  persistence; and
- the current `walletExecutionAdmission.ts`, authorization domain, D1 stores,
  tenant-root composition modules, type fixtures, and intended-behaviour tests
  on the merged R120 branch.

Phase 2 tightens construction and parsing around those domains. It does not add
a new authorization lifecycle, root resolver, session abstraction, repository,
or generic codec layer. A shape decoder proves structure. It never proves
cryptographic verification, current authority, active material, authorization,
or one-use consumption. Refactor 82B terminology and Refactor 90 target shapes
are not used to redesign a current R103F type.

### R123-B: Canonical tenant-root identity

Create one TypeScript owner for `TenantRootIdentityV1`, aligned with the Rust
definition in `crates/router-ab-core/src/derivation/tenant_root.rs`.

Preferred location:

`packages/shared-ts/src/tenant-root/tenantRootIdentity.ts`

Work:

1. Reuse existing branded identifier types where their validation and meaning
   match.
2. Add only the missing organization, project, environment, signing-root ID,
   and signing-root-version brands that prevent real interchange errors.
3. Keep construction provenance explicit. The public/request layer has no
   parser that can turn five caller strings into a trusted root identity. A
   module-private constructor creates the nominal domain value only after the
   authenticated deployment resolver supplies all five already-normalized ID
   values. A separate exact decoder exists only for the named private wire or
   persistence boundary that genuinely stores this identity.
4. Encode the five fields in the frozen order `orgId`, `projectId`, `envId`,
   `signingRootId`, `signingRootVersion`. Reject empty or unknown fields and
   perform no trimming, case folding, or Unicode normalization. Canonical bytes
   remain the ASCII `seams/tenant-root-identity/v1` domain followed by each
   exact UTF-8 field as a four-byte big-endian length and bytes; canonical JSON
   is not a second identity encoding.
5. Preserve the serialized `signingRootId` and `signingRootVersion` names.
   Keep `TenantRootCustodyLineageId`, `TenantRootShareEpoch`, and durable ECDSA
   `RootShareEpoch` as distinct types outside the identity. No role or epoch
   selector enters `TenantRootIdentityV1`.
6. Delete the duplicate raw-string definitions from wallet-console-server and
   wallet-server.
7. Make derivation composition accept only the resolver-produced identity. For
   established material, preserve the exact order: complete R103F B4 admission,
   resolve the B4 `MpcMaterialActivationRef` through B5, resolve tenant-root
   identity and active custody epoch independently, compare the stable root ID
   and version, then construct the Router A/B request. Normal signing stops
   after B5 and never resolves tenant-root custody.
8. Verify that `WalletSessionAuthorizationV2`, operation credentials, V6
   browser records, `MpcMaterialActivationRef`, registration receipts, and
   device-link records gain no root identity, lineage, epoch, or role field.
9. Extend type fixtures to reject swapped identifiers, direct raw-string
   construction, missing fields, broad spreads, public caller construction,
   and invalid selector fields.
10. Reuse the existing Rust canonical encoding and cross-language vectors. A
    representation change requires regenerated vectors through their owning
    generator.

Acceptance:

- a public route body cannot select or override any tenant-root field;
- the private service boundary rejects missing, extra, empty, or
  non-canonical identity fields;
- custody lineage and either epoch type cannot be supplied where stable root
  identity is required;
- an established-material mismatch fails before a Router A/B request or other
  irreversible effect; and
- the Rust and TypeScript canonical bytes and digest remain byte-identical.

### R123-C: Behavior-preserving `alphabetizeStringify` cleanup

`alphabetizeStringify` is shared protocol infrastructure. Its supported
behavior is recursive lexicographic object-key ordering with array order and
ordinary `JSON.stringify` scalar encoding preserved. Refactor 123 removes its
local `isRecord` and nested normalizer without changing any supported output.

This phase is deliberately small. It does not inventory or semantically review
the 463 current invocations across 101 files, replace every JSON-based equality
check, introduce a new canonical-JSON standard, or migrate callers to a new
encoder API. The broader symbol count is 563 because imports and the definition
add another 100 references. R123-H separately migrates equality callers after
their domain types and boundaries are precise.

Targets:

- `packages/shared-ts/src/utils/digests.ts`;
- `tests/unit/alphabetizeStringify.unit.test.ts`.

#### R123-C1: Characterize the current contract

Land the tests against the existing implementation before changing it. Pin:

1. lexicographic ordering of top-level and nested object keys;
2. preservation of array element order and recursive ordering inside array
   elements;
3. exact `JSON.stringify` output for `null`, booleans, strings, escaping,
   finite numbers, empty arrays, and empty objects;
4. insertion-order independence for equivalent domain-shaped values;
5. non-mutation of the input graph; and
6. representative current protocol preimages whose bytes are already consumed
   by authorization, registration, recovery, or device-link digest code.

The compatibility contract covers JSON-shaped values used by current protocol
callers. Accidental behavior for `Date`, `Map`, `Set`, class instances,
functions, symbols, `bigint`, cyclic graphs, sparse arrays, `undefined`, or
non-finite numbers is not promoted into a new protocol guarantee by these
tests. This phase neither expands acceptance of those values nor deliberately
changes their behavior.

#### R123-C2: Refactor the implementation

1. Extract the recursive normalizer into one standalone module-private
   function, following the repository rule against functions declared inside
   functions.
2. Remove the reusable `isRecord` predicate. After the array branch, inspect
   the remaining non-null object inside the normalizer and keep that broad
   shape local; it never escapes as a domain value.
3. Preserve `Object.keys(...).sort()` ordering, recursive value normalization,
   array ordering, property enumeration, and the final `JSON.stringify` call
   exactly.
4. Keep the exported function name, input signature, return type, and every
   caller unchanged. Do not add a compatibility alias or a second serializer.
5. Add no domain labels, normalization, validation, rejection branch, digest
   wrapper, or equality abstraction in this phase.

Acceptance:

- the characterization test passes before and after the implementation change;
- representative protocol preimage and digest fixtures remain byte-identical;
- `packages/shared-ts/src/utils/digests.ts` contains no `isRecord` and no nested
  function;
- the shared package type-check and the focused authorization, registration,
  recovery, and device-link tests pass; and
- production callers outside the target file require no edit.

The direct `isRecord` uses in registration, established-session, recovery, and
device-link parsers migrate with their owning R123-D or R123-E boundary slice.

### R123-D: Wallet-server authorization and persistence boundaries

Migrate server domains in bounded slices. Each slice owns one raw source, its
decoder, its internal type, and its focused behavioral test.

Order:

1. authorization and capability admission;
2. registration ceremony and committed receipt persistence;
3. recovery and export persistence;
4. passkey-custody and identity D1 records;
5. normal-signing and relayer request boundaries;
6. remaining console and hosted-auth service routes.

For each slice:

1. Identify the exact untrusted source and the first function that currently
   receives a broad record.
2. Create or reuse one exact decoder at that location.
3. Separate structural parsing from authority-producing work. A route decoder
   may create `Parsed*` input. Only the passkey/OTP verifier creates
   `VerifiedOwnerProof`; only B4 creates admitted operation state; only B5
   creates authoritative active-material projections. Constructors for those
   proof-bearing types remain private to their owners.
4. Split persistence DTOs from internal domain state when their invariants
   differ. Give every persisted generation its own exact reader. A compatibility
   reader emits the current domain type directly and remains in the owning
   persistence module with a named deletion condition; no legacy branch enters
   core unions or writers.
5. Preserve migration authority. Applied D1 migration files stay immutable,
   writers emit only the current shape, and any representation change uses one
   forward migration with a preflight policy for known, corrupt, and unknown
   rows. Generated Rust/TypeScript bindings and fixtures are regenerated through
   their owners rather than hand-edited.
6. Preserve transaction ownership and effect order. Authorization, quota,
   operation claim, registration replay, recovery, and activation CAS behavior
   stays atomic. Exact identity/material checks and durable one-use claims occur
   before custody opens, MPC starts, or another irreversible effect runs.
7. Keep exact failures distinct. Missing/expired/exhausted/ended/safely
   superseded owner sessions may produce same-method step-up. Malformed tokens,
   identity or material mismatch, revoked state, replay, corruption, and
   persistence unavailability remain hard denials. Infrastructure failure never
   becomes a prompt or retry branch.
8. Replace optional identity, authorization, session, signing, and lifecycle
   fields with required branch fields. Replace correlated flags with a
   discriminated union and narrow every core function input to the valid branch
   it needs.
9. Keep token, session, operation, quota, material activation, threshold
   session, tenant-root, and custody identities separate. A public opaque token
   parser never returns the trusted internal record produced by authoritative
   D1 resolution.
10. Define the corruption policy at each store operation. Exact point reads
    fail closed on malformed current rows. Enumeration, migration, and replay
    scans follow their owning spec's explicit quarantine, delete, preserve, or
    abort behavior; a generic decoder never silently skips corruption.
11. Keep diagnostic provenance and source labels outside control flow. Core
    decisions consume exact unions and proof-bearing values only. Errors and
    logs redact bearer credentials, factor secrets, decrypted custody material,
    and other protected values.
12. Remove repeated validation and broad casts downstream. Delete the generic
    helper once its last caller in the domain is gone.

Large registration-store files are migrated by existing domain seams. This
refactor does not introduce a parallel repository or codec architecture.

Phase 2 exit evidence:

- hostile route, D1, token, and worker inputs stop at one owning decoder;
- ordinary object literals, broad spreads, raw strings, and public payloads
  cannot construct proof-bearing or admitted types in type fixtures;
- the current R103F B4/B5 order, exact operation-claim and replay behavior,
  R107 owner-proof seam, and R120 tenant-root composition retain focused
  behavioral coverage;
- current writers have one shape and every remaining compatibility reader has
  a persistence/request boundary and deletion condition; and
- no migrated core function accepts `unknown`, `Record<string, unknown>`, a raw
  persistence row, or diagnostics as domain input.

### R123-F: Ed25519 Yao ownership and `structuredClone` removal

This is Phase 3 from the initial Refactor 123 outline. Its design is governed by:

- [Refactor 93](./refactor-93.md) and its
  [Gateway persistence follow-up](./refactor-93-gateway-persistence-follow-up.md),
  which own request-scoped partitioning, batch-snapshot reads, typed claims,
  CAS writes, exact replay, and adapter-alias isolation;
- [Refactor 94A](./refactor-94A-performance-regression.md), which requires a
  durable claim before each irreversible effect, no repeated effect after
  ambiguity, at most two D1 roundtrips on successful Yao registration
  execution, and no terminal result dependent on mutable aliasing;
- [Refactor 97](./refactor-97-folder-hierarchy.md), which keeps the domain
  record-store port and codecs host-neutral while the D1 factory remains under
  `cloudflare/d1/ed25519Yao/`;
- `tests/unit/routerAbEd25519YaoProductRegistrationPartitionedStateStore.unit.test.ts`
  and
  `tests/unit/routerAbEd25519YaoProductRegistrationPersistence.unit.test.ts`,
  which own partition isolation, lossless Map/Set/byte encoding, atomic CAS,
  contention, and adapter-alias behavior.

#### Reconciled current design

The existing lifecycle model is stronger than the original Phase 3 outline
assumed:

- registration, recovery, export, capability, and intent-authority state are
  already discriminated unions;
- recovery, export, capability, and authority variants already use readonly
  fields;
- services advance a lifecycle by installing a complete new variant in a Map;
- the mutable Maps and Sets form a request-local working draft loaded from D1;
- D1 remains the lifecycle authority and CAS arbitrates concurrent requests.

Phase 3 preserves the request-local draft and the existing transition services.
It does not convert the whole Yao subsystem to persistent collections or a new
reducer framework. The state rewrite previously proposed in R123-F1 would touch
more than thirty valid mutation sites without removing the actual ambiguity.

The actual ownership problems are:

1. The host-neutral record-store port currently returns parsed domain objects.
   A conforming in-memory adapter can retain and return the same mutable object
   reference, so the state store deep-clones every read.
2. `load()` returns both a mutable request state and a second mutable
   `sharedState` graph used only to detect whether shared state changed. The two
   graphs require deep detachment from each other.
3. Partition and merge helpers clone every nested entry because their types do
   not express which values are immutable and which object owns each mutable
   container.
4. The persisted-state parser checks collection classes and allowed `kind`
   strings, then accepts the nested objects as domain state. It does not prove
   the exact fields or branch invariants needed for safe sharing.
5. `stateFingerprint(unknown)` is used for shared-change detection, terminal
   equality, session comparison, and codec validation. These are distinct
   domain questions and need distinct typed operations.

#### Invariants preserved during Phase 3

1. Shared, ceremony, and registration-execution records are read in one D1
   batch snapshot.
2. Shared and ceremony mutations commit in one transactional `putMany` CAS.
3. An unchanged shared projection produces no shared-row write. Ceremony-only
   work must not contend on the tenant-wide shared row.
4. The recovery capability cache, recovery identity index, recovery session
   index, export authorization nonces, and export uncertainty set remain in the
   shared partition.
5. The shared recovery capability cache remains bounded to 32 entries with the
   existing suspended-capability retention priority.
6. A ceremony record contains state for exactly one validated lifecycle ID.
   Committing one ceremony cannot replace another ceremony's state.
7. Every remote irreversible effect is preceded by a durable typed claim.
8. An uncertain backend result retains its claim and is never converted into an
   automatic backend retry.
9. Identical concurrency converges on the exact stored terminal result.
   Conflicting concurrency fails before a second Router execution.
10. Registration execution keeps its successful-path limit of two D1
    roundtrips and stays off the generic full-product-state runner.
11. Exact terminal output remains redeliverable, and registration finalization
    consumption remains one-use and idempotent for the same consumer.
12. Recovery activation keeps its operation-receipt reconciliation. The shared
    recovery session index cannot bind one backend session to two lifecycles.
13. Gateway handlers remain request-scoped. No mutable tenant snapshot is
    cached across requests.
14. The existing persisted record keys, codec kinds, and encoded Map/Set/byte
    representation remain unchanged. Phase 3 requires no D1 data migration.
15. Router, Deriver, SigningWorker, circuit, transcript, root-share, and custody
    semantics remain unchanged.
16. The host-neutral domain module gains no D1 or Cloudflare dependency.

#### Target ownership model

The record adapter carries encoded JSON. The domain state store owns parsing and
encoding:

```text
D1 or in-memory adapter
  -> VersionedJsonObject
       -> exact partition-record decoder
            -> fresh request-owned Map, Set, object, and byte graph
                 -> request-local transition services
                      -> exact partition encoder
                           -> VersionedJsonObject
                                -> adapter CAS
```

The encoded adapter value may be aliased. The exact decoder always allocates
the domain graph, and the encoder always allocates the value passed to the
adapter. Adapter ownership therefore cannot leak into domain ownership.

`load()` returns one mutable request draft plus immutable scalar baseline data:

```ts
type RouterAbEd25519YaoLoadedDraftV1 = {
  readonly state: RouterAbEd25519YaoProductRegistrationDraftV1;
  readonly baseline: {
    readonly sharedEncoding: RouterAbEd25519YaoSharedStateCanonicalEncodingV1;
    readonly sharedVersion: string | null;
    readonly ceremonyVersion: string | null;
    readonly executionVersion: string | null;
  };
};
```

`sharedEncoding` is the exact canonical encoding of the loaded shared
projection. It exists only to decide whether the shared record belongs in the
next mutation batch. The D1 version remains the concurrency authority. This
field is never an authorization, protocol, or diagnostic digest.

The loaded execution object is removed from the general product-state snapshot.
The generic commit path only needs execution-record presence and version;
registration execution reads and parses its record through the dedicated claim,
commit, reconcile, and consume operations.

The draft aggregate is nominal and can be created only by the empty-state
factory or exact persistence decoder. Its Maps and Sets remain mutable inside
one request. Partition projections expose `ReadonlyMap` and `ReadonlySet`, and
nested entries are shareable only after their builders own every mutable byte
buffer. A readonly property containing a `Uint8Array` is insufficient; builders
copy such data at insertion, and outward byte access uses an existing encoded
form or a copy.

#### R123-F1: Exact persisted-state decoding

Targets:

- `routerAbEd25519YaoProductRegistration.ts`;
- `routerAbEd25519YaoProductRegistrationPersistence.ts`;
- their focused persistence and state tests.

Work:

1. Replace the collection-and-kind-only state parser with exact decoders for
   every registration, intent-authority, capability, recovery, and export
   branch.
2. Reuse the existing protocol parsers for admission requests, receipts,
   results, recovery requests, export requests, material activation refs, and
   runtime policy scopes.
3. Verify exact required and forbidden fields for the local lifecycle wrapper
   around each parsed protocol value.
4. Reject malformed persistence container encodings: unknown or extra
   `__seamsType` fields, duplicate Map keys, duplicate Set entries, invalid byte
   values, non-finite numbers, and tagged values with the wrong payload shape.
5. Reconstruct every accepted branch into a fresh object. Copy every mutable
   byte buffer that is retained in state.
6. Make the aggregate a nominal request-draft type produced by the empty-state
   factory and persistence decoder. Type fixtures reject broad object literals
   and partial state graphs.
7. Preserve the current encoded envelope, Map, Set, and byte tags exactly.
8. Verify partition envelope invariants directly: a shared record has an empty
   ceremony projection, a ceremony record has an empty shared projection and
   contains only its declared lifecycle, and an execution record's lifecycle
   matches its storage key.
9. Decide the remaining `admissionClaims` and `authorizationUncertain`
   missing-field readers against deployed-row evidence. Delete each
   compatibility branch and its test when no supported row needs it. If a
   supported row remains, keep the reader only in this persistence decoder and
   record its deletion condition.
10. Replace the Durable Object structured-clone test. Refactor 93 deleted the
    tenant runtime that owned that boundary. The replacement test proves that
    an encode/decode round trip produces an exact, detached, request-owned
    graph.

Acceptance:

- malformed nested state with an allowed `kind` is rejected;
- unexpected and missing branch fields are rejected;
- stored protocol values pass their existing domain parsers;
- accepted state contains no adapter-owned object or byte reference;
- the persisted JSON representation is unchanged;
- direct construction of the aggregate draft fails at type level.

#### R123-F2: Raw encoded record-store port

Targets:

- `routerAbEd25519YaoProductRegistrationPartitionedStateStore.ts`;
- `cloudflare/d1/ed25519Yao/d1Ed25519YaoProductRegistrationPartitionedStateStore.ts`;
- the focused state-store test and its in-memory adapter.

Work:

1. Change the host-neutral adapter port to read and write
   `VersionedJsonObject` values rather than parsed product-domain records.
2. Decode after every adapter read, including the value returned by the D1
   atomic-patch operation.
3. Encode before every adapter write. No domain object crosses into adapter
   ownership.
4. Keep the existing record keys, kinds, JSON paths used by atomic patching,
   and D1 batch/CAS behavior.
5. Remove the three read-side `structuredClone` calls.
6. Replace the clone-configurable in-memory test adapter with a raw encoded
   adapter that deliberately returns retained object references. The domain
   decoder must still detach the loaded state.

Acceptance:

- an adapter retaining its input cannot observe later domain mutation;
- a request mutating its loaded draft cannot mutate an adapter-retained value;
- atomic patch returns a freshly decoded claimed record;
- D1 read and write counts remain unchanged;
- the domain store stays host-neutral.

#### R123-F3: Scalar baselines and exact comparisons

Work:

1. Replace `sharedState` in load and commit inputs with the canonical shared
   baseline encoding.
2. Replace the unused loaded execution-domain object with its presence/version
   baseline.
3. Compute the next shared encoding from the bounded shared projection. Include
   a shared mutation only when that encoding differs from the loaded baseline.
4. After a successful preclaim commit, create the terminal baseline from the
   exact state that was stored and the returned versions. Retain no second
   mutable graph.
5. Update the deterministic request runner, two-phase runner, request-scoped
   runtime, and export uncertainty path in separate, bounded consumer slices.
6. Replace generic `stateFingerprint` calls with:
   - exact canonical shared-state encoding comparison;
   - the protocol result encoder/comparator for terminal result equality;
   - the existing byte equality function for session IDs;
   - exact partition invariants in the partition-record decoder.
7. Keep diagnostic strings outside lifecycle control flow.

Acceptance:

- ceremony-only commits omit the shared mutation;
- shared changes still conflict atomically on a stale shared version;
- the preclaim and terminal CAS sequence retains its current outcomes;
- registration execution retains exact replay and the two-roundtrip bound;
- load and post-commit snapshots retain no duplicate mutable state graph.

#### R123-F4: Partition sharing after ownership is proven

Targets:

- `routerAbEd25519YaoProductRegistrationPartitioning.ts`;
- `routerAbEd25519YaoProductRegistrationPartitionedStateStore.ts`.

Work:

1. Change partition projection types to readonly collections.
2. Allocate new top-level Map and Set containers for each projection.
3. Share exact immutable lifecycle entries and authorities between the
   request-owned draft and its transient partition projection.
4. Keep mutable collections owned by the draft or projection; no backing Map,
   Set, array, or byte buffer is shared across adapter and request ownership.
5. Keep the recovery cache bound and retained identity index behavior.
6. Construct ready registration execution records through an exact builder that
   accepts only the admitted registration and admitted authority branches. The
   builder verifies matching lifecycle, admission request, fingerprint, and
   expiry before creating the record.
7. Remove the nine partition/merge clones and the two execution-record clones.
8. Keep partition and merge helpers internal to the domain persistence path
   unless a production consumer requires their public export.

Acceptance:

- one ceremony projection contains no lifecycle entry owned by another
  ceremony;
- merging one ceremony preserves unrelated ceremonies;
- mutating a request draft after an adapter write cannot affect the stored raw
  record;
- nested byte mutation cannot cross an ownership boundary;
- all production `structuredClone` calls are gone from the two target files.

#### R123-F5: Fixtures and performance evidence

1. Replace test mutation clones with shared branch-specific fixture builders.
2. Replace persistence-boundary clone setup with exact raw-envelope builders or
   encode/decode round trips.
3. Classify the test asserting survival of a Durable Object structured-clone
   boundary as `obsolete_test_or_fixture`; Refactor 93 deleted that production
   boundary.
4. Preserve the tests for adapter-alias isolation, partition independence,
   shared cache bounds, same-snapshot reads, compare-and-swap conflicts,
   preclaim durability, uncertain outcomes, exact replay, and one-use
   consumption.
5. Replace tests that mutate readonly nested domain objects through
   `Object.assign` with an explicit valid lifecycle transition or a
   branch-specific builder.
6. Replace the benchmark planner's clone with an exact typed configuration
   builder.
7. Capture the performance evidence defined below after correctness and alias
   isolation pass.

### Phase 4 specification authority

R123-E preserves the browser and transport contracts already owned by:

- [Refactor 103F](./refactor-103F-final-cutover.md), for the V6 browser record,
  exact replacement and sibling preservation, known-version quarantine,
  unknown-future `upgrade_required`, registration/recovery/device-link
  journals, protocol-version handshake, and origin-bound hosted credentials;
- [Refactor 107](./refactor-107-remove-app-session.md), for untrusted wallet
  locators, removal of app-session storage and messages, wallet-origin ownership
  of opaque Wallet Session credentials, and the prohibition on rebuilding
  trusted admission in the browser; and
- [Refactor 108](./refactor-108-compact-wallet-iframe.md), for exact directional
  iframe messages, authenticated MessagePort delivery, complete surface
  identity, finite bounded measurements, sequence checks, and stale-event
  rejection;
- [Refactor 100](./refactor-100-passkey-account-refactor.md), only for the
  client-custody boundary that current R120 source still implements: plaintext
  custody remains worker-owned, live material uses opaque handles, and cached
  envelopes remain non-authoritative; and
- the current V6 store/parser, pending registration and recovery journal
  unions, iframe message contract, worker channels, browser-focused unit tests,
  and intended-behaviour contracts on the merged R120 branch.

Phase 4 replaces broad object narrowing at those boundaries. It does not alter
the browser schema, make local storage authoritative, introduce an iframe
message adapter, or move secret material into JavaScript. Refactor 90 and 82B
state machines, compatibility lists, and source guards are historical context
and do not reopen a final R103F boundary.

### R123-E: Browser, IndexedDB, RPC, worker, and UI boundaries

Implement in the following bounded slices:

1. pending wallet registration and recovery commits;
2. Wallet Session authorization persistence;
3. lane-holder and signing-role local records;
4. relayer RPC response families;
5. device-linking worker and transport messages;
6. iframe and custom-event messages; and
7. application draft stores and console API responses.

#### R123-E1: IndexedDB records and durable journals

1. Treat every IndexedDB value as an external persistence DTO even when the
   current application wrote it. Decode on repository read, encode on write,
   and return a freshly owned domain graph.
2. Preserve the existing V6 Wallet Session record, physical key path, separate
   authorization identity, exact wallet/authority/method tuple, same-method
   retirement, and sibling-method preservation. A type-only cleanup does not
   bump `SEAMS_WALLET_DB_VERSION` or change a key path.
3. Preserve the current classification contract: malformed current records
   fail closed, known retired V3/V4/V5 rows remain quarantined according to the
   final cutover, and an applicable unknown future row yields
   `upgrade_required` rather than `corrupt` or fallback.
4. Keep `PendingWalletRegistrationCommitV1`,
   `PendingWalletRecoveryCommitV1`, device-link installation, activation, and
   acknowledgement records as recovery journals. Journal absence is terminal
   only after the owning transaction atomically publishes replacement material
   and lifecycle facts, retires the source, and deletes the journal.
5. Store only durable facts needed to reconcile an uncertain server effect.
   Runtime publication, worker handles, disposal, and zeroization remain
   process-local and never become journal branches.
6. Preserve server-first reconciliation, exact receipt identity, cancellation,
   one-use consumption, and retry ordering. A parser cleanup cannot turn an
   indeterminate committed effect into a fresh mutation.
7. Keep custody envelopes encrypted and non-authoritative browser copies bound
   to the exact server revision and digest. Parsers can validate record shape;
   they cannot claim the manifest, ciphertext, public identity, or material is
   cryptographically verified. The owning verifier creates that proof after
   recomputation.
8. Keep plaintext roots, shares, PRF output, KEKs, bearer credentials destined
   for another origin, and live capability handles out of generic records,
   errors, logs, and UI state.
9. Retain compatibility only for versions the owning spec still supports. A
   representation change requires an explicit migration/reset decision and
   browser operating-path evidence; this refactor does not create one merely to
   replace a predicate.

#### R123-E2: Relayer and external RPC

1. Keep `Response.json()` as `unknown` and decode each endpoint's exact success
   and failure family once. Do not create one cross-endpoint response record.
2. Model transport failure, invalid HTTP/body, protocol rejection, recoverable
   retry, indeterminate commit, and confirmed success as distinct result
   branches. Preserve the endpoint's stable error codes and status mapping.
3. Bind replay and mutation results to their request fingerprint, idempotency
   identity, wallet/authority/material tuple, and receipt where the owning
   protocol requires them. A retry cannot redraw or silently change those
   values.
4. Never repeat an irreversible effect because a response was malformed or
   lost. Query/reconcile paths own uncertain completion; string messages and
   diagnostics never select retry behavior.
5. For third-party APIs that permit additive fields, accept them only in the
   external adapter and normalize to an exact internal union. First-party
   private protocols reject unknown fields and change producer and consumer
   atomically.

#### R123-E3: Worker, MessagePort, iframe, and custom-event protocols

1. Treat every `event.data` and port payload as `unknown`. Define separate
   direction-specific unions and decoders for host-to-iframe,
   iframe-to-host, main-to-worker, and worker-to-main messages. A branch contains
   one exact discriminator and exact keys.
2. Authenticate the transport before trusting its payload. Window-message
   handlers validate source and origin; hosted delivery validates its stored
   app/wallet origins; CONNECT and READY validate
   `WALLET_PROTOCOL_VERSION`; the iframe adopts a transferred port only after
   the existing handshake succeeds.
3. Preserve version-skew behavior: report
   `WALLET_IFRAME_PROTOCOL_VERSION_MISMATCH`, close or reject the connection as
   specified, and retain no dual-version message adapter.
4. Preserve request correlation, complete surface identity, strictly newer
   sequence numbers, terminal-once behavior, cancellation, connection-close,
   and stale-generation rejection. Malformed or stale Refactor 108 measurement
   messages are ignored at the router boundary and cannot move, close, resize,
   or cancel the active surface.
5. Make buffer ownership explicit. `postMessage` transfer lists detach their
   sender buffers; copy only when both sides must retain bytes, transfer when
   ownership moves, and never retain a view whose backing buffer can be
   detached by another branch.
6. Parse Rust/WASM or generated protocol messages through their owning generated
   or exact parser. Regenerate changed bindings. A JavaScript shape decoder
   cannot mint a verified proof, activated capability, or worker handle.
7. Delete remaining app-session, curve-token, and retired reusable-session
   message branches. Public wallet locators and outer-app data cannot satisfy
   wallet-origin proof or internal admission types.
8. Preserve hosted handoff as one origin-bound, single-use delivery capability.
   The wallet host receives and stores its opaque Wallet Session credential;
   the outer application never receives that credential through a decoded
   message or shared UI state.

#### R123-E4: UI drafts and console APIs

1. Decode local/session storage, URL/config data, custom events, and console API
   responses into domain-specific draft or view-model unions at their owning
   adapters.
2. Keep truly optional callbacks, presentation, and display metadata optional.
   Identity, authority, session, signing, budget, restore, and lifecycle fields
   remain required in core values.
3. Treat a corrupt non-authoritative UI draft as a typed reset/re-entry outcome.
   It cannot authorize a wallet action or repair an authoritative server or
   IndexedDB record.
4. Normalize thrown `unknown` values into a display error without using a
   generic record predicate. UI diagnostics and profile provenance remain
   observability; reducers and authorization decisions consume exact domain
   unions.

Phase 4 boundary exit evidence:

- registration, unlock, refresh, recovery, device linking, signing, export,
  and hosted-wallet flows still pass through their existing atomic owners;
- IndexedDB version classification and V6 exact replacement retain focused
  tests for malformed, legacy, unknown-future, and sibling-method records;
- RPC tests distinguish rejection, retryable transport failure, indeterminate
  completion, reconciliation, and success;
- worker/iframe tests cover hostile raw payloads, wrong origin/source, both
  protocol-skew directions, correlation drift, stale generations, and detached
  buffers where transfer is used; and
- no browser parser or UI model can construct `VerifiedOwnerProof`, trusted
  admission, active material, or tenant-root identity.

### Phase 5 specification authority

R123-H preserves every current canonical preimage, digest algorithm, domain
label, version, and persisted or wire representation owned by the merged R120
source and its focused vectors. In particular,
`CapabilityOperationFingerprintDigest` and the domain-separated encoder in
`operationFingerprint.ts` are the preferred existing pattern: one domain owns
the preimage, the resulting digest has a domain-specific brand, and consumers
compare values of that brand.

This phase changes how core code asks whether two already-valid domain values
are equal. It does not redesign protocol identity, add digests to stored rows,
or change canonical bytes merely to make an equality call shorter. Any wire or
persistence representation change remains a separate change owned by that
protocol or store, with its normal migration and vector requirements.

### R123-H: Domain-owned equality and verified digests

The current equality pattern often serializes both operands:

```ts
alphabetizeStringify(left) === alphabetizeStringify(right);
```

That expression performs two recursive allocations and silently makes generic
JSON serialization the definition of domain equality. R123-H replaces only
these equality, conflict, replay, and change-detection uses. Calls that produce
an established canonical preimage or persisted encoding remain with their
owning encoder. This is a semantic equality inventory, not another review of
all 463 `alphabetizeStringify` invocations.

#### R123-H1: Characterize and classify each equality

Start from the merged R120 tip and find call sites where canonicalized strings
or generic fingerprints influence equality, inequality, replay, conflict,
deduplication, or lifecycle control flow. Include comparisons split across
local variables; exclude calls used only to construct an established protocol
preimage or exact persisted JSON.

Before replacing a comparison, add one focused behavioral test to its owning
domain that pins:

1. values that are equal despite different object insertion order;
2. each domain field whose difference must make the values unequal;
3. the relevant discriminated-union branches;
4. collection ordering or set semantics where applicable; and
5. the existing replay, conflict, idempotency, or change-detection outcome that
   consumes the comparison.

Classify the comparison by meaning:

| Equality question                       | Required implementation                                        |
| --------------------------------------- | -------------------------------------------------------------- |
| Small value object                      | Named field-by-field comparator                                |
| Discriminated union                     | Named exhaustive branch comparator with `assertNever`          |
| Established protocol or replay identity | Existing versioned, domain-specific branded digest             |
| Stored value accompanied by its digest  | Boundary parser recomputes and verifies the digest once        |
| Persisted entity or CAS target          | Authoritative identity plus generation, revision, or version   |
| Bounded encoded state change            | Exact canonical encoding baseline owned by that store          |
| Byte or tuple value                     | Existing byte comparator or explicit tuple-field comparison    |
| Raw external value                      | Exact decoder first; comparison only after successful decoding |

If none of these meanings describes the call site, stop that slice and define
the missing domain concept before changing behavior.

#### R123-H2: Named comparators for structural domain equality

1. Put each comparator beside the type whose equality it defines. Name the
   domain and representation version when the value is versioned.
2. Compare required scalar and branded fields directly. Compare tuples and
   ordered arrays element by element. Use explicit set semantics only where the
   domain says order is irrelevant.
3. Switch exhaustively over discriminated unions. Compare only the fields that
   belong to the selected branch and terminate through `assertNever`.
4. Require the narrowest valid type on both operands. A comparator never
   accepts `unknown`, a raw persistence DTO, `Record<string, unknown>`, or two
   unrelated union families.
5. Keep secret and authentication comparisons with their existing owning
   cryptographic comparison. This phase does not replace a required
   constant-time byte comparison with JavaScript string equality.
6. Add no generic `deepEqual`, `equalByCanonicalJson`, `equalByDigest<T>`, or
   configurable comparator framework. A domain-named function must make the
   meaning visible at the call site.

Direct comparison is the default for small or transient values. Computing a
cryptographic digest solely to avoid writing a short comparator would add CPU
cost, collision semantics, and another representation without improving the
model.

#### R123-H3: Verified digest-bearing domain values

Use digest equality only when the digest is already the domain's protocol,
replay, or durable identity.

1. Reuse an existing domain-specific branded digest and its named versioned
   encoder. Do not accept the generic `DigestB64u` type in core equality APIs
   when a narrower digest brand exists.
2. When persistence or a wire value carries both a value and digest, its exact
   decoder parses the value, recomputes the digest, rejects a mismatch, and
   returns a proof-like verified pair. Downstream code compares only the
   verified branded digest.
3. Keep construction provenance private to the encoder or verifying boundary.
   An ordinary object literal or caller-provided digest cannot construct the
   verified pair.
4. Preserve the exact digest algorithm, canonical preimage, domain separation,
   and version. Existing Rust/TypeScript vectors remain byte-identical.
5. Carry a verified digest through a request or loaded domain record when it is
   compared repeatedly. Do not stringify or rehash the full value at every
   decision point.
6. If a stored record has no digest today, use a named comparator unless the
   owning protocol independently requires a representation change. R123-H does
   not add a persistence column or compatibility reader for convenience.
7. Keep corruption detection at the read boundary. Core replay and conflict
   logic cannot trust a stored digest before its associated value has been
   verified.

Type fixtures cover cross-domain digest substitution, direct construction of a
verified pair, raw generic digest use, and invalid union operands where the
public type surface makes those escape hatches possible.

#### R123-H4: Bounded migration slices

Migrate one equality owner and its tests at a time, staying close to five files:

1. shared authorization and operation-fingerprint comparisons;
2. registration request, receipt, policy-scope, and replay comparisons;
3. add-signer, auth-method, and activation comparisons;
4. custody commit, recovery, and export comparisons;
5. linked-device session, authority, and credential-delivery comparisons; and
6. browser session, signing-material, and IndexedDB comparisons.

R123-F3 already owns Ed25519 Yao shared-state baselines, terminal protocol
result equality, and session-byte equality. R123-H reuses those named
operations and does not reopen the Yao ownership design.

For each slice:

1. land the characterization assertion against the current comparison;
2. introduce or reuse the narrow comparator or verified digest type;
3. move digest verification to the exact decoder when required;
4. replace the core equality call and demonstrate its operating path once;
5. remove now-unused `alphabetizeStringify` imports and intermediate canonical
   strings from that slice; and
6. run the owning focused test, type fixture, and vector test when digest bytes
   are involved.

Acceptance:

- no migrated domain decision defines equality by independently serializing
  both operands;
- every replacement states whether equality means fields, union branch,
  protocol digest, authoritative revision, bytes, or canonical store encoding;
- a stored value/digest mismatch is rejected at its owning boundary before
  core logic can compare the digest;
- unrelated branded digest families cannot be passed to the same equality
  operation in type fixtures;
- protocol preimages, persisted encodings, replay outcomes, and conflict
  behavior remain unchanged;
- small-value comparisons allocate no canonical object graph or JSON string;
  and
- remaining `alphabetizeStringify` callers are canonical encoding or preimage
  owners rather than generic domain-equality checks.

### R123-G: Remaining tests, scripts, and helper deletion

1. Convert raw invalid-input fixtures to the boundary's raw wire type or an
   explicit unknown fixture builder.
2. Convert valid complex state fixtures to shared branch-specific factories.
3. Exercise actual IndexedDB, Worker, and `postMessage` boundaries when a test
   owns browser structured-clone semantics. Remove direct cloning from fixture
   setup; using the platform boundary proves serialization, transfer, and
   detachment behavior more accurately.
4. Classify lower-authority inline fixtures and source guards before changing
   production. Delete obsolete tests, fixture fields, guards, and mocks that
   encode retired app-session, V3/V4/V5, compatibility, or broad-object
   behavior.
5. Keep type-fixture claims precise. They prove rejection of ordinary object
   literals, invalid branches, broad spreads, and raw identifiers. They do not
   claim to prevent a deliberate double assertion or unchecked JavaScript;
   boundary tests own those inputs.
6. Remove `isRecord`, `isPlainObject`, `isRecordValue`, `toRecordValue`, and
   equivalent helpers after their final callers are migrated.
7. Remove unused record aliases, clone wrappers, compatibility branches, and
   tests that existed only for those paths. Regenerate owned fixtures and
   bindings rather than editing generated output.
8. Run a final semantic inventory for manual predicates, raw records escaping
   decoders, unsafe domain casts, broad lifecycle spreads, message handlers,
   dynamic dispatch tables, and obsolete runtime message discriminators.
9. Count executable first-party TypeScript/JavaScript under `packages/`,
   `apps/`, `tests/`, and `scripts/`. Documentation may retain historical names;
   generated first-party artifacts are regenerated if their source changes.

Phase 6 is complete only after the domain slices demonstrate their operating
paths before broad cleanup, then the relevant persistence, replay, worker,
iframe, RPC, UI, equality, and type-level tests pass. Source-text checks are not
added as a substitute for those behavioral and type-level contracts.

## Change-Set Discipline

Each implementation change should answer one domain question and stay close to
five files. When a valid slice needs more, split protocol/type ownership from
consumer migration or propose a smaller seam before editing.

A typical change contains:

1. one boundary decoder or one ownership transition;
2. the narrow production consumer;
3. one behavioral test proving the operating path;
4. one type fixture when compile-time rejection is part of the contract;
5. deletion of the replaced helper or branch when it has no remaining caller.

Do not mix canonical wire changes, state-ownership changes, and broad fixture
cleanup in one commit. An equality slice preserves its owning canonical wire
representation unless that protocol independently approves a versioned change.

## Test Strategy

Before changing code for a failing test, classify it as:

- `production_regression`;
- `valid_test_needs_update`;
- `obsolete_test_or_fixture`;
- `environment_or_infrastructure_failure`.

The operating path is demonstrated first. Type fixtures and additional
boundary failures follow after the successful behavior works.

### Required assertions

Boundary decoder tests cover:

- accepted canonical input;
- non-object input;
- arrays and unsupported object instances;
- missing and unexpected fields;
- invalid discriminants;
- wrong field representations;
- invalid branch combinations;
- canonical encode/decode round trips where a wire encoder exists.

Type fixtures cover:

- direct construction from raw strings;
- swapped branded identifiers;
- omitted required identity or lifecycle fields;
- broad object spreads;
- caller-selected root, tenant, share, epoch, or protocol fields;
- invalid union branches;
- non-exhaustive consumption where the existing typecheck pattern supports it.

State-ownership tests cover:

- mutation of caller-owned input after insertion cannot affect stored state;
- values returned from a store expose no mutable store-owned collection;
- updating one partition leaves other partitions unchanged;
- partition projections preserve immutable entry identity where safe;
- byte-buffer mutation cannot cross an ownership boundary;
- compare-and-swap and lifecycle bounds retain their behavior.

Domain-equality tests cover:

- object insertion order does not affect an equality result whose current
  contract is structural;
- every meaningful required field changes the comparison result;
- discriminated-union branches compare exhaustively;
- ordered collections preserve order sensitivity and set-like collections use
  only their declared membership semantics;
- stored value/digest mismatches fail at the decoder boundary;
- related verified digests compare directly while unrelated digest brands fail
  in type fixtures; and
- replay, conflict, idempotency, and change-detection outcomes remain the same
  before and after migration.

### Narrow verification

Use the narrowest applicable commands while implementing:

```text
pnpm -C tests type-check:unit
pnpm -C packages/shared-ts type-check
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/alphabetizeStringify.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/walletConsoleServiceBinding.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/tenantRootIdentityResolution.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519YaoProductRegistrationPartitionedStateStore.unit.test.ts --reporter=line
```

Run the owning vector generator or vector test whenever canonical encoding,
digest input, or Rust/TypeScript protocol agreement is touched. Generated
fixtures are never hand-edited.

### Final verification

Because this refactor crosses shared types, persistence, authorization, and
cryptographic protocol inputs, the final gate is:

```text
pnpm check
pnpm test:intended
pnpm test:unit
```

Run the relevant Rust tenant-root, Router A/B, and wire-vector tests for phases
that touch their shared representations.

## Performance Evidence

The expected runtime improvement comes from removing repeated full-graph clones
in product-registration partitioning and store reads. Generic object predicate
cost is negligible and is not a performance claim of this refactor.

R123-H may also remove repeated canonical-object allocation and JSON encoding
from equality paths. Record the number of canonicalizations removed in each
slice. Benchmark only a demonstrated hot comparison path; direct field or
already-computed digest comparison should not be burdened with a repository-wide
benchmark. Computing a new cryptographic digest for a transient comparison is
not considered a performance optimization.

Before R123-F, capture an R120 baseline for representative small and large
registration states. Measure:

- partition creation;
- partition merge;
- store read and compare-and-swap update;
- one registration, recovery, and export transition;
- allocation volume or retained heap when the runtime makes it available.

Report p50 and p95 latency across enough iterations to avoid timer noise. The
acceptance gate is behavioral equivalence, no alias leak, and no statistically
credible regression. Allocation and latency improvements are recorded as
evidence rather than promised in advance.

## Risks and Controls

| Risk                                                               | Control                                                                     |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------- |
| Compile-time types create false confidence at untrusted boundaries | Keep input `unknown` until one exact decoder succeeds                       |
| `readonly` leaves mutable collection or byte aliases               | Private ownership, copy-in/copy-out, and alias-isolation tests              |
| A broad shared-type change destabilizes Refactor 120               | Land R123-A as the merge gate; base later phases on the merged R120 tip     |
| Canonicalization cleanup changes protocol bytes                    | Preserve encoders and require existing Rust/TypeScript vectors              |
| Fixture repair preserves retired shapes                            | Classify failures and delete obsolete fixtures or helpers                   |
| New codec abstractions add more machinery than they remove         | Reuse current parser patterns and keep decoders domain-named                |
| Partial migration leaves duplicate validation paths                | Delete downstream guards in the same domain slice                           |
| Rolling private-protocol mismatch                                  | Change client, handler, and contract atomically                             |
| Clone removal exposes hidden mutation                              | Establish ownership before removing each clone and keep focused alias tests |
| A generic equality replacement hides domain meaning                | Use domain-named comparators or existing branded protocol digests           |
| A stored digest is trusted without checking its value              | Recompute and verify it in the exact persistence or request decoder         |
| Digest cleanup changes protocol bytes                              | Preserve versioned encoders and run the owning vectors                      |
| Hashing small values costs more than direct comparison             | Prefer explicit field and exhaustive union comparators                      |

## Completion Criteria

Refactor 123 is complete when:

1. `rg` finds zero executable `structuredClone` calls and zero `isRecord`
   helper definitions or calls in first-party TypeScript/JavaScript under
   `packages/`, `apps/`, `tests/`, and `scripts/`. Documentation may describe
   the removed APIs; generated first-party output is regenerated from its owner.
2. Shallow aliases such as `isPlainObject`, `isRecordValue`, and
   `toRecordValue` no longer provide generic domain narrowing.
3. Manual broad-object predicates exist only inside exact boundary decoders and
   return a domain value rather than a reusable record.
4. `Record<string, unknown>` does not cross from a decoder into core domain
   logic.
5. The migrated flows contain no `as never`, `as SomeDomainType`, or broad
   lifecycle construction spread.
6. Identity, auth, session, signing, budget, restore, persistence, and lifecycle
   state use required branch fields and discriminated unions.
7. Every switch over a migrated domain union is exhaustive.
8. Direct invalid domain construction and known spread escape hatches fail in
   type fixtures.
9. Ed25519 Yao partitioning and state-store reads perform no defensive graph
   clone and pass alias-isolation tests.
10. Obsolete helpers, fixtures, tests, and compatibility branches are deleted.
11. The relevant targeted tests, `pnpm check`, `pnpm test:intended`, and
    `pnpm test:unit` pass.
12. Performance results for R123-F are recorded against the R120 baseline.
13. Structural decoders cannot construct verified proof, trusted admission,
    active material, or authenticated tenant-root values; their owning
    verifier/resolver remains the only constructor.
14. D1 CAS/replay behavior, atomic IndexedDB finalization, V6/unknown-future
    classification, RPC uncertainty, iframe origin/version checks, and buffer
    transfer ownership retain their focused behavioral evidence.
15. Core equality, replay, conflict, deduplication, and change-detection
    decisions do not independently canonicalize both operands with
    `alphabetizeStringify` or another generic serializer.
16. Small values use domain-named comparators, union comparisons are
    exhaustive, and protocol identity comparisons accept only their narrow
    branded digest.
17. Stored value/digest pairs are recomputed and verified at their owning read
    boundary before the digest reaches core logic.
