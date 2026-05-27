# Refactor 43: Cleanup of Residual Indirection in `signingEngine`

Date created: 2026-05-26
Status: partially implemented

## Scope

This refactor follows Refactor 33 (`docs/refactor-33.md`) which established the
call-direction layout for `client/src/core/signingEngine/`: facade → assembly →
flows → leaf modules, with explicit dependency rules per folder. The topology
itself is sound and well enforced — `flows/*` and `session/*` do not import
`SigningEngine`, no internal `index.ts` barrels were reintroduced, and the
operation state machine is genuinely monotonic.

The remaining issues are not structural; they are residual scaffolding in the
implementation layer that sits between the facade and the operation modules.
This refactor proposes simplifications that remove indirection without changing
the dependency graph or the public SDK surface.

Refactor 43 is independent of Refactor 41 (budget/step-up invariants) and
Refactor 42 (stricter union types), and can run in parallel with either.

## Problem

Refactor 33 introduced a `createXxxPublicApi` factory tier between
`SigningEngine.ts` and the operation modules. The intent was to give the facade
a small set of cohesive sub-APIs (`sessionPublic`, `emailOtpPublic`,
`recoveryPublic`, `registrationPublic`, `passkeyPublic`, `warmCapabilitiesPublic`,
`thresholdEd25519Public`) rather than wiring every operation function directly.

In practice the tier became mechanical wrapping. Each `xxxPublic` module now
exports both standalone `(deps, args) => ...` functions and a factory that
returns the same methods curried with `deps`. `SigningEngine` calls the factory
and forwards every public method into it. The result is three layers of pass-
through (facade method → factory result method → standalone function) where one
layer would have been enough, and a systematic naming collision between facade
methods and operation functions that is currently papered over with a
`xxxValue` import suffix.

Adjacent symptoms include port factories that vary between real composition and
pure repacking, a 1388-line facade that is mostly forwarders, defensive
`String(...).trim()` chains at trust boundaries that should be one-shot parsed,
and a `*session*` vocabulary that is overloaded across at least seven distinct
concepts.

## Findings

### 1. The `createXxxPublicApi` Factories Are Mechanical Wrapping

Files:

- `client/src/core/signingEngine/flows/recovery/public.ts`
- `client/src/core/signingEngine/flows/registration/public.ts`
- `client/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts`
- `client/src/core/signingEngine/session/public.ts`
- `client/src/core/signingEngine/session/passkey/public.ts`
- `client/src/core/signingEngine/session/warmCapabilities/public.ts`
- `client/src/core/signingEngine/threshold/ed25519/public.ts`

Each module exports a standalone function plus a `createXxxPublicApi(deps)`
factory whose body is

```ts
return {
  someMethod: (args) => someStandaloneFunction(deps, args),
  // …
};
```

There is no caching, no enforcement, no shape adaptation — only currying.
`flows/recovery/public.ts` is the clearest illustration: lines 44–92 define the
standalone functions, lines 96–125 define a factory that curries each one. The
facade then holds `this.recoveryPublic = createRecoveryPublicApi(deps)` and
calls `this.recoveryPublic.method(args)` from a method named the same thing.

Pick one shape per `xxxPublic` module:

- Keep the standalone `xxxValue(deps, args)` functions and have `SigningEngine`
  hold the `deps` bundle for each domain, calling the standalone form directly.
  This removes the factory tier entirely.
- Or keep only the factory and remove the standalone exports, so the curried
  methods are the only public form.

The current state — exporting both — is the worst case because it doubles the
surface area and creates the naming collision in finding 3.

### 2. Port Factories Mix Composition With Repacking

Files:

- `client/src/core/signingEngine/assembly/ports/session.ts`
- `client/src/core/signingEngine/assembly/ports/recovery.ts`
- `client/src/core/signingEngine/assembly/ports/emailOtp.ts`
- `client/src/core/signingEngine/assembly/ports/warmSigning.ts`
- `client/src/core/signingEngine/assembly/ports/evmFamily.ts`
- `client/src/core/signingEngine/assembly/ports/near.ts`

Some port factories do real composition. `assembly/ports/warmSigning.ts` builds
status and capability readers from raw dependencies and exposes a coherent
`WarmSigningPorts` aggregate. `assembly/ports/evmFamily.ts` builds an emailOtp
resolver that reads from runtime or sealed storage.

Other port factories are pure repacking. `assembly/ports/session.ts` (37 lines)
is essentially `{ a: args.a, b: args.b, … }` with one conditional spread for
optional passkey restore. There is no rule for which to expect.

Recommended convention:

- Reserve `assembly/ports/*.ts` for genuine composition: factories that build
  new behavior, resolve runtime versus persisted sources, or aggregate multiple
  readers into a single port.
- Drop the file when the factory is only renaming or repacking dependencies;
  pass the raw bundle directly to the consuming public API or operation entry.

### 3. The `xxxValue` Import Suffix Is a Naming Collision Workaround

File:

- `client/src/core/signingEngine/SigningEngine.ts`, lines 34–92

Roughly 17 imports are aliased with a `Value` suffix
(`reportTempoFinalized as reportTempoFinalizedValue`,
`signTempo as signTempoValue`,
`upsertThresholdEcdsaSessionFromBootstrap as upsertThresholdEcdsaSessionFromBootstrapValue`,
and so on). The suffix has no semantic meaning — it exists because
`SigningEngine` has a method of the same name that wraps the imported function.

This is a downstream symptom of finding 1 plus the choice to mirror operation
function names in facade method names. Resolving finding 1 by collapsing the
`xxxPublic` factory tier should remove most of these. The remaining collisions
should be addressed by renaming either the facade method or the operation
function — not by carrying the alias forever.

### 4. `SigningEngine.ts` Is Predominantly Forwarders

File:

- `client/src/core/signingEngine/SigningEngine.ts` (1388 lines)

The facade has approximately 80 public methods. After the constructor (which is
the legitimate wiring code), the body is dominated by 1–4 line forwarders such
as

```ts
async signNear(request) { return await signNearValue(this.enginePorts.nearSigningDeps, request); }
clearAllThresholdEcdsaSessionRecords() { this.sessionPublic.clearAllThresholdEcdsaSessionRecords(); }
```

The `SigningEnginePublic` type at lines 1316–1387 is a flat `Pick<>` listing all
60+ method names. That `Pick<>` is the real public contract; the class methods
exist only to delegate.

Two viable simplifications, both feasible after finding 1 is resolved:

- Expose the `xxxPublic` aggregates on the class (`sessionPublic`,
  `emailOtpPublic`, etc.) and let SDK callers reach methods through them. This
  removes the facade-level forwarders and makes the sub-API boundaries
  first-class.
- Keep the flat facade but generate it (or its public spec) from the underlying
  module exports so that adding a method to an operation module does not
  require a corresponding edit to the facade.

The decision likely affects the `SeamsPasskey` consumer in
`client/src/core/SeamsPasskey/`, so coordinate before changing the shape.

### 5. Defensive Coding Should Be a Single Boundary Parser

File:

- `client/src/core/signingEngine/SigningEngine.ts`, lines 813–847
  (`buildWalletRegistrationEcdsaSessionBootstrap`)

The function contains roughly 12 consecutive
`String(args.x.y || args.z.y || '').trim()` calls followed by emptiness checks
in a single `if (!keyHandle || !ecdsaThresholdKeyId || ...)` guard. This is the
right defense at a trust boundary (server bootstrap material), but the boundary
is currently the facade, which means every other consumer of the same bootstrap
shape would have to repeat it.

Move the validation to the relayer client boundary:

- Add a `parseWalletRegistrationEcdsaBootstrap(raw): ValidatedBootstrap` in
  `client/src/core/rpcClients/relayer/walletRegistration.ts` (or its neighbor)
  that returns a non-optional, trimmed, integer-validated shape.
- Strip the defensive block from `buildWalletRegistrationEcdsaSessionBootstrap`
  and have it accept the validated shape directly.

This pairs naturally with Refactor 42's stricter union types — the validated
shape can be a discriminated union over `kind: 'jwt' | 'cookie'` etc., not the
mostly-optional bag that exists today.

### 6. Vocabulary Around "Session" Is Overloaded

The following terms refer to distinct concepts but share the `session` word:

| Term                   | Refers to                                                     |
| ---------------------- | ------------------------------------------------------------- |
| `warmSession`          | Pre-authorized PRF material held in the secure-confirm worker |
| `warmSigning`          | The aggregate of warm-session readers and capability state    |
| `warmCapabilities`     | Capability metadata derived from a warm session               |
| `signingSession`       | Lane + budget + identity scope for one or more signing ops    |
| `walletSigningSession` | Server-issued wallet-scoped session ID for budget enforcement |
| `thresholdSession`     | Cryptographic threshold-protocol session (JWT or cookie auth) |
| `emailOtpSession`      | Email OTP step-up sub-session                                 |
| `appSession`           | Outer application session (JWT)                               |

A new contributor cannot reliably guess which axis a given `*Session*` type
varies on. Two concrete steps would help:

- Add a glossary block to `client/src/core/signingEngine/README.md` mapping each
  term to its axis (auth tier / storage tier / cryptographic scope / wallet
  identity) and to the canonical type that owns it.
- Where possible, rename to make the axis explicit:
  `warmSession` → `warmPrfCache`, `signingSession` → `signingScope`,
  `thresholdSession` → `thresholdProtocolSession`. This is invasive and should
  only follow the glossary, not lead it.

### 7. Session Files Are Heavy

Files:

- `client/src/core/signingEngine/session/persistence/records.ts` (2678 lines)
- `client/src/core/signingEngine/session/persistence/sealedSessionStore.ts` (2004 lines)
- `client/src/core/signingEngine/session/availability/availableSigningLanes.ts` (1729 lines)
- `client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts` (1565 lines)
- `client/src/core/signingEngine/session/passkey/ecdsaProvisioner.ts` (1390 lines)

These files are internally focused but each has reached the size where reading
them requires a search-driven workflow. The likely cause is that the underlying
record/identity types are broad enough that every operation has to live next to
the type definition.

This finding overlaps with Refactor 42 finding 2 (persistence records mix raw
storage, public identity, and hot signer material). Splitting the record types
along the lines Refactor 42 recommends should naturally split these files: each
narrower record type pulls its own operations into a separate module.

No standalone work is recommended here — fold the split into Refactor 42 if it
proceeds, and revisit only if Refactor 42 is deferred.

## Out of Scope

The following are working and should not be touched in this refactor:

- The Refactor 33 dependency rules. Grep confirms `flows/*` and `session/*` do
  not import `SigningEngine.ts`, no broad `index.ts` barrels exist, and the
  retired `api/`, `orchestration/`, `chainAdaptors/`, and `signers/` paths stay
  deleted.
- The operation state machine (`PreparedOperation`, `BudgetAdmittedOperation`,
  `SignedOperation` in `flows/shared/operationState.ts`).
- The chain isolation in `chains/evm/`, `chains/tempo/`, `chains/near/`.
- The sub-folder README convention — every directory has one and they are
  accurate.
- The discriminated unions and `?: never` branch guards introduced by Refactor
  42 in newer modules.

## Suggested Phasing

Phase 1 — collapse the `xxxPublic` indirection (findings 1, 3): done

- Pick one shape per `xxxPublic` module (factory or standalone, not both).
- Remove the `xxxValue` import aliases once the collisions disappear.
- Acceptance: zero `as xxxValue` aliases in `SigningEngine.ts`; each operation
  function has exactly one call site from the facade or a single sub-API.

Phase 2 — normalize port factories (finding 2): partially done

- Audit each `assembly/ports/*.ts` against the composition-vs-repacking rule.
- Inline or delete pure-repacking factories; keep composing factories.
- Acceptance: every remaining `assembly/ports/*.ts` builds at least one new
  behavior (reader, resolver, aggregate) rather than only renaming fields.

Implemented so far: `createEmailOtpPublicDeps` was removed and inlined because
it only repacked fields. Remaining port factories perform composition or need a
separate follow-up review before deletion.

Phase 3 — boundary parsing for bootstrap material (finding 5): done

- Move the `String(...).trim()` block out of
  `buildWalletRegistrationEcdsaSessionBootstrap` into a relayer-client parser.
- Acceptance: facade and bootstrap builder receive a validated shape; no
  defensive coercion below the relayer boundary.

Phase 4 — facade slimming (finding 4): deferred

- Decide between exposing `xxxPublic` aggregates on the class versus generating
  the flat facade. Coordinate with `SeamsPasskey` consumers.
- Acceptance: `SigningEngine.ts` under 600 lines, or its public surface is
  generated rather than hand-maintained.

Phase 5 — vocabulary glossary (finding 6): done

- Add the glossary to the top-level README.
- Defer renames until the glossary is in place and reviewed.
- Acceptance: every `*Session*` type in `interfaces/` and `session/` is linked
  from the glossary.

Finding 7 is folded into Refactor 42 and has no phase here.

## Non-Goals

- No changes to the SDK public surface in `client/src/core/SeamsPasskey/`
  beyond what is required to consume the slimmed facade.
- No changes to the worker protocol, threshold protocol, chain encoders, or
  WebAuthn primitives.
- No new dependency-graph rules; the Refactor 33 rules are sufficient.
