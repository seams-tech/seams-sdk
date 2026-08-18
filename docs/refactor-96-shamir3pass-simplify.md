# Refactor 96: Simplify Shamir 3-Pass Configuration

Date created: July 29, 2026

Status: implementation complete; deployment inventory pending

## Decision

Replace the four loose signing-session seal values with one 32-byte Gateway
root secret and versioned public protocol configuration.

The target deployment surface is:

```text
Secret:
  SIGNING_SESSION_SEAL_ROOT_SECRET_B64U

Public Gateway deployment config:
  currentKeyVersion
  acceptedWarmKeyVersions = [currentKeyVersion]
  algorithm = shamir3pass-v2
  groupId = rfc2409-group2
```

The server uses `shamir-3-pass` 0.6.0 to derive its durable lock key pair from
the root and a stable public context. The client uses the same crate through
the existing Wasm runtime to generate a fresh temporary lock key pair for
every lock or unlock operation. The crate owns the group definitions, key
derivation, validation, and modular arithmetic.

Delete these inputs after cutover:

```text
SIGNING_SESSION_SEAL_KEY_VERSION
SIGNING_SESSION_SHAMIR_P_B64U
SIGNING_SESSION_SEAL_E_S_B64U
SIGNING_SESSION_SEAL_D_S_B64U
VITE_SIGNING_SESSION_SEAL_KEY_VERSION
VITE_SIGNING_SESSION_SHAMIR_P_B64U
```

This refactor establishes the configuration rule for the rest of Router A/B:
public values live in typed deployment manifests, derived values are computed
at their owning boundary, and independent trust domains retain independent
root secrets.

## Upstream Release Basis

This plan targets [`shamir-3-pass` 0.6.0](https://crates.io/crates/shamir-3-pass/0.6.0),
released from the merged upstream `main` commit
`7b4f70ff24bb4286c2d35b161d92b3c7aab29136` and tagged `v0.6.0`. The
[GitHub release](https://github.com/peitalin/shamir-3-pass-rs/releases/tag/v0.6.0)
and [versioned API documentation](https://docs.rs/shamir-3-pass/0.6.0/shamir_3_pass/)
are public.

The release provides:

- `Shamir3Pass::default()` with the 1024-bit RFC 2409 group 2;
- explicit 768-bit and 2048-bit built-in groups;
- validated custom safe primes of at least 256 bits;
- `generate_lock_key_pair()` for fresh random lock keys;
- `derive_lock_key_pair(&root_secret, context)` for deterministic durable keys;
- opaque `LockKeyPair` and checked `GroupElement` values.

Router A/B initially selects `rfc2409-group2`. This matches the latency-first
TLS deployment model while avoiding a custom modulus. The public group ID is
versioned record metadata, so a later group change is an explicit protocol
migration.

## Why This Refactor Is Required

The current configuration models four Shamir values as Gateway secrets and
duplicates the key version and prime into frontend build variables. Their
actual roles differ:

- the prime is a public protocol parameter;
- the key version is public routing metadata;
- the decrypt exponent is determined by the encrypt exponent and prime;
- the encrypt exponent is the sole independent server-side Shamir key choice.

The present generators also prefer `65_537` for both server and client encrypt
exponents. Given public `p`, any observer can compute:

```text
d = e^-1 mod (p - 1)
```

Consequently, `e = 65_537` makes the corresponding inverse public. A stored
server-locked value can have that lock removed without the configured server
secret. Configuration cleanup must include removal of this deterministic
exponent path.

The deployment tooling already has the right operator entrypoint:
`wallet-core:deploy:env-prepare` invokes the identity, root-share, and
signing-session generators and builds one validated manifest. Keep that
workflow. Simplify the material it emits and the runtime inputs it installs.

## Scope

This plan owns:

1. the Shamir 3-pass public group definition;
2. server exponent derivation from one Gateway root secret;
3. secure random client exponent generation;
4. signing-session and Email OTP enrollment seal configuration;
5. browser/server capability agreement;
6. persisted Shamir record versioning and v1 migration boundaries;
7. local, self-hosted, staging, and production deployment inputs;
8. removal of obsolete generators, environment variables, fixtures, and
   source guards.

This plan preserves the existing three-pass lifecycle:

```text
Lock:
  client adds temporary lock
  server adds durable lock
  client removes temporary lock
  browser persists server-locked material

Unlock:
  client adds a fresh temporary lock
  server removes the durable lock
  client removes the temporary lock
  worker receives the original material
```

## Outside Scope

- Changing warm-session budgets, expiry, authorization, or idempotency.
- Replacing the Shamir 3-pass protocol with another custody protocol.
- Giving one deployment root to the Gateway, Router, SigningWorker, Deriver A,
  and Deriver B runtimes.
- Deriving the Deriver A and Deriver B MPC root shares from a runtime-accessible
  common secret.
- Deriving third-party credentials such as Stripe, Resend, RPC, or Cloudflare
  tokens.
- Preserving v1 warm-session records after the cutover deployment.

Broader Router A/B secret consolidation should use the trust-boundary rules in
this plan after the Shamir slice is complete and verified.

## Required Security And Lifecycle Invariants

1. `SIGNING_SESSION_SEAL_ROOT_SECRET_B64U` decodes to exactly 32 bytes at the
   environment boundary.
2. Raw environment strings never enter lock, unlock, or key-derivation core
   functions.
3. The group identifier selects one built-in group from `shamir-3-pass` 0.6.0.
   Active Router A/B paths cannot provide an arbitrary modulus.
4. The server exponent is deterministic for one `(root, algorithm, group,
   keyVersion)` tuple and domain-separated from every other derived key.
5. Changing the key version changes the derived server exponent.
6. The derived encrypt exponent is in range and coprime with `p - 1`.
7. The decrypt exponent is computed as the modular inverse of the encrypt
   exponent. It is never configured or derived independently.
8. Client exponent generation uses the cryptographic random generator on every
   operation. No preferred constant exponent remains.
9. Client exponent pairs remain inside the nested Shamir worker and are
   destroyed when the operation finishes.
10. A persisted v2 record requires an algorithm, group identifier, and key
    version. It never stores the prime or either exponent.
11. Lock always uses the configured current version. Unlock uses the
    exact version bound to the persisted record or durable enrollment.
12. Authenticated routes, session identity, remaining-use policy, expiry,
    idempotency, and single-flight behavior remain unchanged.
13. Deriver A and Deriver B keep independently stored MPC root shares.
14. A secret exposed by one runtime never enables derivation of another
    runtime's private material.
15. Logs, diagnostics, public manifests, test errors, and API responses never
    contain the root or derived exponents. The protected deployment apply
    artifact may contain the root with mode `0600`.

## Target Protocol Model

### Public Group

Define the supported wire group in shared TypeScript and map it directly to
the crate's built-in group:

```ts
export const SIGNING_SESSION_SEAL_ALGORITHM = 'shamir3pass-v2' as const;
export const SIGNING_SESSION_SEAL_GROUP_ID = 'rfc2409-group2' as const;

export type SigningSessionSealProtocol = {
  readonly algorithm: typeof SIGNING_SESSION_SEAL_ALGORITHM;
  readonly groupId: typeof SIGNING_SESSION_SEAL_GROUP_ID;
};
```

The crate is the cryptographic authority for the modulus and group validation.
TypeScript owns only the public wire identifier and an exhaustive mapping to
the Wasm group selector. Do not copy the prime into TypeScript, deployment
configuration, request bodies, or persisted records.

The active v2 type accepts only `rfc2409-group2`. The Wasm boundary may expose
the crate's 768-bit and 2048-bit selectors for explicit future protocol
versions, without making arbitrary group selection available to route bodies.

### Boundary Configuration

Normalize the Gateway input once:

```ts
type SigningSessionSealRootConfig = {
  readonly kind: 'shamir3pass_root_v2';
  readonly rootSecret32: Uint8Array;
  readonly currentKeyVersion: SigningSessionSealKeyVersion;
  readonly acceptedWarmKeyVersions: readonly SigningSessionSealKeyVersion[];
  readonly protocol: SigningSessionSealProtocol;
};
```

The environment parser owns base64url decoding, exact-length validation, and
public deployment-config parsing. Core constructors require
`SigningSessionSealRootConfig`; they cannot accept the old four-string bag.

Use a dedicated root. `RELAY_SESSION_HMAC_SECRET` and
`ACCOUNT_ID_DERIVATION_SECRET` have different persistence and rotation
lifecycles, so neither becomes the Shamir root.

### Server Lock-Key Derivation

Use the crate's `derive_lock_key_pair(&root_secret, context)` as the only
derivation implementation. Construct one canonical context from public,
length-delimited fields:

```text
seams/router-ab/signing-session-seal/<algorithm>/<groupId>/<keyVersion>/server-lock/v1
```

The Gateway normalizes the 32-byte root and canonical key version once. The
Rust/Wasm boundary selects the built-in group, derives the opaque pair, and
keeps it behind a runtime handle. Cache that handle for the runtime lifetime.
Node, Cloudflare, browser, and tests must not implement a second HKDF,
candidate-selection, inverse, or raw-exponent path.

Add behavioral vectors around the opaque crate boundary containing only an
explicit test root, algorithm, group, key version, derivation context, and an
apply/remove round trip. Derived exponents remain inaccessible by design.
Production roots and derived values never enter fixtures.

### Client Exponent Generation

Delete the local `pick_client_encrypt_exponent`, `gcd`, `mod_inverse`, and
random-candidate implementation from `wasm/shamir3pass_runtime/src/lib.rs`.
Use the `shamir-3-pass` crate's `generate_lock_key_pair()` operation, which
already generates a random invertible exponent with `getrandom` and calculates
its inverse.

Change the worker boundary from raw prime input to the precise protocol group:

```ts
createClientKeyHandle({ protocol })
```

The worker resolves the group, invokes Wasm key generation, stores the pair by
opaque handle, and returns only the handle. Existing zeroization and handle
destruction remain mandatory.

## Public Capability And Client Configuration

The well-known capability becomes:

```ts
type SigningSessionSealCapabilities =
  | { readonly mode: 'none' }
  | {
      readonly mode: 'sealed_refresh_v1';
      readonly protocol: SigningSessionSealProtocol;
      readonly currentKeyVersion: SigningSessionSealKeyVersion;
    };
```

Remove `signingSessionSeal.keyVersion` and `signingSessionSeal.shamirPrimeB64u`
from public SDK configuration. Sealed-refresh startup fetches the capability,
validates the supported algorithm and group, and retains the server's current
version for apply operations.

Lock responses return the exact key version used. Unlock requests take
their key version from the normalized persisted record. Client application
builds no longer need Shamir values, and server rotation no longer requires a
frontend rebuild.

The existing parity check should compare mode, algorithm, and group support.
The server controls its current key version, so a version difference is no
longer a frontend configuration error.

## Persistence And Rotation

### Warm Signing Sessions

Introduce a strict v2 record:

```ts
type SealedSigningSessionRecordV2 = {
  readonly v: 2;
  readonly alg: 'shamir3pass-v2';
  readonly groupId: 'rfc2409-group2';
  readonly keyVersion: SigningSessionSealKeyVersion;
  readonly sealedSecretB64u: string;
  // Existing required identity, curve, policy, expiry, and restore fields.
};
```

Remove `shamirPrimeB64u` and optional `keyVersion` from the active domain type.
At the IndexedDB boundary, delete v1 warm-session records when encountered.
Their lifetime is already bounded; the user obtains fresh material through the
normal authenticated path.

### Durable Email OTP Enrollment Material

Email OTP device enrollment escrow uses the same Shamir server key and can
outlive a warm session. The active browser record is strict v2 and requires the
algorithm, group, and enrollment seal key version. V1 records fail closed at
the persistence boundary.

Before deployment, run a read-only production inventory for durable v1
enrollments. If any exist, require those users to re-enroll during the cutover
window. This repository does not retain raw-prime or raw-exponent compatibility
code for opening v1 records.

### Key-Version Rotation

The stable root can derive an independent exponent pair for every canonical key
version. Existing records carry the version required for unlock. The typed
Gateway configuration maintains a short `acceptedWarmKeyVersions` list so the
public seal route cannot request arbitrary derived versions. The server derives
only versions accepted by the operation:

- apply uses `currentKeyVersion` from typed Gateway configuration;
- warm unlock requires the normalized record version to appear in
  `acceptedWarmKeyVersions`;
- Email OTP enrollment unlock obtains the version from the server-side durable
  enrollment record through an internal typed path.

Route bodies never select an unrestricted derivation label. During ordinary
rotation, retain the previous warm version for the maximum warm-session TTL,
then remove it from `acceptedWarmKeyVersions`.

Rotating `currentKeyVersion` creates new seals under the new derived pair while
the stable root continues to open explicitly accepted warm versions and exact
durable enrollment versions. A root-secret rotation requires rewrapping durable
enrollments under a new root and stays a separately audited emergency
operation.

## Deployment Configuration

### Hosted Router A/B

Update `wallet-core:deploy:env-prepare` so it:

1. generates one random 32-byte Shamir root;
2. stores the root only in the Gateway environment;
3. writes algorithm, group, and current key version into
   `GATEWAY_DEPLOYMENT_CONFIG_JSON`;
4. omits all six retired server and frontend variables;
5. validates that no other component receives the root;
6. stores the root in the existing mode-`0600` local apply artifact required by
   the prepare/apply workflow;
7. includes only a redacted marker in terminal, JSON summary, audit metadata,
   and diagnostic output.

The generated deployment manifest remains the single setup workflow. Remove
the old signing-session material subprocess from
`generate-github-env-values.mjs`.

### Self-Hosted And Local Development

Replace the old standalone key generator with a root-only command that prints:

```text
SIGNING_SESSION_SEAL_ROOT_SECRET_B64U=<32 random bytes>
```

Local development generates and persists one local root in its generated
runtime directory. Checked-in Wrangler configuration contains the public v2
protocol selection and no reusable private exponent. Delete the checked-in
`AQAB` exponent and inverse.

### Router A/B Secret Rules

Classify every deployment input according to these rules during this phase:

| Class | Treatment |
| --- | --- |
| Public topology, URLs, IDs, versions, public keys | Typed deployment manifest or Worker variable |
| Value determined by another configured value | Derive at the owning boundary |
| Private values inside one runtime trust boundary | Candidate for a per-component root with domain-separated derivation |
| Deriver A/B MPC root shares | Independently generated and separately stored |
| Cross-runtime authentication secret | Retain until replaced by an authenticated platform binding or signed service identity |
| Third-party credential | Independently configured secret |

Do not expand this change into a global Router A/B root. Record a follow-up
inventory showing which remaining environment variables are public,
derivable, independently secret, external, or obsolete. That inventory will
define the next bounded simplification.

## Implementation Phases

### Phase 0: Consume The Upstream Release

- [x] Publish `shamir-3-pass` 0.6.0 to crates.io.
- [x] Tag the merged upstream commit as `v0.6.0`.
- [x] Create the GitHub release with migration and security notes.
- [x] Verify the versioned API documentation is live on docs.rs.
- [x] Update `wasm/shamir3pass_runtime` from 0.5 to 0.6.0.
- [x] Regenerate the Wasm package through the existing build path.

Exit condition: the workspace resolves `shamir-3-pass` 0.6.0 from crates.io
and no active manifest references 0.5.

### Phase 1: Freeze The V2 Protocol

- [x] Select the crate's 1024-bit RFC 2409 group 2 as the initial group.
- [x] Add the shared algorithm/group types and exhaustive Wasm group mapping.
- [x] Define the canonical server-lock derivation context encoding.
- [x] Add fixed root/context and domain-separation coverage around the opaque API.
- [x] Add a client/server three-pass round-trip through the Wasm runtime.

Exit condition: the upstream checked key-pair constructor owns the inverse
invariant, and a client/server three-pass round trip returns the original
material without exposing either exponent.

### Phase 2: Adopt Opaque Lock Keys

- [x] Replace the client `65_537` path with `generate_lock_key_pair()`.
- [x] Add the exact-length server root parser.
- [x] Derive the durable server pair through `derive_lock_key_pair()`.
- [x] Keep client and server pairs behind opaque Wasm runtime handles.
- [x] Make cipher construction require normalized v2 root configuration.
- [x] Delete local GCD, inverse, random-candidate, raw-prime, and raw-exponent
  implementations from active core paths.

Exit condition: production code contains no preferred or configured Shamir
exponent, and focused crypto tests pass.

### Phase 3: Cut Over Capabilities And Active Records

- [x] Replace raw prime/key-version client config with capability negotiation.
- [x] Make v2 persisted record fields required.
- [x] Remove the prime from records, worker requests, transports, and cache keys.
- [x] Delete v1 warm records at the persistence boundary.
- [x] Update passkey, Email OTP ECDSA, and Email OTP Ed25519 Yao unlock paths to
  use the protocol object.

Exit condition: a new browser session locks, reloads, unlocks, and signs for
each supported auth method and curve without Shamir frontend environment
variables.

### Phase 4: Cut Over Durable Email OTP Enrollments

- [x] Make new browser enrollment escrow records strict v2 with a required group.
- [x] Reject v1 enrollment escrow records at the persistence boundary.
- [ ] Inventory production v1 durable enrollment records before deployment.
- [ ] Publish the re-enrollment window and operator runbook when the inventory is
  non-zero.

Exit condition: production inventory and the re-enrollment decision are
recorded, active durable enrollments use v2, and the runtime accepts no v1
material.

### Phase 5: Simplify Deployment Inputs

- [x] Replace the four Gateway Shamir secrets with the root secret.
- [x] Move public protocol selection into the Gateway deployment config.
- [x] Remove the two Vite variables and frontend propagation code.
- [x] Update local runtime generation and self-host documentation.
- [x] Delete the old material generator and stale environment assertions.
- [ ] Produce the follow-up Router A/B environment classification inventory.

Exit condition: a clean target can be prepared and deployed with one Shamir
secret, zero Shamir frontend variables, and no manual exponent or prime setup.

## Expected Code Areas

### Shared Protocol And Server Crypto

- `packages/shared-ts/src/utils/signingSessionSeal.ts`
- `packages/wallet-server/package.json`
- `packages/wallet-server/src/core/types.ts`
- `packages/wallet-server/src/core/keyMaterialBrands.ts`
- `packages/wallet-server/src/threshold/session/signingSessionSeal/crypto/cipher.ts`
- `packages/wallet-server/src/threshold/session/signingSessionSeal/options.ts`
- `packages/wallet-server/src/router/cloudflare/d1RouterApiAuthConfig.ts`
- `packages/wallet-server/src/router/cloudflare/d1EmailOtpServerSealRuntime.ts`

### Browser And Wasm

- `wasm/shamir3pass_runtime/src/lib.rs`
- `packages/wallet/src/core/signingEngine/workerManager/workers/shamir3pass.worker.ts`
- `packages/wallet/src/core/signingEngine/workerManager/workers/shamir3pass/runtime.ts`
- `packages/wallet/src/core/rpcClients/relayer/sealedRefreshCapabilities.ts`
- `packages/wallet/src/core/config/configBuilder.ts`
- `packages/wallet/src/core/types/seams.ts`
- `packages/wallet/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `packages/wallet/src/core/indexedDB/seamsWalletDB/emailOtpDeviceEnrollmentEscrows.ts`

### Hosted And Local Deployment

- `deployment/targets.json`
- `scripts/deployment-targets.mjs`
- `scripts/deploy-backend.mjs`
- `crates/router-ab-cloudflare/scripts/generate-github-env-values.mjs`
- `packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker.ts`
- `packages/console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts`
- `packages/console-server-ts/wrangler.d1-local.toml`
- `crates/router-ab-dev/scripts/d1-local-runtime-config.mjs`
- `apps/seams-site/src/config.ts`
- `apps/seams-site/vite.config.ts`
- `apps/seams-site/vite-env.d.ts`
- `apps/web-server/scripts/generate-signing-session-seal-keys.mjs`
- `docs/deployment/tooling.md`

The implementation should stay linear within each phase. Reuse the existing
cipher, route, worker-handle, capability, and persistence boundaries. Avoid a
general key-management framework.

## Test Classification And Validation

Before changing a failing test, classify it under the repository policy.
Expected classifications are:

- round-trip, authorization, idempotency, budget, expiry, and exact-record
  recovery failures: `production_regression`;
- fixtures with valid lifecycle behavior and old v1 fields:
  `valid_test_needs_update`;
- assertions requiring raw prime/exponent environment variables, `AQAB`, or
  optional v1 record fields: `obsolete_test_or_fixture`;
- Redis, RPC, browser, or deployment-provider failures unrelated to the
  protocol: `environment_or_infrastructure_failure`.

Required focused coverage:

1. root parsing rejects empty, malformed, short, and long inputs;
2. the frozen crate vector derives the expected opaque lock-key pair;
3. version and group domain separation change the pair;
4. imported and derived values pass the crate's checked constructors;
5. two client key generations produce distinct exported test vectors;
6. server apply/remove and the complete three-pass flow recover exact bytes;
7. wrong root, version, or group cannot unlock valid material;
8. v2 record parsers reject missing key version or group and reject raw prime
   fields;
9. v1 warm records are removed at read;
10. authenticated durable enrollment migration is atomic and idempotent;
11. capability discovery works without frontend Shamir variables;
12. generated deployment manifests contain the root only in the Gateway and
    contain none of the retired names.

Run the narrowest relevant commands while implementing. Final validation for
the complete change includes:

```text
cargo test --manifest-path wasm/shamir3pass_runtime/Cargo.toml
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/signingSessionSeal.shared.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/sealedRefresh.parity.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/sealedSessionStore.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/emailOtpDeviceEnrollmentEscrowStore.unit.test.ts --reporter=line
pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/touchConfirm.workerRouter.integration.test.ts --reporter=line
pnpm test:intended
pnpm check
```

Run deployment script tests after the manifest phase. Remove source guards that
exist solely to require the retired variable names.

## Completion Criteria

- Hosted and self-hosted setup requires one Shamir root secret.
- The algorithm, group, and current version are public typed protocol
  configuration; the prime remains owned by the crate.
- Active manifests depend on `shamir-3-pass` 0.6.0 or later within the 0.6
  compatibility line.
- No server or client code prefers `65_537` as a Shamir exponent.
- No environment or request boundary accepts raw encrypt/decrypt exponent
  pairs for active v2 behavior.
- Frontend builds carry no Shamir prime or key version.
- V2 warm and durable records contain a required group and key version and no
  raw prime.
- Passkey and Email OTP sessions unlock exact Ed25519 and ECDSA material.
- Durable Email OTP enrollment migration is complete or proven unnecessary.
- Temporary v1 migration code and inputs are deleted.
- Deriver A and Deriver B root-share separation remains unchanged.
- Deployment preparation, intended-behavior contracts, focused crypto tests,
  type checks, and repository checks pass.
