# Refactor 102: Remove The ECDSA Commitment Policy

Date created: July 19, 2026

Status: Implemented in the repository; staging deployment remains an explicit external operation.

Environment assumption: Router A/B is running in a staging test environment.
There is no live-production compatibility, zero-downtime, maintenance-window,
or old-client migration requirement. The refactor targets the simpler end
state directly.

## Goal

Remove the Router A/B ECDSA commitment policy and all deployment machinery
created for it.

The final system has:

- no commitment policy;
- no commitment registry;
- no release or commitment authority keys;
- no policy or registry provisioning command;
- no commitment-policy build variables;
- no `ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON`;
- no policy freshness receipts or artifact pin checks;
- no policy or registry object in Router responses.

Each Deriver proof already contains its public share commitment. The recipient
verifies the DLEQ proof directly against that commitment, verifies the fixed
Deriver role and share ID, and requires the A/B proof pair to agree on
lifecycle ID, root-share epoch, transcript, recipient, signer identities, and
peer identities.

This intentionally removes the independent precommitted-root trust layer.
The recipient no longer verifies that the pair's signer identities or
root-share epoch equal an independently configured signer set or root record.
It verifies pair consistency and proof correctness. Deployment simplicity is
the priority.

## Step 1: Simplify The Cryptographic Protocol

Remove the policy and registry types from
`crates/router-ab-ecdsa-client-protocol` and remove the registry requirement
from every `router-ab-core` combine path.

Primary scope:

- `crates/router-ab-ecdsa-client-protocol/src/lib.rs`;
- `crates/router-ab-ecdsa-client-protocol/src/recipient_proof.rs`;
- `crates/router-ab-core/src/derivation/ecdsa_commitment_registry.rs`;
- `crates/router-ab-core/src/derivation/ecdsa_threshold_prf.rs`;
- `crates/router-ab-core/src/derivation/ecdsa_threshold_prf_backend.rs`;
- `crates/router-ab-core/src/derivation/mod.rs`;
- `crates/router-ab-core/src/protocol/output.rs`;
- `crates/threshold-prf/tests/client_protocol_verification.rs`.

Delete:

- `EcdsaCommitmentPolicyPinsV1`;
- `EcdsaCommitmentPolicyManifestV1`;
- `EcdsaSignedCommitmentPolicyV1`;
- commitment authority and signed commitment record types;
- `EcdsaCommitmentRegistryDeliveryV1`;
- `EcdsaAuthenticatedCommitmentRegistryV1`;
- policy and record signature verification;
- release epochs, authority epochs, revocations, policy digests, and validity
  checks owned only by the registry.

Change finalization so it accepts the paired A/B proof bundles directly. It
must:

1. require Deriver A in the A slot with share ID `1`;
2. require Deriver B in the B slot with share ID `2`;
3. verify each DLEQ against the commitment carried in that proof bundle;
4. require both bundles to agree on lifecycle ID, root-share epoch, transcript,
   recipient, signer identities, and peer identities;
5. preserve transcript, recipient, and output-purpose proof validation;
6. combine the two verified partials.

Remove `RootShareCommitmentRegistryV1` from:

- `MpcPrfThresholdCombineInputV1`;
- `MpcPrfThresholdBatchCombineInputV1`;
- single-output recipient combination;
- batch recipient combination;
- SigningWorker activation combination;
- every Cloudflare adapter call into those functions.

Delete `AuthenticatedRootShareCommitmentV1`,
`RootShareCommitmentRegistryV1`, the commitment-registry module, and their
registry-specific error variants. The core verifier uses the commitment carried
by each role-bound proof bundle.

Remove the now-unused Ed25519 dependency from the client protocol.

Exit condition: threshold-PRF finalization has no policy or registry input.

## Step 2: Remove The Registry From Runtime Messages

Remove `commitmentRegistry` from every registration, activation-refresh, and
export response.

Update:

- `crates/router-ab-cloudflare`;
- `wasm/router_ab_ecdsa_derivation_client`;
- `packages/shared-ts`;
- `packages/sdk-web`;
- affected server adapters and fixtures.

The browser finalizer input contains only the encrypted A/B bundles. Remove
`verificationTimeMs`; it has no remaining time-based policy or record check.

The SigningWorker verifies its decrypted A/B bundles through the same direct
DLEQ path.

Delete all Cloudflare registry loading and forwarding code.

Exit condition: no runtime request or response contains a policy or commitment
registry.

## Step 3: Remove Local Build And Router Checks

Delete:

- `.env.router-ab.ecdsa-commitment-policy.build.local`;
- `crates/router-ab-dev/scripts/run-with-commitment-policy-build-env.mjs`;
- commitment-policy loading from local commands;
- compile-time pin inspection from `dev-local-workers.mjs`;
- policy hashes from Worker build receipts;
- the browser policy mismatch check;
- commitment-policy preflight checks from WASM and strict Worker builds.

Change the root scripts so:

```text
pnpm build:wasm
pnpm build:sdk
pnpm build:sdk-full
```

invoke their real build commands directly.

`pnpm router` should only stop existing port listeners, confirm required build
artifacts exist, and start the topology.

Exit condition: local builds and `pnpm router` never read or compare commitment
policy values.

## Step 4: Delete Commitment Provisioning

Extract local root-share generation from
`local_ecdsa_commitment_policy.rs` into a narrowly named root-share generator
first. Preserve:

- deterministic local root generation;
- fixed 2-of-2 share splitting;
- Deriver A share ID `1`;
- Deriver B share ID `2`;
- root-share secret encoding and materialization.

After that extraction, delete the remaining commitment-policy and
commitment-registry generation code from `router-ab-dev`.

Delete the production commitment provisioning command, including:

- release-authority private-key input;
- role commitment-authority private-key input;
- policy manifest generation;
- role record signing;
- registry assembly;
- build-pin output.

Keep the existing root-share generation and secret distribution needed by
Deriver A and Deriver B. A Deriver computes its public commitment from its
loaded root share when producing a proof.

Exit condition: deploying or rotating root shares requires no commitment
policy or registry provisioning step.

## Step 5: Simplify Deployment

Remove these variables from CI, SDK publishing, Pages deployment, Router A/B
deployment, GitHub Environments, and deployment documentation:

```text
ROUTER_AB_ECDSA_COMMITMENT_POLICY_RELEASE_AUTHORITY_PUBLIC_KEY_HEX
ROUTER_AB_ECDSA_COMMITMENT_POLICY_DIGEST_HEX
ROUTER_AB_ECDSA_COMMITMENT_POLICY_MINIMUM_RELEASE_EPOCH
ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON
```

Remove every validation step, build argument, Wrangler variable, deployment
receipt, and error message associated with them.

Do not replace them with a new registry variable, digest, receipt, authority,
or provisioning file.

Deployment continues to provide the existing Deriver root-share secrets, HPKE
keys, peer authentication keys, Router authentication configuration, and
SigningWorker configuration.

Exit condition: SDK and Worker deployment has zero commitment-policy or
commitment-registry inputs.

## Step 6: Delete Obsolete Tests And Update The Security Contract

Delete tests, fixtures, and source guards for:

- build pins;
- policy signatures;
- signed commitment records;
- release or authority rotation;
- revocation lists;
- policy rollback;
- registry provisioning;
- policy artifact freshness.

Keep tests for:

- malformed proof bundles;
- invalid DLEQ proofs;
- A/B role and share-ID swaps;
- transcript mismatch;
- recipient mismatch;
- output-purpose mismatch;
- root-share-epoch mismatch;
- mixed A/B proof contexts.

Update `crates/router-ab-core/specs/ecdsa-threshold-prf.md` and active security
documentation to state that proof commitments are self-contained DLEQ inputs.
Remove claims about an independently authenticated commitment root,
configuration substitution resistance, policy revocation, and rollback floors.

Run:

```bash
cargo test --manifest-path crates/router-ab-ecdsa-client-protocol/Cargo.toml
cargo test --manifest-path crates/router-ab-core/Cargo.toml
cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml
cargo test --manifest-path crates/router-ab-dev/Cargo.toml
cargo test --manifest-path crates/threshold-prf/Cargo.toml
pnpm -C packages/sdk-web type-check
pnpm build:sdk-full
```

Exit condition: active tests and documentation describe only direct proof
verification.

## Step 7: Replace The Staging Deployment

Deploy the SDK, gateway, Router, Derivers, and SigningWorker from the completed
revision.

1. Delete the four obsolete GitHub Environment variables.
2. Retire the release-authority key and both role commitment-authority keys.
3. Build the SDK and all Workers without policy or registry inputs.
4. Deploy the staging topology.
5. Test registration, activation refresh, ECDSA signing, and export.
6. Test invalid DLEQ, role swap, transcript mismatch, recipient mismatch, and
   root-share-epoch mismatch rejection.
7. Fix any failure in the new implementation and redeploy.

Do not add a maintenance mode, compatibility parser, dual response shape,
versioned policy endpoint, cache cutover, migration state, or retained policy
configuration.

Exit condition: staging runs with proof-contained commitments and no
commitment deployment configuration.

## Definition Of Done

The work is complete when this search returns no references in active source,
workflows, tests, build scripts, or current protocol specifications:

```bash
rg -n \
  'ROUTER_AB_ECDSA_COMMITMENT_POLICY_|ROUTER_AB_ECDSA_COMMITMENT_REGISTRY_JSON|EcdsaCommitmentPolicy|EcdsaSignedCommitmentPolicy|EcdsaCommitmentRegistryDelivery|RootShareCommitmentRegistryV1|commitment_registry|commitmentRegistry' \
  package.json \
  .github/workflows \
  crates/router-ab-cloudflare \
  crates/router-ab-core \
  crates/router-ab-dev \
  crates/router-ab-ecdsa-client-protocol \
  crates/threshold-prf \
  packages/shared-ts \
  packages/sdk-web \
  tests \
  wasm/router_ab_ecdsa_derivation_client
```

Historical security evidence may retain clearly marked descriptions of the
removed design.
