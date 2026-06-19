# Router A/B Deployment Choices

Date created: June 12, 2026

Status: completed decision memo; superseded for active implementation.

Related docs:

- [Router A/B signer plan](router-A-B-signer.md)
- [Router A/B signer spec](router-A-B-signer-SPEC.md)
- [Router A/B local development](router-a-b-local-dev.md)
- [Deployment runbook](deployment/README.md)
- [Deployment infrastructure](deployment/infra.md)

## Completion Note

This document made the deployment-profile decision: same-account Cloudflare is
the first production self-host target, separate Cloudflare accounts are a
hardening profile, and provider-diverse signers remain future enterprise scope.

The active same-account implementation now lives in the checked-in Wrangler
configs, GitHub Actions workflows, local parity harness, and deployment runbook:

- `.github/workflows/router-ab.yml`
- `.github/workflows/deploy-router-ab.yml`
- `crates/router-ab-cloudflare/wrangler.router.toml`
- `crates/router-ab-cloudflare/wrangler.signer-a.toml`
- `crates/router-ab-cloudflare/wrangler.signer-b.toml`
- `crates/router-ab-cloudflare/wrangler.signing-worker.toml`
- `docs/deployment/README.md`
- `docs/deployment/infra.md`
- `docs/router-a-b-local-dev.md`

Use this file as a historical architecture memo and product framing reference.
Do not use the implementation checklist below as the active deployment plan.

## Goal

Support Router A/B as the default production self-host architecture while
keeping deployment simple through infrastructure-as-code.

The product surface should stay:

```text
Customer deploys one wallet backend profile.
Users and apps see one public Router URL.
Router, Signer A, and Signer B use role-separated runtime and storage.
Transport and credentials are selected by deployment profile.
```

The same Router A/B protocol should run in three deployment scenarios:

1. same Cloudflare account
2. separate Cloudflare accounts
3. provider-diverse signers

The SDK must not fork protocol semantics across these scenarios. It should
fork only the transport, credential, storage, observability, and deployment
adapters.

## Security Position

Router A/B is superior to a one-Worker production self-host profile because no
single Worker process needs both A and B role-local derivation material.

The one-Worker profile may remain useful for local development, tests,
evaluation, and emergency portability. It should not be the recommended
production self-host profile.

Production self-host default:

```text
router_ab_cloudflare_same_account_v1
```

Operational hardening profile:

```text
router_ab_cloudflare_separate_accounts_v1
```

Highest-assurance profile:

```text
router_ab_provider_diverse_v1
```

## Common Architecture

All Router A/B deployment profiles share the same logical roles:

```text
Client -> Router -> Signer A / Relayer
                 -> Signer B

Signer A <-> Signer B for derivation-time coordination where required.
Normal signing remains Client -> Router -> Signer A / Relayer.
```

Common invariants:

- Router is the only public wallet backend endpoint.
- Router handles auth, policy, rate limits, replay, and public lifecycle state.
- Router receives only public metadata and encrypted signer envelopes.
- Signer A receives only A envelopes, A root-share storage, and A decrypt
  credentials.
- Signer B receives only B envelopes, B root-share storage, and B decrypt
  credentials.
- Signer A initially hosts the relayer role and may activate `x_relayer_base`.
- No single production process receives both raw sides of protected split
  derivation material.
- Every signer response and output package binds to the same transcript.

## Deployment Profile Matrix

| Profile                                     | Transport                                                    | Credential boundary                                                       | Operational security                                                                                          | Intended use                                |
| ------------------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- | ------------------------------------------- |
| `router_ab_cloudflare_same_account_v1`      | Cloudflare Service Bindings                                  | separate Worker secrets and bindings in one Cloudflare account            | protects against single Worker compromise and accidental role mixing; weaker against account-admin compromise | default self-host production                |
| `router_ab_cloudflare_separate_accounts_v1` | authenticated HTTPS between Cloudflare accounts              | separate account credentials, deploy tokens, secrets, logs, and storage   | stronger against insider, CI token, and single-account compromise                                             | hardened self-host production               |
| `router_ab_provider_diverse_v1`             | authenticated HTTPS or mutually authenticated provider links | separate provider credentials, optional attestation-bound signer identity | strongest operational separation, highest complexity                                                          | enterprise / regulated / high-value custody |

## Signer Engine Modes

Transport profile and signer engine mode are separate choices.

```ts
type RouterAbSignerEngineMode =
  | {
      kind: 'hss_server_blind_v1';
      trustedHardwareRequired: false;
    }
  | {
      kind: 'tee_accelerated_threshold_v1';
      trustedHardwareRequired: true;
      attestationPolicyDigest: string;
    };
```

### HSS Server-Blind Mode

`hss_server_blind_v1` is the portable default.

Properties:

- runs on commodity serverless infrastructure
- does not require TEEs, enclave measurements, or secret-release services
- preserves server-blindness without trusted hardware
- supports same-account Cloudflare, separate-account Cloudflare, and
  provider-diverse non-TEE deployments
- adds HSS overhead during derivation/bootstrap flows, with current visible
  latency work concentrated on Ed25519 registration

Use this mode when self-hostability and low operational burden matter more than
the lowest possible bootstrap latency.

### TEE-Accelerated Threshold Mode

`tee_accelerated_threshold_v1` is a hardened low-latency mode for customers
that can operate, or pay us to operate, attested signer environments.

Properties:

- Router A/B topology remains intact
- Signer A and Signer B run inside approved TEE or enclave boundaries
- role-local key shares are released only to attested signer code
- signer identity binds role, key epoch, deployment epoch, provider, and
  attestation measurement
- HSS can be bypassed for a non-HSS threshold signer path where the TEE boundary
  supplies the server-blindness and tamper-resistance assumptions
- bootstrap and signing latency can improve because the signer engine no longer
  pays the HSS hidden-evaluation cost

This mode is an extension of Router A/B, not a replacement. The Router,
capability document, transcript binding, signer-set identity, migration
semantics, and client SDK behavior should remain stable.

Required controls:

- public or relying-party-verifiable attestation evidence
- allowlisted enclave measurements
- explicit secret-release policy
- signed deployment manifests
- constrained upgrade policy
- signer key epoch and deployment epoch rotation
- audit evidence for enclave image changes and secret release

Risk tradeoff:

```text
HSS mode derives server-blindness from cryptographic protocol boundaries.
TEE mode derives part of that protection from attested execution and
secret-release policy.
```

The SDK should expose the mode explicitly so customers and app developers can
set a security and latency policy rather than accidentally changing trust
assumptions.

## Customizable Transport And Credentials Layer

Router A/B core should depend on a small deployment-neutral host interface.
Deployment profiles implement that interface.

```ts
type RouterAbDeploymentProfile =
  | {
      kind: 'router_ab_cloudflare_same_account_v1';
      cloudflareAccountId: string;
      transport: CloudflareServiceBindingTransport;
      credentials: SameAccountCloudflareCredentials;
      signerEngineMode: { kind: 'hss_server_blind_v1' };
    }
  | {
      kind: 'router_ab_cloudflare_separate_accounts_v1';
      routerAccountId: string;
      signerAAccountId: string;
      signerBAccountId: string;
      transport: AuthenticatedHttpsTransport;
      credentials: SeparateAccountCloudflareCredentials;
      signerEngineMode: { kind: 'hss_server_blind_v1' };
    }
  | {
      kind: 'router_ab_provider_diverse_v1';
      routerProvider: ProviderDeploymentRef;
      signerAProvider: ProviderDeploymentRef;
      signerBProvider: ProviderDeploymentRef;
      transport: AuthenticatedProviderTransport;
      credentials: ProviderDiverseCredentials;
      attestationPolicy: SignerAttestationPolicy;
      signerEngineMode: RouterAbSignerEngineMode;
    };
```

Core runtime interfaces:

```ts
type RouterAbTransport =
  | {
      kind: 'cloudflare_service_binding';
      callSignerA(request: RouterToSignerPayload): Promise<SignerResponse>;
      callSignerB(request: RouterToSignerPayload): Promise<SignerResponse>;
    }
  | {
      kind: 'authenticated_https';
      callPeer(peer: PeerEndpoint, request: CanonicalWireMessage): Promise<CanonicalWireMessage>;
    };

type RouterAbCredentialProvider = {
  workerIdentity(): Promise<WorkerIdentity>;
  signerIdentity(role: 'A' | 'B'): Promise<SignerIdentity>;
  relayerIdentity(): Promise<RelayerIdentity>;
  signTranscript(input: TranscriptSigningInput): Promise<TranscriptSignature>;
  decryptRoleEnvelope(input: RoleEnvelopeDecryptInput): Promise<RoleEnvelopePlaintext>;
  unwrapRoleShare(input: RoleShareUnwrapInput): Promise<RoleLocalShareWire>;
};
```

These interfaces are illustrative. The implementation should live in Rust core
host traits and TypeScript/Cloudflare adapters where each runtime needs them.
The important boundary is that protocol code receives typed capabilities, not
ambient environment variables, broad account clients, or generic key/value
storage.

## Scenario 1: Same Cloudflare Account

This is the default production self-host profile.

```text
Cloudflare account:
  Router Worker
  Signer A Worker / Relayer
  Signer B Worker
  ROUTER_REPLAY_DO
  ROUTER_LIFECYCLE_DO
  SIGNER_A_ROOT_SHARE_DO
  SIGNER_A_RELAYER_OUTPUT_DO
  SIGNER_B_ROOT_SHARE_DO
  same-account Service Bindings
```

Transport:

- Router calls Signer A and Signer B through Service Bindings.
- Signer A and Signer B call each other through Service Bindings when direct
  A/B coordination is needed.
- No Signer Worker needs a public URL.

Credential boundary:

- Router has Router signing credentials, public signer registry, replay
  Durable Object binding, lifecycle Durable Object binding, and Service
  Bindings to A and B.
- Router must not have signer decrypt keys, root-share Durable Object bindings,
  or relayer-output bindings.
- Signer A has A decrypt credentials, A root-share binding, A relayer-output
  binding, Signer B peer binding, and A transcript-signing credentials.
- Signer B has B decrypt credentials, B root-share binding, Signer A peer
  binding, and B transcript-signing credentials.

IaC requirements:

- Generate one repository template with three Worker configs.
- Generate distinct GitHub Actions jobs for Router, Signer A, and Signer B.
- Use separate GitHub Environments for Router, A, and B secrets.
- Add deploy-time checks that reject forbidden bindings per role.
- Add smoke tests proving Router cannot access signer stores, A cannot access
  B stores, and B cannot access A or relayer-output stores.

Security claim:

```text
No single Worker process has both A and B role-local derivation material.
```

Residual risk:

```text
A Cloudflare account administrator or overbroad CI token may be able to modify
multiple Worker scripts or attach forbidden bindings.
```

This profile is still much stronger than a one-Worker self-host profile. It is
the right default because infrastructure-as-code can hide most deployment
complexity from the customer.

## Scenario 2: Separate Cloudflare Accounts

This is the operational hardening profile.

```text
Cloudflare account 1:
  Router Worker
  ROUTER_REPLAY_DO
  ROUTER_LIFECYCLE_DO

Cloudflare account 2:
  Signer A Worker / Relayer
  SIGNER_A_ROOT_SHARE_DO
  SIGNER_A_RELAYER_OUTPUT_DO

Cloudflare account 3:
  Signer B Worker
  SIGNER_B_ROOT_SHARE_DO
```

Transport:

- Router calls A and B over authenticated HTTPS.
- A and B call each other over authenticated HTTPS when direct A/B
  coordination is needed.
- Service Bindings are replaced by endpoint URLs, pinned peer identities, and
  request authentication.

Credential boundary:

- Each Cloudflare account has its own deploy credentials.
- Each account has its own GitHub Environment or external CI trust root.
- Each account owns only its role-specific Durable Object namespaces and
  secrets.
- Router account stores only public lifecycle and replay state.
- Signer A and Signer B accounts each store only their own root-share state.
- Logs, alerts, and audit exports are separate per account.

Required authenticated transport properties:

- mutual request authentication or equivalent signed request envelopes
- replay protection at every role boundary
- signer identity and key epoch pinned by Router policy
- endpoint deployment epoch bound into the transcript
- explicit peer allowlist for Router, A, B, and relayer identities
- fail-closed behavior when an endpoint presents the wrong role or key epoch

Security claim:

```text
Compromise of one Cloudflare account should not grant access to the other
signer role's root-share storage, deploy credentials, or logs.
```

Residual risk:

```text
Cloudflare platform-level compromise or collusion of both signer accounts can
still compromise server-side custody.
```

This profile is intended for customers concerned about insiders, overbroad
account admin access, long-lived CI tokens, or accidental role binding in one
Cloudflare account.

## Scenario 3: Provider-Diverse Signers

This is the highest-assurance profile.

```text
Cloudflare:
  Router Worker

Provider A:
  Signer A / Relayer
  A root-share storage
  optional TEE or enclave boundary

Provider B:
  Signer B
  B root-share storage
  optional TEE or enclave boundary
```

Example provider placements:

- Router on Cloudflare, Signer A on AWS Nitro Enclave-backed service, Signer B
  on Google Cloud Confidential VM.
- Router on Cloudflare, Signer A and Signer B on two independent customer
  Kubernetes clusters with separate KMS roots.
- Router on customer infrastructure, A and B on two managed enclave providers.

Transport:

- authenticated HTTPS or mutually authenticated provider links
- canonical Router A/B wire messages
- no provider-specific RPC in protocol-critical bytes
- optional attestation evidence carried alongside signer identity

Credential boundary:

- each provider has separate deploy credentials
- each signer role has independent unwrap/decrypt credentials
- attested signer identity can bind provider, measurement, signing key,
  protocol version, and deployment epoch
- Router policy decides which attested signer identities are acceptable

Security claim:

```text
Compromise of Cloudflare alone does not expose Signer A or Signer B plaintext.
Compromise of one signer provider exposes only that signer role.
```

Residual risk:

```text
This profile has more operational complexity, higher latency, and a larger
incident-response surface.
```

Provider-diverse deployment should reuse the same wire vectors and transcript
binding as Cloudflare deployments. Adding a provider should mean implementing a
host adapter, not changing the protocol.

## Transcript And Identity Binding

All deployment profiles must bind the same minimum identity fields into the
Router A/B transcript:

- protocol version
- request kind
- account/session/project/environment scope
- signing root id and version
- root-share epoch
- signer set id
- signer A identity and key epoch
- signer B identity and key epoch
- relayer identity and key epoch
- deployment profile id
- deployment epoch
- transport kind
- Router request digest
- client ephemeral public key
- nonce and expiry

Provider-diverse profiles may additionally bind:

- provider name
- attestation measurement
- attestation evidence digest
- hardware or enclave policy id
- signed deployment manifest digest

Changing deployment profile, signer key epoch, relayer identity, root-share
epoch, or deployment epoch must change transcript-bound fields.

## Deployment Manifest

Every self-host deployment should produce a signed deployment manifest.

```ts
type RouterAbDeploymentManifestV1 = {
  manifestVersion: 'router_ab_deployment_manifest_v1';
  deploymentProfile:
    | 'router_ab_cloudflare_same_account_v1'
    | 'router_ab_cloudflare_separate_accounts_v1'
    | 'router_ab_provider_diverse_v1';
  deploymentEpoch: string;
  publicRouterUrl: string;
  signerSetId: string;
  routerIdentity: PublicWorkerIdentity;
  signerAIdentity: PublicSignerIdentity;
  signerBIdentity: PublicSignerIdentity;
  relayerIdentity: PublicRelayerIdentity;
  signerEngineMode: 'hss_server_blind_v1' | 'tee_accelerated_threshold_v1';
  transport: PublicTransportDescriptor;
  storageScopes: PublicStorageScopeDescriptor[];
  createdAtMs: number;
  manifestDigest: string;
  signature: string;
};
```

The manifest is used by:

- client capability discovery
- migration/import verification
- smoke tests
- incident response
- signer rotation
- deployment drift detection

The manifest must not contain secrets, root shares, decrypted envelope material,
or private endpoint credentials.

## SDK Surface

The browser/client SDK should interact with one public backend URL regardless of
deployment profile.

```ts
createSeamsClient({
  walletBackendUrl: 'https://wallet.example.com',
  requiredSecurityLevel: 'split_server_level_c',
});
```

The backend capability document should make the deployment profile explicit:

```ts
type WalletBackendCapability =
  | {
      kind: 'router_ab_cloudflare_same_account_v1';
      securityLevel: 'split_server_level_c';
      publicRouterUrl: string;
      signerSetId: string;
      deploymentEpoch: string;
      signerEngineMode: 'hss_server_blind_v1';
    }
  | {
      kind: 'router_ab_cloudflare_separate_accounts_v1';
      securityLevel: 'split_server_level_c_hardened';
      publicRouterUrl: string;
      signerSetId: string;
      deploymentEpoch: string;
      signerEngineMode: 'hss_server_blind_v1';
    }
  | {
      kind: 'router_ab_provider_diverse_v1';
      securityLevel: 'split_server_provider_diverse';
      publicRouterUrl: string;
      signerSetId: string;
      deploymentEpoch: string;
      signerEngineMode: 'hss_server_blind_v1' | 'tee_accelerated_threshold_v1';
      attestationPolicyDigest: string;
    };
```

The client should reject a backend whose advertised security level is lower than
the app's configured requirement.

Server-side SDK exports should be profile-specific:

```ts
import { createRouterAbCloudflareSameAccountDeployment } from '@seams/sdk/server/self-host/router-ab/cloudflare-same-account';

import { createRouterAbCloudflareSeparateAccountsDeployment } from '@seams/sdk/server/self-host/router-ab/cloudflare-separate-accounts';

import { createRouterAbProviderDiverseDeployment } from '@seams/sdk/server/self-host/router-ab/provider-diverse';
```

These factories should produce profile-specific Wrangler files, GitHub Actions
workflows, smoke tests, and import commands.

## GitHub Actions And IaC

Same-account template:

```text
.github/workflows/deploy-router-ab-cloudflare.yml
infra/cloudflare/router/wrangler.toml
infra/cloudflare/signer-a/wrangler.toml
infra/cloudflare/signer-b/wrangler.toml
infra/cloudflare/smoke/router-ab-boundary-checks.yml
```

Separate-account template:

```text
.github/workflows/deploy-router.yml
.github/workflows/deploy-signer-a.yml
.github/workflows/deploy-signer-b.yml
infra/cloudflare/router/wrangler.toml
infra/cloudflare/signer-a/wrangler.toml
infra/cloudflare/signer-b/wrangler.toml
infra/cloudflare/cross-account-auth.yml
```

Provider-diverse template:

```text
.github/workflows/deploy-router.yml
.github/workflows/deploy-signer-a-provider.yml
.github/workflows/deploy-signer-b-provider.yml
infra/router/
infra/signer-a/
infra/signer-b/
infra/attestation-policy/
```

Generated workflows must:

- deploy each role independently
- run role-boundary startup checks
- run no-forbidden-binding checks
- run transcript vector checks
- run import verification on test bundles
- publish a signed deployment manifest
- run post-deploy smoke tests through the public Router URL

## Import And Migration

Migration bundle handling should be profile-aware.

Same-account import:

- Router receives public import metadata.
- Signer A receives A role package only.
- Signer B receives B role package only.
- Signer A relayer store receives relayer activation state only after
  verification.

Separate-account import:

- Router import metadata goes to the Router account.
- A role package is uploaded using Signer A account credentials.
- B role package is uploaded using Signer B account credentials.
- Cross-account import receipts are collected into one audit artifact.

Provider-diverse import:

- each provider receives only its role-local sealed package
- provider attestation evidence is recorded before activation
- address/public-key parity must pass before production traffic is enabled

In every profile:

- imported shares must derive the same wallet identities
- hosted signing must be disabled after customer verification
- hosted shares must be deleted or retired with audit evidence
- rollback behavior must be explicit

## Health And Boundary Checks

Required checks for every profile:

- Router startup fails if signer root-share bindings or signer decrypt secrets
  are present.
- Signer A startup fails if B root-share bindings or B decrypt secrets are
  present.
- Signer B startup fails if A root-share bindings, relayer-output bindings, or
  A decrypt secrets are present.
- Router can reserve replay state and persist public lifecycle state.
- Signer A can read only A startup metadata.
- Signer B can read only B startup metadata.
- A and B produce transcript-bound signer responses.
- Client-output packages cannot be accepted as relayer-output packages.
- Relayer-output packages cannot be returned to the client as client output.

Separate-account and provider-diverse profiles add:

- peer endpoint identity checks
- signed request verification checks
- deployment epoch mismatch rejection
- stale signer key epoch rejection
- endpoint allowlist checks

## Historical Implementation Plan

The checklist below is preserved as the original June 12 planning artifact. It
has been superseded by the active deployment runbook and Router A/B local-dev
checklists linked above.

### Phase 1: Profile Types

- [ ] Add deployment profile ids to Router A/B protocol metadata.
- [ ] Add deployment epoch to transcript-bound metadata.
- [ ] Add signer engine mode to deployment manifests and capability documents.
- [ ] Add public deployment manifest types.
- [ ] Add capability document branches for each Router A/B deployment profile.
- [ ] Add client-side security-level downgrade rejection.

### Phase 2: Same-Account IaC

- [ ] Generate same-account Cloudflare Wrangler templates.
- [ ] Generate one GitHub Actions workflow with three role deploy jobs.
- [ ] Add GitHub Environment separation for Router, Signer A, and Signer B.
- [ ] Add Service Binding transport adapter.
- [ ] Add role-boundary smoke tests.
- [ ] Add signed deployment manifest generation.

### Phase 3: Separate-Account IaC

- [ ] Generate separate-account Cloudflare templates.
- [ ] Add authenticated HTTPS transport adapter.
- [ ] Add request-signing and peer verification.
- [ ] Add cross-account import workflow.
- [ ] Add separate-account drift and boundary checks.
- [ ] Add runbooks for rotating one account or signer role independently.

### Phase 4: Provider-Diverse Adapters

- [ ] Define provider-neutral authenticated transport requirements.
- [ ] Add attestation-policy shape.
- [ ] Add `tee_accelerated_threshold_v1` signer engine mode.
- [ ] Add non-HSS threshold signer vectors and latency gates for TEE mode.
- [ ] Add provider adapter interface for signer deployment.
- [ ] Add one reference provider-diverse deployment.
- [ ] Add attestation digest binding to the deployment manifest.
- [ ] Add latency and availability measurement gates.

### Phase 5: Documentation And Product Packaging

- [x] Make `router_ab_cloudflare_same_account_v1` the documented production
      self-host default.
- [x] Document `router_ab_cloudflare_separate_accounts_v1` as the insider-risk
      hardening path.
- [x] Document `router_ab_provider_diverse_v1` as the enterprise
      highest-assurance path.
- [x] Keep one-Worker self-host docs under local/dev/evaluation/escape-hatch
      language.

## Decision Summary

Router A/B should be the default production self-host architecture.

The SDK should support multiple Router A/B deployment profiles by making the
transport and credentials layer customizable. Same-account Cloudflare keeps the
customer experience simple. Separate Cloudflare accounts harden against
insiders and account-level compromise. Provider-diverse signers provide a
future path for customers that need stronger operational independence.

The protocol, transcript binding, output package formats, migration semantics,
and client SDK behavior should remain stable across all three profiles.
