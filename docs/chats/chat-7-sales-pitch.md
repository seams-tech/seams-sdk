# Chat 7: Router A/B Sales Pitch And Value Proposition

Date: 2026-06-14

## Objective

Clarify the Router A/B value proposition, deployment choices, competitive
positioning, business model, and future wallet-auth extensions.

The working sales pitch became:

```text
Hard to steal.
Hard to lose.
Easy to host and migrate.
```

Related docs:

- [docs/route-a-b-sales-pitch.md](../route-a-b-sales-pitch.md)
- [docs/router-a-b-deployment.md](../router-a-b-deployment.md)
- [docs/router-a-b-SPEC.md](../router-a-b-SPEC.md)
- [docs/TEEs-vs-serverless-MPC.md](../TEEs-vs-serverless-MPC.md)

## Core Conclusions

Router A/B is architecturally elegant for the current goal: self-hostable,
non-custodial embedded wallet infrastructure that can run simply on Cloudflare
while preserving a real split-server security boundary.

The one-Worker architecture is operationally simple, but too weak as the
recommended production design. A tampered Worker could log secrets or joined
server-side material. It remains useful for local development, evaluation, and
emergency portability.

Router A/B should be the default production self-host shape:

```text
Client/app sees one public Router URL.
Router handles auth, policy, rate limits, replay, and public lifecycle state.
Signer A and Signer B keep role-local root shares and decrypt credentials.
Transport and credentials vary by deployment profile.
Protocol semantics stay stable.
```

The strongest architecture claim is:

```text
Smart contract wallets make account identity portable.
Router A/B makes signing infrastructure portable.
Together, they avoid per-user migration while preserving non-custodial control.
```

## Deployment Choices

The agreed deployment profiles are:

| Profile                                     | Role                                 | Notes                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `router_ab_cloudflare_same_account_v1`      | Default production self-host         | Three Workers in one Cloudflare account, separate role bindings, secrets, and Durable Objects. Protects against single Worker compromise and accidental role mixing. |
| `router_ab_cloudflare_separate_accounts_v1` | Hardened production self-host        | Router, Signer A, and Signer B use separate Cloudflare accounts. Improves insider, CI-token, and control-plane isolation.                                            |
| `router_ab_provider_diverse_v1`             | Highest-assurance enterprise profile | Signers can run across providers, with authenticated transport and optional attestation-bound identities.                                                            |

The SDK should support these through transport, credential, storage,
observability, and deployment adapters. It should not fork wallet semantics or
protocol-critical logic.

Infrastructure-as-code is central to the simplicity story. Three Workers and
role-scoped Durable Objects should be experienced as a generated deployment
profile, not a manual architecture project. Same-account Cloudflare and
separate-account Cloudflare can be operationally similar if GitHub Actions,
Wrangler config, role-scoped API tokens, and deployment manifests are generated
properly.

## Same Account Versus Separate Accounts

Same-account Cloudflare can segregate roles with separate Workers, secrets,
Durable Object namespaces, Service Bindings, startup guards, and source guards.
This is enough to avoid one tampered Worker trivially reading both A and B
state.

Separate accounts are still the desired hardening path because same-account
deployments remain exposed to account-admin compromise, broad API tokens,
shared billing/control-plane operators, and insider risk. The long-term
enterprise story should move serious customers toward independent accounts or
provider-diverse signers.

## HSS And TEE Position

HSS is justified because it provides server-blindness without trusted hardware.
That matters for commodity self-hosting and Cloudflare-first deployments.

The tradeoff is latency and complexity. The current sales wording should be
precise:

- the visible HSS latency concern is concentrated in Ed25519 registration and
  bootstrap flows
- ECDSA bootstrap should be benchmarked and described separately
- normal signing should remain outside the HSS critical path

TEE-backed Router A/B is a valid hardened future mode. It can keep the same
Router A/B topology while replacing the HSS path with a non-HSS threshold
signer inside attested signer environments. That could improve latency for
customers that accept the TEE trust model.

The distinction:

```text
HSS mode derives server-blindness from cryptographic protocol boundaries.
TEE mode derives part of that protection from attested execution and
secret-release policy.
```

TEE mode should be additive, not a replacement for the serverless HSS baseline.

## Competitive Positioning

Privy, Crossmint, Turnkey, and Router A/B solve different layers.

| Provider   | Durable strength                                                                       | Structural weakness                                                                                                                        |
| ---------- | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Privy      | Product polish, auth UX, embedded-wallet convenience, distribution                     | Customer remains dependent on Privy's hosted signer/control plane. UX advantage can diminish if we match feature coverage.                 |
| Crossmint  | Smart account and signer-rotation story for account continuity                         | Smart-account portability is chain-dependent. Signer rotation does not by itself solve company-level signer-infrastructure lock-in.        |
| Turnkey    | Strong hosted key-management primitives, policy engine, enclave-backed signing         | Feels closer to hosted KMS/key-management-as-a-service. Portability is mostly key export/import, not full wallet-infrastructure migration. |
| Router A/B | Self-hostable signer-infrastructure portability, non-custodial control, hardening path | Needs execution: SDK polish, audits, benchmarks, IaC, migration tooling, reliability, and support.                                         |

The sharp competitive framing:

```text
Privy makes embedded wallets easy.
Crossmint makes account identity more portable.
Turnkey makes key operations programmable.
Router A/B makes embedded wallet infrastructure portable.
```

If we also support NEAR account rotation and EVM smart contract wallets, we can
absorb Crossmint's account-layer argument and add the missing infrastructure
layer.

## Account Rotation And Migration

Account-layer signer rotation is valuable, but it has a migration tradeoff.

User-authorized rotation preserves non-custodial control, but it requires many
per-account transactions and depends on every user completing migration.
Company-authorized rotation can migrate a fleet quickly, but it creates
fleet-wide unilateral control unless constrained by user approval, timelocks,
guardians, or another non-custodial control.

Router A/B changes the migration unit:

```text
Migrate the server signing share and deployment profile.
Keep wallet addresses and user-controlled factors stable.
Verify address parity after cutover.
Retire hosted shares with audit evidence.
```

The operator can migrate infrastructure without requiring every user to appear
online, and without gaining unilateral signing power if the user-controlled
factor remains required.

## User Safety

The product should compete on end-user safety as well as business portability.

NEAR already has the right base model because account identity and signer keys
are separated at the protocol layer. Current and planned safety features:

- link devices across multiple accounts through QR scan flows
- rotate account signers without changing account identity
- use email DKIM signatures as a social-account recovery signal
- support multisig recovery through user, device, email, social, or guardian
  quorums

The planned EVM wallet model should mirror these semantics through smart
contract wallets:

- signer modules for device rotation
- recovery modules for email DKIM and social recovery
- policy modules for spending limits, session keys, allowlists, and
  high-risk-action approvals
- account abstraction support for sponsorship, batching, and recovery
  transactions

The three-layer story:

```text
Portable accounts.
Recoverable wallets.
Portable signing infrastructure.
```

## Business Model

Router A/B supports an open-core model.

The core wallet security runtime should be portable enough that customers have
a credible exit path. The paid product should monetize operational excellence,
managed infrastructure, enterprise hardening, support, compliance, migration
services, and premium transaction infrastructure.

Positioning:

```text
The wallet security runtime is portable.
The operational platform around it is paid.
```

Open core should include the Router A/B protocol, self-host runtime,
same-account Cloudflare IaC, migration bundle format, address verification
tools, health checks, core SDK integration, test vectors, and precise security
claims.

Paid layers can include managed Router A/B, managed self-host, separate-account
and provider-diverse hardening, TEE-backed non-HSS signing, control-plane UI,
RBAC, audit evidence, SLAs, migration services, monitoring, drift detection,
key rotation, gas sponsorship, relayers, billing, and webhooks.

## Fleet Signers And Future Robot/Auth Direction

The discussion extended the wallet-infrastructure thesis to non-human accounts:
AI agents, virtual cards, robotics signers, autonomous workflow signers, and
device-linked accounts.

Important caveat: naive per-wallet MPC shares make fleet migration hard. Each
wallet would need independent export, resharing, verification, and retirement
evidence.

The intended migration unit for fleets should be higher level:

```text
fleet/org signing root
role-scoped A/B server shares
signer key epoch
policy set
deployment manifest
address parity verification
```

The fleet value prop:

```text
Move the fleet.
Recover the fleet.
Keep the accounts stable.
```

## Future Custody Modes

Consumer wallets and org-owned fleets need different custody semantics.

Consumer embedded wallets should remain non-custodial. The app/customer should
not hold recovery codes, recovery unwrap keys, client shares, or equivalent
authority over a human user's wallet.

Org-managed fleet wallets are different because the customer org can be the
principal. For robots, AI agents, virtual cards, and org-owned devices, a future
org-managed recovery authority can be legitimate.

This future feature should be a separate auth mode, such as:

```text
org_managed_fleet_recovery_v1
```

It must be a separate product surface with distinct AAD, recovery binding, SDK
registration path, admin ceremony, dashboard labeling, policy limits, audit
evidence, and an explicit managed-custody claim. It must not be a flag on
consumer wallets.

The rule:

```text
Consumers get non-custodial recovery.
Fleets get org-managed recovery.
Both get portable infrastructure.
```

This is future product direction, not near-term implementation scope.

## Future Biometric-Gated Robot Delegation

The most compelling robot/fleet case for our MPC signer is human-delegated
authority.

Model:

```text
One human-controlled fleet authority.
Many robot operational identities.
Bounded delegated sessions between them.
```

The human or org admin is the principal. Robots are operational actors that
receive bounded authority. A robot never receives the human wallet key or human
client share.

High-authority operations should require fresh human approval through passkey,
biometrics, Email OTP, DKIM recovery, or a multisig/admin quorum:

- create or enroll a robot
- raise spend limits
- change fleet policy
- recover or replace a robot
- rotate robot device identity
- approve high-risk actions
- revoke robot or fleet access

Normal robot actions should use delegated sessions. A delegation should bind:

- human account id or org admin authority
- fleet id
- robot id or robot group id
- allowed action kinds
- spend budget
- merchant, contract, method, or service allowlist
- expiry
- revocation epoch
- risk step-up rules
- audit subject

The product line:

```text
Humans approve.
Robots act.
Keys never move.
```

This is distinct from org-managed fleet custody because the human remains in
control and robots operate inside revocable policy bounds.

## Standalone Fleet SDK Discussion

We explicitly challenged the assumption that Router A/B should be used for all
robot/fleet auth. From first principles, simple org-owned fleet custody could
use a policy server plus org KMS, HSM, or TEE signer. Router A/B is clearly
valuable only when the buyer needs self-hostable split-server hardening,
delegated human control, and vendor-independent migration.

For future fleet work, the better shape is likely a lightweight standalone SDK
that talks to the same Router A/B backend when Router A/B is the selected
signer backend. The SDK should not force Router A/B if a simpler signer backend
fits the use case.

Possible future signer-backend shape:

```ts
type FleetSignerBackend =
  | { kind: 'org_managed_kms_v1' }
  | { kind: 'device_local_key_v1' }
  | { kind: 'tee_signer_v1' }
  | { kind: 'router_ab_root_share_v1' };
```

The stable fleet SDK surface would be:

```text
provision device
bind device to fleet
submit typed action intent
enforce policy
sign
audit
recover / revoke / rotate
```

Router A/B earns its place for human-delegated robot authority because the
human wallet stays protected, the robot gets only bounded delegated sessions,
and policy protects the boundary.

## Docs Created Or Updated During This Chat

- [docs/router-a-b-deployment.md](../router-a-b-deployment.md)
  - Deployment profile plan for same-account Cloudflare, separate-account
    Cloudflare, provider-diverse signers, HSS mode, and TEE-accelerated mode.
- [docs/route-a-b-sales-pitch.md](../route-a-b-sales-pitch.md)
  - Internal sales-positioning notes, competitor comparison, open-core
    business model, account-layer versus infrastructure-layer migration,
    recovery/safety story, fleet-signers notes, future custody-mode warning,
    and future biometric-gated robot delegation.
- [docs/TEEs-vs-serverless-MPC.md](../TEEs-vs-serverless-MPC.md)
  - Updated to treat TEE-backed Router A/B as an additive hardened profile
    rather than the default architecture.

## Open Questions

- How should the migration bundle be specified so customers can verify address
  parity, signer epochs, policy state, hosted-disablement, and share retirement
  evidence?
- What exact HSS latency claims are supported by current benchmarks for
  Ed25519 registration, ECDSA bootstrap, and normal signing?
- What should be included in the open-core self-host runtime, and what should
  stay in the paid operational platform?
- What is the minimal IaC surface for same-account Cloudflare and
  separate-account Cloudflare so both feel equally simple to deploy?
- How should EVM smart contract wallets mirror the NEAR account/signer
  separation model without creating unsafe company-authorized fleet rotation?
- What are the exact safety requirements for DKIM recovery, email-provider
  compromise handling, DKIM key rotation, guardians, and multisig recovery?
- If fleet signers become a product, should the first signer backend be KMS,
  TEE, device-local keys, Router A/B, or a pluggable backend interface?

## Next Steps

### Near Term

1. Turn [docs/router-a-b-deployment.md](../router-a-b-deployment.md) into an implementation checklist for generated Cloudflare same-account IaC.
2. Define the deployment manifest and capability document fields for:
   - deployment profile
   - signer engine mode
   - signer set id
   - signer key epoch
   - transport adapter
   - credential boundary
   - migration epoch
3. Specify hosted-to-self-host migration bundles:
   - exported public wallet inventory
   - role-specific A/B packages
   - address parity verification
   - policy/session migration boundary
   - hosted signing disablement
   - share retirement evidence
4. Add benchmark evidence and language gates for:
   - Ed25519 HSS registration/bootstrap
   - ECDSA bootstrap
   - normal signing latency
   - TEE-backed non-HSS target latency
5. Convert the sales notes into a concise external one-pager around:

```text
Hard to steal.
Hard to lose.
Easy to host and migrate.
```

### Product And GTM

6. Write a precise competitor comparison against Privy, Crossmint, and Turnkey,
   avoiding overclaims and separating account-layer portability from
   infrastructure-layer portability.
7. Define the open-core packaging:
   - what is free and self-hostable
   - what is paid managed infrastructure
   - what is enterprise hardening
   - what is migration/support/compliance
8. Draft public trust-boundary language for:
   - one-Worker development/evaluation profile
   - same-account Router A/B production profile
   - separate-account hardening profile
   - provider-diverse enterprise profile
   - TEE-accelerated profile
9. Add a sales appendix explaining why company-level migration is different
   from individual key export.

### Architecture

10. Preserve adapter discipline: transport and credentials must stay outside
    protocol-critical logic.
11. Keep the SDK shape profile-neutral. Deployment adapters can vary; wallet
    semantics and Router A/B protocol behavior should stay stable.
12. Add source/test guards for Router opacity and role separation where
    deployment profile work touches code.
13. Define the future TEE-backed signer mode as a separate trust model with
    attestation, secret-release policy, enclave upgrade controls, and explicit
    capability reporting.

### Later / Future Product Direction

14. Design EVM smart contract wallet modules to mirror NEAR account/signer
    separation:
    - signer rotation
    - recovery modules
    - DKIM/social recovery
    - policy modules
    - spend limits and step-up approval
15. Keep org-managed fleet recovery as a future feature only. If built, make it
    a separate auth method and product surface, never a consumer-wallet flag.
16. Explore biometric-gated robot delegation:
    - human-controlled fleet authority
    - robot operational identities
    - delegated sessions
    - typed action intents
    - revocation epochs
    - risk step-up
    - full audit trail
17. If fleet SDK work starts, begin from a signer-backend interface and compare
    KMS, device-local keys, TEE signers, and Router A/B before choosing the MVP
    backend.
