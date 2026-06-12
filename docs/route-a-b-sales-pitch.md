# Router A/B Sales Pitch Notes

Date created: June 12, 2026

Status: internal positioning notes for future user-facing sales copy.

Related docs:

- [docs/router-a-b-deployment-choices.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/router-a-b-deployment-choices.md)
- [docs/router-A-B-signer.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/router-A-B-signer.md)

## Core Positioning

Router A/B is the production self-host architecture for companies that want
non-custodial embedded wallet infrastructure without accepting single-provider
lock-in.

The bold pitch:

```text
Hard to steal.
Hard to lose.
Easy to host and migrate.
```

The customer-facing promise:

```text
One public wallet backend URL.
Serverless deployment by default.
Split-server security under the hood.
Clear hardening path from one Cloudflare account to independent accounts and
provider-diverse signers.
```

## Selling Points

### One Public Backend URL

Apps and users do not need to understand Router A/B. They integrate with one
wallet backend URL. The Router handles auth, policy, rate limits, replay, and
public lifecycle state, while the signer split stays behind the deployment
boundary.

### Same Protocol Everywhere

Same-account Cloudflare, separate-account Cloudflare, and provider-diverse
deployments all run the same Router A/B protocol. The deployment profiles
differ only in transport, credentials, storage adapters, and operational
controls.

### Security Scales With Customer Maturity

Customers can start with same-account Cloudflare serverless deployment, then
harden to separate Cloudflare accounts when insider risk, CI-token risk, or
account-control concerns justify the extra setup. Wallet semantics and client
SDK behavior stay stable during that hardening step.

### Infrastructure-As-Code Hides Operational Shape

Three Workers and role-scoped Durable Objects become a generated deployment
profile. Customers should experience Router A/B as a paved-road deployment
workflow, not a manual architecture project.

### Honest Trust Boundaries

Same-account Router A/B protects against single Worker compromise and accidental
role mixing. Separate-account Router A/B adds hardening against insider and
control-plane risk. Provider-diverse Router A/B adds provider-level
independence for customers with the strongest operational requirements.

### Avoid The False Simplicity Trap

One Worker is operationally simple and useful for local development,
evaluation, and emergency portability. Production wallet infrastructure needs a
stronger property: no single server process should observe joined server-side
derivation material. Router A/B preserves that property while keeping the
public product surface simple.

### Company-Level Exit, Not Just User Key Export

Individual private-key export is useful, but it is not enough for embedded
wallet infrastructure.

User key export means one user can move one wallet key into another wallet
client. Company-level migration means the app operator can move the whole
wallet backend without asking every user to manually recover or export keys.

For embedded-wallet customers, the strategic lock-in risk is company-level
operational dependency:

- wallet identity and address inventory
- signing roots or server-side shares
- passkey origin and RP ID assumptions
- recovery and export semantics
- session and policy integration
- audit evidence
- hosted signing disablement
- future signing operations

Router A/B should make operator portability a first-class product feature:

```text
Hosted -> self-host Router A/B:
  export project/environment migration bundle
  import role-specific A/B packages
  verify same wallet addresses
  activate customer Router A/B deployment
  disable hosted signing
  retire or delete hosted shares with audit evidence
```

The positioning:

```text
Key export gives users an escape hatch.
Router A/B migration gives companies an exit path.
```

### Account-Layer Rotation Is A Separate Escape Hatch

Smart contract wallets and protocol-native account/signer separation are still
valuable. NEAR accounts already separate account identity from signer keys, and
EVM smart contract wallets can mirror that product shape with signer rotation
modules.

That solves address and account continuity, but it creates a migration tradeoff
for embedded wallet providers:

| Migration model | Strength | Weakness |
| --- | --- | --- |
| User-authorized account-layer rotation | Preserves non-custodial control because each user authorizes the signer change. | Requires many per-account migration transactions, creates gas cost, and depends on every user eventually completing the migration. |
| Company-authorized account-layer rotation | Lets an operator move a full user fleet quickly. | Gives the operator unilateral signer-replacement power unless constrained by user approval, timelocks, guardians, or another non-custodial control. That power can become a fleet-wide theft path. |
| Router A/B server-share migration | Moves signing infrastructure without per-user onchain migration transactions. | Requires the user-side factor and policy layer to stay outside operator control. |

Router A/B changes the migration unit. The company can migrate or rotate the
server signing share and deployment profile while wallet addresses and user
controls stay stable. Users do not need to appear online for a migration
transaction, and the company does not gain unilateral signing power as long as
the user-controlled share, passkey, or approval factor remains required for
future signatures.

The stronger architecture uses both layers:

- NEAR accounts use protocol-native signer rotation for account continuity.
- EVM smart contract wallets use signer modules for account continuity.
- Router A/B provides portable signing infrastructure behind those accounts.

The concise positioning:

```text
Smart contract wallets make account identity portable.
Router A/B makes signing infrastructure portable.
Together, they avoid per-user migration while preserving non-custodial control.
```

### User Safety: Hard To Steal, Hard To Lose

The product should also compete on end-user safety, not only on business
portability.

The target wallet model is resilient in both directions:

- difficult to steal or hack because no single hosted signer, device, session,
  or operator path can authorize arbitrary transfers alone
- difficult to lose because account recovery and device rotation are native
  wallet features rather than afterthoughts

Current NEAR support already has the right account model. NEAR separates account
identity from signer keys at the protocol level, so signer rotation can preserve
the account while changing the active devices or recovery path.

NEAR user-safety features:

- link devices across multiple accounts through QR scan flows
- rotate account signers without changing the account identity
- use email DKIM signatures as a social-account recovery signal
- support multisig recovery so recovery requires approved combinations of
  user, device, email, social, or guardian factors

The planned EVM wallet model should mirror the same semantics through smart
contract wallets:

- signer modules for device rotation
- recovery modules for email DKIM and social recovery
- policy modules for spending limits, session keys, allowlists, and
  high-risk-action approvals
- account abstraction support for sponsorship, batching, and recovery
  transactions

This gives the sales story three distinct layers:

| Layer | User value | Business value |
| --- | --- | --- |
| Account-layer rotation | Users keep account identity when devices or signers change. | Apps can preserve account continuity across recovery and upgrades. |
| Recovery and safety | Wallets are harder to steal and harder to lose. | Support burden falls, consumer trust rises, and high-value balances become more realistic. |
| Router A/B infrastructure portability | Users keep non-custodial control during backend migrations. | Companies can move hosted, self-hosted, and hardened deployments without fleet-wide user migration. |

The strongest positioning:

```text
Portable accounts.
Recoverable wallets.
Portable signing infrastructure.
```

### Fleet Signers: AI Agents, Cards, And Robotics

The same portability story matters for non-human accounts.

AI agents, virtual cards, robots, and other autonomous systems may each need an
account that can pay for resources, authorize actions, sign attestations, or
prove control over a device or workflow. At fleet scale, manual per-account
migration is operationally unrealistic.

Router A/B lets the operator migrate signing infrastructure for a whole fleet
without rotating every account onchain or asking every agent/device to complete
a bespoke recovery process.

This depends on the MPC state model. Per-wallet MPC shares make fleet migration
hard because the operator must export, reshare, verify, or retire state for
many independent wallet keys. Router A/B should avoid making per-wallet key
shares the canonical migration unit. The intended migration unit is the
fleet-level signing root, signer role share, key epoch, policy set, and
deployment manifest, with address parity checks proving that derived accounts
remain stable after the move.

| Signing state model | Fleet migration impact |
| --- | --- |
| Per-wallet MPC key shares | Hard to migrate. Each wallet may require independent share export, resharing, verification, and retirement evidence. |
| Onchain signer rotation | Chain-dependent and potentially expensive. Each account may require a transaction or user-approved recovery action. |
| Router A/B root-share migration | More practical. Migrate role-scoped server shares and deployment state, then verify derived wallet addresses and policies across the fleet. |

Example fleet use cases:

- virtual cards and spending signers for AI agents
- account signers for robots that need to pay for services or consumables
- cryptographic action signing for autonomous workflows
- device-linked accounts where hardware, policy, and recovery need to move
  together

The recovery model generalizes as well. For consumer wallets, recovery can use
user devices, passkeys, email DKIM, and social or guardian quorums. For fleets,
recovery can use owner/admin quorums, device attestations, hardware roots,
policy limits, and staged replacement ceremonies.

The customer value:

```text
Move the fleet.
Recover the fleet.
Keep the accounts stable.
```

### Future Feature: Custody Modes Must Be Explicit

Fleet accounts may eventually need a different custody model from consumer
embedded wallets. This is a future product direction, not near-term
implementation scope.

For human users, the default product should remain non-custodial. The company
offering the wallet must not hold the user recovery codes, recovery unwrap
keys, client share, or any equivalent authority that can recreate the user's
signing factor. The server may store recovery-wrapped enrollment escrows, but
the unwrap authority belongs to the user.

For AI agents, robots, virtual cards, and other org-owned actors, the company
or org can be the principal. In that setting, a future org-managed recovery
authority may be acceptable because the account exists to serve the
organization. The customer may need to rotate infrastructure, recover devices,
replace agents, and restore fleet signing state without waiting for a human end
user.

| Wallet class | Principal | Recovery authority | Product claim |
| --- | --- | --- | --- |
| Consumer embedded wallet | End user | User-held recovery codes, passkeys, devices, DKIM, guardians, or social recovery quorum | Non-custodial. The app operator cannot unilaterally recover or steal funds. |
| Org-managed fleet wallet | Customer org | Org-created recovery codes, admin quorum, hardware roots, device attestations, or policy-controlled recovery ceremony | Managed custody for agents, robots, cards, and devices owned by the org. |

The current Email OTP recovery design already has a useful primitive:
client-side enrollment material can be encrypted to a set of recovery codes,
then stored server-side as recovery-wrapped escrows. For consumer wallets, those
codes are user recovery codes. In a future fleet-wallet product, a separate
auth mode could replace user recovery codes with org-created recovery codes or
org-quorum unwrap material.

That variant must be a separate auth mode, not a flag on consumer wallets.
Required separation:

- distinct auth-method kind, such as `org_managed_fleet_recovery_v1`
- distinct AAD and recovery binding that names the org as recovery authority
- distinct SDK registration path and admin ceremony
- explicit dashboard and API labeling as managed custody
- policy limits for spending, recovery, rotation, and fleet migration
- audit evidence for every org recovery, share rotation, and fleet migration
- no use for customer-provisioned wallets that belong to human end users

This keeps the main consumer promise intact while still supporting fleets:

```text
Consumers get non-custodial recovery.
Fleets get org-managed recovery.
Both get portable infrastructure.
```

### Future Use Case: Biometric-Gated Robot Delegation

Router A/B also supports a stronger future robot-auth model where a human
controls a fleet through biometric-gated delegated sessions.

The principal is the human or org admin. Robots are operational actors that
receive bounded authority. A robot never receives the human wallet key or the
human client share.

The elegant shape:

```text
One human-controlled fleet authority.
Many robot operational identities.
Bounded delegated sessions between them.
```

High-authority operations should require fresh human approval through passkey,
biometrics, Email OTP, DKIM recovery, or a multisig/admin quorum:

- create or enroll a robot
- raise spend limits
- change fleet policy
- recover or replace a robot
- rotate robot device identity
- approve high-risk actions
- revoke robot or fleet access

Normal robot actions should use delegated sessions instead of raw signing
authority. The delegation should bind:

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

The signing flow:

```text
1. Human approves with passkey, biometrics, Email OTP, or quorum policy.
2. Router creates a delegated session for robot_id or robot_group_id.
3. Robot presents device identity plus delegated session.
4. Router validates policy, expiry, budget, revocation, and typed intent.
5. Router A/B signs only approved intents.
6. Audit logs record the approval, delegation, and robot action.
```

The product value:

```text
Humans approve.
Robots act.
Keys never move.
```

This is distinct from org-managed fleet custody. Human-delegated robot auth
preserves human control while letting robots operate within revocable policy
bounds.

### HSS Baseline And TEE-Backed Hardening

TEE-centric wallet infrastructure can be elegant for managed SaaS. Router A/B
plus HSS is more elegant for self-hostable embedded wallet infrastructure.
Router A/B can also run inside TEEs for customers that want a hardened,
lower-latency deployment.

| Criterion | Router A/B + HSS baseline | Router A/B + TEE-backed non-HSS mode | Typical TEE-centric wallet infrastructure |
| --- | --- | --- | --- |
| Self-hostability | Same protocol can run in customer-owned Cloudflare accounts or hardened provider-diverse deployments. | Available for customers that can run or buy managed attested signer infrastructure. | Usually tied to the provider's enclave and control plane unless the customer operates comparable enclave infrastructure. |
| Operational simplicity | Simple when packaged through infrastructure-as-code; same-account Cloudflare is the paved-road default. | Heavier than serverless HSS, but still uses the same Router A/B product surface and migration model. | Simple for SaaS consumption, heavy for true customer-operated deployment. |
| Server blindness without TEE | HSS and split derivation provide the server-blindness property without requiring trusted hardware. | The TEE boundary and secret-release policy supply the tamper-resistance assumption, allowing a non-HSS threshold signer for lower latency. | Relies on enclave isolation, attestation, and provider-managed enclave operations. |
| Company-level migration | Designed around migration bundles, same-wallet verification, hosted-disablement, and share retirement evidence. | Uses the same migration semantics, with extra attestation and deployment-manifest evidence. | Often supports key export, while full provider-to-self-host operational migration is harder. |
| Latency | The measured user-visible HSS latency concern is concentrated in Ed25519 registration and bootstrap flows. ECDSA bootstrap should be benchmarked and messaged separately, and normal signing remains outside the HSS critical path. | Can avoid HSS hidden-evaluation cost for latency-sensitive threshold signing paths. | Signing can be very fast when key shares live inside managed enclaves. |
| Hardening path | Same Cloudflare account, then separate accounts, then provider-diverse signers. | Provider-diverse signers with attestation-bound identities, deployment epochs, and secret-release policy. | Stronger posture usually means deeper enclave, attestation, and provider-operations dependency. |
| Failure mode | More protocol and adapter discipline. | More attestation, secret-release, and enclave-upgrade discipline. | More platform, attestation, and control-plane dependency. |

The tradeoff is deliberate. HSS supports server-blindness without TEEs and keeps
self-hosting realistic for customers that can operate serverless infrastructure
but cannot operate enclave infrastructure. Sales copy should be precise about
latency: current benchmark work identifies Ed25519 HSS registration as the main
visible HSS latency bucket, while ECDSA bootstrap and normal signing need their
own performance language.

The hardened TEE-backed profile is additive. It lets us offer a non-HSS,
lower-latency threshold signer for customers that want attested signer
infrastructure, while preserving the same Router A/B client integration,
deployment manifest model, migration semantics, and company-level exit story.

## Architecture Discipline

The main thing to preserve is adapter discipline:

- transport providers stay outside protocol-critical logic
- credential providers stay outside protocol-critical logic
- Service Bindings, authenticated HTTPS, and provider-diverse mTLS all
  implement the same host-trait boundary
- the Router A/B protocol, transcript binding, output packages, migration
  semantics, and client SDK behavior remain stable across deployment profiles

If same-account Service Bindings, cross-account HTTPS, and provider-diverse
mTLS are all implementations of the same host traits, the architecture stays
clean.

## Business Model

Router A/B supports an open-core business model.

The core wallet security runtime should be portable enough that customers have
a credible exit path. The paid product should monetize operational excellence,
managed infrastructure, enterprise hardening, and support.

Positioning:

```text
The wallet security runtime is portable.
The operational platform around it is paid.
```

Open core should include:

- Router A/B protocol
- self-host runtime
- Cloudflare same-account infrastructure-as-code
- migration bundle import/export format
- address and public-key verification tools
- basic health checks
- core SDK and client integration
- test vectors and precise security claims

Paid product layers can include:

- hosted wallet-as-a-service using managed Router A/B
- managed self-host where customers own Cloudflare accounts and we manage
  deploys, upgrades, monitoring, rotations, and incident response
- enterprise hardening for separate-account Cloudflare, provider-diverse
  signers, TEE-backed non-HSS threshold signing, custom KMS, HSM, and Secret
  Manager integrations
- control plane for org, project, environment, policy, team RBAC, approval
  workflows, and audit UI
- compliance and support packages, including SOC 2 evidence, audit exports,
  SLAs, security reviews, and incident runbooks
- migration services for hosted-to-self-host cutovers, wallet inventory
  validation, address parity reports, and share retirement evidence
- operations tooling for monitoring, alerting, deployment drift detection, key
  rotation, rollback automation, and deployment manifest verification
- premium transaction infrastructure such as gas sponsorship, relayer
  management, billing, metering, and webhook operations

This business model is stronger than a closed wallet garden because customers
pay for convenience, reliability, and expertise rather than because their users'
wallets are trapped.

## Draft User-Facing Language

```text
Deploy one wallet backend URL. Router A/B keeps the app integration simple
while splitting sensitive server-side derivation across independent signer
roles.

Start with Cloudflare serverless deployment in one account. Harden later by
moving Signer A and Signer B into separate accounts or provider-diverse
environments. Your wallet semantics and client integration stay the same.

Infrastructure-as-code handles the operational shape: Router, Signer A, Signer
B, role-scoped storage, health checks, and deployment manifests. Customers get
a practical self-host path without collapsing wallet security into one
tamperable server process.
```

## Claims To Keep Precise

- Same-account Router A/B is the default self-host production profile.
- Separate-account Router A/B is the insider-risk and control-plane hardening
  profile.
- Provider-diverse Router A/B is the highest-assurance profile.
- One-Worker self-hosting is an escape hatch for development, evaluation, and
  portability, not the recommended production security posture.
- Router A/B keeps one public product surface while allowing the deployment
  hardening level to increase over time.
