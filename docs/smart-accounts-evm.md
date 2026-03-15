# Smart Accounts on EVM

## Current position

We are holding off on making `smartAccountDeploy` a required part of initial registration.

Reason:

- today registration is effectively gas-free
- forcing EVM smart-account deployment during registration would make registration consume gas
- we do not want to lock that product decision in prematurely

## Why this still matters

We may still need `smartAccountDeploy` later for EVM account recovery flows.

The main reason is account recovery and signer continuity:

- smart accounts let one user account support multiple keypairs or signers
- that is useful for recovery, device replacement, and signer rotation
- EVM recovery may eventually need an internal deploy step even if initial registration does not

## Current implementation status

- `smartAccountDeploy` remains an internal hook, not a public route
- the public `/smart-account/deploy` route stays removed
- any further product rollout decisions for `smartAccountDeploy` are deferred

This means the hook can exist internally without committing us to always running it during registration.

## Open product decisions

- Should initial EVM registration remain gas-free even when threshold ECDSA is provisioned?
- If yes, should EVM smart-account deployment happen only on first EVM use instead of during registration?
- Should EVM account recovery flows trigger `smartAccountDeploy` if the smart account is still undeployed?
- Should login-time or manual threshold ECDSA bootstrap ever trigger deployment, or should that stay deferred until first EVM action?
- If deployment happens outside registration, who pays for gas: relayer sponsorship, prepaid balance, x402-style payment, or something else?
- What user experience should we present for an undeployed-but-provisioned EVM account?

## Todo

- [ ] Decide whether EVM registration must stay gas-free as a hard product rule.
- [ ] Decide whether `smartAccountDeploy` should run during registration, first EVM action, recovery only, or some combination.
- [ ] Define the exact EVM account recovery flow that requires smart-account deployment.
- [ ] Define who funds deployment gas for recovery or first-use deployment.
- [ ] Define how undeployed smart-account state is represented in client and server state.
- [ ] Revisit whether threshold ECDSA bootstrap or login-time provisioning should ever trigger deployment.
- [ ] Document the final deployment trigger and billing model once the product decision is made.
