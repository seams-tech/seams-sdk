# Policy ID Rules

Date updated: March 12, 2026

## Canonical Meaning

`policyId` is the canonical, opaque, server-generated identifier for a console policy record.

Rules:

- `policyId` always points to `console_policies.id`
- new policy records receive generated `policy_...` ids
- `policyName` is the mutable human-readable name of that policy
- `policyKind` is explicit where policy projections are exposed

Do not derive org, scope, or behavior from the string form of `policyId`.

## Current Model

### Policy-backed gas sponsorship

Gas sponsorship is no longer a separate config resource.

- gas sponsorship records are stored as `GAS_SPONSORSHIP` policies
- gas CRUD flows use `/console/policies` with `kind=GAS_SPONSORSHIP`
- gas publish uses the shared policy publish and approval flow
- runtime, audit, approvals, insights, and sponsored-call paths use real `policyId`

Gas-specific rule targeting uses:

- `scopePolicyId`

That field is part of gas policy rules. It is not the identity of the gas policy itself.

### Config-based subsystems

If a subsystem still has its own standalone config identity, it must use subsystem-specific names such as:

- `configId`
- `configName`
- `smartWalletConfigId`

Do not introduce new generic `policyId` fields unless they point to `console_policies.id`.

## Runtime and History Naming

Use these names consistently:

- canonical policy reference:
  - `policyId`
  - `policyName`
  - `policyKind`
- immutable event label when a historical snapshot is required:
  - `policyNameAtEvent`

Avoid ambiguous fields that look like policy identity but actually refer to another resource.

## Legacy Cleanup Status

The old gas sponsorship config model is retired.

Removed from production code:

- dedicated backend `/console/gas-sponsorship` CRUD routes
- gas-owned `policyId` fields that were not real policy ids
- `sponsorshipConfigId`
- `sponsorshipConfigNameAtEvent`
- production dependency on `console_gas_sponsorship_configs`

Old gas sponsorship data is now represented as `GAS_SPONSORSHIP` policy records only.

## Practical Review Rule

When reviewing code:

- if a field is named `policyId`, it must reference `console_policies.id`
- if the resource is not a real policy record, rename the field
- if gas sponsorship needs to point at another policy by scope, use `scopePolicyId`
