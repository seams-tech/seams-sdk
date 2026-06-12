# Refresh Context Extension

Refresh needs old and new epoch binding. The base `DerivationContext` has one
`root_share_epoch`, so refresh requires a request-kind-specific extension before
implementation.

## Request Scope Enum

The production Rust API should model request scope as:

```rust
pub enum RequestScope {
    Registration(RegistrationScope),
    Export(ExportScope),
    Refresh(RefreshScope),
}
```

`DerivationContext` should contain `request_scope` rather than a single flat
request-kind payload once refresh implementation begins.

## Registration Scope

Fields:

- `root_share_epoch`
- `registration_id`
- `account_scope`
- expected Router identity
- expected Signer A identity
- expected Signer B identity
- expected client identity
- expected relayer identity

Registration activation creates a verified account binding for the epoch.

## Export Scope

Fields:

- `root_share_epoch`
- `export_id`
- `account_scope`
- export purpose
- export recipient identity
- expected role identities

Export does not change the active root epoch.

## Refresh Scope

Fields:

- `old_root_share_epoch`
- `new_root_share_epoch`
- `refresh_id`
- `account_scope`
- old Signer A identity
- old Signer B identity
- new Signer A identity
- new Signer B identity
- expected Router identity
- expected client identity
- expected relayer identity
- address verification requirement

Rules:

- old and new epochs must differ
- new signer identities may match old identities for same-operator refresh
- Signer A and Signer B identities must differ within each epoch
- transcript binds both old and new signer identity sets
- activation requires verified evidence for the new epoch

## Refresh State Machine

Refresh extends the base state machine with activation:

1. `requested`
2. `role_envelopes_created`
3. `signer_inputs_accepted`
4. `coordination_complete`
5. `outputs_bound`
6. `delivered`
7. `verified`
8. `activation_ready`
9. `activated`

`activation_ready` means Minimum Level C passed and address verification passed.

`activated` means the account-level compare-and-set changed the active epoch
from `old_root_share_epoch` to `new_root_share_epoch`.

## Address Verification Evidence

Refresh activation needs:

- context digest
- transcript digest
- old epoch
- new epoch
- account public key
- candidate-specific relation proof or opened verification relation
- verifier identity
- verification result

Minimum Level C evidence alone cannot enter `activation_ready`.

## Candidate-Specific Refresh

### `mpc_threshold_prf_v1`

Required semantics:

- refresh changes A/B shares
- logical PRF output relation remains stable for the account when required
- old and new share commitments are linked by refresh evidence
- no joined PRF root is reconstructed

This candidate is likely better for preserving refresh.

### `split_root_derivation_v1`

Required decision:

- define preserving refresh for the split-root formula, or
- treat refresh as a new verified epoch with new output relations

The second option is acceptable only if product semantics allow re-verifying
and re-activating the account relation for the new epoch.

## Persistence

Persist refresh records:

- old epoch
- new epoch
- old signer identities
- new signer identities
- verified evidence digest
- address verification evidence digest
- activation state

Persist no plaintext A/B root-share pairs in one record.

## Vectors

Refresh vectors must include:

- valid old-to-new epoch refresh
- identical old and new epoch rejection
- swapped old/new epoch rejection
- mismatched old signer identity
- mismatched new signer identity
- activation without address verification rejection
- activation compare-and-set failure
