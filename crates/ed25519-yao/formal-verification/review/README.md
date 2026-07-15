# Phase 2B External Review Evidence

This directory is reserved for genuine, externally governed Phase 2B evidence.
No authority policy, trusted key, reproduction record, review report, approval,
or successful Phase 2 exit is present.

The normative format and acceptance requirements are defined by
[`../docs/phase2b-exit-evidence-v1.md`](../docs/phase2b-exit-evidence-v1.md).
The readiness parser/rejection suite and fixed-path subject/fresh-observation
builders, protected policy/challenge loader, independent-host prepare/finalize,
fixed Git-object reproduction acceptance, and reviewer-approval acceptance
exist. The complete synthetic command-boundary integration passes; genuine
evidence must still come from the external operator and reviewer named by the
externally pinned policy.

The real cryptographic review report path is
`phase2b-cryptographic-review-v1.md`. It must be authored and signed through the
external process; repository automation must never synthesize it.

The repository workflow checks only the public four-blob staging shape. It has
no release-authority claim. Before attaching genuine evidence, independently
administer the reproducer and reviewer keys, publish the canonical policy digest
and sequence floor outside GitHub, issue the one-use challenge, and establish an
immutable external channel for accepted `E` commit identities. The external
verifier must run the protected-input, record, and approval checks against exact
`E`. GitHub CI, tags, branches, repository history, and administrator actions
cannot close Phase 2.
