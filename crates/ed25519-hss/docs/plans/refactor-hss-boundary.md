# Ed25519 HSS Boundary Refactors

Date updated: April 7, 2026

## Summary

This note consolidates the two major boundary-oriented refactors that reshaped
the `ed25519-hss` production path:

- Refactor 3:
  removed the old production seam that let a client reconstruct server-side
  hidden inputs in non-export flows
- Refactor 4:
  replaced the trace-backed staged executor with a real server-owned staged
  continuation model

Together, these refactors changed the production model from:

- “client evaluates on fully delivered server transport material”

to:

- “client validates and interacts with server-authored staged messages while
  the server owns the hidden-eval continuation state”

## The Problem Refactor 3 Solved

The key boundary invariant was:

- in non-export production flows, the client must not be able to reconstruct
  per-account `y_server`
- in non-export production flows, the client must not be able to reconstruct
  per-account `tau_server`

Before Refactor 3, the old production path violated that rule:

- the sealed `ServerInputsPacket` path let the evaluator open both server
  transport halves
- same-process public helpers such as `PreparedSession::evaluate*` and
  `TrustedServerEval` also kept joined-input execution reachable

That meant the production client boundary was too weak for the intended
non-export secrecy guarantee.

## What Refactor 3 Landed

Refactor 3 removed that production seam.

The lasting outcomes were:

- the old sealed `ServerInputsPacket` path is gone from the production client
  boundary
- the public same-process clear-input `PreparedSession::evaluate*` production
  path is gone
- evaluator-visible joined-input helpers were deleted, server-confined, or
  reduced to explicit regression-test support
- browser and relay runtime surfaces moved off the joined-input production path
- the kept production flow became the staged server-assisted protocol

That was the actual production boundary fix.

## The Problem Refactor 4 Solved

After Refactor 3, the production seam was fixed, but the execution model still
had a structural weakness:

- the transport was staged
- but too much later-round material could still be seeded earlier than the
  round that would consume it

So the code still left room for:

- oversized server state
- unclear stage ownership
- regressions back toward “materialize a full run and bind digests”

Refactor 4 cleaned that up.

## What Refactor 4 Landed

The kept staged model now behaves like a real staged executor:

- add-stage executes only add-stage and stores the first
  `message_schedule` continuation
- each `message_schedule(n)` response advances only the immediately prior
  schedule continuation
- the first `round_core` continuation is created only at the real
  `message_schedule -> round_core` boundary
- each `round_core(n)` response advances only the immediately prior round-core
  continuation
- `output_projection` materializes final output only when that stage executes
- finalize works only from stored finalized state

This removed the old trace-backed staged model from the kept path.

## Accepted Retained-State Exception

The staged server-owned executor now has one explicit retained-state exception:

- `projector_inputs`

Why it is kept:

- raw server roots are dropped after add-stage
- `output_projection` still needs projector prerequisites later
- delaying them further would require forbidden recomputation from dropped
  roots

So `projector_inputs` is the accepted minimal retained post-add-stage state,
not an accidental leftover.

## What The Current Production Shape Became

The kept non-export production flow is now:

- authenticated `ServerAssistInit`
- add-stage request/response
- `message_schedule(n)` request/response chain
- `round_core(n)` request/response chain
- `output_projection`
- `ServerFinalize`

The important rule is:

- the client may validate and compute against staged server-authored messages
- the client must not receive reconstructable server secret material in
  non-export flows

## Browser And Runtime Impact

These refactors were not only internal crate changes.

They also changed the deployed runtime shape:

- browser wasm exports no longer expose the old joined-input production seam
- relay/runtime integration moved onto the staged flow
- duplicate legacy runtime paths were removed from normal production use

So the boundary correction applies to the actual browser/relay surface, not
just local Rust APIs.

## Explicit Exception

`ExplicitKeyExport` remains the intentional exception.

That flow is allowed to deliver private-key-equivalent material to the
authorized client runtime, so the stronger non-export secrecy rule for
`y_server` and `tau_server` does not apply there.

That exception is documented in:

- [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)

## What These Refactors Did Not Solve

These refactors did not attempt to deliver:

- malicious-secure OT
- authenticated Beaver protections
- a full malicious-client security claim
- a stronger browser export trust model

Those remain separate workstreams and are now treated as optional future
hardening in:

- [docs/plans/malicious-security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/malicious-security.md)

## Validation That Came With Them

The combined refactor work landed with:

- boundary tests
- protocol-flow tests
- reconstruction-attempt keep-gates
- browser HSS wasm boundary tests
- relay finalize scope tests

Those tests matter because the refactors were about removing a real client
boundary bug and making the staged executor architecture honest.

## Lasting Value

Taken together, Refactor 3 and Refactor 4 accomplished this:

- the old production client reconstruction bug is gone in non-export flows
- the production path is now staged and server-owned
- stage ownership in the executor is now much clearer
- same-process and browser/relay surfaces no longer blur the boundary the way
  they used to

This consolidated note should now be read as the historical record of the
landed boundary fix and the staged-executor cleanup that made it durable.
