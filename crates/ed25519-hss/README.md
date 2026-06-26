# Ed25519 HSS

`ed25519-hss` is the fixed-function Ed25519 hidden-evaluation crate used in
this repo's threshold key-derivation flow.

It extends FROST threshold Ed25519 signing with a deterministic exportable key path built with homomorphic secret sharing, where the server can participate in signing and recovery flows without seeing the canonical exportable secret.

That means this crate is not just "threshold signing for Ed25519." It is the
piece that makes threshold signing, deterministic key export, and a stronger
server-blind boundary work together in one deployable protocol.

It implements one narrow protocol:

- client and server each hold root-share material
- the parties jointly derive the canonical Ed25519 seed path
  `y_client + y_server -> d -> SHA-512(d) -> clamp -> a`
- the protocol projects that hidden scalar into durable signing shares
  `x_client_base` and `x_server_base`

This crate is not a generic garbling framework and not a generic threshold
signing crate. It is an implementation-focused fixed-function protocol for the
Ed25519 shared-root lifecycle.

## Server-Blind Boundary

The current production path uses `ClientMaskedProjection` for client-owned
finalization. Under the trusted-server/code-as-deployed assumption:

- the server does not receive the client's recoverable secret material
- the server does not receive the client's output mask
- the server finalizes against a client-blinded output artifact
- the client derives the mask locally and opens the final `x_client_base`

This supports the Level A claim: the deployed server protocol does not receive
or materialize the client's sensitive key-derivation secret during Ed25519 HSS
key derivation.

This is a server-blind trusted-service boundary. It is not a full
malicious-server security claim: a maliciously modified server, compromised
client runtime, supply-chain compromise, or arbitrary inspection/modification of
client-side code is outside this Level A guarantee.

## Docs

- API and runtime entrypoint:
  [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- Security and boundary model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- Optimization notes and current benchmarks:
  [optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md)
- Post-quantum roadmap:
  [quantum.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/quantum.md)
- Formal verification overview:
  [formal-verification/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/README.md)
- Protocol spec:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)
- Derivation spec:
  [specs/derivation.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/derivation.md)
- Implementation/refactor history:
  [docs/plans/](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans)

## Public Surface

The boundary-oriented crate surface is centered on:

- `protocol::PreparedSession`
- `client::{ClientSession, ClientDriverState, ClientOtState}`
- `server::{ServerSession, ServerDriverState, ServerOtState}`
- `runtime::{ClientRuntime, ServerRuntime, SharedRuntime}`
- `wire::{WireMessage, ClientOtOffer, ClientPacket}`
- `wire::{ServerAssistInitPacket, ClientStageRequestPacket, ServerStageResponsePacket, ServerFinalizePacket}`
- `wire::{StagedEvaluatorArtifact, EvaluationReport, OutputDelivery}`

The production-facing shape is:

- `client/` owns evaluator-private state and client-side validators
- `server/` owns garbler-private state and server-owned staged execution state
- `wire/` owns the only cross-boundary payloads
- `protocol/` owns prepared-session construction and report helpers
- `runtime/` owns adapters around the staged role APIs

## Runtime Shape

The live runtime split is intentional:

- browser/client flows compile through
  [wasm/hss_client_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/hss_client_signer)
- relay/server flows compile through
  [wasm/near_signer/pkg-server](/Users/pta/Dev/rust/simple-threshold-signer/wasm/near_signer/pkg-server)

The browser HSS artifact is deliberately small enough to ship as a dedicated
wasm package instead of a broad mixed runtime bundle.

Current artifact sizes:

- browser wasm:
  `262,555` bytes
- browser JS glue:
  `14,028` bytes
- browser worker JS:
  `21,744` bytes

## Logical Protocol vs Production HTTP

The staged protocol has many logical transitions:

- `1` add-stage
- `64` `message_schedule(n)` transitions
- `80` `round_core(n)` transitions
- `1` `output_projection`
- `1` finalize step

If every logical stage were exposed directly over the network, the flow would
be roughly `147` staged request/response pairs after OT/init handoff.

That is not the current production transport.

The live browser/relay integration collapses the staged protocol into `3` HTTP
roundtrips:

1. `POST /router-ab/ed25519/hss/prepare`
2. `POST /router-ab/ed25519/hss/respond`
3. `POST /router-ab/ed25519/hss/finalize`

So the crate models a fine-grained staged execution protocol, while the
current production transport batches that work server-side.

## Current Status

The production boundary hardening goal for non-export flows is:

- the client must not be able to reconstruct `y_server`
- the client must not be able to reconstruct `tau_server`

That production seam is now staged and server-owned from add-stage onward.

The explicit exception is `ExplicitKeyExport`:

- the client is intentionally allowed to receive private-key-equivalent
  material
- a compromised client runtime can therefore abuse export by design
- that exception is documented in
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)

## Benchmarks

Latest local benchmark snapshot, generated on 2026-05-20 15:44:37 JST on
macOS/aarch64:

- hidden eval direct executor:
  `224.24ms` mean, `224.71ms` median, `225.83ms` p95
- hidden eval same-process delivery path:
  `264.20ms` mean, `264.24ms` median, `267.41ms` p95
- CPU executor:
  `2.042ms` mean, `2.021ms` median, `2.145ms` p95

The optimization history and hot-path notes live in
[optimization.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization.md).
