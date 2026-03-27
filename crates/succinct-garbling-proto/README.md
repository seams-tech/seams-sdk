# Succinct Garbling Proto

Research crate for the fixed-function succinct-garbling / HSS track in
[`docs/succinct-garbling.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/succinct-garbling.md).

## OT-HSS Protocol Overview

This crate studies one fixed hidden conversion:

- client root share `y_client`,
- server root share `y_relayer`,
- canonical Ed25519 seed `d`,
- canonical Ed25519 signing scalar `a`,
- durable output shares `x_client_base`, `x_relayer_base`.

Mathematically, the fixed functionality is:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`
- `A = [a]B`

The clean way to think about the protocol is as two hidden paths that meet at
the output-share projector.

Seed path:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

Share path:

- `tau_client + tau_relayer -> tau`

Output-share projection:

- `x_client_base = a + tau`
- `x_relayer_base = a + 2 * tau`

Important distinction:

- `d` is the canonical hidden seed,
- `a` is the canonical hidden signing scalar derived from `d`,
- `tau` is a hidden rerandomization value for share projection,
- `x_client_base` and `x_relayer_base` are the actual durable signing shares.

So this is not "sharing two signing secrets." It is:

- one hidden canonical secret chain `d -> a`,
- one hidden rerandomization path `tau_client + tau_relayer -> tau`,
- one projection from those hidden values into durable signing shares.

## OT vs HSS

This README uses `HSS` in the homomorphic-secret-sharing sense:

- `KeyGen`
- `Share`
- `EvalAdd`
- `EvalMult`
- `Decode`

Role split:

- OT is the private input-delivery mechanism for client-owned bits,
- HSS is the hidden-computation mechanism once inputs are represented as hidden
  shared values.

Informally:

- OT answers: "how does the client privately inject its input bits?"
- HSS answers: "how do we compute on those hidden values after they are
  represented as hidden shared values?"

## Protocol Shape

### Prepare Once

The server/garbler starts by preparing a context-bound session:

1. build the reusable prime-order artifact for the canonical context,
2. decode and compile that artifact into a fixed hidden-eval program,
3. run DDH `KeyGen` for the compiled program,
4. prepare OT offer material for `y_client_bits` and `tau_client_bits`.

The result is reusable prepared state:

- artifact bytes and digest,
- compiled hidden-eval program,
- DDH backend and evaluation key,
- client OT offer,
- garbler-held OT sender state and remote-share state.

### Per Run

For one concrete registration/rebuild run:

1. client derives `y_client` and holds `tau_client`,
2. client turns those into `256` OT selections for `y_client_bits` and `256`
   OT selections for `tau_client_bits`,
3. client sends the OT request packet to the server,
4. server derives/holds `y_relayer` and `tau_relayer`,
5. server resolves the OT requests and prepares server-side hidden input
   material,
6. evaluator reconstructs the client-owned hidden bundles from
   evaluator-selected local OT branches plus the garbler-provided remote-share
   release,
7. evaluator executes the compiled hidden-eval program over `y_client_bits`,
   `y_relayer_bits`, `tau_client_bits`, and `tau_relayer_bits`,
8. output-share projection emits hidden `x_client_base` and
   `x_relayer_base`,
9. client opens only `x_client_base`,
10. server opens only `x_relayer_base`,
11. both can verify the public key relation through `A`.

## Who Computes What

The current role model is:

- server = garbler,
- client = evaluator.

Server/garbler responsibilities:

- prepare the reusable artifact and compiled session,
- prepare OT offers,
- hold garbler OT sender state,
- contribute hidden server input material,
- seal the server output packet.

Client/evaluator responsibilities:

- prepare OT selections matching the real client bits,
- reconstruct the client-owned hidden input bundles,
- run the hidden evaluator over hidden shared-value representations,
- seal or open the client output packet through the evaluator role API.

## Where The Hidden Computation Happens

The hidden computation happens after OT has already delivered the client-owned
hidden shared-value representation.

The executor then runs the fixed function over hidden shared values:

- add stage for `y_client + y_relayer`,
- one-block `SHA-512` message schedule,
- `80` SHA-512 rounds,
- RFC 8032 clamp,
- reduction mod `l`,
- output-share projection using `tau_client` and `tau_relayer`.

In this crate, those hidden values use a DDH shared-word/shared-bundle
representation and are evaluated through the DDH hidden-eval executor.

## Security Boundary Reminder

In the intended 2-party design, the evaluator may receive only server-input
hidden shared-value representations that are sufficient to evaluate, but
insufficient to recover plaintext `y_relayer` or plaintext `tau_relayer`.

Design rule:

- the evaluator may evaluate on hidden server input,
- the evaluator must not receive enough material to decode that server input
  into plaintext.

This repo still contains the current implementation baseline for the delivery
path. It should not be read as the final deployed security boundary until the
real OT/HSS-specific 2-party input/output delivery path replaces the current
same-process packet baseline.

Current scope:

- freeze the plaintext `F_expand` reference path,
- freeze deterministic fixtures and serialized fixture format,
- provide invariants for later backend conformance,
- pin the concrete DDH / prime-order Phase 2b dependency baseline,
- compile the 262-window prime-order artifact into a DDH-targeted hidden-eval
  IR,
- provide a transcript-bound DDH primitive baseline with `KeyGen`, `Share`,
  `EvalAdd`, `EvalMult`, and `Decode` over split words plus group commitments,
- move DDH multiplication onto preprocessing-style triple material plus opened
  deltas instead of local cross-term expansion inside `eval_mul`,
- execute the compiled add stage, message schedule, and round-state core
  through a DDH hidden-eval executor over shared bits,
- execute hash-prefix extraction and RFC 8032 clamp over shared bits,
- execute scalar reduction mod `l` over shared bits,
- execute output-share projection over shared bits,
- derive `A` from the projected output shares instead of from clear `a`,
- provide a baseline cached/per-run client/server delivery packet surface over
  the current local simulation boundary, with OT-shaped client input offers,
  evaluator-selected local client shares, and garbler-held remote client
  shares instead of duplicated clear client inputs,
- split DDH transport/output handling across explicit garbler/evaluator role
  views,
- move OT offers, requests, responses, remote-share release, and output return
  across serialized wire messages instead of direct Rust packet handoff,
- seal the client/server output packets as authenticated sealed transport
  ciphertexts,
- open output return through `output_openers()` recipient-specific wire-message
  methods rather than one helper that decodes all outputs at once,
- provide matching client/server hidden output bundles keyed by the same
  `run_binding` inside those sealed transport ciphertexts,
- benchmark DDH primitive ops and the compiled hidden-eval path in release
  mode, with saved reports for later comparison,
- provide a small profiling entry point for the fixed `SHA-512 + clamp` core,
- define the first Phase 2 candidate artifact/message-flow model,
- emit a structured prime-order artifact with fixed-function section
  records, plus a cache benchmark/control stub,
- decode the structured prime-order artifact back into header and grouped-window
  records,
- build a deterministic execution trace from the grouped-window records,
- compile and execute a native prime-order CPU baseline over deterministic point
  tables and bucket schedules,
- compile and execute the same deterministic prime-order CPU baseline in
  browser wasm,
- wire the main prime-order prepared-session path so one object owns the
  context-bound artifact and compiled evaluator program and one call binds a run
  and returns the spec outputs plus evaluator witness data,
- probe browser WebGPU setup and synthetic dispatch throughput against the same
  structured artifact using backend-shaped step vectors, including per-subkernel
  timing for digit recode, window/bucket accumulation, bucket reduction, and
  dependency/normalization passes plus a more explicit signed-digit/window
  recode layout,
- save committed Phase 1 native/browser baseline reports for later comparison,
- provide a standalone browser `IndexedDB` cache benchmark harness for the same
  emitted artifact bytes, including structured-artifact decode and
  execution-trace timing plus prime-order evaluator-op summaries.

Current verification boundary:

- fast debug tests cover the DDH primitive surface, hidden-eval compiler,
  session preparation, and artifact/executor shape,
- end-to-end DDH hidden-eval conformance is available as ignored tests in
  [`src/lib.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/lib.rs)
  because the gate-level path is now materially more expensive than the
  previous oracle-backed path,
- default debug coverage is currently `32 passed, 4 ignored`,
- the current full five-fixture ignored DDH conformance lane passes, but still
  takes about `334.90 s` in the debug test profile.

This crate is intentionally isolated from production signer flows.

Current DDH / prime-order Phase 2b baseline:

- `curve25519-dalek = { version = "=4.1.3", features = ["group", "rand_core"] }`
- `group = "0.13.0"`
- `ff = "0.13.1"`
- `rand_core = { version = "0.6.4", features = ["getrandom"] }`
- `subtle = "2.6.1"`
- `zeroize = { version = "1.8.2", features = ["zeroize_derive"] }`
- `merlin = "3.0.0"`

Useful commands:

```bash
cargo test --manifest-path crates/succinct-garbling-proto/Cargo.toml
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_fixture_json
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin profile_fixed_sha512
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin profile_fixed_sha512 -- --json --output /tmp/phase1-report.json
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_note -- --backend paillier --json
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_candidate_artifact_stub -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_prime_order_artifact -- --fixture derived-alpha
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_cache_artifacts -- --samples 4 --warmups 1
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_prime_order_cpu_executor -- --json
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin run_prime_order_succinct_hss -- --fixture derived-alpha --json
wasm-pack build crates/succinct-garbling-proto --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/succinct-garbling-proto/web/generated
python3 -m http.server 8765 -d crates/succinct-garbling-proto/web
# then open /indexeddb_cache_benchmark.html?bundle=generated/bundle.json&autorun=1
node crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/succinct-garbling-proto/reports/phase1/browser-desktop-chrome-146.json
node crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json
```

Saved reports live in
[`reports/phase1`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase1)
and
[`reports/phase3`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3).
