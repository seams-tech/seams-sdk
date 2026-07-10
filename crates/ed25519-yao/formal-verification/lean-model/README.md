# Ed25519 Yao Lean Model

The FV1 Lean model contains three model-local rehearsal theorems: distinct
activation/export family bytes, seven digest slots, and twelve metrics.

```sh
cargo yao-fv lean-check
```

The task builds the explicit `Ed25519YaoModel` target, checks an exact nonzero
theorem count, and requires its `.olean` output. This handwritten model has no
generated production or Verus bridge, so it is not evidence for the checked
manifest obligations. No execution, view, simulator, privacy, or
protocol-security model is present because those Rust and specification
boundaries are not frozen.
