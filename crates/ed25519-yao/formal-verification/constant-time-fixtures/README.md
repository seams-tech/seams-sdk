# Constant-Time Analyzer Qualification Fixtures

This host-only crate proves that the configured assembly analyzer can distinguish
a branchless selection kernel from an intentionally variable-time division
kernel at the optimization levels required by the Ed25519 Yao validation plan.

The crate contains no production protocol code and provides no constant-time
evidence for `ed25519-yao`. Run it through:

```text
cargo yao-fv constant-time-qualification
```

`CT_ANALYZER` may point to an alternate `ct_analyzer/analyzer.py`. When it is
unset, the task uses the analyzer installed under the current Codex home. The
analyzer and its `uv.lock` must match the digests pinned in `toolchain.toml`.
