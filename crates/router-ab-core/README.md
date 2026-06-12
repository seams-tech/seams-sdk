# `router-ab-core`

This crate is the pure Rust core for Router/A/B derivation and service
protocol logic.

It owns:

- the selected `mpc_threshold_prf_v1` derivation backend
- the `split_root_derivation_v1` comparison/prototype path
- role-specific protocol types, transcript binding, envelopes, lifecycle
  state, output packages, host traits, local simulation, vectors, and source
  guards

Platform adapters live outside this crate. Cloudflare Workers, local SQLite
tooling, and future server runtimes should inject time, randomness, storage,
transport, and identity through explicit boundaries.

## Security Invariant

The target invariant is:

- server-side code never materializes joined `d`, `a`, or `x_client_base`
- client-side code never materializes joined `d`, `a`, `y_relayer`, or
  `tau_relayer`
- client opens only `x_client_base`
- server opens only `x_relayer_base`

This crate owns the derivation and protocol boundaries that make those state
claims enforceable.

## Current Scope

- typed derivation contexts and selected Candidate A backend
- transcript binding and canonical wire payloads
- role-specific client-output and relayer-output packages
- host traits and platform-neutral local simulation
- committed derivation and protocol vectors
- measurement gates and leakage checklist scaffolding
- Verus and Lean folders for future proof work

See [`specs/implementation-plan.md`](specs/implementation-plan.md) for the full
implementation plan.
