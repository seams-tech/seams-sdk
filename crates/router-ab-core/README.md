# `router-ab-core`

This crate is the pure Rust core for Router/A/B derivation and service
protocol logic.

It owns:

- the fixed 2-of-2 ECDSA threshold-PRF adapter
- Deriver A share id `1` and Deriver B share id `2`
- role-specific protocol types, transcript binding, output packages, host
  traits, local simulation, committed vectors, and source guards

Platform adapters live outside this crate. Cloudflare Workers, local SQLite
tooling, and future server runtimes should inject time, randomness, storage,
transport, and identity through explicit boundaries.

## Security Invariant

The target invariant is:

- server-side code never materializes joined `d`, `a`, or `x_client_base`
- client-side code never materializes joined `d`, `a`, `y_server`, or
  `tau_server`
- client opens only `x_client_base`
- server opens only `x_server_base`

This crate owns the derivation and protocol boundaries that make those state
claims enforceable.

## Current Scope

- typed fixed ECDSA threshold-PRF contexts and DLEQ proof bundles
- transcript binding and canonical wire payloads
- role-specific client-output and server-output packages
- host traits and platform-neutral local simulation
- committed protocol vectors
- leakage checks plus Verus and Lean proof scaffolding

See [`specs/ecdsa-threshold-prf.md`](specs/ecdsa-threshold-prf.md) for the fixed
construction and boundary contract.
