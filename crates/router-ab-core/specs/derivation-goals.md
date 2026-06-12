# Split Derivation Goals

The split-derivation primitive exists to support Router/A/B registration,
export, and refresh ceremonies without creating joined secrets inside one
process.

## Target Invariant

- server-side code never materializes joined `d`, `a`, or `x_client_base`
- client-side code never materializes joined `d`, `a`, `y_relayer`, or
  `tau_relayer`
- client opens only `x_client_base`
- server opens only `x_relayer_base`

## Protocol Boundary

This crate owns:

- canonical derivation context
- candidate derivation formulas
- transcript binding
- vector format
- leakage checklist
- proof-facing models

This crate does not own:

- Cloudflare Worker routing
- HTTP envelope encryption
- session auth
- rate limiting
- relayer deployment topology
- storage backends

Those pieces should call into this crate through a thin adapter.
