# Ed25519 HSS Advance Source Probe

This benchmark supports Refactor 83C Phase 0. It builds one deterministic
registration HSS advance input and measures the same input across execution
sources:

- `node_server_wasm_probe`, using `wasm/near_signer/pkg-server`;
- `native_release_probe`, by posting the fixture to a native service endpoint;
- `workerd_wasm_probe`, by posting the fixture to a workerd probe endpoint.

Only the Node server-WASM probe is required to run locally before the native
service and workerd probe endpoints exist.

```bash
pnpm benchmark:ed25519-hss:advance-sources -- --skip-optional
```

Optional endpoints use the same JSON fixture:

```bash
pnpm benchmark:ed25519-hss:advance-sources -- \
  --native-url http://127.0.0.1:8788/hss/registration/advance-probe \
  --workerd-url http://127.0.0.1:9444/debug/hss/registration/advance-probe
```

To measure the native service with explicit preflight materialization, pass the
warmup endpoint before the advance endpoint:

```bash
pnpm benchmark:ed25519-hss:advance-sources -- \
  --native-warmup-url http://127.0.0.1:8788/hss/registration/warmup-probe \
  --native-url http://127.0.0.1:8788/hss/registration/advance-probe
```
