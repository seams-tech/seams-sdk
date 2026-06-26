# Security Review 2: Ed25519 Round-1 Nonce Lifecycle Hardening

Date: 2026-06-26

Scope:

- `crates/ed25519-hss/src/role_signing.rs`
- Router A/B Ed25519 normal-signing round-1 storage and take paths.
- Router A/B Ed25519 presign-pool storage and take paths.
- Client-side worker-material Ed25519 presign handles in `wasm/near_signer`.
- SDK-web presign reservation and finalize orchestration.

## Summary

I found no active classic signing nonce reuse in the reviewed Ed25519 role-signing or server round-1 storage paths.

The remaining items are client-side nonce-lifecycle hardening issues:

- A reserved client presign can leave nonce bytes resident in WASM memory if WASM signing fails before the nonce handle is taken.
- Client presign nonce handles are predictable counters.

These are low to medium-low operational risks. They do not expose nonce bytes to the server, and the normal SDK path removes a presign from the JS pool before signing. They are still worth fixing because the handle is a local capability for nonce material.

## Required Fixes

### 1. Burn the reserved WASM nonce handle on presign failure

Current behavior:

- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts` reserves a ready presign before calling `signThresholdEd25519ClientPresignFromMaterialHandleWasm`.
- The JS reservation is burned in the catch path.
- The WASM nonce bytes are removed only after `take_client_presign_nonce` runs in `wasm/near_signer/src/threshold/worker_material.rs`.
- If request validation, material lookup, or another pre-take operation fails, the JS pool drops the reservation while the WASM nonce bytes can remain in the thread-local nonce map.

Change:

- In `signReservedRouterAbEd25519Presign`, explicitly call `burnThresholdEd25519ClientPresignWasm` for the reserved `entry.nonceHandle` on failure.
- Preserve the original signing/finalize error if cleanup fails.
- Keep burning the JS reservation after the cleanup attempt.
- It is acceptable for this cleanup to be idempotent. If signing already consumed the nonce, the cleanup can no-op or return an ignored miss.

Expected shape:

```ts
function ignoreClientPresignBurnFailure(): void {}

try {
  // existing sign and finalize flow
} catch (error) {
  await burnThresholdEd25519ClientPresignWasm({
    sessionId: input.thresholdSessionId,
    clientNonceHandleB64u: reservation.reservation.entry.nonceHandle,
    workerCtx: input.ctx,
  }).catch(ignoreClientPresignBurnFailure);

  burnThresholdEd25519ReservedPresign({
    scopeKey: reservation.scopeKey,
    reservation: reservation.reservation,
    reason: signedShare ? 'send_attempted' : 'rejected',
  });

  throw error;
}
```

Acceptance criteria:

- A failed reserved-presign signing attempt burns both the JS reservation and the WASM nonce handle.
- Cleanup failure does not replace the original signing or finalize error.
- Existing behavior after successful signing stays one-use: WASM consumes the nonce before returning the client signature share, and the JS reservation is burned after finalize.
- Add a focused SDK-web test or source guard for the failure path so reserved presign failures cannot skip the WASM burn call.

### 2. Replace predictable client presign handles with random handles

Current behavior:

- `wasm/near_signer/src/threshold/worker_material.rs` creates handles with `CLIENT_PRESIGN_HANDLE_COUNTER`.
- `next_client_presign_handle` returns strings shaped like `ed25519-client-presign:{id}`.
- The handle is an opaque local reference to nonce material held inside the WASM worker.

Change:

- Generate at least 128 bits of randomness for each client presign handle.
- Use the existing worker random-byte helper or direct CSPRNG plumbing already used in the module.
- Return `Result<String, JsValue>` from `next_client_presign_handle` if randomness can fail, then propagate the error from `create_client_presign_from_worker_material`.
- Remove the counter from client presign nonce handles after the random path lands.

Expected shape:

```rust
fn next_client_presign_handle() -> Result<String, JsValue> {
    let bytes = random_fixed_bytes::<16>("client presign handle")?;
    Ok(format!(
        "ed25519-client-presign:{}",
        base64_url_encode(&bytes)
    ))
}
```

Acceptance criteria:

- Newly created client presign handles contain CSPRNG output.
- No active source still formats client presign handles from a monotonic counter.
- Existing external request and response fields can keep their current names; callers must continue to treat the handle as opaque.
- Add a focused Rust test or source guard that rejects the old `format!("ed25519-client-presign:{id}")` pattern.

## Safe Paths Reviewed

### Ed25519 role signing

`crates/ed25519-hss/src/role_signing.rs` generates hiding and binding nonce scalars from a `CryptoRng`, stores them in zeroizing secret state, validates commitments before use, and redacts secret fields from debug output.

### Server round-1 storage

Cloudflare and local-dev round-1 storage use take-style APIs. The server record is looked up, validated against the handle and binding digest, removed from storage, then passed to finalize.

### Server presign-pool storage

The server presign-pool hit paths also use take-style storage. A pool entry is removed before the server role-signing share is finalized.

### HSS key derivation

The HSS modules derive key/share material. They do not produce Ed25519 FROST or ECDSA signing nonces, so the classic signature nonce reuse risk remains in the signing and presign paths.

## Validation For The Fix

Run the cheapest checks that exercise the changed boundaries:

- `cargo test --manifest-path wasm/near_signer/Cargo.toml`
- `pnpm -C packages/sdk-web type-check`
- A focused SDK-web test or guard for reserved-presign failure cleanup.
- A focused Rust test or guard for random client presign handle generation.
