# WebAuthnFallbacks - Safari WebAuthn and WASM Worker Compatibility Layer

This directory contains fallback mechanisms to handle Safari-specific limitations with WebAuthn in cross-origin iframe contexts and WASM worker interactions.

## Overview

**Issue 1: WASM Worker Control Message Errors**

- **Symptom:** `invalid type: string 'WORKER_PING', expected u32`
- **Cause:** Control messages with string `type` values reaching Rust handlers that expect numeric enums
- **Solution:** Worker ignores messages without request IDs or with non-numeric `type` values before Rust processing
- **Files:** `workerManager/workerTransport.ts`, `workerManager/workers/near-signer.worker.ts`

**Issue 2: Cross-Origin Ancestor Error**

- **Symptom:** `The origin of the document is not the same as its ancestors`
- **Cause:** Safari blocks WebAuthn in cross-origin iframes
- **Solution:** Parent bridge executes WebAuthn at top-level, postMessages serialized result to iframe
- **Files:** `WalletIframe/client/transport/IframeTransport.ts`, `touchIdPrompt.ts`

**Issue 3: Document Not Focused Error**

- **Symptom:** NotAllowedError about document focus
- **Cause:** Safari requires explicit focus for WebAuthn in iframes
- **Solution:** Refocus retry, then parent bridge fallback if still blocked
- **Files:** `touchIdPrompt.ts`

---

## Safari WASM Worker Bugs

### Problem

Older worker transport code could deliver a control ping `{ type: "WORKER_PING" }` to the signer WASM worker. In Safari, that ping was routed to the Rust handler which expects a numeric `type` (`u32`), causing:

- Error: `invalid type: string 'WORKER_PING', expected u32`
- Registration/signing flows to fail before the first valid RPC request completed

### Root Cause

- Worker transport treats `WORKER_READY` frames as readiness signals and posts numeric RPC requests from `workerManager/workerTransport.ts`
- Rust expects numeric `type` enums, and receiving a string triggers a parse error
- Worker entrypoints reject missing IDs and non-numeric `type` values before WASM dispatch

### Solution

Worker guards against non-numeric control messages:

- Early-return if `typeof event.data?.type !== 'number'`
- Early-return if the request is missing an RPC `id`
- Serialize valid requests through `messageQueue` before WASM dispatch

---

## Safari Cross-Origin WebAuthn

### Problem

Safari blocks WebAuthn (`navigator.credentials.create/get`) in cross-origin iframes with error: `The origin of the document is not the same as its ancestors`, even with proper Permissions Policy delegation.

### Solution: Parent Bridge Pattern

- **Default behavior:** Iframe attempts WebAuthn directly (works in Chrome/Firefox)
- **Safari fallback:** On ancestor error, iframe postMessages request to parent
- **Parent execution:** Parent runs WebAuthn at top-level, serializes credential with PRF, sends result back to iframe
- **Seamless flow:** Iframe receives serialized credential and proceeds normally

### How It Works

#### Runtime Flow

1. Iframe attempts `navigator.credentials.create/get()` with `rpId` and PRF extension
2. If NotAllowedError about ancestors → send `WALLET_WEBAUTHN_CREATE`/`GET` to parent
3. Parent executes WebAuthn at top-level with same options
4. Parent serializes credential (including PRF outputs) and replies with `WALLET_WEBAUTHN_*_RESULT`
5. Iframe resolves promise with serialized credential
6. Downstream code detects pre-serialized credential and skips re-serialization

#### RP ID Strategy

- **Default:** `example.localhost` (parent domain) to align iframe and parent contexts
- **Tradeoff:** Credentials scoped to parent domain, not wallet domain
- **ROR option:** Related Origin Requests (Safari 18+) allows wallet-scoped credentials while executing at parent level

#### Security

- Parent bridge validates `event.origin === walletOrigin`
- Correlation via unique `requestId` with timeouts
- Replies targeted to wallet origin, never `*`
- Parent can observe WebAuthn calls (by design for this architecture)

### Related Origin Requests (ROR)

Enables top-level page on Origin A to create credentials for RP ID B if B opts-in:

- Serve `/.well-known/webauthn` on wallet origin with allowed parent origins
- Example: `{ "origins": ["https://www.example.com"] }`
- Parent executes `navigator.credentials.create()` with `rp.id = "wallet-provider.com"`
- Keeps credentials bound to wallet domain while executing at top-level
- **Dev support:** Wallet dev server can serve a static allowlist via `VITE_ROR_ALLOWED_ORIGINS` (comma-separated absolute origins)

### Permissions Policy

**Parent response header:**

```
Permissions-Policy: publickey-credentials-get=(self "https://wallet.example.localhost"),
                    publickey-credentials-create=(self "https://wallet.example.localhost")
```

**Iframe `allow` attribute:**

- Safari: `publickey-credentials-get *; publickey-credentials-create *; clipboard-read; clipboard-write`
- Other: `publickey-credentials-get 'self' https://wallet.example.localhost; publickey-credentials-create 'self' https://wallet.example.localhost; clipboard-read; clipboard-write`

### When Bridge Activates

- **Registration (`create`):** Always on ancestor error; after refocus retry on focus error
- **Authentication (`get`):** Generally works in iframe with delegation; bridges only on ancestor error fallback

**Key Files:**

- `client/src/core/WebAuthnManager/touchIdPrompt.ts:241` (create fallback)
- `client/src/core/WebAuthnManager/touchIdPrompt.ts:316` (get fallback)
- `client/src/SeamsWeb/walletIframe/client/transport/IframeTransport.ts:87` (parent create handler)
- `client/src/SeamsWeb/walletIframe/client/transport/IframeTransport.ts:106` (parent get handler)
- `client/src/SeamsWeb/walletIframe/client/transport/IframeTransport.ts:131` (iframe permissions)
- `client/src/core/WebAuthnManager/credentialsHelpers.ts` (serialization)
- `client/src/plugins/vite.ts` (dev server headers)

---

## Document Focus Error

### Problem

Safari throws NotAllowedError: "The document is not focused" when WebAuthn called in iframe without explicit focus.

### Solution

1. Attempt `window.focus()` and `document.body.focus()`
2. Brief delays between retry attempts (50ms, 120ms)
3. Retry WebAuthn operation after refocus
4. If still blocked and in iframe → use parent bridge fallback

Implemented in `touchIdPrompt.ts` focus handling before WebAuthn calls.

---

## Architecture Notes

### Fallback Orchestration

- **Single source of truth:** `rpId` resolution centralized in `TouchIdPrompt.getRpId()`
- **Error classification:** Detects ancestor-origin vs focus errors with specific handling
- **Idempotent behavior:** Exactly one resolution path per call, deterministic cleanup of listeners/timers
- **Progressive enhancement:** Direct WebAuthn preferred, fallbacks only when necessary
