# WalletIframe

## Overview

The WalletIframe isolates sensitive wallet operations (passkey authentication and transaction signing) in a separate iframe window. Key benefits:

- **Security**: Private keys and sensitive operations are isolated from the main application
- **WebAuthn Compatibility**: TouchID/FaceID authentication works properly in the iframe context
- **No Popups**: All operations happen within the same window using an invisible overlay
- **Isolation**: Even if the main app is compromised, the wallet remains secure

## How It Works

The system consists of three layers:

1. **SeamsWebIframe** - A proxy that provides the same API as the regular SeamsWeb but routes calls to the iframe
2. **WalletIframeRouter** - Handles communication between the main app and the iframe using MessagePort
3. **Wallet Host** - The actual SeamsWeb running inside the iframe, executing the real operations

When you call methods like `registerPasskey()` or `signTransaction()`, the request flows through these layers. The iframe temporarily expands to capture user activation (TouchID/WebAuthn or iframe-hosted confirmation) when needed, then shrinks back to invisible once that interaction is complete. This is driven by v2 `WalletFlowEvent.interaction.overlay` metadata emitted from SeamsWeb calls.

## Architecture Overview

### Core Components

#### 1. **Entry Point Layer**

- **`SeamsWebIframe.ts`** - The main API that developers interact with. It provides the same interface as the regular SeamsWeb but routes all calls to the iframe.
- **`index.ts`** - Exports all public APIs and types for the WalletIframe system.

#### 2. **Client-Side Communication Layer** (Runs in Parent App)

- **`client/index.ts`** - Client entrypoint; exports `WalletIframeRouter` and `initWalletIframeClient()`.
- **`client/router.ts`** - The `WalletIframeRouter` class that manages all communication with the iframe. It handles:
  - Request/response correlation using unique request IDs
  - Progress event bridging from iframe back to parent callbacks
  - Overlay show/hide logic for user activation
  - Timeout and error handling
- **`client/transport/IframeTransport.ts`** - Low-level iframe management:
  - Creates and mounts the iframe element
  - Handles the CONNECT → READY handshake using MessageChannel
  - Manages iframe permissions and security attributes
  - Waits for iframe load events to avoid race conditions
- **`client/progress/on-events-progress-bus.ts`** - Manages overlay visibility from v2 event metadata:
  - Shows overlay when `interaction.overlay` is `'show'`
  - Hides overlay when `interaction.overlay` is `'hide'`
  - Leaves overlay unchanged when `interaction.overlay` is `'none'`

#### 3. **Host-Side Execution Layer** (Runs in Iframe)

- **`host/index.ts`** - The main service host entry that:
  - Receives messages from the parent via MessagePort
  - Creates and manages the actual SeamsWeb instance
  - Executes wallet operations (register, login, sign, etc.)
  - Sends progress events back to the parent
  - Handles UI component mounting requests
- **`host/lit-ui/iframe-lit-elem-mounter.ts`** - Manages Lit-based UI components inside the iframe:
  - Mounts transaction buttons and other UI elements
  - Wires UI interactions to SeamsWeb methods
  - Handles component lifecycle (mount/unmount/update)
- **`host/lit-ui/iframe-lit-element-registry.ts`** - Declarative registry of available UI components:
  - Defines which Lit components can be mounted
  - Maps UI events to SeamsWeb actions
  - Provides type-safe component definitions

#### 4. **Shared Communication Protocol**

- **`shared/messages.ts`** - Defines the typed message protocol:
  - Parent-to-child message types (PM_REGISTER_WALLET, PM_UNLOCK, etc.)
  - Child-to-parent response types (PROGRESS, PM_RESULT, ERROR)
  - Payload interfaces for all message types
  - `ProgressPayload` (`WalletFlowEvent`) for real-time public flow updates

#### 5. **Supporting Infrastructure**

- **`validation.ts`** - Type guards and validation utilities for message payloads
- **`sanitization.ts`** - Security utilities for HTML and URL sanitization
- **`env.ts`** - Environment variable reading for wallet configuration
- **`html.ts`** - Generates minimal HTML for the wallet service page

### Data Flow Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Your App      │    │  WalletIframe    │    │  Wallet Host    │
│                 │    │                  │    │                 │
│ SeamsWeb   │───▶│ SeamsWeb    │───▶│ SeamsWeb   │
│ Iframe          │    │ Router           │    │ (real instance) │
│                 │    │                  │    │                 │
│                 │    │ IframeTransport  │    │                 │
│                 │    │ ProgressBus      │    │ LitElemMounter  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Hook Calls    │    │  MessagePort     │    │  WebAuthn UI    │
│ (onEvent, etc.) │    │  Communication   │    │  Components     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Key Design Patterns

1. **Proxy Pattern**: `SeamsWebIframe` acts as a transparent proxy to the real SeamsWeb
2. **Message Passing**: All communication uses typed messages over MessagePort
3. **Event Bridging**: Progress events flow from iframe back to parent callbacks
4. **Overlay Management**: Explicit show/hide behavior from `WalletFlowEvent.interaction.overlay`
5. **Component Registry**: Declarative UI component definitions with automatic wiring

### Security Model

- **Origin Isolation**: Wallet operations run in a separate origin/domain
- **Permission Delegation**: WebAuthn permissions are delegated to the iframe
- **Message Validation**: All messages are validated using type guards
- **Capability Delegation**: The iframe grants WebAuthn and clipboard access via explicit `allow` attributes. Sandboxing is intentionally omitted for cross-origin deployments because Chromium drops transferred `MessagePort`s from sandboxed iframes, which would break the CONNECT → READY handshake.
- **No Function Transfer**: Functions never cross the iframe boundary

## Callback Chain for SeamsWebIframe Calls

The callback chain follows this flow:

### 1. **SeamsWebIframe** (Entry Point)

- Acts as a proxy/wrapper around the WalletIframeRouter
- Handles hook callbacks (`afterCall`, `onError`, `onEvent`)
- For example, in `registerWallet()`:
  ```typescript
  const res = await this.client.registerWallet({
    wallet,
    rpId,
    authMethod,
    signerSelection,
    options: { onEvent: options?.onEvent },
  });
  ```

### 2. **WalletIframeRouter** (Communication Layer)

- Manages the iframe and MessagePort communication
- Posts messages to the iframe host via `this.post()` method
- Handles progress events by bridging them back to the caller's `onEvent` callback
- For example, in `registerWallet()`:
  ```typescript
  const res = await this.post<any>(
    {
      type: 'PM_REGISTER_WALLET',
      payload: { wallet, rpId, authMethod, signerSelection, options: safeOptions },
    },
    { onProgress: payload.options?.onEvent },
  );
  ```

### 3. **host/index.ts** (Service Host)

- Receives messages via MessagePort in `onPortMessage()`
- Creates and manages the actual SeamsWeb instance
- Executes the requested operations (like `seams!.registration.registerPasskey()`)
- Sends progress events back via `post({ type: 'PROGRESS', requestId, payload: ev })`
- Returns results via `post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } })`

## Key Communication Flow:

1. **SeamsWebIframe** → calls **WalletIframeRouter** method
2. **WalletIframeRouter** → posts message to iframe via MessagePort
3. **host/index.ts** → receives message, executes SeamsWeb operation
4. **host/index.ts** → sends PROGRESS events during operation
5. **WalletIframeRouter** → bridges PROGRESS events to caller's `onEvent` callback
6. **host/index.ts** → sends final result
7. **WalletIframeRouter** → resolves promise with result
8. **SeamsWebIframe** → calls `afterCall` hook and returns result

## Progress Event Bridging:

The key point is that public progress events are bridged through the MessagePort:

- Host sends: `{ type: 'PROGRESS', requestId, payload: ev }`
- Client receives and calls: `pend?.onProgress?.(msg.payload)`
- This allows the original `onEvent` callback to receive real-time progress updates

`ev` is a v2 `WalletFlowEvent`. Private signer worker progress is not forwarded directly to the app; it is mapped into public flow events only when the flow intentionally exposes that state.

So yes, your understanding is correct: **SeamsWebIframe → WalletIframeRouter → posts to host/index.ts**, with the additional detail that progress events flow back through the same channel to provide real-time updates to the caller.

## Modal Overlay (iframe sizing behavior)

The wallet iframe mounts as a hidden surface. `WalletIframeRouter` owns one
typed foreground surface at a time and the surface renderer is the only writer
of iframe visibility, geometry, focusability, title, and pointer events.

### Surface lifecycle

- `hidden`: no footprint and no hit target.
- `modal_registration_confirm`, `modal_transaction_confirm`,
  `modal_key_export_confirm`, and `modal_unlock_confirm`: viewport modal
  surfaces that expose wallet-origin confirmation controls.

Each foreground surface carries its authenticated connection identity and
request identity. Result, error, cancellation, timeout, and connection close
events clear only a matching active surface. Progress events remain available
to app callbacks and diagnostics; they cannot modify the iframe DOM.

`OverlayController` is a low-level renderer target. The surface renderer uses
its hidden and viewport-modal operations. Styling is CSP-safe and uses the
shared overlay stylesheet. The default z-index is `2147483646`.

### Notes

- Layering: the iframe overlay uses `z-index: 2147483646`, kept one below the inner modal card (2147483647) to ensure the UI remains clickable when visible.
- Debugging: set `window.__W3A_DEBUG__ = true` (or pass `debug: true` to the client) to log surface transitions and progress routing.
