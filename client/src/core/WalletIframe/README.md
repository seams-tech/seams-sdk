# WalletIframe

## Overview

The WalletIframe isolates sensitive wallet operations (passkey authentication and transaction signing) in a separate iframe window. Key benefits:

- **Security**: Private keys and sensitive operations are isolated from the main application
- **WebAuthn Compatibility**: TouchID/FaceID authentication works properly in the iframe context
- **No Popups**: All operations happen within the same window using an invisible overlay
- **Isolation**: Even if the main app is compromised, the wallet remains secure

## How It Works

The system consists of three layers:

1. **SeamsPasskeyIframe** - A proxy that provides the same API as the regular SeamsPasskey but routes calls to the iframe
2. **WalletIframeRouter** - Handles communication between the main app and the iframe using MessagePort
3. **Wallet Host** - The actual SeamsPasskey running inside the iframe, executing the real operations

When you call methods like `registerPasskey()` or `signTransaction()`, the request flows through these layers. The iframe temporarily expands to capture user activation (TouchID/WebAuthn or iframe-hosted confirmation) when needed, then shrinks back to invisible once that interaction is complete. This is driven by v2 `WalletFlowEvent.interaction.overlay` metadata emitted from SeamsPasskey calls.

## Architecture Overview

### Core Components

#### 1. **Entry Point Layer**

- **`SeamsPasskeyIframe.ts`** - The main API that developers interact with. It provides the same interface as the regular SeamsPasskey but routes all calls to the iframe.
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
  - Creates and manages the actual SeamsPasskey instance
  - Executes wallet operations (register, login, sign, etc.)
  - Sends progress events back to the parent
  - Handles UI component mounting requests
- **`host/lit-ui/iframe-lit-elem-mounter.ts`** - Manages Lit-based UI components inside the iframe:
  - Mounts transaction buttons and other UI elements
  - Wires UI interactions to SeamsPasskey methods
  - Handles component lifecycle (mount/unmount/update)
- **`host/lit-ui/iframe-lit-element-registry.ts`** - Declarative registry of available UI components:
  - Defines which Lit components can be mounted
  - Maps UI events to SeamsPasskey actions
  - Provides type-safe component definitions

#### 4. **Shared Communication Protocol**

- **`shared/messages.ts`** - Defines the typed message protocol:
  - Parent-to-child message types (PM_REGISTER, PM_UNLOCK, etc.)
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
│ SeamsPasskey   │───▶│ SeamsPasskey    │───▶│ SeamsPasskey   │
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

1. **Proxy Pattern**: `SeamsPasskeyIframe` acts as a transparent proxy to the real SeamsPasskey
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

## Callback Chain for SeamsPasskeyIframe Calls

The callback chain follows this flow:

### 1. **SeamsPasskeyIframe** (Entry Point)

- Acts as a proxy/wrapper around the WalletIframeRouter
- Handles hook callbacks (`afterCall`, `onError`, `onEvent`)
- For example, in `registerPasskey()`:
  ```typescript
  const res = await this.client.registerPasskey({
    nearAccountId,
    options: { onEvent: options?.onEvent },
  });
  ```

### 2. **WalletIframeRouter** (Communication Layer)

- Manages the iframe and MessagePort communication
- Posts messages to the iframe host via `this.post()` method
- Handles progress events by bridging them back to the caller's `onEvent` callback
- For example, in `registerPasskey()`:
  ```typescript
  const res = await this.post<any>(
    {
      type: 'PM_REGISTER',
      payload: { nearAccountId: payload.nearAccountId, options: safeOptions },
    },
    { onProgress: payload.options?.onEvent },
  );
  ```

### 3. **host/index.ts** (Service Host)

- Receives messages via MessagePort in `onPortMessage()`
- Creates and manages the actual SeamsPasskey instance
- Executes the requested operations (like `seams!.registration.registerPasskey()`)
- Sends progress events back via `post({ type: 'PROGRESS', requestId, payload: ev })`
- Returns results via `post({ type: 'PM_RESULT', requestId, payload: { ok: true, result } })`

## Key Communication Flow:

1. **SeamsPasskeyIframe** → calls **WalletIframeRouter** method
2. **WalletIframeRouter** → posts message to iframe via MessagePort
3. **host/index.ts** → receives message, executes SeamsPasskey operation
4. **host/index.ts** → sends PROGRESS events during operation
5. **WalletIframeRouter** → bridges PROGRESS events to caller's `onEvent` callback
6. **host/index.ts** → sends final result
7. **WalletIframeRouter** → resolves promise with result
8. **SeamsPasskeyIframe** → calls `afterCall` hook and returns result

## Progress Event Bridging:

The key point is that public progress events are bridged through the MessagePort:

- Host sends: `{ type: 'PROGRESS', requestId, payload: ev }`
- Client receives and calls: `pend?.onProgress?.(msg.payload)`
- This allows the original `onEvent` callback to receive real-time progress updates

`ev` is a v2 `WalletFlowEvent`. Private signer worker progress is not forwarded directly to the app; it is mapped into public flow events only when the flow intentionally exposes that state.

So yes, your understanding is correct: **SeamsPasskeyIframe → WalletIframeRouter → posts to host/index.ts**, with the additional detail that progress events flow back through the same channel to provide real-time updates to the caller.

## Activation Overlay (iframe sizing behavior)

The wallet iframe mounts as an invisible 0×0 element and temporarily expands to a full‑screen overlay when user activation (e.g., TouchID/WebAuthn) is needed. This lets the wallet host collect credentials in the same browsing context while satisfying WebAuthn requirements.

### OverlayController (state owner)

The OverlayController is the single owner of wallet iframe overlay state. It manages
visibility, positioning, and sticky behavior without scattering style writes across
router code. Styling is CSP-safe and applied via CSS classes and a shared stylesheet.

#### Modes

- `hidden`: no footprint, pointer-events disabled
- `fullscreen`: fixed inset, fills viewport for WebAuthn activation
- `anchored`: fixed rect at specific viewport coordinates

#### API (current)

```ts
type DOMRectLike = { top: number; left: number; width: number; height: number };

class OverlayController {
  constructor(opts: { ensureIframe: () => HTMLIFrameElement });
  showFullscreen(): void;
  showAnchored(rect: DOMRectLike): void;
  showPreferAnchored(): void; // anchored if rect set, else fullscreen
  setAnchoredRect(rect: DOMRectLike): void;
  clearAnchoredRect(): void;
  setSticky(v: boolean): void; // hide() is ignored when sticky
  hide(): void;
  getState(): {
    visible: boolean;
    mode: 'hidden' | 'fullscreen' | 'anchored';
    sticky: boolean;
    rect?: DOMRectLike;
  };
}
```

#### Router integration

- Router owns the controller instance and is the only caller.
- `computeOverlayIntent()` decides whether to show fullscreen before posting a request.
- `OnEventsProgressBus` decides when to hide after completion; the controller just executes.
- `setOverlayBounds()` anchors the iframe for inline UI overlays.

#### Styling notes

- Uses class-based styling from `client/src/core/WalletIframe/client/overlay/overlay-styles.ts` (no inline styles).
- Anchored rects are clamped to non-negative coordinates with minimum size.
- Default z-index is `2147483646` via `--w3a-wallet-overlay-z`.

### Overlay lifecycle

- Initial mount (hidden):
  - `client/src/core/WalletIframe/client/transport/IframeTransport.ts` mounts the iframe with `w3a-wallet-overlay is-hidden`, `width/height: 0`, `aria-hidden`, and `tabindex=-1` so it is invisible yet present in the DOM. Base styles come from `client/src/core/WalletIframe/client/overlay/overlay-styles.ts`.

- Expand to full‑screen during activation:
  - `showFrameForActivation()` in `client/src/core/WalletIframe/client/router.ts` ensures the iframe exists and delegates to `OverlayController.showFullscreen()`, which applies the fullscreen class (fixed inset, pointer-events enabled, z-index 2147483646).
  - This is invoked explicitly for sensitive flows (e.g., `registerPasskey()`, `seams.auth.unlock()`, transaction signing, key export, and link-device authorization) and by v2 progress events with `interaction.overlay: 'show'`.

- Collapse back to 0×0:
  - `hideFrameForActivation()` in the same router delegates to `OverlayController.hide()` to restore the hidden state and make it non-interactive.
  - The router calls `hideFrameForActivation()` when a request finishes (success or error) unless the flow is marked sticky (UI-managed lifecycle).

- Anchored overlays for inline UI:
  - `setOverlayBounds()` anchors the iframe to a DOMRect via `OverlayController.showAnchored()` for UI components that must appear at a specific viewport location.

- When the overlay shows/hides automatically:
  - `client/src/core/WalletIframe/client/progress/on-events-progress-bus.ts` implements `defaultOverlayIntentResolver`, which reads v2 `WalletFlowEvent.interaction.overlay`.
  - Behavior is declared by each emitted event:
    - `overlay: 'show'` for phases that require immediate user activation or an iframe-hosted confirmation prompt.
    - `overlay: 'hide'` when activation is complete, the user leaves the app for recovery, or a terminal failed/cancelled event must close a prior prompt.
    - `overlay: 'none'` for non-interactive threshold signer, nonce, broadcast, persistence, polling, and finalization work.
    - Link-device QR display uses `overlay: 'hide'` because the QR screen is app-owned; later link authorization/passkey phases emit `overlay: 'show'` when the iframe must capture activation.

### Why the overlay may block clicks after sending

With explicit v2 overlay metadata, the overlay collapses immediately after the event that completes the user-interactive step, even if subsequent signing, broadcasting, or waiting events continue. This minimizes the time the overlay blocks clicks.

### Options to adjust behavior

- Adjust the emitting event metadata:
  - Set `interaction.overlay` on the flow event that owns the UI transition. The progress bus should stay a small metadata reader.

- Last‑resort local control:
  - If needed for a specific integration, you can wrap calls with your own timing to ensure the overlay hides immediately after activation by ensuring the flow emits the appropriate `interaction.overlay: 'hide'` event promptly.

### Notes

- Layering: the iframe overlay uses `z-index: 2147483646`, kept one below the inner modal card (2147483647) to ensure the UI remains clickable when visible.
- Debugging: set `window.__W3A_DEBUG__ = true` (or pass `debug: true` to the client) to log overlay/phase routing decisions from the progress bus.
