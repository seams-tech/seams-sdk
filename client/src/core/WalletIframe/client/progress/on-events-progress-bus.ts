/**
 * OnEventsProgressBus - Client-Side Communication Layer
 *
 * Manages progress event routing and overlay visibility *intents* for the wallet
 * iframe. It never manipulates the iframe directly; instead it calls the
 * injected OverlayController interface (show/hide), and WalletIframeRouter
 * owns the concrete OverlayController that knows how to display the iframe.
 *
 * Key Responsibilities:
 * - Progress Routing: Dispatches typed progress payloads to per-request subscribers
 * - Overlay Intents: Applies SHOW/HIDE based on event metadata, leaving actual
 *   DOM/CSS work to WalletIframeRouter + OverlayController
 * - Concurrent Aggregation: Tracks overlay demand per requestId and only hides
 *   when no request still requires SHOW (multi-request safe)
 * - Sticky Subscriptions: Supports long-running subscriptions that persist after completion
 * - Overlay Resolution: Pluggable logic to map payloads to 'show' | 'hide' | 'none'
 * - Event Statistics: Tracks counts/timestamps for debugging
 */

import type { ProgressPayload as MessageProgressPayload } from '../../shared/messages';

export type ProgressPayload = MessageProgressPayload;

// Minimal overlay control interface used by ProgressBus.
// Implemented by WalletIframeRouter via an adapter object that calls
// into the concrete OverlayToggler (fullscreen/anchored) as needed.
export interface OverlayToggler {
  show: () => void;
  hide: () => void;
}

export type OverlayIntentResolver = (payload: ProgressPayload) => 'show' | 'hide' | 'none';

export interface ProgressStats {
  count: number;
  flow: string | null;
  phase: string | null;
  status: string | null;
  lastAt: number | null;
}

export interface ProgressSubscriber {
  onProgress?: (payload: ProgressPayload) => void;
  sticky: boolean;
  stats: ProgressStats;
}

export class OnEventsProgressBus {
  private subs = new Map<string, ProgressSubscriber>();
  private logger?: (msg: string, data?: Record<string, unknown>) => void;
  private overlay: OverlayToggler;
  private resolveOverlayIntent: OverlayIntentResolver;
  // Track the most recent overlay intent per requestId so that we can
  // aggregate visibility across concurrent requests. If any request's
  // latest intent is 'show', we keep the overlay visible.
  private overlayDemands = new Map<string, 'show' | 'hide' | 'none'>();

  constructor(
    overlay: OverlayToggler,
    resolveOverlayIntent: OverlayIntentResolver,
    logger?: (msg: string, data?: Record<string, unknown>) => void,
  ) {
    this.overlay = overlay;
    this.resolveOverlayIntent = resolveOverlayIntent;
    this.logger = logger;
  }

  /**
   * Register a subscriber for a requestId.
   * Initializes demand tracking to 'none' (neutral) until phases arrive.
   */
  register({
    requestId,
    onProgress,
    sticky = false,
    initialDemand = 'none',
  }: {
    requestId: string;
    sticky: boolean;
    onProgress?: (p: ProgressPayload) => void;
    initialDemand?: 'show' | 'hide' | 'none';
  }): void {
    const demand = initialDemand === 'show' || initialDemand === 'hide' ? initialDemand : 'none';
    this.subs.set(requestId, {
      onProgress,
      sticky,
      stats: { count: 0, flow: null, phase: null, status: null, lastAt: null },
    });
    // Initialize demand tracking for this request (used to prevent racey hides).
    this.overlayDemands.set(requestId, demand);
    this.log('register', { requestId, sticky });
  }

  /**
   * Unregister a subscriber and clear its overlay demand.
   * If no remaining requests demand 'show', the overlay is hidden.
   */
  unregister(requestId: string): void {
    if (this.subs.delete(requestId)) this.log('unregister', { requestId });
    // Remove any overlay demand for this request
    this.overlayDemands.delete(requestId);
    // If no remaining requests demand 'show', we can safely hide
    if (!this.wantsVisible()) {
      try {
        this.overlay.hide();
      } catch {}
    }
  }

  /**
   * Remove all subscribers and demands; overlay demand set is cleared.
   */
  clearAll(): void {
    this.subs.clear();
    this.overlayDemands.clear();
    this.log('clearAll');
  }

  /**
   * Clear only the overlay demand for a request while keeping its subscriber.
   * Useful for sticky subscriptions that must continue receiving progress events
   * after an initial PM_RESULT, without pinning the overlay in "show".
   */
  clearDemand(requestId: string): void {
    if (!requestId) return;
    this.overlayDemands.delete(requestId);
    this.log('clearDemand', { requestId });
  }

  isSticky(requestId: string): boolean {
    const sub = this.subs.get(requestId);
    return !!sub?.sticky;
  }

  /**
   * Dispatch a progress payload to a request's subscriber and update
   * the aggregate overlay demand based on explicit event metadata.
   */
  dispatch({ requestId, payload }: { requestId: string; payload: ProgressPayload }): boolean {
    const action = this.resolveOverlayIntent(payload);

    // Update the latest demand for this request.
    // If the event returns 'none', preserve any existing demand to avoid
    // clearing a preflight "show" before real phases arrive.
    const prevDemand = this.overlayDemands.get(requestId) || 'none';
    const nextDemand = action === 'none' ? prevDemand : action;
    this.overlayDemands.set(requestId, nextDemand);

    // Apply aggregated overlay visibility:
    // - If any request currently demands 'show', ensure overlay is visible
    // - Only hide when no outstanding 'show' demands remain
    if (action === 'show') {
      try {
        this.overlay.show();
      } catch {}
    } else if (action === 'hide') {
      if (!this.wantsVisible()) {
        try {
          this.overlay.hide();
        } catch {}
      }
    }

    const sub = this.subs.get(requestId);
    if (sub) {
      this.bumpStats(sub, payload);
      try {
        sub.onProgress?.(payload);
      } catch {}
      this.log('dispatch', {
        requestId,
        flow: sub.stats.flow || undefined,
        phase: sub.stats.phase || undefined,
        status: sub.stats.status || undefined,
        sticky: sub.sticky,
      });
      return true;
    }

    // Deliver to sticky-only subscriber if present (e.g., flow finished but status updates continue)
    const sticky = this.findSticky(requestId);
    if (sticky) {
      this.bumpStats(sticky, payload);
      try {
        sticky.onProgress?.(payload);
      } catch {}
      this.log('dispatch-sticky', {
        requestId,
        flow: sticky.stats.flow || undefined,
        phase: sticky.stats.phase || undefined,
        status: sticky.stats.status || undefined,
      });
      return true;
    }
    this.log('dispatch-miss', {
      requestId,
      flow: payload?.flow,
      phase: payload?.phase,
      status: payload?.status,
    });
    return false;
  }

  getStats(requestId: string): ProgressStats | null {
    const sub = this.subs.get(requestId);
    return sub ? sub.stats : null;
  }

  /**
   * Returns true if any tracked request currently demands the overlay be visible.
   * Useful for higher layers (router) to avoid premature hides on completion/timeout.
   */
  wantsVisible(): boolean {
    for (const v of this.overlayDemands.values()) {
      if (v === 'show') return true;
    }
    return false;
  }

  private findSticky(requestId: string): ProgressSubscriber | null {
    const sub = this.subs.get(requestId);
    if (sub && sub.sticky) return sub;
    // sticky subscribers are keyed by the same requestId in this design
    return null;
  }

  private bumpStats(sub: ProgressSubscriber, payload: ProgressPayload) {
    sub.stats.count += 1;
    sub.stats.flow = payload?.flow ? String(payload.flow) : null;
    sub.stats.phase = payload?.phase ? String(payload.phase) : null;
    sub.stats.status = payload?.status ? String(payload.status) : null;
    sub.stats.lastAt = Date.now();
  }

  private log(msg: string, data?: Record<string, unknown>) {
    try {
      this.logger?.(msg, data);
    } catch {}
  }
}

/**
 * defaultOverlayIntentResolver
 *
 * Decides when to expand or contract the invisible wallet iframe overlay
 * based on incoming progress event metadata. Returning:
 *  - 'show' → expands the iframe to a full-screen, invisible layer that captures
 *             user activation (e.g., TouchID / WebAuthn prompts) and pointer events.
 *  - 'hide' → immediately contracts the iframe back to 0×0 so it no longer blocks clicks.
 *  - 'none' → no change.
 *
 * Important UX constraint: the overlay covers the entire viewport and is
 * intentionally invisible. While expanded, it will intercept clicks and can
 * block interactions with the app. Therefore, we must minimize the time it is
 * expanded and only show it during the brief windows where user activation is
 * required (e.g., when the TouchID prompt is about to appear or the modal is
 * mounting and needs focus/activation in the iframe context). As soon as
 * activation completes, the emitting flow sends `interaction.overlay: 'hide'`.
 *
 * WalletFlowEvent payloads declare overlay intent explicitly at
 * `interaction.overlay`. Terminal v2 events receive `overlay: 'hide'` from the
 * shared event constructor, so this bus no longer infers behavior from phase
 * names.
 */
export const defaultOverlayIntentResolver: OverlayIntentResolver = (payload: ProgressPayload) => {
  try {
    const overlay = payload?.interaction?.overlay;
    if (isOverlayIntent(overlay)) return overlay;

    return 'none';
  } catch {
    return 'none';
  }
};

function isOverlayIntent(value: unknown): value is 'show' | 'hide' | 'none' {
  return value === 'show' || value === 'hide' || value === 'none';
}
