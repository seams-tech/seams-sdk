/**
 * OnEventsProgressBus - Client-Side Communication Layer
 *
 * Routes progress events for the wallet iframe.
 *
 * Key Responsibilities:
 * - Progress Routing: Dispatches typed progress payloads to per-request subscribers
 * - Sticky Subscriptions: Supports long-running subscriptions that persist after completion
 * - Event Statistics: Tracks counts/timestamps for debugging
 */

import type { ProgressPayload as MessageProgressPayload } from '../../shared/messages';

export type ProgressPayload = MessageProgressPayload;

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

  constructor(logger?: (msg: string, data?: Record<string, unknown>) => void) {
    this.logger = logger;
  }

  /**
   * Register a subscriber for a requestId.
   */
  register({
    requestId,
    onProgress,
    sticky = false,
  }: {
    requestId: string;
    sticky: boolean;
    onProgress?: (p: ProgressPayload) => void;
  }): void {
    this.subs.set(requestId, {
      onProgress,
      sticky,
      stats: { count: 0, flow: null, phase: null, status: null, lastAt: null },
    });
    this.log('register', { requestId, sticky });
  }

  /**
   * Unregister a subscriber.
   */
  unregister(requestId: string): void {
    if (this.subs.delete(requestId)) this.log('unregister', { requestId });
  }

  /**
   * Remove all subscribers.
   */
  clearAll(): void {
    this.subs.clear();
    this.log('clearAll');
  }

  isSticky(requestId: string): boolean {
    const sub = this.subs.get(requestId);
    return !!sub?.sticky;
  }

  /**
   * Dispatch a progress payload to a request's subscriber.
   */
  dispatch({ requestId, payload }: { requestId: string; payload: ProgressPayload }): boolean {
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
