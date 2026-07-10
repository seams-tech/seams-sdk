/**
 * OverlayController - Client-Side Communication Layer
 *
 * This module is the centralized controller for managing the wallet iframe's overlay
 * visibility and positioning. It provides a clean abstraction over the complex CSS
 * manipulations needed to show/hide the iframe for WebAuthn user activation.
 *
 * Key Responsibilities:
 * - Overlay Visibility Management: Controls when the iframe is visible vs hidden
 * - Positioning Modes: Supports fullscreen and anchored positioning modes
 * - Sticky Behavior: Prevents overlay from being hidden during critical operations
 * - CSS State Management: Handles all iframe styling for different overlay states
 * - Accessibility: Manages ARIA attributes and tabindex for screen readers
 * - Coordinate Handling: Converts DOMRect coordinates to CSS positioning
 *
 * Architecture:
 * - Single source of truth for iframe overlay state
 * - Mode-based positioning (hidden, fullscreen, anchored)
 * - Sticky mode prevents premature hiding during operations
 * - Clean separation between positioning logic and iframe management
 *
 * Overlay Modes:
 * - hidden: iframe is invisible with no footprint (0x0, pointer-events: none)
 * - fullscreen: iframe covers entire viewport for WebAuthn activation
 * - anchored: iframe positioned at specific coordinates (for inline UI components)
 *
 * Security Considerations:
 * - Uses high z-index (2147483646) to ensure overlay is above other content
 * - Controls pointer-events to avoid blocking page interaction when hidden
 * - Properly manages ARIA attributes for accessibility compliance
 * - Preserves viewport-relative coordinates, including negative offscreen positions
 *
 * Usage Pattern:
 * 1. Create controller with iframe reference
 * 2. Set sticky mode for operations that need persistent overlay
 * 3. Show overlay (fullscreen or anchored) for user activation
 * 4. Hide overlay when activation is complete
 * 5. Clear sticky mode to allow normal hiding behavior
 */

export type DOMRectLike = { top: number; left: number; width: number; height: number };
import { setAnchored, setFullscreen, setHidden } from './overlay-styles';

type Mode = 'hidden' | 'fullscreen' | 'anchored';

export type AnchoredOverlayLease = {
  readonly kind: 'anchored_overlay_lease_v1';
  readonly leaseId: string;
};

export class OverlayController {
  private ensureIframe: () => HTMLIFrameElement;
  private mode: Mode = 'hidden';
  private visible = false;
  private sticky = false;
  private rect: DOMRectLike | null = null;
  private suspended = false;
  private anchoredLease: AnchoredOverlayLease | null = null;
  private leaseCounter = 0;

  constructor(opts: { ensureIframe: () => HTMLIFrameElement }) {
    this.ensureIframe = opts.ensureIframe;
  }

  /**
   * Set sticky mode - prevents overlay from being hidden during critical operations
   * When sticky=true, hide() calls are ignored to maintain overlay visibility
   */
  setSticky(v: boolean): void {
    this.sticky = !!v;
  }

  /**
   * Show overlay in fullscreen mode - covers the viewport
   * Used for WebAuthn activation where user needs to interact with TouchID/FaceID
   * This mode allows the iframe to receive user activation events
   */
  showFullscreen(): void {
    if (this.anchoredLease) return;
    const iframe = this.ensureIframe();
    this.visible = true;
    this.mode = 'fullscreen';
    this.rect = null;

    // Apply fullscreen via CSS classes (CSP-safe)
    setFullscreen(iframe);

    // Step 3: Set accessibility attributes
    iframe.setAttribute('aria-hidden', 'false');
    iframe.removeAttribute('tabindex');
  }

  /**
   * Show overlay in anchored mode - positioned at specific coordinates
   * Used for inline UI components that need to appear at a specific location
   * Coordinates are viewport-relative (from getBoundingClientRect()); values are
   * preserved as measured, with only minimum width/height enforcement
   */
  showAnchored(rect: DOMRectLike): void {
    if (this.anchoredLease) return;
    this.applyAnchored(rect);
  }

  acquireAnchoredLease(): AnchoredOverlayLease | null {
    if (this.anchoredLease || this.visible || this.mode !== 'hidden') return null;
    const lease: AnchoredOverlayLease = Object.freeze({
      kind: 'anchored_overlay_lease_v1',
      leaseId: `anchored-overlay-${++this.leaseCounter}`,
    });
    this.anchoredLease = lease;
    return lease;
  }

  showAnchoredForLease(lease: AnchoredOverlayLease, rect: DOMRectLike): boolean {
    if (this.anchoredLease !== lease) return false;
    this.applyAnchored(rect);
    return true;
  }

  private applyAnchored(rect: DOMRectLike): void {
    const iframe = this.ensureIframe();
    this.visible = true;
    this.mode = 'anchored';
    this.rect = { ...rect };
    this.suspended = false;

    // Apply anchored geometry via dynamic rule + classes (CSP-safe)
    setAnchored(iframe, rect);

    // Step 4: Set accessibility attributes
    iframe.setAttribute('aria-hidden', 'false');
    iframe.removeAttribute('tabindex');
  }

  /**
   * Update anchored rectangle coordinates
   * If overlay is currently in anchored mode, immediately apply new position
   */
  setAnchoredRect(rect: DOMRectLike): void {
    if (this.anchoredLease) return;
    this.rect = { ...rect };
    if (this.visible && this.mode === 'anchored') {
      this.showAnchored(this.rect);
    }
  }

  suspendAnchored(): void {
    if (this.anchoredLease) return;
    this.applyAnchoredSuspension();
  }

  suspendAnchoredForLease(lease: AnchoredOverlayLease): boolean {
    if (this.anchoredLease !== lease) return false;
    this.applyAnchoredSuspension();
    return true;
  }

  private applyAnchoredSuspension(): void {
    if (this.mode !== 'anchored') return;
    const iframe = this.ensureIframe();
    this.visible = false;
    this.suspended = true;
    setHidden(iframe);
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
  }

  /**
   * Show overlay preferring anchored mode when a rect is available.
   * Falls back to fullscreen when no anchored rect has been set yet.
   * Safe to call repeatedly; it will re-apply current state.
   */
  showPreferAnchored(): void {
    if (this.rect) {
      this.showAnchored(this.rect);
    } else {
      this.showFullscreen();
    }
  }

  /**
   * Clear anchored rectangle - removes stored coordinates
   */
  clearAnchoredRect(): void {
    if (this.anchoredLease) return;
    this.rect = null;
  }

  releaseAnchoredLease(lease: AnchoredOverlayLease): boolean {
    if (this.anchoredLease !== lease) return false;
    this.anchoredLease = null;
    this.rect = null;
    this.sticky = false;
    const iframe = this.ensureIframe();
    this.visible = false;
    this.mode = 'hidden';
    this.suspended = false;
    setHidden(iframe);
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
    return true;
  }

  /**
   * Hide overlay - makes iframe invisible with no footprint
   * Respects sticky mode - won't hide if sticky=true
   * Used when WebAuthn activation is complete or operation is cancelled
   */
  hide(): void {
    if (this.anchoredLease) return;
    // Step 1: Check sticky mode - don't hide if operation is still in progress
    if (this.sticky) {
      return;
    }

    const iframe = this.ensureIframe();
    this.visible = false;
    this.mode = 'hidden';
    this.suspended = false;

    // Apply hidden state via classes (CSP-safe)
    setHidden(iframe);

    // Step 3: Set accessibility attributes for hidden state
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
  }

  forceHide(): void {
    if (this.anchoredLease) return;
    this.sticky = false;
    if (!this.visible) return;
    this.hide();
  }

  getState(): {
    visible: boolean;
    mode: Mode;
    sticky: boolean;
    suspended: boolean;
    ownership: 'unowned' | 'anchored_lease';
    rect?: DOMRectLike;
  } {
    return {
      visible: this.visible,
      mode: this.mode,
      sticky: this.sticky,
      suspended: this.suspended,
      ownership: this.anchoredLease ? 'anchored_lease' : 'unowned',
      rect: this.rect || undefined,
    };
  }
}

export default OverlayController;
