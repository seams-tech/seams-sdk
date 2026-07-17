/**
 * OverlayController - Client-Side Communication Layer
 *
 * Low-level DOM/CSS writer for wallet iframe visibility and positioning. Typed
 * surfaces are rendered through applyHidden(), applyAnchored(),
 * applyAnchoredSuspended(), and applyViewportModal().
 *
 * Key Responsibilities:
 * - Overlay Visibility Management: Controls when the iframe is visible vs hidden
 * - Positioning Modes: Supports fullscreen and anchored positioning modes
 * - CSS State Management: Handles all iframe styling for different overlay states
 * - Accessibility: Manages ARIA attributes and tabindex for screen readers
 * - Coordinate Handling: Converts DOMRect coordinates to CSS positioning
 *
 * Architecture:
 * - Mirrors the last DOM mode for diagnostics
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
 * 2. Render one surface-derived DOM mode
 * 3. Render hidden when the owning surface finishes
 */

export type DOMRectLike = { top: number; left: number; width: number; height: number };
import { setAnchored, setFullscreen, setHidden } from './overlay-styles';

type Mode = 'hidden' | 'fullscreen' | 'anchored';

export class OverlayController {
  private ensureIframe: () => HTMLIFrameElement;
  private mode: Mode = 'hidden';
  private visible = false;
  private rect: DOMRectLike | null = null;
  private suspended = false;

  constructor(opts: { ensureIframe: () => HTMLIFrameElement }) {
    this.ensureIframe = opts.ensureIframe;
  }

  applyAnchored(rect: DOMRectLike, accessibility: { title?: string }): void {
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
    this.applyTitle(iframe, accessibility.title);
  }

  applyAnchoredSuspended(accessibility: { title?: string }): void {
    const iframe = this.ensureIframe();
    this.mode = 'anchored';
    this.visible = false;
    this.suspended = true;
    setHidden(iframe);
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
    this.applyTitle(iframe, accessibility.title);
  }

  applyViewportModal(accessibility: { title?: string }): void {
    const iframe = this.ensureIframe();
    this.visible = true;
    this.mode = 'fullscreen';
    this.rect = null;
    this.suspended = false;
    setFullscreen(iframe);
    iframe.setAttribute('aria-hidden', 'false');
    iframe.removeAttribute('tabindex');
    this.applyTitle(iframe, accessibility.title);
  }

  applyHidden(): void {
    this.rect = null;
    this.visible = false;
    this.mode = 'hidden';
    this.suspended = false;
    const iframe = this.ensureIframe();
    setHidden(iframe);
    iframe.setAttribute('aria-hidden', 'true');
    iframe.setAttribute('tabindex', '-1');
    iframe.removeAttribute('title');
  }

  private applyTitle(iframe: HTMLIFrameElement, title: string | undefined): void {
    if (title) {
      iframe.setAttribute('title', title);
      return;
    }
    iframe.removeAttribute('title');
  }

  getState(): {
    visible: boolean;
    mode: Mode;
    suspended: boolean;
    rect?: DOMRectLike;
  } {
    return {
      visible: this.visible,
      mode: this.mode,
      suspended: this.suspended,
      rect: this.rect || undefined,
    };
  }
}

export default OverlayController;
