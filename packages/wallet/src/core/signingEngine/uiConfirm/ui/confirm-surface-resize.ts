/**
 * Host-driven tree growth for wallet-iframe confirmations.
 *
 * In the wallet-iframe modal surface the parent window sizes the iframe to hug
 * this confirmer (surface-measurement-reporter.ts) and eases the box to every
 * new size it hears about (OverlayController.startSurfaceResize, ~220ms). A
 * tree node that animates its own height fights that ease: every frame of the
 * tree's transition posts a fresh measurement, the box restarts its ease from
 * wherever it is, and the card — anchored to the iframe's top-left and already
 * at full height — is clipped by an iframe still catching up.
 *
 * So the order is reversed here. When a tree node starts to open or close, the
 * confirmer host is pinned to the size the card is heading for — exactly one
 * measurement, so the parent runs exactly one ease — and the tree's body height
 * is then fed from the room the iframe has actually made available, frame by
 * frame. The card can never outrun the box, whatever the parent's easing (or
 * its absence under reduced motion) turns out to be.
 *
 * The host is a transparent shell in that surface, so pinning it taller (open)
 * or shorter (close) than its content is invisible. The pin goes through a
 * constructable stylesheet because the wallet origin ships
 * `style-src-attr 'none'`.
 */

import {
  addLitTreeResizeBeginListener,
  type LitTreeResizeBeginDetail,
  type LitTreeResizeDriver,
} from './lit-events';

export const CONFIRM_SURFACE_MODE_ATTR = 'data-w3a-confirm-surface';
export const CONFIRM_SURFACE_MODE_WALLET_IFRAME = 'wallet-iframe';
export const CONFIRM_SURFACE_MODE_STANDALONE = 'standalone';
export const CONFIRM_SURFACE_PINNED_CLASS = 'w3a-confirm-surface-pinned';

/** Frames the box may sit still, after it has moved, before its motion counts as over. */
const SETTLED_FRAMES_AFTER_MOTION = 8;
/** Frames to wait for the parent to react at all before giving up on it. */
const SETTLED_FRAMES_WITHOUT_MOTION = 20;
/**
 * The parent writes the destination box and forces a layout BEFORE it starts
 * its ease, and a cross-origin iframe receives that destination size for one
 * frame before the animation snaps it back to the origin. Landing on that
 * frame finishes the interior instantly and leaves the box to ease on its
 * own — the exact jank this module exists to remove. A box that jumps straight
 * to the target therefore has to stay there this many frames before the body
 * lands on it; a box that eased through intermediate sizes lands at once.
 */
const LANDING_CONFIRM_FRAMES = 3;
/** The parent rounds the measured size; allow that much slack when asking whether the box hugs the host. */
const HUG_TOLERANCE_CSS_PX = 1;

export type ConfirmSurfaceResizeChoreographer = {
  dispose(): void;
};

export type ConfirmSurfaceResizeChoreographerOptions = {
  /** Height of the box the parent gave this document, in CSS px. Defaults to the viewport. */
  readonly viewportHeightCssPx?: () => number;
};

type ActiveResize = {
  readonly driver: LitTreeResizeDriver;
  readonly open: boolean;
  /** Host height with the node closed; the body height is the room above it. */
  readonly closedHostPx: number;
  readonly deltaCssPx: number;
  lastViewportPx: number;
  framesSinceChange: number;
  moved: boolean;
  /** The box was seen strictly between origin and target, so it is easing. */
  sawIntermediate: boolean;
  /** Consecutive frames the box has reported the target without easing there. */
  framesAtTarget: number;
  frame: number | null;
};

type HostHeightPin = {
  set(px: number): boolean;
  release(): void;
  dispose(): void;
};

function defaultViewportHeightCssPx(): number {
  const height = document.documentElement?.clientHeight ?? 0;
  return height > 0 ? height : window.innerHeight;
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(Math.max(value, min), max);
}

export function isWalletIframeConfirmSurface(element: Element): boolean {
  return element.getAttribute(CONFIRM_SURFACE_MODE_ATTR) === CONFIRM_SURFACE_MODE_WALLET_IFRAME;
}

function createHostHeightPin(element: HTMLElement): HostHeightPin | null {
  if (typeof CSSStyleSheet !== 'function' || !('adoptedStyleSheets' in document)) return null;
  let sheet: CSSStyleSheet | null = null;
  const release = () => element.classList.remove(CONFIRM_SURFACE_PINNED_CLASS);
  return {
    set(px) {
      try {
        if (!sheet) sheet = new CSSStyleSheet();
        sheet.replaceSync(
          `.${CONFIRM_SURFACE_PINNED_CLASS}{height:${Math.max(0, Math.round(px))}px}`,
        );
        if (!document.adoptedStyleSheets.includes(sheet)) {
          document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
        }
      } catch {
        return false;
      }
      element.classList.add(CONFIRM_SURFACE_PINNED_CLASS);
      return true;
    },
    release,
    dispose() {
      release();
      if (!sheet) return;
      const retired = sheet;
      sheet = null;
      try {
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== retired);
      } catch {}
    },
  };
}

export function attachConfirmSurfaceResizeChoreographer(
  element: HTMLElement,
  options: ConfirmSurfaceResizeChoreographerOptions = {},
): ConfirmSurfaceResizeChoreographer {
  const readViewportHeightCssPx = options.viewportHeightCssPx ?? defaultViewportHeightCssPx;
  const pin = createHostHeightPin(element);
  let active: ActiveResize | null = null;

  const settle = (): void => {
    const current = active;
    if (!current) return;
    active = null;
    if (current.frame !== null) cancelAnimationFrame(current.frame);
    // Land the body on its target before the pin comes off, so the host's
    // natural height equals the pinned one and the reporter sees no second
    // change from this toggle.
    current.driver.setHeightCssPx(current.open ? current.deltaCssPx : 0);
    current.driver.finish();
    pin?.release();
  };

  const step = (): void => {
    const current = active;
    if (!current) return;
    current.frame = null;
    const viewportPx = readViewportHeightCssPx();
    if (viewportPx !== current.lastViewportPx) {
      current.lastViewportPx = viewportPx;
      current.framesSinceChange = 0;
      current.moved = true;
    } else {
      current.framesSinceChange += 1;
    }
    const bodyPx = clamp(viewportPx - current.closedHostPx, 0, current.deltaCssPx);
    // The pinned target is what the parent applies, rounded on both sides, so
    // the box reaches it exactly; a box the parent clamps short settles below.
    const atTarget = current.open ? bodyPx >= current.deltaCssPx : bodyPx <= 0;
    if (atTarget) {
      current.framesAtTarget += 1;
      if (current.sawIntermediate || current.framesAtTarget >= LANDING_CONFIRM_FRAMES) {
        settle();
        return;
      }
      // Hold the body where it is: this may be the destination blip.
      current.frame = requestAnimationFrame(step);
      return;
    }
    current.framesAtTarget = 0;
    if (current.open ? bodyPx > 0 : bodyPx < current.deltaCssPx) {
      current.sawIntermediate = true;
    }
    current.driver.setHeightCssPx(bodyPx);
    const settledFrames = current.moved
      ? SETTLED_FRAMES_AFTER_MOTION
      : SETTLED_FRAMES_WITHOUT_MOTION;
    if (current.framesSinceChange >= settledFrames) {
      settle();
      return;
    }
    current.frame = requestAnimationFrame(step);
  };

  const onTreeResizeBegin = (event: CustomEvent<LitTreeResizeBeginDetail>): void => {
    const detail = event.detail;
    if (!pin || !detail || !isWalletIframeConfirmSurface(element)) return;
    const deltaCssPx = detail.deltaCssPx;
    if (!Number.isFinite(deltaCssPx) || deltaCssPx <= 0) return;
    // A second toggle mid-motion: land the first one, then measure afresh.
    settle();
    const viewportPx = readViewportHeightCssPx();
    const hostPx = element.getBoundingClientRect().height;
    // Only a box that hugs the host will follow a new measurement 1:1. A
    // clamped or full-viewport box leaves the tree to its own transition,
    // which cannot be clipped there.
    if (
      !(viewportPx > 0) ||
      !(hostPx > 0) ||
      Math.abs(viewportPx - hostPx) > HUG_TOLERANCE_CSS_PX
    ) {
      return;
    }
    const closedHostPx = Math.round(detail.open ? hostPx : hostPx - deltaCssPx);
    if (closedHostPx < 0) return;
    const targetHostPx = detail.open ? closedHostPx + deltaCssPx : closedHostPx;
    if (!pin.set(targetHostPx)) return;
    const driver = detail.claim();
    if (!driver) {
      pin.release();
      return;
    }
    active = {
      driver,
      open: detail.open,
      closedHostPx,
      deltaCssPx,
      lastViewportPx: viewportPx,
      framesSinceChange: 0,
      moved: false,
      sawIntermediate: false,
      framesAtTarget: 0,
      frame: null,
    };
    active.frame = requestAnimationFrame(step);
  };

  const removeListener = addLitTreeResizeBeginListener(element, onTreeResizeBegin);
  return {
    dispose() {
      removeListener();
      settle();
      pin?.dispose();
    },
  };
}
