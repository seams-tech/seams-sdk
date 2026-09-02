/**
 * Host-driven height changes for wallet-iframe confirmations.
 *
 * In the wallet-iframe modal surface the parent window sizes the iframe to hug
 * this confirmer (surface-measurement-reporter.ts) and eases the box to every
 * new size it hears about (OverlayController.startSurfaceResize). Content that
 * animates its own height fights that ease: every frame of the animation posts
 * a fresh measurement, the box restarts its ease from wherever it is, and the
 * card — anchored to the iframe's top-left and already at full height — is
 * clipped by an iframe still catching up.
 *
 * So the order is reversed here. A component about to change height clamps
 * itself at its pre-change height and announces the change; the confirmer host
 * is pinned to the size it is heading for — exactly one measurement, so the
 * parent runs exactly one ease — and the component is then driven from the
 * room the iframe has actually made available, frame by frame. The content can
 * never outrun the box, whatever the parent's easing (or its absence under
 * reduced motion) turns out to be.
 *
 * The host is a transparent shell in that surface, so pinning it taller or
 * shorter than its content is invisible. The pin goes through a constructable
 * stylesheet because the wallet origin ships `style-src-attr 'none'`.
 *
 * Refactor 116 owns the rules this module enforces; see
 * `docs/refactor-116-lit-component-consolidation.md`.
 */

import {
  addLitSurfaceResizeBeginListener,
  dispatchLitSurfaceResizeBegin,
  type LitSurfaceResizeBeginDetail,
  type LitSurfaceResizeDriver,
} from './lit-events';
export const CONFIRM_SURFACE_MODE_ATTR = 'data-w3a-confirm-surface';
export const CONFIRM_SURFACE_MODE_WALLET_IFRAME = 'wallet-iframe';
export const CONFIRM_SURFACE_MODE_STANDALONE = 'standalone';
/** Marks the confirmer host while its height is held at a motion's target. */
export const CONFIRM_SURFACE_PINNED_CLASS = 'w3a-confirm-surface-pinned';
/**
 * Marks the document root for the same span. It is a second class rather than
 * the one above because the host rule must match any element that hosts a
 * confirmation — including the plain container the component suites mount —
 * so it cannot be qualified by tag, and an unqualified height rule would
 * otherwise also size `<html>`.
 */
export const CONFIRM_SURFACE_PINNED_ROOT_CLASS = 'w3a-confirm-surface-pinned-root';
/** Marks an element whose height is being driven through a motion. */
export const CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS = 'w3a-surface-height-driven';
/** The CSS variable the class above reads. Components own the write (CSP). */
export const CONFIRM_SURFACE_HEIGHT_DRIVEN_VAR = '--w3a-surface-height-driven-target';

/** Frames the box may sit still, after it has moved, before its motion counts as over. */
const SETTLED_FRAMES_AFTER_MOTION = 8;
/** Frames to wait for the parent to react at all before giving up on it. */
const SETTLED_FRAMES_WITHOUT_MOTION = 20;
/**
 * The parent writes the destination box and forces a layout BEFORE it starts
 * its ease, and a cross-origin iframe can receive that destination size for one
 * frame before the animation snaps it back to the origin. Landing on that
 * frame finishes the interior instantly and leaves the box to ease on its
 * own — the exact jank this module exists to remove. A box that jumps straight
 * to the target therefore has to stay there this many frames before the
 * content lands on it; a box that eased through intermediate sizes lands at
 * once. The parent pins the iframe to the origin for that read
 * (`overlay-styles.ts pinDialogIframe`), so this is the second of two guards.
 */
const LANDING_CONFIRM_FRAMES = 3;
/** The parent rounds the measured size; allow that much slack when asking whether the box hugs the host. */
const HUG_TOLERANCE_CSS_PX = 1;
/** A host that claims a motion and never lands it must not leave content clamped. */
const ANNOUNCE_SAFETY_MS = 1500;
/** Height changes below this are not worth a motion, and round to nothing. */
const MIN_ANNOUNCED_DELTA_CSS_PX = 1;

/**
 * What a component hands over when it is about to change its own height.
 *
 * The contract, in order: lay out the new content, clamp the changing element
 * at `fromCssPx`, then announce. The clamp must be in place before the call,
 * because a host measures itself synchronously while the announcement is
 * dispatched and would otherwise read a change that has already happened. It
 * must go through a stylesheet or CSS variable — never a style attribute,
 * since the wallet origin ships `style-src-attr 'none'`.
 */
export type SurfaceResizeAnnouncement = {
  /** Diagnostics label: a tree node id, `file-content-mode`, `confirm-body`. */
  readonly reason?: string;
  /** Height of the changing element before the change, in CSS px. */
  readonly fromCssPx: number;
  /** Height of the changing element after the change, in CSS px. */
  readonly toCssPx: number;
  /** Called once, when a host takes the motion, before the first height is written. */
  onClaimed?(): void;
  /** Hold the changing element at this height, in CSS px. */
  setHeightCssPx(px: number): void;
  /** Release the clamp and commit the final DOM state. Runs at most once. */
  finish(): void;
};

/**
 * Offer a height change to the surrounding surface before making it.
 *
 * Returns true when a host claimed the motion and now owns it: the component
 * must not animate, and its `finish` will be called when the box has arrived.
 * Returns false when nobody claimed it — a standalone surface, or a box that
 * does not hug this content — and the component animates itself as usual.
 */
export function announceSurfaceResize(
  target: EventTarget,
  announcement: SurfaceResizeAnnouncement,
): boolean {
  const { fromCssPx, toCssPx } = announcement;
  if (!Number.isFinite(fromCssPx) || !Number.isFinite(toCssPx)) return false;
  const deltaCssPx = toCssPx - fromCssPx;
  if (Math.abs(deltaCssPx) < MIN_ANNOUNCED_DELTA_CSS_PX) return false;

  const lowerCssPx = Math.min(fromCssPx, toCssPx);
  const upperCssPx = Math.max(fromCssPx, toCssPx);
  let driver: LitSurfaceResizeDriver | null = null;
  let finished = false;
  let safety: number | null = null;

  const setProgress = (progress: number): void => {
    if (finished) return;
    const ratio = Number.isFinite(progress) ? Math.min(Math.max(progress, 0), 1) : 0;
    const px = fromCssPx + ratio * deltaCssPx;
    announcement.setHeightCssPx(Math.min(Math.max(px, lowerCssPx), upperCssPx));
  };
  const finish = (): void => {
    if (finished) return;
    finished = true;
    if (safety !== null) window.clearTimeout(safety);
    announcement.finish();
  };
  const claim = (): LitSurfaceResizeDriver | null => {
    if (driver || finished) return null;
    announcement.onClaimed?.();
    setProgress(0);
    safety = window.setTimeout(() => {
      setProgress(1);
      finish();
    }, ANNOUNCE_SAFETY_MS);
    driver = { setProgress, finish };
    return driver;
  };

  dispatchLitSurfaceResizeBegin(target, {
    ...(announcement.reason ? { reason: announcement.reason } : {}),
    deltaCssPx,
    claim,
  });
  return driver !== null;
}

/**
 * Announce the height change a re-render is about to make.
 *
 * A component renders new content and then finds out what it cost: capture the
 * height before the DOM is written, commit after it is written and before the
 * frame is painted. Lit's `willUpdate` and `updated` are exactly those two
 * points and run in one task, so a change that grows the card never reaches
 * the screen — or the surface reporter — at its natural height.
 */
export type SurfaceHeightReflow = {
  /** Record the current height. Call from `willUpdate`. */
  capture(): void;
  /** Measure the new height and announce the change. Call from `updated`. */
  commit(): void;
  /** Release any clamp this reflow still holds. */
  dispose(): void;
};

export function createSurfaceHeightReflow(args: {
  readonly reason?: string;
  /** The element whose height changes, resolved fresh on every call. */
  element: () => HTMLElement | null;
  /** Hold the element at this height, in CSS px. */
  setHeightCssPx(px: number): void;
  /**
   * Resolves once this component AND the children it renders have settled.
   * Nested components update in their own microtasks, so a height measured in
   * `updated` can be short by whatever a child adds a moment later — and the
   * box would then be sent to the wrong size. Waiting is safe because the
   * element is already clamped by then.
   */
  settled?(): Promise<unknown>;
}): SurfaceHeightReflow {
  let capturedCssPx: number | null = null;
  let clampedElement: HTMLElement | null = null;

  const release = (): void => {
    const element = clampedElement;
    clampedElement = null;
    if (!element) return;
    element.classList.remove(CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS);
  };

  return {
    capture(): void {
      const element = args.element();
      capturedCssPx = element ? element.getBoundingClientRect().height : null;
    },
    commit(): void {
      const fromCssPx = capturedCssPx;
      capturedCssPx = null;
      const element = args.element();
      if (!element || fromCssPx === null) return;
      // A motion already owns this surface. Let it land: the reporter picks up
      // whatever this render changed when the pin comes off, so the parent
      // still eases once rather than chasing two overlapping motions.
      if (document.documentElement.classList.contains(CONFIRM_SURFACE_PINNED_ROOT_CLASS)) return;
      // An enclosing reflow is already holding this subtree. Its motion covers
      // whatever changed in here, and a clamp of our own would make the height
      // it is about to measure short by exactly this element's growth.
      if (element.parentElement?.closest(`.${CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS}`)) return;
      // Clamp in this task, before anything is painted or observed. Everything
      // after this point can take its time.
      clampedElement = element;
      element.classList.add(CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS);
      args.setHeightCssPx(fromCssPx);

      void Promise.resolve(args.settled?.())
        // Nested components render in their own microtasks, and a height read
        // before they have is short by whatever they add. One frame under the
        // clamp is long enough for all of them, and costs nothing visible: the
        // element is holding its pre-change height either way.
        .then(() => new Promise<void>((resolve) => requestAnimationFrame(() => resolve())))
        .then(() => {
          // A newer render, or a dispose, has taken this element over.
          if (clampedElement !== element) return;
          // A motion claimed the surface while this render was settling. It
          // owns the box, and this element sits inside what it is moving.
          if (document.documentElement.classList.contains(CONFIRM_SURFACE_PINNED_ROOT_CLASS)) {
            release();
            return;
          }
          // Read the natural height with the clamp momentarily off. No frame
          // is painted between these two writes, so nothing sees the gap.
          element.classList.remove(CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS);
          const toCssPx = element.getBoundingClientRect().height;
          element.classList.add(CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS);
          const claimed = announceClampedSurfaceResize({
            ...(args.reason ? { reason: args.reason } : {}),
            element,
            fromCssPx,
            toCssPx,
            setHeightCssPx: (px) => args.setHeightCssPx(px),
            onSettled: () => {
              clampedElement = null;
            },
          });
          if (!claimed) release();
        });
    },
    dispose: release,
  };
}

/**
 * Clamp an element at its pre-change height, announce the change, and release
 * the clamp when the motion lands. This is the call every height change in a
 * confirmation goes through, because the clamp has to be in place *before* the
 * announcement: a host measures itself while the event is dispatched.
 *
 * Returns true when a host took the motion. False means the clamp was never
 * applied (or has already been dropped) and the caller animates itself.
 */
export function announceClampedSurfaceResize(args: {
  readonly reason?: string;
  /** The element to hold; it carries `drivenClasses` for the motion. */
  readonly element: HTMLElement;
  readonly fromCssPx: number;
  readonly toCssPx: number;
  /**
   * Classes that make the element read the height written by
   * `setHeightCssPx`, without a transition of its own. Defaults to the shared
   * one; components with their own height rules pass theirs.
   */
  readonly drivenClasses?: readonly string[];
  setHeightCssPx(px: number): void;
  /** Extra commit work once the clamp is released. */
  onSettled?(): void;
}): boolean {
  const { element, fromCssPx, toCssPx } = args;
  if (!Number.isFinite(fromCssPx) || !Number.isFinite(toCssPx)) return false;
  if (Math.abs(toCssPx - fromCssPx) < MIN_ANNOUNCED_DELTA_CSS_PX) return false;
  const drivenClasses = args.drivenClasses ?? [CONFIRM_SURFACE_HEIGHT_DRIVEN_CLASS];

  element.classList.add(...drivenClasses);
  args.setHeightCssPx(fromCssPx);
  const claimed = announceSurfaceResize(element, {
    ...(args.reason ? { reason: args.reason } : {}),
    fromCssPx,
    toCssPx,
    setHeightCssPx: args.setHeightCssPx,
    finish: () => {
      element.classList.remove(...drivenClasses);
      args.onSettled?.();
    },
  });
  // Nobody owns the motion, so there is no box to wait for: drop the clamp in
  // the same task, before anything is painted.
  if (!claimed) element.classList.remove(...drivenClasses);
  return claimed;
}

export type ConfirmSurfaceResizeChoreographer = {
  dispose(): void;
};

export type ConfirmSurfaceResizeChoreographerOptions = {
  /** Height of the box the parent gave this document, in CSS px. Defaults to the viewport. */
  readonly viewportHeightCssPx?: () => number;
};

type ActiveResize = {
  readonly driver: LitSurfaceResizeDriver;
  /** Host height with the announcing element still at its pre-change height. */
  readonly originHostPx: number;
  /** Signed change the host was pinned to make. */
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
  const release = () => {
    element.classList.remove(CONFIRM_SURFACE_PINNED_CLASS);
    document.documentElement.classList.remove(CONFIRM_SURFACE_PINNED_ROOT_CLASS);
  };
  return {
    set(px) {
      try {
        if (!sheet) sheet = new CSSStyleSheet();
        // While pinned the document deliberately overflows its frame (the host
        // is taller than the box while growing, its content taller than the
        // host while shrinking). A classic scrollbar appearing for those frames
        // would narrow the content, re-wrap text, and post a spurious
        // measurement, so the document must not scroll until the pin comes off.
        sheet.replaceSync(
          `.${CONFIRM_SURFACE_PINNED_CLASS}{height:${Math.max(0, Math.round(px))}px}` +
            `.${CONFIRM_SURFACE_PINNED_ROOT_CLASS}{overflow:hidden}`,
        );
        if (!document.adoptedStyleSheets.includes(sheet)) {
          document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
        }
      } catch {
        return false;
      }
      element.classList.add(CONFIRM_SURFACE_PINNED_CLASS);
      document.documentElement.classList.add(CONFIRM_SURFACE_PINNED_ROOT_CLASS);
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
    // Land the content on its target before the pin comes off, so the host's
    // natural height equals the pinned one and the reporter sees no second
    // change from this motion.
    current.driver.setProgress(1);
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
    // The pinned target is what the parent applies, rounded on both sides, so
    // the box reaches it exactly; a box the parent clamps short settles below.
    const progress = clamp((viewportPx - current.originHostPx) / current.deltaCssPx, 0, 1);
    if (progress >= 1) {
      current.framesAtTarget += 1;
      if (current.sawIntermediate || current.framesAtTarget >= LANDING_CONFIRM_FRAMES) {
        settle();
        return;
      }
      // Hold the content where it is: this may be the destination blip.
      current.frame = requestAnimationFrame(step);
      return;
    }
    current.framesAtTarget = 0;
    if (progress > 0) current.sawIntermediate = true;
    current.driver.setProgress(progress);
    const settledFrames = current.moved
      ? SETTLED_FRAMES_AFTER_MOTION
      : SETTLED_FRAMES_WITHOUT_MOTION;
    if (current.framesSinceChange >= settledFrames) {
      settle();
      return;
    }
    current.frame = requestAnimationFrame(step);
  };

  const onSurfaceResizeBegin = (event: CustomEvent<LitSurfaceResizeBeginDetail>): void => {
    const detail = event.detail;
    if (!pin || !detail || !isWalletIframeConfirmSurface(element)) return;
    const deltaCssPx = detail.deltaCssPx;
    if (!Number.isFinite(deltaCssPx) || Math.abs(deltaCssPx) < MIN_ANNOUNCED_DELTA_CSS_PX) return;
    // A second change mid-motion: land the first one, then measure afresh.
    settle();
    const viewportPx = readViewportHeightCssPx();
    const hostPx = element.getBoundingClientRect().height;
    // Only a box that hugs the host will follow a new measurement 1:1. A
    // clamped or full-viewport box leaves the component to animate itself,
    // which cannot be clipped there.
    if (
      !(viewportPx > 0) ||
      !(hostPx > 0) ||
      Math.abs(viewportPx - hostPx) > HUG_TOLERANCE_CSS_PX
    ) {
      return;
    }
    // The announcing element is clamped at its pre-change height, so the host
    // measured now IS the origin, and the target is one signed delta away.
    const originHostPx = Math.round(hostPx);
    const targetHostPx = originHostPx + deltaCssPx;
    if (!(targetHostPx > 0)) return;
    if (!pin.set(targetHostPx)) return;
    const driver = detail.claim();
    if (!driver) {
      pin.release();
      return;
    }
    active = {
      driver,
      originHostPx,
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

  const removeListener = addLitSurfaceResizeBeginListener(element, onSurfaceResizeBegin);
  return {
    dispose() {
      removeListener();
      settle();
      pin?.dispose();
    },
  };
}
