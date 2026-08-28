/**
 * CSP-safe styles for the host-owned wallet iframe dialog.
 *
 * Geometry is applied through the CSP stylesheet manager rather than style
 * attributes. The iframe keeps its historical marker class because the
 * transport uses it to remove stale instances from the same origin.
 */

import {
  createCspStylesheetManager,
  getDefaultCspNonce,
} from '@/core/browser/walletIframe/csp-stylesheet';
import { WALLET_IFRAME_SURFACE_INSET_CSS_PX } from '../surface/geometry';

const CLASS_BASE = 'w3a-wallet-overlay';
const CLASS_DIALOG = 'w3a-wallet-overlay-dialog';
const CLASS_INLINE_DIALOG = 'w3a-wallet-inline-dialog';
const CLASS_IFRAME = 'w3a-wallet-overlay-iframe';
const CLASS_HIDDEN = 'is-hidden';
const CLASS_MODAL = 'is-modal';
const CLASS_DRAWER = 'is-drawer';
const CLASS_FALLBACK = 'is-viewport-fallback';
const CLASS_PROVISIONAL = 'is-provisional';
const CLASS_AUTH_MENU = 'is-auth-menu';
const CLASS_HAS_GEOMETRY = 'has-geometry';
const CLASS_RESIZE_ANIMATED = 'is-resize-animated';
const CLASS_REVEAL_PENDING = 'is-reveal-pending';
const CLASS_HAS_TRANSITION_ORIGIN = 'has-transition-origin';
const DIALOG_ID_PREFIX = 'w3a-wallet-overlay-dialog-';

const BASE_CSS = `
  dialog.${CLASS_DIALOG} {
    position: fixed;
    display: block;
    inset: auto;
    top: auto;
    left: auto;
    right: auto;
    bottom: auto;
    margin: 0;
    padding: 0;
    border: 0;
    overflow: visible;
    max-width: none;
    max-height: none;
    background: transparent;
    color-scheme: normal;
    box-sizing: border-box;
    --w3a-wallet-overlay-safe-top: env(safe-area-inset-top, 0px);
    --w3a-wallet-overlay-safe-right: env(safe-area-inset-right, 0px);
    --w3a-wallet-overlay-safe-bottom: env(safe-area-inset-bottom, 0px);
    --w3a-wallet-overlay-safe-left: env(safe-area-inset-left, 0px);
    z-index: var(--w3a-wallet-overlay-z, 2147483646);
  }
  /* A dialog with no geometry rule would otherwise fall back to its static
     position — the top-left of <body> — which is never right for an overlay.
     Any surface that reaches the DOM before (or without) a measured rect gets
     centred with the standard elevation instead of stranded in the corner.
     Scoped to :not(.has-geometry) so a positioned surface is untouched. */
  dialog.${CLASS_DIALOG}:not(.${CLASS_HAS_GEOMETRY}) {
    top: 50%;
    left: 50%;
    translate: -50% -50%;
    filter:
      drop-shadow(0 12px 24px rgb(0 0 0 / 0.22))
      drop-shadow(0 2px 8px rgb(0 0 0 / 0.12));
  }
  dialog.${CLASS_DIALOG}:not([open]),
  dialog.${CLASS_DIALOG}.${CLASS_HIDDEN} {
    visibility: hidden;
    pointer-events: none;
  }
  dialog.${CLASS_DIALOG}.${CLASS_DRAWER}::backdrop {
    background: transparent;
  }
  @keyframes w3a-wallet-overlay-backdrop-in {
    from {
      background: transparent;
    }
    to {
      background: rgb(0 0 0 / 0.26);
    }
  }
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}::backdrop {
    background: transparent;
  }
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}:not(.${CLASS_PROVISIONAL}):not(.${CLASS_FALLBACK}):not(.${CLASS_AUTH_MENU}):not(.${CLASS_REVEAL_PENDING}):not(.${CLASS_HAS_TRANSITION_ORIGIN})::backdrop {
    background: rgb(0 0 0 / 0.26);
    animation: w3a-wallet-overlay-backdrop-in 180ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
  }
  /* A modal launched from an existing wallet card reuses that card's backdrop
     while the host surface morphs from its bounds. A second backdrop would
     darken the page midway through the transition and read as a flash. */
  dialog.${CLASS_DIALOG}.${CLASS_HAS_TRANSITION_ORIGIN}::backdrop {
    background: transparent;
    animation: none;
  }
  /* The host owns the modal frame. Keep the focused dialog and iframe from
     adding a user-agent outline around the rounded card. */
  dialog.${CLASS_DIALOG}.${CLASS_MODAL},
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}:focus,
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}:focus-visible,
  dialog.${CLASS_DIALOG}.${CLASS_MODAL} iframe.${CLASS_IFRAME},
  dialog.${CLASS_DIALOG}.${CLASS_MODAL} iframe.${CLASS_IFRAME}:focus,
  dialog.${CLASS_DIALOG}.${CLASS_MODAL} iframe.${CLASS_IFRAME}:focus-visible {
    outline: none;
  }
  /* The iframe clips the child's box shadow at its layout edge. Paint the
     compact modal elevation in the host compositor so it can extend beyond
     that edge without changing the measured hit region. */
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}:not(.${CLASS_PROVISIONAL}):not(.${CLASS_FALLBACK}):not(.${CLASS_AUTH_MENU})
    iframe.${CLASS_IFRAME} {
    filter:
      drop-shadow(0 12px 24px rgb(0 0 0 / 0.22))
      drop-shadow(0 2px 8px rgb(0 0 0 / 0.12));
  }
  /* The auth-menu card paints no shadow of its own (auth-menu.css) for the
     same clipping reason; give it the quieter card elevation here, where the
     drop-shadow hugs the card's silhouette and may extend past the iframe. */
  dialog.${CLASS_DIALOG}.${CLASS_AUTH_MENU} iframe.${CLASS_IFRAME} {
    filter:
      drop-shadow(0 1px 2px rgb(15 23 42 / 0.05))
      drop-shadow(0 10px 20px rgb(15 23 42 / 0.1));
  }
  dialog.${CLASS_DIALOG}.${CLASS_PROVISIONAL}::backdrop {
    background: transparent;
  }
  dialog.${CLASS_DIALOG}.${CLASS_FALLBACK}::backdrop {
    background: transparent;
  }
  /* The hosted auth menu is host-page furniture rather than an overlay: it is
     opened non-modally, so it never enters the top layer, and it renders in the
     host document's own stacking context. Page chrome (navbars, sticky headers,
     popovers) therefore paints above it at ordinary z-index values instead of
     losing to the overlay escape hatch.

     It is position: absolute in DOCUMENT coordinates (its dynamic rule adds the
     page scroll offset), not fixed: compositor scrolling then moves it with the
     page content natively, instead of pinning it for a frame and snapping once
     the scroll listener re-measures the anchor. It cannot be static because the
     wallet iframe is mounted into this dialog once, before connect(), and
     cannot be reparented afterwards without discarding its browsing context and
     MessagePort — so the dialog stays a body child and mirrors the host
     anchor's rect; --w3a-wallet-inline-dialog-z is the host's hook for placing
     it within the page's own layering. */
  dialog.${CLASS_DIALOG}.${CLASS_INLINE_DIALOG} {
    position: absolute;
    z-index: var(--w3a-wallet-inline-dialog-z, auto);
    transform-origin: top left;
  }
  dialog.${CLASS_DIALOG}.${CLASS_INLINE_DIALOG}::backdrop {
    background: transparent;
  }
  /* The dialog must NOT animate its own resize. The auth-menu card inside the
     iframe animates its height, and a ResizeObserver posts every intermediate
     frame out to this dialog. Transitioning here would make the host box ease
     toward a target that is itself still easing — the box visibly trails the
     card and the change reads as two steps (resize, then catch up). Applying
     each reported frame instantly makes the dialog track the card 1:1, so the
     card's own spring is the single motion, and the anchor height published
     from the same frames keeps the host centring in step. */
  dialog.${CLASS_DIALOG}.${CLASS_INLINE_DIALOG}.${CLASS_RESIZE_ANIMATED} {
    transition: none;
  }
  /* A provisional drawer already owns the full visual viewport. The hosted
     auth menu also renders provisionally: hiding its dialog prevents the
     child ResizeObserver from producing the measurement that replaces those
     provisional bounds, leaving the menu invisible until the 4s fallback.
     Request modals remain hidden until their measured bounds are ready. */
  dialog.${CLASS_DIALOG}.${CLASS_PROVISIONAL}.${CLASS_MODAL}:not(.${CLASS_AUTH_MENU}) {
    visibility: hidden;
  }
  /* Measured geometry is installed one frame before a request modal is
     revealed. This prevents the native dialog's fallback position from ever
     reaching the screen while its dynamic geometry rule settles. */
  dialog.${CLASS_DIALOG}.${CLASS_REVEAL_PENDING} {
    visibility: hidden;
    pointer-events: none;
  }
  dialog.${CLASS_DIALOG}.${CLASS_HAS_TRANSITION_ORIGIN} {
    transform-origin: top left;
  }
  iframe.${CLASS_IFRAME} {
    display: block;
    width: 100%;
    height: 100%;
    border: 0;
    margin: 0;
    padding: 0;
    background: transparent;
    background-color: transparent;
    box-sizing: border-box;
  }
  iframe.${CLASS_IFRAME}.${CLASS_HIDDEN} {
    width: 0;
    height: 0;
    opacity: 0;
    pointer-events: none;
  }
  @media (prefers-reduced-motion: reduce) {
    dialog.${CLASS_DIALOG}.${CLASS_INLINE_DIALOG} {
      transition: none;
    }
    dialog.${CLASS_DIALOG}.${CLASS_MODAL}::backdrop {
      animation: none;
    }
  }
`;

let styleManager: ReturnType<typeof createCspStylesheetManager> | null = null;
let nextDialogId = 0;

const getStyleManager = () => {
  if (!styleManager) {
    styleManager = createCspStylesheetManager({
      doc: document,
      baseCss: BASE_CSS,
      dynamicStyleDataAttr: 'data-w3a-overlay-dyn',
      nonce: () => getDefaultCspNonce(),
    });
  }
  return styleManager;
};

function isFiniteCssNumber(value: number): boolean {
  return Number.isFinite(value) && value >= 0;
}

function cssPx(value: number): string {
  if (!isFiniteCssNumber(value)) {
    return '0px';
  }
  return `${Math.min(Math.round(value), 100_000)}px`;
}

function signedCssPx(value: number): string {
  if (!Number.isFinite(value)) return '0px';
  return `${Math.min(Math.max(Math.round(value), -100_000), 100_000)}px`;
}

function cssScale(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '1';
  return String(Math.min(Math.max(value, 0.25), 4));
}

const drawerGeometryRuleId = (dialogId: string): string => `${dialogId}::drawer`;
const authMenuGeometryRuleId = (dialogId: string): string => `${dialogId}::auth-menu`;

function ensureDialogId(dialog: HTMLDialogElement): string {
  const currentId = dialog.id;
  if (currentId.startsWith(DIALOG_ID_PREFIX)) {
    return currentId;
  }
  nextDialogId += 1;
  const id = `${DIALOG_ID_PREFIX}${nextDialogId}`;
  dialog.id = id;
  return id;
}

export function ensureOverlayBase(el: HTMLElement): void {
  getStyleManager().ensureBase();
  try {
    el.classList.add(CLASS_BASE);
    if (el instanceof HTMLIFrameElement) {
      el.classList.add(CLASS_IFRAME);
    }
  } catch {
    // Detached or test doubles may not expose classList; styling is best effort.
  }
}

export function ensureOverlayDialog(dialog: HTMLDialogElement): void {
  getStyleManager().ensureBase();
  ensureDialogId(dialog);
  dialog.classList.add(CLASS_DIALOG);
}

export function setHidden(el: HTMLElement): void {
  ensureOverlayBase(el);
  el.classList.add(CLASS_HIDDEN);
  el.classList.remove(
    CLASS_MODAL,
    CLASS_DRAWER,
    CLASS_FALLBACK,
    CLASS_PROVISIONAL,
    CLASS_RESIZE_ANIMATED,
    CLASS_REVEAL_PENDING,
    CLASS_HAS_TRANSITION_ORIGIN,
  );
}

export function setVisible(el: HTMLElement): void {
  ensureOverlayBase(el);
  el.classList.remove(CLASS_HIDDEN);
}

export type OverlayPresentation = 'modal' | 'drawer';

export function setDialogPresentation(
  dialog: HTMLDialogElement,
  presentation: OverlayPresentation,
  geometryKind: 'provisional' | 'measured' | 'fallback',
): void {
  ensureOverlayDialog(dialog);
  dialog.classList.toggle(CLASS_MODAL, presentation === 'modal');
  dialog.classList.toggle(CLASS_DRAWER, presentation === 'drawer');
  dialog.classList.toggle(CLASS_FALLBACK, geometryKind === 'fallback');
  dialog.classList.toggle(CLASS_PROVISIONAL, geometryKind === 'provisional');
  dialog.classList.remove(CLASS_HIDDEN);
}

export function setDialogAuthMenu(
  dialog: HTMLDialogElement,
  authMenu: boolean,
  animateResize: boolean,
): void {
  ensureOverlayDialog(dialog);
  dialog.classList.toggle(CLASS_AUTH_MENU, authMenu);
  // The auth menu opts out of the overlay chrome entirely: no backdrop, no top
  // layer, and no z-index escape above host page chrome.
  dialog.classList.toggle(CLASS_INLINE_DIALOG, authMenu);
  dialog.classList.toggle(CLASS_RESIZE_ANIMATED, authMenu && animateResize);
}

export type OverlayRect = {
  topCssPx: number;
  leftCssPx: number;
  widthCssPx: number;
  heightCssPx: number;
};

export function setDialogGeometry(
  dialog: HTMLDialogElement,
  rect: OverlayRect,
  authMenuVisualScale = 1,
): void {
  ensureOverlayDialog(dialog);
  const id = ensureDialogId(dialog);
  const inset = cssPx(WALLET_IFRAME_SURFACE_INSET_CSS_PX);
  const safeTop = 'var(--w3a-wallet-overlay-safe-top, 0px)';
  const safeRight = 'var(--w3a-wallet-overlay-safe-right, 0px)';
  const safeBottom = 'var(--w3a-wallet-overlay-safe-bottom, 0px)';
  const safeLeft = 'var(--w3a-wallet-overlay-safe-left, 0px)';
  const width = `min(${cssPx(rect.widthCssPx)},max(1px,calc(100vw - ${safeLeft} - ${safeRight} - ${inset} - ${inset})))`;
  const height = `min(${cssPx(rect.heightCssPx)},max(1px,calc(100dvh - ${safeTop} - ${safeBottom} - ${inset} - ${inset})))`;
  // An auth-menu rect arrives from the router already in DOCUMENT coordinates
  // (the dialog is position:absolute), so it must escape the base rule's
  // viewport-inset clamps on both position AND size. Size matters under
  // browser zoom: the viewport's CSS px shrink while the anchored rect keeps
  // its CSS size, so the base rule's 100vw/100dvh clamps would shrink the menu
  // instead of letting it scale with the page. Scrolling re-derives an
  // identical rect, and the stylesheet manager skips the rewrite.
  dialog.classList.add(CLASS_HAS_GEOMETRY);
  // Three separately addressable rules rather than one packed string: an
  // auth-menu resize repoints these on every frame the surface reports, and a
  // retained rule mutated through CSSOM costs a declaration write instead of a
  // reserialise-and-reparse of the whole dynamic sheet.
  const manager = getStyleManager();
  manager.setDynamicDeclarations(id, `#${id}.${CLASS_DIALOG}`, {
    top: `max(${cssPx(rect.topCssPx)},calc(${safeTop} + ${inset}))`,
    left: `max(${cssPx(rect.leftCssPx)},calc(${safeLeft} + ${inset}))`,
    width,
    height,
  });
  manager.setDynamicDeclarations(
    drawerGeometryRuleId(id),
    `#${id}.${CLASS_DIALOG}.${CLASS_DRAWER}`,
    {
      top: signedCssPx(rect.topCssPx),
      left: signedCssPx(rect.leftCssPx),
      width: cssPx(rect.widthCssPx),
      height: cssPx(rect.heightCssPx),
    },
  );
  manager.setDynamicDeclarations(
    authMenuGeometryRuleId(id),
    `#${id}.${CLASS_DIALOG}.${CLASS_AUTH_MENU}`,
    {
      top: signedCssPx(rect.topCssPx),
      left: signedCssPx(rect.leftCssPx),
      width: cssPx(rect.widthCssPx),
      height: cssPx(rect.heightCssPx),
      transform: `scale(${cssScale(authMenuVisualScale)})`,
    },
  );
}

export function clearDialogGeometry(dialog: HTMLDialogElement): void {
  ensureOverlayDialog(dialog);
  dialog.classList.remove(CLASS_HAS_GEOMETRY);
  const id = ensureDialogId(dialog);
  const manager = getStyleManager();
  manager.deleteDynamicRule(id);
  manager.deleteDynamicRule(drawerGeometryRuleId(id));
  manager.deleteDynamicRule(authMenuGeometryRuleId(id));
}

export const OverlayStyleClasses = {
  BASE: CLASS_BASE,
  DIALOG: CLASS_DIALOG,
  INLINE_DIALOG: CLASS_INLINE_DIALOG,
  IFRAME: CLASS_IFRAME,
  HIDDEN: CLASS_HIDDEN,
  MODAL: CLASS_MODAL,
  DRAWER: CLASS_DRAWER,
  FALLBACK: CLASS_FALLBACK,
  PROVISIONAL: CLASS_PROVISIONAL,
  AUTH_MENU: CLASS_AUTH_MENU,
  HAS_GEOMETRY: CLASS_HAS_GEOMETRY,
  RESIZE_ANIMATED: CLASS_RESIZE_ANIMATED,
  REVEAL_PENDING: CLASS_REVEAL_PENDING,
  HAS_TRANSITION_ORIGIN: CLASS_HAS_TRANSITION_ORIGIN,
};

export const WALLET_IFRAME_DIALOG_ID_PREFIX = DIALOG_ID_PREFIX;
