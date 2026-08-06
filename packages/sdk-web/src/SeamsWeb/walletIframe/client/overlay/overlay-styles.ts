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
const CLASS_IFRAME = 'w3a-wallet-overlay-iframe';
const CLASS_HIDDEN = 'is-hidden';
const CLASS_MODAL = 'is-modal';
const CLASS_DRAWER = 'is-drawer';
const CLASS_FALLBACK = 'is-viewport-fallback';
const CLASS_PROVISIONAL = 'is-provisional';
const CLASS_AUTH_MENU = 'is-auth-menu';
const CLASS_RESIZE_ANIMATED = 'is-resize-animated';
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
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}:not(.${CLASS_PROVISIONAL}):not(.${CLASS_FALLBACK}):not(.${CLASS_AUTH_MENU})::backdrop {
    background: rgb(0 0 0 / 0.26);
    animation: w3a-wallet-overlay-backdrop-in 180ms cubic-bezier(0.2, 0.7, 0.2, 1) both;
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
  dialog.${CLASS_DIALOG}.${CLASS_PROVISIONAL}::backdrop {
    background: transparent;
  }
  dialog.${CLASS_DIALOG}.${CLASS_FALLBACK}::backdrop {
    background: transparent;
  }
  dialog.${CLASS_DIALOG}.${CLASS_AUTH_MENU}::backdrop {
    background: transparent;
  }
  dialog.${CLASS_DIALOG}.${CLASS_AUTH_MENU}.${CLASS_RESIZE_ANIMATED} {
    transition:
      top 230ms cubic-bezier(0.34, 1.18, 0.64, 1),
      height 230ms cubic-bezier(0.34, 1.18, 0.64, 1);
  }
  /* A provisional drawer already owns the full visual viewport. Keep it
     visible so the iframe's inner sheet can play its slide-in transition;
     provisional compact modals stay hidden until their measured bounds are
     ready. */
  dialog.${CLASS_DIALOG}.${CLASS_PROVISIONAL}.${CLASS_MODAL} {
    visibility: hidden;
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
    dialog.${CLASS_DIALOG}.${CLASS_AUTH_MENU} {
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
  dialog.classList.toggle(CLASS_RESIZE_ANIMATED, authMenu && animateResize);
}

export type OverlayRect = {
  topCssPx: number;
  leftCssPx: number;
  widthCssPx: number;
  heightCssPx: number;
};

export function setDialogGeometry(dialog: HTMLDialogElement, rect: OverlayRect): void {
  ensureOverlayDialog(dialog);
  const id = ensureDialogId(dialog);
  const inset = cssPx(WALLET_IFRAME_SURFACE_INSET_CSS_PX);
  const safeTop = 'var(--w3a-wallet-overlay-safe-top, 0px)';
  const safeRight = 'var(--w3a-wallet-overlay-safe-right, 0px)';
  const safeBottom = 'var(--w3a-wallet-overlay-safe-bottom, 0px)';
  const safeLeft = 'var(--w3a-wallet-overlay-safe-left, 0px)';
  const width = `min(${cssPx(rect.widthCssPx)},max(1px,calc(100vw - ${safeLeft} - ${safeRight} - ${inset} - ${inset})))`;
  const height = `min(${cssPx(rect.heightCssPx)},max(1px,calc(100dvh - ${safeTop} - ${safeBottom} - ${inset} - ${inset})))`;
  getStyleManager().setDynamicRule(
    id,
    `#${id}.${CLASS_DIALOG}{top:max(${cssPx(rect.topCssPx)},calc(${safeTop} + ${inset}));left:max(${cssPx(rect.leftCssPx)},calc(${safeLeft} + ${inset}));width:${width};height:${height};}#${id}.${CLASS_DIALOG}.${CLASS_DRAWER}{top:${signedCssPx(rect.topCssPx)};left:${signedCssPx(rect.leftCssPx)};width:${cssPx(rect.widthCssPx)};height:${cssPx(rect.heightCssPx)};}#${id}.${CLASS_DIALOG}.${CLASS_AUTH_MENU}{top:${signedCssPx(rect.topCssPx)};height:${cssPx(rect.heightCssPx)};}`,
  );
}

export function clearDialogGeometry(dialog: HTMLDialogElement): void {
  ensureOverlayDialog(dialog);
  getStyleManager().deleteDynamicRule(ensureDialogId(dialog));
}

export const OverlayStyleClasses = {
  BASE: CLASS_BASE,
  DIALOG: CLASS_DIALOG,
  IFRAME: CLASS_IFRAME,
  HIDDEN: CLASS_HIDDEN,
  MODAL: CLASS_MODAL,
  DRAWER: CLASS_DRAWER,
  FALLBACK: CLASS_FALLBACK,
  PROVISIONAL: CLASS_PROVISIONAL,
  AUTH_MENU: CLASS_AUTH_MENU,
  RESIZE_ANIMATED: CLASS_RESIZE_ANIMATED,
};

export const WALLET_IFRAME_DIALOG_ID_PREFIX = DIALOG_ID_PREFIX;
