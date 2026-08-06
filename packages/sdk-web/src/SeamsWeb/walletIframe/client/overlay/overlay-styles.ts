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
  dialog.${CLASS_DIALOG}.${CLASS_MODAL}::backdrop {
    background: rgb(0 0 0 / 0.4);
  }
  dialog.${CLASS_DIALOG}.${CLASS_PROVISIONAL} {
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
    box-sizing: border-box;
  }
  iframe.${CLASS_IFRAME}.${CLASS_HIDDEN} {
    width: 0;
    height: 0;
    opacity: 0;
    pointer-events: none;
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
  el.classList.remove(CLASS_MODAL, CLASS_DRAWER, CLASS_FALLBACK, CLASS_PROVISIONAL);
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
    `#${id}.${CLASS_DIALOG}{top:max(${cssPx(rect.topCssPx)},calc(${safeTop} + ${inset}));left:max(${cssPx(rect.leftCssPx)},calc(${safeLeft} + ${inset}));width:${width};height:${height};}#${id}.${CLASS_DIALOG}.${CLASS_DRAWER}{top:max(calc(${cssPx(rect.topCssPx)} - ${safeBottom}),calc(${safeTop} + ${inset}));}`,
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
};

export const WALLET_IFRAME_DIALOG_ID_PREFIX = DIALOG_ID_PREFIX;
