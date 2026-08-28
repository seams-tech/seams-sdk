import type { HostedAuthMenuSessionId } from '../../shared/messages';
import type { RequestSurfaceIdentity } from '../surface/domain';
import {
  walletIframeSurfaceGeometryEqual,
  type WalletIframeSurfaceGeometry,
} from '../surface/geometry';
import type { WalletIframeSurfaceRenderMode } from '../surface/renderer';
import {
  clearDialogGeometry,
  ensureOverlayDialog,
  OverlayStyleClasses,
  setDialogGeometry,
  setDialogAuthMenu,
  setDialogPresentation,
  setHidden,
  setVisible,
} from './overlay-styles';

export type OverlayRenderMode = WalletIframeSurfaceRenderMode;

export type OverlayDismissReason = 'backdrop' | 'escape';

export type OverlayDismissEvent = {
  identity: RequestSurfaceIdentity;
  authMenuSessionId?: HostedAuthMenuSessionId;
  reason: OverlayDismissReason;
  generation: number;
};

export type OverlayControllerState = {
  visible: boolean;
  mode: 'hidden' | 'compact_modal' | 'bottom_drawer' | 'viewport_fallback';
  dialogOpen: boolean;
  generation: number;
};

type PointerCapture = {
  pointerId: number;
  generation: number;
};

type OverlayControllerOptions = {
  ensureIframe: (mountParent?: HTMLElement) => HTMLIFrameElement;
  onDismiss?: (event: OverlayDismissEvent) => void | Promise<void>;
};

type SurfaceMorphRect = {
  top: number;
  left: number;
  width: number;
  height: number;
};

const SURFACE_MORPH_DURATION_MS = 220;
const SURFACE_REDUCED_MOTION_DURATION_MS = 120;

function finiteSurfaceMorphRect(rect: DOMRect): SurfaceMorphRect | null {
  if (
    !Number.isFinite(rect.top) ||
    !Number.isFinite(rect.left) ||
    !Number.isFinite(rect.width) ||
    !Number.isFinite(rect.height) ||
    rect.width <= 0 ||
    rect.height <= 0
  ) {
    return null;
  }
  return { top: rect.top, left: rect.left, width: rect.width, height: rect.height };
}

function surfaceMorphKeyframes(
  origin: SurfaceMorphRect,
  destination: SurfaceMorphRect,
  reducedMotion: boolean,
): Keyframe[] {
  if (reducedMotion) return [{ opacity: 0 }, { opacity: 1 }];
  const translateX = origin.left - destination.left;
  const translateY = origin.top - destination.top;
  const scaleX = origin.width / destination.width;
  const scaleY = origin.height / destination.height;
  return [
    {
      transform: `translate(${translateX}px, ${translateY}px) scale(${scaleX}, ${scaleY})`,
    },
    { transform: 'none' },
  ];
}

function surfaceResizeKeyframes(
  origin: SurfaceMorphRect,
  destination: SurfaceMorphRect,
): Keyframe[] {
  return [
    {
      top: `${origin.top}px`,
      left: `${origin.left}px`,
      width: `${origin.width}px`,
      height: `${origin.height}px`,
    },
    {
      top: `${destination.top}px`,
      left: `${destination.left}px`,
      width: `${destination.width}px`,
      height: `${destination.height}px`,
    },
  ];
}

function assertNever(value: never): never {
  throw new Error(`Unhandled wallet iframe overlay mode: ${String(value)}`);
}

function presentationKind(
  mode: Exclude<OverlayRenderMode, { kind: 'hidden' }>,
): 'modal' | 'drawer' {
  switch (mode.kind) {
    case 'compact_request_modal':
    case 'compact_auth_menu':
      return 'modal';
    case 'compact_request_drawer':
      return 'drawer';
    default:
      return assertNever(mode);
  }
}

function geometryKind(
  geometry: WalletIframeSurfaceGeometry,
): 'provisional' | 'measured' | 'fallback' {
  switch (geometry.kind) {
    case 'hidden':
      throw new Error('Visible wallet iframe overlay cannot use hidden geometry');
    case 'provisional_centered_modal':
    case 'provisional_bottom_drawer':
      return 'provisional';
    case 'centered_modal':
    case 'bottom_drawer':
      return 'measured';
    case 'viewport_fallback':
      return 'fallback';
    default:
      return assertNever(geometry);
  }
}

function diagnosticsMode(mode: OverlayRenderMode): OverlayControllerState['mode'] {
  switch (mode.kind) {
    case 'hidden':
      return 'hidden';
    case 'compact_request_modal':
    case 'compact_auth_menu':
      return mode.geometry.kind === 'viewport_fallback' ? 'viewport_fallback' : 'compact_modal';
    case 'compact_request_drawer':
      return mode.geometry.kind === 'viewport_fallback' ? 'viewport_fallback' : 'bottom_drawer';
    default:
      return assertNever(mode);
  }
}

function sameIdentity(left: OverlayRenderMode, right: OverlayRenderMode): boolean {
  if (left.kind === 'hidden' || right.kind === 'hidden') return left.kind === right.kind;
  if (
    left.identity.surfaceId !== right.identity.surfaceId ||
    left.identity.requestId !== right.identity.requestId
  ) {
    return false;
  }
  if (left.kind === 'compact_auth_menu' || right.kind === 'compact_auth_menu') {
    return (
      left.kind === 'compact_auth_menu' &&
      right.kind === 'compact_auth_menu' &&
      left.authMenuSessionId === right.authMenuSessionId
    );
  }
  return true;
}

function isOutsideRect(event: PointerEvent, rect: DOMRect): boolean {
  return (
    event.clientX <= rect.left ||
    event.clientX >= rect.right ||
    event.clientY <= rect.top ||
    event.clientY >= rect.bottom
  );
}

function ignoreDismissFailure(error: unknown): void {
  void error;
}

export class OverlayController {
  private readonly ensureIframe: (mountParent?: HTMLElement) => HTMLIFrameElement;
  private dismissHandler: ((event: OverlayDismissEvent) => void | Promise<void>) | undefined;
  private dialog: HTMLDialogElement | null = null;
  private iframe: HTMLIFrameElement | null = null;
  private mode: OverlayRenderMode = { kind: 'hidden' };
  private visible = false;
  private generation = 0;
  private pointerCapture: PointerCapture | null = null;
  private restoreFocus: HTMLElement | null = null;
  // Dialog close events can arrive after the next surface is visible. Count
  // programmatic closes so a stale event cannot dismiss that newer request.
  private pendingProgrammaticCloseEvents = 0;
  private listenersInstalled = false;
  private lastAppliedGeometry: WalletIframeSurfaceGeometry | null = null;
  private authMenuVisualScale = 1;
  private lastAppliedAuthMenuVisualScale = 1;
  private dialogDisplayMode: 'modal' | 'nonmodal' | null = null;
  private transitionOrigin: SurfaceMorphRect | null = null;
  private pendingRevealFrame: number | null = null;
  private surfaceMorphAnimation: Animation | null = null;

  constructor(opts: OverlayControllerOptions) {
    this.ensureIframe = opts.ensureIframe;
    this.dismissHandler = opts.onDismiss;
  }

  setDismissHandler(handler: (event: OverlayDismissEvent) => void | Promise<void>): void {
    this.dismissHandler = handler;
  }

  prepare(): HTMLIFrameElement {
    return this.ensureDialog().iframe;
  }

  setAuthMenuVisualScale(scale: number): void {
    this.authMenuVisualScale = Number.isFinite(scale) && scale > 0 ? scale : 1;
  }

  apply(mode: OverlayRenderMode): void {
    switch (mode.kind) {
      case 'hidden':
        this.hideOverlay();
        return;
      case 'compact_request_modal':
      case 'compact_request_drawer':
      case 'compact_auth_menu':
        this.applyVisible(mode);
        return;
      default:
        return assertNever(mode);
    }
  }

  private ensureDialog(): { dialog: HTMLDialogElement; iframe: HTMLIFrameElement } {
    if (!this.dialog) {
      const dialog = document.createElement('dialog');
      ensureOverlayDialog(dialog);
      dialog.addEventListener('cancel', this.handleCancel);
      dialog.addEventListener('close', this.handleClose);
      dialog.addEventListener('pointerdown', this.handlePointerDown);
      dialog.addEventListener('pointerup', this.handlePointerUp);
      window.addEventListener('pointerup', this.handlePointerUp);
      window.addEventListener('pointercancel', this.handlePointerCancel);
      this.listenersInstalled = true;
      this.dialog = dialog;
    }
    const dialog = this.dialog;
    ensureOverlayDialog(dialog);
    if (!dialog.isConnected) {
      document.body.appendChild(dialog);
    }
    const iframe = this.ensureIframe(dialog);
    this.iframe = iframe;
    if (iframe.parentElement !== dialog) {
      if (iframe.isConnected) {
        throw new Error('Wallet iframe cannot be reparented after it has been mounted');
      }
      dialog.appendChild(iframe);
    }
    return { dialog, iframe };
  }

  private applyVisible(mode: Exclude<OverlayRenderMode, { kind: 'hidden' }>): void {
    const { dialog, iframe } = this.ensureDialog();
    const identityChanged = !sameIdentity(this.mode, mode);
    const authMenu = mode.kind === 'compact_auth_menu';
    const previousGeometryKind = this.lastAppliedGeometry
      ? geometryKind(this.lastAppliedGeometry)
      : null;
    const nextGeometryKind = geometryKind(mode.geometry);
    const revealMeasuredRequestModal =
      mode.kind === 'compact_request_modal' &&
      previousGeometryKind === 'provisional' &&
      nextGeometryKind !== 'provisional';
    const geometryChanged =
      !this.lastAppliedGeometry ||
      !walletIframeSurfaceGeometryEqual(this.lastAppliedGeometry, mode.geometry);
    const authMenuScaleChanged =
      authMenu && Math.abs(this.lastAppliedAuthMenuVisualScale - this.authMenuVisualScale) > 0.001;
    const animateAuthMenuResize =
      authMenu &&
      !identityChanged &&
      geometryChanged &&
      this.lastAppliedGeometry !== null &&
      geometryKind(this.lastAppliedGeometry) !== 'provisional' &&
      geometryKind(mode.geometry) !== 'provisional';
    const requestTransitionOrigin =
      mode.kind === 'compact_request_modal' && this.mode.kind === 'compact_auth_menu'
        ? finiteSurfaceMorphRect(dialog.getBoundingClientRect())
        : null;
    const requestResizeOrigin =
      mode.kind === 'compact_request_modal' &&
      !identityChanged &&
      geometryChanged &&
      previousGeometryKind === 'measured' &&
      nextGeometryKind === 'measured'
        ? finiteSurfaceMorphRect(dialog.getBoundingClientRect())
        : null;
    if (identityChanged) {
      this.cancelPendingReveal();
      this.cancelSurfaceMorph();
      this.generation += 1;
      this.pointerCapture = null;
      this.transitionOrigin = requestTransitionOrigin;
      this.captureFocusForDialog();
    }
    this.mode = mode;
    this.visible = true;

    if (revealMeasuredRequestModal) {
      dialog.classList.add(OverlayStyleClasses.REVEAL_PENDING);
    }
    dialog.classList.toggle(
      OverlayStyleClasses.HAS_TRANSITION_ORIGIN,
      this.transitionOrigin !== null,
    );
    setVisible(iframe);
    setDialogPresentation(dialog, presentationKind(mode), geometryKind(mode.geometry));
    setDialogAuthMenu(dialog, authMenu, animateAuthMenuResize);
    dialog.setAttribute('aria-modal', authMenu ? 'false' : 'true');
    if (geometryChanged || authMenuScaleChanged) {
      if (geometryChanged) this.cancelSurfaceMorph();
      setDialogGeometry(dialog, mode.geometry, authMenu ? this.authMenuVisualScale : 1);
      this.lastAppliedGeometry = mode.geometry;
      this.lastAppliedAuthMenuVisualScale = authMenu ? this.authMenuVisualScale : 1;
      const requestResizeDestination = requestResizeOrigin
        ? finiteSurfaceMorphRect(dialog.getBoundingClientRect())
        : null;
      if (requestResizeOrigin && requestResizeDestination) {
        this.startSurfaceResize(requestResizeOrigin, requestResizeDestination);
      }
    }
    iframe.setAttribute('aria-hidden', 'false');
    iframe.removeAttribute('tabindex');
    iframe.setAttribute('title', mode.presentation.title);
    dialog.setAttribute('aria-label', mode.presentation.title);
    dialog.classList.remove(OverlayStyleClasses.HIDDEN);

    const requestedDisplayMode = authMenu ? 'nonmodal' : 'modal';
    const requestModalAwaitingMeasurement =
      mode.kind === 'compact_request_modal' && nextGeometryKind === 'provisional';
    if (dialog.open && this.dialogDisplayMode !== requestedDisplayMode) {
      this.closeDialogProgrammatically(dialog);
      this.dialogDisplayMode = null;
    }
    if (!dialog.open && !requestModalAwaitingMeasurement) {
      this.showDialog(dialog, requestedDisplayMode);
    }
    if (revealMeasuredRequestModal) {
      this.scheduleMeasuredReveal();
    }
  }

  private scheduleMeasuredReveal(): void {
    this.cancelPendingReveal();
    this.pendingRevealFrame = window.requestAnimationFrame(this.revealMeasuredSurface);
  }

  private readonly revealMeasuredSurface = (): void => {
    this.pendingRevealFrame = null;
    const dialog = this.dialog;
    if (
      !dialog ||
      !this.visible ||
      this.mode.kind !== 'compact_request_modal' ||
      geometryKind(this.mode.geometry) === 'provisional'
    ) {
      return;
    }
    const destination = finiteSurfaceMorphRect(dialog.getBoundingClientRect());
    const origin = this.transitionOrigin;
    if (origin && destination) {
      this.startSurfaceMorph(origin, destination);
    }
    dialog.classList.remove(OverlayStyleClasses.REVEAL_PENDING);
  };

  private startSurfaceMorph(origin: SurfaceMorphRect, destination: SurfaceMorphRect): void {
    const dialog = this.dialog;
    if (!dialog) return;
    this.cancelSurfaceMorph();
    const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const animation = dialog.animate(surfaceMorphKeyframes(origin, destination, reducedMotion), {
      duration: reducedMotion ? SURFACE_REDUCED_MOTION_DURATION_MS : SURFACE_MORPH_DURATION_MS,
      easing: 'cubic-bezier(0.2, 0.7, 0.2, 1)',
    });
    this.surfaceMorphAnimation = animation;
    animation.addEventListener('finish', this.handleSurfaceMorphFinished, { once: true });
  }

  private startSurfaceResize(origin: SurfaceMorphRect, destination: SurfaceMorphRect): void {
    const dialog = this.dialog;
    if (!dialog || window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    this.cancelSurfaceMorph();
    const animation = dialog.animate(surfaceResizeKeyframes(origin, destination), {
      duration: SURFACE_MORPH_DURATION_MS,
      easing: 'cubic-bezier(0.2, 0.7, 0.2, 1)',
    });
    this.surfaceMorphAnimation = animation;
    animation.addEventListener('finish', this.handleSurfaceMorphFinished, { once: true });
  }

  private readonly handleSurfaceMorphFinished = (event: Event): void => {
    if (event.currentTarget !== this.surfaceMorphAnimation) return;
    this.surfaceMorphAnimation?.cancel();
    this.surfaceMorphAnimation = null;
  };

  private cancelPendingReveal(): void {
    if (this.pendingRevealFrame === null) return;
    window.cancelAnimationFrame(this.pendingRevealFrame);
    this.pendingRevealFrame = null;
  }

  private cancelSurfaceMorph(): void {
    this.surfaceMorphAnimation?.cancel();
    this.surfaceMorphAnimation = null;
  }

  private showDialog(dialog: HTMLDialogElement, displayMode: 'modal' | 'nonmodal'): void {
    if (displayMode === 'nonmodal') {
      if (typeof dialog.show !== 'function') {
        throw new Error('Wallet iframe overlay requires native HTMLDialogElement.show support');
      }
      dialog.show();
      this.dialogDisplayMode = 'nonmodal';
      return;
    }
    if (typeof dialog.showModal !== 'function') {
      throw new Error('Wallet iframe overlay requires native HTMLDialogElement.showModal support');
    }
    dialog.showModal();
    this.dialogDisplayMode = 'modal';
  }

  private closeDialogProgrammatically(dialog: HTMLDialogElement): void {
    this.pendingProgrammaticCloseEvents += 1;
    dialog.close();
  }

  private hideOverlay(): void {
    const wasVisible = this.visible;
    this.cancelPendingReveal();
    this.cancelSurfaceMorph();
    this.generation += 1;
    this.pointerCapture = null;
    this.mode = { kind: 'hidden' };
    this.visible = false;
    this.lastAppliedGeometry = null;
    this.authMenuVisualScale = 1;
    this.lastAppliedAuthMenuVisualScale = 1;
    this.transitionOrigin = null;
    if (!this.dialog) {
      return;
    }
    const iframe = this.iframe;
    if (iframe) {
      setHidden(iframe);
      iframe.setAttribute('aria-hidden', 'true');
      iframe.setAttribute('tabindex', '-1');
      iframe.removeAttribute('title');
    }
    this.dialog.removeAttribute('aria-label');
    this.dialog.classList.add(OverlayStyleClasses.HIDDEN);
    this.dialog.classList.remove(
      OverlayStyleClasses.REVEAL_PENDING,
      OverlayStyleClasses.HAS_TRANSITION_ORIGIN,
    );
    clearDialogGeometry(this.dialog);
    if (this.dialog.open) {
      this.closeDialogProgrammatically(this.dialog);
    }
    this.dialogDisplayMode = null;
    if (wasVisible) {
      this.restoreCapturedFocus();
    }
  }

  private captureFocusForDialog(): void {
    const active = document.activeElement;
    if (active instanceof HTMLElement && this.dialog && !this.dialog.contains(active)) {
      this.restoreFocus = active;
    }
  }

  private restoreCapturedFocus(): void {
    const focusTarget = this.restoreFocus;
    this.restoreFocus = null;
    if (!focusTarget || !focusTarget.isConnected || focusTarget.matches('[inert]')) return;
    focusTarget.focus({ preventScroll: true });
  }

  private activeDismissEvent(reason: OverlayDismissReason): OverlayDismissEvent | null {
    if (this.mode.kind === 'hidden') return null;
    const event: OverlayDismissEvent = {
      identity: this.mode.identity,
      reason,
      generation: this.generation,
    };
    if (this.mode.kind === 'compact_auth_menu') {
      event.authMenuSessionId = this.mode.authMenuSessionId;
    }
    return event;
  }

  private requestDismiss(reason: OverlayDismissReason): void {
    const event = this.activeDismissEvent(reason);
    if (!event || !this.dismissHandler) return;
    void Promise.resolve(this.dismissHandler(event)).catch(ignoreDismissFailure);
  }

  private handleCancel = (event: Event): void => {
    event.preventDefault();
    this.requestDismiss('escape');
  };

  private handleClose = (): void => {
    this.dialogDisplayMode = null;
    if (this.pendingProgrammaticCloseEvents > 0) {
      this.pendingProgrammaticCloseEvents -= 1;
      return;
    }
    if (this.visible) this.requestDismiss('escape');
  };

  private handlePointerDown = (event: PointerEvent): void => {
    if (!this.visible || this.mode.kind === 'hidden' || !this.dialog) return;
    const dialogRect = this.dialog.getBoundingClientRect();
    const iframe = this.ensureIframe();
    const iframeRect = iframe.getBoundingClientRect();
    if (!isOutsideRect(event, dialogRect) || !isOutsideRect(event, iframeRect)) {
      this.pointerCapture = null;
      return;
    }
    this.pointerCapture = { pointerId: event.pointerId, generation: this.generation };
  };

  private handlePointerUp = (event: PointerEvent): void => {
    const capture = this.pointerCapture;
    this.pointerCapture = null;
    if (
      !capture ||
      capture.pointerId !== event.pointerId ||
      capture.generation !== this.generation
    ) {
      return;
    }
    if (!this.dialog || this.mode.kind === 'hidden') return;
    const dialogRect = this.dialog.getBoundingClientRect();
    const iframeRect = this.ensureIframe().getBoundingClientRect();
    if (isOutsideRect(event, dialogRect) && isOutsideRect(event, iframeRect)) {
      this.requestDismiss('backdrop');
    }
  };

  private handlePointerCancel = (event: PointerEvent): void => {
    if (this.pointerCapture?.pointerId === event.pointerId) {
      this.pointerCapture = null;
    }
  };

  getState(): OverlayControllerState {
    return {
      visible: this.visible,
      mode: diagnosticsMode(this.mode),
      dialogOpen: this.dialog?.open ?? false,
      generation: this.generation,
    };
  }

  dispose(): void {
    this.cancelPendingReveal();
    this.cancelSurfaceMorph();
    this.generation += 1;
    this.pointerCapture = null;
    this.mode = { kind: 'hidden' };
    this.visible = false;
    this.lastAppliedGeometry = null;
    this.transitionOrigin = null;
    this.dialogDisplayMode = null;
    this.restoreFocus = null;
    const dialog = this.dialog;
    if (!dialog) {
      this.dismissHandler = undefined;
      return;
    }
    if (this.listenersInstalled) {
      dialog.removeEventListener('cancel', this.handleCancel);
      dialog.removeEventListener('close', this.handleClose);
      dialog.removeEventListener('pointerdown', this.handlePointerDown);
      dialog.removeEventListener('pointerup', this.handlePointerUp);
      window.removeEventListener('pointerup', this.handlePointerUp);
      window.removeEventListener('pointercancel', this.handlePointerCancel);
    }
    if (dialog.open) {
      dialog.close();
    }
    clearDialogGeometry(dialog);
    dialog.remove();
    this.dialog = null;
    this.iframe = null;
    this.listenersInstalled = false;
    this.dismissHandler = undefined;
  }
}

export default OverlayController;
