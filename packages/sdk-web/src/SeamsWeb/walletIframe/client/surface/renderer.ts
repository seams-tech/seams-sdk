import {
  assertNever,
  type RequestSurfaceIdentity,
  type WalletIframeAuthMenuPresentation,
  type WalletIframeDrawerPresentation,
  type WalletIframeModalPresentation,
  type WalletIframeSurface,
  type WalletIframeSurfacePresentation,
} from './domain';
import {
  provisionalWalletIframeSurfaceGeometry,
  type WalletIframeDrawerGeometry,
  type WalletIframeModalGeometry,
  type WalletIframeSurfaceGeometry,
  type WalletIframeSurfaceViewport,
} from './geometry';
import type { HostedAuthMenuSessionId } from '../../shared/messages';

export type WalletIframeSurfaceRenderMode =
  | { kind: 'hidden' }
  | {
      kind: 'compact_request_modal';
      presentation: WalletIframeModalPresentation;
      geometry: WalletIframeModalGeometry;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId?: never;
    }
  | {
      kind: 'compact_request_drawer';
      presentation: WalletIframeDrawerPresentation;
      geometry: WalletIframeDrawerGeometry;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId?: never;
    }
  | {
      kind: 'compact_auth_menu';
      presentation: WalletIframeAuthMenuPresentation;
      geometry: WalletIframeModalGeometry;
      focusTrap: true;
      identity: RequestSurfaceIdentity;
      authMenuSessionId: HostedAuthMenuSessionId;
    };

export type WalletIframeSurfaceRenderController = {
  apply(mode: WalletIframeSurfaceRenderMode): void;
};

const DEFAULT_PROVISIONAL_VIEWPORT: WalletIframeSurfaceViewport = {
  widthCssPx: 1024,
  heightCssPx: 768,
  offsetLeftCssPx: 0,
  offsetTopCssPx: 0,
};

function isModalGeometry(
  geometry: WalletIframeSurfaceGeometry,
): geometry is WalletIframeModalGeometry {
  return (
    geometry.kind === 'provisional_centered_modal' ||
    geometry.kind === 'centered_modal' ||
    geometry.kind === 'viewport_fallback'
  );
}

function isDrawerGeometry(
  geometry: WalletIframeSurfaceGeometry,
): geometry is WalletIframeDrawerGeometry {
  return (
    geometry.kind === 'provisional_bottom_drawer' ||
    geometry.kind === 'bottom_drawer' ||
    geometry.kind === 'viewport_fallback'
  );
}

function geometryForSurface(
  presentation: WalletIframeSurfacePresentation,
  geometry: WalletIframeSurfaceGeometry | undefined,
): WalletIframeSurfaceGeometry {
  return (
    geometry ?? provisionalWalletIframeSurfaceGeometry(presentation, DEFAULT_PROVISIONAL_VIEWPORT)
  );
}

function requestModalRenderMode(args: {
  presentation: WalletIframeModalPresentation;
  geometry: WalletIframeSurfaceGeometry;
  identity: RequestSurfaceIdentity;
}): WalletIframeSurfaceRenderMode {
  if (!isModalGeometry(args.geometry)) {
    throw new Error('Modal request surface received drawer geometry');
  }
  return {
    kind: 'compact_request_modal',
    presentation: args.presentation,
    geometry: args.geometry,
    focusTrap: true,
    identity: args.identity,
  };
}

function requestDrawerRenderMode(args: {
  presentation: WalletIframeDrawerPresentation;
  geometry: WalletIframeSurfaceGeometry;
  identity: RequestSurfaceIdentity;
}): WalletIframeSurfaceRenderMode {
  if (!isDrawerGeometry(args.geometry)) {
    throw new Error('Drawer request surface received modal geometry');
  }
  return {
    kind: 'compact_request_drawer',
    presentation: args.presentation,
    geometry: args.geometry,
    focusTrap: true,
    identity: args.identity,
  };
}

function authMenuRenderMode(args: {
  presentation: WalletIframeAuthMenuPresentation;
  geometry: WalletIframeSurfaceGeometry;
  identity: RequestSurfaceIdentity;
  authMenuSessionId: HostedAuthMenuSessionId;
}): WalletIframeSurfaceRenderMode {
  if (!isModalGeometry(args.geometry)) {
    throw new Error('Auth-menu surface received drawer geometry');
  }
  return {
    kind: 'compact_auth_menu',
    presentation: args.presentation,
    geometry: args.geometry,
    focusTrap: true,
    identity: args.identity,
    authMenuSessionId: args.authMenuSessionId,
  };
}

export function renderWalletIframeSurface(
  surface: WalletIframeSurface,
  geometry?: WalletIframeSurfaceGeometry,
): WalletIframeSurfaceRenderMode {
  if (surface.kind === 'hidden') return { kind: 'hidden' };

  const resolvedGeometry = geometryForSurface(surface.presentation, geometry);
  switch (surface.kind) {
    case 'modal_registration_confirm':
    case 'modal_transaction_confirm':
    case 'modal_key_export_confirm':
    case 'modal_unlock_confirm':
    case 'modal_recovery_codes':
    case 'modal_device_link_qr':
      switch (surface.presentation.kind) {
        case 'modal':
          return requestModalRenderMode({
            presentation: surface.presentation,
            geometry: resolvedGeometry,
            identity: surface.identity,
          });
        case 'drawer':
          return requestDrawerRenderMode({
            presentation: surface.presentation,
            geometry: resolvedGeometry,
            identity: surface.identity,
          });
        default:
          return assertNever(surface.presentation);
      }
    case 'modal_auth_menu':
      return authMenuRenderMode({
        presentation: surface.presentation,
        geometry: resolvedGeometry,
        identity: surface.identity,
        authMenuSessionId: surface.authMenuSessionId,
      });
    default:
      return assertNever(surface);
  }
}

export class WalletIframeSurfaceRenderer {
  constructor(private readonly controller: WalletIframeSurfaceRenderController) {}

  render(surface: WalletIframeSurface, geometry?: WalletIframeSurfaceGeometry): void {
    this.controller.apply(renderWalletIframeSurface(surface, geometry));
  }
}
