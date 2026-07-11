import type { DOMRectLike } from '../overlay/overlay-controller';
import type OverlayController from '../overlay/overlay-controller';
import {
  assertNever,
  type AnchoredRegistrationActivationSurface,
  type WalletIframeSurface,
} from './domain';

export type WalletIframeSurfaceRenderMode =
  | { kind: 'hidden' }
  | { kind: 'anchored_interactive'; rect: DOMRectLike; title: string }
  | { kind: 'anchored_suspended'; title: string }
  | { kind: 'viewport_modal'; title: string; focusTrap: true };

function renderAnchoredRegistrationActivationSurface(
  surface: AnchoredRegistrationActivationSurface,
): WalletIframeSurfaceRenderMode {
  switch (surface.placement.kind) {
    case 'interactive':
      return {
        kind: 'anchored_interactive',
        rect: surface.placement.targetRect,
        title: surface.presentation.accessibleLabel,
      };
    case 'suspended':
      return {
        kind: 'anchored_suspended',
        title: surface.presentation.accessibleLabel,
      };
    default:
      return assertNever(surface.placement);
  }
}

export function renderWalletIframeSurface(
  surface: WalletIframeSurface,
): WalletIframeSurfaceRenderMode {
  switch (surface.kind) {
    case 'hidden':
      return { kind: 'hidden' };
    case 'anchored_registration_activation':
      return renderAnchoredRegistrationActivationSurface(surface);
    case 'modal_registration_confirm':
      return { kind: 'viewport_modal', title: 'Confirm passkey registration', focusTrap: true };
    case 'modal_transaction_confirm':
      return { kind: 'viewport_modal', title: 'Confirm transaction', focusTrap: true };
    case 'modal_key_export_confirm':
      return { kind: 'viewport_modal', title: 'Confirm key export', focusTrap: true };
    case 'modal_unlock_confirm':
      return { kind: 'viewport_modal', title: 'Unlock wallet', focusTrap: true };
    default:
      return assertNever(surface);
  }
}

export class WalletIframeSurfaceRenderer {
  private readonly controller: OverlayController;

  constructor(controller: OverlayController) {
    this.controller = controller;
  }

  render(surface: WalletIframeSurface): void {
    const mode = renderWalletIframeSurface(surface);
    switch (mode.kind) {
      case 'hidden':
        this.controller.applyHidden();
        return;
      case 'anchored_interactive':
        this.controller.applyAnchored(mode.rect, { title: mode.title });
        return;
      case 'anchored_suspended':
        this.controller.applyAnchoredSuspended({ title: mode.title });
        return;
      case 'viewport_modal':
        this.controller.applyViewportModal({ title: mode.title });
        return;
      default:
        return assertNever(mode);
    }
  }
}
