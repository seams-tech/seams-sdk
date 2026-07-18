import type OverlayController from '../overlay/overlay-controller';
import { assertNever, type WalletIframeSurface } from './domain';

export type WalletIframeSurfaceRenderMode =
  | { kind: 'hidden' }
  | { kind: 'viewport_modal'; title: string; focusTrap: true };

export function renderWalletIframeSurface(
  surface: WalletIframeSurface,
): WalletIframeSurfaceRenderMode {
  switch (surface.kind) {
    case 'hidden':
      return { kind: 'hidden' };
    case 'modal_registration_confirm':
      return { kind: 'viewport_modal', title: 'Confirm passkey registration', focusTrap: true };
    case 'modal_transaction_confirm':
      return { kind: 'viewport_modal', title: 'Confirm transaction', focusTrap: true };
    case 'modal_key_export_confirm':
      return { kind: 'viewport_modal', title: 'Confirm key export', focusTrap: true };
    case 'modal_unlock_confirm':
      return { kind: 'viewport_modal', title: 'Unlock wallet', focusTrap: true };
    case 'modal_recovery_codes':
      return {
        kind: 'viewport_modal',
        title: surface.operation === 'show' ? 'Recovery codes' : 'Rotate recovery codes',
        focusTrap: true,
      };
    case 'modal_device_link_qr':
      return { kind: 'viewport_modal', title: 'Link a device', focusTrap: true };
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
      case 'viewport_modal':
        this.controller.applyViewportModal({ title: mode.title });
        return;
      default:
        return assertNever(mode);
    }
  }
}
