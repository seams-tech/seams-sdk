import type {
  WalletRecoveryCodeBackupAcknowledgementV1,
  WalletRecoveryCodeBackupRequestV1,
} from '@/core/types/sdkSentEvents';
import type { UiConfirmSurfaceMeasurementBinding } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  createWalletIframeSurfaceMeasurementReporter,
  type WalletIframeSurfaceMeasurementReporter,
} from '../../walletIframe/host/lit-ui/surface-measurement-reporter';
/* Relative, not `@/`-aliased: unit tests load this module as raw source over
   Vite's /@fs route, where the SDK's path alias is not configured. Type-only
   `@/` imports above are erased before that matters; these are values. */
import { W3A_RECOVERY_CODE_BACKUP_HOST_ID } from '../../../core/signingEngine/uiConfirm/ui/registry';
import {
  RECOVERY_BACKUP_CANCEL_EVENT,
  RECOVERY_BACKUP_CLOSE_EVENT,
  type RecoveryBackupCloseDetail,
} from '../../../core/signingEngine/uiConfirm/ui/lit-components/RecoveryCodeBackup/events';
import type RecoveryCodeBackupHost from '../../../core/signingEngine/uiConfirm/ui/lit-components/RecoveryCodeBackup/host';

const CANCELLED_MESSAGE = 'Wallet registration was cancelled before recovery-code backup';

/**
 * The lit host/viewer pair loads on demand: this module sits in the static
 * import graph of registration and SeamsWeb, and the dialog is the only
 * reason to pull lit into it.
 */
async function createRecoveryCodeBackupHost(): Promise<RecoveryCodeBackupHost> {
  const { default: HostElement } =
    await import('../../../core/signingEngine/uiConfirm/ui/lit-components/RecoveryCodeBackup/host');
  if (!customElements.get(W3A_RECOVERY_CODE_BACKUP_HOST_ID)) {
    customElements.define(W3A_RECOVERY_CODE_BACKUP_HOST_ID, HostElement);
  }
  return document.createElement(W3A_RECOVERY_CODE_BACKUP_HOST_ID) as RecoveryCodeBackupHost;
}

/**
 * Shows the recovery-code backup dialog and resolves with the user's
 * acknowledgement. The dialog is the lit RecoveryCodeBackup host/viewer pair;
 * this wrapper owns the promise contract: an acknowledged close resolves as
 * backed-up, an unacknowledged close defers during registration and cancels
 * from the account menu, and Escape always cancels.
 */
export async function showWalletRecoveryCodeBackupUi(
  request: WalletRecoveryCodeBackupRequestV1,
  measurementBinding: UiConfirmSurfaceMeasurementBinding = { kind: 'disabled' },
): Promise<WalletRecoveryCodeBackupAcknowledgementV1> {
  if (typeof document === 'undefined') {
    throw new Error('Wallet recovery-code backup requires a browser or a backup handler');
  }

  const previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;
  const host = await createRecoveryCodeBackupHost();
  host.walletId = request.walletId;
  host.recoveryCodes = request.recoveryCodes;
  host.continuation = request.continuation;
  host.surface = measurementBinding.kind === 'wallet_iframe' ? 'wallet-iframe' : 'standalone';

  let measurementReporter: WalletIframeSurfaceMeasurementReporter | null = null;
  let settled = false;

  return await new Promise<WalletRecoveryCodeBackupAcknowledgementV1>((resolve, reject) => {
    const cleanup = (): void => {
      measurementReporter?.disconnect();
      measurementReporter = null;
      host.remove(); // disconnectedCallback closes and removes the dialog
      previousFocus?.focus();
    };

    const settle = (result: WalletRecoveryCodeBackupAcknowledgementV1 | Error): void => {
      if (settled) return;
      settled = true;
      cleanup();
      if (result instanceof Error) reject(result);
      else resolve(result);
    };

    host.addEventListener(RECOVERY_BACKUP_CLOSE_EVENT, (event) => {
      const detail = (event as CustomEvent<RecoveryBackupCloseDetail>).detail;
      if (detail?.acknowledged) {
        settle({ kind: 'wallet_recovery_codes_backed_up_v1' });
        return;
      }
      if (request.continuation === 'registration_may_defer') {
        settle({ kind: 'wallet_recovery_code_backup_deferred_v1' });
        return;
      }
      settle(new Error(CANCELLED_MESSAGE));
    });

    host.addEventListener(RECOVERY_BACKUP_CANCEL_EVENT, () => {
      settle(new Error(CANCELLED_MESSAGE));
    });

    document.body.appendChild(host);

    void host.whenDialogShown().then((dialog) => {
      if (settled || measurementBinding.kind !== 'wallet_iframe') return;
      measurementReporter = createWalletIframeSurfaceMeasurementReporter({
        kind: 'request_scroll_surface',
        requestId: measurementBinding.requestId,
        element: dialog,
        postMeasurement: measurementBinding.postMeasurement,
      });
    });
  });
}
