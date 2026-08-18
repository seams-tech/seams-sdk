// Direct-mount host for the wallet recovery-code backup dialog.
//
// Owns the native `<dialog>` shell — top-layer stacking, focus containment,
// and Escape-as-cancel come from the platform — and mounts the lit viewer
// inside it. All styling lives in recovery-code-backup.css (document-level,
// strict-CSP friendly); this module carries no inline styles.
import { html, type PropertyValues } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import {
  W3A_RECOVERY_CODE_BACKUP_HOST_ID,
  W3A_RECOVERY_CODE_BACKUP_VIEWER_ID,
} from '../../registry';
// BINDING import, not a side-effect import: the per-file ESM build honors
// sideEffects and would drop a bare `import './viewer'`.
import RecoveryCodeBackupViewer, { type RecoveryCodeBackupContinuation } from './viewer';
import { RECOVERY_BACKUP_CANCEL_EVENT, type RecoveryBackupSurface } from './events';

if (
  typeof customElements !== 'undefined' &&
  !customElements.get(W3A_RECOVERY_CODE_BACKUP_VIEWER_ID)
) {
  customElements.define(W3A_RECOVERY_CODE_BACKUP_VIEWER_ID, RecoveryCodeBackupViewer);
}

export class RecoveryCodeBackupHost extends LitElementWithProps {
  static properties = {
    walletId: { type: String, attribute: 'wallet-id' },
    recoveryCodes: { attribute: false },
    continuation: { type: String },
    surface: { type: String },
  } as const;

  declare walletId: string;
  declare recoveryCodes: readonly string[];
  declare continuation: RecoveryCodeBackupContinuation;
  declare surface: RecoveryBackupSurface;

  private dialogEl: HTMLDialogElement | null = null;
  private viewerEl: RecoveryCodeBackupViewer | null = null;
  private shown = false;
  private readonly dialogShown: Promise<HTMLDialogElement>;
  private resolveDialogShown!: (dialog: HTMLDialogElement) => void;

  constructor() {
    super();
    this.walletId = '';
    this.recoveryCodes = [];
    this.continuation = 'pending_backup_must_finish';
    this.surface = 'standalone';
    this.dialogShown = new Promise((resolve) => {
      this.resolveDialogShown = resolve;
    });
  }

  protected getComponentPrefix(): string {
    return 'recovery-backup-host';
  }

  /** Resolves with the dialog element once it is styled and shown modally. */
  whenDialogShown(): Promise<HTMLDialogElement> {
    return this.dialogShown;
  }

  disconnectedCallback(): void {
    super.disconnectedCallback();
    if (this.dialogEl?.open) this.dialogEl.close();
    this.dialogEl?.remove();
    this.dialogEl = null;
    this.viewerEl = null;
  }

  private ensureDialogAndViewer(): { dialog: HTMLDialogElement; viewer: RecoveryCodeBackupViewer } {
    let dialog = this.dialogEl;
    if (!dialog || !dialog.isConnected) {
      dialog = document.createElement('dialog');
      dialog.setAttribute('data-w3a-wallet-recovery-backup-dialog', '');
      dialog.setAttribute('aria-labelledby', 'w3a-wallet-recovery-backup-title');
      dialog.setAttribute('aria-describedby', 'w3a-wallet-recovery-backup-description');
      // The app-palette override rules in the wallet-iframe host target this
      // class; keep it so appearance colors keep applying.
      dialog.className = 'w3a-host-themed-dialog';
      dialog.tabIndex = -1;
      dialog.addEventListener('cancel', (event) => {
        // Escape: surface the cancellation as an event; the mount decides what
        // rejecting means. preventDefault keeps the dialog under our control.
        event.preventDefault();
        this.dispatchEvent(
          new CustomEvent(RECOVERY_BACKUP_CANCEL_EVENT, { bubbles: true, composed: true }),
        );
      });
      this.appendChild(dialog);
      this.dialogEl = dialog;
      this.viewerEl = null;
    }
    let viewer = this.viewerEl;
    if (!viewer || !viewer.isConnected) {
      viewer = document.createElement(
        W3A_RECOVERY_CODE_BACKUP_VIEWER_ID,
      ) as RecoveryCodeBackupViewer;
      dialog.appendChild(viewer);
      this.viewerEl = viewer;
    }
    return { dialog, viewer };
  }

  protected updated(changed: PropertyValues): void {
    super.updated(changed);
    const { dialog, viewer } = this.ensureDialogAndViewer();
    dialog.setAttribute(
      'data-w3a-recovery-surface',
      this.surface === 'wallet-iframe' ? 'wallet-iframe' : 'standalone',
    );
    viewer.walletId = this.walletId;
    viewer.recoveryCodes = this.recoveryCodes;
    viewer.continuation = this.continuation;
    if (!this.shown) {
      this.shown = true;
      // Hold showModal until the stylesheets applied: the dialog is a measured
      // surface in the wallet iframe, and an unstyled first layout would post
      // a wrong height before the real one.
      void viewer.whenStylesReady().then(() => {
        const currentDialog = this.dialogEl;
        if (!currentDialog?.isConnected || currentDialog.open) return;
        currentDialog.showModal();
        // The dialog itself takes programmatic focus on open, so the reading
        // order starts at the title rather than the first button.
        currentDialog.focus();
        this.resolveDialogShown(currentDialog);
      });
    }
  }

  render(): unknown {
    // The dialog and viewer are light-DOM children (managed in updated()):
    // they are styled by document-level CSS, which cannot pierce this shadow
    // root, and the dialog's aria-labelledby must resolve in the document.
    return html`<slot></slot>`;
  }
}

if (
  typeof customElements !== 'undefined' &&
  !customElements.get(W3A_RECOVERY_CODE_BACKUP_HOST_ID)
) {
  customElements.define(W3A_RECOVERY_CODE_BACKUP_HOST_ID, RecoveryCodeBackupHost);
}

export default RecoveryCodeBackupHost;
