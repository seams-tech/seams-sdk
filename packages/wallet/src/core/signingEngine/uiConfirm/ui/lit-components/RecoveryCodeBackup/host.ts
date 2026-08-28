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
import RecoveryCodeBackupViewer, { type RecoveryCodeBackupExperience } from './viewer';
import {
  RECOVERY_BACKUP_CANCEL_EVENT,
  RECOVERY_BACKUP_STAGE_EVENT,
  type RecoveryBackupStageDetail,
  type RecoveryBackupSurface,
} from './events';

if (
  typeof customElements !== 'undefined' &&
  !customElements.get(W3A_RECOVERY_CODE_BACKUP_VIEWER_ID)
) {
  customElements.define(W3A_RECOVERY_CODE_BACKUP_VIEWER_ID, RecoveryCodeBackupViewer);
}

export class RecoveryCodeBackupHost extends LitElementWithProps {
  static properties = {
    experience: { attribute: false },
    surface: { type: String },
  } as const;

  declare experience: RecoveryCodeBackupExperience;
  declare surface: RecoveryBackupSurface;

  private dialogEl: HTMLDialogElement | null = null;
  private viewerEl: RecoveryCodeBackupViewer | null = null;
  private shown = false;
  private readonly dialogShown: Promise<HTMLDialogElement>;
  private resolveDialogShown!: (dialog: HTMLDialogElement) => void;

  private readonly handleCancel = (event: Event): void => {
    event.preventDefault();
    this.dispatchEvent(
      new CustomEvent(RECOVERY_BACKUP_CANCEL_EVENT, { bubbles: true, composed: true }),
    );
  };

  private readonly handleStageChange = (event: Event): void => {
    const dialog = event.currentTarget;
    if (!(dialog instanceof HTMLDialogElement)) return;
    const detail = (event as CustomEvent<RecoveryBackupStageDetail>).detail;
    dialog.dataset.w3aRecoveryStage = detail.stage;
  };

  constructor() {
    super();
    this.experience = { kind: 'unconfigured' };
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
      dialog.setAttribute('aria-labelledby', 'w3a-wallet-recovery-title');
      dialog.setAttribute('aria-describedby', 'w3a-wallet-recovery-description');
      // The app-palette override rules in the wallet-iframe host target this
      // class; keep it so appearance colors keep applying.
      dialog.className = 'w3a-host-themed-dialog';
      dialog.tabIndex = -1;
      // Escape is surfaced to the mount; preventDefault keeps the dialog under
      // the recovery experience's single lifecycle owner.
      dialog.addEventListener('cancel', this.handleCancel);
      dialog.addEventListener(RECOVERY_BACKUP_STAGE_EVENT, this.handleStageChange);
      this.appendChild(dialog);
      this.dialogEl = dialog;
      this.viewerEl = null;
    }
    let viewer = this.viewerEl;
    if (!viewer || !viewer.isConnected) {
      viewer = document.createElement(
        W3A_RECOVERY_CODE_BACKUP_VIEWER_ID,
      ) as RecoveryCodeBackupViewer;
      viewer.configure(this.experience);
      dialog.appendChild(viewer);
      this.viewerEl = viewer;
    }
    return { dialog, viewer };
  }

  private async showDialogWhenReady(viewer: RecoveryCodeBackupViewer): Promise<void> {
    await viewer.updateComplete;
    await viewer.whenStylesReady();
    // Style readiness queues the viewer's gated content render. Cross one
    // frame boundary so layout and updateComplete both reflect that update.
    await new Promise<number>(requestAnimationFrame);
    await viewer.updateComplete;
    const currentDialog = this.dialogEl;
    if (this.viewerEl !== viewer || !currentDialog?.isConnected || currentDialog.open) return;
    currentDialog.showModal();
    viewer.focusInitialTarget();
    this.resolveDialogShown(currentDialog);
  }

  protected updated(changed: PropertyValues): void {
    super.updated(changed);
    const { dialog, viewer } = this.ensureDialogAndViewer();
    dialog.setAttribute(
      'data-w3a-recovery-surface',
      this.surface === 'wallet-iframe' ? 'wallet-iframe' : 'standalone',
    );
    viewer.configure(this.experience);
    const stage = viewer.currentStage();
    if (stage) dialog.dataset.w3aRecoveryStage = stage;
    if (!this.shown) {
      this.shown = true;
      void this.showDialogWhenReady(viewer);
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
