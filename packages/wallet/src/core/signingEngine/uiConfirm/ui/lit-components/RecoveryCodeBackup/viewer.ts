import { html } from 'lit';
import { LitElementWithProps } from '../LitElementWithProps';
import { ensureExternalStyles } from '../css/css-loader';
import type { WalletRecoveryCodeBackupRequestV1 } from '@/core/types/sdkSentEvents';
import { RECOVERY_BACKUP_CLOSE_EVENT, type RecoveryBackupCloseDetail } from './events';

export type RecoveryCodeBackupContinuation = WalletRecoveryCodeBackupRequestV1['continuation'];

const COPIED_FLASH_MS = 1_800;

function safeWalletId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]/g, '_') || 'wallet';
}

function backupText(walletId: string, recoveryCodes: readonly string[]): string {
  const lines = [
    'Seams wallet recovery codes',
    '',
    `Wallet: ${walletId}`,
    '',
    'Save these codes somewhere private. Each code can be used once.',
    '',
  ];
  for (const [index, code] of recoveryCodes.entries()) {
    lines.push(`${String(index + 1).padStart(2, '0')}  ${code}`);
  }
  return `${lines.join('\n')}\n`;
}

/**
 * Content card for the wallet recovery-code backup dialog: codes grid,
 * download/copy actions, the acknowledgement checkbox, and the single close
 * control. Light-DOM on purpose — the surrounding native `<dialog>` references
 * the title/description ids via aria-labelledby, which cannot cross a shadow
 * boundary, and the document-level stylesheet then covers dialog and viewer
 * with one file.
 */
export class RecoveryCodeBackupViewer extends LitElementWithProps {
  static properties = {
    walletId: { type: String, attribute: 'wallet-id' },
    recoveryCodes: { attribute: false },
    continuation: { type: String },
    acknowledged: { state: true },
    statusMessage: { state: true },
    copied: { state: true },
  } as const;

  declare walletId: string;
  declare recoveryCodes: readonly string[];
  declare continuation: RecoveryCodeBackupContinuation;
  declare acknowledged: boolean;
  declare statusMessage: string;
  declare copied: boolean;

  private copiedResetTimer: number | null = null;
  private stylesReady = false;
  private stylePromise: Promise<void> | null = null;

  constructor() {
    super();
    this.walletId = '';
    this.recoveryCodes = [];
    this.continuation = 'pending_backup_must_finish';
    this.acknowledged = false;
    this.statusMessage = '';
    this.copied = false;
  }

  protected getComponentPrefix(): string {
    return 'recovery-backup';
  }

  protected createRenderRoot(): HTMLElement {
    // Light DOM: aria-labelledby ids must be reachable from the host dialog,
    // and document-level recovery-code-backup.css styles everything.
    const root = this as unknown as HTMLElement;
    this.stylePromise = Promise.all([
      ensureExternalStyles(root, 'recovery-code-backup.css', 'data-w3a-recovery-code-backup-css'),
      ensureExternalStyles(root, 'copy-icon.css', 'data-w3a-copy-icon-css'),
      // Token aliases for standalone documents; the wallet-iframe document
      // already links this sheet, deduped by the marker attribute.
      ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
    ]).then(() => {});
    this.stylePromise.catch(() => {});
    return root;
  }

  /** Resolves when the external stylesheets have been applied (or failed). */
  whenStylesReady(): Promise<void> {
    return this.stylePromise ?? Promise.resolve();
  }

  protected shouldUpdate(): boolean {
    // The dialog is a measured surface in the wallet iframe: an unstyled first
    // layout would post a wrong height before the real one.
    if (this.stylesReady) return true;
    void (this.stylePromise ?? Promise.resolve()).then(() => {
      this.stylesReady = true;
      this.requestUpdate();
    });
    return false;
  }

  disconnectedCallback(): void {
    if (this.copiedResetTimer !== null) {
      window.clearTimeout(this.copiedResetTimer);
      this.copiedResetTimer = null;
    }
    super.disconnectedCallback();
  }

  private download(): void {
    try {
      const url = URL.createObjectURL(
        new Blob([backupText(this.walletId, this.recoveryCodes)], {
          type: 'text/plain;charset=utf-8',
        }),
      );
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `seams-wallet-recovery-codes-${safeWalletId(this.walletId)}.txt`;
      try {
        anchor.click();
      } finally {
        window.setTimeout(URL.revokeObjectURL.bind(URL, url), 0);
      }
      this.statusMessage = 'Recovery codes downloaded.';
    } catch {
      this.statusMessage = 'Unable to download the codes. Copy them or try again.';
    }
  }

  private async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(backupText(this.walletId, this.recoveryCodes));
      this.statusMessage = 'Recovery codes copied.';
      this.flashCopied();
    } catch {
      this.statusMessage = 'Unable to copy the codes. Download them or try again.';
    }
  }

  /** Holds the check glyph long enough to read, then crossfades back. */
  private flashCopied(): void {
    if (this.copiedResetTimer !== null) window.clearTimeout(this.copiedResetTimer);
    this.copied = true;
    this.copiedResetTimer = window.setTimeout(() => {
      this.copiedResetTimer = null;
      this.copied = false;
    }, COPIED_FLASH_MS);
  }

  private onAcknowledgementChange(event: Event): void {
    const input = event.target;
    if (input instanceof HTMLInputElement) this.acknowledged = input.checked;
  }

  private onCloseClick(): void {
    this.dispatchEvent(
      new CustomEvent<RecoveryBackupCloseDetail>(RECOVERY_BACKUP_CLOSE_EVENT, {
        detail: { acknowledged: this.acknowledged },
        bubbles: true,
        composed: true,
      }),
    );
  }

  private closeLabel(): string {
    /* One control ends the dialog either way; the checkbox decides what that
       means and the label says so out loud. Checked = "Finish backup": closing
       completes the backup and the wallet deletes its local copy. Unchecked =
       plain dismissal: deferral during registration, cancellation from the
       account menu. */
    if (this.acknowledged) return 'Finish backup';
    return this.continuation === 'registration_may_defer' ? 'Back up later' : 'Close';
  }

  render(): unknown {
    const description =
      this.continuation === 'registration_may_defer'
        ? 'These ten single-use codes recover every signing key in this wallet. Save them now, or back them up later from Recovery Codes in the account menu.'
        : 'These ten single-use codes recover every signing key in this wallet. Save them somewhere private.';
    return html`
      <h1 id="w3a-wallet-recovery-backup-title" class="recovery-backup-title">
        Save your wallet recovery codes
      </h1>
      <p id="w3a-wallet-recovery-backup-description" class="recovery-backup-description">
        ${description}
      </p>
      <ol class="recovery-code-list">
        ${this.recoveryCodes.map(
          (code, index) => html`
            <li class="recovery-code-item">
              <span class="recovery-code-index">${index + 1}</span>
              <span class="recovery-code-value">${code}</span>
            </li>
          `,
        )}
      </ol>
      <div class="recovery-backup-actions">
        <button
          type="button"
          class="recovery-backup-button primary"
          @click=${() => this.download()}
        >
          Download codes
        </button>
        <button
          type="button"
          class="recovery-backup-button primary recovery-backup-copy ${this.copied ? 'copied' : ''}"
          @click=${() => this.copy()}
        >
          <span class="copy-icon" aria-hidden="true">
            <span class="copy-icon-check">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <path d="M20 6 9 17l-5-5"></path>
              </svg>
            </span>
            <span class="copy-icon-copy">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor">
                <rect width="14" height="14" x="8" y="8" rx="2" ry="2"></rect>
                <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"></path>
              </svg>
            </span>
          </span>
          Copy codes
        </button>
      </div>
      <label class="recovery-backup-acknowledgement">
        <input
          type="checkbox"
          data-w3a-wallet-recovery-backup-acknowledgement
          .checked=${this.acknowledged}
          @change=${(event: Event) => this.onAcknowledgementChange(event)}
        />
        I saved these recovery codes (these codes will not be shown again).
      </label>
      <p class="recovery-backup-status" role="status">${this.statusMessage}</p>
      <div class="recovery-backup-footer">
        <button
          type="button"
          class="recovery-backup-button ${this.acknowledged ? 'primary' : 'secondary'}"
          data-w3a-wallet-recovery-backup-close
          @click=${() => this.onCloseClick()}
        >
          ${this.closeLabel()}
        </button>
      </div>
    `;
  }
}

export default RecoveryCodeBackupViewer;
