import { html, type PropertyValues, type TemplateResult } from 'lit';
import type { WalletRecoveryCodeStatusResult } from '@/core/rpcClients/relayer/walletRecoveryRotate';
import type { WalletRecoveryCodeBackupRequestV1 } from '@/core/types/sdkSentEvents';
import { LitElementWithProps } from '../LitElementWithProps';
import { ensureExternalStyles } from '../css/css-loader';
import {
  RECOVERY_BACKUP_CLOSE_EVENT,
  RECOVERY_BACKUP_STAGE_EVENT,
  type RecoveryBackupCloseDetail,
  type RecoveryBackupStage,
} from './events';

export type RecoveryCodeBackupContinuation = WalletRecoveryCodeBackupRequestV1['continuation'];

export type RecoveryCodeBackupExperience =
  | { readonly kind: 'unconfigured' }
  | {
      readonly kind: 'direct_backup';
      readonly request: WalletRecoveryCodeBackupRequestV1;
    }
  | {
      readonly kind: 'account_menu';
      readonly walletId: string;
      readonly loadStatus: () => Promise<WalletRecoveryCodeStatusResult>;
      readonly loadPendingBackup: () => Promise<WalletRecoveryCodeBackupRequestV1 | null>;
    };

type SummaryLoadState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'loaded'; readonly status: WalletRecoveryCodeStatusResult }
  | { readonly kind: 'error'; readonly message: string };

type SummaryViewState =
  | {
      readonly kind: 'summary';
      readonly walletId: string;
      readonly loadState: SummaryLoadState;
      readonly actionError: string | null;
    }
  | {
      readonly kind: 'opening';
      readonly walletId: string;
      readonly loadState: SummaryLoadState;
      readonly actionError: string | null;
    };

type RecoveryCodeViewState =
  | { readonly kind: 'unconfigured' }
  | SummaryViewState
  | {
      readonly kind: 'recovery_codes';
      readonly request: WalletRecoveryCodeBackupRequestV1;
    };

const COPIED_FLASH_MS = 1_800;

function assertNever(value: never): never {
  throw new Error(`Unhandled recovery-code state: ${String(value)}`);
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message.trim() ? error.message : fallback;
}

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

function stageForState(state: RecoveryCodeViewState): RecoveryBackupStage | null {
  switch (state.kind) {
    case 'unconfigured':
      return null;
    case 'summary':
    case 'opening':
    case 'recovery_codes':
      return state.kind;
    default:
      return assertNever(state);
  }
}

function statusLabel(status: WalletRecoveryCodeStatusResult): string {
  switch (status.kind) {
    case 'ready':
      return status.pendingLocalBackup || status.backupOutstanding ? 'Backup needed' : 'Backed up';
    case 'no_recovery_set':
      return 'No recovery set';
    case 'unauthorized':
      return 'Authorization required';
    case 'transport_failed':
      return 'Could not load';
    default:
      return assertNever(status);
  }
}

function canViewPendingRecoveryCodes(loadState: SummaryLoadState): boolean {
  if (loadState.kind !== 'loaded') return true;
  switch (loadState.status.kind) {
    case 'ready':
      return loadState.status.pendingLocalBackup;
    case 'unauthorized':
    case 'transport_failed':
      return true;
    case 'no_recovery_set':
      return false;
    default:
      return assertNever(loadState.status);
  }
}

function recoveryStatusFailureMessage(loadState: SummaryLoadState): string | null {
  if (loadState.kind === 'error') return loadState.message;
  if (loadState.kind !== 'loaded') return null;
  switch (loadState.status.kind) {
    case 'unauthorized':
    case 'transport_failed':
      return loadState.status.message;
    case 'ready':
    case 'no_recovery_set':
      return null;
    default:
      return assertNever(loadState.status);
  }
}

function statusValue(loadState: SummaryLoadState): string {
  switch (loadState.kind) {
    case 'loading':
      return 'Loading';
    case 'error':
      return 'Could not load';
    case 'loaded':
      return statusLabel(loadState.status);
    default:
      return assertNever(loadState);
  }
}

function activeCodesValue(loadState: SummaryLoadState): string {
  return loadState.kind === 'loaded' && loadState.status.kind === 'ready'
    ? `${loadState.status.activeCodeCount} / ${loadState.status.totalCodeCount}`
    : '—';
}

function renderRecoveryCodeItem(code: string, index: number): TemplateResult {
  return html`
    <li class="recovery-code-item">
      <span class="recovery-code-index">${index + 1}</span>
      <span class="recovery-code-value">${code}</span>
    </li>
  `;
}

/**
 * One light-DOM recovery-code surface. Account-menu launches begin at the
 * summary and advance through opening to the code grid; registration enters
 * directly at the code grid. The surrounding native dialog remains mounted
 * for the whole experience, so focus, backdrop, and surface measurement have
 * one owner.
 */
export class RecoveryCodeBackupViewer extends LitElementWithProps {
  static properties = {
    viewState: { state: true },
    acknowledged: { state: true },
    statusMessage: { state: true },
    copied: { state: true },
  } as const;

  declare viewState: RecoveryCodeViewState;
  declare acknowledged: boolean;
  declare statusMessage: string;
  declare copied: boolean;

  private experience: RecoveryCodeBackupExperience = { kind: 'unconfigured' };
  private loadGeneration = 0;
  private copiedResetTimer: number | null = null;
  private stylesReady = false;
  private stylePromise: Promise<void> | null = null;

  constructor() {
    super();
    this.viewState = { kind: 'unconfigured' };
    this.acknowledged = false;
    this.statusMessage = '';
    this.copied = false;
  }

  protected getComponentPrefix(): string {
    return 'recovery-backup';
  }

  protected createRenderRoot(): HTMLElement {
    const root = this as unknown as HTMLElement;
    this.stylePromise = Promise.all([
      ensureExternalStyles(root, 'recovery-code-backup.css', 'data-w3a-recovery-code-backup-css'),
      ensureExternalStyles(root, 'copy-icon.css', 'data-w3a-copy-icon-css'),
      ensureExternalStyles(root, 'w3a-components.css', 'data-w3a-components-css'),
    ]).then(() => {});
    this.stylePromise.catch(() => {});
    return root;
  }

  whenStylesReady(): Promise<void> {
    return this.stylePromise ?? Promise.resolve();
  }

  currentStage(): RecoveryBackupStage | null {
    return stageForState(this.viewState);
  }

  focusInitialTarget(): void {
    switch (this.viewState.kind) {
      case 'summary':
      case 'opening':
        this.querySelector<HTMLElement>('#w3a-wallet-recovery-title')?.focus();
        return;
      case 'recovery_codes':
        this.querySelector<HTMLElement>('#w3a-wallet-recovery-title')?.focus();
        return;
      case 'unconfigured':
        return;
      default:
        assertNever(this.viewState);
    }
  }

  configure(experience: RecoveryCodeBackupExperience): void {
    if (experience.kind === 'unconfigured' || this.experience === experience) return;
    this.experience = experience;
    this.dataset.w3aRecoveryEntry = experience.kind;
    this.loadGeneration += 1;
    this.acknowledged = false;
    this.statusMessage = '';
    this.copied = false;
    switch (experience.kind) {
      case 'direct_backup':
        this.viewState = { kind: 'recovery_codes', request: experience.request };
        this.dataset.w3aRecoveryStage = 'recovery_codes';
        return;
      case 'account_menu': {
        this.viewState = {
          kind: 'summary',
          walletId: experience.walletId,
          loadState: { kind: 'loading' },
          actionError: null,
        };
        this.dataset.w3aRecoveryStage = 'summary';
        void this.loadSummaryStatus(experience, this.loadGeneration);
        return;
      }
      default:
        assertNever(experience);
    }
  }

  protected shouldUpdate(): boolean {
    if (this.stylesReady) return true;
    void (this.stylePromise ?? Promise.resolve()).then(() => {
      this.stylesReady = true;
      this.requestUpdate();
    });
    return false;
  }

  protected updated(changed: PropertyValues<this>): void {
    super.updated(changed);
    if (!changed.has('viewState')) return;
    const stage = stageForState(this.viewState);
    if (!stage) return;
    this.dataset.w3aRecoveryStage = stage;
    this.dispatchEvent(
      new CustomEvent(RECOVERY_BACKUP_STAGE_EVENT, {
        detail: { stage },
        bubbles: true,
        composed: true,
      }),
    );
  }

  disconnectedCallback(): void {
    this.loadGeneration += 1;
    if (this.copiedResetTimer !== null) {
      window.clearTimeout(this.copiedResetTimer);
      this.copiedResetTimer = null;
    }
    super.disconnectedCallback();
  }

  private async loadSummaryStatus(
    experience: Extract<RecoveryCodeBackupExperience, { kind: 'account_menu' }>,
    generation: number,
  ): Promise<void> {
    try {
      const status = await experience.loadStatus();
      this.updateSummaryLoadState(generation, { kind: 'loaded', status });
    } catch (error: unknown) {
      this.updateSummaryLoadState(generation, {
        kind: 'error',
        message: errorMessage(error, 'Could not load recovery-code status'),
      });
    }
  }

  private updateSummaryLoadState(generation: number, loadState: SummaryLoadState): void {
    if (generation !== this.loadGeneration) return;
    switch (this.viewState.kind) {
      case 'summary':
      case 'opening':
        this.viewState = { ...this.viewState, loadState };
        return;
      case 'unconfigured':
      case 'recovery_codes':
        return;
      default:
        assertNever(this.viewState);
    }
  }

  private readonly retryStatus = (): void => {
    if (this.experience.kind !== 'account_menu') return;
    const generation = this.loadGeneration + 1;
    this.loadGeneration = generation;
    const current = this.viewState;
    if (current.kind !== 'summary') return;
    this.viewState = { ...current, loadState: { kind: 'loading' }, actionError: null };
    void this.loadSummaryStatus(this.experience, generation);
  };

  private readonly openRecoveryCodes = async (): Promise<void> => {
    if (this.experience.kind !== 'account_menu' || this.viewState.kind !== 'summary') return;
    const generation = this.loadGeneration;
    const summary = this.viewState;
    this.viewState = { ...summary, kind: 'opening', actionError: null };
    try {
      const request = await this.experience.loadPendingBackup();
      if (generation !== this.loadGeneration) return;
      if (!request) {
        this.viewState = {
          ...summary,
          actionError: 'Recovery codes are no longer available on this device.',
        };
        return;
      }
      this.viewState = { kind: 'recovery_codes', request };
      await this.updateComplete;
      await new Promise<number>(requestAnimationFrame);
      this.querySelector<HTMLElement>('#w3a-wallet-recovery-title')?.focus();
    } catch (error: unknown) {
      if (generation !== this.loadGeneration) return;
      this.viewState = {
        ...summary,
        actionError: errorMessage(error, 'Could not open recovery codes'),
      };
    }
  };

  private readonly closeSummary = (): void => {
    this.dispatchClose({ kind: 'dismissed' });
  };

  private dispatchClose(detail: RecoveryBackupCloseDetail): void {
    this.dispatchEvent(
      new CustomEvent<RecoveryBackupCloseDetail>(RECOVERY_BACKUP_CLOSE_EVENT, {
        detail,
        bubbles: true,
        composed: true,
      }),
    );
  }

  private readonly download = (): void => {
    if (this.viewState.kind !== 'recovery_codes') return;
    const { walletId, recoveryCodes } = this.viewState.request;
    try {
      const url = URL.createObjectURL(
        new Blob([backupText(walletId, recoveryCodes)], {
          type: 'text/plain;charset=utf-8',
        }),
      );
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `seams-wallet-recovery-codes-${safeWalletId(walletId)}.txt`;
      try {
        anchor.click();
      } finally {
        window.setTimeout(URL.revokeObjectURL.bind(URL, url), 0);
      }
      this.statusMessage = 'Recovery codes downloaded.';
    } catch {
      this.statusMessage = 'Unable to download the codes. Copy them or try again.';
    }
  };

  private readonly copy = async (): Promise<void> => {
    if (this.viewState.kind !== 'recovery_codes') return;
    const { walletId, recoveryCodes } = this.viewState.request;
    try {
      await navigator.clipboard.writeText(backupText(walletId, recoveryCodes));
      this.statusMessage = 'Recovery codes copied.';
      this.flashCopied();
    } catch {
      this.statusMessage = 'Unable to copy the codes. Download them or try again.';
    }
  };

  private flashCopied(): void {
    if (this.copiedResetTimer !== null) window.clearTimeout(this.copiedResetTimer);
    this.copied = true;
    this.copiedResetTimer = window.setTimeout(() => {
      this.copiedResetTimer = null;
      this.copied = false;
    }, COPIED_FLASH_MS);
  }

  private readonly onAcknowledgementChange = (event: Event): void => {
    const input = event.target;
    if (input instanceof HTMLInputElement) this.acknowledged = input.checked;
  };

  private readonly closeRecoveryCodes = (): void => {
    this.dispatchClose({ kind: 'recovery_codes', acknowledged: this.acknowledged });
  };

  private closeLabel(request: WalletRecoveryCodeBackupRequestV1): string {
    if (this.acknowledged) return 'Finish backup';
    return request.continuation === 'registration_may_defer' ? 'Back up later' : 'Close';
  }

  private renderSummary(state: SummaryViewState): unknown {
    const statusFailure = recoveryStatusFailureMessage(state.loadState);
    const showViewCodesButton = canViewPendingRecoveryCodes(state.loadState);
    const opening = state.kind === 'opening';
    return html`
      <button
        type="button"
        class="recovery-summary-close"
        aria-label="Close recovery codes"
        @click=${this.closeSummary}
      >
        <svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <path d="M6 6l12 12M18 6 6 18"></path>
        </svg>
      </button>
      <h1 id="w3a-wallet-recovery-title" class="recovery-backup-title" tabindex="-1">
        Wallet recovery codes
      </h1>
      <p id="w3a-wallet-recovery-description" class="recovery-backup-description">
        View and save the recovery codes retained by this wallet after registration.
      </p>
      <div class="recovery-summary-body">
        <div class="recovery-summary-row">
          <span class="recovery-summary-label">Wallet</span>
          <span class="recovery-summary-value">${state.walletId}</span>
        </div>
        <div class="recovery-summary-row">
          <span class="recovery-summary-label">Status</span>
          <span class="recovery-summary-value">${statusValue(state.loadState)}</span>
        </div>
        <div class="recovery-summary-row">
          <span class="recovery-summary-label">Active codes</span>
          <span class="recovery-summary-value">${activeCodesValue(state.loadState)}</span>
        </div>
        ${showViewCodesButton
          ? html`
              <button
                type="button"
                class="recovery-backup-button primary recovery-summary-open"
                ?disabled=${opening}
                @click=${this.openRecoveryCodes}
              >
                ${opening
                  ? html`
                      Opening recovery codes<span
                        class="recovery-summary-ellipsis"
                        aria-hidden="true"
                        ><span>.</span><span>.</span><span>.</span></span
                      >
                    `
                  : 'View recovery codes'}
              </button>
            `
          : null}
        <p class="recovery-summary-live-status" role="status" aria-live="polite">
          ${state.loadState.kind === 'loading' ? 'Loading recovery-code status…' : ''}
        </p>
        ${statusFailure
          ? html`<p class="recovery-summary-error" role="alert">${statusFailure}</p>`
          : null}
        ${state.actionError
          ? html`<p class="recovery-summary-error" role="alert">${state.actionError}</p>`
          : null}
        ${state.loadState.kind === 'error'
          ? html`
              <button
                type="button"
                class="recovery-backup-button secondary"
                @click=${this.retryStatus}
              >
                Retry status
              </button>
            `
          : null}
      </div>
    `;
  }

  private renderRecoveryCodes(request: WalletRecoveryCodeBackupRequestV1): unknown {
    const description =
      request.continuation === 'registration_may_defer'
        ? 'These ten single-use codes recover every signing key in this wallet. Save them now, or back them up later from Recovery Codes in the account menu.'
        : 'These ten single-use codes recover every signing key in this wallet. Save them somewhere private.';
    return html`
      <h1 id="w3a-wallet-recovery-title" class="recovery-backup-title" tabindex="-1">
        Save your wallet recovery codes
      </h1>
      <p id="w3a-wallet-recovery-description" class="recovery-backup-description">${description}</p>
      <ol class="recovery-code-list">${request.recoveryCodes.map(renderRecoveryCodeItem)}</ol>
      <div class="recovery-backup-actions">
        <button type="button" class="recovery-backup-button primary" @click=${this.download}>
          Download codes
        </button>
        <button
          type="button"
          class="recovery-backup-button primary recovery-backup-copy ${this.copied ? 'copied' : ''}"
          @click=${this.copy}
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
          @change=${this.onAcknowledgementChange}
        />
        I saved these recovery codes (these codes will not be shown again).
      </label>
      <p class="recovery-backup-status" role="status">${this.statusMessage}</p>
      <div class="recovery-backup-footer">
        <button
          type="button"
          class="recovery-backup-button ${this.acknowledged ? 'primary' : 'secondary'}"
          data-w3a-wallet-recovery-backup-close
          @click=${this.closeRecoveryCodes}
        >
          ${this.closeLabel(request)}
        </button>
      </div>
    `;
  }

  render(): unknown {
    switch (this.viewState.kind) {
      case 'unconfigured':
        return null;
      case 'summary':
      case 'opening':
        return this.renderSummary(this.viewState);
      case 'recovery_codes':
        return this.renderRecoveryCodes(this.viewState.request);
      default:
        return assertNever(this.viewState);
    }
  }
}

export default RecoveryCodeBackupViewer;
