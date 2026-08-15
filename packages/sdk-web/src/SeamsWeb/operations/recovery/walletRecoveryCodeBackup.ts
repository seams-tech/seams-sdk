import type {
  WalletRecoveryCodeBackupAcknowledgementV1,
  WalletRecoveryCodeBackupRequestV1,
} from '@/core/types/sdkSentEvents';
import type { UiConfirmSurfaceMeasurementBinding } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import {
  createWalletIframeSurfaceMeasurementReporter,
  type WalletIframeSurfaceMeasurementReporter,
} from '../../walletIframe/host/lit-ui/surface-measurement-reporter';

function safeWalletId(value: string): string {
  return value.trim().replace(/[^A-Za-z0-9_.-]/g, '_') || 'wallet';
}

function backupText(request: WalletRecoveryCodeBackupRequestV1): string {
  const lines = [
    'Seams wallet recovery codes',
    '',
    `Wallet: ${request.walletId}`,
    '',
    'Save these codes somewhere private. Each code can be used once.',
    '',
  ];
  for (const [index, code] of request.recoveryCodes.entries()) {
    lines.push(`${String(index + 1).padStart(2, '0')}  ${code}`);
  }
  return `${lines.join('\n')}\n`;
}

const COPY_ICON_SVG_ATTRS: ReadonlyArray<readonly [string, string]> = [
  ['width', '16'],
  ['height', '16'],
  ['viewBox', '0 0 24 24'],
  ['fill', 'none'],
  ['stroke', 'currentColor'],
];

function copyIconSvg(paths: readonly string[], shapes: readonly string[] = []): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  for (const [name, value] of COPY_ICON_SVG_ATTRS) svg.setAttribute(name, value);
  for (const shape of shapes) {
    const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    for (const pair of shape.split(' ')) {
      const [name, value] = pair.split('=');
      rect.setAttribute(name, value);
    }
    svg.appendChild(rect);
  }
  for (const d of paths) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', d);
    svg.appendChild(path);
  }
  return svg;
}

/**
 * The `.copy-icon` check/copy crossfade from the export viewer, rebuilt in
 * imperative DOM. Same class names and the same two glyphs, so the two copy
 * affordances in the wallet read as one control — see
 * `lit-components/css/export-viewer.css`.
 */
function buildCopyIcon(): HTMLSpanElement {
  const icon = document.createElement('span');
  icon.className = 'copy-icon';
  icon.setAttribute('aria-hidden', 'true');

  const check = document.createElement('span');
  check.className = 'copy-icon-check';
  check.appendChild(copyIconSvg(['M20 6 9 17l-5-5']));

  const copy = document.createElement('span');
  copy.className = 'copy-icon-copy';
  copy.appendChild(
    copyIconSvg(
      ['M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2'],
      ['width=14 height=14 x=8 y=8 rx=2 ry=2'],
    ),
  );

  icon.append(check, copy);
  return icon;
}

/* Scoped to this dialog so the animation works whether or not the export
   viewer's stylesheet happens to be loaded in this document. */
const COPY_ICON_STYLES = `
[data-w3a-wallet-recovery-backup-dialog] .copy-icon {
  position: relative;
  width: 16px;
  height: 16px;
  flex: 0 0 16px;
  color: currentColor;
}
[data-w3a-wallet-recovery-backup-dialog] .copy-icon svg {
  display: block;
  stroke-width: 2;
  stroke-linecap: round;
  stroke-linejoin: round;
}
[data-w3a-wallet-recovery-backup-dialog] .copy-icon-check,
[data-w3a-wallet-recovery-backup-dialog] .copy-icon-copy {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  transition:
    transform 300ms ease-in-out,
    opacity 300ms ease-in-out,
    filter 300ms ease-in-out;
}
[data-w3a-wallet-recovery-backup-dialog] .copy-icon-check {
  transform: scale(0.25);
  opacity: 0;
  filter: blur(2px);
}
[data-w3a-wallet-recovery-backup-dialog] .copy-icon-copy {
  transform: scale(1);
  opacity: 1;
  filter: blur(0);
}
[data-w3a-wallet-recovery-backup-dialog] .copied .copy-icon {
  color: var(--w3a-colors-success, #34d399);
}
[data-w3a-wallet-recovery-backup-dialog] .copied .copy-icon-check {
  transform: scale(1);
  opacity: 1;
  filter: blur(0);
}
[data-w3a-wallet-recovery-backup-dialog] .copied .copy-icon-copy {
  transform: scale(0.25);
  opacity: 0;
  filter: blur(2px);
}
@media (prefers-reduced-motion: reduce) {
  [data-w3a-wallet-recovery-backup-dialog] .copy-icon-check,
  [data-w3a-wallet-recovery-backup-dialog] .copy-icon-copy {
    transition-duration: 0.01ms;
  }
}
`;

function downloadBackup(request: WalletRecoveryCodeBackupRequestV1): void {
  const url = URL.createObjectURL(
    new Blob([backupText(request)], { type: 'text/plain;charset=utf-8' }),
  );
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `seams-wallet-recovery-codes-${safeWalletId(request.walletId)}.txt`;
  try {
    anchor.click();
  } finally {
    window.setTimeout(URL.revokeObjectURL.bind(URL, url), 0);
  }
}

class WalletRecoveryCodeBackupDialog {
  private readonly dialog = document.createElement('dialog');
  private readonly acknowledgement = document.createElement('input');
  private readonly status = document.createElement('p');
  private readonly previousFocus =
    document.activeElement instanceof HTMLElement ? document.activeElement : null;
  private readonly result: Promise<WalletRecoveryCodeBackupAcknowledgementV1>;
  private resolveResult!: (value: WalletRecoveryCodeBackupAcknowledgementV1) => void;
  private rejectResult!: (error: Error) => void;
  private settled = false;
  private measurementReporter: WalletIframeSurfaceMeasurementReporter | null = null;
  private copyButton: HTMLButtonElement | null = null;
  private copiedResetTimer: number | null = null;

  constructor(
    private readonly request: WalletRecoveryCodeBackupRequestV1,
    private readonly measurementBinding: UiConfirmSurfaceMeasurementBinding,
  ) {
    this.result = new Promise((resolve, reject) => {
      this.resolveResult = resolve;
      this.rejectResult = reject;
    });
    this.build();
  }

  async show(): Promise<WalletRecoveryCodeBackupAcknowledgementV1> {
    document.body.appendChild(this.dialog);
    this.measurementReporter = this.createMeasurementReporter();
    this.dialog.showModal();
    this.dialog.focus();
    return await this.result;
  }

  private build(): void {
    const iframeSurface = this.measurementBinding.kind === 'wallet_iframe';
    /* Inside the wallet iframe the host sizes the frame FROM this dialog's
       measurement, so the dialog must own the whole frame: zero UA centering
       margins and a max-height of exactly 100vh. Any slack (auto margins, the
       standalone 1.5rem breathing room) becomes dead space around the card and
       clips/scrolls it once the measured height feeds back into the frame. */
    const dialogSizing = iframeSurface
      ? 'width:100%;max-width:100%;margin:0;max-height:100vh'
      : 'width:min(44rem,calc(100vw - 1.5rem));max-height:calc(100vh - 1.5rem)';
    /* In the iframe the frame is a square rect hugging the rounded card, so
       anything painted outside the card's radius — the UA ::backdrop tint, the
       drop shadow — shows up as a dark pointed corner over the host's own
       backdrop. The host dims the page; this surface must paint nothing
       outside the card. */
    const dialogShadow = iframeSurface
      ? 'box-shadow:none'
      : 'box-shadow:0 1.5rem 5rem rgba(0,0,0,.24)';
    this.dialog.setAttribute('aria-labelledby', 'w3a-wallet-recovery-backup-title');
    this.dialog.setAttribute('aria-describedby', 'w3a-wallet-recovery-backup-description');
    this.dialog.setAttribute('data-w3a-wallet-recovery-backup-dialog', '');
    this.dialog.tabIndex = -1;
    this.dialog.className = 'w3a-host-themed-dialog';
    this.dialog.style.cssText = [
      dialogSizing,
      'overflow:auto',
      'box-sizing:border-box',
      /* The dialog itself takes programmatic focus on open; a focus ring on
         the card's own edge reads as a stray blue border. */
      'outline:none',
      /* border:none must stay explicit — the UA gives <dialog> a default
         border. The card floats on a dimmed backdrop with its own shadow, and
         in the iframe the frame hugs the card exactly, so a border reads as a
         detached hairline once the scroller rubber-bands.
         overscroll-behavior:none (not contain) suppresses that bounce: the
         card can measure fractionally taller than the frame's whole-px height,
         which leaves a sub-pixel scroll range for the bounce to act on. */
      'border:none',
      'border-radius:1rem',
      'background:var(--w3a-colors-colorBackground,#fffaf3)',
      'color:var(--w3a-colors-textPrimary,#565177)',
      'padding:1.75rem 1.25rem 1.25rem',
      dialogShadow,
      'font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      'overscroll-behavior:none',
    ].join(';');
    const dialogStyles = document.createElement('style');
    dialogStyles.textContent = iframeSurface
      ? `dialog[data-w3a-wallet-recovery-backup-dialog]::backdrop{background:transparent}${COPY_ICON_STYLES}`
      : COPY_ICON_STYLES;
    this.dialog.appendChild(dialogStyles);

    const title = document.createElement('h1');
    title.id = 'w3a-wallet-recovery-backup-title';
    title.textContent = 'Save your wallet recovery codes';
    title.style.cssText =
      'margin:0 0 .5rem;font-size:1.3125rem;line-height:1.25;font-weight:600;letter-spacing:-0.01em';
    this.dialog.appendChild(title);

    const description = document.createElement('p');
    description.id = 'w3a-wallet-recovery-backup-description';
    description.textContent =
      this.request.continuation === 'registration_may_defer'
        ? 'These ten single-use codes recover every signing key in this wallet. Save them now, or back them up later from Recovery Codes in the account menu.'
        : 'These ten single-use codes recover every signing key in this wallet. Save them somewhere private.';
    description.style.cssText =
      'margin:0 0 1rem;color:var(--w3a-colors-textSecondary,#565177);line-height:1.5';
    this.dialog.appendChild(description);

    const list = document.createElement('ol');
    /* auto-fit rather than a fixed two columns: on a narrow surface the grid
       collapses to one column instead of wrapping every code to three lines. */
    list.style.cssText =
      'display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:.5rem;margin:0 0 1rem;padding:0;list-style:none';
    for (const [index, code] of this.request.recoveryCodes.entries()) {
      const item = document.createElement('li');
      item.style.cssText = [
        'display:flex',
        'gap:.4rem',
        'align-items:baseline',
        'border-radius:.5rem',
        'background:var(--w3a-colors-surface2,#f4eadf)',
        'padding:.375rem .5rem',
        'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
        'font-size:.71875rem',
        'line-height:1.4',
      ].join(';');
      const indexBadge = document.createElement('span');
      indexBadge.textContent = String(index + 1);
      indexBadge.style.cssText = [
        'flex:0 0 2ch',
        'text-align:right',
        'font-weight:400',
        'color:var(--w3a-colors-textSecondary,#565177)',
        'user-select:none',
      ].join(';');
      const codeText = document.createElement('span');
      codeText.textContent = code;
      /* user-select:all — one click grabs the whole code, matching how people
         actually lift these into a password manager. Wraps at the hyphens. */
      codeText.style.cssText = [
        'min-width:0',
        'font-weight:400',
        'letter-spacing:.01em',
        'overflow-wrap:anywhere',
        'user-select:all',
      ].join(';');
      item.append(indexBadge, codeText);
      list.appendChild(item);
    }
    this.dialog.appendChild(list);

    const backupActions = document.createElement('div');
    backupActions.style.cssText = 'display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem';
    const downloadButton = this.button('Download codes', this.download.bind(this), true);
    const copyButton = this.button('Copy codes', this.copy.bind(this), true);
    // The icon crossfades to a check in place, so it leads the label and the
    // button keeps its width through the transition.
    copyButton.style.cssText +=
      ';display:inline-flex;align-items:center;justify-content:center;gap:.5rem';
    copyButton.prepend(buildCopyIcon());
    this.copyButton = copyButton;
    /* flex-basis 0, not auto: both columns split the row evenly instead of
       tracking their label widths. */
    downloadButton.style.flex = '1 1 0';
    copyButton.style.flex = '1 1 0';
    backupActions.append(downloadButton, copyButton);
    this.dialog.appendChild(backupActions);

    const acknowledgementLabel = document.createElement('label');
    acknowledgementLabel.style.cssText =
      'display:flex;gap:.625rem;align-items:flex-start;margin-bottom:.75rem;font-size:.9375rem;line-height:1.4;cursor:pointer';
    this.acknowledgement.type = 'checkbox';
    this.acknowledgement.setAttribute('data-w3a-wallet-recovery-backup-acknowledgement', '');
    this.acknowledgement.style.cssText =
      'width:1.125rem;height:1.125rem;margin:.1rem 0 0;flex:none;accent-color:var(--w3a-colors-primary,#3b82f6)';
    acknowledgementLabel.appendChild(this.acknowledgement);
    acknowledgementLabel.append(
      'I saved these recovery codes (these codes will not be shown again).',
    );
    this.dialog.appendChild(acknowledgementLabel);

    this.status.setAttribute('role', 'status');
    this.status.style.cssText =
      'min-height:1rem;margin:0 0 .5rem;color:var(--w3a-colors-textSecondary,#565177);font-size:.8125rem';
    this.dialog.appendChild(this.status);

    const finalActions = document.createElement('div');
    finalActions.style.cssText = [
      'position:sticky',
      'bottom:0',
      'display:flex',
      'flex-wrap:wrap',
      'justify-content:flex-end',
      'gap:.5rem',
      'padding-top:.5rem',
      'background:var(--w3a-colors-colorBackground,#fffaf3)',
    ].join(';');
    /* One control ends the dialog either way; the checkbox decides what that
       means and the label says so out loud. Checked = "Finish backup": closing
       completes the backup and the wallet deletes its local copy. Unchecked =
       plain dismissal: deferral during registration, cancellation from the
       account menu. */
    const idleCloseLabel =
      this.request.continuation === 'registration_may_defer' ? 'Back up later' : 'Close';
    const closeButton = this.button(idleCloseLabel, this.closeAction.bind(this), true);
    closeButton.setAttribute('data-w3a-wallet-recovery-backup-close', '');
    this.acknowledgement.addEventListener('change', () => {
      closeButton.textContent = this.acknowledgement.checked ? 'Finish backup' : idleCloseLabel;
    });
    finalActions.appendChild(closeButton);
    this.dialog.appendChild(finalActions);

    this.dialog.addEventListener('cancel', this.cancelFromEscape.bind(this));
  }

  private button(label: string, action: () => void, primary: boolean): HTMLButtonElement {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = label;
    button.style.cssText = [
      'min-height:2.75rem',
      'border-radius:.625rem',
      primary
        ? 'border:1px solid transparent;background:var(--w3a-colors-buttonBackground,#565177);color:var(--w3a-colors-textButton,#fffaf3)'
        : 'border:1px solid var(--w3a-colors-borderPrimary,rgba(86,81,119,.22));background:transparent;color:inherit',
      'padding:.625rem .875rem',
      'font:inherit',
      'font-weight:600',
      'cursor:pointer',
    ].join(';');
    button.addEventListener('click', action);
    return button;
  }

  private download(): void {
    try {
      downloadBackup(this.request);
      this.status.textContent = 'Recovery codes downloaded.';
    } catch {
      this.status.textContent = 'Unable to download the codes. Copy them or try again.';
    }
  }

  private async copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(backupText(this.request));
      this.status.textContent = 'Recovery codes copied.';
      this.flashCopied();
    } catch {
      this.status.textContent = 'Unable to copy the codes. Download them or try again.';
    }
  }

  /** Holds the check glyph long enough to read, then crossfades back. */
  private flashCopied(): void {
    const button = this.copyButton;
    if (!button) return;
    if (this.copiedResetTimer !== null) window.clearTimeout(this.copiedResetTimer);
    button.classList.add('copied');
    this.copiedResetTimer = window.setTimeout(() => {
      this.copiedResetTimer = null;
      button.classList.remove('copied');
    }, 1800);
  }

  private closeAction(): void {
    if (this.settled) return;
    if (this.acknowledgement.checked) {
      this.settled = true;
      this.close();
      this.resolveResult({ kind: 'wallet_recovery_codes_backed_up_v1' });
      return;
    }
    if (this.request.continuation === 'registration_may_defer') {
      this.defer();
      return;
    }
    this.cancel();
  }

  private defer(): void {
    if (this.settled || this.request.continuation !== 'registration_may_defer') return;
    this.settled = true;
    this.close();
    this.resolveResult({ kind: 'wallet_recovery_code_backup_deferred_v1' });
  }

  private cancel(): void {
    if (this.settled) return;
    this.settled = true;
    this.close();
    this.rejectResult(new Error('Wallet registration was cancelled before recovery-code backup'));
  }

  private cancelFromEscape(event: Event): void {
    event.preventDefault();
    this.cancel();
  }

  private close(): void {
    if (this.copiedResetTimer !== null) {
      window.clearTimeout(this.copiedResetTimer);
      this.copiedResetTimer = null;
    }
    this.measurementReporter?.disconnect();
    this.measurementReporter = null;
    this.dialog.close();
    this.dialog.remove();
    this.previousFocus?.focus();
  }

  private createMeasurementReporter(): WalletIframeSurfaceMeasurementReporter | null {
    switch (this.measurementBinding.kind) {
      case 'disabled':
        return null;
      case 'wallet_iframe':
        return createWalletIframeSurfaceMeasurementReporter({
          kind: 'request_scroll_surface',
          requestId: this.measurementBinding.requestId,
          element: this.dialog,
          postMeasurement: this.measurementBinding.postMeasurement,
        });
    }
  }
}

export async function showWalletRecoveryCodeBackupUi(
  request: WalletRecoveryCodeBackupRequestV1,
  measurementBinding: UiConfirmSurfaceMeasurementBinding = { kind: 'disabled' },
): Promise<WalletRecoveryCodeBackupAcknowledgementV1> {
  if (typeof document === 'undefined') {
    throw new Error('Wallet recovery-code backup requires a browser or a backup handler');
  }
  return await new WalletRecoveryCodeBackupDialog(request, measurementBinding).show();
}
