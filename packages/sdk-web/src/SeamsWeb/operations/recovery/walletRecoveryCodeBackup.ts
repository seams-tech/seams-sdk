import type {
  WalletRecoveryCodeBackupAcknowledgementV1,
  WalletRecoveryCodeBackupRequestV1,
} from '@/core/types/sdkSentEvents';

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

  constructor(private readonly request: WalletRecoveryCodeBackupRequestV1) {
    this.result = new Promise((resolve, reject) => {
      this.resolveResult = resolve;
      this.rejectResult = reject;
    });
    this.build();
  }

  async show(): Promise<WalletRecoveryCodeBackupAcknowledgementV1> {
    document.body.appendChild(this.dialog);
    this.dialog.showModal();
    this.acknowledgement.focus();
    return await this.result;
  }

  private build(): void {
    this.dialog.setAttribute('aria-labelledby', 'w3a-wallet-recovery-backup-title');
    this.dialog.setAttribute('aria-describedby', 'w3a-wallet-recovery-backup-description');
    this.dialog.setAttribute('data-w3a-wallet-recovery-backup-dialog', '');
    this.dialog.className = 'w3a-host-themed-dialog';
    this.dialog.style.cssText = [
      'width:min(30rem,calc(100vw - 1.5rem))',
      'max-height:calc(100vh - 1.5rem)',
      'overflow:auto',
      'box-sizing:border-box',
      'border:1px solid var(--w3a-colors-borderPrimary,rgba(86,81,119,.22))',
      'border-radius:1rem',
      'background:var(--w3a-colors-colorBackground,#fffaf3)',
      'color:var(--w3a-colors-textPrimary,#565177)',
      'padding:1.25rem',
      'box-shadow:0 1.5rem 5rem rgba(0,0,0,.24)',
      'font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
      'overscroll-behavior:contain',
    ].join(';');

    const title = document.createElement('h1');
    title.id = 'w3a-wallet-recovery-backup-title';
    title.textContent = 'Save your wallet recovery codes';
    title.style.cssText = 'margin:0 0 .5rem;font-size:1.25rem;line-height:1.25;font-weight:600';
    this.dialog.appendChild(title);

    const description = document.createElement('p');
    description.id = 'w3a-wallet-recovery-backup-description';
    description.textContent =
      'These ten single-use codes recover every signing key in this wallet. Save them somewhere private before you finish registration.';
    description.style.cssText =
      'margin:0 0 1rem;color:var(--w3a-colors-textSecondary,#565177);line-height:1.5';
    this.dialog.appendChild(description);

    const list = document.createElement('ol');
    list.style.cssText = 'display:grid;gap:.5rem;margin:0 0 1rem;padding:0;list-style:none';
    for (const [index, code] of this.request.recoveryCodes.entries()) {
      const item = document.createElement('li');
      item.textContent = `${index + 1}. ${code}`;
      item.style.cssText = [
        'border-radius:.625rem',
        'background:var(--w3a-colors-surface2,#f4eadf)',
        'padding:.625rem .75rem',
        'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
        'font-size:.8125rem',
        'font-weight:700',
        'line-height:1.25',
        'overflow-wrap:anywhere',
      ].join(';');
      list.appendChild(item);
    }
    this.dialog.appendChild(list);

    const backupActions = document.createElement('div');
    backupActions.style.cssText = 'display:flex;flex-wrap:wrap;gap:.5rem;margin-bottom:1rem';
    backupActions.appendChild(this.button('Download codes', this.download.bind(this), false));
    backupActions.appendChild(this.button('Copy codes', this.copy.bind(this), false));
    this.dialog.appendChild(backupActions);

    const acknowledgementLabel = document.createElement('label');
    acknowledgementLabel.style.cssText =
      'display:flex;gap:.625rem;align-items:flex-start;margin-bottom:1rem;line-height:1.4;cursor:pointer';
    this.acknowledgement.type = 'checkbox';
    this.acknowledgement.setAttribute('data-w3a-wallet-recovery-backup-acknowledgement', '');
    this.acknowledgement.style.cssText = 'width:1.25rem;height:1.25rem;margin:.05rem 0 0;flex:none';
    acknowledgementLabel.appendChild(this.acknowledgement);
    acknowledgementLabel.append('I saved these recovery codes somewhere private.');
    this.dialog.appendChild(acknowledgementLabel);

    this.status.setAttribute('role', 'status');
    this.status.style.cssText =
      'min-height:1.25rem;margin:0 0 .75rem;color:var(--w3a-colors-textSecondary,#565177);font-size:.8125rem';
    this.dialog.appendChild(this.status);

    const finalActions = document.createElement('div');
    finalActions.style.cssText = 'display:flex;flex-wrap:wrap;justify-content:flex-end;gap:.5rem';
    finalActions.appendChild(this.button('Cancel registration', this.cancel.bind(this), false));
    finalActions.appendChild(this.button('Finish backup', this.finish.bind(this), true));
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
    } catch {
      this.status.textContent = 'Unable to copy the codes. Download them or try again.';
    }
  }

  private finish(): void {
    if (!this.acknowledgement.checked) {
      this.status.textContent = 'Confirm that you saved the recovery codes before continuing.';
      this.acknowledgement.focus();
      return;
    }
    this.settled = true;
    this.close();
    this.resolveResult({ kind: 'wallet_recovery_codes_backed_up_v1' });
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
    this.dialog.close();
    this.dialog.remove();
    this.previousFocus?.focus();
  }
}

export async function showWalletRecoveryCodeBackupUi(
  request: WalletRecoveryCodeBackupRequestV1,
): Promise<WalletRecoveryCodeBackupAcknowledgementV1> {
  if (typeof document === 'undefined') {
    throw new Error('Wallet recovery-code backup requires a browser or a backup handler');
  }
  return await new WalletRecoveryCodeBackupDialog(request).show();
}
