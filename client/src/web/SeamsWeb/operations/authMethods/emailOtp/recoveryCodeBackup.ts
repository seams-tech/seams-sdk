import { joinNormalizedUrl } from '@shared/utils/normalize';
import type {
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
} from '@/web/SeamsWeb/signingSurface/types';
import type { EmailOtpRecoveryCodeStatus } from './challenge';
import {
  postJson,
  readString,
  type FetchLike,
} from './challenge';

type EmailOtpRecoveryCodeBackupUiInput = {
  walletId: string;
  enrollment: EmailOtpEnrollmentResult;
};

function stripEmailOtpRecoveryKeysAfterBackup(
  result: EmailOtpEnrollmentResult,
  recoveryCodeBackup: EmailOtpRecoveryCodeBackupStatus,
): EmailOtpBackedUpEnrollmentResult {
  const { recoveryKeys: _recoveryKeys, ...metadata } = result;
  return {
    ...metadata,
    recoveryCodeBackup,
  };
}

function filenameSafeWalletId(walletId: string): string {
  const safe = walletId.trim().replace(/[^A-Za-z0-9_.-]/g, '_');
  return safe || 'wallet';
}

function buildEmailOtpRecoveryCodeBackupFilename(walletId: string): string {
  return `seams-email-otp-recovery-codes-${filenameSafeWalletId(walletId)}.txt`;
}

function buildEmailOtpRecoveryCodeBackupText(
  input: EmailOtpRecoveryCodeBackupUiInput,
): string {
  const created = new Date(input.enrollment.recoveryCodesIssuedAtMs).toISOString();
  const lines = [
    'Seams Email OTP recovery codes',
    '',
    `Wallet: ${input.walletId}`,
    `Created: ${created}`,
    '',
    'Store these codes somewhere private. Each code can be used once.',
    '',
    ...input.enrollment.recoveryKeys.map(
      (code, index) => `${String(index + 1).padStart(2, '0')}  ${code}`,
    ),
  ];
  return `${lines.join('\n')}\n`;
}

function htmlEscape(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      case "'":
        return '&#39;';
      default:
        return char;
    }
  });
}

function downloadRecoveryCodes(input: EmailOtpRecoveryCodeBackupUiInput): void {
  const blob = new Blob([buildEmailOtpRecoveryCodeBackupText(input)], {
    type: 'text/plain;charset=utf-8',
  });
  let url: string | null = null;
  url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = buildEmailOtpRecoveryCodeBackupFilename(input.walletId);
  try {
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}

async function copyRecoveryCodes(input: EmailOtpRecoveryCodeBackupUiInput): Promise<void> {
  const clipboard = navigator.clipboard;
  if (!clipboard || typeof clipboard.writeText !== 'function') {
    throw new Error('Clipboard API is unavailable');
  }
  await clipboard.writeText(buildEmailOtpRecoveryCodeBackupText(input));
}

function printRecoveryCodes(input: EmailOtpRecoveryCodeBackupUiInput): boolean {
  const printWindow = window.open('', '_blank', 'noopener,noreferrer');
  if (!printWindow || typeof printWindow.print !== 'function') return false;
  const text = htmlEscape(buildEmailOtpRecoveryCodeBackupText(input));
  printWindow.document.write(
    `<!doctype html><title>Email OTP recovery codes</title><pre style="font:16px monospace;white-space:pre-wrap">${text}</pre>`,
  );
  printWindow.document.close();
  printWindow.print();
  return true;
}

function showEmailOtpRecoveryCodeBackupUi(
  input: EmailOtpRecoveryCodeBackupUiInput,
): Promise<void> {
  if (typeof document === 'undefined') {
    return Promise.reject(new Error('Email OTP recovery code backup UI requires document'));
  }
  const { enrollment } = input;
  const overlay = document.createElement('div');
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.style.cssText = [
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'background:rgba(28,27,34,.54)',
    'font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
    'color:#565177',
  ].join(';');

  const panel = document.createElement('section');
  panel.style.cssText = [
    'width:min(720px,calc(100vw - 32px))',
    'max-height:calc(100vh - 32px)',
    'overflow:auto',
    'box-sizing:border-box',
    'border:1px solid rgba(86,81,119,.22)',
    'border-radius:24px',
    'background:#fffaf3',
    'padding:28px',
    'box-shadow:0 24px 80px rgba(0,0,0,.24)',
  ].join(';');

  const title = document.createElement('h1');
  title.textContent = 'Email OTP recovery codes';
  title.style.cssText = 'margin:0 0 18px;font-size:32px;line-height:1.1;color:#565177';
  panel.appendChild(title);

  const list = document.createElement('ol');
  list.style.cssText = [
    'display:grid',
    'grid-template-columns:repeat(auto-fit,minmax(230px,1fr))',
    'gap:10px 14px',
    'margin:0 0 22px',
    'padding:0',
    'list-style-position:inside',
  ].join(';');
  for (const code of enrollment.recoveryKeys) {
    const item = document.createElement('li');
    item.textContent = code;
    item.style.cssText = [
      'box-sizing:border-box',
      'border:1px solid rgba(86,81,119,.16)',
      'border-radius:12px',
      'background:#f4eadf',
      'padding:12px',
      'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
      'font-size:15px',
      'font-weight:700',
      'letter-spacing:0',
    ].join(';');
    list.appendChild(item);
  }
  panel.appendChild(list);

  const actions = document.createElement('div');
  actions.style.cssText =
    'display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin:0 0 16px';
  const download = document.createElement('button');
  download.type = 'button';
  download.textContent = 'Download';
  const copy = document.createElement('button');
  copy.type = 'button';
  copy.textContent = 'Copy';
  const print = document.createElement('button');
  print.type = 'button';
  print.textContent = 'Print';
  download.style.cssText =
    'grid-column:1/-1;border:1px solid rgba(86,81,119,.24);border-radius:12px;background:#565177;color:#fffaf3;padding:14px;font-size:17px;font-weight:900;cursor:pointer';
  actions.appendChild(download);
  for (const action of [copy, print]) {
    action.style.cssText =
      'border:1px solid rgba(86,81,119,.24);border-radius:12px;background:#fffaf3;color:#565177;padding:12px;font-size:16px;font-weight:800;cursor:pointer';
    actions.appendChild(action);
  }
  panel.appendChild(actions);

  const manualCopy = document.createElement('div');
  manualCopy.hidden = true;
  manualCopy.style.cssText = 'margin:0 0 16px';
  const manualCopyText = document.createElement('textarea');
  manualCopyText.readOnly = true;
  manualCopyText.rows = 9;
  manualCopyText.style.cssText = [
    'box-sizing:border-box',
    'width:100%',
    'margin:0 0 10px',
    'border:1px solid rgba(86,81,119,.22)',
    'border-radius:12px',
    'background:#fffaf3',
    'color:#565177',
    'padding:12px',
    'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
    'font-size:13px',
  ].join(';');
  const manualCopyConfirm = document.createElement('button');
  manualCopyConfirm.type = 'button';
  manualCopyConfirm.textContent = 'I copied these codes';
  manualCopyConfirm.style.cssText =
    'border:1px solid rgba(86,81,119,.24);border-radius:12px;background:#565177;color:#fffaf3;padding:12px;font-size:15px;font-weight:800;cursor:pointer';
  manualCopy.appendChild(manualCopyText);
  manualCopy.appendChild(manualCopyConfirm);
  panel.appendChild(manualCopy);

  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.style.cssText = 'min-height:20px;margin:0 0 14px;font-size:14px;color:#565177';
  panel.appendChild(status);

  const checkboxLabel = document.createElement('label');
  checkboxLabel.style.cssText =
    'display:flex;gap:10px;align-items:flex-start;margin:0 0 16px;font-size:15px;font-weight:700;color:#565177';
  const checkbox = document.createElement('input');
  checkbox.type = 'checkbox';
  checkbox.style.cssText = 'width:18px;height:18px;margin-top:2px';
  checkboxLabel.appendChild(checkbox);
  checkboxLabel.appendChild(document.createTextNode('I saved these codes in a private place'));
  panel.appendChild(checkboxLabel);

  const continueButton = document.createElement('button');
  continueButton.type = 'button';
  continueButton.textContent = 'Continue';
  continueButton.disabled = true;
  continueButton.style.cssText = [
    'width:100%',
    'border:1px solid rgba(86,81,119,.24)',
    'border-radius:14px',
    'background:#565177',
    'color:#fffaf3',
    'padding:14px 18px',
    'font-size:18px',
    'font-weight:800',
    'cursor:pointer',
    'opacity:.45',
  ].join(';');
  panel.appendChild(continueButton);
  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  let backupActionCompleted = false;
  const refreshContinue = () => {
    continueButton.disabled = !(backupActionCompleted && checkbox.checked);
    continueButton.style.opacity = continueButton.disabled ? '.45' : '1';
  };
  const completeBackupAction = () => {
    backupActionCompleted = true;
    refreshContinue();
  };
  const showManualCopy = (message: string) => {
    status.textContent = message;
    manualCopyText.value = buildEmailOtpRecoveryCodeBackupText(input);
    manualCopy.hidden = false;
    manualCopyText.focus();
    manualCopyText.select();
  };
  download.addEventListener('click', () => {
    try {
      downloadRecoveryCodes(input);
      status.textContent = 'Recovery codes downloaded.';
      completeBackupAction();
    } catch {
      status.textContent = 'Download failed. Copy or print the recovery codes instead.';
    }
  });
  copy.addEventListener('click', () => {
    void copyRecoveryCodes(input)
      .then(() => {
        status.textContent = 'Recovery codes copied.';
        completeBackupAction();
      })
      .catch(() => {
        showManualCopy('Copy failed. Select the codes below, copy them manually, then confirm.');
      });
  });
  print.addEventListener('click', () => {
    if (printRecoveryCodes(input)) {
      status.textContent = 'Recovery codes sent to print.';
      completeBackupAction();
      return;
    }
    status.textContent = 'Print is blocked. Download or copy the recovery codes instead.';
  });
  manualCopyConfirm.addEventListener('click', completeBackupAction);
  checkbox.addEventListener('change', refreshContinue);
  download.focus();

  return new Promise((resolve) => {
    continueButton.addEventListener(
      'click',
      () => {
        overlay.remove();
        resolve();
      },
      { once: true },
    );
  });
}

export async function backupEmailOtpRecoveryCodes(input: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  enrollment: EmailOtpEnrollmentResult;
  acknowledge?: (args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) => Promise<EmailOtpRecoveryCodeBackupStatus>;
}): Promise<EmailOtpBackedUpEnrollmentResult> {
  await showEmailOtpRecoveryCodeBackupUi({
    walletId: input.walletId,
    enrollment: input.enrollment,
  });
  const acknowledge = input.acknowledge || acknowledgeEmailOtpRecoveryCodeBackup;
  const backup = await acknowledge({
    relayUrl: input.relayUrl,
    walletId: input.walletId,
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
  });
  return stripEmailOtpRecoveryKeysAfterBackup(input.enrollment, backup);
}

export async function acknowledgeEmailOtpRecoveryCodeBackup(args: {
  relayUrl: string;
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  appSessionJwt?: string;
  fetchImpl?: FetchLike;
}): Promise<EmailOtpRecoveryCodeBackupStatus> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/recovery-key/backup-acknowledge'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
      enrollmentId: readString(args.enrollmentId, 'enrollmentId'),
      enrollmentSealKeyVersion: readString(
        args.enrollmentSealKeyVersion,
        'enrollmentSealKeyVersion',
      ),
    },
  });
  return {
    status: 'active',
    walletId: readString(response.walletId, 'recovery-code backup status walletId'),
    enrollmentId: readString(response.enrollmentId, 'recovery-code backup status enrollmentId'),
    recoveryCodeCount: Math.floor(Number(response.recoveryCodeCount)),
    issuedAtMs: Math.floor(Number(response.issuedAtMs)),
    acknowledgedAtMs: Math.floor(Number(response.acknowledgedAtMs)),
    activeRecoveryCodeCountAtAcknowledgement: Math.floor(
      Number(response.activeRecoveryCodeCountAtAcknowledgement),
    ),
  };
}

function parseNullableNumber(value: unknown): number | null {
  if (value === null || value === undefined) return null;
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return null;
  return Math.floor(parsed);
}

export async function getEmailOtpRecoveryCodeStatus(args: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  fetchImpl?: FetchLike;
}): Promise<EmailOtpRecoveryCodeStatus> {
  const response = await postJson({
    url: joinNormalizedUrl(args.relayUrl, '/wallet/email-otp/recovery-key/status'),
    appSessionJwt: args.appSessionJwt,
    fetchImpl: args.fetchImpl,
    body: {
      walletId: readString(args.walletId, 'walletId'),
    },
  });
  const status = readString(response.status, 'recovery-code status');
  if (
    status !== 'ready' &&
    status !== 'pending_backup' &&
    status !== 'incomplete' &&
    status !== 'not_enrolled'
  ) {
    throw new Error('Unexpected Email OTP recovery-code status');
  }
  return {
    status,
    walletId: readString(response.walletId, 'recovery-code status walletId'),
    enrollmentId: readString(response.enrollmentId, 'recovery-code status enrollmentId'),
    enrollmentSealKeyVersion: readString(
      response.enrollmentSealKeyVersion,
      'recovery-code status enrollmentSealKeyVersion',
    ),
    expectedRecoveryCodeCount: Math.floor(Number(response.expectedRecoveryCodeCount)),
    activeRecoveryCodeCount: Math.floor(Number(response.activeRecoveryCodeCount)),
    pendingBackupRecoveryCodeCount: Math.floor(Number(response.pendingBackupRecoveryCodeCount)),
    consumedRecoveryCodeCount: Math.floor(Number(response.consumedRecoveryCodeCount)),
    revokedRecoveryCodeCount: Math.floor(Number(response.revokedRecoveryCodeCount)),
    abandonedRecoveryCodeCount: Math.floor(Number(response.abandonedRecoveryCodeCount)),
    totalRecoveryCodeCount: Math.floor(Number(response.totalRecoveryCodeCount)),
    issuedAtMs: parseNullableNumber(response.issuedAtMs),
    acknowledgedAtMs: parseNullableNumber(response.acknowledgedAtMs),
  };
}
