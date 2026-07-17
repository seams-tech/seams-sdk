import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type {
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  GoogleEmailOtpRegistrationBackedUpEnrollmentResult,
} from '@/SeamsWeb/signingSurface/types';
import {
  type EmailOtpRecoveryCodeBackupStorageScope,
  emailOtpRecoveryCodeBackupRepository,
} from '@/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';
import type { EmailOtpRecoveryCodeStatus } from './challenge';
import type { EmailOtpRecoveryCodeRotationMaterial } from '@/core/signingEngine/session/emailOtp/publicTypes';
import {
  postJson,
  readString,
  type FetchLike,
} from './challenge';

export type EmailOtpRecoveryCodeBackupUiInput = {
  walletId: string;
  enrollmentId: string;
  enrollmentSealKeyVersion: string;
  recoveryKeys: EmailOtpRecoveryCodeSet;
  recoveryCodesIssuedAtMs: number;
};

export type EmailOtpRecoveryCodeBackupUiOptions = {
  onDownloaded?: () => Promise<void> | void;
  onClosed?: () => void;
};

export type GoogleEmailOtpRegistrationBackupEnrollmentInput = Omit<
  EmailOtpEnrollmentResult,
  'challengeId'
> & {
  registrationAuthorityId: string;
  challengeId?: never;
};

type EmailOtpRecoveryCodeBackupEnrollmentInput =
  | EmailOtpEnrollmentResult
  | GoogleEmailOtpRegistrationBackupEnrollmentInput;

function stripEmailOtpRecoveryKeysAfterBackup(
  result: EmailOtpRecoveryCodeBackupEnrollmentInput,
): EmailOtpBackedUpEnrollmentResult | GoogleEmailOtpRegistrationBackedUpEnrollmentResult {
  const recoveryCodeBackup: EmailOtpRecoveryCodeBackupStatus = {
    status: 'active',
    walletId: '',
    enrollmentId: result.enrollmentId,
    recoveryCodeCount: result.recoveryKeys.length,
    issuedAtMs: result.recoveryCodesIssuedAtMs,
    storedAtMs: result.recoveryCodesIssuedAtMs,
    activeRecoveryCodeCountAtBackup: result.recoveryKeys.length,
  };

  if ('registrationAuthorityId' in result) {
    const { recoveryKeys: _recoveryKeys, ...metadata } = result;
    return {
      ...metadata,
      recoveryCodeBackup,
    };
  }

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

export function buildEmailOtpRecoveryCodeBackupFilename(walletId: string): string {
  return `seams-email-otp-recovery-codes-${filenameSafeWalletId(walletId)}.txt`;
}

export function buildEmailOtpRecoveryCodeBackupText(
  input: EmailOtpRecoveryCodeBackupUiInput,
): string {
  const created = new Date(input.recoveryCodesIssuedAtMs).toISOString();
  const lines = [
    'Seams Email OTP recovery codes',
    '',
    `Wallet: ${input.walletId}`,
    `Created: ${created}`,
    '',
    'Store these codes somewhere private. Each code can be used once.',
    '',
    ...input.recoveryKeys.map(
      (code, index) => `${String(index + 1).padStart(2, '0')}  ${code}`,
    ),
  ];
  return `${lines.join('\n')}\n`;
}

export function downloadRecoveryCodes(input: EmailOtpRecoveryCodeBackupUiInput): void {
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
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}

export function showEmailOtpRecoveryCodeBackupUi(
  input: EmailOtpRecoveryCodeBackupUiInput,
  options: EmailOtpRecoveryCodeBackupUiOptions = {},
): void {
  if (typeof document === 'undefined') {
    throw new Error('Email OTP recovery code backup UI requires document');
  }
  const overlay = document.createElement('div');
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  overlay.setAttribute('data-w3a-email-otp-recovery-code-dialog', '');
  /* the class enrolls this plain-DOM dialog in the app-palette override
     stylesheet (see W3A_LIT_HOST_SELECTORS), so tokens follow the theme */
  overlay.className = 'w3a-host-themed-dialog';
  overlay.style.cssText = [
    'position:fixed',
    'inset:0',
    'z-index:2147483647',
    'display:flex',
    'align-items:center',
    'justify-content:center',
    'background:oklch(0.2 0.01 240 / .6)',
    'backdrop-filter:blur(8px)',
    'font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
    'color:var(--w3a-colors-textPrimary, #565177)',
  ].join(';');

  const panel = document.createElement('section');
  panel.style.cssText = [
    'width:min(460px,calc(100vw - 24px))',
    'min-width:320px',
    'max-height:calc(100vh - 24px)',
    'overflow:auto',
    'box-sizing:border-box',
    'border:1px solid var(--w3a-colors-borderPrimary, rgba(86,81,119,.22))',
    'border-radius:min(var(--w3a-shape-card, 16px), 2rem)',
    'background:var(--w3a-colors-colorBackground, #fffaf3)',
    'padding:20px',
    'box-shadow:0 24px 80px rgba(0,0,0,.24)',
  ].join(';');

  const title = document.createElement('h1');
  title.textContent = 'Email OTP recovery codes';
  title.style.cssText =
    'margin:0 0 14px;font-size:21px;line-height:1.15;font-weight:600;color:var(--w3a-colors-textPrimary, #565177)';
  const close = document.createElement('button');
  close.type = 'button';
  close.textContent = '×';
  close.setAttribute('aria-label', 'Close recovery codes');
  close.setAttribute('data-w3a-email-otp-recovery-code-dialog-close', '');
  close.style.cssText =
    'position:absolute;right:16px;top:12px;border:0;background:transparent;color:var(--w3a-colors-textMuted, #565177);font-size:28px;line-height:1;cursor:pointer';
  panel.style.position = 'relative';
  panel.appendChild(close);
  panel.appendChild(title);

  const list = document.createElement('ol');
  list.style.cssText = [
    'display:grid',
    'grid-template-columns:1fr',
    'gap:8px',
    'margin:0 0 14px',
    'padding:0',
    'list-style:none',
  ].join(';');
  for (const [index, code] of input.recoveryKeys.entries()) {
    const item = document.createElement('li');
    item.style.cssText = [
      'box-sizing:border-box',
      'display:flex',
      'gap:10px',
      'align-items:flex-start',
      'border:1px solid var(--w3a-colors-borderPrimary, rgba(86,81,119,.16))',
      'border-radius:var(--w3a-shape-box, 10px)',
      'background:var(--w3a-colors-surface2, #f4eadf)',
      'padding:9px 10px',
      'font-family:ui-monospace,SFMono-Regular,Menlo,monospace',
      'font-size:13px',
      'font-weight:700',
      'line-height:1.25',
      'letter-spacing:0',
      'overflow-wrap:anywhere',
    ].join(';');
    const number = document.createElement('span');
    number.textContent = `${index + 1}.`;
    number.style.cssText = 'flex:0 0 2.3ch;color:var(--w3a-colors-textSecondary, #565177)';
    const value = document.createElement('span');
    value.textContent = code;
    value.style.cssText = 'min-width:0;color:var(--w3a-colors-textPrimary, #565177)';
    item.appendChild(number);
    item.appendChild(value);
    list.appendChild(item);
  }
  panel.appendChild(list);

  const actions = document.createElement('div');
  actions.style.cssText = 'display:grid;margin:0 0 12px';
  const download = document.createElement('button');
  download.type = 'button';
  download.textContent = 'Download';
  download.style.cssText =
    'min-height:42px;border:1px solid transparent;border-radius:var(--w3a-shape-control, 10px);background:var(--w3a-colors-buttonBackground, #565177);color:var(--w3a-colors-textButton, #fffaf3);padding:9px 12px;font-size:15px;font-weight:600;cursor:pointer';
  actions.appendChild(download);
  panel.appendChild(actions);

  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.style.cssText =
    'min-height:18px;margin:0;font-size:13px;color:var(--w3a-colors-textSecondary, #565177)';
  panel.appendChild(status);

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  close.addEventListener('click', () => {
    overlay.remove();
    options.onClosed?.();
  });

  download.focus();

  download.addEventListener('click', async () => {
    try {
      downloadRecoveryCodes(input);
    } catch {
      status.textContent = 'Download failed. Try again.';
      return;
    }
    try {
      await options.onDownloaded?.();
    } catch {
      status.textContent = 'Recovery codes downloaded. Last download status was not updated.';
      return;
    }
    status.textContent = 'Recovery codes downloaded.';
  });
}

export async function backupEmailOtpRecoveryCodes(input: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  enrollment: EmailOtpEnrollmentResult;
  storageScope?: EmailOtpRecoveryCodeBackupStorageScope;
}): Promise<EmailOtpBackedUpEnrollmentResult>;
export async function backupEmailOtpRecoveryCodes(input: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  enrollment: GoogleEmailOtpRegistrationBackupEnrollmentInput;
  storageScope?: EmailOtpRecoveryCodeBackupStorageScope;
}): Promise<GoogleEmailOtpRegistrationBackedUpEnrollmentResult>;
export async function backupEmailOtpRecoveryCodes(input: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  enrollment: EmailOtpRecoveryCodeBackupEnrollmentInput;
  storageScope?: EmailOtpRecoveryCodeBackupStorageScope;
}): Promise<EmailOtpBackedUpEnrollmentResult | GoogleEmailOtpRegistrationBackedUpEnrollmentResult> {
  const storageScope = input.storageScope || 'host_origin_indexeddb';
  await emailOtpRecoveryCodeBackupRepository.write({
    storageScope,
    walletId: input.walletId,
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    recoveryCodesIssuedAtMs: input.enrollment.recoveryCodesIssuedAtMs,
    recoveryKeys: input.enrollment.recoveryKeys,
  });
  const stored = await emailOtpRecoveryCodeBackupRepository.readMatching({
    walletId: input.walletId,
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
  });
  if (!stored) {
    throw new Error('Email OTP recovery-code backup was not persisted');
  }
  const result = stripEmailOtpRecoveryKeysAfterBackup(input.enrollment);
  return {
    ...result,
    recoveryCodeBackup: {
      ...result.recoveryCodeBackup,
      walletId: input.walletId,
      storedAtMs: stored.createdAtMs,
    },
  };
}

export async function storeRotatedEmailOtpRecoveryCodes(input: {
  walletId: string;
  rotation: EmailOtpRecoveryCodeRotationMaterial;
  storageScope?: EmailOtpRecoveryCodeBackupStorageScope;
}): Promise<EmailOtpRecoveryCodeBackupStatus> {
  const storageScope = input.storageScope || 'host_origin_indexeddb';
  const stored = await emailOtpRecoveryCodeBackupRepository.write({
    storageScope,
    walletId: input.walletId,
    enrollmentId: input.rotation.enrollmentId,
    enrollmentSealKeyVersion: input.rotation.enrollmentSealKeyVersion,
    recoveryCodesIssuedAtMs: input.rotation.recoveryCodesIssuedAtMs,
    recoveryKeys: input.rotation.recoveryKeys,
  });
  return {
    status: 'active',
    walletId: input.walletId,
    enrollmentId: input.rotation.enrollmentId,
    recoveryCodeCount: input.rotation.recoveryKeys.length,
    issuedAtMs: input.rotation.recoveryCodesIssuedAtMs,
    storedAtMs: stored.createdAtMs,
    activeRecoveryCodeCountAtBackup: input.rotation.activeRecoveryCodeCount,
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
    consumedRecoveryCodeCount: Math.floor(Number(response.consumedRecoveryCodeCount)),
    revokedRecoveryCodeCount: Math.floor(Number(response.revokedRecoveryCodeCount)),
    totalRecoveryCodeCount: Math.floor(Number(response.totalRecoveryCodeCount)),
    issuedAtMs: parseNullableNumber(response.issuedAtMs),
  };
}
