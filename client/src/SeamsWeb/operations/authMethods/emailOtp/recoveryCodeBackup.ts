import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { EmailOtpRecoveryCodeSet } from '@shared/utils/emailOtpRecoveryKey';
import type {
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
} from '@/SeamsWeb/signingSurface/types';
import {
  emailOtpPendingRecoveryCodeBackupRepository,
  type PendingEmailOtpRecoveryCodeBackupRecord,
  type EmailOtpPendingRecoveryCodeBackupStorageScope,
} from '@/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups';
import type { EmailOtpRecoveryCodeStatus } from './challenge';
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
    URL.revokeObjectURL(url);
  }
}

function showEmailOtpRecoveryCodeBackupUi(
  input: EmailOtpRecoveryCodeBackupUiInput,
  onDownloadComplete: () => Promise<void>,
): Promise<void> {
  if (typeof document === 'undefined') {
    return Promise.reject(new Error('Email OTP recovery code backup UI requires document'));
  }
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
    'background:oklch(0.2 0.01 240 / .6)',
    'backdrop-filter:blur(8px)',
    'font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif',
    'color:#565177',
  ].join(';');

  const panel = document.createElement('section');
  panel.style.cssText = [
    'width:min(460px,calc(100vw - 24px))',
    'min-width:320px',
    'max-height:calc(100vh - 24px)',
    'overflow:auto',
    'box-sizing:border-box',
    'border:1px solid rgba(86,81,119,.22)',
    'border-radius:24px',
    'background:#fffaf3',
    'padding:20px',
    'box-shadow:0 24px 80px rgba(0,0,0,.24)',
  ].join(';');

  const title = document.createElement('h1');
  title.textContent = 'Email OTP recovery codes';
  title.style.cssText =
    'margin:0 0 14px;font-size:24px;line-height:1.15;font-weight:700;color:#565177';
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
      'border:1px solid rgba(86,81,119,.16)',
      'border-radius:12px',
      'background:#f4eadf',
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
    number.style.cssText = 'flex:0 0 2.3ch;color:#565177';
    const value = document.createElement('span');
    value.textContent = code;
    value.style.cssText = 'min-width:0;color:#565177';
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
    'min-height:40px;border:1px solid rgba(86,81,119,.24);border-radius:12px;background:#565177;color:#fffaf3;padding:9px 12px;font-size:15px;font-weight:700;cursor:pointer';
  actions.appendChild(download);
  panel.appendChild(actions);

  const status = document.createElement('p');
  status.setAttribute('role', 'status');
  status.style.cssText = 'min-height:18px;margin:0;font-size:13px;color:#565177';
  panel.appendChild(status);

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  download.focus();

  return new Promise((resolve) => {
    download.addEventListener(
      'click',
      () => {
        try {
          downloadRecoveryCodes(input);
        } catch {
          status.textContent = 'Download failed. Try again.';
          return;
        }
        status.textContent = 'Confirming backup...';
        download.disabled = true;
        void onDownloadComplete()
          .then(() => {
            overlay.remove();
            resolve();
          })
          .catch((error: unknown) => {
            download.disabled = false;
            status.textContent =
              error instanceof Error ? error.message : 'Could not confirm backup. Try again.';
          });
      },
    );
  });
}

export async function completePendingEmailOtpRecoveryCodeBackup(input: {
  pendingBackup: PendingEmailOtpRecoveryCodeBackupRecord;
  acknowledge: (args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
  }) => Promise<EmailOtpRecoveryCodeBackupStatus>;
}): Promise<EmailOtpRecoveryCodeBackupStatus> {
  let backup: EmailOtpRecoveryCodeBackupStatus | null = null;
  await showEmailOtpRecoveryCodeBackupUi(
    {
      walletId: input.pendingBackup.walletId,
      enrollmentId: input.pendingBackup.enrollmentId,
      enrollmentSealKeyVersion: input.pendingBackup.enrollmentSealKeyVersion,
      recoveryCodesIssuedAtMs: input.pendingBackup.recoveryCodesIssuedAtMs,
      recoveryKeys: input.pendingBackup.recoveryKeys,
    },
    async () => {
      backup = await input.acknowledge({
        walletId: input.pendingBackup.walletId,
        enrollmentId: input.pendingBackup.enrollmentId,
        enrollmentSealKeyVersion: input.pendingBackup.enrollmentSealKeyVersion,
      });
      await emailOtpPendingRecoveryCodeBackupRepository
        .delete({
          walletId: input.pendingBackup.walletId,
          enrollmentId: input.pendingBackup.enrollmentId,
        })
        .catch(() => undefined);
    },
  );
  if (!backup) {
    throw new Error('Email OTP recovery-code backup did not complete');
  }
  return backup;
}

export async function backupEmailOtpRecoveryCodes(input: {
  relayUrl: string;
  walletId: string;
  appSessionJwt?: string;
  enrollment: EmailOtpEnrollmentResult;
  storageScope?: EmailOtpPendingRecoveryCodeBackupStorageScope;
  acknowledge?: (args: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }) => Promise<EmailOtpRecoveryCodeBackupStatus>;
}): Promise<EmailOtpBackedUpEnrollmentResult> {
  const storageScope = input.storageScope || 'host_origin_indexeddb';
  await emailOtpPendingRecoveryCodeBackupRepository.write({
    storageScope,
    walletId: input.walletId,
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
    recoveryCodesIssuedAtMs: input.enrollment.recoveryCodesIssuedAtMs,
    recoveryKeys: input.enrollment.recoveryKeys,
  });
  const record = await emailOtpPendingRecoveryCodeBackupRepository.readMatching({
    walletId: input.walletId,
    enrollmentId: input.enrollment.enrollmentId,
    enrollmentSealKeyVersion: input.enrollment.enrollmentSealKeyVersion,
  });
  if (!record) {
    throw new Error('Email OTP recovery-code backup was not persisted');
  }
  const backup = await completePendingEmailOtpRecoveryCodeBackup({
    pendingBackup: record,
    acknowledge: async (args) => {
      const acknowledge = input.acknowledge || acknowledgeEmailOtpRecoveryCodeBackup;
      return await acknowledge({
        relayUrl: input.relayUrl,
        walletId: args.walletId,
        enrollmentId: args.enrollmentId,
        enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
        ...(input.appSessionJwt ? { appSessionJwt: input.appSessionJwt } : {}),
      });
    },
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
