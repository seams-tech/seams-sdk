import type {
  EmailOtpRecoveryCodeStatus,
  RecoveryCapability,
} from '@/SeamsWeb/signingSurface/types';
import type {
  emailOtpPendingRecoveryCodeBackupRepository,
  PendingEmailOtpRecoveryCodeBackupRecord,
} from '@/core/indexedDB/seamsWalletDB/emailOtpPendingRecoveryCodeBackups';

export type RecoveryCodesLoadedState = {
  kind: 'loaded';
  status: EmailOtpRecoveryCodeStatus;
  localBackup: PendingEmailOtpRecoveryCodeBackupRecord | null;
  actionError: string;
};

type RecoveryCodesModalRepository = Pick<
  typeof emailOtpPendingRecoveryCodeBackupRepository,
  'deleteInvalid' | 'readMatching'
>;

type ShowEmailOtpPendingBackupForAccountMenu = (args: {
  walletId: string;
}) => Promise<EmailOtpRecoveryCodeStatus>;

type EmailOtpPendingBackupPresenter = {
  showEmailOtpPendingRecoveryCodeBackupForAccountMenu?: ShowEmailOtpPendingBackupForAccountMenu;
};

export function getEmailOtpPendingBackupPresenter(
  seams: unknown,
): ShowEmailOtpPendingBackupForAccountMenu | null {
  const method =
    seams && typeof seams === 'object'
      ? Reflect.get(seams, 'showEmailOtpPendingRecoveryCodeBackupForAccountMenu')
      : null;
  if (typeof method !== 'function') return null;
  return method.bind(seams) as ShowEmailOtpPendingBackupForAccountMenu;
}

export async function loadRecoveryCodesModalLoadedState(args: {
  walletId: string;
  recovery: Pick<RecoveryCapability, 'getEmailOtpRecoveryCodeStatus'>;
  pendingBackupRepository: RecoveryCodesModalRepository;
  showPendingBackup: ShowEmailOtpPendingBackupForAccountMenu | null;
}): Promise<RecoveryCodesLoadedState> {
  await args.pendingBackupRepository.deleteInvalid().catch(() => undefined);
  let status = await args.recovery.getEmailOtpRecoveryCodeStatus({
    walletId: args.walletId,
  });
  let localBackup: PendingEmailOtpRecoveryCodeBackupRecord | null = null;
  if (status.enrollmentId && status.enrollmentSealKeyVersion) {
    try {
      localBackup = await args.pendingBackupRepository.readMatching({
        walletId: status.walletId,
        enrollmentId: status.enrollmentId,
        enrollmentSealKeyVersion: status.enrollmentSealKeyVersion,
      });
    } catch {
      localBackup = null;
    }
    if (!localBackup && status.status === 'pending_backup' && args.showPendingBackup) {
      status = await args.showPendingBackup({ walletId: status.walletId });
      if (status.status === 'pending_backup') {
        localBackup = null;
      }
    }
  }
  return { kind: 'loaded', status, localBackup, actionError: '' };
}
