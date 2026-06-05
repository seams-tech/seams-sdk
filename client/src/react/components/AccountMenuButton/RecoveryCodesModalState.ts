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
  pendingBackup: PendingEmailOtpRecoveryCodeBackupRecord | null;
  actionError: string;
};

type RecoveryCodesModalRepository = Pick<
  typeof emailOtpPendingRecoveryCodeBackupRepository,
  'deleteExpired' | 'readMatching' | 'delete'
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
  await args.pendingBackupRepository.deleteExpired().catch(() => undefined);
  let status = await args.recovery.getEmailOtpRecoveryCodeStatus({
    walletId: args.walletId,
  });
  let pendingBackup: PendingEmailOtpRecoveryCodeBackupRecord | null = null;
  if (status.status === 'pending_backup') {
    try {
      pendingBackup = await args.pendingBackupRepository.readMatching({
        walletId: status.walletId,
        enrollmentId: status.enrollmentId,
        enrollmentSealKeyVersion: status.enrollmentSealKeyVersion,
      });
    } catch {
      pendingBackup = null;
    }
    if (!pendingBackup && args.showPendingBackup) {
      status = await args.showPendingBackup({ walletId: status.walletId });
      if (status.status === 'pending_backup') {
        pendingBackup = null;
      }
    }
  } else if (status.enrollmentId) {
    await args.pendingBackupRepository
      .delete({
        walletId: status.walletId,
        enrollmentId: status.enrollmentId,
      })
      .catch(() => undefined);
  }
  return { kind: 'loaded', status, pendingBackup, actionError: '' };
}
