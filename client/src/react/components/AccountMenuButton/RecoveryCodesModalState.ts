import type {
  EmailOtpRecoveryCodeStatus,
  RecoveryCapability,
} from '@/SeamsWeb/signingSurface/types';
import type {
  emailOtpRecoveryCodeBackupRepository,
  StoredEmailOtpRecoveryCodeBackupRecord,
} from '@/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';

export type RecoveryCodesLoadedState = {
  kind: 'loaded';
  status: EmailOtpRecoveryCodeStatus;
  localBackup: StoredEmailOtpRecoveryCodeBackupRecord | null;
  actionError: string;
};

type RecoveryCodesModalRepository = Pick<
  typeof emailOtpRecoveryCodeBackupRepository,
  'deleteInvalid' | 'markDisplayed' | 'readMatching'
>;

type ShowEmailOtpRecoveryCodesForAccountMenu = (args: {
  walletId: string;
}) => Promise<EmailOtpRecoveryCodeStatus>;

export function getEmailOtpRecoveryCodePresenter(
  seams: unknown,
): ShowEmailOtpRecoveryCodesForAccountMenu | null {
  const method =
    seams && typeof seams === 'object'
      ? Reflect.get(seams, 'showEmailOtpRecoveryCodesForAccountMenu')
      : null;
  if (typeof method !== 'function') return null;
  return method.bind(seams) as ShowEmailOtpRecoveryCodesForAccountMenu;
}

export async function loadRecoveryCodesModalLoadedState(args: {
  walletId: string;
  recovery: Pick<RecoveryCapability, 'getEmailOtpRecoveryCodeStatus'>;
  recoveryCodeBackupRepository: RecoveryCodesModalRepository;
  showRecoveryCodes: ShowEmailOtpRecoveryCodesForAccountMenu | null;
}): Promise<RecoveryCodesLoadedState> {
  await args.recoveryCodeBackupRepository.deleteInvalid().catch(() => undefined);
  let status = await args.recovery.getEmailOtpRecoveryCodeStatus({
    walletId: args.walletId,
  });
  let localBackup: StoredEmailOtpRecoveryCodeBackupRecord | null = null;
  if (status.enrollmentId && status.enrollmentSealKeyVersion) {
    try {
      localBackup = await args.recoveryCodeBackupRepository.readMatching({
        walletId: status.walletId,
        enrollmentId: status.enrollmentId,
        enrollmentSealKeyVersion: status.enrollmentSealKeyVersion,
      });
    } catch {
      localBackup = null;
    }
    if (localBackup) {
      localBackup =
        (await args.recoveryCodeBackupRepository
          .markDisplayed({
            walletId: localBackup.walletId,
            enrollmentId: localBackup.enrollmentId,
            enrollmentSealKeyVersion: localBackup.enrollmentSealKeyVersion,
          })
          .catch(() => null)) || localBackup;
    } else if (args.showRecoveryCodes) {
      status = await args.showRecoveryCodes({ walletId: status.walletId });
    }
  }
  return { kind: 'loaded', status, localBackup, actionError: '' };
}
