// Event contract between the RecoveryCodeBackup lit components and their
// mount (showWalletRecoveryCodeBackupUi). Deliberately free of lit imports so
// the mount can reference the names without pulling the component bundle into
// its static import graph.

/** Bubbles from the viewer when the single close control is activated. */
export const RECOVERY_BACKUP_CLOSE_EVENT = 'w3a-recovery-backup-close';

/** Dispatched from the host when Escape cancels the native dialog. */
export const RECOVERY_BACKUP_CANCEL_EVENT = 'w3a-recovery-backup-cancel';

export type RecoveryBackupCloseDetail = {
  readonly acknowledged: boolean;
};

export type RecoveryBackupSurface = 'standalone' | 'wallet-iframe';
