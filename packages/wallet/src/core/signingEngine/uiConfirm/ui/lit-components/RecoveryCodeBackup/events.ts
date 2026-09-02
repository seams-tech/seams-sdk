// Event contract between the RecoveryCodeBackup lit components and their
// mount (showWalletRecoveryCodeBackupUi). Deliberately free of lit imports so
// the mount can reference the names without pulling the component bundle into
// its static import graph.

/** Bubbles from the viewer when the single close control is activated. */
export const RECOVERY_BACKUP_CLOSE_EVENT = 'w3a-recovery-backup-close';

/** Bubbles whenever the one recovery dialog advances to a new visual stage. */
export const RECOVERY_BACKUP_STAGE_EVENT = 'w3a-recovery-backup-stage';

/** Dispatched from the host when Escape cancels the native dialog. */
export const RECOVERY_BACKUP_CANCEL_EVENT = 'w3a-recovery-backup-cancel';

export type RecoveryBackupCloseDetail =
  | { readonly kind: 'dismissed' }
  | { readonly kind: 'recovery_codes'; readonly acknowledged: boolean };

export type RecoveryBackupStage = 'summary' | 'opening' | 'recovery_codes';

export type RecoveryBackupStageDetail = {
  readonly stage: RecoveryBackupStage;
};

export type RecoveryBackupSurface = 'standalone' | 'wallet-iframe';
