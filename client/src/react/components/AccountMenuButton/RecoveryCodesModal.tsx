import React, { useEffect } from 'react';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import type { EmailOtpRecoveryCodeStatus } from '@/SeamsWeb/signingSurface/types';
import {
  downloadRecoveryCodes,
  type EmailOtpRecoveryCodeBackupUiInput,
} from '@/SeamsWeb/operations/authMethods/emailOtp/recoveryCodeBackup';
import {
  emailOtpRecoveryCodeBackupRepository,
  type StoredEmailOtpRecoveryCodeBackupRecord,
} from '@/core/indexedDB/seamsWalletDB/emailOtpRecoveryCodeBackups';
import {
  getEmailOtpRecoveryCodePresenter,
  loadRecoveryCodesModalLoadedState,
  type RecoveryCodesLoadedState,
} from './RecoveryCodesModalState';
import './RecoveryCodesModal.css';

interface RecoveryCodesModalProps {
  nearAccountId: string;
  isOpen: boolean;
  onClose: () => void;
}

type RecoveryCodesLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | RecoveryCodesLoadedState
  | { kind: 'error'; message: string };

function statusLabel(status: EmailOtpRecoveryCodeStatus['status']): string {
  switch (status) {
    case 'ready':
      return 'Backed up';
    case 'incomplete':
      return 'Rotation needed';
    case 'not_enrolled':
      return 'No Email OTP enrollment';
  }
}

function formatTimestamp(value: number | null): string {
  if (value === null) return 'None';
  return new Date(value).toLocaleString();
}

function recoveryCodeBackupUiInput(
  backup: StoredEmailOtpRecoveryCodeBackupRecord,
): EmailOtpRecoveryCodeBackupUiInput {
  return {
    walletId: backup.walletId,
    enrollmentId: backup.enrollmentId,
    enrollmentSealKeyVersion: backup.enrollmentSealKeyVersion,
    recoveryCodesIssuedAtMs: backup.recoveryCodesIssuedAtMs,
    recoveryKeys: backup.recoveryKeys,
  };
}

export const RecoveryCodesModal: React.FC<RecoveryCodesModalProps> = ({
  nearAccountId,
  isOpen,
  onClose,
}) => {
  const { seams } = useSeams();
  const [loadState, setLoadState] = React.useState<RecoveryCodesLoadState>({ kind: 'idle' });
  const loadStatusSeq = React.useRef(0);
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );

  const loadRecoveryCodeStatus = React.useCallback(
    async () => {
      const requestSeq = loadStatusSeq.current + 1;
      loadStatusSeq.current = requestSeq;
      setLoadState({ kind: 'loading' });
      try {
        const loaded = await loadRecoveryCodesModalLoadedState({
          walletId: nearAccountId,
          recovery: seams.recovery,
          recoveryCodeBackupRepository: emailOtpRecoveryCodeBackupRepository,
          showRecoveryCodes: getEmailOtpRecoveryCodePresenter(seams),
        });
        if (loadStatusSeq.current !== requestSeq) return;
        setLoadState(loaded);
      } catch (error: unknown) {
        if (loadStatusSeq.current !== requestSeq) return;
        setLoadState({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load recovery-code status',
        });
      }
    },
    [nearAccountId, seams],
  );

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' || event.key === 'Esc') {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  useEffect(() => {
    if (!isOpen) {
      loadStatusSeq.current += 1;
      setLoadState({ kind: 'idle' });
      return;
    }
    void loadRecoveryCodeStatus();
  }, [isOpen, loadRecoveryCodeStatus]);

  const downloadRecoveryCodeBackup = React.useCallback(async () => {
    const current = loadState;
    if (current.kind !== 'loaded' || !current.localBackup) return;
    const { localBackup } = current;
    try {
      downloadRecoveryCodes(recoveryCodeBackupUiInput(localBackup));
    } catch {
      setLoadState({ ...current, actionError: 'Download failed. Try again.' });
      return;
    }
    try {
      const updated = await emailOtpRecoveryCodeBackupRepository.markDownloaded({
        walletId: localBackup.walletId,
        enrollmentId: localBackup.enrollmentId,
        enrollmentSealKeyVersion: localBackup.enrollmentSealKeyVersion,
      });
      setLoadState({
        ...current,
        localBackup: updated || localBackup,
        actionError: '',
      });
    } catch {
      setLoadState({
        ...current,
        actionError: '',
      });
    }
  }, [loadState]);

  if (!isOpen) return null;

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`w3a-recovery-codes-modal-backdrop theme-${theme}`}
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose();
        }}
      >
        <div
          className="w3a-recovery-codes-modal-content"
          role="dialog"
          aria-modal="true"
          aria-labelledby="w3a-recovery-codes-modal-title"
        >
          <button
            type="button"
            className="w3a-recovery-codes-modal-close"
            onClick={(event) => {
              event.preventDefault();
              event.stopPropagation();
              onClose();
            }}
            aria-label="Close recovery codes"
          >
            ✕
          </button>
          <div className="w3a-recovery-codes-modal-header">
            <h2 id="w3a-recovery-codes-modal-title" className="w3a-recovery-codes-modal-title">
              Email OTP recovery codes
            </h2>
          </div>
          <div className="w3a-recovery-codes-modal-body">
            <div className="w3a-recovery-codes-status-row">
              <span className="w3a-recovery-codes-status-label">Account</span>
              <span className="w3a-recovery-codes-status-value">{nearAccountId}</span>
            </div>
            <div className="w3a-recovery-codes-status-row">
              <span className="w3a-recovery-codes-status-label">Status</span>
              <span className="w3a-recovery-codes-status-value">
                {loadState.kind === 'loaded'
                  ? statusLabel(loadState.status.status)
                  : loadState.kind === 'error'
                    ? 'Could not load'
                    : 'Loading'}
              </span>
            </div>
            {loadState.kind === 'loaded' ? (
              <>
                {loadState.localBackup ? (
                  <>
                    <p className="w3a-recovery-codes-note">
                      Each code can be used once. Store them somewhere private.
                    </p>
                    <ol className="w3a-recovery-codes-list">
                      {loadState.localBackup.recoveryKeys.map((code, index) => (
                        <li className="w3a-recovery-codes-list-item" key={code}>
                          <span className="w3a-recovery-codes-list-index">{index + 1}.</span>
                          <span className="w3a-recovery-codes-list-code">{code}</span>
                        </li>
                      ))}
                    </ol>
                    <button
                      type="button"
                      className="w3a-recovery-codes-primary-action"
                      onClick={() => void downloadRecoveryCodeBackup()}
                    >
                      Download
                    </button>
                    {loadState.actionError ? (
                      <div className="w3a-recovery-codes-inline-error" role="alert">
                        {loadState.actionError}
                      </div>
                    ) : null}
                  </>
                ) : loadState.status.status !== 'not_enrolled' ? (
                  <div className="w3a-recovery-codes-status-row">
                    <span className="w3a-recovery-codes-status-label">Backup</span>
                    <span className="w3a-recovery-codes-status-value">
                      Recovery codes are unavailable on this device.
                    </span>
                  </div>
                ) : null}
                <div className="w3a-recovery-codes-status-row">
                  <span className="w3a-recovery-codes-status-label">Active codes</span>
                  <span className="w3a-recovery-codes-status-value">
                    {loadState.status.activeRecoveryCodeCount} /{' '}
                    {loadState.status.expectedRecoveryCodeCount}
                  </span>
                </div>
                <div className="w3a-recovery-codes-status-row">
                  <span className="w3a-recovery-codes-status-label">Last download</span>
                  <span className="w3a-recovery-codes-status-value">
                    {formatTimestamp(loadState.localBackup?.lastDownloadedAtMs ?? null)}
                  </span>
                </div>
              </>
            ) : null}
            {loadState.kind === 'error' ? (
              <div className="w3a-recovery-codes-status-row">
                <span className="w3a-recovery-codes-status-label">Error</span>
                <span className="w3a-recovery-codes-status-value">{loadState.message}</span>
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </Theme>
  );
};

export default RecoveryCodesModal;
