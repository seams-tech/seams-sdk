import React, { useEffect } from 'react';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import type { EmailOtpRecoveryCodeStatus } from '@/web/SeamsWeb/signingSurface/types';
import './RecoveryCodesModal.css';

interface RecoveryCodesModalProps {
  nearAccountId: string;
  isOpen: boolean;
  onClose: () => void;
}

type RecoveryCodesLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'loaded'; status: EmailOtpRecoveryCodeStatus }
  | { kind: 'error'; message: string };

function statusLabel(status: EmailOtpRecoveryCodeStatus['status']): string {
  switch (status) {
    case 'ready':
      return 'Backed up';
    case 'pending_backup':
      return 'Backup pending';
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
        const status = await seams.recovery.getEmailOtpRecoveryCodeStatus({
          walletId: nearAccountId,
        });
        if (loadStatusSeq.current !== requestSeq) return;
        setLoadState({ kind: 'loaded', status });
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
                <div className="w3a-recovery-codes-status-row">
                  <span className="w3a-recovery-codes-status-label">Active codes</span>
                  <span className="w3a-recovery-codes-status-value">
                    {loadState.status.activeRecoveryCodeCount} /{' '}
                    {loadState.status.expectedRecoveryCodeCount}
                  </span>
                </div>
                <div className="w3a-recovery-codes-status-row">
                  <span className="w3a-recovery-codes-status-label">Last backup</span>
                  <span className="w3a-recovery-codes-status-value">
                    {formatTimestamp(loadState.status.acknowledgedAtMs)}
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
