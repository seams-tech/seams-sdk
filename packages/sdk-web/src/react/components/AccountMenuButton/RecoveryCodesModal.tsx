import React, { useEffect } from 'react';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import type { WalletRecoveryCodeStatusResult } from '@/SeamsWeb/publicApi/types';
import './RecoveryCodesModal.css';

interface RecoveryCodesModalProps {
  walletId: string;
  isOpen: boolean;
  onClose: () => void;
}

type RecoveryCodesLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'loaded'; status: WalletRecoveryCodeStatusResult }
  | { kind: 'error'; message: string };

function resetRecoveryCodesLoadState(state: RecoveryCodesLoadState): RecoveryCodesLoadState {
  return state.kind === 'idle' ? state : { kind: 'idle' };
}

function statusLabel(status: WalletRecoveryCodeStatusResult): string {
  switch (status.kind) {
    case 'ready':
      return status.backupOutstanding ? 'Backup confirmation needed' : 'Backed up';
    case 'no_recovery_set':
      return 'No recovery set';
    case 'unauthorized':
      return 'Authorization required';
    case 'transport_failed':
      return 'Could not load';
  }
}

export const RecoveryCodesModal: React.FC<RecoveryCodesModalProps> = ({
  walletId,
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

  const loadRecoveryCodeStatus = React.useCallback(async () => {
    const requestSeq = loadStatusSeq.current + 1;
    loadStatusSeq.current = requestSeq;
    setLoadState({ kind: 'loading' });
    try {
      const status = await seams.recovery.getWalletRecoveryCodeStatus({ walletId });
      if (loadStatusSeq.current === requestSeq) {
        setLoadState({ kind: 'loaded', status });
      }
    } catch (error: unknown) {
      if (loadStatusSeq.current === requestSeq) {
        setLoadState({
          kind: 'error',
          message: error instanceof Error ? error.message : 'Could not load recovery-code status',
        });
      }
    }
  }, [seams.recovery, walletId]);

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
      setLoadState(resetRecoveryCodesLoadState);
      return;
    }
    void loadRecoveryCodeStatus();
  }, [isOpen, loadRecoveryCodeStatus]);

  if (!isOpen) return null;
  const status = loadState.kind === 'loaded' ? loadState.status : null;

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
            onClick={onClose}
            aria-label="Close recovery codes"
          >
            ✕
          </button>
          <div className="w3a-recovery-codes-modal-header">
            <h2 id="w3a-recovery-codes-modal-title" className="w3a-recovery-codes-modal-title">
              Wallet recovery codes
            </h2>
          </div>
          <div className="w3a-recovery-codes-modal-body">
            <div className="w3a-recovery-codes-status-row">
              <span className="w3a-recovery-codes-status-label">Wallet</span>
              <span className="w3a-recovery-codes-status-value">{walletId}</span>
            </div>
            <div className="w3a-recovery-codes-status-row">
              <span className="w3a-recovery-codes-status-label">Status</span>
              <span className="w3a-recovery-codes-status-value">
                {status ? statusLabel(status) : loadState.kind === 'error' ? 'Could not load' : 'Loading'}
              </span>
            </div>
            {status?.kind === 'ready' ? (
              <>
                <div className="w3a-recovery-codes-status-row">
                  <span className="w3a-recovery-codes-status-label">Active codes</span>
                  <span className="w3a-recovery-codes-status-value">
                    {status.activeCodeCount} / {status.totalCodeCount}
                  </span>
                </div>
                {status.backupOutstanding ? (
                  <p className="w3a-recovery-codes-note">
                    Confirm the backup only while the recovery codes are visible during issuance.
                  </p>
                ) : null}
              </>
            ) : null}
            {loadState.kind === 'error' ? (
              <div className="w3a-recovery-codes-inline-error" role="alert">
                {loadState.message}
              </div>
            ) : null}
          </div>
        </div>
      </div>
    </Theme>
  );
};

export default RecoveryCodesModal;
