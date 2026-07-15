import React, { useEffect } from 'react';
import { Theme, useTheme } from '../theme';
import './ExportKeyTypeModal.css';

type ExportChain = 'near' | 'evm';

interface ExportKeyTypeModalProps {
  isOpen: boolean;
  loadingChain: ExportChain | null;
  onClose: () => void;
  onSelectChain: (chain: ExportChain) => void;
  restrictionMessage?: string | null;
}

export const ExportKeyTypeModal: React.FC<ExportKeyTypeModalProps> = ({
  isOpen,
  loadingChain,
  onClose,
  onSelectChain,
  restrictionMessage,
}) => {
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );

  useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' || e.key === 'Esc') {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const isBusy = loadingChain !== null;
  const isRestricted = Boolean(restrictionMessage);

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`w3a-export-key-type-modal-backdrop theme-${theme}`}
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          onClose();
        }}
        onMouseDown={(e) => e.stopPropagation()}
        onMouseUp={(e) => e.stopPropagation()}
      >
        <div
          className="w3a-export-key-type-modal-content"
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onMouseDown={(e) => e.stopPropagation()}
          onMouseUp={(e) => e.stopPropagation()}
        >
          <div className="w3a-export-key-type-modal-header">
            <h2 className="w3a-export-key-type-modal-title">Export Keys</h2>
          </div>
          <button
            className="w3a-export-key-type-modal-close"
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onClose();
            }}
          >
            ✕
          </button>
          <p className="w3a-export-key-type-modal-subtitle">
            Choose which threshold key set to export.
          </p>
          {restrictionMessage && (
            <div className="w3a-export-key-type-restriction" role="status">
              {restrictionMessage}
            </div>
          )}
          <div className="w3a-export-key-type-options">
            <button
              type="button"
              className="w3a-export-key-type-option"
              disabled={isBusy || isRestricted}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onSelectChain('near');
              }}
            >
              <span className="w3a-export-key-type-option-title">NEAR Ed25519 key</span>
              <span className="w3a-export-key-type-option-description">
                Export the exact seed for the active NEAR signing key.
              </span>
            </button>
            <button
              type="button"
              className="w3a-export-key-type-option"
              disabled={isBusy || isRestricted}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                onSelectChain('evm');
              }}
            >
              <span className="w3a-export-key-type-option-title">EVM ECDSA threshold key</span>
              <span className="w3a-export-key-type-option-description">
                Export the account signing key set for EVM.
              </span>
            </button>
          </div>
        </div>
      </div>
    </Theme>
  );
};
