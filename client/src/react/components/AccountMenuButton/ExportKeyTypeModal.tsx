import React, { useEffect } from 'react';
import { useTheme } from '../theme';
import './ExportKeyTypeModal.css';

type ExportChain = 'near' | 'evm';

interface ExportKeyTypeModalProps {
  isOpen: boolean;
  loadingChain: ExportChain | null;
  onClose: () => void;
  onSelectChain: (chain: ExportChain) => void;
}

export const ExportKeyTypeModal: React.FC<ExportKeyTypeModalProps> = ({
  isOpen,
  loadingChain,
  onClose,
  onSelectChain,
}) => {
  const { theme } = useTheme();

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

  return (
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
        <div className="w3a-export-key-type-options">
          <button
            type="button"
            className="w3a-export-key-type-option"
            disabled={isBusy}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onSelectChain('near');
            }}
          >
            <span className="w3a-export-key-type-option-title">NEAR ed25519 threshold keys</span>
            <span className="w3a-export-key-type-option-description">
              Export the account signing key set for NEAR.
            </span>
            {loadingChain === 'near' && (
              <span className="w3a-export-key-type-option-status">Opening export drawer...</span>
            )}
          </button>
          <button
            type="button"
            className="w3a-export-key-type-option"
            disabled={isBusy}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onSelectChain('evm');
            }}
          >
            <span className="w3a-export-key-type-option-title">EVM ecdsa threshold keys</span>
            <span className="w3a-export-key-type-option-description">
              Export the account signing key set for EVM.
            </span>
            {loadingChain === 'evm' && (
              <span className="w3a-export-key-type-option-status">Opening export drawer...</span>
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
