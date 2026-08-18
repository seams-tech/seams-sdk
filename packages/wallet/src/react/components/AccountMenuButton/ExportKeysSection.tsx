import React from 'react';
import { SpinnerIcon } from './icons/SpinnerIcon';
import type { ExportChain } from './types';
import './ExportKeysSection.css';

export interface ExportKeysSectionProps {
  isOpen?: boolean;
  loadingChain: ExportChain | null;
  onSelectChain: (chain: ExportChain) => void;
  className?: string;
  style?: React.CSSProperties;
}

const EXPORT_ROWS: Array<{ chain: ExportChain; label: string; description: string }> = [
  { chain: 'near', label: 'Export NEAR Key', description: 'Ed25519 signing key' },
  { chain: 'evm', label: 'Export EVM Keys', description: 'ECDSA threshold key set' },
];

/** Expandable panel under the Export Keys menu item: one row per exportable
 * key set, launching the export flow inline instead of via a modal. */
export const ExportKeysSection: React.FC<ExportKeysSectionProps> = ({
  isOpen = false,
  loadingChain,
  onSelectChain,
  className,
  style,
}) => {
  const isBusy = loadingChain !== null;

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  return (
    <div
      className={`w3a-dropdown-export-keys-root ${isOpen ? 'is-expanded' : ''} ${className || ''}`}
      style={style}
      onClick={handleClick}
    >
      <div className="w3a-dropdown-export-keys-clip">
        <div
          className="w3a-dropdown-export-keys-content"
          aria-hidden={!isOpen}
          style={{ pointerEvents: isOpen ? 'auto' : 'none' }}
        >
          {EXPORT_ROWS.map((row) => (
            <button
              key={row.chain}
              type="button"
              className="w3a-export-keys-row"
              disabled={isBusy}
              tabIndex={isOpen ? 0 : -1}
              onClick={(e) => {
                e.stopPropagation();
                onSelectChain(row.chain);
              }}
            >
              <span className="w3a-export-keys-row-label">{row.label}</span>
              <span className="w3a-export-keys-row-description">{row.description}</span>
              {/* always-reserved slot: the spinner appearing must not resize
                  the row (and with it the menu) */}
              <span className="w3a-export-keys-row-spinner" aria-hidden>
                {loadingChain === row.chain ? <SpinnerIcon /> : null}
              </span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};
