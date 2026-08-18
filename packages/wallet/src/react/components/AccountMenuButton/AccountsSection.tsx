import React from 'react';
import type { AccountsSectionRow } from './types';
import './AccountsSection.css';

function shortenAddress(address: string): string {
  const value = address.trim();
  if (value.length <= 18) return value;
  return `${value.slice(0, 8)}...${value.slice(-6)}`;
}

export interface AccountsSectionProps {
  rows: AccountsSectionRow[];
  isOpen?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

/** Expandable panel under the Accounts menu item: one row per configured
 * chain, each linking to the user's account page on that chain's explorer. */
export const AccountsSection: React.FC<AccountsSectionProps> = ({
  rows,
  isOpen = true,
  className,
  style,
}) => {
  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
  };

  return (
    <div
      className={`w3a-dropdown-accounts-root ${isOpen ? 'is-expanded' : ''} ${className || ''}`}
      style={style}
      onClick={handleClick}
    >
      <div className="w3a-dropdown-accounts-clip">
        <div
          className="w3a-dropdown-accounts-content"
          aria-hidden={!isOpen}
          style={{ pointerEvents: isOpen ? 'auto' : 'none' }}
        >
          {rows.map((row) => (
            <a
              key={row.id}
              className="w3a-accounts-row"
              href={row.href}
              target="_blank"
              rel="noopener noreferrer"
              tabIndex={isOpen ? 0 : -1}
              title={row.address}
            >
              <span className="w3a-accounts-row-chain">{row.label}</span>
              <span className="w3a-accounts-row-address">{shortenAddress(row.address)}</span>
              <svg
                className="w3a-accounts-row-arrow"
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
                focusable="false"
              >
                <path d="M7 7h10v10" />
                <path d="M7 17 17 7" />
              </svg>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
};
