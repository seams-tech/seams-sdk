import React from 'react';
import TouchIcon from './icons/TouchIcon';
import type { UserAccountButtonProps } from './types';

function shortenAccountId(accountId: string): string {
  const value = accountId.trim();
  if (value.length <= 18) return value;
  return `${value.slice(0, 10)}...${value.slice(-6)}`;
}

export const UserAccountButton: React.FC<UserAccountButtonProps> = ({
  username,
  hideUsername,
  fullAccountId,
  isOpen,
  onClick,
  onMouseEnter,
  onMouseLeave,
  theme = 'dark',
  menuId,
  triggerId,
}) => {
  const onKeyDown: React.KeyboardEventHandler<HTMLDivElement> = (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onClick();
    }
  };
  const hideWhenClosed = hideUsername && !isOpen;
  return (
    <div className={`w3a-user-account-button-root ${theme}`}>
      <div
        id={triggerId}
        className={`w3a-user-account-button-trigger ${hideWhenClosed ? 'hide-username' : ''} ${isOpen ? 'open' : 'closed'}`}
        onClick={onClick}
        role="button"
        tabIndex={0}
        aria-haspopup="menu"
        aria-expanded={isOpen}
        {...(menuId ? ({ 'aria-controls': menuId } as any) : {})}
        onKeyDown={onKeyDown}
        {...(onMouseEnter && { onMouseEnter })}
        {...(onMouseLeave && { onMouseLeave })}
      >
        <div className="w3a-user-account--user-content">
          <div
            className={`w3a-user-account--avatar ${hideWhenClosed ? 'hide-username' : ''} ${isOpen ? 'expanded' : 'shrunk'}`}
          >
            <TouchIcon
              className={`w3a-fingerprint-icon ${isOpen ? 'open' : 'closed'}`}
              strokeWidth={1.4}
            />
          </div>
          {!hideWhenClosed && (
            <UserAccountId
              username={username}
              fullAccountId={fullAccountId}
              isOpen={isOpen}
              theme={theme}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export const UserAccountId = ({
  username,
  fullAccountId,
  isOpen,
  theme = 'dark',
}: {
  username: string;
  fullAccountId?: string;
  isOpen: boolean;
  theme?: 'dark' | 'light';
}) => {
  const displayAccountId = (fullAccountId || username || '').trim();

  /* plain identity label (the wallet id) — explorer links live in the
     Accounts section of the dropdown */
  return (
    <div className="w3a-user-account--user-details">
      <p className="w3a-user-account--username">Settings</p>
      <span
        title={displayAccountId || undefined}
        className={`w3a-user-account--account-id ${isOpen ? 'visible' : 'hidden'}`}
      >
        {displayAccountId ? shortenAccountId(displayAccountId) : ''}
      </span>
    </div>
  );
};
