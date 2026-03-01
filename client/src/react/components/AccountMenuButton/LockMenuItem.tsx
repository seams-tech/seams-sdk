import LogOutIcon from './icons/LogOutIcon2';
import { memo } from 'react';
import type { LockMenuItemProps } from './types';

export const LockMenuItem: React.FC<LockMenuItemProps> = memo(
  ({ onLock, className, style }) => {
    return (
      <button
        className={`w3a-dropdown-menu-item ${className || ''}`}
        style={style}
        onClick={(e: React.MouseEvent) => {
          e.stopPropagation();
          onLock();
        }}
      >
        <div className="w3a-dropdown-menu-item-icon">
          <LogOutIcon />
        </div>
        <div className="w3a-dropdown-menu-item-content">
          <div className="w3a-dropdown-menu-item-label">Lock Wallet</div>
        </div>
      </button>
    );
  },
);
