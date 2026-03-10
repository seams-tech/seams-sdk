import React from 'react';
import { useDashboardInlineModalEscape } from '../useDashboardInlineModalEscape';

interface DashboardInlineModalProps {
  isOpen: boolean;
  ariaLabel: string;
  onRequestClose: () => void;
  children: React.ReactNode;
  className?: string;
}

export function DashboardInlineModal({
  isOpen,
  ariaLabel,
  onRequestClose,
  children,
  className,
}: DashboardInlineModalProps): React.JSX.Element | null {
  useDashboardInlineModalEscape({
    isOpen,
    onClose: onRequestClose,
  });

  if (!isOpen) return null;

  const modalClassName = ['dashboard-modal', className].filter(Boolean).join(' ');

  return (
    <div className="dashboard-inline-modal-backdrop" role="presentation" onClick={onRequestClose}>
      <section
        className={modalClassName}
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel}
        onClick={(event) => event.stopPropagation()}
      >
        {children}
      </section>
    </div>
  );
}
