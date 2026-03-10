import React from 'react';

interface DashboardInlineModalEscapeOptions {
  isOpen: boolean;
  onClose: () => void;
}

export function useDashboardInlineModalEscape({
  isOpen,
  onClose,
}: DashboardInlineModalEscapeOptions): void {
  React.useEffect(() => {
    if (!isOpen) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      onClose();
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [isOpen, onClose]);
}
