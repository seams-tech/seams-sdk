import React from 'react';
import { createPortal } from 'react-dom';
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
  const modalRef = React.useRef<HTMLElement | null>(null);
  const [portalHost, setPortalHost] = React.useState<HTMLElement | null>(null);
  const [scrollHost, setScrollHost] = React.useState<HTMLElement | null>(null);

  useDashboardInlineModalEscape({
    isOpen,
    onClose: onRequestClose,
  });

  React.useEffect(() => {
    if (typeof document === 'undefined') return;
    setPortalHost(
      (document.querySelector('.dashboard-overlay-layer') as HTMLElement | null) || document.body,
    );
    setScrollHost((document.querySelector('.dashboard-main') as HTMLElement | null) || null);
  }, []);

  React.useEffect(() => {
    if (!isOpen || typeof document === 'undefined') return;
    const host =
      scrollHost || ((document.querySelector('.dashboard-main') as HTMLElement | null) || null);
    const overlayHost =
      portalHost?.classList.contains('dashboard-overlay-layer') === true ? portalHost : null;

    const previousActiveElement =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousBodyOverflow = document.body.style.overflow;
    if (overlayHost) {
      overlayHost.classList.add('dashboard-overlay-layer--modal-open');
    }
    if (host) {
      host.classList.add('dashboard-main--modal-open');
    } else {
      document.body.style.overflow = 'hidden';
    }

    const focusModal = window.requestAnimationFrame(() => {
      modalRef.current?.focus();
    });

    return () => {
      window.cancelAnimationFrame(focusModal);
      if (overlayHost) {
        overlayHost.classList.remove('dashboard-overlay-layer--modal-open');
      }
      if (host) {
        host.classList.remove('dashboard-main--modal-open');
      } else {
        document.body.style.overflow = previousBodyOverflow;
      }
      if (previousActiveElement?.isConnected) {
        previousActiveElement.focus();
      }
    };
  }, [isOpen, portalHost, scrollHost]);

  if (!isOpen) return null;
  if (typeof document === 'undefined') return null;
  if (!portalHost) return null;

  const modalClassName = ['dashboard-modal', className].filter(Boolean).join(' ');
  const backdropClassName = [
    'dashboard-inline-modal-backdrop',
    portalHost.classList.contains('dashboard-overlay-layer')
      ? ''
      : 'dashboard-inline-modal-backdrop--self-styled',
  ]
    .filter(Boolean)
    .join(' ');

  return createPortal(
    <div className={backdropClassName} role="presentation" onClick={onRequestClose}>
      <section
        ref={modalRef}
        className={modalClassName}
        role="dialog"
        aria-modal="true"
        aria-label={ariaLabel}
        tabIndex={-1}
        onClick={(event) => event.stopPropagation()}
      >
        {children}
      </section>
    </div>,
    portalHost,
  );
}
