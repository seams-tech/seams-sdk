import React, { useEffect } from 'react';
import type { LinkedDeviceSummaryV1 } from '@shared/device-linking';
import { Theme, useTheme } from '../theme';
import { useSeams } from '../../context';
import './LinkedDevicesModal.css';

export interface LinkedDevicesModalProps {
  walletId: string | null;
  isOpen: boolean;
  onClose: () => void;
}

type LinkedDevicesLoadState =
  | { kind: 'idle' }
  | { kind: 'loading' }
  | { kind: 'loaded'; devices: readonly LinkedDeviceSummaryV1[] }
  | { kind: 'error' };

type RevokeState =
  | { kind: 'idle' }
  | { kind: 'confirming'; deviceId: string }
  | { kind: 'working'; deviceId: string }
  | { kind: 'error'; message: string };

/**
 * Plain-language state for one device. The wire model carries five states and a
 * revocation epoch; a person only needs to know whether the device can still
 * reach the wallet right now.
 */
function deviceStanding(device: LinkedDeviceSummaryV1): {
  readonly label: string;
  readonly tone: 'active' | 'pending' | 'off';
} {
  switch (device.state) {
    case 'active':
      return { label: 'Can use this wallet', tone: 'active' };
    case 'provisioning':
      return { label: 'Finishing setup', tone: 'pending' };
    case 'suspended':
      return { label: 'Paused', tone: 'off' };
    case 'expired':
      return { label: 'Expired', tone: 'off' };
    case 'revoked':
      return { label: 'Removed', tone: 'off' };
  }
}

/** "today" / "yesterday" / a plain date — never a timestamp with seconds. */
function friendlyDay(value: number, now: number): string {
  const then = new Date(value);
  const startOfToday = new Date(now);
  startOfToday.setHours(0, 0, 0, 0);
  const dayMs = 24 * 60 * 60 * 1000;
  const daysAgo = Math.floor((startOfToday.getTime() - then.setHours(0, 0, 0, 0)) / dayMs);
  if (daysAgo <= 0) return 'today';
  if (daysAgo === 1) return 'yesterday';
  if (daysAgo < 7) return `${daysAgo} days ago`;
  return new Date(value).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

function focusableDialogElements(dialog: HTMLElement): HTMLElement[] {
  return Array.from(
    dialog.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  );
}

export const LinkedDevicesModal: React.FC<LinkedDevicesModalProps> = ({
  walletId,
  isOpen,
  onClose,
}) => {
  const { seams } = useSeams();
  const [loadState, setLoadState] = React.useState<LinkedDevicesLoadState>({ kind: 'idle' });
  const [revokeState, setRevokeState] = React.useState<RevokeState>({ kind: 'idle' });
  const [announcement, setAnnouncement] = React.useState('');
  const loadSeq = React.useRef(0);
  const dialogRef = React.useRef<HTMLDivElement>(null);
  const closeButtonRef = React.useRef<HTMLButtonElement>(null);
  const previousFocusRef = React.useRef<HTMLElement | null>(null);
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );

  const loadDevices = React.useCallback(async () => {
    if (!walletId) return;
    const seq = loadSeq.current + 1;
    loadSeq.current = seq;
    setLoadState({ kind: 'loading' });
    try {
      const result = await seams.devices.listLinkedDevices({ walletId, limit: 50, cursor: null });
      if (loadSeq.current === seq) setLoadState({ kind: 'loaded', devices: result.devices });
    } catch {
      if (loadSeq.current === seq) setLoadState({ kind: 'error' });
    }
  }, [seams, walletId]);

  const handleDialogKeyDown = React.useCallback(
    (event: KeyboardEvent) => {
      if (event.key === 'Escape' || event.key === 'Esc') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;
      const focusable = focusableDialogElements(dialogRef.current);
      if (focusable.length === 0) {
        event.preventDefault();
        dialogRef.current.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    },
    [onClose],
  );

  useEffect(() => {
    if (!isOpen) return;
    previousFocusRef.current =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeButtonRef.current?.focus();
    window.addEventListener('keydown', handleDialogKeyDown);
    return () => {
      window.removeEventListener('keydown', handleDialogKeyDown);
      previousFocusRef.current?.focus();
      previousFocusRef.current = null;
    };
  }, [handleDialogKeyDown, isOpen]);

  useEffect(() => {
    if (!isOpen) {
      loadSeq.current += 1;
      setLoadState({ kind: 'idle' });
      setRevokeState({ kind: 'idle' });
      setAnnouncement('');
      return;
    }
    void loadDevices();
  }, [isOpen, loadDevices]);

  const revokeDevice = React.useCallback(
    async (device: LinkedDeviceSummaryV1) => {
      if (!walletId) return;
      const deviceId = String(device.deviceId);
      setRevokeState({ kind: 'working', deviceId });
      setAnnouncement(`Removing ${device.label}…`);
      try {
        const result = await seams.devices.revokeLinkedDevice({
          walletId,
          deviceId,
          requestedAtMs: Date.now(),
        });
        switch (result.kind) {
          case 'revoked':
          case 'replayed':
            setRevokeState({ kind: 'idle' });
            setAnnouncement(`${device.label} can no longer use this wallet.`);
            await loadDevices();
            return;
          case 'not_found':
            setRevokeState({ kind: 'error', message: 'That device is already gone.' });
            await loadDevices();
            return;
          case 'conflict':
            setRevokeState({
              kind: 'error',
              message: 'Something changed on that device. Try again.',
            });
            await loadDevices();
            return;
          case 'unauthorized':
            setRevokeState({
              kind: 'error',
              message: 'You need to unlock this wallet before removing a device.',
            });
            return;
        }
      } catch {
        setRevokeState({ kind: 'error', message: "Couldn't remove that device. Try again." });
      }
    },
    [loadDevices, seams, walletId],
  );

  if (!isOpen) return null;

  const devices = loadState.kind === 'loaded' ? loadState.devices : [];
  const showEmpty = loadState.kind === 'loaded' && devices.length === 0;

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`w3a-linked-devices-modal-backdrop theme-${theme}`}
        role="presentation"
        onMouseDown={(event) => {
          if (event.target === event.currentTarget) onClose();
        }}
      >
        <div
          ref={dialogRef}
          className="w3a-linked-devices-modal-content"
          role="dialog"
          aria-modal="true"
          aria-labelledby="w3a-linked-devices-modal-title"
          aria-describedby="w3a-linked-devices-modal-description"
          tabIndex={-1}
        >
          <button
            ref={closeButtonRef}
            type="button"
            className="w3a-linked-devices-modal-close"
            onClick={onClose}
            aria-label="Close linked devices"
          >
            ✕
          </button>
          <h2 id="w3a-linked-devices-modal-title" className="w3a-linked-devices-modal-title">
            Your devices
          </h2>
          <p id="w3a-linked-devices-modal-description" className="w3a-linked-devices-modal-note">
            These devices can use this wallet. Remove any you don&apos;t recognize.
          </p>

          <div className="w3a-linked-devices-modal-body">
            {loadState.kind === 'loading' || loadState.kind === 'idle' ? (
              <div className="w3a-linked-devices-modal-placeholder">Checking your devices…</div>
            ) : null}

            {loadState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-placeholder">
                <span>We couldn&apos;t load your devices.</span>
                <button
                  type="button"
                  className="w3a-linked-devices-modal-secondary"
                  onClick={() => void loadDevices()}
                >
                  Try again
                </button>
              </div>
            ) : null}

            {showEmpty ? (
              <div className="w3a-linked-devices-modal-placeholder">
                No other devices are using this wallet.
              </div>
            ) : null}

            {devices.length > 0 ? (
              <ul className="w3a-linked-devices-modal-list">
                {devices.map((device) => {
                  const deviceId = String(device.deviceId);
                  const standing = deviceStanding(device);
                  const confirming =
                    revokeState.kind === 'confirming' && revokeState.deviceId === deviceId;
                  const working =
                    revokeState.kind === 'working' && revokeState.deviceId === deviceId;
                  const removed = device.state === 'revoked';
                  return (
                    <li key={deviceId} className="w3a-linked-devices-modal-item">
                      <div className="w3a-linked-devices-modal-item-main">
                        <span className="w3a-linked-devices-modal-item-name">{device.label}</span>
                        <span className={`w3a-linked-devices-modal-standing tone-${standing.tone}`}>
                          {standing.label}
                        </span>
                      </div>
                      <div className="w3a-linked-devices-modal-item-detail">
                        Last used {friendlyDay(device.lastActivityAtMs, Date.now())}
                      </div>
                      {confirming ? (
                        <div className="w3a-linked-devices-modal-confirm">
                          <span>Remove this device? It will lose access right away.</span>
                          <div className="w3a-linked-devices-modal-confirm-actions">
                            <button
                              type="button"
                              className="w3a-linked-devices-modal-secondary"
                              onClick={() => setRevokeState({ kind: 'idle' })}
                            >
                              Keep it
                            </button>
                            <button
                              type="button"
                              className="w3a-linked-devices-modal-danger"
                              onClick={() => void revokeDevice(device)}
                            >
                              Yes, remove
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-secondary"
                          disabled={working || removed}
                          onClick={() => setRevokeState({ kind: 'confirming', deviceId })}
                        >
                          {working ? 'Removing…' : removed ? 'Removed' : 'Remove'}
                        </button>
                      )}
                    </li>
                  );
                })}
              </ul>
            ) : null}

            {revokeState.kind === 'error' ? (
              <div className="w3a-linked-devices-modal-error" role="alert">
                {revokeState.message}
              </div>
            ) : null}

            <div className="w3a-linked-devices-modal-live" role="status" aria-live="polite">
              {announcement}
            </div>
          </div>
        </div>
      </div>
    </Theme>
  );
};

export default LinkedDevicesModal;
