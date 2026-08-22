import React, { useEffect } from 'react';
import type {
  LinkedDeviceSummaryV1,
  LinkedOwnerCredentialMetadataV1,
  OwnerDeviceSummaryV1,
} from '@shared/device-linking';
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
  | { kind: 'loaded'; devices: readonly NumberedWalletDevice[] }
  | { kind: 'error'; message: string };

/**
 * One card in the list: either a founding owner passkey (registered or
 * recovered directly, removable only through auth-method revocation) or a
 * linked-device enrollment (removable here).
 */
type WalletDeviceView =
  | { readonly kind: 'owner'; readonly owner: OwnerDeviceSummaryV1 }
  | { readonly kind: 'linked'; readonly device: LinkedDeviceSummaryV1 };

type NumberedWalletDevice = {
  readonly view: WalletDeviceView;
  readonly deviceNumber: number;
};

type RevokeState =
  | { kind: 'idle' }
  | { kind: 'confirming'; walletAuthMethodId: string }
  | { kind: 'working'; walletAuthMethodId: string }
  | { kind: 'error'; message: string };

function viewCreatedAtMs(view: WalletDeviceView): number {
  return view.kind === 'owner' ? view.owner.createdAtMs : view.device.createdAtMs;
}

function viewLastActivityAtMs(view: WalletDeviceView): number {
  return view.kind === 'owner' ? view.owner.lastActivityAtMs : view.device.lastActivityAtMs;
}

function viewCredential(view: WalletDeviceView): LinkedOwnerCredentialMetadataV1 {
  return view.kind === 'owner' ? view.owner.credential : view.device.credential;
}

/**
 * The card's stable identity for expand/remove state. Linked devices carry a
 * LinkedDeviceId; founding owners have only their credential.
 */
function viewId(view: WalletDeviceView): string {
  return view.kind === 'owner'
    ? String(view.owner.credential.walletAuthMethodId)
    : String(view.device.deviceId);
}

/** The identifier a person can match against their other device. */
function viewDisplayId(view: WalletDeviceView): string {
  return view.kind === 'owner'
    ? String(view.owner.credential.credentialIdB64u ?? view.owner.credential.walletAuthMethodId)
    : String(view.device.deviceId);
}

/**
 * Founding owners and linked enrollments in one numbered list, oldest first.
 * Revoked devices are historical records, not devices the owner can manage.
 */
function visibleWalletDevices(
  ownerDevices: readonly OwnerDeviceSummaryV1[],
  devices: readonly LinkedDeviceSummaryV1[],
): readonly NumberedWalletDevice[] {
  const views: WalletDeviceView[] = [
    ...ownerDevices.map((owner): WalletDeviceView => ({ kind: 'owner', owner })),
    ...devices.map((device): WalletDeviceView => ({ kind: 'linked', device })),
  ];
  return views
    .sort(
      (left, right) =>
        viewCreatedAtMs(left) - viewCreatedAtMs(right) || viewId(left).localeCompare(viewId(right)),
    )
    .map((view, index) => ({ view, deviceNumber: index + 1 }))
    .filter(({ view }) => view.kind === 'owner' || view.device.state !== 'revoked');
}

/**
 * Plain-language state for one device. The wire model carries five states and a
 * revocation epoch; a person only needs to know whether the device can still
 * reach the wallet right now. Founding owners in the list are active by
 * construction — the projection only serves active owner credentials.
 */
function deviceStanding(view: WalletDeviceView): {
  readonly label: string;
  readonly tone: 'active' | 'pending' | 'off';
} {
  if (view.kind === 'owner') return { label: 'Can use this wallet', tone: 'active' };
  switch (view.device.state) {
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

function shortDisplayId(value: string): string {
  return value.length <= 12 ? value : `…${value.slice(-8)}`;
}

/**
 * The one description the card heading, the removal confirmation, and every
 * live announcement share. Credential labels repeat across cards — two platform
 * passkeys are both "Platform passkey" — so the stable ID suffix is what makes
 * a sentence name a single card rather than a category of them.
 */
function credentialDescription(credential: LinkedOwnerCredentialMetadataV1): string {
  switch (credential.kind) {
    case 'passkey':
      return credential.device.label;
    case 'email_otp':
      return 'Email OTP';
  }
}

function credentialSecondaryDescription(
  credential: LinkedOwnerCredentialMetadataV1,
): string | null {
  switch (credential.kind) {
    case 'email_otp':
      return null;
    case 'passkey': {
      const metadata = credential.device;
      const provider = metadata.providerLabel ?? metadata.provider;
      const sync = metadata.synced ? 'Synced passkey' : 'Passkey';
      return provider ? `${provider} · ${sync}` : sync;
    }
  }
}

function deviceDescription(view: WalletDeviceView, deviceNumber: number): string {
  return `Device ${deviceNumber}, ${credentialDescription(viewCredential(view))} (ID ${shortDisplayId(viewDisplayId(view))})`;
}

function linkedDevicesLoadErrorMessage(error: unknown): string {
  if (error instanceof Error && error.message.trim()) return error.message;
  return 'Try again.';
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
  /** Device IDs are identifiers, not secrets, but printing one in full by
   * default buries the rest of the card. One card at a time may expand. */
  const [expandedDeviceId, setExpandedDeviceId] = React.useState<string | null>(null);
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
      if (loadSeq.current === seq) {
        setLoadState({
          kind: 'loaded',
          devices: visibleWalletDevices(result.ownerDevices, result.devices),
        });
      }
    } catch (error: unknown) {
      if (loadSeq.current === seq) {
        setLoadState({ kind: 'error', message: linkedDevicesLoadErrorMessage(error) });
      }
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
      setExpandedDeviceId(null);
      return;
    }
    void loadDevices();
  }, [isOpen, loadDevices]);

  const revokeDevice = React.useCallback(
    async (device: LinkedDeviceSummaryV1, deviceNumber: number) => {
      if (!walletId) return;
      const walletAuthMethodId = String(device.credential.walletAuthMethodId);
      const description = deviceDescription({ kind: 'linked', device }, deviceNumber);
      setRevokeState({ kind: 'working', walletAuthMethodId });
      setAnnouncement(`Removing ${description}…`);
      try {
        const result = await seams.devices.revokeLinkedDevice({
          walletId,
          walletAuthMethodId,
          requestedAtMs: Date.now(),
        });
        switch (result.kind) {
          case 'revoked':
            setRevokeState({ kind: 'idle' });
            setAnnouncement(`${description} can no longer use this wallet.`);
            await loadDevices();
            return;
          case 'not_found':
            setRevokeState({ kind: 'idle' });
            setAnnouncement(`${description} was already removed.`);
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
              <div className="w3a-linked-devices-modal-placeholder" role="alert">
                <span>Unable to load your devices: {loadState.message}</span>
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
                {devices.map(({ view, deviceNumber }) => {
                  const cardId = viewId(view);
                  const displayId = viewDisplayId(view);
                  const secondaryDescription = credentialSecondaryDescription(viewCredential(view));
                  const standing = deviceStanding(view);
                  const walletAuthMethodId = String(viewCredential(view).walletAuthMethodId);
                  const confirming =
                    revokeState.kind === 'confirming' &&
                    revokeState.walletAuthMethodId === walletAuthMethodId;
                  const working =
                    revokeState.kind === 'working' &&
                    revokeState.walletAuthMethodId === walletAuthMethodId;
                  const fullIdShown = expandedDeviceId === cardId;
                  return (
                    <li key={cardId} className="w3a-linked-devices-modal-item">
                      <div className="w3a-linked-devices-modal-item-main">
                        <span className="w3a-linked-devices-modal-item-name">
                          Device {deviceNumber} &middot;{' '}
                          {credentialDescription(viewCredential(view))}
                        </span>
                        <span className={`w3a-linked-devices-modal-standing tone-${standing.tone}`}>
                          {standing.label}
                        </span>
                      </div>
                      <div className="w3a-linked-devices-modal-item-identity">
                        {secondaryDescription ? <span>{secondaryDescription}</span> : null}
                        {secondaryDescription ? <span aria-hidden="true">&middot;</span> : null}
                        <span className="w3a-linked-devices-modal-device-id">
                          ID {fullIdShown ? displayId : shortDisplayId(displayId)}
                        </span>
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-disclosure"
                          aria-expanded={fullIdShown}
                          onClick={() => setExpandedDeviceId(fullIdShown ? null : cardId)}
                        >
                          {fullIdShown ? 'Hide full ID' : 'Show full ID'}
                        </button>
                      </div>
                      <div className="w3a-linked-devices-modal-item-detail">
                        Last used {friendlyDay(viewLastActivityAtMs(view), Date.now())}
                      </div>
                      {view.kind === 'owner' ? (
                        <div className="w3a-linked-devices-modal-item-detail">
                          Original device — manage it from that device&apos;s wallet settings.
                        </div>
                      ) : confirming ? (
                        <div className="w3a-linked-devices-modal-confirm">
                          <span>
                            Remove {deviceDescription(view, deviceNumber)}? It will lose access
                            right away.
                          </span>
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
                              onClick={() => void revokeDevice(view.device, deviceNumber)}
                            >
                              Yes, remove
                            </button>
                          </div>
                        </div>
                      ) : (
                        <button
                          type="button"
                          className="w3a-linked-devices-modal-secondary"
                          disabled={working}
                          aria-label={`Remove ${deviceDescription(view, deviceNumber)}`}
                          onClick={() => setRevokeState({ kind: 'confirming', walletAuthMethodId })}
                        >
                          {working ? 'Removing…' : 'Remove'}
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
