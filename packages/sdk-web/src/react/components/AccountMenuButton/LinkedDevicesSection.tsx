import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { LinkedDeviceSummaryV1 } from '@shared/device-linking';
import { useSeams } from '../../context';
import './LinkedDevicesSection.css';

export interface LinkedDevicesSectionProps {
  walletId: string | null;
  isOpen?: boolean;
  className?: string;
  style?: React.CSSProperties;
}

export const LinkedDevicesSection: React.FC<LinkedDevicesSectionProps> = ({
  walletId,
  isOpen = false,
  className,
  style,
}) => {
  const { seams } = useSeams();
  const [devices, setDevices] = useState<readonly LinkedDeviceSummaryV1[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const loadedForRef = useRef<string | null>(null);

  const loadDevices = useCallback(async () => {
    if (!walletId) return;
    setIsLoading(true);
    setError(null);
    try {
      const result = await seams.devices.listLinkedDevices({ walletId });
      setDevices(result.devices);
      loadedForRef.current = walletId;
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : 'Failed to load linked devices');
    } finally {
      setIsLoading(false);
    }
  }, [seams, walletId]);

  useEffect(() => {
    if (!isOpen || !walletId || loadedForRef.current === walletId) return;
    void loadDevices();
  }, [isOpen, loadDevices, walletId]);

  return (
    <div
      className={`w3a-dropdown-linked-devices-root ${isOpen ? 'is-expanded' : ''} ${className || ''}`}
      style={style}
    >
      <div className="w3a-dropdown-linked-devices-clip">
        <div
          className="w3a-dropdown-linked-devices-content"
          aria-hidden={!isOpen}
          style={{ pointerEvents: isOpen ? 'auto' : 'none' }}
        >
          {isLoading && <div className="w3a-linked-devices-status">Loading linked devices…</div>}
          {!isLoading && error && (
            <div className="w3a-linked-devices-status">
              <span>{error}</span>
              <button
                type="button"
                className="w3a-linked-devices-retry"
                tabIndex={isOpen ? 0 : -1}
                onClick={() => void loadDevices()}
              >
                Retry
              </button>
            </div>
          )}
          {!isLoading && !error && devices.length === 0 && (
            <div className="w3a-linked-devices-status">No linked devices found.</div>
          )}
          {!isLoading && !error && devices.length > 0 && (
            <div className="w3a-linked-devices-list">
              {devices.map((device) => (
                <LinkedDeviceRow key={String(device.deviceId)} device={device} />
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

function LinkedDeviceRow(props: { readonly device: LinkedDeviceSummaryV1 }): React.ReactElement {
  const { device } = props;
  return (
    <div className="w3a-linked-devices-row">
      <div className="w3a-linked-devices-heading">
        <strong>{device.label}</strong>
        <span>{device.platform}</span>
      </div>
      <div className="w3a-linked-devices-meta">
        <span>
          {device.permission.kind} · {device.permission.administrationScope} · local presence:{' '}
          {device.permission.localUserPresence}
        </span>
        <span>{device.coveredWalletKeys.length} wallet key(s) covered</span>
        <span>State: {device.state}</span>
        <span>Revocation epoch: {device.revocationEpoch}</span>
        <span>Created: {formatTimestamp(device.createdAtMs)}</span>
        <span>Last activity: {formatTimestamp(device.lastActivityAtMs)}</span>
        <span>Revocation disables this device&apos;s linked lanes and wallet session.</span>
      </div>
      <span className="w3a-linked-devices-revoke-consequence">
        Revocation is available from the linked-device management service.
      </span>
    </div>
  );
}

function formatTimestamp(value: number): string {
  return new Date(value).toLocaleString();
}
