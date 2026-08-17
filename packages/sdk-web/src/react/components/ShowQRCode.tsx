import { useState, useEffect, useRef } from 'react';

import { useSeams } from '../context';
import {
  classifyLinkDeviceFlowEvent,
  type LinkDeviceFlowEvent,
  type LinkDeviceFlowOutcome,
} from '../../core/types/sdkSentEvents';
import { toAccountId } from '../../core/types/accountIds';
import './ShowQRCode.css';

export interface ShowQRCodeProps {
  isOpen: boolean;
  onClose: () => void;
  onEvent: (event: LinkDeviceFlowEvent) => void;
  onError: (error: Error) => void;
}

function isCompletedDeviceLink(event: LinkDeviceFlowEvent): boolean {
  const outcome = classifyLinkDeviceFlowEvent(event);
  switch (outcome.kind) {
    case 'active':
      return true;
    case 'pending':
    case 'invalid_active':
    case 'failed':
    case 'cancelled':
      return false;
    default:
      return assertNeverLinkDeviceFlowOutcome(outcome);
  }
}

function assertNeverLinkDeviceFlowOutcome(value: never): never {
  throw new Error(`Unhandled link-device flow outcome: ${String(value)}`);
}

export function ShowQRCode({ isOpen, onClose, onEvent, onError }: ShowQRCodeProps) {
  const { startDevice2LinkingFlow, cancelDeviceLinking, accountInputState, loginState } =
    useSeams();

  const [deviceLinkingState, setDeviceLinkingState] = useState<{
    mode: 'idle' | 'device1' | 'device2';
    qrCodeDataURL?: string;
    isProcessing: boolean;
    lastPhase?: string;
    lastMessage?: string;
  }>({ mode: 'idle', isProcessing: false });

  // Ignore async results from an earlier menu opening.
  const sessionRef = useRef(0);
  const flowRuntimeRef = useRef({
    startDevice2LinkingFlow,
    cancelDeviceLinking,
    accountIdRaw: '',
    onClose,
    onEvent,
    onError,
  });
  flowRuntimeRef.current = {
    startDevice2LinkingFlow,
    cancelDeviceLinking,
    accountIdRaw: String(
      accountInputState?.targetAccountId || loginState?.nearAccountId || '',
    ).trim(),
    onClose,
    onEvent,
    onError,
  };

  // One menu opening owns one linking ceremony. Render-time callback changes must
  // not cancel and restart the one-time QR invitation.
  useEffect(() => {
    if (!isOpen) return;

    const runtime = flowRuntimeRef.current;
    const { accountIdRaw } = runtime;

    const mySession = ++sessionRef.current;
    let cancelled = false;
    setDeviceLinkingState({ mode: 'device2', isProcessing: true });

    (async () => {
      try {
        const { qrCodeDataURL } = await runtime.startDevice2LinkingFlow({
          ...(accountIdRaw ? { accountId: toAccountId(accountIdRaw) } : {}),
          options: {
            onEvent: (event: LinkDeviceFlowEvent) => {
              if (cancelled) return;
              if (isCompletedDeviceLink(event)) {
                cancelled = true;
                sessionRef.current++;
                runtime.onEvent(event);
                runtime.onClose();
                return;
              }
              setDeviceLinkingState((prev) => ({
                ...prev,
                lastPhase: String(event.phase),
                lastMessage: event.message,
              }));
              runtime.onEvent(event);
            },
            onError: (error: Error) => {
              if (cancelled) return;
              setDeviceLinkingState({ mode: 'idle', isProcessing: false });
              runtime.onError(error);
              try {
                runtime.onClose();
              } catch {}
            },
          },
        });
        if (!cancelled && sessionRef.current === mySession) {
          setDeviceLinkingState((prev) => ({ ...prev, qrCodeDataURL, isProcessing: false }));
        }
      } catch (err) {
        if (!cancelled && sessionRef.current === mySession) {
          const msg =
            err instanceof Error ? err.message : String(err || 'Failed to generate QR code');
          setDeviceLinkingState({ mode: 'device2', isProcessing: false, lastMessage: msg });
        }
      }
    })();

    return () => {
      cancelled = true;
      sessionRef.current++;
      try {
        runtime.cancelDeviceLinking().catch(() => {});
      } catch {}
    };
  }, [isOpen]);

  if (!isOpen) return null;

  const ready = Boolean(deviceLinkingState.qrCodeDataURL);
  const failed = !ready && !deviceLinkingState.isProcessing;

  if (deviceLinkingState.mode === 'device2' && failed) {
    return (
      <div className="w3a-link-device-failure" onClick={(e) => e.stopPropagation()}>
        <div className="w3a-link-device-failure-icon">
          <LinkFailedIcon />
        </div>
        <h2 className="qr-title">Couldn&apos;t link device</h2>
        <p className="w3a-link-device-failure-detail" role="alert">
          {deviceLinkingState.lastMessage || 'Failed to generate QR code'}
        </p>
        <button type="button" className="w3a-link-device-btn" onClick={onClose}>
          Close
        </button>
      </div>
    );
  }

  return (
    <div className="qr-code-container" onClick={(e) => e.stopPropagation()}>
      <div className="qr-body">
        {deviceLinkingState.mode === 'device2' && (
          <div className="qr-code-section">
            {/* The plate keeps its box while the code is generated, so the copy
                below never shifts once the image lands. */}
            <div className="qr-code-display">
              {ready ? (
                <img
                  src={deviceLinkingState.qrCodeDataURL}
                  alt="Device Linking QR Code"
                  className="qr-code-image"
                />
              ) : (
                <div className="qr-code-placeholder">
                  <span className="w3a-spinner" aria-hidden="true"></span>
                </div>
              )}
            </div>
            <div className="qr-header">
              <h2 className="qr-title">Scan and Link Device</h2>
            </div>
            <div className="qr-instruction">
              {ready
                ? 'Scan to backup your other device.'
                : 'Preparing a one-time code for your other device.'}
            </div>
            <div className="qr-status" role="status" aria-live="polite">
              {ready
                ? deviceLinkingState.lastMessage || 'Waiting for device to scan'
                : 'Generating QR code'}
              <span className="animated-ellipsis"></span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function LinkFailedIcon() {
  return (
    <svg
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M9 17H7A5 5 0 0 1 7 7h2" />
      <path d="M15 7h2a5 5 0 0 1 3.54 8.54" />
      <path d="m2 2 20 20" />
      <path d="M8 12h3" />
    </svg>
  );
}
