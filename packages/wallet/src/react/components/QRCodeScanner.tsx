import React, { useCallback, useEffect, useRef, useState } from 'react';
import type {
  LinkedDeviceEmailOtpBaseFactorChoiceV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { classifyLinkDeviceFlowEvent, type LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import { useQRCamera, QRScanMode } from '../hooks/useQRCamera';
import { useDeviceLinking } from '../hooks/useDeviceLinking';
import { Theme, useTheme } from './theme';

/**
 * QR scanner shell for the linked-device flow.
 */
export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: QrLinkedDeviceSessionPayloadV5) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: LinkDeviceFlowEvent) => void;
  isOpen?: boolean;
  cameraId?: string;
  className?: string;
  style?: React.CSSProperties;
  showCamera?: boolean;
}

type EmailOtpBaseFactorSelectionState =
  | {
      readonly kind: 'required';
      readonly choices: readonly [
        LinkedDeviceEmailOtpBaseFactorChoiceV1,
        ...LinkedDeviceEmailOtpBaseFactorChoiceV1[],
      ];
      readonly selectedBaseWalletAuthMethodId: WalletAuthMethodId | null;
    }
  | {
      readonly kind: 'submitting';
      readonly choice: LinkedDeviceEmailOtpBaseFactorChoiceV1;
    };

type PendingEmailOtpBaseFactorSelection = {
  readonly resolve: (baseWalletAuthMethodId: WalletAuthMethodId) => void;
  readonly reject: (reason?: unknown) => void;
};

export const QRCodeScanner: React.FC<QRCodeScannerProps> = ({
  onQRCodeScanned,
  onError,
  onClose,
  onEvent,
  isOpen = true,
  cameraId,
  className,
  style,
  showCamera = true,
}) => {
  const { theme, tokens } = useTheme();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );

  const scannedPayloadRef = React.useRef<QrLinkedDeviceSessionPayloadV5 | null>(null);
  const completionReportedRef = React.useRef(false);
  const pendingEmailOtpSelectionRef = useRef<PendingEmailOtpBaseFactorSelection | null>(null);
  const [emailOtpSelection, setEmailOtpSelection] =
    useState<EmailOtpBaseFactorSelectionState | null>(null);

  const rejectPendingEmailOtpSelection = useCallback((reason: Error) => {
    const pending = pendingEmailOtpSelectionRef.current;
    pendingEmailOtpSelectionRef.current = null;
    setEmailOtpSelection(null);
    pending?.reject(reason);
  }, []);

  const requestEmailOtpBaseFactor = useCallback(
    (
      choices: readonly [
        LinkedDeviceEmailOtpBaseFactorChoiceV1,
        ...LinkedDeviceEmailOtpBaseFactorChoiceV1[],
      ],
    ): Promise<WalletAuthMethodId> => {
      rejectPendingEmailOtpSelection(new Error('A newer Email OTP method selection is required'));
      setEmailOtpSelection({
        kind: 'required',
        choices,
        selectedBaseWalletAuthMethodId: null,
      });
      return new Promise<WalletAuthMethodId>((resolve, reject) => {
        pendingEmailOtpSelectionRef.current = { resolve, reject };
      });
    },
    [rejectPendingEmailOtpSelection],
  );

  const selectEmailOtpBaseFactor = useCallback(() => {
    if (emailOtpSelection?.kind !== 'required') return;
    const selected = emailOtpSelection.selectedBaseWalletAuthMethodId;
    if (selected === null) return;
    const choice = emailOtpSelection.choices.find(
      (candidate) => candidate.baseWalletAuthMethodId === selected,
    );
    const pending = pendingEmailOtpSelectionRef.current;
    if (!choice || !pending) return;
    pendingEmailOtpSelectionRef.current = null;
    setEmailOtpSelection({ kind: 'submitting', choice });
    pending.resolve(choice.baseWalletAuthMethodId);
  }, [emailOtpSelection]);

  const handleEmailOtpChoiceChange = useCallback((baseWalletAuthMethodId: WalletAuthMethodId) => {
    setEmailOtpSelection((current) =>
      current?.kind === 'required'
        ? { ...current, selectedBaseWalletAuthMethodId: baseWalletAuthMethodId }
        : current,
    );
  }, []);

  const handleLinkDeviceEvent = React.useCallback(
    (event: LinkDeviceFlowEvent) => {
      onEvent?.(event);
      const outcome = classifyLinkDeviceFlowEvent(event);
      if (outcome.kind !== 'active' || completionReportedRef.current) return;
      const scannedPayload = scannedPayloadRef.current;
      if (!scannedPayload) return;
      completionReportedRef.current = true;
      onQRCodeScanned?.(scannedPayload);
      onClose?.();
    },
    [onClose, onEvent, onQRCodeScanned],
  );

  const handleFlowClose = useCallback(() => {
    rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
    onClose?.();
  }, [onClose, rejectPendingEmailOtpSelection]);

  const { linkDevice } = useDeviceLinking({
    onError,
    onClose: handleFlowClose,
    onEvent: handleLinkDeviceEvent,
    onEmailOtpBaseFactorRequired: requestEmailOtpBaseFactor,
  });

  const qrCamera = useQRCamera({
    onQRDetected: async (qrData: QrLinkedDeviceSessionPayloadV5) => {
      scannedPayloadRef.current = qrData;
      await linkDevice(qrData, QRScanMode.CAMERA);
    },
    onError,
    isOpen: showCamera ? isOpen : false, // Only active when camera should be shown
    cameraId,
  });

  const [isVideoReady, setIsVideoReady] = useState(false);

  // Reset video ready state when modal opens so we can re-fade
  useEffect(() => {
    if (isOpen) {
      setIsVideoReady(false);
      scannedPayloadRef.current = null;
      completionReportedRef.current = false;
      rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
    }
  }, [isOpen, rejectPendingEmailOtpSelection]);

  // Camera Cleanup Point 1: User-initiated close
  const handleClose = useCallback(() => {
    qrCamera.stopScanning();
    handleFlowClose();
  }, [handleFlowClose, qrCamera.stopScanning]);

  const stopPropagationNative = useCallback((event: React.SyntheticEvent<HTMLElement>) => {
    const nativeEvent = event.nativeEvent as Event & { stopImmediatePropagation?: () => void };
    if (typeof nativeEvent.stopImmediatePropagation === 'function') {
      nativeEvent.stopImmediatePropagation();
    }
  }, []);

  const handleBackdropClick = useCallback(
    (event: React.MouseEvent<HTMLDivElement>) => {
      event.stopPropagation();
      stopPropagationNative(event);
      if (event.target === event.currentTarget) {
        handleClose();
      }
    },
    [handleClose, stopPropagationNative],
  );

  const stopEventPropagation = useCallback(
    (event: React.SyntheticEvent<HTMLElement>) => {
      event.stopPropagation();
      stopPropagationNative(event);
    },
    [stopPropagationNative],
  );

  // Camera Cleanup Point 2: Component unmount
  useEffect(() => {
    return () => {
      rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
      qrCamera.stopScanning();
    };
  }, [qrCamera.stopScanning, rejectPendingEmailOtpSelection]);

  // Camera Cleanup Point 3: Modal state changes (isOpen prop)
  useEffect(() => {
    if (!isOpen && qrCamera.isScanning) {
      qrCamera.stopScanning();
    }
  }, [isOpen, qrCamera.isScanning, qrCamera.stopScanning, qrCamera.videoRef]);

  // Camera Cleanup Point 4: ESC key handling
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isOpen) {
        handleClose();
      }
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, [isOpen, handleClose]);

  // Early return for closed state to prevent unnecessary rendering when modal is closed
  // Note: Camera cleanup is handled by useEffect() above, not by conditional rendering
  if (!isOpen) {
    return null;
  }

  if (qrCamera.error) {
    return (
      <Theme theme={theme} tokens={scopedTokens}>
        <div className="qr-scanner-error-container">
          <div className="qr-scanner-error-message">
            <p>{qrCamera.error}</p>
            <button onClick={() => qrCamera.setError(null)} className="qr-scanner-error-button">
              Try Again
            </button>
            <button onClick={handleClose} className="qr-scanner-error-button">
              Close
            </button>
          </div>
        </div>
      </Theme>
    );
  }

  if (emailOtpSelection) {
    return (
      <Theme theme={theme} tokens={scopedTokens}>
        <div
          className={`qr-scanner-modal ${className || ''}`}
          style={style}
          onClick={handleBackdropClick}
          onPointerDown={stopEventPropagation}
          onMouseDown={stopEventPropagation}
        >
          <section
            className="qr-scanner-panel qr-scanner-email-selection"
            aria-labelledby="qr-scanner-email-selection-title"
            onClick={stopEventPropagation}
            onPointerDown={stopEventPropagation}
            onMouseDown={stopEventPropagation}
          >
            <h2 id="qr-scanner-email-selection-title">Choose an Email OTP method</h2>
            <p>Select the masked address to authorize this linked device.</p>
            {emailOtpSelection.kind === 'required' ? (
              <fieldset className="qr-scanner-email-choice-list">
                <legend className="qr-scanner-email-choice-legend">Available methods</legend>
                {emailOtpSelection.choices.map((choice) => {
                  const choiceId = `qr-email-method-${String(choice.baseWalletAuthMethodId)}`;
                  return (
                    <label key={choiceId} className="qr-scanner-email-choice" htmlFor={choiceId}>
                      <input
                        id={choiceId}
                        type="radio"
                        name="qr-email-base-method"
                        value={String(choice.baseWalletAuthMethodId)}
                        checked={
                          emailOtpSelection.selectedBaseWalletAuthMethodId ===
                          choice.baseWalletAuthMethodId
                        }
                        onChange={() => handleEmailOtpChoiceChange(choice.baseWalletAuthMethodId)}
                      />
                      <span>{choice.maskedEmailHint}</span>
                    </label>
                  );
                })}
              </fieldset>
            ) : (
              <p role="status">Authorizing {emailOtpSelection.choice.maskedEmailHint}…</p>
            )}
            {emailOtpSelection.kind === 'required' && (
              <button
                type="button"
                className="qr-scanner-email-continue"
                disabled={emailOtpSelection.selectedBaseWalletAuthMethodId === null}
                onClick={selectEmailOtpBaseFactor}
              >
                Continue
              </button>
            )}
          </section>
          <button type="button" onClick={handleClose} className="qr-scanner-close">
            <span aria-hidden="true">✕</span>
            <span className="qr-scanner-visually-hidden">Close</span>
          </button>
        </div>
      </Theme>
    );
  }

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`qr-scanner-modal ${className || ''}`}
        style={style}
        onClick={handleBackdropClick}
        onPointerDown={stopEventPropagation}
        onMouseDown={stopEventPropagation}
      >
        <div
          className="qr-scanner-panel"
          onClick={stopEventPropagation}
          onPointerDown={stopEventPropagation}
          onMouseDown={stopEventPropagation}
        >
          {/* Camera Scanner Section */}
          {showCamera &&
            (qrCamera.scanMode === QRScanMode.CAMERA || qrCamera.scanMode === QRScanMode.AUTO) && (
              <div className="qr-scanner-camera-section">
                {/* Camera Feed */}
                <div className="qr-scanner-camera-container">
                  <video
                    ref={qrCamera.videoRef}
                    className={`qr-scanner-video${isVideoReady ? ' is-ready' : ''}`}
                    style={{
                      transform: qrCamera.isFrontCamera ? 'scaleX(-1)' : 'none',
                    }}
                    playsInline
                    autoPlay
                    muted
                    onCanPlay={() => setIsVideoReady(true)}
                    onLoadedData={() => setIsVideoReady(true)}
                  />
                  <canvas ref={qrCamera.canvasRef} className="qr-scanner-canvas" />

                  {/* Scanner Overlay */}
                  <div className="qr-scanner-overlay">
                    <div className="qr-scanner-box" />
                  </div>
                </div>

                {/* Instructions */}
                <div className="qr-scanner-instructions">
                  <p>Position the QR code within the frame</p>
                  {qrCamera.isScanning && (
                    <p className="qr-scanner-sub-instruction qr-scanner-sub-instruction--small">
                      Scanning...
                    </p>
                  )}
                </div>

                {/* Camera Controls */}
                {qrCamera.cameras.length > 1 && (
                  <div className="qr-scanner-camera-controls">
                    <select
                      name="camera"
                      value={qrCamera.selectedCamera}
                      onChange={(e) => qrCamera.handleCameraChange(e.target.value)}
                      className="qr-scanner-camera-selector"
                    >
                      {qrCamera.cameras.map((camera) => (
                        <option key={camera.deviceId} value={camera.deviceId}>
                          {camera.label || `Camera ${camera.deviceId.substring(0, 8)}...`}
                        </option>
                      ))}
                    </select>
                  </div>
                )}
              </div>
            )}
        </div>

        {/* Close Button */}
        <button
          onClick={(event) => {
            event.stopPropagation();
            stopPropagationNative(event);
            handleClose();
          }}
          className="qr-scanner-close"
        >
          ✕
        </button>
      </div>
    </Theme>
  );
};

export default QRCodeScanner;
