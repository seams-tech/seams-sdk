import React, { useCallback, useEffect, useRef, useState } from 'react';
import type {
  LinkedDeviceEmailOtpBaseFactorChoiceV1,
  QrLinkedDeviceSessionPayloadV5,
} from '@shared/device-linking';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { classifyLinkDeviceFlowEvent, type LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import { DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import { useQRCamera, QRScanMode } from '../hooks/useQRCamera';
import { useDeviceLinking } from '../hooks/useDeviceLinking';
import { useSeams } from '../context';
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

type ScannerLifecycleState =
  | { readonly kind: 'scanning' }
  | { readonly kind: 'linking' }
  | { readonly kind: 'expired' };

type FocusIntent = 'scanner' | 'email' | 'progress' | 'return' | null;

function focusElement(element: HTMLElement | null): void {
  if (!element || !element.isConnected) return;
  if (element.closest('[aria-hidden="true"]')) return;
  element.focus({ preventScroll: true });
}

function focusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll<HTMLElement>(
      'button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => !element.closest('[aria-hidden="true"]'));
}

function focusFirstElement(container: HTMLElement | null): void {
  if (!container) return;
  focusElement(focusableElements(container)[0] ?? container);
}

function restorableFocusElement(): HTMLElement | null {
  const activeElement = document.activeElement;
  if (!(activeElement instanceof HTMLElement)) return null;
  if (activeElement instanceof HTMLIFrameElement) return null;
  if (activeElement.closest('[aria-hidden="true"]')) return null;
  return activeElement;
}

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
  const { cancelDeviceLinking } = useSeams();
  const scopedTokens = React.useMemo(
    () => (theme === 'dark' ? { dark: tokens } : { light: tokens }),
    [theme, tokens],
  );

  const scannedPayloadRef = React.useRef<QrLinkedDeviceSessionPayloadV5 | null>(null);
  const completionReportedRef = React.useRef(false);
  const closeReportedRef = React.useRef(false);
  const linkStartedRef = React.useRef(false);
  const linkExpiredRef = React.useRef(false);
  const cancellationRequestedRef = React.useRef(false);
  const stopScanningRef = React.useRef<(() => void) | null>(null);
  const previousIsOpenRef = React.useRef(false);
  const returnFocusRef = React.useRef<HTMLElement | null>(null);
  const focusIntentRef = React.useRef<FocusIntent>(null);
  const scannerPanelRef = React.useRef<HTMLDivElement | null>(null);
  const progressTitleRef = React.useRef<HTMLHeadingElement | null>(null);
  const closeButtonRef = React.useRef<HTMLButtonElement | null>(null);
  const pendingEmailOtpSelectionRef = useRef<PendingEmailOtpBaseFactorSelection | null>(null);
  const [scannerState, setScannerState] = useState<ScannerLifecycleState>({ kind: 'scanning' });
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
      focusIntentRef.current = 'email';
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

  const reportClose = useCallback(() => {
    if (closeReportedRef.current) return;
    closeReportedRef.current = true;
    onClose?.();
  }, [onClose]);

  const handleLinkDeviceEvent = React.useCallback(
    (event: LinkDeviceFlowEvent) => {
      onEvent?.(event);
      const outcome = classifyLinkDeviceFlowEvent(event);
      if (
        outcome.kind === 'failed' &&
        event.error?.code === DeviceLinkingErrorCode.SESSION_EXPIRED
      ) {
        linkExpiredRef.current = true;
        rejectPendingEmailOtpSelection(new Error('Device linking expired'));
        focusIntentRef.current = 'progress';
        setScannerState({ kind: 'expired' });
        return;
      }
      if (outcome.kind !== 'active' || completionReportedRef.current) return;
      const scannedPayload = scannedPayloadRef.current;
      if (!scannedPayload) return;
      completionReportedRef.current = true;
      onQRCodeScanned?.(scannedPayload);
      reportClose();
    },
    [onEvent, onQRCodeScanned, rejectPendingEmailOtpSelection, reportClose],
  );

  const handleFlowClose = useCallback(() => {
    if (linkExpiredRef.current) return;
    rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
    reportClose();
  }, [rejectPendingEmailOtpSelection, reportClose]);

  const { linkDevice } = useDeviceLinking({
    onError,
    onClose: handleFlowClose,
    onEvent: handleLinkDeviceEvent,
    onEmailOtpBaseFactorRequired: requestEmailOtpBaseFactor,
  });

  const qrCamera = useQRCamera({
    onQRDetected: async (qrData: QrLinkedDeviceSessionPayloadV5) => {
      if (linkStartedRef.current) return;
      linkStartedRef.current = true;
      scannedPayloadRef.current = qrData;
      stopScanningRef.current?.();
      setScannerState({ kind: 'linking' });
      focusIntentRef.current = 'progress';
      await linkDevice(qrData, QRScanMode.CAMERA);
    },
    onError,
    isOpen: showCamera ? isOpen : false, // Only active when camera should be shown
    cameraId,
  });
  const stopScanning = qrCamera.stopScanning;
  stopScanningRef.current = stopScanning;

  const [isVideoReady, setIsVideoReady] = useState(false);

  // Reset video ready state when modal opens so we can re-fade
  useEffect(() => {
    if (isOpen) {
      setIsVideoReady(false);
      setScannerState({ kind: 'scanning' });
      scannedPayloadRef.current = null;
      completionReportedRef.current = false;
      closeReportedRef.current = false;
      linkStartedRef.current = false;
      linkExpiredRef.current = false;
      cancellationRequestedRef.current = false;
      focusIntentRef.current = 'scanner';
    }
    /* Both transitions settle the pending chooser. Open: a stale selection
       must not answer the new scan. Closed: a parent driving `isOpen` false
       while the component stays mounted is the exit the unmount cleanup never
       sees - left unrejected, the host coroutine stays parked on the chooser
       and the claimed session is held until it expires. */
    rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
  }, [isOpen, rejectPendingEmailOtpSelection]);

  useEffect(() => {
    const wasOpen = previousIsOpenRef.current;
    if (isOpen && !wasOpen) {
      returnFocusRef.current = restorableFocusElement();
      closeReportedRef.current = false;
      cancellationRequestedRef.current = false;
      focusIntentRef.current = 'scanner';
    }
    if (!isOpen && wasOpen) {
      focusIntentRef.current = 'return';
    }
    previousIsOpenRef.current = isOpen;
  }, [isOpen]);

  useEffect(() => {
    if (isOpen && qrCamera.error) {
      focusIntentRef.current = 'scanner';
    }
  }, [isOpen, qrCamera.error]);

  useEffect(() => {
    const intent = focusIntentRef.current;
    if (!intent) return;
    focusIntentRef.current = null;

    switch (intent) {
      case 'scanner':
        focusElement(closeButtonRef.current);
        break;
      case 'email':
        focusFirstElement(scannerPanelRef.current);
        break;
      case 'progress':
        focusElement(progressTitleRef.current);
        break;
      case 'return':
        focusElement(returnFocusRef.current);
        break;
      default: {
        const exhaustiveIntent: never = intent;
        return exhaustiveIntent;
      }
    }
  }, [emailOtpSelection?.kind, isOpen, qrCamera.error, scannerState.kind]);

  useEffect(() => {
    return () => {
      if (previousIsOpenRef.current) {
        focusElement(returnFocusRef.current);
      }
    };
  }, []);

  // Camera Cleanup Point 1: User-initiated close
  const cancelActiveLink = useCallback(() => {
    if (scannerState.kind === 'scanning') return;
    if (cancellationRequestedRef.current || completionReportedRef.current) return;
    cancellationRequestedRef.current = true;
    void cancelDeviceLinking().catch(() => undefined);
  }, [cancelDeviceLinking, scannerState.kind]);

  const handleClose = useCallback(() => {
    stopScanning();
    cancelActiveLink();
    handleFlowClose();
  }, [cancelActiveLink, handleFlowClose, stopScanning]);

  const handleCancelLinking = useCallback(() => {
    stopScanning();
    cancelActiveLink();
    handleFlowClose();
  }, [cancelActiveLink, handleFlowClose, stopScanning]);

  const handleRetryExpiredLink = useCallback(() => {
    linkExpiredRef.current = false;
    linkStartedRef.current = false;
    scannedPayloadRef.current = null;
    cancellationRequestedRef.current = false;
    focusIntentRef.current = 'scanner';
    setScannerState({ kind: 'scanning' });
    void qrCamera.startScanning();
  }, [qrCamera]);

  const handleDismissExpiredLink = useCallback(() => {
    linkExpiredRef.current = false;
    reportClose();
  }, [reportClose]);

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

  const isFocusTrapActive =
    scannerState.kind === 'scanning' || emailOtpSelection !== null || qrCamera.error !== null;

  const handleModalKeyDown = useCallback(
    (event: React.KeyboardEvent<HTMLDivElement>) => {
      if (event.key !== 'Tab' || !isFocusTrapActive) return;
      const elements = focusableElements(event.currentTarget);
      if (elements.length === 0) {
        event.preventDefault();
        focusElement(scannerPanelRef.current);
        return;
      }

      const activeElement = document.activeElement;
      const activeIndex =
        activeElement instanceof HTMLElement ? elements.indexOf(activeElement) : -1;
      if (event.shiftKey && (activeIndex <= 0 || activeIndex === -1)) {
        event.preventDefault();
        focusElement(elements[elements.length - 1]);
      } else if (!event.shiftKey && (activeIndex === elements.length - 1 || activeIndex === -1)) {
        event.preventDefault();
        focusElement(elements[0]);
      }
    },
    [isFocusTrapActive],
  );

  // Camera Cleanup Point 2: Component unmount
  useEffect(() => {
    return () => {
      rejectPendingEmailOtpSelection(new Error('Device linking was cancelled'));
      stopScanning();
    };
  }, [rejectPendingEmailOtpSelection, stopScanning]);

  // Camera Cleanup Point 3: Modal and scanner state changes
  useEffect(() => {
    if ((!isOpen || scannerState.kind !== 'scanning') && qrCamera.isScanning) {
      stopScanning();
    }
  }, [isOpen, qrCamera.isScanning, scannerState.kind, stopScanning]);

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
        <div
          className={`qr-scanner-modal qr-scanner-modal--error ${className || ''}`}
          style={style}
          role="dialog"
          aria-modal="true"
          aria-labelledby="qr-scanner-error-title"
          onKeyDown={handleModalKeyDown}
          onClick={handleBackdropClick}
          onPointerDown={stopEventPropagation}
          onMouseDown={stopEventPropagation}
        >
          <div className="qr-scanner-error-message">
            <h2 id="qr-scanner-error-title">Unable to scan a QR code</h2>
            <p role="alert">{qrCamera.error}</p>
            <button
              type="button"
              onClick={() => qrCamera.setError(null)}
              className="qr-scanner-error-button"
            >
              Try Again
            </button>
            <button
              ref={closeButtonRef}
              type="button"
              onClick={handleClose}
              className="qr-scanner-error-button"
            >
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
          role="dialog"
          aria-modal="true"
          aria-labelledby="qr-scanner-email-selection-title"
          onKeyDown={handleModalKeyDown}
          onClick={handleBackdropClick}
          onPointerDown={stopEventPropagation}
          onMouseDown={stopEventPropagation}
        >
          <section
            ref={scannerPanelRef}
            className="qr-scanner-panel qr-scanner-email-selection"
            tabIndex={-1}
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
          <button
            ref={closeButtonRef}
            type="button"
            aria-label="Close scanner"
            onClick={handleClose}
            className="qr-scanner-close"
          >
            <span aria-hidden="true">✕</span>
          </button>
        </div>
      </Theme>
    );
  }

  return (
    <Theme theme={theme} tokens={scopedTokens}>
      <div
        className={`qr-scanner-modal${scannerState.kind === 'linking' ? ' qr-scanner-modal--linking' : ''} ${className || ''}`}
        style={style}
        role={isFocusTrapActive ? 'dialog' : 'region'}
        aria-modal={isFocusTrapActive ? true : undefined}
        aria-labelledby="qr-scanner-title"
        onKeyDown={handleModalKeyDown}
        onClick={handleBackdropClick}
        onPointerDown={stopEventPropagation}
        onMouseDown={stopEventPropagation}
      >
        <div
          ref={scannerPanelRef}
          className={`qr-scanner-panel${scannerState.kind === 'linking' || scannerState.kind === 'expired' ? ' qr-scanner-progress-panel' : ''}`}
          tabIndex={-1}
          onClick={stopEventPropagation}
          onPointerDown={stopEventPropagation}
          onMouseDown={stopEventPropagation}
        >
          <h2 id="qr-scanner-title" className="qr-scanner-visually-hidden">
            Scan and link a device
          </h2>
          {scannerState.kind === 'expired' ? (
            <div className="qr-scanner-progress" aria-labelledby="qr-scanner-progress-title">
              <h2 id="qr-scanner-progress-title" ref={progressTitleRef} tabIndex={-1}>
                Linking expired
              </h2>
              <p className="qr-scanner-progress-message" role="alert">
                This linking request expired. Scan the QR code again to retry.
              </p>
              <div className="qr-scanner-progress-actions">
                <button
                  type="button"
                  className="qr-scanner-progress-cancel"
                  onClick={handleDismissExpiredLink}
                >
                  Close
                </button>
                <button
                  type="button"
                  className="qr-scanner-progress-primary"
                  onClick={handleRetryExpiredLink}
                >
                  Try again
                </button>
              </div>
            </div>
          ) : scannerState.kind === 'linking' ? (
            <div className="qr-scanner-progress" aria-labelledby="qr-scanner-progress-title">
              <h2 id="qr-scanner-progress-title" ref={progressTitleRef} tabIndex={-1}>
                Linking device
              </h2>
              <div className="qr-scanner-progress-dots" aria-hidden="true">
                <span />
                <span />
                <span />
              </div>
              <p className="qr-scanner-progress-message" role="status" aria-live="polite">
                Continue linking on your other device.
              </p>
              <div className="qr-scanner-progress-actions">
                <button
                  type="button"
                  className="qr-scanner-progress-cancel"
                  onClick={handleCancelLinking}
                >
                  Cancel linking
                </button>
              </div>
            </div>
          ) : (
            showCamera &&
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
            )
          )}
        </div>

        {scannerState.kind === 'scanning' && (
          <button
            ref={closeButtonRef}
            type="button"
            aria-label="Close scanner"
            onClick={(event) => {
              event.stopPropagation();
              stopPropagationNative(event);
              handleClose();
            }}
            className="qr-scanner-close"
          >
            <span aria-hidden="true">✕</span>
          </button>
        )}
      </div>
    </Theme>
  );
};

export default QRCodeScanner;
