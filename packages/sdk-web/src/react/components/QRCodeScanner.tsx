import React, { useCallback, useEffect, useState } from 'react';
import type { DeviceLinkingQRData } from '@/core/types/linkDevice';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import { useQRCamera, QRScanMode } from '../hooks/useQRCamera';
import { useDeviceLinking } from '../hooks/useDeviceLinking';
import { Theme, useTheme } from './theme';

/**
 * QR scanner shell kept for the refactor-84 link-device replacement.
 */
export interface QRCodeScannerProps {
  onQRCodeScanned?: (qrData: DeviceLinkingQRData) => void;
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: LinkDeviceFlowEvent) => void;
  fundingAmount?: string;
  isOpen?: boolean;
  cameraId?: string;
  className?: string;
  style?: React.CSSProperties;
  showCamera?: boolean;
}

export const QRCodeScanner: React.FC<QRCodeScannerProps> = ({
  onQRCodeScanned,
  onError,
  onClose,
  onEvent,
  fundingAmount = '0.05', // 0.05 NEAR
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

  const { linkDevice } = useDeviceLinking({
    onError,
    onClose,
    onEvent,
    fundingAmount,
  });

  const qrCamera = useQRCamera({
    onQRDetected: async (qrData: DeviceLinkingQRData) => {
      onQRCodeScanned?.(qrData);
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
    }
  }, [isOpen]);

  // Camera Cleanup Point 1: User-initiated close
  const handleClose = useCallback(() => {
    qrCamera.stopScanning();
    onClose?.();
  }, [qrCamera.stopScanning, qrCamera.isScanning, qrCamera.videoRef, onClose]);

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
      if (qrCamera.isScanning) {
        qrCamera.stopScanning();
      }
    };
  }, []);

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
                    <div className="qr-scanner-box">
                      <div className="qr-scanner-corner-top-left" />
                      <div className="qr-scanner-corner-top-right" />
                      <div className="qr-scanner-corner-bottom-left" />
                      <div className="qr-scanner-corner-bottom-right" />
                    </div>
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
