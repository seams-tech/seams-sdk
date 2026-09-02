import { useRef, useCallback } from 'react';
import { useSeams } from '../context';
import type { QrLinkedDeviceSessionPayloadV5 } from '@shared/device-linking';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import type { ScanAndLinkDeviceOptionsDevice1 } from '@/core/types/linkDevice';
import { QRScanMode } from '@/react/hooks/useQRCamera';

export interface UseDeviceLinkingOptions {
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: LinkDeviceFlowEvent) => void;
  onEmailOtpBaseFactorRequired?: ScanAndLinkDeviceOptionsDevice1['onEmailOtpBaseFactorRequired'];
}

export interface UseDeviceLinkingReturn {
  linkDevice: (qrData: QrLinkedDeviceSessionPayloadV5, source: QRScanMode) => Promise<void>;
}

export const useDeviceLinking = (options: UseDeviceLinkingOptions): UseDeviceLinkingReturn => {
  const { seams } = useSeams();
  const { onError, onClose, onEvent, onEmailOtpBaseFactorRequired } = options;

  const callbacksRef = useRef({
    onError,
    onClose,
    onEvent,
    onEmailOtpBaseFactorRequired,
  });

  callbacksRef.current = {
    onError,
    onClose,
    onEvent,
    onEmailOtpBaseFactorRequired,
  };

  const linkDevice = useCallback(
    async (qrData: QrLinkedDeviceSessionPayloadV5, _source: QRScanMode) => {
      const { onError, onClose, onEvent, onEmailOtpBaseFactorRequired } = callbacksRef.current;
      try {
        await seams.devices.scanAndLinkDevice(qrData, {
          onEvent,
          onEmailOtpBaseFactorRequired,
        });
      } catch (linkingError: unknown) {
        onClose?.();
        onError?.(linkingError instanceof Error ? linkingError : new Error(String(linkingError)));
      }
    },
    [seams],
  );

  return {
    linkDevice,
  };
};
