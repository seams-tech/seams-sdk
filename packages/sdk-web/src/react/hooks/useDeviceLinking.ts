import { useRef, useCallback } from 'react';
import { useSeams } from '../context';
import type { QrLinkedDeviceSessionPayloadV4 } from '@shared/device-linking';
import type { LinkDeviceFlowEvent } from '@/core/types/sdkSentEvents';
import { QRScanMode } from '@/react/hooks/useQRCamera';

export interface UseDeviceLinkingOptions {
  onError?: (error: Error) => void;
  onClose?: () => void;
  onEvent?: (event: LinkDeviceFlowEvent) => void;
}

export interface UseDeviceLinkingReturn {
  linkDevice: (qrData: QrLinkedDeviceSessionPayloadV4, source: QRScanMode) => Promise<void>;
}

export const useDeviceLinking = (options: UseDeviceLinkingOptions): UseDeviceLinkingReturn => {
  const { seams } = useSeams();
  const { onError, onClose, onEvent } = options;

  const callbacksRef = useRef({
    onError,
    onClose,
    onEvent,
  });

  callbacksRef.current = {
    onError,
    onClose,
    onEvent,
  };

  const linkDevice = useCallback(
    async (qrData: QrLinkedDeviceSessionPayloadV4, _source: QRScanMode) => {
      const { onError, onClose, onEvent } = callbacksRef.current;
      try {
        await seams.devices.scanAndLinkDevice(qrData, {
          onEvent,
        });
      } catch (linkingError: unknown) {
        onError?.(linkingError instanceof Error ? linkingError : new Error(String(linkingError)));
        onClose?.();
      }
    },
    [seams],
  );

  return {
    linkDevice,
  };
};
