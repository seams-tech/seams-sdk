import type { DeviceLinkingWebContext } from '@/SeamsWeb/signingSurface/types';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
} from '@/core/types/linkDevice';
import { DeviceLinkingError, DeviceLinkingErrorCode } from '@/core/types/linkDevice';
import {
  createLinkDeviceFlowEvent,
  LinkDeviceEventPhase,
  type CreateLinkDeviceFlowEventInput,
} from '@/core/types/sdkSentEvents';
import { validateNearAccountId } from '@shared/utils/validation';

const LINK_DEVICE_REFACTOR_84_MESSAGE =
  'Linked-device lane creation is disabled until refactor 84 lands';
const LINK_DEVICE_QR_MAX_AGE_MS = 15 * 60 * 1000;

type EmitLinkDeviceEventInput = Omit<CreateLinkDeviceFlowEventInput, 'flowId' | 'accountId'> & {
  accountId?: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object');
}

function createInvalidQrError(message: string): DeviceLinkingError {
  return new DeviceLinkingError(message, DeviceLinkingErrorCode.INVALID_QR_DATA, 'authorization');
}

function createUnsupportedScannerError(): DeviceLinkingError {
  return new DeviceLinkingError(
    LINK_DEVICE_REFACTOR_84_MESSAGE,
    DeviceLinkingErrorCode.UNSUPPORTED,
    'authorization',
  );
}

function flowIdForQrData(qrData: DeviceLinkingQRData): string {
  const sessionId = String(qrData?.sessionId || '').trim();
  return sessionId || 'link-device-scan:refactor-84-stub';
}

function emitScannerLinkDeviceEvent(
  onEvent: ScanAndLinkDeviceOptionsDevice1['onEvent'] | undefined,
  qrData: DeviceLinkingQRData,
  event: EmitLinkDeviceEventInput,
): void {
  onEvent?.(
    createLinkDeviceFlowEvent({
      flowId: flowIdForQrData(qrData),
      ...(event.accountId ? { accountId: event.accountId } : {}),
      ...event,
      data: {
        role: 'scanner',
        ...(event.data || {}),
      },
    }),
  );
}

function notifyScannerError(
  onError: ScanAndLinkDeviceOptionsDevice1['onError'] | undefined,
  error: Error,
): void {
  try {
    onError?.(error);
  } catch {
    // Callback failures must not replace the link-device stub error.
  }
}

function emitScannerFailure(args: {
  onEvent: ScanAndLinkDeviceOptionsDevice1['onEvent'] | undefined;
  qrData: DeviceLinkingQRData;
  error: DeviceLinkingError;
  retryable: boolean;
}): void {
  emitScannerLinkDeviceEvent(args.onEvent, args.qrData, {
    phase: LinkDeviceEventPhase.FAILED,
    status: 'failed',
    message: args.error.message,
    interaction: {
      kind: 'qr_scan',
      overlay: 'none',
    },
    error: {
      code: args.error.code,
      message: args.error.message,
      retryable: args.retryable,
    },
  });
}

export async function linkDeviceWithScannedQRData(
  _context: DeviceLinkingWebContext,
  qrData: DeviceLinkingQRData,
  options: ScanAndLinkDeviceOptionsDevice1,
): Promise<LinkDeviceResult> {
  const onEvent = options?.onEvent;
  const onError = options?.onError;

  emitScannerLinkDeviceEvent(onEvent, qrData, {
    phase: LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED,
    status: 'running',
    interaction: {
      kind: 'qr_scan',
      overlay: 'none',
    },
  });

  try {
    validateDeviceLinkingQRData(qrData);
  } catch (error: unknown) {
    const deviceLinkingError =
      error instanceof DeviceLinkingError ? error : createInvalidQrError(String(error || ''));
    emitScannerFailure({
      onEvent,
      qrData,
      error: deviceLinkingError,
      retryable: true,
    });
    notifyScannerError(onError, deviceLinkingError);
    throw deviceLinkingError;
  }

  const error = createUnsupportedScannerError();
  emitScannerFailure({
    onEvent,
    qrData,
    error,
    retryable: false,
  });
  notifyScannerError(onError, error);
  throw error;
}

export function validateDeviceLinkingQRData(qrData: DeviceLinkingQRData): void {
  if (!isRecord(qrData)) {
    throw createInvalidQrError('QR data must be an object');
  }

  const sessionId = String(qrData.sessionId || '').trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{7,127}$/.test(sessionId)) {
    throw createInvalidQrError('Invalid sessionId');
  }

  const version = String(qrData.version || '').trim();
  if (!version) {
    throw createInvalidQrError('Missing version');
  }

  const timestamp = Number(qrData.timestamp);
  if (!Number.isFinite(timestamp) || timestamp <= 0) {
    throw createInvalidQrError('Missing timestamp');
  }

  if (Date.now() - timestamp > LINK_DEVICE_QR_MAX_AGE_MS) {
    throw new DeviceLinkingError(
      'QR code expired',
      DeviceLinkingErrorCode.SESSION_EXPIRED,
      'authorization',
    );
  }

  if (qrData.accountId) {
    validateNearAccountId(qrData.accountId);
  }
}
