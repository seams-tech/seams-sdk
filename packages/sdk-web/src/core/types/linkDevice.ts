import type { ActionResult } from './seams';
import type { AfterCall, EventCallback, LinkDeviceFlowEvent } from './sdkSentEvents';
import { LinkDeviceEventPhase } from './sdkSentEvents';
import { AccountId } from './accountIds';
import type { ConfirmationConfig } from './signer-worker';

export { LinkDeviceEventPhase } from './sdkSentEvents';

export interface DeviceLinkingQRData {
  sessionId: string;
  accountId?: AccountId;
  timestamp: number;
  version: string;
}

export interface DeviceLinkingSession {
  sessionId: string;
  phase: LinkDeviceEventPhase;
  createdAt: number;
  expiresAt: number;
}

export type LinkDeviceResult = Extract<ActionResult, { success: false }>;

export class DeviceLinkingError extends Error {
  constructor(
    message: string,
    public code: DeviceLinkingErrorCode,
    public phase: 'generation' | 'authorization' | 'registration',
  ) {
    super(message);
  }
}

export enum DeviceLinkingErrorCode {
  INVALID_QR_DATA = 'INVALID_QR_DATA',
  ACCOUNT_NOT_OWNED = 'ACCOUNT_NOT_OWNED',
  AUTHORIZATION_TIMEOUT = 'AUTHORIZATION_TIMEOUT',
  INSUFFICIENT_BALANCE = 'INSUFFICIENT_BALANCE',
  REGISTRATION_FAILED = 'REGISTRATION_FAILED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  UNSUPPORTED = 'UNSUPPORTED',
}

export type StartDevice2LinkingFlowArgs = {
  ui?: 'modal' | 'inline';
  /**
   * Optional preferred signer slot for the new passkey credential (1-indexed).
   * When omitted, device2 will attempt `2` and auto-increment on duplicate.
   */
  signerSlot?: number;
} & StartDeviceLinkingOptionsDevice2;

export interface StartDevice2LinkingFlowResults {
  qrData: DeviceLinkingQRData;
  qrCodeDataURL: string;
}

export interface StartDeviceLinkingOptionsDevice2 {
  cameraId?: string;
  options?: {
    onEvent?: EventCallback<LinkDeviceFlowEvent>;
    onError?: (error: Error) => void;
    afterCall?: AfterCall<any>;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
  };
}

export interface ScanAndLinkDeviceOptionsDevice1 {
  fundingAmount: string;
  onEvent?: EventCallback<LinkDeviceFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<any>;
  confirmationConfig?: Partial<ConfirmationConfig>;
  confirmerText?: { title?: string; body?: string };
}
