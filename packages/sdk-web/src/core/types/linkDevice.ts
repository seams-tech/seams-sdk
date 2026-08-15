import type { ActionResult } from './seams';
import type { AfterCall, EventCallback, LinkDeviceFlowEvent } from './sdkSentEvents';
import type { ConfirmationConfig } from './signer-worker';
import type {
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceSessionState,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletId } from '@shared/utils/domainIds';

export { LinkDeviceEventPhase } from './sdkSentEvents';

/** Public browser projection of the exhaustive shared session state. */
export type DeviceLinkingSession = {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly state: LinkedDeviceSessionState;
  readonly qrData: QrLinkedDeviceSessionPayloadV4;
};

export type LinkDeviceResult =
  | {
      readonly success: true;
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
      readonly error?: never;
    }
  | (Extract<ActionResult, { success: false }> & {
      readonly walletId?: never;
      readonly enrollmentId?: never;
      readonly deviceId?: never;
      readonly manifestDigestB64u?: never;
      readonly receipt?: never;
    });

export class DeviceLinkingError extends Error {
  readonly name = 'DeviceLinkingError';

  constructor(
    message: string,
    readonly code: DeviceLinkingErrorCode,
    readonly phase: 'generation' | 'authorization' | 'registration',
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
} & StartDeviceLinkingOptionsDevice2;

export interface StartDevice2LinkingFlowResults {
  readonly qrData: QrLinkedDeviceSessionPayloadV4;
  readonly qrCodeDataURL: string;
}

export type LinkedDeviceTargetPasskeyActivationV1 = {
  readonly kind: 'linked_device_target_passkey_activation_v1';
  readonly createPasskey: () => Promise<void>;
};

export interface StartDeviceLinkingOptionsDevice2 {
  cameraId?: string;
  options?: {
    onEvent?: EventCallback<LinkDeviceFlowEvent>;
    onError?: (error: Error) => void;
    onTargetPasskeyRequired?: (activation: LinkedDeviceTargetPasskeyActivationV1) => void;
    afterCall?: AfterCall<StartDevice2LinkingFlowResults>;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    /** Internal-only test/runtime port injection; omitted from serialized API requests. */
    readonly ports?: never;
  };
}

export interface ScanAndLinkDeviceOptionsDevice1 {
  onEvent?: EventCallback<LinkDeviceFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LinkDeviceResult>;
  confirmationConfig?: Partial<ConfirmationConfig>;
  confirmerText?: { title?: string; body?: string };
}

export type { LinkDevicePublicKeyB64u } from '@shared/device-linking';
