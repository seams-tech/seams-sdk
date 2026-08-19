import type { ActionResult } from './seams';
import type { AfterCall, EventCallback, LinkDeviceFlowEvent } from './sdkSentEvents';
import type { ConfirmationConfig } from './signer-worker';
import type {
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceSessionState,
  QrLinkedDeviceSessionPayloadV5,
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
  readonly qrData: QrLinkedDeviceSessionPayloadV5;
};

export type LinkDeviceResult =
  | {
      readonly success: true;
      /** The target's additive Ed25519/ECDSA lane enrollment is active. */
      readonly kind: 'lane_enrollment_complete';
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly manifestDigestB64u: DigestB64u;
      readonly receipt: LinkedDeviceEnrollmentReceiptV1;
      readonly error?: never;
    }
  | (Extract<ActionResult, { success: false }> & {
      readonly kind?: never;
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
  /**
   * R103 zero-prompt handoff: Device 1 is not unlocked with the custody
   * capability linking needs. The QR flow never prompts; the user unlocks the
   * wallet and scans again.
   */
  WALLET_UNLOCK_REQUIRED = 'WALLET_UNLOCK_REQUIRED',
  SESSION_EXPIRED = 'SESSION_EXPIRED',
  UNSUPPORTED = 'UNSUPPORTED',
}

export type StartDevice2LinkingFlowArgs = {
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  ui?: 'modal' | 'inline';
} & StartDeviceLinkingOptionsDevice2;

export interface StartDevice2LinkingFlowResults {
  readonly qrData: QrLinkedDeviceSessionPayloadV5;
  readonly qrCodeDataURL: string;
}

export type LinkedDeviceTargetPasskeyActivationV1 = {
  readonly kind: 'linked_device_target_passkey_activation_v1';
  readonly createPasskey: () => Promise<void>;
};

/**
 * Public state for the target Email OTP activation. The challenge identity and
 * OTP remain inside the operation; the browser receives display-safe timing
 * and destination data only.
 */
export type LinkedDeviceEmailOtpActivationStateV1 =
  | {
      readonly kind: 'sending';
      readonly maskedEmailHint: string;
      readonly expiresAtMs?: never;
      readonly resendAvailableAtMs?: never;
      readonly message?: never;
    }
  | {
      readonly kind: 'code_input';
      readonly maskedEmailHint: string;
      readonly expiresAtMs: number;
      readonly resendAvailableAtMs: number;
      readonly message?: never;
    }
  | {
      readonly kind: 'submitting';
      readonly maskedEmailHint: string;
      readonly expiresAtMs: number;
      readonly resendAvailableAtMs: number;
      readonly message?: never;
    }
  | {
      readonly kind: 'incorrect';
      readonly maskedEmailHint: string;
      readonly expiresAtMs: number;
      readonly resendAvailableAtMs: number;
      readonly message: string;
    }
  | {
      readonly kind: 'resending';
      readonly maskedEmailHint: string;
      readonly expiresAtMs?: never;
      readonly resendAvailableAtMs?: never;
      readonly message?: never;
    }
  | {
      readonly kind: 'expired';
      readonly maskedEmailHint: string;
      readonly expiresAtMs?: never;
      readonly resendAvailableAtMs?: never;
      readonly message: string;
    }
  | {
      readonly kind: 'unavailable';
      readonly maskedEmailHint?: never;
      readonly expiresAtMs?: never;
      readonly resendAvailableAtMs?: never;
      readonly message: string;
    }
  | {
      readonly kind: 'completed';
      readonly maskedEmailHint: string;
      readonly expiresAtMs?: never;
      readonly resendAvailableAtMs?: never;
      readonly message?: never;
    };

export type LinkedDeviceTargetEmailOtpActivationV1 = {
  readonly kind: 'linked_device_target_email_otp_activation_v1';
  readonly state: LinkedDeviceEmailOtpActivationStateV1;
  readonly sendCode: () => Promise<void>;
  readonly submitCode: (otpCode: string) => Promise<void>;
  readonly resendCode: () => Promise<void>;
};

export type LinkedDeviceTargetFactorActivationV1 =
  | LinkedDeviceTargetPasskeyActivationV1
  | LinkedDeviceTargetEmailOtpActivationV1;

export interface StartDeviceLinkingOptionsDevice2 {
  cameraId?: string;
  options?: {
    onEvent?: EventCallback<LinkDeviceFlowEvent>;
    onError?: (error: Error) => void;
    /** Receives one immutable activation snapshot for each target-factor transition. */
    onTargetFactorRequired?: (activation: LinkedDeviceTargetFactorActivationV1) => void;
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
export type { LinkedDeviceTargetFactorV1 } from '@shared/device-linking';
