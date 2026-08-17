import type { ActionResult } from './seams';
import type { AfterCall, EventCallback, LinkDeviceFlowEvent } from './sdkSentEvents';
import type { ConfirmationConfig } from './signer-worker';
import type { LinkedDeviceSessionState, QrLinkedDeviceSessionPayloadV4 } from '@shared/device-linking';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
} from '@shared/signing-lanes/ids';
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
      /**
       * Refactor 103 Phase 8. The canonical owner finalize committed Device 2's
       * credential and advanced the session in one transaction, which is the
       * whole of the handoff. There is no lane enrollment on this path and so no
       * aggregate receipt to report.
       */
      readonly kind: 'owner_handoff_complete';
      readonly walletId: WalletId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly deviceId: LinkedDeviceId;
      readonly manifestDigestB64u?: never;
      readonly receipt?: never;
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
