import type { ParentToChildEnvelope, ParentToChildType } from '../shared/messages';

type WalletHostRequest<T extends ParentToChildType> = ParentToChildEnvelope & { type: T };

export type BootWalletRequestType = 'PING' | 'PM_SET_CONFIG' | 'PM_CANCEL';
export type NearWalletRequestType =
  | 'PM_REGISTRATION_ACTIVATION_PREPARE'
  | 'PM_REGISTRATION_ACTIVATION_CANCEL'
  | 'PM_REGISTRATION_ACTIVATION_FOCUS'
  | 'PM_REGISTER_WALLET'
  | 'PM_ADD_WALLET_SIGNER'
  | 'PM_PREFETCH_BLOCKHEIGHT'
  | 'PM_SIGN_TX_WITH_ACTIONS'
  | 'PM_SIGN_AND_SEND_TX'
  | 'PM_SEND_TRANSACTION'
  | 'PM_EXECUTE_ACTION'
  | 'PM_SIGN_DELEGATE_ACTION'
  | 'PM_SIGN_NEP413';
export type AuthWalletRequestType =
  | 'PM_UNLOCK'
  | 'PM_LOCK'
  | 'PM_GET_WALLET_SESSION'
  | 'PM_GET_RECENT_UNLOCKS';
export type EcdsaWalletRequestType =
  | 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'
  | 'PM_SIGN_TEMPO'
  | 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'
  | 'PM_REPORT_TEMPO_BROADCAST_REJECTED'
  | 'PM_REPORT_TEMPO_FINALIZED'
  | 'PM_REPORT_TEMPO_DROPPED_OR_REPLACED'
  | 'PM_RECONCILE_TEMPO_NONCE_LANE'
  | 'PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL';
export type EmailOtpWalletRequestType =
  | 'PM_REQUEST_EMAIL_OTP_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE'
  | 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION'
  | 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL'
  | 'PM_ENROLL_EMAIL_OTP'
  | 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'
  | 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'
  | 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'
  | 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS'
  | 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES'
  | 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES';
export type RecoveryWalletRequestType =
  | 'PM_GET_RECOVERY_EMAILS'
  | 'PM_SET_RECOVERY_EMAILS'
  | 'PM_START_EMAIL_RECOVERY'
  | 'PM_FINALIZE_EMAIL_RECOVERY'
  | 'PM_STOP_EMAIL_RECOVERY'
  | 'PM_SYNC_ACCOUNT_FLOW';
export type ExportWalletRequestType =
  | 'PM_EXPORT_KEYPAIR_UI'
  | 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI';
export type DeviceLinkWalletRequestType =
  | 'PM_HAS_PASSKEY'
  | 'PM_VIEW_ACCESS_KEYS'
  | 'PM_DELETE_DEVICE_KEY'
  | 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'
  | 'PM_START_DEVICE2_LINKING_FLOW'
  | 'PM_STOP_DEVICE2_LINKING_FLOW'
  | 'PM_SYNC_ACCOUNT_FLOW';
export type PreferencesWalletRequestType =
  | 'PM_GET_RECOVERY_EMAILS'
  | 'PM_SET_RECOVERY_EMAILS'
  | 'PM_SET_CONFIRM_BEHAVIOR'
  | 'PM_SET_CONFIRMATION_CONFIG'
  | 'PM_GET_CONFIRMATION_CONFIG'
  | 'PM_SET_THEME';

export type WalletHostRoute =
  | {
      kind: 'boot';
      type: BootWalletRequestType;
      request: WalletHostRequest<BootWalletRequestType>;
    }
  | {
      kind: 'near';
      type: NearWalletRequestType;
      request: WalletHostRequest<NearWalletRequestType>;
    }
  | {
      kind: 'auth';
      type: AuthWalletRequestType;
      request: WalletHostRequest<AuthWalletRequestType>;
    }
  | {
      kind: 'ecdsa';
      type: EcdsaWalletRequestType;
      request: WalletHostRequest<EcdsaWalletRequestType>;
    }
  | {
      kind: 'email_otp';
      type: EmailOtpWalletRequestType;
      request: WalletHostRequest<EmailOtpWalletRequestType>;
    }
  | {
      kind: 'recovery';
      type: RecoveryWalletRequestType;
      request: WalletHostRequest<RecoveryWalletRequestType>;
    }
  | {
      kind: 'export';
      type: ExportWalletRequestType;
      request: WalletHostRequest<ExportWalletRequestType>;
    }
  | {
      kind: 'device_link';
      type: DeviceLinkWalletRequestType;
      request: WalletHostRequest<DeviceLinkWalletRequestType>;
    }
  | {
      kind: 'preferences';
      type: PreferencesWalletRequestType;
      request: WalletHostRequest<PreferencesWalletRequestType>;
    };

function assertNever(value: never): never {
  throw new Error(`Unhandled wallet host route: ${String(value)}`);
}

export function routeWalletHostRequest(request: ParentToChildEnvelope): WalletHostRoute {
  switch (request.type) {
    case 'PING':
    case 'PM_SET_CONFIG':
    case 'PM_CANCEL':
      return { kind: 'boot', type: request.type, request };

    case 'PM_REGISTRATION_ACTIVATION_PREPARE':
    case 'PM_REGISTRATION_ACTIVATION_CANCEL':
    case 'PM_REGISTRATION_ACTIVATION_FOCUS':
    case 'PM_REGISTER_WALLET':
    case 'PM_ADD_WALLET_SIGNER':
    case 'PM_PREFETCH_BLOCKHEIGHT':
    case 'PM_SIGN_TX_WITH_ACTIONS':
    case 'PM_SIGN_AND_SEND_TX':
    case 'PM_SEND_TRANSACTION':
    case 'PM_EXECUTE_ACTION':
    case 'PM_SIGN_DELEGATE_ACTION':
    case 'PM_SIGN_NEP413':
      return { kind: 'near', type: request.type, request };

    case 'PM_UNLOCK':
    case 'PM_LOCK':
    case 'PM_GET_WALLET_SESSION':
    case 'PM_GET_RECENT_UNLOCKS':
      return { kind: 'auth', type: request.type, request };

    case 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION':
    case 'PM_SIGN_TEMPO':
    case 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED':
    case 'PM_REPORT_TEMPO_BROADCAST_REJECTED':
    case 'PM_REPORT_TEMPO_FINALIZED':
    case 'PM_REPORT_TEMPO_DROPPED_OR_REPLACED':
    case 'PM_RECONCILE_TEMPO_NONCE_LANE':
    case 'PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL':
      return { kind: 'ecdsa', type: request.type, request };

    case 'PM_REQUEST_EMAIL_OTP_CHALLENGE':
    case 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE':
    case 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE':
    case 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION':
    case 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH':
    case 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND':
    case 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID':
    case 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT':
    case 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION':
    case 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL':
    case 'PM_ENROLL_EMAIL_OTP':
    case 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY':
    case 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION':
    case 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY':
    case 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS':
    case 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES':
    case 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES':
      return { kind: 'email_otp', type: request.type, request };

    case 'PM_START_EMAIL_RECOVERY':
    case 'PM_FINALIZE_EMAIL_RECOVERY':
    case 'PM_STOP_EMAIL_RECOVERY':
    case 'PM_GET_RECOVERY_EMAILS':
    case 'PM_SET_RECOVERY_EMAILS':
    case 'PM_SYNC_ACCOUNT_FLOW':
      return { kind: 'recovery', type: request.type, request };

    case 'PM_EXPORT_KEYPAIR_UI':
    case 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI':
      return { kind: 'export', type: request.type, request };

    case 'PM_HAS_PASSKEY':
    case 'PM_VIEW_ACCESS_KEYS':
    case 'PM_DELETE_DEVICE_KEY':
    case 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA':
    case 'PM_START_DEVICE2_LINKING_FLOW':
    case 'PM_STOP_DEVICE2_LINKING_FLOW':
      return { kind: 'device_link', type: request.type, request };

    case 'PM_SET_CONFIRM_BEHAVIOR':
    case 'PM_SET_CONFIRMATION_CONFIG':
    case 'PM_GET_CONFIRMATION_CONFIG':
    case 'PM_SET_THEME':
      return { kind: 'preferences', type: request.type, request };
  }
  return assertNever(request);
}

export type RuntimeWalletHostRoute = Exclude<WalletHostRoute, { kind: 'boot' }>;

export function routeRequiresRuntime(route: WalletHostRoute): route is RuntimeWalletHostRoute {
  return route.kind !== 'boot';
}

type MissingRouteTypes = Exclude<ParentToChildType, WalletHostRoute['type']>;
const _allParentRequestTypesAreRouted: MissingRouteTypes extends never ? true : never = true;
void _allParentRequestTypesAreRouted;
