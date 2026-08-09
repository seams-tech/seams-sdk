/*
 * WalletIframeRouter - Client-Side Communication Layer
 *
 * Owns wallet iframe request correlation and typed surface transitions.
 *
 * High-level flow:
 *
 *   Step legend
 *   -----------
 *   (1) App calls a router RPC (executeAction, registerPasskey, etc).
 *   (2) Router posts request to iframe and tracks a pending entry.
 *   (3) Wallet iframe sends PROGRESS messages back to the router.
 *   (4) Router forwards ProgressPayloads into OnEventsProgressBus.
 *   (5) Surface events own iframe visibility, geometry, and focus.
 *   (6) Router receives a final result and finishes only the matching surface.
 *
 *  +-----------+       +--------------------+       +----------------------+       +----------------------+
 *  |   App     |       | WalletIframeRouter |       | OnEventsProgressBus  |       | OverlayController    |
 *  +-----+-----+       +---------+----------+       +----------+-----------+       +----------+-----------+
 *        |   (1) RPC call (executeAction, etc.)                |                              |
 *        |---------------------->|---------------------------->|                              |
 *        |                                                     |                              |
 *        |                        (2) post(): send request to iframe                          |
 *        |                                                     |                              |
 *        |                        (3) PROGRESS from iframe via onPortMessage()                |
 *        |<----------------------------------------------------|                              |
 *        |                                                     |                              |
 *        |                        (4) ProgressPayload -> callbacks and diagnostics            |
 *        |                                                     |                              |
 *        |                        (5) Surface reducer -> renderer -> overlay DOM              |
 *        |                                                     |----------------------------->|
 *        |                                                     |                              |
 *        |                        (6) PM_RESULT/ERROR -> finish matching surface              |
 *        |<----------------------------------------------------|                              |
 *
 * Communication Flow (requests):
 * 1. Parent calls RPC method (e.g., registerPasskey).
 * 2. Router creates unique request ID and pending entry.
 * 3. Message sent to iframe via MessagePort.
 * 4. Progress events are bridged to parent callbacks and diagnostics.
 * 5. The request surface reducer drives the renderer.
 * 6. Final results resolve the pending promise and finish the matching surface.
 */

import {
  type ParentToChildEnvelope,
  type ChildToParentEnvelope,
  type ProgressPayload,
  type PreferencesChangedPayload,
  type PMExportKeypairUiPayload,
  type PMRegistrationAuthMethodInput,
  parseWalletIframeSurfaceMeasurement,
  isRegistrationTimingSpanV1,
} from '../shared/messages';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { OnEventsProgressBus } from './progress/on-events-progress-bus';
import type {
  ActionHooksOptions,
  AfterCall,
  LinkDeviceFlowEvent,
  LoginHooksOptions,
  KeyExportFlowEvent,
  UnlockFlowEvent,
  RegistrationFlowEvent,
  RegistrationTimingSpanV1,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SigningFlowEvent,
  AccountSyncFlowEvent,
  SdkLifecycleEvent,
  SdkLifecycleEventListener,
  SigningSessionExpiredEvent,
  WalletSessionId,
} from '@/core/types/sdkSentEvents';
import type { WalletIframeTransportDiagnostics } from './transport/IframeTransport';
import {
  AccountSyncEventPhase,
  createAccountSyncFlowEvent,
  createKeyExportFlowEvent,
  createLinkDeviceFlowEvent,
  createRegistrationFlowEvent,
  createSigningFlowEvent,
  createUnlockFlowEvent,
  KeyExportEventPhase,
  isWalletFlowEvent,
  LinkDeviceEventPhase,
  RegistrationEventPhase,
  parseNearProvisioningState,
  parseSdkLifecycleEvent,
  SigningEventPhase,
  UnlockEventPhase,
} from '@/core/types/sdkSentEvents';
import type {
  ActionResult,
  AppearanceConfigInput,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  WalletSession,
  NearProvisioningState,
  RegistrationResult,
  SignDelegateActionResult,
  SignTransactionResult,
  SeamsChainConfig,
  SeamsConfigsInput,
} from '@/core/types/seams';
import type { WalletIframeRequestId } from '@/SeamsWeb/publicApi/types';
import { walletIframeSurfaceIdFromBoundary } from '@/core/types/walletIframeIdentity';
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import { requireTempoFeeTokenPreferenceSigningRequest } from '@/core/signingEngine/chains/tempo/feeToken';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import type { RouterAbEcdsaDerivationLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { DemoEmailOtpCodeResponse } from '@/core/signingEngine/session/emailOtp/publicTypes';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { registrationSignerSetRequestSelection } from '@/core/rpcClients/relayer/registrationSignerSetRequest';
import {
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519ExportMaterialIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { parseMpcMaterialActivationRef } from '@shared/utils/domainIds';
import type {
  LinkDeviceResult,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  DeviceLinkingQRData,
} from '@/core/types/linkDevice';
import type { SyncAccountResult } from '@/SeamsWeb/operations/recovery/syncAccount';
import type {
  CompleteWalletRecoveryResult,
  PrepareWalletWithCodeResult,
  WalletRecoveryBootstrapChallengeResult,
  WalletRecoveryBootstrapVerifyResult,
} from '@/SeamsWeb/operations/recovery/walletRecovery';
import type { WalletEmailOtpChannel } from '@shared/utils/emailOtpDomain';
import type { ExportKeypairWithUIInput } from '@/SeamsWeb/signingSurface/types';
import type {
  FundImplicitNearAccountForTestingResult,
  ResolveExactKeyExportLaneInput,
  ResolveExactKeyExportLaneResult,
  AddPasskeyResult,
} from '@/SeamsWeb/publicApi/types';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeRotationResult,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthStartInput,
  GoogleEmailOtpWalletAuthSubmitSuccess,
  RegistrationCapability,
} from '@/SeamsWeb/signingSurface/types';
import {
  buildHostedAuthMenuCancelPayload,
  parseHostedAuthMenuOpenRequest,
  parseHostedAuthMenuOutcome,
  hostedAuthMenuSessionIdFromBoundary,
  parseHostedAuthMenuExternalAuthRequest,
  parseHostedAuthMenuExternalAuthResolution,
  parseHostedAuthMenuDemoEmailOtpDelivery,
} from '../shared/messages';
import type {
  PMGoogleEmailOtpWalletAuthCompleteRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthStartPayload,
  PMGoogleEmailOtpWalletAuthSubmitWireResult,
  PMGoogleEmailOtpWalletAuthWireFlow,
  PMGoogleEmailOtpWalletAuthWireResult,
  HostedAuthMenuCancelPayload,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuSessionId,
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuExternalAuthResolutionInput,
  HostedAuthMenuDemoEmailOtpDelivery,
} from '../shared/messages';
import { ActionArgs, TransactionInput, TxExecutionStatus } from '@/core/types';
import type { DelegateActionInput } from '@/core/types/delegate';
import { IframeTransport } from './transport/IframeTransport';
import OverlayController, { type OverlayControllerState } from './overlay/overlay-controller';
import {
  authMenuWalletIframeSurfacePresentation,
  drawerWalletIframeSurfacePresentation,
  hiddenWalletIframeSurface,
  modalWalletIframeSurfacePresentation,
  passkeyRegistrationPreparationReceipt,
  requestSurfaceIdentity,
  reduceWalletIframeSurface,
  trustedWalletIframeSurfaceMeasurementFromWire,
  walletIframeConnectionIdFromBoundary,
  type ReduceWalletIframeSurfaceResult,
  type RequestSurfaceIdentity,
  type WalletIframeConnectionId,
  type WalletIframeSurface,
  type WalletIframeSurfacePresentation,
  type WalletIframeTrustedSurfaceMeasurement,
  type WalletIframeAuthMenuPresentation,
  type WalletIframeRequestSurfacePresentation,
  type WalletIframeSurfaceBusyError,
  type WalletIframeSurfaceEvent,
} from './surface/domain';
import {
  anchorWalletIframeModalGeometry,
  isWalletIframeModalGeometry,
  resolveWalletIframeSurfaceGeometry,
  type WalletIframeModalGeometry,
  type WalletIframeSurfaceMeasurementState,
  type WalletIframeSurfaceViewport,
} from './surface/geometry';
import { WalletIframeSurfaceRenderer } from './surface/renderer';
import {
  WalletIframeTransactionSurfaceQueue,
  type WalletIframeTransactionSurfaceDeadline,
  type WalletIframeTransactionSurfaceLease,
} from './surface/transactionSurfaceQueue';
import {
  isObject,
  isPlainSignedTransactionLike,
  extractBorshBytesFromPlainSignedTx,
  isBoolean,
  toBasePath,
} from '@shared/utils/validation';
import type { WalletUIRegistry } from '../host/lit-ui/iframe-lit-element-registry';
import { toError } from '@shared/utils/errors';
import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  walletIdFromString,
  type RegistrationAuthMethodInput,
} from '@shared/utils/registrationIntent';
import { parseAppSessionJwt, type AppSessionJwt } from '@shared/utils/domainIds';
import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import { needsExplicitActivation } from '@/utils/deviceDetection';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type { SignNEP413MessageResult } from '@/SeamsWeb/operations/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { cloneResolvedChainConfig } from '@/core/config/chains';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import type { LoginUnlockRequest } from '@/core/types/login.types';
import { buildPMUnlockPayload } from '../shared/unlockOptions';
import type { WalletId } from '@shared/utils/domainIds';
import type {
  WalletCredentialActivityListResult,
  WalletCredentialRenameResult,
} from '@/core/rpcClients/relayer/walletCredentialActivity';
import {
  exactSessionStateFromWalletSession,
  parseWalletIframeExactSessionLockResult,
  parseWalletIframeExactSessionState,
  parseWalletSessionFromBoundary,
  WalletIframeSessionExpiredRequestError,
  type WalletIframeExactSessionIdentity,
  type WalletIframeExactSessionLockResult,
  type WalletIframeExactSessionState,
  type WalletIframePendingSessionBinding,
} from '../shared/exactSessionState';

// Simple, framework-agnostic service iframe client.
// Responsibilities split:
// - IframeTransport: low-level mount + load + CONNECT/READY handshake (MessagePort)
// - WalletIframeRouter (this): request/response correlation, progress events,
//   overlay display, and high-level wallet RPC helpers

export interface WalletIframeRouterOptions {
  walletOrigin: string; // e.g., https://wallet.example.com
  servicePath?: string; // default '/wallet-service'
  connectTimeoutMs?: number; // default 8000
  requestTimeoutMs?: number; // default 20000
  // Enable verbose client-side logging for debugging
  debug?: boolean;
  // Test-only/diagnostic options (not part of the public app API surface)
  testOptions?: {
    // Optional identity/ownership tags for the iframe instance (useful for tests/tools)
    routerId?: string;
    ownerTag?: string; // e.g., 'app' | 'tests'
    // Lazy mounting: when false, do not auto-connect/mount during init(); connect on first use
    autoMount?: boolean;
  };
  // Optional config forwarded to wallet host
  chains?: readonly SeamsChainConfig[];
  relayerAccount?: string;
  relayer?: SeamsConfigsInput['relayer'];
  registration?: SeamsConfigsInput['registration'];
  signingSessionDefaults?: SeamsConfigsInput['signingSessionDefaults'];
  signingSessionPersistenceMode?: SeamsConfigsInput['signingSessionPersistenceMode'];
  routerAb?: SeamsConfigsInput['routerAb'];
  routerAbEcdsaDerivationPresignaturePool?: SeamsConfigsInput['routerAbEcdsaDerivationPresignaturePool'];
  provisioningDefaults?: SeamsConfigsInput['provisioningDefaults'];
  rpIdOverride?: string;
  authenticatorOptions?: AuthenticatorOptions;
  // SDK asset base path for embedded bundles when mounting same‑origin via srcdoc
  // Must serve dist/esm under this base path. Defaults to '/sdk'.
  sdkBasePath?: string;
  // Optional appearance defaults forwarded to wallet host.
  appearance?: AppearanceConfigInput;
  // Runtime appearance source used when init sends PM_SET_CONFIG.
  getAppearance?: () => AppearanceConfigInput | undefined;
  // Optional: pre-register UI components in wallet host
  uiRegistry?: Record<string, unknown>;
  // Optional browser assembly hook for owning wallet iframe overlay state construction.
  createOverlayState?: (args: {
    ensureIframe: (mountParent?: HTMLElement) => HTMLIFrameElement;
  }) => WalletIframeOverlayState;
}

export type WalletIframeOverlayState = {
  controller: OverlayController;
};

type WalletIframeRequestSurfaceKind =
  | 'auth_menu'
  | 'registration'
  | 'transaction'
  | 'key_export_near'
  | 'key_export_threshold'
  | 'unlock'
  | 'device_link'
  | 'device_link_qr'
  | 'recovery_codes_show'
  | 'recovery_codes_rotate';

type Pending = {
  requestId: WalletIframeRequestId;
  connectionId: WalletIframeConnectionId;
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
  timer: number | undefined;
  timeout:
    | { readonly kind: 'interactive' }
    | { readonly kind: 'deadline'; readonly timeoutMs: number; readonly deadlineAtMs: number };
  onProgress?: (payload: ProgressPayload) => void;
  requestType: ParentToChildEnvelope['type'];
  onTimeout: () => Error;
  sessionBinding: WalletIframePendingSessionBinding;
};

type WalletIframePostOptionsBase = {
  requestId?: WalletIframeRequestId;
  shouldContinue?: () => boolean;
};

type WalletIframePostOptions =
  | (WalletIframePostOptionsBase & {
      timeout?: 'deadline';
      timeoutMs?: number;
      progressTimeoutExtensionFactor?: number;
    })
  | (WalletIframePostOptionsBase & {
      timeout: 'interactive';
      timeoutMs?: never;
      progressTimeoutExtensionFactor?: never;
    });

type WalletIframeRequestAdmission =
  | {
      readonly kind: 'admitted';
      readonly binding: WalletIframePendingSessionBinding;
    }
  | {
      readonly kind: 'expired';
      readonly identity: WalletIframeExactSessionIdentity;
    };

function requestSurfaceKindForMessage(
  type: ParentToChildEnvelope['type'],
  payload: unknown,
): WalletIframeRequestSurfaceKind | null {
  if (
    isTransactionSurfaceMessage(type) &&
    confirmationUiModeForRequest(type, payload) === 'none' &&
    !needsExplicitActivation()
  ) {
    return null;
  }
  switch (type) {
    case 'PM_OPEN_AUTH_MENU':
      return 'auth_menu';
    case 'PM_REGISTER_WALLET':
    case 'PM_ADD_WALLET_SIGNER':
    case 'PM_ADD_PASSKEY':
    case 'PM_COMPLETE_WALLET_RECOVERY':
      return 'registration';
    case 'PM_SIGN_TX_WITH_ACTIONS':
    case 'PM_SIGN_AND_SEND_TX':
    case 'PM_EXECUTE_ACTION':
    case 'PM_SIGN_DELEGATE_ACTION':
    case 'PM_SIGN_NEP413':
    case 'PM_SIGN_TEMPO':
      return 'transaction';
    case 'PM_EXPORT_KEYPAIR_UI':
      return isObject(payload) && payload.kind === 'ecdsa'
        ? 'key_export_threshold'
        : 'key_export_near';
    case 'PM_UNLOCK':
      return 'unlock';
    case 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA':
      return 'device_link';
    case 'PM_START_DEVICE2_LINKING_FLOW':
      return 'device_link_qr';
    case 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES':
      return 'recovery_codes_show';
    case 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES':
      return 'recovery_codes_rotate';
    default:
      return null;
  }
}

function isTransactionSurfaceMessage(type: ParentToChildEnvelope['type']): boolean {
  switch (type) {
    case 'PM_SIGN_TX_WITH_ACTIONS':
    case 'PM_SIGN_AND_SEND_TX':
    case 'PM_EXECUTE_ACTION':
    case 'PM_SIGN_DELEGATE_ACTION':
    case 'PM_SIGN_NEP413':
    case 'PM_SIGN_TEMPO':
      return true;
    default:
      return false;
  }
}

type RequestConfirmationUiMode = 'none' | 'modal' | 'drawer';

function confirmationUiModeForRequest(
  type: ParentToChildEnvelope['type'],
  payload: unknown,
  fallbackUiMode?: RequestConfirmationUiMode,
): RequestConfirmationUiMode {
  // An export request carries its own surface variant, and callers rely on it:
  // the account menu asks for a drawer explicitly. It must outrank the mirrored
  // confirmation config, or the host dresses a box the iframe is not rendering
  // into and the viewer never appears.
  if (type === 'PM_EXPORT_KEYPAIR_UI' && isObject(payload)) {
    const exportOptions = isObject(payload.options) ? payload.options : null;
    if (exportOptions?.variant === 'drawer') return 'drawer';
    if (exportOptions?.variant === 'modal') return 'modal';
  }

  if (!isObject(payload)) return 'modal';
  const rootConfig = isObject(payload.confirmationConfig) ? payload.confirmationConfig : null;
  const options = isObject(payload.options) ? payload.options : null;
  const optionConfig =
    options && isObject(options.confirmationConfig) ? options.confirmationConfig : null;
  const configuredUiMode = optionConfig?.uiMode ?? rootConfig?.uiMode ?? fallbackUiMode;
  if (
    configuredUiMode === 'none' ||
    configuredUiMode === 'drawer' ||
    configuredUiMode === 'modal'
  ) {
    return configuredUiMode;
  }
  return 'modal';
}

function effectiveTransactionSurfaceUiMode(
  payload: unknown,
  fallbackUiMode?: RequestConfirmationUiMode,
): Exclude<RequestConfirmationUiMode, 'none'> {
  const requested = confirmationUiModeForRequest(
    'PM_SIGN_TX_WITH_ACTIONS',
    payload,
    fallbackUiMode,
  );
  if (requested === 'none') return needsExplicitActivation() ? 'drawer' : 'modal';
  return requested;
}

function requestSurfacePresentationFor(
  kind: 'auth_menu',
  payload: unknown,
  fallbackUiMode?: RequestConfirmationUiMode,
): WalletIframeAuthMenuPresentation;
function requestSurfacePresentationFor(
  kind: Exclude<WalletIframeRequestSurfaceKind, 'auth_menu'>,
  payload: unknown,
  fallbackUiMode?: RequestConfirmationUiMode,
): WalletIframeRequestSurfacePresentation;
function requestSurfacePresentationFor(
  kind: WalletIframeRequestSurfaceKind,
  payload: unknown,
  fallbackUiMode?: RequestConfirmationUiMode,
): WalletIframeSurfacePresentation {
  switch (kind) {
    case 'auth_menu':
      return authMenuWalletIframeSurfacePresentation('Sign in or create an account');
    case 'registration':
      return modalWalletIframeSurfacePresentation('Confirm passkey registration');
    case 'transaction':
      return effectiveTransactionSurfaceUiMode(payload, fallbackUiMode) === 'drawer'
        ? drawerWalletIframeSurfacePresentation('Confirm transaction')
        : modalWalletIframeSurfacePresentation('Confirm transaction');
    case 'key_export_near':
    case 'key_export_threshold':
      // An export request paints two surfaces in sequence — the email OTP
      // authorization prompt and the key viewer — and both resolve their own
      // variant from the confirmation UI mode, exactly like the tx confirmer.
      // The host box must read the same setting or it dresses a full-viewport
      // drawer around a compact modal card (or the reverse). 'none' is not a
      // presentation an export can use, so it lands on modal like every other
      // always-visible confirmation.
      return confirmationUiModeForRequest('PM_EXPORT_KEYPAIR_UI', payload, fallbackUiMode) ===
        'drawer'
        ? drawerWalletIframeSurfacePresentation('Confirm key export')
        : modalWalletIframeSurfacePresentation('Confirm key export');
    case 'unlock':
      return confirmationUiModeForRequest('PM_UNLOCK', payload, fallbackUiMode) === 'drawer'
        ? drawerWalletIframeSurfacePresentation('Unlock wallet')
        : modalWalletIframeSurfacePresentation('Unlock wallet');
    case 'device_link':
    case 'device_link_qr':
      return modalWalletIframeSurfacePresentation('Link a device');
    case 'recovery_codes_show':
      return confirmationUiModeForRequest(
        'PM_SHOW_EMAIL_OTP_RECOVERY_CODES',
        payload,
        fallbackUiMode,
      ) === 'drawer'
        ? drawerWalletIframeSurfacePresentation('Recovery codes')
        : modalWalletIframeSurfacePresentation('Recovery codes');
    case 'recovery_codes_rotate':
      return confirmationUiModeForRequest(
        'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES',
        payload,
        fallbackUiMode,
      ) === 'drawer'
        ? drawerWalletIframeSurfacePresentation('Rotate recovery codes')
        : modalWalletIframeSurfacePresentation('Rotate recovery codes');
    default:
      return assertNeverWalletIframeRequestSurfaceKind(kind);
  }
}

function authMenuSessionIdForMessage(
  type: ParentToChildEnvelope['type'],
  payload: unknown,
): HostedAuthMenuSessionId | null {
  if (type !== 'PM_OPEN_AUTH_MENU') return null;
  const parsed = parseHostedAuthMenuOpenRequest(payload);
  return parsed?.authMenuSessionId ?? null;
}

function assertNeverWalletIframeRequestSurfaceKind(value: never): never {
  throw new Error(`Unhandled wallet iframe request surface kind: ${String(value)}`);
}

function isTerminalStickyWalletFlowProgress(payload: ProgressPayload): boolean {
  if (!isWalletFlowEvent(payload)) return false;
  return (
    payload.status === 'cancelled' ||
    payload.status === 'failed' ||
    payload.phase === KeyExportEventPhase.STEP_05_VIEWER_CLOSED ||
    payload.phase === KeyExportEventPhase.STEP_06_COMPLETED
  );
}

function shouldHideWalletIframeSurface(payload: ProgressPayload): boolean {
  if (!isWalletFlowEvent(payload)) return false;
  if (payload.interaction?.overlay !== 'hide') return false;
  if (payload.flow !== 'key_export') return true;
  return isTerminalStickyWalletFlowProgress(payload);
}

const WALLET_IFRAME_PROGRESS_TIMEOUT_EXTENSION_FACTOR = 4;
/**
 * Grace period before an unmeasured surface falls back to filling the viewport.
 *
 * Every in-iframe mounter binds a measurement reporter, and the reporter posts
 * as soon as its element exists, so "no measurement" means "nothing is mounted
 * yet" — not "mounted but unmeasurable". Plenty of surfaces mount behind a
 * network round-trip (the email OTP export prompt waits for its challenge to be
 * issued and mailed), so a short deadline declared them broken mid-flight and
 * swapped a hidden provisional box for a full-viewport, unshadowed one that
 * then snapped back once the card finally reported. The deadline is a backstop
 * for a child that never reports at all, so it is sized to outlast a slow
 * request rather than to race one, and progress on the request restarts it.
 */
const WALLET_IFRAME_SURFACE_MEASUREMENT_FALLBACK_TIMEOUT_MS = 4_000;
const WALLET_IFRAME_REGISTRATION_TIMEOUT_MS = 180_000;
const WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS = 30_000;

type HostedAuthMenuAnchorMetrics = {
  topCssPx: number;
  leftCssPx: number;
  layoutWidthCssPx: number;
  heightCssPx: number;
  visualScale: number;
};

function hostedAuthMenuAnchorMetrics(
  anchor: HTMLElement | undefined,
): HostedAuthMenuAnchorMetrics | null {
  if (!anchor?.isConnected) return null;
  const rect = anchor.getBoundingClientRect();
  const layoutWidthCssPx = anchor.offsetWidth;
  if (
    !Number.isFinite(rect.top) ||
    !Number.isFinite(rect.left) ||
    !Number.isFinite(rect.width) ||
    !Number.isFinite(rect.height) ||
    rect.width <= 0 ||
    rect.height <= 0 ||
    !Number.isFinite(layoutWidthCssPx) ||
    layoutWidthCssPx <= 0
  ) {
    return null;
  }
  return {
    topCssPx: rect.top,
    leftCssPx: rect.left,
    layoutWidthCssPx,
    heightCssPx: rect.height,
    visualScale: rect.width / layoutWidthCssPx,
  };
}

export const HOSTED_AUTH_MENU_ANCHOR_HEIGHT_CSS_VAR = '--seams-auth-menu-height';

function pageScrollOffsetCssPx(axis: 'x' | 'y'): number {
  if (typeof window === 'undefined') return 0;
  const value = axis === 'x' ? window.scrollX : window.scrollY;
  return Number.isFinite(value) ? value : 0;
}

function documentCoordinateAuthMenuGeometry(
  geometry: WalletIframeModalGeometry,
): WalletIframeModalGeometry {
  return {
    ...geometry,
    topCssPx: Math.round(geometry.topCssPx + pageScrollOffsetCssPx('y')),
    leftCssPx: Math.round(geometry.leftCssPx + pageScrollOffsetCssPx('x')),
  };
}

function publishHostedAuthMenuAnchorHeight(
  anchor: HTMLElement | undefined,
  heightCssPx: number,
): void {
  if (!anchor?.isConnected || !Number.isFinite(heightCssPx) || heightCssPx <= 0) return;
  const next = `${Math.round(heightCssPx)}px`;
  // Writing an unchanged value would still dirty layout, and this runs on every
  // scroll and resize tick.
  if (anchor.style.getPropertyValue(HOSTED_AUTH_MENU_ANCHOR_HEIGHT_CSS_VAR) === next) return;
  anchor.style.setProperty(HOSTED_AUTH_MENU_ANCHOR_HEIGHT_CSS_VAR, next);
}

type SignTempoRouterPayload = {
  walletSession: WalletSessionRef;
  request: MultichainSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
};

function buildSignTempoIframePayload(
  payload: SignTempoRouterPayload,
): Extract<ParentToChildEnvelope, { type: 'PM_SIGN_TEMPO' }>['payload'] {
  if (payload.request.chain === 'tempo') {
    if (payload.chainTarget.kind !== 'tempo') {
      throw new Error('[wallet-iframe] Tempo request requires a Tempo target');
    }
    return {
      ...payload,
      operationKind: 'tempo_transaction',
      request: payload.request,
      chainTarget: payload.chainTarget,
    };
  }
  if (payload.chainTarget.kind === 'evm') {
    return {
      ...payload,
      operationKind: 'evm_transaction',
      request: payload.request,
      chainTarget: payload.chainTarget,
    };
  }
  return {
    ...payload,
    operationKind: 'tempo_fee_token_preference',
    request: requireTempoFeeTokenPreferenceSigningRequest({
      request: payload.request,
      chainTarget: payload.chainTarget,
    }),
    chainTarget: payload.chainTarget,
  };
}
const WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS = 5 * 60 * 1000;

type WalletIframeLoginStatusSnapshot = {
  isLoggedIn: boolean;
  walletId: string | null;
};

function walletIframeLoginStatusFromExactSession(
  state: WalletIframeExactSessionState,
): WalletIframeLoginStatusSnapshot {
  switch (state.kind) {
    case 'active_session':
    case 'expired_session':
    case 'wallet_authenticated_identity_unresolvable':
    case 'wallet_unlocked_without_signing_session':
      return { isLoggedIn: true, walletId: state.walletId };
    case 'wallet_locked':
      return { isLoggedIn: false, walletId: null };
    default:
      state satisfies never;
      throw new Error('Wallet iframe exact session state is invalid');
  }
}

function parseResolveExactKeyExportLaneResult(
  result: ResolveExactKeyExportLaneResult,
): ResolveExactKeyExportLaneResult {
  switch (result.kind) {
    case 'ecdsa':
      return {
        kind: 'ecdsa',
        laneIdentity: parseExactEcdsaSigningLaneIdentity(result.laneIdentity),
      };
    case 'ed25519': {
      const materialActivation = parseMpcMaterialActivationRef(result.materialActivation);
      if (!materialActivation.ok) throw new Error(materialActivation.error.message);
      return {
        kind: 'ed25519',
        laneIdentity: parseExactEd25519ExportMaterialIdentity(result.laneIdentity),
        materialActivation: materialActivation.value,
      };
    }
  }
}

function walletIframeExportPayload(
  input: ExportKeypairWithUIInput,
  options: { variant?: 'modal' | 'drawer'; theme?: 'dark' | 'light' },
): PMExportKeypairUiPayload {
  switch (input.kind) {
    case 'ecdsa': {
      const laneIdentity = parseExactEcdsaSigningLaneIdentity(input.laneIdentity);
      if (String(laneIdentity.signer.walletId) !== String(input.walletSession.walletId)) {
        throw new Error(
          '[WalletIframeRouter] key export lane wallet does not match wallet session',
        );
      }
      if (!thresholdEcdsaChainTargetsEqual(laneIdentity.signer.chainTarget, input.chainTarget)) {
        throw new Error(
          '[WalletIframeRouter] key export lane chain target does not match request target',
        );
      }
      return {
        kind: 'ecdsa',
        chainTarget: input.chainTarget,
        walletSession: input.walletSession,
        laneIdentity,
        options,
      };
    }
    case 'ed25519': {
      const laneIdentity = parseExactEd25519ExportMaterialIdentity(input.laneIdentity);
      if (
        String(laneIdentity.signer.account.wallet.walletId) !== String(input.walletSession.walletId)
      ) {
        throw new Error(
          '[WalletIframeRouter] Ed25519 export lane wallet does not match wallet session',
        );
      }
      if (
        String(laneIdentity.signer.account.nearAccountId) !== String(input.nearAccount.accountId)
      ) {
        throw new Error('[WalletIframeRouter] Ed25519 export lane does not match the NEAR account');
      }
      return {
        kind: 'ed25519',
        nearAccount: input.nearAccount,
        walletSession: input.walletSession,
        laneIdentity,
        materialActivation: input.materialActivation,
        options,
      };
    }
  }
}

const EMAIL_OTP_APP_ORIGIN_FORBIDDEN_RESULT_KEYS = new Set([
  'S',
  'secretS',
  'recoveredS',
  'recoveredSB64u',
  'recoveryKeys',
  'clientSecret32',
  'clientRootShare32',
  'clientRootShare32B64u',
  'clientAdditiveShare32',
  'clientAdditiveShare32B64u',
  'clientSigningShare32',
  'clientSigningShare32B64u',
  'kShareB64u',
  'sigmaShareB64u',
]);

type PostResult<T> = {
  ok: boolean;
  result: T;
};

export type HostedWalletSeamsSessionSource = {
  readonly relayUrl: string;
  readonly appSessionJwt: AppSessionJwt;
};

type HostedWalletSeamsSessionExchangeDelivery = {
  readonly exchangeCode: string;
  readonly nonce: string;
  readonly expiresAtMs: number;
};

type HostedWalletSeamsSessionRedemption = {
  readonly kind: 'redeemed_hosted_wallet_seams_session';
  readonly expiresAtMs: number;
};

function requireNonEmptyBoundaryString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  return value;
}

function requireCompactExchangeValue(value: unknown, label: string): string {
  const parsed = requireNonEmptyBoundaryString(value, label);
  // eslint-disable-next-line no-control-regex
  if (parsed.length > 512 || /[\s\u0000-\u001f\u007f]/.test(parsed)) {
    throw new Error(`${label} must be a compact opaque identifier`);
  }
  return parsed;
}

function parseHostedWalletExchangeFailure(value: unknown, status: number): Error {
  const record = isObject(value) ? value : {};
  const code = requireNonEmptyBoundaryString(record.code, 'session exchange error code');
  const message = requireNonEmptyBoundaryString(record.message, 'session exchange error message');
  const error = new Error(message) as Error & { code: string; status: number };
  error.code = code;
  error.status = status;
  return error;
}

function parseHostedWalletExchangeDelivery(
  value: unknown,
  expected: { readonly appOrigin: string; readonly walletOrigin: string },
): HostedWalletSeamsSessionExchangeDelivery {
  if (!isObject(value) || value.ok !== true || !isObject(value.delivery)) {
    throw new Error('session exchange response must contain one delivery');
  }
  const delivery = value.delivery;
  if (delivery.kind !== 'hosted_wallet_session_exchange_delivery') {
    throw new Error('session exchange returned the wrong delivery kind');
  }
  const appOrigin = requireNonEmptyBoundaryString(delivery.appOrigin, 'delivery.appOrigin');
  const walletOrigin = requireNonEmptyBoundaryString(
    delivery.walletOrigin,
    'delivery.walletOrigin',
  );
  if (appOrigin !== expected.appOrigin || walletOrigin !== expected.walletOrigin) {
    throw new Error('session exchange delivery origin binding does not match the iframe');
  }
  const expiresAtMs = Number(delivery.expiresAtMs);
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('session exchange delivery is expired');
  }
  return {
    exchangeCode: requireCompactExchangeValue(delivery.exchangeCode, 'delivery.exchangeCode'),
    nonce: requireCompactExchangeValue(delivery.nonce, 'delivery.nonce'),
    expiresAtMs,
  };
}

async function readSessionExchangeJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function requireAppSessionJwtAtParentBoundary(value: unknown): AppSessionJwt {
  const parsed = parseAppSessionJwt(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function canonicalHostedWalletRelayUrl(value: unknown): string {
  return stripTrailingSlashes(requireNonEmptyBoundaryString(value, 'hosted-wallet relayUrl'));
}

function hostedWalletSessionSourcesMatch(
  left: HostedWalletSeamsSessionSource | null,
  right: HostedWalletSeamsSessionSource,
): boolean {
  return (
    left !== null &&
    canonicalHostedWalletRelayUrl(left.relayUrl) ===
      canonicalHostedWalletRelayUrl(right.relayUrl) &&
    left.appSessionJwt === right.appSessionJwt
  );
}

function hostedWalletSeamsSessionSource(input: {
  readonly relayUrl?: string;
  readonly appSessionJwt?: string;
}): HostedWalletSeamsSessionSource | null {
  if (input.appSessionJwt === undefined) return null;
  return {
    relayUrl: canonicalHostedWalletRelayUrl(input.relayUrl),
    appSessionJwt: requireAppSessionJwtAtParentBoundary(input.appSessionJwt),
  };
}

function hostedWalletSeamsSessionSourceFromUnlock(
  request: LoginUnlockRequest,
  defaultRelayUrl: string | undefined,
): HostedWalletSeamsSessionSource | null {
  if (request.kind !== 'custom_options') return null;
  const inventory = request.options.ecdsaKeyFactsInventory;
  if (!inventory || inventory.mode !== 'app_session') return null;
  return hostedWalletSeamsSessionSource({
    relayUrl: request.options.session?.relayUrl || defaultRelayUrl,
    appSessionJwt: inventory.appSessionJwt,
  });
}

type HostedWalletRegistrationTransport = {
  readonly authMethod: PMRegistrationAuthMethodInput;
  readonly sessionSource: HostedWalletSeamsSessionSource | null;
};

function assertNeverRegistrationAuthMethod(value: never): never {
  throw new Error(`Unsupported registration auth method: ${String(value)}`);
}

function hostedWalletRegistrationTransport(
  authMethod: RegistrationAuthMethodInput,
  relayUrl: string | undefined,
): HostedWalletRegistrationTransport {
  switch (authMethod.kind) {
    case 'passkey':
      return {
        authMethod: {
          kind: 'passkey',
          rpId: authMethod.rpId,
          ...(authMethod.authenticatorOptions === undefined
            ? {}
            : { authenticatorOptions: authMethod.authenticatorOptions }),
        },
        sessionSource: null,
      };
    case 'email_otp': {
      const sessionSource = hostedWalletSeamsSessionSource({
        relayUrl,
        appSessionJwt: authMethod.appSessionJwt,
      });
      if (!sessionSource) {
        throw new Error('Email OTP registration requires a hosted-wallet Seams Session');
      }
      switch (authMethod.proofKind) {
        case 'otp_challenge':
          return {
            authMethod: {
              kind: 'email_otp',
              proofKind: 'otp_challenge',
              email: authMethod.email,
              otpCode: authMethod.otpCode,
              ...(authMethod.challengeId === undefined
                ? {}
                : { challengeId: authMethod.challengeId }),
            },
            sessionSource,
          };
        case 'google_sso_registration':
          return {
            authMethod: {
              kind: 'email_otp',
              proofKind: 'google_sso_registration',
              email: authMethod.email,
              googleEmailOtpRegistrationAttemptId: authMethod.googleEmailOtpRegistrationAttemptId,
              googleEmailOtpRegistrationOfferId: authMethod.googleEmailOtpRegistrationOfferId,
              googleEmailOtpRegistrationCandidateId:
                authMethod.googleEmailOtpRegistrationCandidateId,
            },
            sessionSource,
          };
        default:
          return assertNeverRegistrationAuthMethod(authMethod);
      }
    }
    default:
      return assertNeverRegistrationAuthMethod(authMethod);
  }
}

function getErrorCode(error: Error): string {
  if (!isObject(error)) return '';
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : '';
}

function walletIframeSurfaceBusyError(
  detail?: WalletIframeSurfaceBusyError,
): Error & { code: 'wallet_iframe_surface_busy'; detail?: WalletIframeSurfaceBusyError } {
  const error = new Error(
    'The wallet iframe is reserved by an active foreground surface',
  ) as Error & {
    code: 'wallet_iframe_surface_busy';
    detail?: WalletIframeSurfaceBusyError;
  };
  error.code = 'wallet_iframe_surface_busy';
  if (detail) error.detail = detail;
  return error;
}

class WalletIframeConnectionClosedRequestError extends Error {
  readonly code = 'connection_closed' as const;

  constructor(
    readonly requestId: WalletIframeRequestId,
    readonly connectionId: WalletIframeConnectionId,
    requestType: ParentToChildEnvelope['type'],
  ) {
    super(`Wallet iframe connection closed while handling ${requestType}`);
    this.name = 'WalletIframeConnectionClosedRequestError';
  }
}

function createTerminalProgressForRequest(args: {
  requestType: ParentToChildEnvelope['type'];
  requestId: string;
  status: 'failed' | 'cancelled';
  message: string;
  errorCode?: string;
}): ProgressPayload | null {
  const { requestType, requestId, status, message, errorCode } = args;
  const flowId = `wallet-iframe:${requestType}:${requestId}`;
  const error = { ...(errorCode ? { code: errorCode } : {}), message };
  const common = { flowId, requestId, status, message, error };
  const registrationRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_REGISTER_WALLET',
    'PM_ADD_PASSKEY',
    'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE',
    'PM_ENROLL_EMAIL_OTP',
  ]);
  const unlockRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_UNLOCK',
    'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION',
    'PM_REQUEST_EMAIL_OTP_CHALLENGE',
    'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
  ]);
  const signingRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_SIGN_TX_WITH_ACTIONS',
    'PM_SIGN_AND_SEND_TX',
    'PM_SEND_TRANSACTION',
    'PM_EXECUTE_ACTION',
    'PM_SIGN_DELEGATE_ACTION',
    'PM_SIGN_NEP413',
    'PM_SIGN_TEMPO',
    'PM_REPORT_TEMPO_BROADCAST_ACCEPTED',
    'PM_REPORT_TEMPO_BROADCAST_REJECTED',
    'PM_REPORT_TEMPO_FINALIZED',
    'PM_REPORT_TEMPO_DROPPED_OR_REPLACED',
    'PM_RECONCILE_TEMPO_NONCE_LANE',
    'PM_SET_RECOVERY_EMAILS',
    'PM_DELETE_DEVICE_KEY',
  ]);
  const linkDeviceRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA',
    'PM_START_DEVICE2_LINKING_FLOW',
    'PM_STOP_DEVICE2_LINKING_FLOW',
  ]);
  if (registrationRequests.has(requestType)) {
    return createRegistrationFlowEvent({
      ...common,
      phase:
        status === 'cancelled' ? RegistrationEventPhase.CANCELLED : RegistrationEventPhase.FAILED,
    });
  }
  if (unlockRequests.has(requestType)) {
    return createUnlockFlowEvent({
      ...common,
      phase: status === 'cancelled' ? UnlockEventPhase.CANCELLED : UnlockEventPhase.FAILED,
    });
  }
  if (signingRequests.has(requestType)) {
    return createSigningFlowEvent({
      ...common,
      phase: status === 'cancelled' ? SigningEventPhase.CANCELLED : SigningEventPhase.FAILED,
    });
  }
  if (linkDeviceRequests.has(requestType)) {
    return createLinkDeviceFlowEvent({
      ...common,
      phase: status === 'cancelled' ? LinkDeviceEventPhase.CANCELLED : LinkDeviceEventPhase.FAILED,
    });
  }
  if (requestType === 'PM_SYNC_ACCOUNT_FLOW') {
    return createAccountSyncFlowEvent({
      ...common,
      phase:
        status === 'cancelled' ? AccountSyncEventPhase.CANCELLED : AccountSyncEventPhase.FAILED,
    });
  }
  if (requestType === 'PM_EXPORT_KEYPAIR_UI') {
    return createKeyExportFlowEvent({
      ...common,
      phase: status === 'cancelled' ? KeyExportEventPhase.CANCELLED : KeyExportEventPhase.FAILED,
    });
  }
  return null;
}

function sanitizeEmailOtpIframeResult<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((entry) => sanitizeEmailOtpIframeResult(entry)) as T;
  }
  if (!isObject(value)) {
    return value;
  }

  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (EMAIL_OTP_APP_ORIGIN_FORBIDDEN_RESULT_KEYS.has(key)) {
      continue;
    }
    out[key] = sanitizeEmailOtpIframeResult(entry);
  }
  return out as T;
}

const CANONICAL_SIGNER_BOUNDARY_MESSAGES: Record<string, string> = {
  commit_queue_overflow:
    'Threshold signing commit queue is full. Wait for pending requests and retry.',
  commit_queue_timeout: 'Threshold signing commit request timed out in queue. Retry the request.',
  threshold_ed25519_session_not_ready:
    'Threshold Ed25519 signing session is not ready. Refresh the signing session and retry.',
  threshold_ecdsa_session_not_ready:
    'Threshold ECDSA signing session is not ready. Refresh the signing session and retry.',
  threshold_session_kind_mismatch:
    'Threshold signing session kind mismatch. Refresh the signing session and retry.',
  session_not_ready:
    'Threshold signing session is not ready. Refresh the signing session and retry.',
  nonce_conflict_retryable: 'Nonce conflict detected. Refresh nonce state and retry the request.',
  rpc_request_failed: 'RPC request failed. Retry the request or use another RPC endpoint.',
  cancelled: 'Request cancelled.',
};

function resolveCanonicalSignerBoundaryMessage(rawCode: unknown, fallbackMessage: unknown): string {
  const code = String(rawCode || '')
    .trim()
    .toLowerCase();
  if (code && CANONICAL_SIGNER_BOUNDARY_MESSAGES[code]) {
    return CANONICAL_SIGNER_BOUNDARY_MESSAGES[code];
  }
  const fallback = String(fallbackMessage || '').trim();
  return fallback || 'Wallet error';
}

function emitDemoEmailOtpCodeFromWire(args: {
  wire: PMGoogleEmailOtpWalletAuthWireFlow;
  onDemoOtp: ((response: DemoEmailOtpCodeResponse) => void) | undefined;
}): void {
  if (args.wire.mode !== 'login') return;
  switch (args.wire.delivery.kind) {
    case 'provider':
      return;
    case 'demo_code_response':
    case 'provider_and_demo_code':
      args.onDemoOtp?.(args.wire.delivery);
      return;
  }
}

type ParsedSdkLifecycleEnvelope =
  | { readonly kind: 'not_lifecycle_event' }
  | { readonly kind: 'invalid_lifecycle_event' }
  | { readonly kind: 'lifecycle_event'; readonly event: SdkLifecycleEvent };

function parseSdkLifecycleEnvelope(value: unknown): ParsedSdkLifecycleEnvelope {
  if (!isObject(value) || value.type !== 'SDK_LIFECYCLE_EVENT') {
    return { kind: 'not_lifecycle_event' };
  }
  const event = parseSdkLifecycleEvent(value.payload);
  if (!event) return { kind: 'invalid_lifecycle_event' };
  return { kind: 'lifecycle_event', event };
}

function assertNeverSdkLifecycleEventName(value: never): never {
  throw new Error(`Unsupported SDK lifecycle event: ${String(value)}`);
}

export class WalletIframeRouter {
  private opts: Required<WalletIframeRouterOptions>;
  // Low-level transport handling iframe mount + handshake
  private transport: IframeTransport;
  private state = {
    port: null as MessagePort | null,
    connectionId: null as WalletIframeConnectionId | null,
    ready: false,
    // Deduplicate concurrent init() calls and avoid race conditions
    initInFlight: null as Promise<void> | null,
    hostedWalletSessionInFlight: null as Promise<void> | null,
    hostedWalletSessionExpiresAtMs: 0,
    hostedWalletSessionSource: null as HostedWalletSeamsSessionSource | null,
    pending: new Map<string, Pending>(),
    reqCounter: 0,
  };
  private readonly listeners = {
    ready: new Set<() => void>(),
    loginStatus: new Set<(status: { isLoggedIn: boolean; walletId: string | null }) => void>(),
    preferencesChanged: new Set<(payload: PreferencesChangedPayload) => void>(),
    hostedAuthMenuExternalAuthRequest: new Set<
      (payload: HostedAuthMenuExternalAuthRequest) => void
    >(),
    hostedAuthMenuDemoEmailOtpDelivery: new Set<
      (payload: HostedAuthMenuDemoEmailOtpDelivery) => void
    >(),
    sdkLifecycleEvent: new Set<SdkLifecycleEventListener>(),
  };
  private readonly expiredSigningSessionsByWallet = new Map<WalletId, Set<WalletSessionId>>();
  private exactSessionState: WalletIframeExactSessionState | null = null;
  private lastPreferencesChangedPayload: PreferencesChangedPayload | null = null;
  private mirroredConfirmationUiMode: RequestConfirmationUiMode | null = null;
  private progressBus: OnEventsProgressBus;
  private debug = false;
  private readonly walletOriginUrl: URL;
  private readonly walletOriginOrigin: string;
  private overlayState: WalletIframeOverlayState;
  private walletIframeSurface: WalletIframeSurface = hiddenWalletIframeSurface();
  private surfaceRenderer: WalletIframeSurfaceRenderer;
  private activeSurfaceMeasurement: WalletIframeTrustedSurfaceMeasurement | null = null;
  private activeSurfaceMeasurementUnavailable = false;
  private surfaceGeneration = 0;
  private activeSurfaceMeasurementGeneration = 0;
  private surfaceViewportListenersAttached = false;
  private surfaceLayoutObserver: ResizeObserver | null = null;
  private measurementFallbackTimer: number | null = null;
  private measurementFallbackGeneration = 0;
  private disposed = false;
  private readonly transactionSurfaceQueue = new WalletIframeTransactionSurfaceQueue();
  private readonly hostedAuthMenuRequestIds = new Map<
    HostedAuthMenuSessionId,
    WalletIframeRequestId
  >();
  private readonly hostedAuthMenuConnectionIds = new Map<
    HostedAuthMenuSessionId,
    WalletIframeConnectionId
  >();
  private readonly hostedAuthMenuAnchors = new Map<HostedAuthMenuSessionId, HTMLElement>();
  private hostedAuthMenuAnchorTrackingFrame: number | null = null;
  private hostedAuthMenuAnchorTrackingSession: HostedAuthMenuSessionId | null = null;
  private hostedAuthMenuAnchorTrackingDeadlineMs = 0;
  private readonly cancelledHostedAuthMenuSessions = new Set<HostedAuthMenuSessionId>();

  constructor(options: WalletIframeRouterOptions) {
    if (!options?.walletOrigin) {
      throw new Error('[WalletIframeRouter] walletOrigin is required when using the wallet iframe');
    }

    let parsedOrigin: URL;
    try {
      parsedOrigin = new URL(options.walletOrigin);
    } catch (err) {
      throw new Error(`[WalletIframeRouter] Invalid walletOrigin: ${options.walletOrigin}`);
    }

    if (typeof window !== 'undefined') {
      const parentOrigin = window.location.origin;
      if (parsedOrigin.origin === parentOrigin) {
        console.warn(
          '[WalletIframeRouter] walletOrigin matches the host origin. Isolation safeguards rely on the parent; consider moving the wallet to a dedicated origin.',
        );
      }
    }

    const defaultRouterId = `w3a-${Date.now()}-${secureRandomBase36(6, 'wallet iframe router IDs')}`;
    const testOptions = {
      routerId: defaultRouterId,
      ownerTag: undefined as string | undefined,
      autoMount: true,
      ...(options?.testOptions || {}),
    };
    const normalizedServicePath = (() => {
      const p = toBasePath(options?.servicePath, '/wallet-service');
      return p === '/' ? '/wallet-service' : p;
    })();
    const normalizedSdkBasePath = (() => {
      const p = toBasePath(options?.sdkBasePath, '/sdk');
      return p === '/' ? '/sdk' : p;
    })();
    this.opts = {
      connectTimeoutMs: 8000,
      requestTimeoutMs: 20000,
      getAppearance: () => options.appearance,
      ...options,
      // Normalize path-like options so empty strings (common when CI env vars are unset)
      // don't accidentally become the wallet origin root. If sdkBasePath becomes "", then:
      //   new URL("", "https://wallet.example.com") -> "https://wallet.example.com/"
      // which makes Lit components request CSS from the origin root (Pages SPA fallback),
      // yielding `Content-Type: text/html` and browser MIME-type errors.
      servicePath: normalizedServicePath,
      sdkBasePath: normalizedSdkBasePath,
      testOptions,
      chains: (options.chains ?? PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains).map(
        cloneResolvedChainConfig,
      ),
    } as Required<WalletIframeRouterOptions>;
    this.walletOriginUrl = parsedOrigin;
    this.walletOriginOrigin = parsedOrigin.origin;
    this.debug = !!this.opts.debug;
    // Encapsulate iframe mount + handshake logic in transport
    this.transport = new IframeTransport({
      walletOrigin: this.opts.walletOrigin,
      servicePath: this.opts.servicePath,
      connectTimeoutMs: this.opts.connectTimeoutMs,
      debug: this.debug,
      testOptions: {
        routerId: this.opts.testOptions.routerId,
        ownerTag: this.opts.testOptions.ownerTag,
      },
    });
    this.transport.onConnectionClosed(this.handleTransportConnectionClosed);

    // Centralize overlay sizing, visibility, and identity-bound dismissal.
    this.overlayState = (
      this.opts.createOverlayState ||
      ((args: { ensureIframe: (mountParent?: HTMLElement) => HTMLIFrameElement }) => ({
        controller: new OverlayController(args),
      }))
    )({
      ensureIframe: (mountParent) => this.transport.ensureIframeMounted(mountParent),
    });
    this.overlayState.controller.setDismissHandler(this.handleOverlayDismiss);
    this.surfaceRenderer = new WalletIframeSurfaceRenderer(this.overlayState.controller);

    // Progress remains a content and diagnostics channel. Surface transitions own
    // iframe visibility, focusability, and geometry.
    this.progressBus = new OnEventsProgressBus(
      this.debug
        ? (msg: string, data?: Record<string, unknown>) => {
            console.debug('[WalletIframeRouter][OnEventsProgressBus]', msg, data || {});
          }
        : undefined,
    );
  }

  private getCurrentAppearance(): AppearanceConfigInput | undefined {
    return this.opts.getAppearance() ?? this.opts.appearance;
  }

  private transitionWalletIframeSurface(
    event: WalletIframeSurfaceEvent,
  ): ReduceWalletIframeSurfaceResult {
    const result = reduceWalletIframeSurface(this.walletIframeSurface, event);
    if (result.kind === 'applied') {
      const previousSurface = this.walletIframeSurface;
      this.walletIframeSurface = result.surface;
      if (!this.surfaceIdentityEqual(previousSurface, result.surface)) {
        this.surfaceGeneration += 1;
        this.activeSurfaceMeasurement = null;
        this.activeSurfaceMeasurementUnavailable = false;
        this.activeSurfaceMeasurementGeneration = this.surfaceGeneration;
      }
      this.updateSurfaceViewportListeners();
      this.renderActiveWalletIframeSurface();
      if (
        result.surface.kind === 'modal_auth_menu' &&
        this.hostedAuthMenuAnchors.has(result.surface.authMenuSessionId)
      ) {
        this.startHostedAuthMenuAnchorTracking(result.surface.authMenuSessionId);
      }
      if (result.surface.kind !== 'hidden' && !this.activeSurfaceMeasurement) {
        this.scheduleMeasurementFallback(this.surfaceGeneration);
      }
    }
    return result;
  }

  private updateSurfaceViewportListeners(): void {
    const shouldAttach = this.walletIframeSurface.kind !== 'hidden';
    if (shouldAttach === this.surfaceViewportListenersAttached) return;
    const visualViewport = window.visualViewport;
    if (shouldAttach) {
      window.addEventListener('resize', this.handleSurfaceViewportChange);
      window.addEventListener('scroll', this.handleSurfaceViewportChange, true);
      visualViewport?.addEventListener('resize', this.handleSurfaceViewportChange);
      visualViewport?.addEventListener('scroll', this.handleSurfaceViewportChange);
      // Anchored surfaces also go stale when the page reflows without any
      // scroll/resize event — fonts and images loading, responsive relayout —
      // because the anchor's document position moves silently. Body size is a
      // cheap proxy for "content above the anchor changed"; unchanged geometry
      // short-circuits in the render path, so spurious fires are free.
      if (typeof ResizeObserver === 'function' && document.body) {
        this.surfaceLayoutObserver = new ResizeObserver(this.handleSurfaceViewportChange);
        this.surfaceLayoutObserver.observe(document.body);
      }
      this.surfaceViewportListenersAttached = true;
      return;
    }
    window.removeEventListener('resize', this.handleSurfaceViewportChange);
    window.removeEventListener('scroll', this.handleSurfaceViewportChange, true);
    visualViewport?.removeEventListener('resize', this.handleSurfaceViewportChange);
    visualViewport?.removeEventListener('scroll', this.handleSurfaceViewportChange);
    this.surfaceLayoutObserver?.disconnect();
    this.surfaceLayoutObserver = null;
    this.surfaceViewportListenersAttached = false;
    this.cancelMeasurementFallback();
  }

  private handleSurfaceViewportChange = (): void => {
    if (this.walletIframeSurface.kind === 'hidden') return;
    this.renderActiveWalletIframeSurface();
  };

  private scheduleMeasurementFallback(generation: number): void {
    this.cancelMeasurementFallback();
    if (this.walletIframeSurface.kind === 'hidden') return;
    this.measurementFallbackGeneration = generation;
    this.measurementFallbackTimer = window.setTimeout(
      this.handleMeasurementFallbackTimeout,
      WALLET_IFRAME_SURFACE_MEASUREMENT_FALLBACK_TIMEOUT_MS,
    );
  }

  private handleMeasurementFallbackTimeout = (): void => {
    this.measurementFallbackTimer = null;
    this.markMeasurementUnavailable(this.measurementFallbackGeneration);
  };

  /**
   * A request that is still reporting progress has not stalled, so its surface
   * must not be declared unmeasurable while it works toward mounting.
   */
  private extendMeasurementFallbackOnProgress(requestId: string): void {
    if (this.measurementFallbackTimer === null) return;
    const surface = this.walletIframeSurface;
    if (surface.kind === 'hidden' || surface.identity.requestId !== requestId) return;
    this.scheduleMeasurementFallback(this.measurementFallbackGeneration);
  }

  private markMeasurementUnavailable(generation: number): void {
    if (generation !== this.surfaceGeneration || this.walletIframeSurface.kind === 'hidden') return;
    if (this.activeSurfaceMeasurement) return;
    this.activeSurfaceMeasurementUnavailable = true;
    this.cancelMeasurementFallback();
    this.renderActiveWalletIframeSurface();
  }

  private cancelMeasurementFallback(): void {
    if (this.measurementFallbackTimer !== null) {
      window.clearTimeout(this.measurementFallbackTimer);
      this.measurementFallbackTimer = null;
    }
  }

  private handleOverlayDismiss = (event: {
    identity: RequestSurfaceIdentity;
    authMenuSessionId?: HostedAuthMenuSessionId;
  }): void => {
    const surface = this.walletIframeSurface;
    if (surface.kind === 'hidden') return;
    if (
      surface.identity.surfaceId !== event.identity.surfaceId ||
      surface.identity.requestId !== event.identity.requestId
    ) {
      return;
    }
    if (surface.kind === 'modal_auth_menu') {
      if (surface.authMenuSessionId !== event.authMenuSessionId) return;
      void this.cancelHostedAuthMenuWithReason(surface.authMenuSessionId, 'close_button');
      return;
    }
    if (event.authMenuSessionId !== undefined) return;
    void this.cancelRequest(surface.identity.requestId);
  };

  private handleTransportConnectionClosed = (): void => {
    const connectionId = this.state.connectionId;
    if (connectionId) this.handleConnectionClosed(connectionId);
  };

  private surfaceIdentityEqual(left: WalletIframeSurface, right: WalletIframeSurface): boolean {
    if (left.kind === 'hidden' || right.kind === 'hidden') return left.kind === right.kind;
    if (
      left.connectionId !== right.connectionId ||
      left.identity.surfaceId !== right.identity.surfaceId ||
      left.identity.requestId !== right.identity.requestId
    ) {
      return false;
    }
    if (left.kind === 'modal_auth_menu' || right.kind === 'modal_auth_menu') {
      return (
        left.kind === 'modal_auth_menu' &&
        right.kind === 'modal_auth_menu' &&
        left.authMenuSessionId === right.authMenuSessionId
      );
    }
    return true;
  }

  private currentSurfaceViewport(): WalletIframeSurfaceViewport {
    const visualViewport = window.visualViewport;
    const widthCandidate = visualViewport?.width ?? window.innerWidth;
    const heightCandidate = visualViewport?.height ?? window.innerHeight;
    const widthCssPx = Number.isFinite(widthCandidate) && widthCandidate > 0 ? widthCandidate : 1;
    const heightCssPx =
      Number.isFinite(heightCandidate) && heightCandidate > 0 ? heightCandidate : 1;
    const offsetLeftCandidate = visualViewport?.offsetLeft ?? 0;
    const offsetTopCandidate = visualViewport?.offsetTop ?? 0;
    return {
      widthCssPx,
      heightCssPx,
      offsetLeftCssPx: Number.isFinite(offsetLeftCandidate) ? offsetLeftCandidate : 0,
      offsetTopCssPx: Number.isFinite(offsetTopCandidate) ? offsetTopCandidate : 0,
    };
  }

  private renderActiveWalletIframeSurface(): void {
    const surface = this.walletIframeSurface;
    if (surface.kind === 'hidden') {
      this.surfaceRenderer.render(surface);
      return;
    }
    const measurement: WalletIframeSurfaceMeasurementState | undefined = this
      .activeSurfaceMeasurement
      ? {
          kind: 'measured',
          widthCssPx: this.activeSurfaceMeasurement.widthCssPx,
          heightCssPx: this.activeSurfaceMeasurement.heightCssPx,
        }
      : this.activeSurfaceMeasurementUnavailable
        ? { kind: 'unavailable' }
        : undefined;
    const viewport = this.currentSurfaceViewport();
    const resolvedGeometry = resolveWalletIframeSurfaceGeometry({
      presentation: surface.presentation,
      viewport,
      measurement,
    });
    const anchor =
      surface.kind === 'modal_auth_menu'
        ? this.hostedAuthMenuAnchors.get(surface.authMenuSessionId)
        : undefined;
    let anchorMetrics = hostedAuthMenuAnchorMetrics(anchor);
    let geometry = resolvedGeometry;
    let authMenuVisualScale = 1;
    if (
      surface.kind === 'modal_auth_menu' &&
      anchorMetrics &&
      isWalletIframeModalGeometry(resolvedGeometry) &&
      resolvedGeometry.kind !== 'viewport_fallback'
    ) {
      // The menu paints from a <body>-level dialog, so it reserves no layout
      // space of its own. Publish its height to the host anchor, which does sit
      // in the page flow, so following content is pushed down instead of being
      // covered.
      //
      // Reserve BEFORE re-measuring. Hosts commonly centre the block containing
      // the anchor, so changing the reserved height moves the anchor's top; if
      // the geometry were derived from the pre-reflow rect, the dialog would
      // animate its height now and its top on a later tick, reading as two
      // separate movements instead of one in-place resize. Height does not
      // depend on the anchor, so this settles in a single pass.
      publishHostedAuthMenuAnchorHeight(anchor, resolvedGeometry.heightCssPx);
      anchorMetrics = hostedAuthMenuAnchorMetrics(anchor) ?? anchorMetrics;
      authMenuVisualScale = anchorMetrics.visualScale;
      geometry = anchorWalletIframeModalGeometry(resolvedGeometry, viewport, {
        topCssPx: anchorMetrics.topCssPx,
        leftCssPx: anchorMetrics.leftCssPx,
        widthCssPx: anchorMetrics.layoutWidthCssPx,
        heightCssPx: anchorMetrics.heightCssPx,
      });
    }
    if (surface.kind === 'modal_auth_menu' && isWalletIframeModalGeometry(geometry)) {
      // The auth-menu dialog is position:absolute, so hand it DOCUMENT
      // coordinates. Scrolling then moves it with the page on the compositor
      // thread (no fixed-position lag), and because anchor viewport movement
      // and the scroll offset cancel out, scroll events re-derive identical
      // geometry and the render pipeline short-circuits.
      geometry = documentCoordinateAuthMenuGeometry(geometry);
    }
    this.overlayState.controller.setAuthMenuVisualScale(authMenuVisualScale);
    this.surfaceRenderer.render(surface, geometry);
  }

  private startHostedAuthMenuAnchorTracking(authMenuSessionId: HostedAuthMenuSessionId): void {
    if (this.hostedAuthMenuAnchorTrackingFrame !== null) {
      cancelAnimationFrame(this.hostedAuthMenuAnchorTrackingFrame);
    }
    this.hostedAuthMenuAnchorTrackingSession = authMenuSessionId;
    this.hostedAuthMenuAnchorTrackingDeadlineMs = performance.now() + 750;
    this.hostedAuthMenuAnchorTrackingFrame = requestAnimationFrame(
      this.updateHostedAuthMenuAnchorPosition,
    );
  }

  private readonly updateHostedAuthMenuAnchorPosition = (timestampMs: number): void => {
    this.hostedAuthMenuAnchorTrackingFrame = null;
    const authMenuSessionId = this.hostedAuthMenuAnchorTrackingSession;
    if (!authMenuSessionId) return;
    const surface = this.walletIframeSurface;
    if (surface.kind === 'modal_auth_menu' && surface.authMenuSessionId === authMenuSessionId) {
      this.renderActiveWalletIframeSurface();
    }
    if (timestampMs >= this.hostedAuthMenuAnchorTrackingDeadlineMs) return;
    this.hostedAuthMenuAnchorTrackingFrame = requestAnimationFrame(
      this.updateHostedAuthMenuAnchorPosition,
    );
  };

  private stopHostedAuthMenuAnchorTracking(authMenuSessionId: HostedAuthMenuSessionId): void {
    if (this.hostedAuthMenuAnchorTrackingSession !== authMenuSessionId) return;
    this.hostedAuthMenuAnchorTrackingSession = null;
    if (this.hostedAuthMenuAnchorTrackingFrame !== null) {
      cancelAnimationFrame(this.hostedAuthMenuAnchorTrackingFrame);
      this.hostedAuthMenuAnchorTrackingFrame = null;
    }
  }

  private handleSurfaceMeasurement(value: unknown): void {
    const measurement = parseWalletIframeSurfaceMeasurement(value);
    if (!measurement) return;
    const surface = this.walletIframeSurface;
    const connectionId = this.state.connectionId;
    if (!connectionId || surface.kind === 'hidden') return;
    if (measurement.requestId !== surface.identity.requestId) return;
    if (measurement.kind === 'measured_auth_menu_v1') {
      if (
        surface.kind !== 'modal_auth_menu' ||
        measurement.authMenuSessionId !== surface.authMenuSessionId
      ) {
        return;
      }
    } else if (surface.kind === 'modal_auth_menu') {
      return;
    }
    const trusted = trustedWalletIframeSurfaceMeasurementFromWire({
      connectionId,
      identity: surface.identity,
      measurement,
    });
    if (!trusted) return;
    if (
      this.activeSurfaceMeasurement &&
      this.activeSurfaceMeasurementGeneration === this.surfaceGeneration &&
      trusted.sequence <= this.activeSurfaceMeasurement.sequence
    ) {
      return;
    }
    this.activeSurfaceMeasurement = trusted;
    this.activeSurfaceMeasurementUnavailable = false;
    this.activeSurfaceMeasurementGeneration = this.surfaceGeneration;
    this.cancelMeasurementFallback();
    this.renderActiveWalletIframeSurface();
  }

  private requestSurfaceIdentity(requestId: WalletIframeRequestId): RequestSurfaceIdentity {
    return requestSurfaceIdentity({
      surfaceId: walletIframeSurfaceIdFromBoundary(`request-surface-${requestId}`),
      requestId,
    });
  }

  private beginRequestSurface(args: {
    kind: WalletIframeRequestSurfaceKind;
    requestId: WalletIframeRequestId;
    deadlineAtMs: number | null;
    payload: unknown;
    authMenuSessionId?: HostedAuthMenuSessionId;
  }): void {
    const connectionId = this.state.connectionId;
    if (!connectionId) {
      throw new Error('Wallet iframe connection is unavailable for a foreground surface');
    }
    const identity = this.requestSurfaceIdentity(args.requestId);
    let result: ReduceWalletIframeSurfaceResult;
    switch (args.kind) {
      case 'auth_menu': {
        if (!args.authMenuSessionId) {
          throw new Error('Hosted auth-menu request is missing its session identity');
        }
        result = this.transitionWalletIframeSurface({
          kind: 'auth_menu_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor('auth_menu', args.payload),
          authMenuSessionId: args.authMenuSessionId,
        });
        break;
      }
      case 'registration': {
        if (args.deadlineAtMs === null) {
          throw new Error('Registration surface requires a finite request deadline');
        }
        result = this.transitionWalletIframeSurface({
          kind: 'registration_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'registration',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          preparation: passkeyRegistrationPreparationReceipt(args.deadlineAtMs),
        });
        break;
      }
      case 'transaction':
        result = this.transitionWalletIframeSurface({
          kind: 'transaction_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'transaction',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
        });
        break;
      case 'key_export_near':
        result = this.transitionWalletIframeSurface({
          kind: 'key_export_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'key_export_near',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          exportKind: 'near_keypair',
        });
        break;
      case 'key_export_threshold':
        result = this.transitionWalletIframeSurface({
          kind: 'key_export_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'key_export_threshold',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          exportKind: 'threshold_ed25519_seed_from_yao',
        });
        break;
      case 'unlock':
        result = this.transitionWalletIframeSurface({
          kind: 'unlock_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'unlock',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          unlockKind: 'passkey',
        });
        break;
      case 'device_link':
        result = this.transitionWalletIframeSurface({
          kind: 'unlock_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'unlock',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          unlockKind: 'device_link',
        });
        break;
      case 'device_link_qr':
        result = this.transitionWalletIframeSurface({
          kind: 'device_link_qr_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'device_link_qr',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
        });
        break;
      case 'recovery_codes_show':
        result = this.transitionWalletIframeSurface({
          kind: 'recovery_codes_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'recovery_codes_show',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          operation: 'show',
        });
        break;
      case 'recovery_codes_rotate':
        result = this.transitionWalletIframeSurface({
          kind: 'recovery_codes_modal_request_started',
          connectionId,
          identity,
          presentation: requestSurfacePresentationFor(
            'recovery_codes_rotate',
            args.payload,
            this.mirroredConfirmationUiMode ?? undefined,
          ),
          operation: 'rotate',
        });
        break;
      default:
        return assertNeverWalletIframeRequestSurfaceKind(args.kind);
    }
    if (result.kind === 'rejected') {
      throw walletIframeSurfaceBusyError(result.error);
    }
    if (args.kind === 'auth_menu' && args.authMenuSessionId) {
      this.hostedAuthMenuConnectionIds.set(args.authMenuSessionId, connectionId);
    }
  }

  private finishRequestSurface(requestId: WalletIframeRequestId, cancelled: boolean): void {
    const connectionId = this.state.connectionId;
    if (!connectionId) return;
    this.transitionWalletIframeSurface({
      kind: cancelled ? 'request_cancelled' : 'request_finished',
      connectionId,
      identity: this.requestSurfaceIdentity(requestId),
    });
  }

  private hostedAuthMenuSessionIdForRequestId(requestId: string): HostedAuthMenuSessionId | null {
    for (const [sessionId, activeRequestId] of this.hostedAuthMenuRequestIds) {
      if (activeRequestId === requestId) return sessionId;
    }
    return null;
  }

  private settleHostedAuthMenuCancellation(
    authMenuSessionId: HostedAuthMenuSessionId,
    reason: 'close_button' | 'component_unmounted' | 'connection_closed',
  ): void {
    const requestId = this.hostedAuthMenuRequestIds.get(authMenuSessionId);
    this.cancelledHostedAuthMenuSessions.add(authMenuSessionId);
    this.hostedAuthMenuConnectionIds.delete(authMenuSessionId);
    if (!requestId) return;
    this.hostedAuthMenuRequestIds.delete(authMenuSessionId);

    const pending = this.state.pending.get(requestId);
    if (pending) {
      if (pending.timer !== undefined) window.clearTimeout(pending.timer);
      this.state.pending.delete(requestId);
      this.progressBus.unregister(requestId);
      if (reason === 'connection_closed' || reason === 'close_button') {
        pending.resolve({
          ok: true,
          result: {
            kind: 'cancelled',
            authMenuSessionId,
            reason,
          },
        });
      } else {
        pending.reject(new Error(`Hosted auth-menu cancelled: ${reason}`));
      }
    }

    const surface = this.walletIframeSurface;
    if (surface.kind === 'modal_auth_menu' && surface.authMenuSessionId === authMenuSessionId) {
      this.transitionWalletIframeSurface({
        kind: 'auth_menu_request_cancelled',
        connectionId: surface.connectionId,
        identity: surface.identity,
        authMenuSessionId,
      });
    }
  }

  private settlePendingRequestsForConnectionClosed(connectionId: WalletIframeConnectionId): void {
    for (const [requestId, pending] of this.state.pending) {
      if (pending.connectionId !== connectionId) continue;
      if (this.hostedAuthMenuSessionIdForRequestId(pending.requestId)) continue;

      this.state.pending.delete(requestId);
      if (pending.timer !== undefined) window.clearTimeout(pending.timer);

      const error = new WalletIframeConnectionClosedRequestError(
        pending.requestId,
        pending.connectionId,
        pending.requestType,
      );
      const fallbackProgress = createTerminalProgressForRequest({
        requestType: pending.requestType,
        requestId: pending.requestId,
        status: 'failed',
        message: error.message,
        errorCode: error.code,
      });
      if (fallbackProgress) {
        this.progressBus.dispatch({ requestId: pending.requestId, payload: fallbackProgress });
      }
      this.progressBus.unregister(pending.requestId);
      this.finishRequestSurface(pending.requestId, false);
      this.sendBestEffortCancel(pending.requestId);
      pending.reject(error);
    }
  }

  private handleConnectionClosed(connectionId: WalletIframeConnectionId): void {
    this.transactionSurfaceQueue.cancelAll(
      new Error('Wallet iframe connection closed while waiting for transaction surface'),
    );
    for (const [authMenuSessionId, activeConnectionId] of this.hostedAuthMenuConnectionIds) {
      if (activeConnectionId !== connectionId) continue;
      this.settleHostedAuthMenuCancellation(authMenuSessionId, 'connection_closed');
    }
    this.settlePendingRequestsForConnectionClosed(connectionId);
    if (
      this.walletIframeSurface.kind !== 'hidden' &&
      this.walletIframeSurface.connectionId === connectionId
    ) {
      this.transitionWalletIframeSurface({ kind: 'connection_closed', connectionId });
    }
    this.overlayState.controller.dispose();
    this.updateSurfaceViewportListeners();
    if (this.state.connectionId === connectionId) {
      this.state.connectionId = null;
      this.state.port = null;
      this.state.ready = false;
    }
  }

  private hideRequestSurface(requestId: WalletIframeRequestId): void {
    const connectionId = this.state.connectionId;
    if (!connectionId) return;
    this.transitionWalletIframeSurface({
      kind: 'request_surface_hidden',
      connectionId,
      identity: this.requestSurfaceIdentity(requestId),
    });
  }

  private finishDeviceLinkQrSurface(): void {
    const surface = this.walletIframeSurface;
    if (surface.kind !== 'modal_device_link_qr') return;
    this.finishRequestSurface(surface.identity.requestId, true);
  }

  /**
   * Subscribe to service-ready event. Returns an unsubscribe function.
   * If already ready, the listener is invoked on next microtask.
   */
  onReady(listener: () => void): () => void {
    if (this.state.ready) {
      Promise.resolve().then(() => {
        listener();
      });
      return () => {};
    }
    this.listeners.ready.add(listener);
    return () => {
      this.listeners.ready.delete(listener);
    };
  }

  onHostedAuthMenuExternalAuthRequest(
    listener: (payload: HostedAuthMenuExternalAuthRequest) => void,
  ): () => void {
    this.listeners.hostedAuthMenuExternalAuthRequest.add(listener);
    return () => this.listeners.hostedAuthMenuExternalAuthRequest.delete(listener);
  }

  onHostedAuthMenuDemoEmailOtpDelivery(
    listener: (payload: HostedAuthMenuDemoEmailOtpDelivery) => void,
  ): () => void {
    this.listeners.hostedAuthMenuDemoEmailOtpDelivery.add(listener);
    return () => this.listeners.hostedAuthMenuDemoEmailOtpDelivery.delete(listener);
  }

  async resolveHostedAuthMenuExternalAuth(
    resolution: HostedAuthMenuExternalAuthResolutionInput,
  ): Promise<void> {
    const sessionId = hostedAuthMenuSessionIdFromBoundary(resolution.authMenuSessionId);
    if (!sessionId) throw new Error('authMenuSessionId must be a non-empty string');
    const activeRequestId = this.hostedAuthMenuRequestIds.get(sessionId);
    if (!activeRequestId) return;
    const normalized = parseHostedAuthMenuExternalAuthResolution({
      ...resolution,
      requestId: activeRequestId,
    });
    if (!normalized) throw new Error('Hosted auth-menu external-auth resolution is invalid');
    await this.post<void>({
      type: 'PM_RESOLVE_AUTH_MENU_EXTERNAL_AUTH',
      payload: normalized,
    }).then(() => undefined);
  }

  private emitReady(): void {
    if (!this.listeners.ready.size) return;
    for (const cb of Array.from(this.listeners.ready)) {
      cb();
    }
    // Keep listeners registered; callers can unsubscribe if desired.
  }

  /**
   * Initialize the transport and configure the wallet host.
   * Safe to call multiple times; concurrent calls deduplicate via initInFlight.
   */
  async init(hostedWalletSession?: HostedWalletSeamsSessionSource): Promise<void> {
    if (this.state.initInFlight) {
      return this.state.initInFlight;
    }
    if (this.state.ready && this.exactSessionState !== null) return;
    this.state.initInFlight = (async () => {
      // Respect autoMount=false by deferring connect until first use
      if (this.opts.testOptions.autoMount !== false) {
        // A connected iframe cannot move between parents without reloading and losing its MessagePort.
        this.overlayState.controller.prepare();
        this.state.port = await this.transport.connect();
        const connectionId = walletIframeConnectionIdFromBoundary(
          `wallet-iframe-connection-${secureRandomBase36(16, 'wallet iframe connection IDs')}`,
        );
        this.state.connectionId = connectionId;
        this.state.port.onmessage = (ev) => this.onPortMessage(ev, connectionId);
        this.state.port.start?.();
        this.state.ready = true;
        // Seed the confirmation-config mirror. The host only pushes
        // PREFERENCES_CHANGED once its SeamsWeb has booted (lazily, on the
        // first real request), so on a fresh page the mirror can still be
        // empty when the first surface is dressed — which made an export
        // resolve to the modal fallback instead of the wallet's persisted
        // drawer preference. Fire-and-forget: readiness must not wait on it.
        void this.getConfirmationConfig().catch(() => {});
      }
      const signingSessionPersistenceMode = this.opts.signingSessionPersistenceMode;
      await this.post({
        type: 'PM_SET_CONFIG',
        payload: {
          chains: this.opts.chains,
          relayerAccount: this.opts.relayerAccount,
          relayer: this.opts.relayer,
          registration: this.opts.registration,
          signingSessionDefaults: this.opts.signingSessionDefaults,
          signingSessionPersistenceMode,
          routerAb: this.opts.routerAb,
          routerAbEcdsaDerivationPresignaturePool:
            this.opts.routerAbEcdsaDerivationPresignaturePool,
          provisioningDefaults: this.opts.provisioningDefaults,
          iframeWallet: this.opts.rpIdOverride
            ? { rpIdOverride: this.opts.rpIdOverride }
            : undefined,
          authenticatorOptions: this.opts.authenticatorOptions,
          appearance: this.getCurrentAppearance(),
          uiRegistry: this.opts.uiRegistry,
          // for embedded Lit components
          assetsBaseUrl: (() => {
            try {
              const base = new URL(this.opts.sdkBasePath, this.walletOriginUrl).toString();
              return base.endsWith('/') ? base : `${base}/`;
            } catch {
              const fallback = new URL('/sdk/', this.walletOriginUrl).toString();
              return fallback.endsWith('/') ? fallback : `${fallback}/`;
            }
          })(),
        },
      });
      if (hostedWalletSession) {
        await this.ensureHostedWalletSeamsSession(hostedWalletSession);
      }
      await this.refreshExactSessionAndEmitLoginStatus('restore', { kind: 'current' });
      // Resolve the host's confirmation mode while initialization is still in flight. Foreground
      // requests can then begin their surface without a nested config RPC on first use.
      await this.getConfirmationConfig().catch(() => undefined);
      this.emitReady();
    })();

    try {
      await this.state.initInFlight;
    } finally {
      this.state.initInFlight = null;
    }
  }

  isReady(): boolean {
    return this.state.ready;
  }

  async initializeHostedWalletSeamsSession(source: HostedWalletSeamsSessionSource): Promise<void> {
    await this.init(source);
    await this.ensureHostedWalletSeamsSession(source);
  }

  private async ensureHostedWalletSeamsSession(
    source: HostedWalletSeamsSessionSource | null,
  ): Promise<void> {
    if (!source) return;
    const normalizedSource: HostedWalletSeamsSessionSource = {
      relayUrl: canonicalHostedWalletRelayUrl(source.relayUrl),
      appSessionJwt: source.appSessionJwt,
    };
    if (
      this.state.hostedWalletSessionExpiresAtMs > Date.now() + 30_000 &&
      hostedWalletSessionSourcesMatch(this.state.hostedWalletSessionSource, normalizedSource)
    ) {
      return;
    }
    const inFlight = this.state.hostedWalletSessionInFlight;
    if (inFlight) {
      await inFlight;
      if (
        this.state.hostedWalletSessionExpiresAtMs > Date.now() + 30_000 &&
        hostedWalletSessionSourcesMatch(this.state.hostedWalletSessionSource, normalizedSource)
      ) {
        return;
      }
    }
    this.state.hostedWalletSessionInFlight =
      this.exchangeHostedWalletSeamsSession(normalizedSource);
    try {
      await this.state.hostedWalletSessionInFlight;
    } finally {
      this.state.hostedWalletSessionInFlight = null;
    }
  }

  private async exchangeHostedWalletSeamsSession(
    source: HostedWalletSeamsSessionSource,
  ): Promise<void> {
    const relayUrl = canonicalHostedWalletRelayUrl(source.relayUrl);
    const appSessionJwt = requireAppSessionJwtAtParentBoundary(source.appSessionJwt);
    const response = await fetch(joinNormalizedUrl(relayUrl, '/session/exchange'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${appSessionJwt}`,
      },
      body: JSON.stringify({
        sessionKind: 'jwt',
        exchange: {
          type: 'hosted_wallet_exchange_code',
          wallet_origin: this.walletOriginOrigin,
        },
      }),
    });
    const raw = await readSessionExchangeJson(response);
    if (!response.ok) throw parseHostedWalletExchangeFailure(raw, response.status);
    const delivery = parseHostedWalletExchangeDelivery(raw, {
      appOrigin: window.location.origin,
      walletOrigin: this.walletOriginOrigin,
    });
    const redeemed = await this.post<HostedWalletSeamsSessionRedemption>({
      type: 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION',
      payload: {
        exchangeCode: delivery.exchangeCode,
        nonce: delivery.nonce,
        relayUrl,
      },
    });
    if (
      redeemed.result.kind !== 'redeemed_hosted_wallet_seams_session' ||
      !Number.isSafeInteger(redeemed.result.expiresAtMs) ||
      redeemed.result.expiresAtMs <= Date.now()
    ) {
      throw new Error('wallet iframe returned an invalid hosted-wallet session redemption');
    }
    this.state.hostedWalletSessionExpiresAtMs = redeemed.result.expiresAtMs;
    this.state.hostedWalletSessionSource = {
      relayUrl,
      appSessionJwt,
    };
  }

  getTransportDiagnosticsSnapshot(): WalletIframeTransportDiagnostics {
    return this.transport.getDiagnosticsSnapshot();
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    const connectionId = this.state.connectionId;
    if (connectionId) this.handleConnectionClosed(connectionId);
    this.cancelMeasurementFallback();
    this.updateSurfaceViewportListeners();
    this.overlayState.controller.dispose();
    this.transport.dispose();
  }

  // ===== UI registry/window-message helpers (generic mounting) =====
  registerUiTypes(registry: WalletUIRegistry): void {
    const iframe = this.overlayState.controller.prepare();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_REGISTER_TYPES', payload: registry }, target);
  }

  mountUiComponent(params: {
    key: string;
    props?: Record<string, unknown>;
    targetSelector?: string;
    id?: string;
  }): void {
    const iframe = this.overlayState.controller.prepare();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_MOUNT', payload: params }, target);
  }

  updateUiComponent(params: { id: string; props?: Record<string, unknown> }): void {
    const iframe = this.overlayState.controller.prepare();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_UPDATE', payload: params }, target);
  }

  unmountUiComponent(id: string): void {
    const iframe = this.overlayState.controller.prepare();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_UNMOUNT', payload: { id } }, target);
  }

  // ===== Public RPC helpers =====

  // Subscribe to wallet-host login status changes observed by this client
  onLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void {
    this.listeners.loginStatus.add(listener);
    return () => {
      this.listeners.loginStatus.delete(listener);
    };
  }

  // Subscribe to wallet-host preference changes (authoritative in wallet-iframe mode).
  onPreferencesChanged(listener: (payload: PreferencesChangedPayload) => void): () => void {
    this.listeners.preferencesChanged.add(listener);
    if (this.lastPreferencesChangedPayload) {
      this.notifyPreferencesChangedListener(listener, this.lastPreferencesChangedPayload);
    }
    return () => {
      this.listeners.preferencesChanged.delete(listener);
    };
  }

  onSdkLifecycleEvent(listener: SdkLifecycleEventListener): () => void {
    this.listeners.sdkLifecycleEvent.add(listener);
    return () => {
      this.listeners.sdkLifecycleEvent.delete(listener);
    };
  }

  getMirroredExactSessionState(): WalletIframeExactSessionState {
    if (this.exactSessionState === null) {
      throw new Error('Wallet iframe exact session state has not been initialized');
    }
    return this.exactSessionState;
  }

  async getExactSessionState(): Promise<WalletIframeExactSessionState> {
    if (this.hostedAuthMenuRequestIds.size > 0 && this.exactSessionState !== null) {
      return this.exactSessionState;
    }
    return await this.refreshExactSessionState('current', { kind: 'current' });
  }

  private async refreshExactSessionState(
    authenticationRead: 'restore' | 'current',
    wallet: { readonly kind: 'current' } | { readonly kind: 'exact'; readonly walletId: string },
  ): Promise<WalletIframeExactSessionState> {
    const response = await this.post<unknown>({
      type: 'PM_GET_EXACT_WALLET_SESSION_STATE',
      payload: { authenticationRead, wallet },
    });
    const state = parseWalletIframeExactSessionState(response.result);
    this.exactSessionState = state;
    return state;
  }

  private emitLoginStatusChanged(status: { isLoggedIn: boolean; walletId: string | null }): void {
    for (const cb of Array.from(this.listeners.loginStatus)) {
      try {
        cb(status);
      } catch {}
    }
  }

  private mirrorExactSessionAndEmitLoginStatus(state: WalletIframeExactSessionState): void {
    this.exactSessionState = state;
    this.emitLoginStatusChanged(walletIframeLoginStatusFromExactSession(state));
  }

  private async refreshExactSessionAndEmitLoginStatus(
    authenticationRead: 'restore' | 'current',
    wallet: { readonly kind: 'current' } | { readonly kind: 'exact'; readonly walletId: string },
  ): Promise<WalletIframeExactSessionState> {
    const state = await this.refreshExactSessionState(authenticationRead, wallet);
    this.mirrorExactSessionAndEmitLoginStatus(state);
    return state;
  }

  private emitPreferencesChanged(payload: PreferencesChangedPayload): void {
    this.lastPreferencesChangedPayload = payload;
    this.mirroredConfirmationUiMode = payload.confirmationConfig.uiMode;
    for (const cb of Array.from(this.listeners.preferencesChanged)) {
      this.notifyPreferencesChangedListener(cb, payload);
    }
  }

  private notifyPreferencesChangedListener(
    listener: (payload: PreferencesChangedPayload) => void,
    payload: PreferencesChangedPayload,
  ): void {
    try {
      listener(payload);
    } catch {}
  }

  private emitSdkLifecycleEvent(event: SdkLifecycleEvent): void {
    const eventName = event.event;
    switch (eventName) {
      case 'signing_session.expired':
        this.failPendingRequestsForExpiredSession(event);
        this.mirrorExpiredSession(event);
        if (!this.markSigningSessionExpiryAsNew(event)) return;
        for (const listener of Array.from(this.listeners.sdkLifecycleEvent)) {
          listener(event);
        }
        return;
      case 'registration.near_provisioning_changed':
        for (const listener of Array.from(this.listeners.sdkLifecycleEvent)) {
          listener(event);
        }
        return;
      default:
        assertNeverSdkLifecycleEventName(eventName);
    }
  }

  private mirrorExpiredSession(event: SigningSessionExpiredEvent): void {
    const state = this.exactSessionState;
    if (state === null || state.kind !== 'active_session') return;
    if (state.walletId !== event.walletId || state.walletSessionId !== event.walletSessionId)
      return;
    this.exactSessionState = {
      kind: 'expired_session',
      walletId: event.walletId,
      authorizationId: state.authorizationId,
      walletSessionId: event.walletSessionId,
      authMethod: event.authMethod,
      expiresAtMs: event.expiresAtMs,
    };
    this.emitLoginStatusChanged(walletIframeLoginStatusFromExactSession(this.exactSessionState));
  }

  private failPendingRequestsForExpiredSession(event: SigningSessionExpiredEvent): void {
    for (const [requestId, pending] of this.state.pending) {
      const binding = pending.sessionBinding;
      if (binding.kind !== 'exact_session') continue;
      if (
        binding.walletId !== event.walletId ||
        binding.walletSessionId !== event.walletSessionId
      ) {
        continue;
      }
      this.state.pending.delete(requestId);
      if (pending.timer !== undefined) window.clearTimeout(pending.timer);
      this.progressBus.unregister(requestId);
      this.finishRequestSurface(requestId as WalletIframeRequestId, true);
      this.sendBestEffortCancel(requestId);
      pending.reject(
        new WalletIframeSessionExpiredRequestError({
          kind: 'wallet_iframe_request_failure',
          code: 'wallet_session_expired',
          walletId: event.walletId,
          walletSessionId: event.walletSessionId,
        }),
      );
    }
  }

  private markSigningSessionExpiryAsNew(event: SigningSessionExpiredEvent): boolean {
    const expiredSessionIds = this.expiredSigningSessionsByWallet.get(event.walletId);
    if (expiredSessionIds?.has(event.walletSessionId)) return false;
    if (expiredSessionIds) {
      expiredSessionIds.add(event.walletSessionId);
      return true;
    }
    this.expiredSigningSessionsByWallet.set(event.walletId, new Set([event.walletSessionId]));
    return true;
  }

  // ===== SeamsWeb RPCs =====

  async signTransactionWithActions(payload: {
    walletId: string;
    nearAccountId: string;
    transaction: TransactionInput;
    options: {
      signerSlot?: number;
      onEvent?: (ev: SigningFlowEvent) => void;
      onError?: (error: Error) => void;
      afterCall?: AfterCall<SignTransactionResult>;
      // Allow minimal overrides (e.g., { uiMode: 'drawer' })
      confirmationConfig?: Partial<ConfirmationConfig>;
      confirmerText?: { title?: string; body?: string };
    };
  }): Promise<SignTransactionResult> {
    // Do not forward non-cloneable functions in options; host emits its own PROGRESS messages
    const safeOptions = {
      ...(typeof payload.options.signerSlot === 'number'
        ? { signerSlot: payload.options.signerSlot }
        : {}),
      ...(payload.options.confirmationConfig
        ? { confirmationConfig: payload.options.confirmationConfig }
        : {}),
      ...(payload.options.confirmerText ? { confirmerText: payload.options.confirmerText } : {}),
    };
    const res = await this.post<SignTransactionResult>({
      type: 'PM_SIGN_TX_WITH_ACTIONS',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        transaction: payload.transaction,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return normalizeSignedTransactionResult(res.result);
  }

  async signDelegateAction(payload: {
    walletId: string;
    nearAccountId: string;
    delegate: DelegateActionInput;
    options: {
      signerSlot?: number;
      onEvent?: (ev: SigningFlowEvent) => void;
      onError?: (error: Error) => void;
      afterCall?: AfterCall<any>;
      confirmationConfig?: Partial<ConfirmationConfig>;
      confirmerText?: { title?: string; body?: string };
    };
  }): Promise<SignDelegateActionResult> {
    const safeOptions = {
      ...(typeof payload.options.signerSlot === 'number'
        ? { signerSlot: payload.options.signerSlot }
        : {}),
      ...(payload.options.confirmationConfig
        ? { confirmationConfig: payload.options.confirmationConfig }
        : {}),
      ...(payload.options.confirmerText ? { confirmerText: payload.options.confirmerText } : {}),
    };
    const res = await this.post<SignDelegateActionResult>({
      type: 'PM_SIGN_DELEGATE_ACTION',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        delegate: payload.delegate,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async registerWallet(
    payload: Parameters<RegistrationCapability['registerWallet']>[0],
  ): Promise<RegistrationResult> {
    const transport = hostedWalletRegistrationTransport(payload.authMethod, this.opts.relayer?.url);
    await this.ensureHostedWalletSeamsSession(transport.sessionSource);
    const confirmationConfig = payload.options?.confirmationConfig;
    if (confirmationConfig) {
      const base = await this.getConfirmationConfig();
      await this.setConfirmationConfig({ ...base, ...confirmationConfig });
    }
    const safeOptions = removeFunctionsFromOptions(payload.options);
    const res = await this.post<RegistrationResult>(
      {
        type: 'PM_REGISTER_WALLET',
        payload: {
          authMethod: transport.authMethod,
          wallet: payload.wallet,
          signerSelection: registrationSignerSetRequestSelection(payload.signerSelection),
          options: safeOptions,
          ...(confirmationConfig ? { confirmationConfig } : {}),
        },
        options: {
          onProgress: bridgeRegistrationProgress(
            payload.options?.onEvent,
            payload.options?.onTimingSpan,
          ),
        },
      },
      { timeoutMs: WALLET_IFRAME_REGISTRATION_TIMEOUT_MS },
    );
    const walletId = res.result?.success ? String(res.result.walletId || '') : '';
    if (walletId) {
      await this.refreshExactSessionAndEmitLoginStatus('current', { kind: 'exact', walletId });
    }
    return res.result;
  }

  async getNearProvisioningState(args: {
    walletId: WalletId | string;
  }): Promise<NearProvisioningState | null> {
    const walletId = toWalletId(args.walletId);
    const response = await this.post<unknown>({
      type: 'PM_GET_NEAR_PROVISIONING_STATE',
      payload: { walletId: String(walletId) },
    });
    if (response.result === null) return null;
    const state = parseNearProvisioningState(response.result);
    if (!state) throw new Error('[WalletIframeRouter] Invalid NEAR provisioning state response');
    return state;
  }

  async addWalletSigner(
    payload: Parameters<RegistrationCapability['addWalletSigner']>[0],
  ): Promise<RegistrationResult> {
    const confirmationConfig = payload.options?.confirmationConfig;
    if (confirmationConfig) {
      const base = await this.getConfirmationConfig();
      await this.setConfirmationConfig({ ...base, ...confirmationConfig });
    }
    const safeOptions = removeFunctionsFromOptions(payload.options);
    const res = await this.post<RegistrationResult>({
      type: 'PM_ADD_WALLET_SIGNER',
      payload: {
        walletId: payload.walletId,
        rpId: payload.rpId,
        signerSelection: payload.signerSelection,
        options: safeOptions,
        ...(confirmationConfig ? { confirmationConfig } : {}),
      },
      options: {
        onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
      },
    });
    return res.result;
  }

  async addPasskey(
    payload: Parameters<RegistrationCapability['addPasskey']>[0],
  ): Promise<AddPasskeyResult> {
    const confirmationConfig = payload.options?.confirmationConfig;
    if (confirmationConfig) {
      const base = await this.getConfirmationConfig();
      await this.setConfirmationConfig({ ...base, ...confirmationConfig });
    }
    const safeOptions = removeFunctionsFromOptions(payload.options);
    const res = await this.post<AddPasskeyResult>({
      type: 'PM_ADD_PASSKEY',
      payload: {
        walletId: payload.walletId,
        rpId: payload.rpId,
        options: safeOptions,
        ...(confirmationConfig ? { confirmationConfig } : {}),
      },
      options: {
        onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
      },
    });
    return res.result;
  }

  async bootstrapEcdsaSession(
    payload: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const safePayload = removeFunctionsFromOptions(payload);
    const res = await this.post<ThresholdEcdsaSessionBootstrapResult>(
      {
        type: 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION',
        payload: safePayload,
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async unlock(payload: LoginUnlockRequest): Promise<LoginAndCreateSessionResult> {
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSourceFromUnlock(payload, this.opts.relayer?.url),
    );
    const unlockPayload = buildPMUnlockPayload(payload);
    const onEvent = unlockOnEventFromRequest(payload);
    const res = await this.post<LoginAndCreateSessionResult>({
      type: 'PM_UNLOCK',
      payload: unlockPayload,
      options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
    });
    const result = res.result;
    if (result.success) {
      await this.refreshExactSessionAndEmitLoginStatus('current', { kind: 'current' });
    }
    return result;
  }

  async getWalletSession(walletId?: string): Promise<WalletSession> {
    const expectedWalletId = walletId === undefined ? undefined : parseRequestedWalletId(walletId);
    const res = await this.post<unknown>({
      type: 'PM_GET_WALLET_SESSION',
      payload: expectedWalletId ? { walletId: expectedWalletId } : undefined,
    });
    return parseWalletSessionFromBoundary(res.result, expectedWalletId);
  }

  async requestEmailOtpChallenge(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (ev: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const { onEvent, appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpChallengeResult>({
      type: 'PM_REQUEST_EMAIL_OTP_CHALLENGE',
      payload: wirePayload,
      options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
    });
    return res.result;
  }

  async requestEmailOtpEnrollmentChallenge(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    onEvent?: (ev: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const { onEvent, appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpChallengeResult>({
      type: 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE',
      payload: wirePayload,
      options: { onProgress: this.wrapOnEvent(onEvent, isRegistrationFlowEvent) },
    });
    return res.result;
  }

  async requestEmailOtpSigningSessionChallenge(payload: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    onEvent?: (ev: UnlockFlowEvent) => void;
  }): Promise<Pick<EmailOtpChallengeResult, 'challengeId' | 'emailHint'>> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<Pick<EmailOtpChallengeResult, 'challengeId' | 'emailHint'>>({
      type: 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE',
      payload: wirePayload,
      options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
    });
    return res.result;
  }

  async exchangeGoogleEmailOtpSession(payload: {
    idToken: string;
    accountMode: 'register' | 'login';
    relayUrl?: string;
    sessionKind?: 'jwt' | 'cookie';
    onEvent?: (ev: RegistrationFlowEvent | UnlockFlowEvent) => void;
  }): Promise<GoogleEmailOtpSessionExchangeResult> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<GoogleEmailOtpSessionExchangeResult>({
      type: 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION',
      payload: wirePayload,
      options: {
        onProgress:
          payload.accountMode === 'register'
            ? this.wrapOnEvent(onEvent, isRegistrationFlowEvent)
            : this.wrapOnEvent(onEvent, isUnlockFlowEvent),
      },
    });
    return res.result;
  }

  private googleEmailOtpWalletAuthFlowFromWire(
    wire: PMGoogleEmailOtpWalletAuthWireFlow,
    onDemoOtp: ((response: DemoEmailOtpCodeResponse) => void) | undefined,
  ): GoogleEmailOtpWalletAuthFlow {
    emitDemoEmailOtpCodeFromWire({ wire, onDemoOtp });
    const cancel = async (): Promise<void> => {
      await this.post<void>({
        type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL',
        payload: {
          flowHandleId: wire.flowHandleId,
          flowId: wire.flowId,
          walletId: wire.walletId,
          mode: wire.mode,
        },
      });
    };
    if (wire.mode === 'register') {
      return {
        kind: 'google_email_otp_wallet_auth_flow_v1',
        state: 'registration_ready',
        flowId: wire.flowId,
        requestedMode: wire.requestedMode,
        mode: 'register',
        walletId: walletIdFromString(wire.walletId),
        emailHint: wire.emailHint,
        prompt: wire.prompt,
        expiresAtMs: wire.expiresAtMs,
        completeRegistration: async (): Promise<
          GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationCompleted>
        > => {
          const res = await this.post<PMGoogleEmailOtpWalletAuthCompleteRegistrationWireResult>(
            {
              type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
              payload: {
                flowHandleId: wire.flowHandleId,
                flowId: wire.flowId,
                walletId: wire.walletId,
                mode: wire.mode,
              },
            },
            {
              timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
              progressTimeoutExtensionFactor: 1,
            },
          );
          if (res.result.ok) {
            this.mirrorExactSessionAndEmitLoginStatus(
              exactSessionStateFromWalletSession(res.result.value.session),
            );
          }
          return res.result;
        },
        rerollWalletId: async (): Promise<
          GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthRegistrationFlow>
        > => {
          const res = await this.post<PMGoogleEmailOtpWalletAuthRegistrationWireResult>({
            type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
            payload: {
              flowHandleId: wire.flowHandleId,
              flowId: wire.flowId,
              walletId: wire.walletId,
              mode: wire.mode,
            },
          });
          if (!res.result.ok) return res.result;
          const flow = this.googleEmailOtpWalletAuthFlowFromWire(res.result.value, onDemoOtp);
          if (flow.mode !== 'register') {
            throw new Error('Google Email OTP registration reroll returned a login flow');
          }
          return { ok: true, value: flow };
        },
        cancel,
      };
    }
    return {
      kind: 'google_email_otp_wallet_auth_flow_v1' as const,
      state: 'challenge_sent' as const,
      flowId: wire.flowId,
      requestedMode: wire.requestedMode,
      mode: 'login' as const,
      walletId: walletIdFromString(wire.walletId),
      emailHint: wire.emailHint,
      prompt: wire.prompt,
      delivery: wire.delivery,
      expiresAtMs: wire.expiresAtMs,
      resend: async (): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> => {
        const res = await this.post<
          PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthWireFlow>
        >({
          type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND',
          payload: {
            flowHandleId: wire.flowHandleId,
            flowId: wire.flowId,
            walletId: wire.walletId,
            mode: wire.mode,
          },
        });
        return res.result.ok
          ? {
              ok: true,
              value: this.googleEmailOtpWalletAuthFlowFromWire(res.result.value, onDemoOtp),
            }
          : res.result;
      },
      submit: async (input: {
        otpCode: string;
      }): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthSubmitSuccess>> => {
        const res = await this.post<PMGoogleEmailOtpWalletAuthSubmitWireResult>(
          {
            type: 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT',
            payload: {
              flowHandleId: wire.flowHandleId,
              flowId: wire.flowId,
              walletId: wire.walletId,
              mode: wire.mode,
              otpCode: input.otpCode,
            },
          },
          {
            timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
            progressTimeoutExtensionFactor: 1,
          },
        );
        if (res.result.ok) {
          await this.refreshExactSessionAndEmitLoginStatus('current', { kind: 'current' });
        }
        return res.result;
      },
      cancel,
    };
  }

  async beginGoogleEmailOtpWalletAuth(
    payload: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> {
    const { onDemoOtp, onEvent, ...wirePayload } = payload;
    const diagnosticsEnabled =
      Reflect.get(globalThis, '__SEAMS_EMAIL_OTP_UNLOCK_DIAGNOSTICS') === true;
    const registrationBenchmarkTimings =
      Reflect.get(globalThis, '__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS') === true;
    const requestPayload: PMGoogleEmailOtpWalletAuthStartPayload = {
      ...wirePayload,
      diagnostics: {
        emailOtpUnlockTimings: diagnosticsEnabled,
        registrationBenchmarkTimings,
      },
    };
    const res = await this.post<
      PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthWireFlow>
    >(
      {
        type: 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
        payload: requestPayload,
        options: {
          onProgress:
            payload.mode === 'register'
              ? this.wrapOnEvent(onEvent, isRegistrationFlowEvent)
              : this.wrapOnEvent(onEvent, isUnlockFlowEvent),
        },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result.ok
      ? {
          ok: true,
          value: this.googleEmailOtpWalletAuthFlowFromWire(res.result.value, onDemoOtp),
        }
      : res.result;
  }

  async enrollEmailOtp(payload: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    groupId?: string;
    appSessionJwt?: string;
    onEvent?: (ev: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpBackedUpEnrollmentResult> {
    const { onEvent, appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpBackedUpEnrollmentResult>(
      {
        type: 'PM_ENROLL_EMAIL_OTP',
        payload: wirePayload,
        options: { onProgress: this.wrapOnEvent(onEvent, isRegistrationFlowEvent) },
      },
      {
        timeoutMs: WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async loginWithEmailOtpEcdsaCapability(
    payload: EmailOtpEcdsaCapabilityArgs & {
      publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
    },
  ): Promise<EmailOtpEcdsaCapabilityResult> {
    const { onEvent, appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpEcdsaCapabilityResult>(
      {
        type: 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
        payload: wirePayload,
        options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    await this.refreshExactSessionAndEmitLoginStatus('current', { kind: 'current' });
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async refreshEmailOtpSigningSession(payload: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
    onEvent?: (ev: UnlockFlowEvent) => void;
  }): Promise<EmailOtpEcdsaCapabilityResult> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<EmailOtpEcdsaCapabilityResult>(
      {
        type: 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION',
        payload: wirePayload,
        options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    await this.refreshExactSessionAndEmitLoginStatus('current', { kind: 'current' });
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async getEmailOtpRecoveryCodeStatus(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeStatus> {
    const { appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpRecoveryCodeStatus>({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      payload: wirePayload,
    });
    return res.result;
  }

  async showEmailOtpRecoveryCodes(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<{
    status: EmailOtpRecoveryCodeStatus;
    displayedStoredCodes: boolean;
  }> {
    const { appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<{
      status: EmailOtpRecoveryCodeStatus;
      displayedStoredCodes: boolean;
    }>(
      {
        type: 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES',
        payload: wirePayload,
      },
      {
        timeoutMs: WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async rotateEmailOtpRecoveryCodes(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeRotationResult> {
    const { appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<EmailOtpRecoveryCodeRotationResult>(
      {
        type: 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES',
        payload: wirePayload,
      },
      {
        timeoutMs: WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async requestWalletRecoveryChallenge(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<{
    challengeId: string;
    otpChannel: WalletEmailOtpChannel;
    emailHint?: string;
    expiresAtMs?: number;
  }> {
    const { appSessionJwt, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<{
      challengeId: string;
      otpChannel: WalletEmailOtpChannel;
      emailHint?: string;
      expiresAtMs?: number;
    }>({
      type: 'PM_REQUEST_WALLET_RECOVERY_CHALLENGE',
      payload: wirePayload,
    });
    return res.result;
  }

  async requestWalletRecoveryBootstrapChallenge(payload: {
    walletId: string;
    orgId: string;
    relayUrl?: string;
  }): Promise<WalletRecoveryBootstrapChallengeResult> {
    const { relayUrl, ...wirePayload } = payload;
    const res = await this.post<WalletRecoveryBootstrapChallengeResult>({
      type: 'PM_REQUEST_WALLET_RECOVERY_BOOTSTRAP_CHALLENGE',
      payload: { ...wirePayload, ...(relayUrl ? { relayUrl } : {}) },
    });
    return res.result;
  }

  async verifyWalletRecoveryBootstrap(payload: {
    walletId: string;
    orgId: string;
    challengeId: string;
    otpCode: string;
    relayUrl?: string;
  }): Promise<WalletRecoveryBootstrapVerifyResult> {
    const { relayUrl, ...wirePayload } = payload;
    const res = await this.post<WalletRecoveryBootstrapVerifyResult>({
      type: 'PM_VERIFY_WALLET_RECOVERY_BOOTSTRAP',
      payload: { ...wirePayload, ...(relayUrl ? { relayUrl } : {}) },
    });
    return res.result;
  }

  async prepareWalletRecovery(payload: {
    walletId: string;
    challengeId: string;
    otpCode: string;
    recoveryCode: string;
    replacedCredentialIdB64u: string;
    relayUrl?: string;
    appSessionJwt?: string;
    abortSignal?: AbortSignal;
  }): Promise<PrepareWalletWithCodeResult> {
    const { appSessionJwt, abortSignal: _abortSignal, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<PrepareWalletWithCodeResult>({
      type: 'PM_PREPARE_WALLET_RECOVERY',
      payload: wirePayload,
    });
    return res.result;
  }

  async prepareWalletRecoveryWithBootstrap(payload: {
    walletId: string;
    orgId: string;
    challengeId: string;
    recoveryBootstrapGrant: string;
    replacedCredentialIdB64u: string;
    recoveryCode: string;
    relayUrl?: string;
    abortSignal?: AbortSignal;
  }): Promise<PrepareWalletWithCodeResult> {
    const { abortSignal: _abortSignal, ...wirePayload } = payload;
    const res = await this.post<PrepareWalletWithCodeResult>({
      type: 'PM_PREPARE_WALLET_RECOVERY_WITH_BOOTSTRAP',
      payload: wirePayload,
    });
    return res.result;
  }

  async completeWalletRecovery(payload: {
    walletId: string;
    recoveryOperationId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    abortSignal?: AbortSignal;
  }): Promise<CompleteWalletRecoveryResult> {
    const { appSessionJwt, abortSignal: _abortSignal, ...wirePayload } = payload;
    await this.ensureHostedWalletSeamsSession(
      hostedWalletSeamsSessionSource({ relayUrl: payload.relayUrl, appSessionJwt }),
    );
    const res = await this.post<CompleteWalletRecoveryResult>(
      {
        type: 'PM_COMPLETE_WALLET_RECOVERY',
        payload: wirePayload,
      },
      { timeout: 'interactive' },
    );
    return res.result;
  }

  async checkLoginStatus(): Promise<PostResult<WalletIframeLoginStatusSnapshot>> {
    const state = await this.getExactSessionState();
    return { ok: true, result: walletIframeLoginStatusFromExactSession(state) };
  }

  async lock(): Promise<PostResult<void>> {
    await this.post<void>({ type: 'PM_LOCK' });
    this.exactSessionState = { kind: 'wallet_locked' };
    this.emitLoginStatusChanged({ isLoggedIn: false, walletId: null });
    return { ok: true, result: undefined };
  }

  async lockExactSession(
    expected: WalletIframeExactSessionIdentity,
  ): Promise<WalletIframeExactSessionLockResult> {
    const response = await this.post<unknown>({
      type: 'PM_LOCK_EXACT_WALLET_SESSION',
      payload: expected,
    });
    const result = parseWalletIframeExactSessionLockResult(response.result);
    if (result.kind === 'locked') {
      this.exactSessionState = { kind: 'wallet_locked' };
      this.emitLoginStatusChanged({ isLoggedIn: false, walletId: null });
    } else {
      this.exactSessionState = result.current;
      this.emitLoginStatusChanged(walletIframeLoginStatusFromExactSession(result.current));
    }
    return result;
  }

  async signNep413Message(payload: {
    walletId: string;
    nearAccountId: string;
    message: string;
    recipient: string;
    state?: string;
    options: {
      signerSlot?: number;
      onEvent?: (ev: SigningFlowEvent) => void;
      confirmerText?: { title?: string; body?: string };
      confirmationConfig?: Partial<ConfirmationConfig>;
    };
  }): Promise<SignNEP413MessageResult> {
    const safeOptions = {
      ...(typeof payload.options.signerSlot === 'number'
        ? { signerSlot: payload.options.signerSlot }
        : {}),
      ...(payload.options.confirmerText ? { confirmerText: payload.options.confirmerText } : {}),
      ...(payload.options.confirmationConfig
        ? { confirmationConfig: payload.options.confirmationConfig }
        : {}),
    };
    const res = await this.post<SignNEP413MessageResult>({
      type: 'PM_SIGN_NEP413',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        params: {
          message: payload.message,
          recipient: payload.recipient,
          state: payload.state,
        },
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async signTempo(payload: {
    walletSession: WalletSessionRef;
    request: MultichainSigningRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    options?: {
      confirmationConfig?: Partial<ConfirmationConfig>;
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<TempoSignedResult | EvmSignedResult> {
    const res = await this.post<TempoSignedResult>(
      {
        type: 'PM_SIGN_TEMPO',
        payload: buildSignTempoIframePayload({
          walletSession: payload.walletSession,
          request: payload.request,
          chainTarget: payload.chainTarget,
          options: payload.options
            ? {
                ...(payload.options.confirmationConfig
                  ? { confirmationConfig: payload.options.confirmationConfig }
                  : {}),
              }
            : undefined,
        }),
        options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
      },
      {
        timeout: 'interactive',
      },
    );
    return res.result;
  }

  async reportTempoBroadcastAccepted(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    txHash: `0x${string}`;
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
        txHash: payload.txHash,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
  }

  async reportTempoBroadcastRejected(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    error?: { code?: string; message?: string; details?: unknown };
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_REPORT_TEMPO_BROADCAST_REJECTED',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
        ...(payload.error ? { error: payload.error } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
  }

  async reportTempoFinalized(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    txHash?: `0x${string}`;
    receiptStatus?: 'success' | 'reverted';
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_REPORT_TEMPO_FINALIZED',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
        ...(payload.txHash ? { txHash: payload.txHash } : {}),
        ...(payload.receiptStatus ? { receiptStatus: payload.receiptStatus } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
  }

  async reportTempoDroppedOrReplaced(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    reason: 'dropped' | 'replaced';
    txHash?: `0x${string}`;
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_REPORT_TEMPO_DROPPED_OR_REPLACED',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
        reason: payload.reason,
        ...(payload.txHash ? { txHash: payload.txHash } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
  }

  async reconcileTempoNonceLane(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<{
    chainNextNonce: string;
    unresolvedInFlightNonces: string[];
    blocked: boolean;
    blockedNonce?: string;
  }> {
    const res = await this.post<{
      chainNextNonce: string;
      unresolvedInFlightNonces: string[];
      blocked: boolean;
      blockedNonce?: string;
    }>({
      type: 'PM_RECONCILE_TEMPO_NONCE_LANE',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async executeAction(payload: {
    walletId: string;
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    // Strip non-cloneable functions from options; host emits PROGRESS events
    const { options } = payload;
    const safeOptions = {
      waitUntil: options.waitUntil,
      confirmationConfig: options.confirmationConfig,
      ...(typeof options.signerSlot === 'number' ? { signerSlot: options.signerSlot } : {}),
      ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
    };

    const res = await this.post<ActionResult>({
      type: 'PM_EXECUTE_ACTION',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        receiverId: payload.receiverId,
        actionArgs: payload.actionArgs,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async setConfirmBehavior(
    behavior: 'requireClick' | 'skipClick',
    walletId?: string | null,
  ): Promise<void> {
    await this.post<void>({
      type: 'PM_SET_CONFIRM_BEHAVIOR',
      payload: { behavior, ...(walletId ? { walletId } : {}) },
    });
  }

  async setConfirmationConfig(
    config: Partial<ConfirmationConfig>,
    walletId?: string | null,
  ): Promise<void> {
    await this.post<void>({
      type: 'PM_SET_CONFIRMATION_CONFIG',
      payload: { config, ...(walletId ? { walletId } : {}) },
    });
    if (config.uiMode === 'none' || config.uiMode === 'modal' || config.uiMode === 'drawer') {
      this.mirroredConfirmationUiMode = config.uiMode;
    }
  }

  async getConfirmationConfig(): Promise<ConfirmationConfig> {
    const res = await this.post<ConfirmationConfig>({ type: 'PM_GET_CONFIRMATION_CONFIG' });
    this.mirroredConfirmationUiMode = res.result.uiMode;
    return res.result;
  }

  /**
   * Push appearance (theme name and/or color token overrides) to the wallet
   * host at runtime. The host merges this with prior config and re-applies the
   * Lit token override stylesheet, so embedded components (tx confirmer, etc.)
   * re-theme without a re-init. Appearance is excluded from the runtime-reset
   * fingerprint, so this never drops warm signing-session state.
   */
  async setAppearance(appearance: AppearanceConfigInput): Promise<void> {
    await this.post<void>({ type: 'PM_SET_CONFIG', payload: { appearance } });
  }

  async prefetchBlockheight(): Promise<void> {
    await this.post<void>({ type: 'PM_PREFETCH_BLOCKHEIGHT' });
  }

  async prefillRouterAbEcdsaDerivationPresignaturePool(payload: {
    walletSession: WalletSessionRef;
    options: {
      chainTarget: ThresholdEcdsaChainTarget;
      waitForPoolReady?: boolean;
      poolReadyTimeoutMs?: number;
      poolReadyPollIntervalMs?: number;
      minRemainingUsesBeforePrefill?: number;
    };
  }): Promise<RouterAbEcdsaDerivationLoginPresignaturePrefillResult> {
    const res = await this.post<RouterAbEcdsaDerivationLoginPresignaturePrefillResult>(
      {
        type: 'PM_PREFILL_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL',
        payload: {
          walletSession: payload.walletSession,
          ...(payload.options ? { options: payload.options } : {}),
        },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async getRecentUnlocks(): Promise<GetRecentUnlocksResult> {
    const res = await this.post<GetRecentUnlocksResult>({ type: 'PM_GET_RECENT_UNLOCKS' });
    return res.result;
  }

  async getRecoveryEmails(walletId: string): Promise<Array<{ hashHex: string; email: string }>> {
    const res = await this.post<Array<{ hashHex: string; email: string }>>({
      type: 'PM_GET_RECOVERY_EMAILS',
      payload: { walletId },
    });
    return Array.isArray(res?.result) ? res.result : [];
  }

  async setRecoveryEmails(payload: {
    walletId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    const { options } = payload;
    const safeOptions = {
      waitUntil: options.waitUntil,
      confirmationConfig: options.confirmationConfig,
      ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
    };

    const res = await this.post<ActionResult>({
      type: 'PM_SET_RECOVERY_EMAILS',
      payload: {
        walletId: payload.walletId,
        recoveryEmails: payload.recoveryEmails,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async syncAccount(payload: {
    walletId?: string;
    onEvent?: (ev: AccountSyncFlowEvent) => void;
  }): Promise<SyncAccountResult> {
    const res = await this.post<SyncAccountResult>({
      type: 'PM_SYNC_ACCOUNT_FLOW',
      payload: { ...(payload?.walletId ? { walletId: payload.walletId } : {}) },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isAccountSyncFlowEvent) },
    });
    return res.result as SyncAccountResult;
  }

  async linkDeviceWithScannedQRData(payload: {
    qrData: DeviceLinkingQRData;
    fundingAmount: string;
    options?: {
      onEvent?: (ev: LinkDeviceFlowEvent) => void;
      confirmationConfig?: Partial<ConfirmationConfig>;
      confirmerText?: { title?: string; body?: string };
    };
  }): Promise<LinkDeviceResult> {
    const res = await this.post<LinkDeviceResult>({
      type: 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA',
      payload: {
        qrData: payload.qrData,
        fundingAmount: payload.fundingAmount,
        ...(payload.options
          ? {
              options: {
                ...(payload.options.confirmationConfig
                  ? { confirmationConfig: payload.options.confirmationConfig }
                  : {}),
                ...(payload.options.confirmerText
                  ? { confirmerText: payload.options.confirmerText }
                  : {}),
              },
            }
          : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isLinkDeviceFlowEvent) },
    });
    return res.result as LinkDeviceResult;
  }

  async startDevice2LinkingFlow(
    payload?: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults> {
    const res = await this.post<StartDevice2LinkingFlowResults>({
      type: 'PM_START_DEVICE2_LINKING_FLOW',
      payload: {
        ...(payload?.ui ? { ui: payload.ui } : {}),
        ...(payload?.cameraId ? { cameraId: payload.cameraId } : {}),
        ...(typeof payload?.signerSlot === 'number' ? { signerSlot: payload.signerSlot } : {}),
        ...(payload?.options
          ? {
              options: {
                ...(payload.options.confirmationConfig
                  ? { confirmationConfig: payload.options.confirmationConfig }
                  : {}),
                ...(payload.options.confirmerText
                  ? { confirmerText: payload.options.confirmerText }
                  : {}),
              },
            }
          : {}),
      },
      options: {
        sticky: true,
        onProgress: this.wrapOnEvent(payload?.options?.onEvent, isLinkDeviceFlowEvent),
      },
    });
    return res.result as StartDevice2LinkingFlowResults;
  }

  async stopDevice2LinkingFlow(): Promise<void> {
    await this.post<void>({ type: 'PM_STOP_DEVICE2_LINKING_FLOW' });
    this.finishDeviceLinkQrSurface();
  }

  // Bridge typed public onEvent callbacks to the transport's onProgress callback.
  // - onEvent: consumer's strongly-typed event handler (e.g., SigningFlowEvent)
  // - isExpectedEvent: runtime type guard that validates a ProgressPayload as that event type
  // Returns an onProgress handler that safely narrows before invoking onEvent.
  private wrapOnEvent<TEvent extends ProgressPayload>(
    onEvent: ((event: TEvent) => void) | undefined,
    isExpectedEvent: (progress: ProgressPayload) => progress is TEvent,
  ): ((progress: ProgressPayload) => void) | undefined {
    if (!onEvent) return undefined;
    return (progress: ProgressPayload) => {
      try {
        if (isExpectedEvent(progress)) onEvent(progress);
      } catch {}
    };
  }

  async signAndSendTransaction(payload: {
    walletId: string;
    nearAccountId: string;
    transaction: TransactionInput;
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult> {
    const { options } = payload;
    // cannot send objects/functions through postMessage(), clean options first
    const safeOptions = {
      waitUntil: options.waitUntil,
      confirmationConfig: options.confirmationConfig,
      ...(typeof options.signerSlot === 'number' ? { signerSlot: options.signerSlot } : {}),
      ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
    };

    const res = await this.post<ActionResult>({
      type: 'PM_SIGN_AND_SEND_TX',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        transaction: payload.transaction,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async fundImplicitNearAccountForTesting(payload: {
    walletId: string;
    nearAccountId: string;
    nearPublicKey: string;
  }): Promise<FundImplicitNearAccountForTestingResult> {
    const res = await this.post<FundImplicitNearAccountForTestingResult>({
      type: 'PM_FUND_IMPLICIT_NEAR_ACCOUNT_FOR_TESTING',
      payload,
    });
    return res.result;
  }

  async hasPasskeyCredential(walletId: string): Promise<boolean> {
    const res = await this.post<boolean>({
      type: 'PM_HAS_PASSKEY',
      payload: { walletId },
    });
    return !!res?.result;
  }

  async viewAccessKeyList(args: {
    walletId: string;
    nearAccountId: string;
  }): Promise<AccessKeyList> {
    const res = await this.post<AccessKeyList>({
      type: 'PM_VIEW_ACCESS_KEYS',
      payload: { walletId: args.walletId, nearAccountId: args.nearAccountId },
    });
    return res.result;
  }

  async deleteDeviceKey(payload: {
    walletId: string;
    nearAccountId: string;
    publicKeyToDelete: string;
    options: { onEvent?: (ev: SigningFlowEvent) => void };
  }): Promise<ActionResult> {
    const res = await this.post<ActionResult>({
      type: 'PM_DELETE_DEVICE_KEY',
      payload: {
        walletId: payload.walletId,
        nearAccountId: payload.nearAccountId,
        publicKeyToDelete: payload.publicKeyToDelete,
        options: {},
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async listWalletCredentials(payload: {
    walletId: string;
  }): Promise<WalletCredentialActivityListResult> {
    const res = await this.post<WalletCredentialActivityListResult>({
      type: 'PM_LIST_WALLET_CREDENTIALS',
      payload,
    });
    return res.result;
  }

  async renameWalletCredential(payload: {
    walletId: string;
    envelopeId: string;
    label?: string;
  }): Promise<WalletCredentialRenameResult> {
    const res = await this.post<WalletCredentialRenameResult>({
      type: 'PM_RENAME_WALLET_CREDENTIAL',
      payload,
    });
    return res.result;
  }

  async sendTransaction(args: {
    walletId: string;
    nearAccountId: string;
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    // Strip non-cloneable functions from options; host emits PROGRESS events
    const { options } = args;
    const safeOptions = options ? { waitUntil: options.waitUntil } : undefined;

    const res = await this.post<ActionResult>({
      type: 'PM_SEND_TRANSACTION',
      payload: {
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        signedTransaction: args.signedTransaction,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async resolveExactKeyExportLane(
    input: ResolveExactKeyExportLaneInput,
  ): Promise<ResolveExactKeyExportLaneResult> {
    const res = await this.post<ResolveExactKeyExportLaneResult>({
      type: 'PM_RESOLVE_EXACT_KEY_EXPORT_LANE',
      payload: input,
    });
    return parseResolveExactKeyExportLaneResult(res.result);
  }

  async exportKeypairWithUI(input: ExportKeypairWithUIInput): Promise<void> {
    const { onEvent, ...messageOptions } = input.options;
    // Key export ALWAYS presents as a bottom drawer — it deliberately does not
    // follow the Confirmer UI (modal|drawer|none) preference the tx confirmer
    // uses. Stamping the variant here keeps the one invariant that matters:
    // the host box and the in-iframe viewer read the same value, so the two
    // sides cannot disagree. An explicit options.variant from a caller still
    // wins for embedders that need it.
    const payload = walletIframeExportPayload(input, {
      ...messageOptions,
      variant: messageOptions.variant ?? 'drawer',
    });
    await this.post<void>({
      type: 'PM_EXPORT_KEYPAIR_UI',
      payload,
      options: {
        sticky: true,
        onProgress: this.wrapOnEvent(onEvent, isKeyExportFlowEvent),
      },
    });
  }

  // ===== Control APIs =====
  async openHostedAuthMenu(
    request: HostedAuthMenuOpenRequest,
    anchorElement?: HTMLElement,
  ): Promise<HostedAuthMenuOutcome> {
    const normalized = parseHostedAuthMenuOpenRequest(request);
    if (!normalized) throw new Error('Hosted auth-menu open request is invalid');
    if (this.hostedAuthMenuRequestIds.has(normalized.authMenuSessionId)) {
      throw new Error('Hosted auth-menu session is already active');
    }
    const requestId = this.allocateRequestId();
    this.hostedAuthMenuRequestIds.set(normalized.authMenuSessionId, requestId);
    if (anchorElement) this.hostedAuthMenuAnchors.set(normalized.authMenuSessionId, anchorElement);
    try {
      const responsePromise = this.post<unknown>(
        {
          type: 'PM_OPEN_AUTH_MENU',
          payload: normalized,
        },
        {
          requestId,
          timeout: 'interactive',
          shouldContinue: () =>
            !this.cancelledHostedAuthMenuSessions.has(normalized.authMenuSessionId),
        },
      );
      const response = await responsePromise;
      const outcome = parseHostedAuthMenuOutcome(response.result);
      if (!outcome || outcome.authMenuSessionId !== normalized.authMenuSessionId) {
        throw new Error('Hosted auth-menu returned an invalid terminal outcome');
      }
      return outcome;
    } finally {
      this.stopHostedAuthMenuAnchorTracking(normalized.authMenuSessionId);
      this.hostedAuthMenuRequestIds.delete(normalized.authMenuSessionId);
      this.hostedAuthMenuConnectionIds.delete(normalized.authMenuSessionId);
      this.hostedAuthMenuAnchors.delete(normalized.authMenuSessionId);
      this.cancelledHostedAuthMenuSessions.delete(normalized.authMenuSessionId);
    }
  }

  async cancelHostedAuthMenu(args: { authMenuSessionId: HostedAuthMenuSessionId }): Promise<void> {
    await this.cancelHostedAuthMenuWithReason(args.authMenuSessionId, 'component_unmounted');
  }

  private async cancelHostedAuthMenuWithReason(
    rawAuthMenuSessionId: HostedAuthMenuSessionId,
    reason: 'close_button' | 'component_unmounted',
  ): Promise<void> {
    const authMenuSessionId = hostedAuthMenuSessionIdFromBoundary(rawAuthMenuSessionId);
    if (!authMenuSessionId) throw new Error('authMenuSessionId must be a non-empty string');
    const activeRequestId = this.hostedAuthMenuRequestIds.get(authMenuSessionId);
    if (!activeRequestId) return;
    const payload: HostedAuthMenuCancelPayload = buildHostedAuthMenuCancelPayload({
      authMenuSessionId,
      requestId: activeRequestId,
      reason,
    });
    try {
      await this.post<void>({ type: 'PM_CANCEL_AUTH_MENU', payload });
    } catch {
      this.settleHostedAuthMenuCancellation(authMenuSessionId, reason);
    }
  }

  async cancelRequest(requestId: string): Promise<void> {
    this.transactionSurfaceQueue.cancel(requestId);
    await this.post<void>({ type: 'PM_CANCEL', payload: { requestId } }).catch(() => {});
    this.progressBus.unregister(requestId);
    const authMenuSessionId = this.hostedAuthMenuSessionIdForRequestId(requestId);
    if (authMenuSessionId) {
      this.settleHostedAuthMenuCancellation(authMenuSessionId, 'component_unmounted');
      return;
    }
    this.finishRequestSurface(requestId as WalletIframeRequestId, true);
  }

  async cancelAll(): Promise<void> {
    this.transactionSurfaceQueue.cancelAll(new Error('Wallet requests cancelled'));
    await this.post<void>({ type: 'PM_CANCEL', payload: {} }).catch(() => {});
    this.progressBus.clearAll();
    for (const authMenuSessionId of Array.from(this.hostedAuthMenuRequestIds.keys())) {
      this.settleHostedAuthMenuCancellation(authMenuSessionId, 'component_unmounted');
    }
    if (this.walletIframeSurface.kind === 'hidden') return;
    this.transitionWalletIframeSurface({
      kind: 'request_cancelled',
      connectionId: this.walletIframeSurface.connectionId,
      identity: this.walletIframeSurface.identity,
    });
  }

  private onPortMessage(
    e: MessageEvent<ChildToParentEnvelope>,
    connectionId: WalletIframeConnectionId,
  ): void {
    if (this.state.connectionId !== connectionId) return;
    const lifecycleEnvelope = parseSdkLifecycleEnvelope(e.data);
    switch (lifecycleEnvelope.kind) {
      case 'lifecycle_event':
        this.emitSdkLifecycleEvent(lifecycleEnvelope.event);
        return;
      case 'invalid_lifecycle_event':
        if (this.debug) {
          console.warn('[WalletIframeRouter] Ignored invalid SDK lifecycle event');
        }
        return;
      case 'not_lifecycle_event':
        break;
    }
    const msg = e.data as ChildToParentEnvelope;
    // Some wallet-host messages are push-style and are not correlated to a requestId.
    if (msg.type === 'PREFERENCES_CHANGED') {
      const payload = msg.payload as PreferencesChangedPayload;
      this.emitPreferencesChanged(payload);
      return;
    }
    if (msg.type === 'AUTH_MENU_EXTERNAL_AUTH_REQUEST') {
      const payload = parseHostedAuthMenuExternalAuthRequest(msg.payload);
      if (!payload) return;
      const activeRequestId = this.hostedAuthMenuRequestIds.get(payload.authMenuSessionId);
      if (
        !activeRequestId ||
        typeof msg.requestId !== 'string' ||
        msg.requestId !== activeRequestId
      ) {
        return;
      }
      for (const listener of Array.from(this.listeners.hostedAuthMenuExternalAuthRequest)) {
        try {
          listener(payload);
        } catch {}
      }
      return;
    }
    if (msg.type === 'AUTH_MENU_DEMO_EMAIL_OTP_DELIVERY') {
      const payload = parseHostedAuthMenuDemoEmailOtpDelivery(msg.payload);
      if (!payload) return;
      const activeRequestId = this.hostedAuthMenuRequestIds.get(payload.authMenuSessionId);
      if (
        !activeRequestId ||
        typeof msg.requestId !== 'string' ||
        msg.requestId !== activeRequestId
      ) {
        return;
      }
      for (const listener of Array.from(this.listeners.hostedAuthMenuDemoEmailOtpDelivery)) {
        try {
          listener(payload);
        } catch {}
      }
      return;
    }
    if (msg.type === 'SURFACE_MEASUREMENT') {
      this.handleSurfaceMeasurement(msg.payload);
      return;
    }
    const requestId = msg.requestId;
    if (!requestId) return;

    // Bridge PROGRESS events to caller-provided onEvent callback via pending registry
    if (msg.type === 'PROGRESS') {
      const payload = msg.payload as ProgressPayload;
      this.progressBus.dispatch({ requestId: requestId, payload: payload });
      this.extendMeasurementFallbackOnProgress(requestId);
      if (shouldHideWalletIframeSurface(payload)) {
        this.hideRequestSurface(requestId as WalletIframeRequestId);
      }
      if (this.progressBus.isSticky(requestId) && isTerminalStickyWalletFlowProgress(payload)) {
        this.progressBus.unregister(requestId);
        this.finishRequestSurface(
          requestId as WalletIframeRequestId,
          isWalletFlowEvent(payload) && payload.status === 'cancelled',
        );
      }
      // Refresh timeout for long-running operations whenever progress is received
      const pend = this.state.pending.get(requestId);
      if (pend?.timeout.kind === 'deadline') {
        if (pend.timer) window.clearTimeout(pend.timer);
        const remainingLifetimeMs = Math.max(0, pend.timeout.deadlineAtMs - Date.now());
        if (remainingLifetimeMs === 0) {
          const err = pend.onTimeout();
          pend.reject(err);
          return;
        }
        const nextTimeoutMs = Math.max(1, Math.min(pend.timeout.timeoutMs, remainingLifetimeMs));
        pend.timer = window.setTimeout(() => {
          const err = pend.onTimeout();
          pend.reject(err);
        }, nextTimeoutMs);
      }
      return;
    }

    const pending = this.state.pending.get(requestId);
    if (!pending) {
      if (this.debug) {
        console.debug('[WalletIframeRouter] Non-PROGRESS without pending', {
          requestId,
          type: msg.type,
        });
      }
      this.progressBus.unregister(requestId);
      this.finishRequestSurface(requestId as WalletIframeRequestId, msg.type === 'ERROR');
      return;
    }
    this.state.pending.delete(requestId);
    if (pending.timer) window.clearTimeout(pending.timer);

    if (msg.type === 'ERROR') {
      const message = resolveCanonicalSignerBoundaryMessage(
        msg.payload?.code,
        msg.payload?.message,
      );
      const err: Error & { code?: string; details?: unknown } = new Error(message);
      err.code = msg.payload?.code;
      err.details = msg.payload?.details;
      // Deliver to pending promise if present
      pending.reject(err);
      // Also notify all progress subscribers for this requestId
      const terminalStatus = msg.payload?.code === 'cancelled' ? 'cancelled' : 'failed';
      const fallbackProgress = createTerminalProgressForRequest({
        requestType: pending.requestType,
        requestId,
        status: terminalStatus,
        message,
        errorCode: msg.payload?.code,
      });
      if (fallbackProgress) {
        this.progressBus.dispatch({ requestId, payload: fallbackProgress });
      }
      this.progressBus.unregister(requestId);
      this.finishRequestSurface(requestId as WalletIframeRequestId, terminalStatus === 'cancelled');
      return;
    }

    pending.resolve(msg.payload);
    if (this.progressBus.isSticky(requestId)) return;
    this.progressBus.unregister(requestId);
    this.finishRequestSurface(requestId as WalletIframeRequestId, false);
  }

  /**
   * Post a typed envelope over the MessagePort with robust readiness handling.
   * This is the core method that handles all communication with the iframe.
   *
   * Flow:
   * 1. Ensure iframe is ready (lazy initialization)
   * 2. Generate unique request ID for correlation
   * 3. Set up timeout and progress handling
   * 4. Send message to iframe via MessagePort
   * 5. Wait for response (PM_RESULT or ERROR)
   * 6. Clean up on completion or timeout
   */
  private async post<T>(
    envelope: Omit<ParentToChildEnvelope, 'requestId'>,
    postOpts?: WalletIframePostOptions,
  ): Promise<PostResult<T>> {
    // Step 1: Lazily initialize the iframe/client if not ready yet
    if (!this.state.ready || !this.state.port) {
      await this.init();
    }
    const connectionId = this.state.connectionId;
    if (!connectionId || !this.state.port) {
      throw new Error('Wallet iframe connection is unavailable');
    }
    if (postOpts?.shouldContinue && !postOpts.shouldContinue()) {
      throw new Error('Wallet iframe request was cancelled before dispatch');
    }

    // Step 2: Generate unique request ID for correlation
    const requestId = postOpts?.requestId ?? this.allocateRequestId();
    const full: ParentToChildEnvelope = { ...(envelope as ParentToChildEnvelope), requestId };
    const sessionBinding = this.sessionBindingForRequest(full);
    const { options } = full;
    const requestStartMs = Date.now();
    const timeoutPolicy =
      postOpts?.timeout === 'interactive'
        ? ({ kind: 'interactive' } as const)
        : (() => {
            const timeoutMs = postOpts?.timeoutMs ?? this.opts.requestTimeoutMs;
            const parsedProgressTimeoutExtensionFactor = Number(
              postOpts?.progressTimeoutExtensionFactor,
            );
            const progressTimeoutExtensionFactor =
              Number.isFinite(parsedProgressTimeoutExtensionFactor) &&
              parsedProgressTimeoutExtensionFactor >= 1
                ? parsedProgressTimeoutExtensionFactor
                : WALLET_IFRAME_PROGRESS_TIMEOUT_EXTENSION_FACTOR;
            const maxLifetimeMs = Math.max(timeoutMs, timeoutMs * progressTimeoutExtensionFactor);
            return {
              kind: 'deadline' as const,
              timeoutMs,
              deadlineAtMs: requestStartMs + maxLifetimeMs,
            };
          })();
    const deadlineAtMs = timeoutPolicy.kind === 'deadline' ? timeoutPolicy.deadlineAtMs : null;
    const surfaceKind = requestSurfaceKindForMessage(envelope.type, full.payload);
    let transactionSurfaceLease: WalletIframeTransactionSurfaceLease | null = null;
    if (surfaceKind === 'transaction') {
      const queueDeadline: WalletIframeTransactionSurfaceDeadline =
        timeoutPolicy.kind === 'deadline'
          ? { kind: 'deadline', atMs: timeoutPolicy.deadlineAtMs }
          : { kind: 'interactive' };
      transactionSurfaceLease = await this.transactionSurfaceQueue.acquire({
        requestId,
        deadline: queueDeadline,
      });
    }

    try {
      if (this.state.connectionId !== connectionId || !this.state.port) {
        throw new WalletIframeConnectionClosedRequestError(requestId, connectionId, envelope.type);
      }
      const admission = this.requestAdmission(sessionBinding);
      if (admission.kind === 'expired') {
        throw new WalletIframeSessionExpiredRequestError({
          kind: 'wallet_iframe_request_failure',
          code: 'wallet_session_expired',
          walletId: admission.identity.walletId,
          walletSessionId: admission.identity.walletSessionId,
        });
      }
      if (surfaceKind) {
        this.beginRequestSurface({
          kind: surfaceKind,
          requestId,
          deadlineAtMs,
          payload: full.payload,
          authMenuSessionId: authMenuSessionIdForMessage(envelope.type, full.payload) ?? undefined,
        });
      }

      return await new Promise<PostResult<T>>((resolve, reject) => {
        const onTimeout = () => {
          const pending = this.state.pending.get(requestId);
          if (pending?.timer !== undefined) window.clearTimeout(pending.timer);
          this.state.pending.delete(requestId);
          this.progressBus.unregister(requestId);
          this.finishRequestSurface(requestId, true);
          this.sendBestEffortCancel(requestId);
          const elapsedMs = Math.max(0, Date.now() - requestStartMs);
          return new Error(`Wallet request timeout for ${envelope.type} after ${elapsedMs}ms`);
        };

        // Step 3: Set up timeout handler for request
        const timer =
          timeoutPolicy.kind === 'deadline'
            ? window.setTimeout(
                () => {
                  const err = onTimeout();
                  reject(err);
                },
                Math.max(
                  1,
                  Math.min(timeoutPolicy.timeoutMs, timeoutPolicy.deadlineAtMs - Date.now()),
                ),
              )
            : undefined;

        // Step 4: Register pending request for correlation
        this.state.pending.set(requestId, {
          requestId,
          connectionId,
          resolve: (v) => resolve(v as PostResult<T>),
          reject,
          timer,
          timeout: timeoutPolicy,
          onProgress: options?.onProgress,
          requestType: envelope.type,
          onTimeout,
          sessionBinding: admission.binding,
        });

        // Step 5: Register progress handler for real-time updates
        this.progressBus.register({
          requestId: requestId,
          sticky: !!options?.sticky, // Some flows need to persist after completion
          onProgress: (payload: ProgressPayload) => {
            // Bridge progress events from iframe back to parent callback
            try {
              options?.onProgress?.(payload);
            } catch {}
          },
        });

        try {
          // Step 6: Strip non-cloneable fields (functions) from envelope options before posting
          const stickyVal = isObject(options)
            ? (options as { sticky?: unknown }).sticky
            : undefined;
          const wireOptions = isBoolean(stickyVal) ? { sticky: stickyVal } : undefined;
          const serializableFull = wireOptions
            ? { ...full, options: wireOptions }
            : { ...full, options: undefined };

          // Send message to iframe via MessagePort after its surface owns visibility.
          this.state.port!.postMessage(serializableFull as ParentToChildEnvelope);
        } catch (err) {
          // Step 8: Handle send errors - clean up and reject
          this.state.pending.delete(requestId);
          window.clearTimeout(timer);
          this.progressBus.unregister(requestId);
          this.finishRequestSurface(requestId, true);
          reject(toError(err));
        }
      });
    } finally {
      transactionSurfaceLease?.release();
    }
  }

  private sessionBindingForRequest(
    envelope: ParentToChildEnvelope,
  ): WalletIframePendingSessionBinding {
    const requestWalletId = exactSessionRequestWalletId(envelope);
    if (requestWalletId === null) return { kind: 'unbound' };
    const state = this.exactSessionState;
    if (state === null || state.kind !== 'active_session' || state.walletId !== requestWalletId) {
      return { kind: 'unbound' };
    }
    return {
      kind: 'exact_session',
      walletId: state.walletId,
      authorizationId: state.authorizationId,
      walletSessionId: state.walletSessionId,
      authMethod: state.authMethod,
      expiresAtMs: state.expiresAtMs,
    };
  }

  private requestAdmission(
    binding: WalletIframePendingSessionBinding,
  ): WalletIframeRequestAdmission {
    if (binding.kind === 'unbound') {
      return { kind: 'admitted', binding };
    }
    const expiredSessionIds = this.expiredSigningSessionsByWallet.get(binding.walletId);
    if (!expiredSessionIds?.has(binding.walletSessionId)) {
      return { kind: 'admitted', binding };
    }
    return {
      kind: 'expired',
      identity: {
        walletId: binding.walletId,
        authorizationId: binding.authorizationId,
        walletSessionId: binding.walletSessionId,
        authMethod: binding.authMethod,
        expiresAtMs: binding.expiresAtMs,
      },
    };
  }

  private allocateRequestId(): WalletIframeRequestId {
    return `${Date.now()}-${++this.state.reqCounter}` as WalletIframeRequestId;
  }

  private sendBestEffortCancel(targetRequestId?: string): void {
    const port = this.state.port;
    if (!port) return;
    const cancelEnvelope: ParentToChildEnvelope = {
      type: 'PM_CANCEL',
      requestId: `cancel-${Date.now()}-${secureRandomBase36(12, 'wallet iframe cancel request IDs')}`,
      payload: targetRequestId ? { requestId: targetRequestId } : {},
    };
    port.postMessage(cancelEnvelope);
  }

  /** Public helper for tests/tools: get the underlying iframe element. */
  getIframeEl(): HTMLIFrameElement | null {
    return this.transport.getIframeEl();
  }

  /** Public helper for tests/tools: inspect current overlay state. */
  getOverlayState(): OverlayControllerState {
    return this.overlayState.controller.getState();
  }

  // Post a window message and surface errors in debug mode instead of silently swallowing them
  private postWindowMessage(w: Window, data: unknown, target: string): void {
    try {
      w.postMessage(data, target);
    } catch (err) {
      if (this.debug) {
        console.error('[WalletIframeRouter] window.postMessage failed', { error: err, data });
      }
    }
  }
}

function exactSessionRequestWalletId(envelope: ParentToChildEnvelope): string | null {
  if (envelope.payload === undefined) return null;
  switch (envelope.type) {
    case 'PM_SIGN_TX_WITH_ACTIONS':
    case 'PM_SIGN_AND_SEND_TX':
    case 'PM_EXECUTE_ACTION':
    case 'PM_SIGN_DELEGATE_ACTION':
    case 'PM_SIGN_NEP413':
      return envelope.payload.walletId;
    case 'PM_SIGN_TEMPO':
    case 'PM_RESOLVE_EXACT_KEY_EXPORT_LANE':
    case 'PM_EXPORT_KEYPAIR_UI':
      return envelope.payload.walletSession.walletId;
    case 'PM_LIST_WALLET_CREDENTIALS':
    case 'PM_RENAME_WALLET_CREDENTIAL':
      return envelope.payload.walletId;
    default:
      return null;
  }
}

function parseRequestedWalletId(value: string): WalletId {
  const normalized = value.trim();
  if (!normalized) throw new Error('Wallet Session request walletId is required');
  return walletIdFromString(normalized);
}

// ===== Runtime type guards to safely bridge ProgressPayload -> typed flow events =====
function isRegistrationFlowEvent(progress: ProgressPayload): progress is RegistrationFlowEvent {
  return isWalletFlowEvent(progress) && progress.flow === 'registration';
}

function bridgeRegistrationProgress(
  onEvent: ((event: RegistrationFlowEvent) => void) | undefined,
  onTimingSpan: ((span: RegistrationTimingSpanV1) => void) | undefined,
): ((progress: ProgressPayload) => void) | undefined {
  if (!onEvent && !onTimingSpan) return undefined;
  return (progress: ProgressPayload) => {
    try {
      if (isRegistrationFlowEvent(progress)) {
        onEvent?.(progress);
      } else if (isRegistrationTimingSpanV1(progress)) {
        onTimingSpan?.(progress);
      }
    } catch {}
  };
}

function isUnlockFlowEvent(p: ProgressPayload): p is UnlockFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'unlock';
}

function isSigningFlowEvent(p: ProgressPayload): p is SigningFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'signing';
}

function isLinkDeviceFlowEvent(p: ProgressPayload): p is LinkDeviceFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'link_device';
}

function isAccountSyncFlowEvent(p: ProgressPayload): p is AccountSyncFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'account_sync';
}

function isKeyExportFlowEvent(p: ProgressPayload): p is KeyExportFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'key_export';
}

/**
 * Strips out class functions as they cannot be sent over postMessage to iframe
 */
function normalizeSignedTransactionResult(result: SignTransactionResult): SignTransactionResult {
  const signedTransaction = result.signedTransaction;
  if (!isPlainSignedTransactionLike(signedTransaction)) return result;
  const nonceLease =
    (signedTransaction as { nonceLease?: NonceLeaseRef }).nonceLease || result.nonceLease;
  const serverDispatch = (
    signedTransaction as { serverDispatch?: SignedTransaction['serverDispatch'] }
  ).serverDispatch;
  return {
    ...result,
    signedTransaction: SignedTransaction.fromPlain({
      transaction: signedTransaction.transaction,
      signature: signedTransaction.signature,
      borsh_bytes: extractBorshBytesFromPlainSignedTx(signedTransaction),
      ...(nonceLease ? { nonceLease } : {}),
      ...(serverDispatch ? { serverDispatch } : {}),
    }),
  };
}

/**
 * Strips out functions as they cannot be sent over postMessage to iframe
 */
import { stripFunctionsShallow } from '@shared/utils/validation';

function unlockOnEventFromRequest(
  request: LoginUnlockRequest,
): LoginHooksOptions['onEvent'] | undefined {
  switch (request.kind) {
    case 'default_options':
      return undefined;
    case 'custom_options':
      return request.options.onEvent;
  }
  return assertNeverLoginUnlockRequest(request);
}

function removeFunctionsFromOptions(options?: object): object | undefined {
  if (!options || !isObject(options)) return undefined;
  return stripFunctionsShallow(options);
}

function assertNeverLoginUnlockRequest(value: never): never {
  throw new Error(`Unhandled wallet iframe unlock request: ${String(value)}`);
}
