/*
 * WalletIframeRouter - Client-Side Communication Layer
 *
 * Owns all iframe overlay show/hide behavior for WebAuthn activation. It is the
 * single place that decides *how* the wallet iframe is displayed (fullscreen vs
 * anchored, sticky mode, force-fullscreen during registration, etc.).
 *
 * High-level flow:
 *
 *   Step legend
 *   -----------
 *   (1) App calls a router RPC (executeAction, registerPasskey, etc).
 *   (2) Router posts request to iframe and tracks a pending entry.
 *   (3) Wallet iframe sends PROGRESS messages back to the router.
 *   (4) Router forwards ProgressPayloads into OnEventsProgressBus.
 *   (5) OnEventsProgressBus decides 'show' | 'hide' and calls router adapters.
 *   (6) Router delegates to OverlayController to show|hide the iframe.
 *   (7) Router receives final result, resolves the pending promise, unregisters,
 *       and may hide the overlay if no other request still needs it.
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
 *        |                        (4) ProgressPayload -> overlay metadata                     |
 *        |                                                     |---(5) 'show'|'hide' intent-->|
 *        |                                                     |                              |
 *        |                        (6) showFrameForActivation() | hideFrameForActivation()     |
 *        |                                                     |                              |
 *        |                                                     |            (6) show()|hide() |
 *        |                                                     |----------------------------->|
 *        |                                                     |                              |
 *        |                        (7) PM_RESULT/ERROR -> resolve pending, maybe hide overlay  |
 *        |<----------------------------------------------------|                              |
 *
 * Communication Flow (requests):
 * 1. Parent calls RPC method (e.g., registerPasskey).
 * 2. Router creates unique request ID and pending entry.
 * 3. Message sent to iframe via MessagePort.
 * 4. Progress events bridged back to parent callbacks and fed into OnEventsProgressBus.
 * 5. OnEventsProgressBus emits show/hide intents; router invokes OverlayController.
 * 6. Final result resolves the pending promise; router unregisters and may hide overlay.
 */

import {
  parseRegistrationActivationButtonStatePayload,
  parseRegistrationActivationReadyPayload,
  parseRegistrationActivationStartedPayload,
  type ParentToChildEnvelope,
  type ChildToParentEnvelope,
  type ProgressPayload,
  type PreferencesChangedPayload,
  type RegistrationActivationButtonInteractionState,
  type PMRegistrationActivationButtonStatePayload,
  type PMRegistrationActivationReadyPayload,
  type PMRegistrationActivationStartedPayload,
} from '../shared/messages';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import {
  OnEventsProgressBus,
  defaultOverlayIntentResolver,
} from './progress/on-events-progress-bus';
import type {
  ActionHooksOptions,
  AfterCall,
  LinkDeviceFlowEvent,
  LoginHooksOptions,
  KeyExportFlowEvent,
  EmailRecoveryFlowEvent,
  UnlockFlowEvent,
  RegistrationFlowEvent,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SigningFlowEvent,
  AccountSyncFlowEvent,
} from '@/core/types/sdkSentEvents';
import type { WalletIframeTransportDiagnostics } from './transport/IframeTransport';
import {
  AccountSyncEventPhase,
  createAccountSyncFlowEvent,
  createEmailRecoveryFlowEvent,
  createKeyExportFlowEvent,
  createLinkDeviceFlowEvent,
  createRegistrationFlowEvent,
  createSigningFlowEvent,
  createUnlockFlowEvent,
  EmailRecoveryFlowEventPhase,
  KeyExportEventPhase,
  isWalletFlowEvent,
  LinkDeviceEventPhase,
  RegistrationEventPhase,
  SigningEventPhase,
  UnlockEventPhase,
} from '@/core/types/sdkSentEvents';
import type {
  ActionResult,
  AppearanceConfigInput,
  GetRecentUnlocksResult,
  LoginAndCreateSessionResult,
  LoginState,
  WalletSession,
  RegistrationResult,
  SignDelegateActionResult,
  SignTransactionResult,
  SeamsChainConfig,
  SeamsConfigsInput,
} from '@/core/types/seams';
import type {
  CreatePasskeyRegistrationActivationSurfaceArgs,
  RegistrationActivationButtonPresentation,
  RegistrationActivationSurfaceState,
  WalletIframeRegistrationActivationSurface,
} from '@/SeamsWeb/publicApi/types';
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import type { RouterAbEcdsaHssLoginPresignaturePrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
  type WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { registrationSignerSetRequestSelection } from '@/core/rpcClients/relayer/registrationSignerSetRequest';
import {
  parseExactEcdsaSigningLaneIdentity,
  parseExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type {
  LinkDeviceResult,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  DeviceLinkingQRData,
} from '@/core/types/linkDevice';
import type { SyncAccountResult } from '@/SeamsWeb/operations/recovery/syncAccount';
import type { ExportKeypairWithUIInput } from '@/SeamsWeb/signingSurface/types';
import type {
  FundImplicitNearAccountForTestingResult,
  ResolveExactKeyExportLaneInput,
  ResolveExactKeyExportLaneResult,
} from '@/SeamsWeb/publicApi/types';
import type {
  BootstrapThresholdEcdsaSessionArgs,
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityResult,
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
import type { LoginWithEmailOtpEd25519CapabilityInternalResult } from '@/core/signingEngine/flows/signEvmFamily/emailOtpPublic';
import type {
  PMGoogleEmailOtpWalletAuthCompleteRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthRegistrationWireResult,
  PMGoogleEmailOtpWalletAuthSubmitWireResult,
  PMGoogleEmailOtpWalletAuthWireFlow,
  PMGoogleEmailOtpWalletAuthWireResult,
  PMEmailOtpEd25519CapabilityPayload,
} from '../shared/messages';
import { ActionArgs, TransactionInput, TxExecutionStatus } from '@/core/types';
import type { DelegateActionInput } from '@/core/types/delegate';
import { IframeTransport } from './transport/IframeTransport';
import OverlayController, { type DOMRectLike } from './overlay/overlay-controller';
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
import { walletIdFromString } from '@shared/utils/registrationIntent';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type { SignNEP413MessageResult } from '@/SeamsWeb/operations/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { cloneResolvedChainConfig } from '@/core/config/chains';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import type { LoginUnlockRequest } from '@/core/types/login.types';
import { buildPMUnlockPayload } from '../shared/unlockOptions';

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
  signingSessionSeal?: SeamsConfigsInput['signingSessionSeal'];
  routerAb?: SeamsConfigsInput['routerAb'];
  routerAbEcdsaHssPresignaturePool?: SeamsConfigsInput['routerAbEcdsaHssPresignaturePool'];
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
    ensureIframe: () => HTMLIFrameElement;
  }) => WalletIframeOverlayState;
}

export type WalletIframeOverlayState = {
  controller: OverlayController;
  forceFullscreen: boolean;
};

type Pending = {
  resolve: (value: unknown) => void;
  reject: (reason?: unknown) => void;
  timer: number | undefined;
  timeoutMs: number;
  deadlineAtMs: number;
  onProgress?: (payload: ProgressPayload) => void;
  requestType: ParentToChildEnvelope['type'];
  onTimeout: () => Error;
};

const WALLET_IFRAME_PROGRESS_TIMEOUT_EXTENSION_FACTOR = 4;
const WALLET_IFRAME_REGISTRATION_TIMEOUT_MS = 180_000;
const WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS = 30_000;
const WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS = 5 * 60 * 1000;

type WalletIframeLoginStatusSnapshot = {
  isLoggedIn: boolean;
  walletId: string | null;
};

function walletIframeLoginStatusFromSession(
  session: WalletSession,
): WalletIframeLoginStatusSnapshot {
  const walletId = String(session.login.walletId || '').trim();
  return {
    isLoggedIn: Boolean(session.login.isLoggedIn && walletId),
    walletId: walletId || null,
  };
}

function walletIdFromRecentUnlocks(result: GetRecentUnlocksResult | null): string | null {
  const lastWalletId = String(result?.lastUsedAccount?.walletId || '').trim();
  return lastWalletId || null;
}

function parseResolveExactKeyExportLaneResult(
  result: ResolveExactKeyExportLaneResult,
): ResolveExactKeyExportLaneResult {
  switch (result.kind) {
    case 'near':
      return {
        kind: 'near',
        laneIdentity: parseExactEd25519SigningLaneIdentity(result.laneIdentity),
      };
    case 'ecdsa':
      return {
        kind: 'ecdsa',
        laneIdentity: parseExactEcdsaSigningLaneIdentity(result.laneIdentity),
      };
  }
  result satisfies never;
  throw new Error('[WalletIframeRouter] unsupported key export lane resolution result');
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

type RegistrationActivationMountCleanup = {
  dispose(): void;
};

const REGISTRATION_ACTIVATION_TARGET_VISIBILITY_TIMEOUT_MS = 1200;
const REGISTRATION_ACTIVATION_TARGET_VISIBILITY_MAX_FRAMES = 45;

const REGISTRATION_ACTIVATION_ACTIVE_ATTRIBUTE = 'data-seams-registration-button-active';
const REGISTRATION_ACTIVATION_STATE_ATTRIBUTES = {
  hovered: 'data-seams-registration-button-hovered',
  focused: 'data-seams-registration-button-focused',
  pressed: 'data-seams-registration-button-pressed',
  busy: 'data-seams-registration-button-busy',
  disabled: 'data-seams-registration-button-disabled',
} as const;
const REGISTRATION_ACTIVATION_MOUNTING_BUTTON_STATE: RegistrationActivationButtonInteractionState =
  {
    kind: 'registration_activation_button_interaction_state_v1',
    hovered: false,
    focused: false,
    pressed: false,
    busy: true,
    disabled: true,
  };
const REGISTRATION_ACTIVATION_READY_BUTTON_STATE: RegistrationActivationButtonInteractionState = {
  kind: 'registration_activation_button_interaction_state_v1',
  hovered: false,
  focused: false,
  pressed: false,
  busy: false,
  disabled: false,
};

type RegistrationActivationCancelReason = Extract<
  RegistrationActivationSurfaceState,
  { kind: 'cancelled' }
>['reason'];

function getErrorCode(error: Error): string {
  if (!isObject(error)) return '';
  const code = (error as { code?: unknown }).code;
  return typeof code === 'string' ? code : '';
}

function shouldTreatRegistrationActivationErrorAsExpired(error: Error): boolean {
  const message = error.message.toLowerCase();
  if (message.includes('registration activation expired')) return true;
  return message.includes('wallet request timeout for pm_registration_activation_prepare');
}

function shouldCancelRegistrationActivationOnDispose(
  state: RegistrationActivationSurfaceState,
): boolean {
  switch (state.kind) {
    case 'idle':
    case 'mounting':
    case 'ready':
    case 'starting':
      return true;
    case 'completed':
    case 'cancelled':
    case 'failed':
      return false;
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
    'PM_REGISTRATION_ACTIVATION_PREPARE',
    'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE',
    'PM_ENROLL_EMAIL_OTP',
    'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
  ]);
  const unlockRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_UNLOCK',
    'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION',
    'PM_REQUEST_EMAIL_OTP_CHALLENGE',
    'PM_LOGIN_EMAIL_OTP_ED25519_CAPABILITY',
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
  const emailRecoveryRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_START_EMAIL_RECOVERY',
    'PM_FINALIZE_EMAIL_RECOVERY',
    'PM_STOP_EMAIL_RECOVERY',
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
  if (emailRecoveryRequests.has(requestType)) {
    return createEmailRecoveryFlowEvent({
      ...common,
      phase:
        status === 'cancelled'
          ? EmailRecoveryFlowEventPhase.CANCELLED
          : EmailRecoveryFlowEventPhase.FAILED,
    });
  }
  if (requestType === 'PM_SYNC_ACCOUNT_FLOW') {
    return createAccountSyncFlowEvent({
      ...common,
      phase:
        status === 'cancelled' ? AccountSyncEventPhase.CANCELLED : AccountSyncEventPhase.FAILED,
    });
  }
  if (
    requestType === 'PM_EXPORT_KEYPAIR_UI' ||
    requestType === 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI'
  ) {
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

function setRegistrationActivationBooleanAttribute(
  target: HTMLElement,
  name: string,
  active: boolean,
): void {
  if (active) {
    target.setAttribute(name, 'true');
  } else {
    target.setAttribute(name, 'false');
  }
}

function canApplyRegistrationActivationButtonState(
  state: RegistrationActivationSurfaceState,
): boolean {
  switch (state.kind) {
    case 'ready':
    case 'starting':
      return true;
    case 'idle':
    case 'mounting':
    case 'completed':
    case 'cancelled':
    case 'failed':
      return false;
  }
}

function applyRegistrationActivationButtonState(args: {
  target: HTMLElement | null;
  state: RegistrationActivationButtonInteractionState;
}): void {
  if (!args.target) return;
  setRegistrationActivationBooleanAttribute(
    args.target,
    REGISTRATION_ACTIVATION_STATE_ATTRIBUTES.hovered,
    args.state.hovered,
  );
  setRegistrationActivationBooleanAttribute(
    args.target,
    REGISTRATION_ACTIVATION_STATE_ATTRIBUTES.focused,
    args.state.focused,
  );
  setRegistrationActivationBooleanAttribute(
    args.target,
    REGISTRATION_ACTIVATION_STATE_ATTRIBUTES.pressed,
    args.state.pressed,
  );
  setRegistrationActivationBooleanAttribute(
    args.target,
    REGISTRATION_ACTIVATION_STATE_ATTRIBUTES.busy,
    args.state.busy,
  );
  setRegistrationActivationBooleanAttribute(
    args.target,
    REGISTRATION_ACTIVATION_STATE_ATTRIBUTES.disabled,
    args.state.disabled,
  );
}

type ParsedRegistrationActivationChildMessage =
  | {
      type: 'PM_REGISTRATION_ACTIVATION_READY';
      payload: PMRegistrationActivationReadyPayload;
    }
  | {
      type: 'PM_REGISTRATION_ACTIVATION_STARTED';
      payload: PMRegistrationActivationStartedPayload;
    }
  | {
      type: 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE';
      payload: PMRegistrationActivationButtonStatePayload;
    };

function parseRegistrationActivationChildMessage(
  msg: ChildToParentEnvelope,
): ParsedRegistrationActivationChildMessage | null {
  switch (msg.type) {
    case 'PM_REGISTRATION_ACTIVATION_READY': {
      const payload = parseRegistrationActivationReadyPayload(msg.payload);
      return payload ? { type: msg.type, payload } : null;
    }
    case 'PM_REGISTRATION_ACTIVATION_STARTED': {
      const payload = parseRegistrationActivationStartedPayload(msg.payload);
      return payload ? { type: msg.type, payload } : null;
    }
    case 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE': {
      const payload = parseRegistrationActivationButtonStatePayload(msg.payload);
      return payload ? { type: msg.type, payload } : null;
    }
    default:
      return null;
  }
}

function clearRegistrationActivationButtonState(target: HTMLElement | null): void {
  if (!target) return;
  target.removeAttribute(REGISTRATION_ACTIVATION_ACTIVE_ATTRIBUTE);
  for (const attributeName of Object.values(REGISTRATION_ACTIVATION_STATE_ATTRIBUTES)) {
    target.removeAttribute(attributeName);
  }
}

function readRegistrationActivationTargetRect(target: HTMLElement): DOMRectLike | null {
  if (target.isConnected === false) return null;
  const rect = target.getBoundingClientRect();
  const top = Number(rect.top);
  const left = Number(rect.left);
  const width = Number(rect.width);
  const height = Number(rect.height);
  if (
    !Number.isFinite(top) ||
    !Number.isFinite(left) ||
    !Number.isFinite(width) ||
    !Number.isFinite(height) ||
    width <= 0 ||
    height <= 0
  ) {
    return null;
  }
  return { top, left, width, height };
}

function installRegistrationActivationTargetProxy(args: {
  target: HTMLElement;
  accessibleLabel: string;
  onFocusRequest(): void;
}): RegistrationActivationMountCleanup {
  const role = args.target.getAttribute('role');
  const tabindex = args.target.getAttribute('tabindex');
  const ariaLabel = args.target.getAttribute('aria-label');
  const active = args.target.getAttribute(REGISTRATION_ACTIVATION_ACTIVE_ATTRIBUTE);
  args.target.setAttribute(REGISTRATION_ACTIVATION_ACTIVE_ATTRIBUTE, 'true');
  if (role === null) args.target.setAttribute('role', 'button');
  if (tabindex === null) args.target.setAttribute('tabindex', '0');
  if (ariaLabel === null) args.target.setAttribute('aria-label', args.accessibleLabel);
  const onFocus = (): void => {
    args.onFocusRequest();
  };
  const consumeActivationEvent = (event: Event): void => {
    event.preventDefault();
    event.stopPropagation();
    event.stopImmediatePropagation?.();
  };
  const onKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    consumeActivationEvent(event);
    args.onFocusRequest();
  };
  const onKeyUp = (event: KeyboardEvent): void => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    consumeActivationEvent(event);
  };
  const onClick = (event: MouseEvent): void => {
    consumeActivationEvent(event);
    args.onFocusRequest();
  };
  args.target.addEventListener('focus', onFocus);
  args.target.addEventListener('keydown', onKeyDown, true);
  args.target.addEventListener('keyup', onKeyUp, true);
  args.target.addEventListener('click', onClick, true);
  return {
    dispose: (): void => {
      args.target.removeEventListener('focus', onFocus);
      args.target.removeEventListener('keydown', onKeyDown, true);
      args.target.removeEventListener('keyup', onKeyUp, true);
      args.target.removeEventListener('click', onClick, true);
      clearRegistrationActivationButtonState(args.target);
      restoreNullableAttribute(args.target, 'role', role);
      restoreNullableAttribute(args.target, 'tabindex', tabindex);
      restoreNullableAttribute(args.target, 'aria-label', ariaLabel);
      restoreNullableAttribute(args.target, REGISTRATION_ACTIVATION_ACTIVE_ATTRIBUTE, active);
    },
  };
}

function restoreNullableAttribute(target: HTMLElement, name: string, value: string | null): void {
  if (value === null) {
    target.removeAttribute(name);
    return;
  }
  target.setAttribute(name, value);
}

function installRegistrationActivationIframeAccessibility(args: {
  iframe: HTMLIFrameElement;
  accessibleLabel: string;
}): RegistrationActivationMountCleanup {
  const title = args.iframe.getAttribute('title');
  args.iframe.setAttribute('title', args.accessibleLabel);
  return {
    dispose: (): void => {
      restoreNullableAttribute(args.iframe, 'title', title);
    },
  };
}

function visibleRegistrationActivationTargetRect(target: HTMLElement): DOMRectLike | null {
  const rect = readRegistrationActivationTargetRect(target);
  if (!rect) return null;
  const viewportWidth = Number(globalThis.innerWidth || document.documentElement.clientWidth || 0);
  const viewportHeight = Number(
    globalThis.innerHeight || document.documentElement.clientHeight || 0,
  );
  if (viewportWidth <= 0 || viewportHeight <= 0) return rect;
  if (rect.left + rect.width <= 0 || rect.top + rect.height <= 0) return null;
  if (rect.left >= viewportWidth || rect.top >= viewportHeight) return null;
  return rect;
}

function nextRegistrationActivationLayoutFrame(): Promise<void> {
  return new Promise((resolve) => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => resolve());
      return;
    }
    setTimeout(resolve, 16);
  });
}

async function waitForVisibleRegistrationActivationTarget(target: HTMLElement): Promise<boolean> {
  const deadline = Date.now() + REGISTRATION_ACTIVATION_TARGET_VISIBILITY_TIMEOUT_MS;
  let frames = 0;
  while (frames < REGISTRATION_ACTIVATION_TARGET_VISIBILITY_MAX_FRAMES && Date.now() <= deadline) {
    if (visibleRegistrationActivationTargetRect(target)) return true;
    await nextRegistrationActivationLayoutFrame();
    frames += 1;
  }
  return visibleRegistrationActivationTargetRect(target) !== null;
}

function collectRegistrationActivationGeometryTargets(target: HTMLElement): EventTarget[] {
  const events: EventTarget[] = [];
  if (typeof window !== 'undefined') {
    events.push(window);
  }
  if (typeof window === 'undefined' || typeof window.getComputedStyle !== 'function') {
    return events;
  }
  let current = target.parentElement;
  while (current) {
    const styles = window.getComputedStyle(current);
    const overflow = `${styles.overflow} ${styles.overflowX} ${styles.overflowY}`;
    if (/\b(auto|scroll|overlay)\b/.test(overflow)) {
      events.push(current);
    }
    current = current.parentElement;
  }
  return events;
}

function registrationActivationShadowPaddingPx(
  presentation: RegistrationActivationButtonPresentation,
): number {
  if (presentation.kind !== 'iframe_button') return 0;
  return Number.isFinite(presentation.shadowPaddingPx)
    ? Math.max(0, presentation.shadowPaddingPx)
    : 0;
}

function registrationActivationOverlayRectForPresentation(args: {
  rect: DOMRectLike;
  presentation: RegistrationActivationButtonPresentation;
}): DOMRectLike {
  const shadowPaddingPx = registrationActivationShadowPaddingPx(args.presentation);
  if (shadowPaddingPx <= 0) return args.rect;
  return {
    top: args.rect.top - shadowPaddingPx,
    left: args.rect.left - shadowPaddingPx,
    width: args.rect.width + shadowPaddingPx * 2,
    height: args.rect.height + shadowPaddingPx * 2,
  };
}

function installRegistrationActivationOverlayGeometry(args: {
  target: HTMLElement;
  overlayState: WalletIframeOverlayState;
  presentation: RegistrationActivationButtonPresentation;
  onTargetUnavailable(): void;
}): RegistrationActivationMountCleanup | null {
  const applyRect = (): boolean => {
    const rect = visibleRegistrationActivationTargetRect(args.target);
    if (!rect) return false;
    const overlayRect = registrationActivationOverlayRectForPresentation({
      rect,
      presentation: args.presentation,
    });
    args.overlayState.forceFullscreen = false;
    args.overlayState.controller.setSticky(true);
    args.overlayState.controller.showAnchored(overlayRect);
    return true;
  };
  if (!applyRect()) return null;
  let disposed = false;
  const onGeometryChanged = (): void => {
    if (disposed) return;
    if (applyRect()) return;
    args.onTargetUnavailable();
  };
  const resizeObserver =
    typeof ResizeObserver !== 'undefined' ? new ResizeObserver(onGeometryChanged) : null;
  resizeObserver?.observe(args.target);
  const eventTargets = collectRegistrationActivationGeometryTargets(args.target);
  if (typeof window !== 'undefined' && window.visualViewport) {
    eventTargets.push(window.visualViewport);
  }
  for (const eventTarget of eventTargets) {
    eventTarget.addEventListener('scroll', onGeometryChanged, true);
    eventTarget.addEventListener('resize', onGeometryChanged);
  }
  let animationFrameId: number | null = null;
  let alignmentFrameCount = 0;
  const scheduleAlignmentFrame = (): void => {
    if (typeof requestAnimationFrame !== 'function') return;
    if (animationFrameId !== null || disposed) return;
    animationFrameId = requestAnimationFrame(() => {
      animationFrameId = null;
      if (disposed) return;
      alignmentFrameCount += 1;
      onGeometryChanged();
      if (alignmentFrameCount < 12) {
        scheduleAlignmentFrame();
      }
    });
  };
  scheduleAlignmentFrame();
  return {
    dispose: (): void => {
      disposed = true;
      if (animationFrameId !== null && typeof cancelAnimationFrame === 'function') {
        cancelAnimationFrame(animationFrameId);
      }
      resizeObserver?.disconnect();
      for (const eventTarget of eventTargets) {
        eventTarget.removeEventListener('scroll', onGeometryChanged, true);
        eventTarget.removeEventListener('resize', onGeometryChanged);
      }
      args.overlayState.controller.clearAnchoredRect();
    },
  };
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

export class WalletIframeRouter {
  private opts: Required<WalletIframeRouterOptions>;
  // Low-level transport handling iframe mount + handshake
  private transport: IframeTransport;
  private state = {
    port: null as MessagePort | null,
    ready: false,
    // Deduplicate concurrent init() calls and avoid race conditions
    initInFlight: null as Promise<void> | null,
    pending: new Map<string, Pending>(),
    reqCounter: 0,
  };
  private readonly listeners = {
    ready: new Set<() => void>(),
    loginStatus: new Set<(status: { isLoggedIn: boolean; walletId: string | null }) => void>(),
    preferencesChanged: new Set<(payload: PreferencesChangedPayload) => void>(),
    registerOverlayResult: new Set<
      (payload: {
        ok: boolean;
        result?: RegistrationResult;
        cancelled?: boolean;
        error?: string;
      }) => void
    >(),
    registerOverlaySubmit: new Set<() => void>(),
  };
  private readonly registrationActivationListeners = new Map<
    string,
    Set<(event: ChildToParentEnvelope) => void>
  >();
  private lastPreferencesChangedPayload: PreferencesChangedPayload | null = null;
  private progressBus: OnEventsProgressBus;
  private debug = false;
  private readonly walletOriginUrl: URL;
  private readonly walletOriginOrigin: string;
  // Force the overlay to remain fullscreen during critical flows (e.g., registration)
  // and ignore anchored rect updates from helper hooks.
  private overlayState: WalletIframeOverlayState;
  private windowMsgHandlerBound?: (ev: MessageEvent) => void;

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

    // Centralize overlay sizing/visibility. The router is the single owner of
    // "how" the iframe is shown/hidden (fullscreen vs anchored, sticky, etc).
    this.overlayState = (
      this.opts.createOverlayState ||
      ((args: { ensureIframe: () => HTMLIFrameElement }) => ({
        controller: new OverlayController(args),
        forceFullscreen: false,
      }))
    )({
      ensureIframe: () => this.transport.ensureIframeMounted(),
    });

    // Initialize progress router with overlay control and v2 overlay intents.
    // OnEventsProgressBus only decides *when* to show/hide based on events; it calls
    // these adapter functions, and the router delegates to OverlayController.
    this.progressBus = new OnEventsProgressBus(
      {
        show: this.showFrameForActivation.bind(this),
        hide: this.hideFrameAfterProgressDemandCleared.bind(this),
      },
      defaultOverlayIntentResolver,
      this.debug
        ? (msg: string, data?: Record<string, unknown>) => {
            console.debug('[WalletIframeRouter][OnEventsProgressBus]', msg, data || {});
          }
        : undefined,
    );

    // Bridge wallet-host overlay UI messages into router callbacks
    this.windowMsgHandlerBound = (ev: MessageEvent) => {
      if (ev.origin !== this.walletOriginOrigin) return;
      const data = ev.data as unknown;
      if (!data || typeof data !== 'object') return;
      const type = (data as { type?: unknown }).type;
      if (type === 'REGISTER_BUTTON_SUBMIT') {
        // User clicked the register arrow inside the wallet-anchored UI
        // Force the overlay to fullscreen immediately so the TxConfirmer
        // can mount and capture activation in Safari/iOS/mobile.
        this.overlayState.forceFullscreen = true;
        this.overlayState.controller.setSticky(true);
        this.overlayState.controller.showFullscreen();
        for (const cb of Array.from(this.listeners.registerOverlaySubmit)) {
          try {
            cb();
          } catch {}
        }
        return;
      }
      if (type === 'REGISTER_BUTTON_RESULT') {
        const payload = (data as { payload?: unknown }).payload as
          | { ok?: boolean; result?: RegistrationResult; cancelled?: boolean; error?: string }
          | undefined;
        const ok = !!payload?.ok;
        for (const cb of Array.from(this.listeners.registerOverlayResult)) {
          cb({ ok, result: payload?.result, cancelled: payload?.cancelled, error: payload?.error });
        }
        // Release overlay lock after result
        this.releaseOverlayLockAndHideWhenIdle();
        if (ok) {
          const walletId = payload?.result?.walletId;
          void this.getWalletSession(walletId)
            .then(({ login: st }) => {
              this.emitLoginStatusFromState(st);
            })
            .catch(() => {});
        }
        return;
      }
    };
    globalThis.addEventListener?.('message', this.windowMsgHandlerBound);
  }

  private getCurrentAppearance(): AppearanceConfigInput | undefined {
    return this.opts.getAppearance() ?? this.opts.appearance;
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
  async init(): Promise<void> {
    if (this.state.ready) return;
    if (this.state.initInFlight) {
      return this.state.initInFlight;
    }
    this.state.initInFlight = (async () => {
      // Respect autoMount=false by deferring connect until first use
      if (this.opts.testOptions.autoMount !== false) {
        this.state.port = await this.transport.connect();
        this.state.port.onmessage = (ev) => this.onPortMessage(ev);
        this.state.port.start?.();
        this.state.ready = true;
      }
      console.debug(
        '[WalletIframeRouter] init: %s',
        this.state.ready ? 'connected' : 'deferred (autoMount=false)',
      );
      const signingSessionPersistenceMode = this.opts.signingSessionPersistenceMode;
      const signingSessionSeal =
        signingSessionPersistenceMode === 'sealed_refresh_v1'
          ? this.opts.signingSessionSeal
          : undefined;
      await this.post({
        type: 'PM_SET_CONFIG',
        payload: {
          chains: this.opts.chains,
          relayerAccount: this.opts.relayerAccount,
          relayer: this.opts.relayer,
          registration: this.opts.registration,
          signingSessionDefaults: this.opts.signingSessionDefaults,
          signingSessionPersistenceMode,
          ...(signingSessionSeal ? { signingSessionSeal } : {}),
          routerAb: this.opts.routerAb,
          routerAbEcdsaHssPresignaturePool: this.opts.routerAbEcdsaHssPresignaturePool,
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

  getTransportDiagnosticsSnapshot(): WalletIframeTransportDiagnostics {
    return this.transport.getDiagnosticsSnapshot();
  }

  // ===== UI registry/window-message helpers (generic mounting) =====
  registerUiTypes(registry: WalletUIRegistry): void {
    const iframe = this.transport.ensureIframeMounted();
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
    const iframe = this.transport.ensureIframeMounted();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_MOUNT', payload: params }, target);
  }

  updateUiComponent(params: { id: string; props?: Record<string, unknown> }): void {
    const iframe = this.transport.ensureIframeMounted();
    const w = iframe.contentWindow;
    if (!w) return;
    const target = this.walletOriginOrigin;
    this.postWindowMessage(w, { type: 'WALLET_UI_UPDATE', payload: params }, target);
  }

  unmountUiComponent(id: string): void {
    const iframe = this.transport.ensureIframeMounted();
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

  private emitLoginStatusChanged(status: { isLoggedIn: boolean; walletId: string | null }): void {
    for (const cb of Array.from(this.listeners.loginStatus)) {
      try {
        cb(status);
      } catch {}
    }
  }

  private emitLoginStatusFromState(login: LoginState): void {
    this.emitLoginStatusChanged({
      isLoggedIn: !!login.isLoggedIn,
      walletId: login.walletId ? String(login.walletId) : null,
    });
  }

  private emitPreferencesChanged(payload: PreferencesChangedPayload): void {
    this.lastPreferencesChangedPayload = payload;
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

  // Overlay register button events (optional convenience API)
  onRegisterOverlayResult(
    listener: (payload: {
      ok: boolean;
      result?: RegistrationResult;
      cancelled?: boolean;
      error?: string;
    }) => void,
  ): () => void {
    this.listeners.registerOverlayResult.add(listener);
    return () => {
      this.listeners.registerOverlayResult.delete(listener);
    };
  }

  onRegisterOverlaySubmit(listener: () => void): () => void {
    this.listeners.registerOverlaySubmit.add(listener);
    return () => {
      this.listeners.registerOverlaySubmit.delete(listener);
    };
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

  createPasskeyRegistrationActivationSurface(
    payload: CreatePasskeyRegistrationActivationSurfaceArgs,
  ): WalletIframeRegistrationActivationSurface {
    const activationId = `regact-${secureRandomBase36(16, 'registration activation IDs')}`;
    const expiresAtMs = Date.now() + 5 * 60 * 1000;
    let currentState: RegistrationActivationSurfaceState = { kind: 'idle' };
    let mounted = false;
    let disposed = false;
    let target: HTMLElement | null = null;
    let targetCleanup: RegistrationActivationMountCleanup | null = null;
    let geometryCleanup: RegistrationActivationMountCleanup | null = null;
    let iframeTitleCleanup: RegistrationActivationMountCleanup | null = null;
    const listeners = new Set<(state: RegistrationActivationSurfaceState) => void>();
    const setState = (next: RegistrationActivationSurfaceState): void => {
      currentState = next;
      for (const listener of listeners) {
        try {
          listener(next);
        } catch {}
      }
    };
    const cleanupActivationMount = (): void => {
      geometryCleanup?.dispose();
      geometryCleanup = null;
      iframeTitleCleanup?.dispose();
      iframeTitleCleanup = null;
      targetCleanup?.dispose();
      targetCleanup = null;
      clearRegistrationActivationButtonState(target);
      target = null;
    };
    const releaseActivationOverlay = (): void => {
      cleanupActivationMount();
      this.releaseOverlayLockAndHideWhenIdle();
    };
    const postActivationCancel = (reason: RegistrationActivationCancelReason): void => {
      void this.post({
        type: 'PM_REGISTRATION_ACTIVATION_CANCEL',
        payload: { activationId, reason },
      }).catch(() => {});
    };
    const cancelActivation = (reason: RegistrationActivationCancelReason): void => {
      if (disposed) return;
      disposed = true;
      this.registrationActivationListeners.delete(activationId);
      postActivationCancel(reason);
      setState({ kind: 'cancelled', activationId, reason });
      releaseActivationOverlay();
    };
    const activationEventListener = (event: ChildToParentEnvelope): void => {
      const parsed = parseRegistrationActivationChildMessage(event);
      if (!parsed || parsed.payload.activationId !== activationId) return;
      if (parsed.type === 'PM_REGISTRATION_ACTIVATION_READY') {
        if (!target) {
          cancelActivation('target_unavailable');
          return;
        }
        if (!geometryCleanup) {
          geometryCleanup = installRegistrationActivationOverlayGeometry({
            target,
            overlayState: this.overlayState,
            presentation: payload.presentation,
            onTargetUnavailable: () => cancelActivation('target_unavailable'),
          });
        }
        if (!geometryCleanup) {
          cancelActivation('target_unavailable');
          return;
        }
        applyRegistrationActivationButtonState({
          target,
          state: REGISTRATION_ACTIVATION_READY_BUTTON_STATE,
        });
        setState({
          kind: 'ready',
          activationId,
          expiresAtMs: parsed.payload.expiresAtMs,
        });
        return;
      }
      if (parsed.type === 'PM_REGISTRATION_ACTIVATION_STARTED') {
        if (currentState.kind !== 'ready') return;
        setState({ kind: 'starting', activationId });
        releaseActivationOverlay();
        return;
      }
      if (parsed.type === 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE') {
        if (!canApplyRegistrationActivationButtonState(currentState)) return;
        applyRegistrationActivationButtonState({ target, state: parsed.payload.state });
      }
    };

    return {
      kind: 'wallet_iframe_registration_activation_surface_v1',
      mount: (mountTarget: HTMLElement): void => {
        if (mounted || disposed) return;
        target = mountTarget;
        iframeTitleCleanup = installRegistrationActivationIframeAccessibility({
          iframe: this.transport.ensureIframeMounted(),
          accessibleLabel: payload.presentation.accessibleLabel,
        });
        targetCleanup = installRegistrationActivationTargetProxy({
          target: mountTarget,
          accessibleLabel: payload.presentation.accessibleLabel,
          onFocusRequest: () => {
            void this.post({
              type: 'PM_REGISTRATION_ACTIVATION_FOCUS',
              payload: { activationId },
            }).catch(() => {});
          },
        });
        applyRegistrationActivationButtonState({
          target: mountTarget,
          state: REGISTRATION_ACTIVATION_MOUNTING_BUTTON_STATE,
        });
        mounted = true;
        setState({ kind: 'mounting', activationId });
        this.registrationActivationListeners.set(activationId, new Set([activationEventListener]));
        void (async () => {
          try {
            const targetVisible = await waitForVisibleRegistrationActivationTarget(mountTarget);
            if (disposed) return;
            if (!targetVisible) {
              cancelActivation('target_unavailable');
              return;
            }
            const safeOptions = removeFunctionsFromOptions(payload.options);
            const res = await this.post<RegistrationResult>(
              {
                type: 'PM_REGISTRATION_ACTIVATION_PREPARE',
                payload: {
                  activationId,
                  expiresAtMs,
                  wallet: payload.wallet,
                  ...(safeOptions ? { options: safeOptions } : {}),
                  ...(payload.options?.confirmationConfig
                    ? { confirmationConfig: payload.options.confirmationConfig }
                    : {}),
                  presentation: payload.presentation,
                },
                options: {
                  onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
                },
              },
              { timeoutMs: Math.max(1, expiresAtMs - Date.now()) },
            );
            setState({ kind: 'completed', activationId, result: res.result });
            const walletId = res.result?.success ? String(res.result.walletId || '') : '';
            if (walletId) {
              const { login: st } = await this.getWalletSession(walletId);
              this.emitLoginStatusFromState(st);
            }
          } catch (error) {
            if (disposed) return;
            const err = toError(error);
            const code = getErrorCode(err);
            if (code === 'cancelled') {
              postActivationCancel('user_cancelled');
              setState({ kind: 'cancelled', activationId, reason: 'user_cancelled' });
            } else if (shouldTreatRegistrationActivationErrorAsExpired(err)) {
              postActivationCancel('expired');
              setState({ kind: 'cancelled', activationId, reason: 'expired' });
            } else {
              setState({
                kind: 'failed',
                activationId,
                error: err.message || 'Registration failed',
              });
            }
          } finally {
            this.registrationActivationListeners.delete(activationId);
            releaseActivationOverlay();
          }
        })();
      },
      dispose: (): void => {
        if (disposed) return;
        disposed = true;
        this.registrationActivationListeners.delete(activationId);
        if (shouldCancelRegistrationActivationOnDispose(currentState)) {
          postActivationCancel('disposed');
          setState({ kind: 'cancelled', activationId, reason: 'disposed' });
        }
        releaseActivationOverlay();
      },
      state: (): RegistrationActivationSurfaceState => currentState,
      onStateChange: (
        listener: (state: RegistrationActivationSurfaceState) => void,
      ): (() => void) => {
        listeners.add(listener);
        return () => {
          listeners.delete(listener);
        };
      },
    };
  }

  async registerWallet(
    payload: Parameters<RegistrationCapability['registerWallet']>[0],
  ): Promise<RegistrationResult> {
    this.overlayState.forceFullscreen = true;
    this.overlayState.controller.setSticky(true);
    this.overlayState.controller.showFullscreen();

    try {
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
            authMethod: payload.authMethod,
            wallet: payload.wallet,
            signerSelection: registrationSignerSetRequestSelection(payload.signerSelection),
            options: safeOptions,
            ...(confirmationConfig ? { confirmationConfig } : {}),
          },
          options: {
            onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
          },
        },
        { timeoutMs: WALLET_IFRAME_REGISTRATION_TIMEOUT_MS },
      );
      const walletId = res.result?.success ? String(res.result.walletId || '') : '';
      if (walletId) {
        const { login: st } = await this.getWalletSession(walletId);
        this.emitLoginStatusFromState(st);
      }
      return res.result;
    } finally {
      this.releaseOverlayLockAndHideWhenIdle();
    }
  }

  async addWalletSigner(
    payload: Parameters<RegistrationCapability['addWalletSigner']>[0],
  ): Promise<RegistrationResult> {
    this.overlayState.forceFullscreen = true;
    this.overlayState.controller.setSticky(true);
    this.overlayState.controller.showFullscreen();

    try {
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
    } finally {
      this.releaseOverlayLockAndHideWhenIdle();
    }
  }

  async bootstrapEcdsaSession(
    payload: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    this.showFrameForActivation();
    try {
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
    } finally {
      this.hideFrameForActivation();
    }
  }

  async unlock(payload: LoginUnlockRequest): Promise<LoginAndCreateSessionResult> {
    this.showFrameForActivation();
    try {
      const unlockPayload = buildPMUnlockPayload(payload);
      const onEvent = unlockOnEventFromRequest(payload);
      const res = await this.post<LoginAndCreateSessionResult>({
        type: 'PM_UNLOCK',
        payload: unlockPayload,
        options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
      });
      const result = res.result;
      if (result.success) {
        const { login: st } = await this.getWalletSession(unlockPayload.walletId);
        this.emitLoginStatusFromState(st);
      }
      return result;
    } finally {
      this.hideFrameForActivation();
    }
  }

  async getWalletSession(walletId?: string): Promise<WalletSession> {
    const res = await this.post<WalletSession>({
      type: 'PM_GET_WALLET_SESSION',
      payload: walletId ? { walletId } : undefined,
    });
    return res.result;
  }

  async requestEmailOtpChallenge(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
    operation?: WalletEmailOtpLoginOperation;
    onEvent?: (ev: UnlockFlowEvent) => void;
  }): Promise<EmailOtpChallengeResult> {
    const { onEvent, ...wirePayload } = payload;
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
    const { onEvent, ...wirePayload } = payload;
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
  ): GoogleEmailOtpWalletAuthFlow {
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
            const { login: st } = await this.getWalletSession(res.result.value.walletId);
            this.emitLoginStatusFromState(st);
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
          const flow = this.googleEmailOtpWalletAuthFlowFromWire(res.result.value);
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
          ? { ok: true, value: this.googleEmailOtpWalletAuthFlowFromWire(res.result.value) }
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
          const { login: st } = await this.getWalletSession(res.result.value.walletId);
          this.emitLoginStatusFromState(st);
        }
        return res.result;
      },
      cancel,
    };
  }

  async beginGoogleEmailOtpWalletAuth(
    payload: GoogleEmailOtpWalletAuthStartInput,
  ): Promise<GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<
      PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthWireFlow>
    >(
      {
        type: 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH',
        payload: wirePayload,
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
      ? { ok: true, value: this.googleEmailOtpWalletAuthFlowFromWire(res.result.value) }
      : res.result;
  }

  async enrollEmailOtp(payload: {
    walletId: string;
    otpCode: string;
    relayUrl?: string;
    challengeId?: string;
    shamirPrimeB64u?: string;
    appSessionJwt?: string;
    onEvent?: (ev: RegistrationFlowEvent) => void;
  }): Promise<EmailOtpBackedUpEnrollmentResult> {
    const { onEvent, ...wirePayload } = payload;
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
    const { onEvent, ...wirePayload } = payload;
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
    const { login: st } = await this.getWalletSession(payload.walletSession.walletId);
    this.emitLoginStatusFromState(st);
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async loginWithEmailOtpEd25519Capability(
    payload: PMEmailOtpEd25519CapabilityPayload & {
      onEvent?: (event: UnlockFlowEvent) => void;
    },
  ): Promise<LoginWithEmailOtpEd25519CapabilityInternalResult> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<LoginWithEmailOtpEd25519CapabilityInternalResult>(
      {
        type: 'PM_LOGIN_EMAIL_OTP_ED25519_CAPABILITY',
        payload: wirePayload,
        options: { onProgress: this.wrapOnEvent(onEvent, isUnlockFlowEvent) },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    const { login: st } = await this.getWalletSession(payload.walletSession.walletId);
    this.emitLoginStatusFromState(st);
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
    const { login: st } = await this.getWalletSession(payload.walletSession.walletId);
    this.emitLoginStatusFromState(st);
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async getEmailOtpRecoveryCodeStatus(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeStatus> {
    const res = await this.post<EmailOtpRecoveryCodeStatus>({
      type: 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS',
      payload,
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
    const res = await this.post<{
      status: EmailOtpRecoveryCodeStatus;
      displayedStoredCodes: boolean;
    }>(
      {
        type: 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES',
        payload,
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
    const res = await this.post<EmailOtpRecoveryCodeRotationResult>(
      {
        type: 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES',
        payload,
      },
      {
        timeoutMs: WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async enrollAndLoginWithEmailOtpEcdsaCapability(
    payload: Omit<EmailOtpEcdsaEnrollmentCapabilityArgs, 'clientSecret32'>,
  ): Promise<EmailOtpEcdsaEnrollmentCapabilityResult> {
    const { onEvent, ...wirePayload } = payload;
    const res = await this.post<EmailOtpEcdsaEnrollmentCapabilityResult>(
      {
        type: 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
        payload: wirePayload,
        options: {
          onProgress: this.wrapOnEvent(
            onEvent,
            (ev): ev is RegistrationFlowEvent | UnlockFlowEvent =>
              isRegistrationFlowEvent(ev) || isUnlockFlowEvent(ev),
          ),
        },
      },
      {
        timeoutMs: WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    const { login: st } = await this.getWalletSession(payload.walletSession.walletId);
    this.emitLoginStatusFromState(st);
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async checkLoginStatus(): Promise<PostResult<WalletIframeLoginStatusSnapshot>> {
    const directSession = await this.getWalletSession();
    const directStatus = walletIframeLoginStatusFromSession(directSession);
    if (directStatus.isLoggedIn) {
      return { ok: true, result: directStatus };
    }

    const recentUnlocks = await this.getRecentUnlocks().catch(() => null);
    const fallbackWalletId = walletIdFromRecentUnlocks(recentUnlocks);
    if (!fallbackWalletId) {
      return { ok: true, result: directStatus };
    }

    const fallbackSession = await this.getWalletSession(fallbackWalletId).catch(() => null);
    if (!fallbackSession) {
      return { ok: true, result: directStatus };
    }
    const fallbackStatus = walletIframeLoginStatusFromSession(fallbackSession);
    if (!fallbackStatus.isLoggedIn) {
      return { ok: true, result: directStatus };
    }
    return {
      ok: true,
      result: fallbackStatus,
    };
  }

  async lock(): Promise<PostResult<void>> {
    await this.post<void>({ type: 'PM_LOCK' });
    this.emitLoginStatusChanged({ isLoggedIn: false, walletId: null });
    return { ok: true, result: undefined };
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
        payload: {
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
        },
        options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
      },
      {
        timeoutMs: WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS,
        progressTimeoutExtensionFactor: 1,
      },
    );
    return res.result;
  }

  async reportTempoBroadcastAccepted(payload: {
    walletSession: WalletSessionRef;
    signedResult: TempoSignedResult | EvmSignedResult;
    txHash?: `0x${string}`;
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED',
      payload: {
        walletSession: payload.walletSession,
        signedResult: payload.signedResult,
        ...(payload.txHash ? { txHash: payload.txHash } : {}),
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
  }

  async getConfirmationConfig(): Promise<ConfirmationConfig> {
    const res = await this.post<ConfirmationConfig>({ type: 'PM_GET_CONFIRMATION_CONFIG' });
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

  async prefillRouterAbEcdsaHssPresignaturePool(payload: {
    walletSession: WalletSessionRef;
    options: {
      chainTarget: ThresholdEcdsaChainTarget;
      waitForPoolReady?: boolean;
      poolReadyTimeoutMs?: number;
      poolReadyPollIntervalMs?: number;
      minRemainingUsesBeforePrefill?: number;
    };
  }): Promise<RouterAbEcdsaHssLoginPresignaturePrefillResult> {
    const res = await this.post<RouterAbEcdsaHssLoginPresignaturePrefillResult>(
      {
        type: 'PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL',
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

  async startEmailRecovery(payload: {
    walletId: string;
    onEvent?: (ev: EmailRecoveryFlowEvent) => void;
    options?: {
      confirmerText?: { title?: string; body?: string };
      confirmationConfig?: Partial<ConfirmationConfig>;
    };
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    const res = await this.post<{ mailtoUrl: string; nearPublicKey: string }>({
      type: 'PM_START_EMAIL_RECOVERY',
      payload: {
        walletId: payload.walletId,
        ...(payload.options ? { options: payload.options } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isEmailRecoveryFlowEvent) },
    });
    return res.result as { mailtoUrl: string; nearPublicKey: string };
  }

  async finalizeEmailRecovery(payload: {
    walletId: string;
    nearPublicKey?: string;
    onEvent?: (ev: EmailRecoveryFlowEvent) => void;
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_FINALIZE_EMAIL_RECOVERY',
      payload: {
        walletId: payload.walletId,
        ...(payload.nearPublicKey ? { nearPublicKey: payload.nearPublicKey } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isEmailRecoveryFlowEvent) },
    });
  }

  async stopEmailRecovery(payload?: { walletId?: string; nearPublicKey?: string }): Promise<void> {
    await this.post<void>({
      type: 'PM_STOP_EMAIL_RECOVERY',
      ...(payload ? { payload } : {}),
    });
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
    if (input.kind === 'near') {
      const laneIdentity = parseExactEd25519SigningLaneIdentity(input.laneIdentity);
      if (
        String(laneIdentity.signer.account.wallet.walletId) !== String(input.walletSession.walletId)
      ) {
        throw new Error(
          '[WalletIframeRouter] key export lane wallet does not match wallet session',
        );
      }
      if (
        String(laneIdentity.signer.account.nearAccountId) !== String(input.nearAccount.accountId)
      ) {
        throw new Error(
          '[WalletIframeRouter] key export lane NEAR account does not match request account',
        );
      }
      await this.post<void>({
        type: 'PM_EXPORT_KEYPAIR_UI',
        payload: {
          kind: 'near',
          walletSession: input.walletSession,
          nearAccount: input.nearAccount,
          laneIdentity,
          options: {
            ...messageOptions,
            chain: 'near',
          },
        },
        options: {
          sticky: true,
          onProgress: this.wrapOnEvent(onEvent, isKeyExportFlowEvent),
        },
      });
      return;
    }

    const laneIdentity = parseExactEcdsaSigningLaneIdentity(input.laneIdentity);
    if (String(laneIdentity.signer.walletId) !== String(input.walletSession.walletId)) {
      throw new Error('[WalletIframeRouter] key export lane wallet does not match wallet session');
    }
    if (!thresholdEcdsaChainTargetsEqual(laneIdentity.signer.chainTarget, input.chainTarget)) {
      throw new Error(
        '[WalletIframeRouter] key export lane chain target does not match request target',
      );
    }
    await this.post<void>({
      type: 'PM_EXPORT_KEYPAIR_UI',
      payload: {
        kind: 'ecdsa',
        chainTarget: input.chainTarget,
        walletSession: input.walletSession,
        laneIdentity,
        options: messageOptions,
      },
      options: {
        sticky: true,
        onProgress: this.wrapOnEvent(onEvent, isKeyExportFlowEvent),
      },
    });
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
    walletId: string;
    nearAccountId: string;
    preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
    finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
    expectedPublicKey: string;
    options: {
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
      onEvent?: (ev: KeyExportFlowEvent) => void;
    };
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI',
      payload: {
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        preparedSession: args.preparedSession,
        finalizedReport: args.finalizedReport,
        expectedPublicKey: args.expectedPublicKey,
        variant: args.options.variant,
        theme: args.options.theme,
      },
      options: {
        sticky: true,
        onProgress: this.wrapOnEvent(args.options.onEvent, isKeyExportFlowEvent),
      },
    });
  }

  // ===== Control APIs =====
  async cancelRequest(requestId: string): Promise<void> {
    // Best-effort cancel. Host will attempt to close open modals and mark the request as cancelled.
    await this.post<void>({ type: 'PM_CANCEL', payload: { requestId } }).catch(() => {});
    // Always clear local progress + hide overlay even if the host didn't receive the message
    this.progressBus.unregister(requestId);
    this.releaseOverlayLockAndHideWhenIdle();
  }

  async cancelAll(): Promise<void> {
    // Try to cancel all requests on the host, but don't depend on READY/port availability
    await this.post<void>({ type: 'PM_CANCEL', payload: {} }).catch(() => {});
    // Clear all local progress listeners and force-hide the overlay
    this.progressBus.clearAll();
    this.releaseOverlayLockAndHideWhenIdle();
  }

  private onPortMessage(e: MessageEvent<ChildToParentEnvelope>) {
    const msg = e.data as ChildToParentEnvelope;
    // Some wallet-host messages are push-style and are not correlated to a requestId.
    if (msg.type === 'PREFERENCES_CHANGED') {
      const payload = msg.payload as PreferencesChangedPayload;
      this.emitPreferencesChanged(payload);
      return;
    }
    if (
      msg.type === 'PM_REGISTRATION_ACTIVATION_READY' ||
      msg.type === 'PM_REGISTRATION_ACTIVATION_STARTED' ||
      msg.type === 'PM_REGISTRATION_ACTIVATION_BUTTON_STATE'
    ) {
      const parsed = parseRegistrationActivationChildMessage(msg);
      if (parsed) {
        const listeners = this.registrationActivationListeners.get(parsed.payload.activationId);
        if (!listeners) return;
        for (const listener of listeners) {
          try {
            listener(msg);
          } catch {}
        }
      }
      return;
    }
    const requestId = msg.requestId;
    if (!requestId) return;

    // Bridge PROGRESS events to caller-provided onEvent callback via pending registry
    if (msg.type === 'PROGRESS') {
      const payload = msg.payload as ProgressPayload;
      // Route via ProgressBus (handles overlay + sticky delivery)
      this.progressBus.dispatch({ requestId: requestId, payload: payload });
      // Refresh timeout for long-running operations whenever progress is received
      const pend = this.state.pending.get(requestId);
      if (pend) {
        if (pend.timer) window.clearTimeout(pend.timer);
        const remainingLifetimeMs = Math.max(0, pend.deadlineAtMs - Date.now());
        if (remainingLifetimeMs === 0) {
          const err = pend.onTimeout();
          pend.reject(err);
          return;
        }
        const nextTimeoutMs = Math.max(1, Math.min(pend.timeoutMs, remainingLifetimeMs));
        pend.timer = window.setTimeout(() => {
          const err = pend.onTimeout();
          pend.reject(err);
        }, nextTimeoutMs);
      }
      return;
    }

    // Sticky subscriptions can outlive their initial PM_RESULT/ERROR.
    // Clear only preflight fullscreen demand here; if a progress event has taken
    // ownership, its matching progress hide event must own the close.
    if (this.progressBus.isSticky(requestId)) {
      this.progressBus.clearInitialDemand(requestId);
    }

    const pending = this.state.pending.get(requestId);
    // Hide overlay on completion only if no other requests still need it.
    // Sticky progress subscribers wait for a later lifecycle progress event.
    if (!this.progressBus.isSticky(requestId)) {
      if (!this.progressBus.wantsVisible()) {
        this.hideFrameForActivation();
      }
    }
    if (!pending) {
      // Even if no pending exists (e.g., early cancel or pre-resolved),
      // ensure any lingering progress subscriber is removed.
      if (this.debug) {
        console.debug('[WalletIframeRouter] Non-PROGRESS without pending → hide + unregister', {
          requestId,
          type: msg.type,
        });
      }
      this.progressBus.unregister(requestId);
      this.releaseOverlayLockAndHideWhenIdle();
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
      this.releaseOverlayLockAndHideWhenIdle();
      return;
    }

    pending.resolve(msg.payload);
    if (!this.progressBus.isSticky(requestId)) {
      this.progressBus.unregister(requestId);
    }
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
    postOpts?: { timeoutMs?: number; progressTimeoutExtensionFactor?: number },
  ): Promise<PostResult<T>> {
    // Step 1: Lazily initialize the iframe/client if not ready yet
    if (!this.state.ready || !this.state.port) {
      await this.init();
    }

    // Step 2: Generate unique request ID for correlation
    const requestId = `${Date.now()}-${++this.state.reqCounter}`;
    const full: ParentToChildEnvelope = { ...(envelope as ParentToChildEnvelope), requestId };
    const { options } = full;
    const overlayIntent = this.computeOverlayIntent(envelope.type);
    const timeoutMs = postOpts?.timeoutMs ?? this.opts.requestTimeoutMs;
    const parsedProgressTimeoutExtensionFactor = Number(postOpts?.progressTimeoutExtensionFactor);
    const progressTimeoutExtensionFactor =
      Number.isFinite(parsedProgressTimeoutExtensionFactor) &&
      parsedProgressTimeoutExtensionFactor >= 1
        ? parsedProgressTimeoutExtensionFactor
        : WALLET_IFRAME_PROGRESS_TIMEOUT_EXTENSION_FACTOR;
    const requestStartMs = Date.now();
    const maxLifetimeMs = Math.max(timeoutMs, timeoutMs * progressTimeoutExtensionFactor);
    const deadlineAtMs = requestStartMs + maxLifetimeMs;

    return new Promise<PostResult<T>>((resolve, reject) => {
      const onTimeout = () => {
        const pending = this.state.pending.get(requestId);
        if (pending?.timer !== undefined) window.clearTimeout(pending.timer);
        this.state.pending.delete(requestId);
        this.progressBus.unregister(requestId);
        this.releaseOverlayLockAndHideWhenIdle();
        this.sendBestEffortCancel(requestId);
        const elapsedMs = Math.max(0, Date.now() - requestStartMs);
        return new Error(`Wallet request timeout for ${envelope.type} after ${elapsedMs}ms`);
      };

      // Step 3: Set up timeout handler for request
      const timer = window.setTimeout(() => {
        const err = onTimeout();
        reject(err);
      }, timeoutMs);

      // Step 4: Register pending request for correlation
      this.state.pending.set(requestId, {
        resolve: (v) => resolve(v as PostResult<T>),
        reject,
        timer,
        timeoutMs,
        deadlineAtMs,
        onProgress: options?.onProgress,
        requestType: envelope.type,
        onTimeout,
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
        initialDemand: overlayIntent.mode === 'fullscreen' ? 'show' : 'none',
      });

      try {
        // Step 6: Strip non-cloneable fields (functions) from envelope options before posting
        const stickyVal = isObject(options) ? (options as { sticky?: unknown }).sticky : undefined;
        const wireOptions = isBoolean(stickyVal) ? { sticky: stickyVal } : undefined;
        const serializableFull = wireOptions
          ? { ...full, options: wireOptions }
          : { ...full, options: undefined };

        // Step 7: Apply overlay intent (conservative) if not already visible, then post
        if (!this.overlayState.controller.getState().visible) {
          if (overlayIntent.mode === 'fullscreen') {
            this.overlayState.controller.showFullscreen();
          }
        }

        // Send message to iframe via MessagePort
        this.state.port!.postMessage(serializableFull as ParentToChildEnvelope);
      } catch (err) {
        // Step 8: Handle send errors - clean up and reject
        this.state.pending.delete(requestId);
        window.clearTimeout(timer);
        this.progressBus.unregister(requestId);
        this.releaseOverlayLockAndHideWhenIdle();
        reject(toError(err));
      }
    });
  }

  /**
   * Preflight overlay decision before sending the request.
   * - This decides whether to show fullscreen early for user activation.
   * - ProgressBus handles hide timing; OverlayController just executes the decision.
   */
  private computeOverlayIntent(type: ParentToChildEnvelope['type']): {
    mode: 'hidden' | 'fullscreen';
  } {
    switch (type) {
      // Operations that require fullscreen overlay for WebAuthn activation
      case 'PM_EXPORT_KEYPAIR_UI':
      case 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI':
      case 'PM_UNLOCK':
      case 'PM_SIGN_AND_SEND_TX':
      case 'PM_EXECUTE_ACTION':
      case 'PM_SEND_TRANSACTION':
      case 'PM_SIGN_TX_WITH_ACTIONS':
      case 'PM_SIGN_DELEGATE_ACTION':
      case 'PM_SIGN_NEP413':
      case 'PM_SIGN_TEMPO':
      case 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION':
      case 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA':
      case 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES':
      case 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES':
        return { mode: 'fullscreen' };

      // All other operations (background/read-only) don't need overlay
      default:
        return { mode: 'hidden' };
    }
  }

  // Temporarily show the service iframe to capture user activation
  private showFrameForActivation(): void {
    // Ensure iframe exists so overlay can be applied immediately
    this.transport.ensureIframeMounted();
    if (this.overlayState.forceFullscreen) {
      this.overlayState.controller.showFullscreen();
    } else {
      // Prefer fullscreen by default
      this.overlayState.controller.showFullscreen();
    }
  }

  private hideFrameForActivation(): void {
    if (!this.overlayState.controller.getState().visible) return;
    if (this.progressBus.wantsVisible()) return;
    this.overlayState.controller.hide();
  }

  private hideFrameAfterProgressDemandCleared(): void {
    if (this.progressBus.wantsVisible()) return;
    this.overlayState.forceFullscreen = false;
    this.overlayState.controller.forceHide();
  }

  private releaseOverlayLockAndHideWhenIdle(): void {
    this.overlayState.forceFullscreen = false;
    this.overlayState.controller.setSticky(false);
    if (this.progressBus.wantsVisible()) return;
    this.overlayState.controller.forceHide();
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

  /**
   * Public toggle to surface the wallet iframe for user activation or hide it.
   * Useful when mounting inline UI components that require direct user clicks.
   */
  setOverlayVisible(visible: boolean): void {
    if (visible) {
      // Respect fullscreen lock when present
      if (this.overlayState.forceFullscreen) {
        this.overlayState.controller.showFullscreen();
      } else {
        this.showFrameForActivation();
      }
    } else {
      this.hideFrameForActivation();
    }
  }

  /** Public helper for tests/tools: get the underlying iframe element. */
  getIframeEl(): HTMLIFrameElement | null {
    return this.transport.getIframeEl();
  }

  /** Public helper for tests/tools: inspect current overlay state. */
  getOverlayState(): {
    visible: boolean;
    mode: 'hidden' | 'fullscreen' | 'anchored';
    sticky: boolean;
    rect?: DOMRectLike;
  } {
    return this.overlayState.controller.getState();
  }

  /**
   * Position and show the wallet iframe as an anchored overlay matching a DOMRect.
   * Accepts viewport-relative coordinates (from getBoundingClientRect()).
   *
   * Important: Some apps apply CSS transforms (or filters/perspective) on html/body,
   * which changes the containing block for position: fixed. In those cases a fixed
   * iframe will be offset by the page scroll. To avoid that mismatch, anchor the
   * overlay using absolute positioning in document coordinates.
   */
  setOverlayBounds(rect: DOMRectLike): void {
    if (this.overlayState.forceFullscreen) return; // ignore anchored bounds while locked to fullscreen
    this.transport.ensureIframeMounted();
    this.overlayState.controller.showAnchored(rect);
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

// ===== Runtime type guards to safely bridge ProgressPayload -> typed flow events =====
function isRegistrationFlowEvent(progress: ProgressPayload): progress is RegistrationFlowEvent {
  return isWalletFlowEvent(progress) && progress.flow === 'registration';
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

function isEmailRecoveryFlowEvent(p: ProgressPayload): p is EmailRecoveryFlowEvent {
  return isWalletFlowEvent(p) && p.flow === 'email_recovery';
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
