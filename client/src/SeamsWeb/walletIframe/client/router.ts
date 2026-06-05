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
  type ParentToChildEnvelope,
  type ChildToParentEnvelope,
  type ProgressPayload,
  type PreferencesChangedPayload,
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
  KeyExportFlowEvent,
  EmailRecoveryFlowEvent,
  UnlockFlowEvent,
  RegistrationFlowEvent,
  SendTransactionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SigningFlowEvent,
  AccountSyncFlowEvent,
} from '@/core/types/sdkSentEvents';
import type { EcdsaSignerProvisioningDefaults } from '@/core/types/ecdsaSignerProvisioningDefaults';
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
  WalletSession,
  RegistrationResult,
  SignDelegateActionResult,
  SignTransactionResult,
  SeamsChainConfig,
  SeamsConfigsInput,
} from '@/core/types/seams';
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type { NonceLeaseRef } from '@/core/signingEngine/nonce/NonceCoordinator';
import type { ThresholdEcdsaLoginPrefillResult } from '@/core/signingEngine/session/warmCapabilities/ecdsaLoginPrefill';
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  BootstrapThresholdEcdsaSessionArgs,
  EmailOtpChallengeResult,
  EmailOtpEcdsaCapabilityArgs,
  EmailOtpEcdsaCapabilityResult,
  EmailOtpEcdsaEnrollmentCapabilityArgs,
  EmailOtpEcdsaEnrollmentCapabilityResult,
  EmailOtpBackedUpEnrollmentResult,
  EmailOtpEnrollmentResult,
  EmailOtpRecoveryCodeBackupStatus,
  EmailOtpRecoveryCodeStatus,
  GoogleEmailOtpSessionExchangeResult,
  RegistrationCapability,
} from '@/SeamsWeb/signingSurface/types';
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
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import { type ConfirmationConfig } from '@/core/types/signer-worker';
import type { AccessKeyList } from '@/core/rpcClients/near/NearClient';
import type { SignNEP413MessageResult } from '@/SeamsWeb/operations/near';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { cloneResolvedChainConfig } from '@/core/config/chains';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';

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
  thresholdEcdsaPresignPool?: SeamsConfigsInput['thresholdEcdsaPresignPool'];
  provisioningDefaults?: SeamsConfigsInput['provisioningDefaults'];
  rpIdOverride?: string;
  authenticatorOptions?: AuthenticatorOptions;
  // SDK asset base path for embedded bundles when mounting same‑origin via srcdoc
  // Must serve dist/esm under this base path. Defaults to '/sdk'.
  sdkBasePath?: string;
  // Optional appearance defaults forwarded to wallet host (theme + color token overrides).
  appearance?: Pick<AppearanceConfigInput, 'theme' | 'tokens'>;
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
const WALLET_IFRAME_THRESHOLD_SIGNING_TIMEOUT_MS = 30_000;
const WALLET_IFRAME_EMAIL_OTP_BACKUP_TIMEOUT_MS = 5 * 60 * 1000;
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
    'PM_REGISTER',
    'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE',
    'PM_ENROLL_EMAIL_OTP',
    'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
  ]);
  const unlockRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_UNLOCK',
    'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION',
    'PM_REQUEST_EMAIL_OTP_CHALLENGE',
    'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
  ]);
  const signingRequests = new Set<ParentToChildEnvelope['type']>([
    'PM_SIGN_TXS_WITH_ACTIONS',
    'PM_SIGN_AND_SEND_TXS',
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
        show: () => this.showFrameForActivation(),
        hide: () => this.hideFrameForActivation(),
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
        this.overlayState.forceFullscreen = false;
        this.overlayState.controller.setSticky(false);
        // Progress bus will hide after completion; hide defensively here
        this.hideFrameForActivation();
        if (ok) {
          const walletId = payload?.result?.nearAccountId;
          void this.getWalletSession(walletId)
            .then(({ login: st }) => {
              this.emitLoginStatusChanged({
                isLoggedIn: !!st.isLoggedIn,
                walletId: st.nearAccountId,
              });
            })
            .catch(() => {});
        }
        return;
      }
    };
    globalThis.addEventListener?.('message', this.windowMsgHandlerBound);
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
          thresholdEcdsaPresignPool: this.opts.thresholdEcdsaPresignPool,
          provisioningDefaults: this.opts.provisioningDefaults,
          iframeWallet: this.opts.rpIdOverride
            ? { rpIdOverride: this.opts.rpIdOverride }
            : undefined,
          authenticatorOptions: this.opts.authenticatorOptions,
          appearance: this.opts.appearance,
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

  private emitPreferencesChanged(payload: PreferencesChangedPayload): void {
    if (!this.listeners.preferencesChanged.size) return;
    for (const cb of Array.from(this.listeners.preferencesChanged)) {
      try {
        cb(payload);
      } catch {}
    }
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

  async signTransactionsWithActions(payload: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: {
      signerSlot?: number;
      onEvent?: (ev: SigningFlowEvent) => void;
      onError?: (error: Error) => void;
      afterCall?: AfterCall<SignTransactionResult[]>;
      // Allow minimal overrides (e.g., { uiMode: 'drawer' })
      confirmationConfig?: Partial<ConfirmationConfig>;
      confirmerText?: { title?: string; body?: string };
    };
  }): Promise<SignTransactionResult[]> {
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
      type: 'PM_SIGN_TXS_WITH_ACTIONS',
      payload: {
        nearAccountId: payload.nearAccountId,
        transactions: payload.transactions,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return normalizeSignedTransactionObject(res.result);
  }

  async signDelegateAction(payload: {
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
        nearAccountId: payload.nearAccountId,
        delegate: payload.delegate,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async registerPasskey(payload: {
    nearAccountId: string;
    confirmationConfig?: Partial<ConfirmationConfig>;
    options?: {
      onEvent?: (ev: RegistrationFlowEvent) => void;
      signerOptions?: EcdsaSignerProvisioningDefaults;
      confirmerText?: { title?: string; body?: string };
    };
  }): Promise<RegistrationResult> {
    // Step 1: For registration, force fullscreen overlay (not anchored to CTA)
    // so the TxConfirmer (drawer/modal) has space to render and capture activation.
    // Lock overlay to fullscreen for the duration of registration
    this.overlayState.forceFullscreen = true;
    this.overlayState.controller.setSticky(true);
    this.overlayState.controller.showFullscreen();

    try {
      // Optional one-time confirmation override (non-persistent)
      if (payload.confirmationConfig) {
        const base = await this.getConfirmationConfig();
        await this.setConfirmationConfig({ ...base, ...payload.confirmationConfig });
      }

      // Step 2: Strip non-serializable functions from options (functions can't cross iframe boundary)
      const safeOptions = removeFunctionsFromOptions(payload.options);

      // Step 3: Send PM_REGISTER message to iframe and wait for response
      const res = await this.post<RegistrationResult>({
        type: 'PM_REGISTER',
        payload: {
          nearAccountId: payload.nearAccountId,
          options: safeOptions,
          ...(payload.confirmationConfig ? { confirmationConfig: payload.confirmationConfig } : {}),
        },
        // Bridge progress events from iframe back to parent callback
        options: {
          onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
        },
      });

      // Step 4: Update login status after successful registration
      const { login: st } = await this.getWalletSession(payload.nearAccountId);
      this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });

      return res?.result;
    } finally {
      // Step 5: Always release overlay lock and hide when done (success or error)
      this.overlayState.forceFullscreen = false;
      this.overlayState.controller.setSticky(false);
      this.hideFrameForActivation();
    }
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
      const res = await this.post<RegistrationResult>({
        type: 'PM_REGISTER_WALLET',
        payload: {
          authMethod: payload.authMethod,
          wallet: payload.wallet,
          rpId: payload.rpId,
          signerSelection: payload.signerSelection,
          options: safeOptions,
          ...(confirmationConfig ? { confirmationConfig } : {}),
        },
        options: {
          onProgress: this.wrapOnEvent(payload.options?.onEvent, isRegistrationFlowEvent),
        },
      });
      const nearAccountId =
        payload.signerSelection.mode === 'ed25519_only' ||
        payload.signerSelection.mode === 'ed25519_and_ecdsa'
          ? payload.signerSelection.ed25519.nearAccountId
          : '';
      if (nearAccountId) {
        const { login: st } = await this.getWalletSession(nearAccountId);
        this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });
      }
      return res.result;
    } finally {
      this.overlayState.forceFullscreen = false;
      this.overlayState.controller.setSticky(false);
      this.hideFrameForActivation();
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
      this.overlayState.forceFullscreen = false;
      this.overlayState.controller.setSticky(false);
      this.hideFrameForActivation();
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

  async unlock(payload: {
    nearAccountId: string;
    options?: {
      onEvent?: (ev: UnlockFlowEvent) => void;
      signerSlot?: number;
      // Forward session config so host can mint JWT/cookie
      session?: {
        kind: 'jwt' | 'cookie';
        relayUrl?: string;
        route?: string;
      };
      // Warm signing session policy override during login
      signingSession?: {
        ttlMs?: number;
        remainingUses?: number;
      };
    };
  }): Promise<LoginAndCreateSessionResult> {
    this.showFrameForActivation();
    try {
      const safeOptions = removeFunctionsFromOptions(payload.options);
      const res = await this.post<LoginAndCreateSessionResult>({
        type: 'PM_UNLOCK',
        payload: {
          nearAccountId: payload.nearAccountId,
          options: safeOptions,
        },
        options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isUnlockFlowEvent) },
      });
      const result = res.result;
      if (result.success) {
        const { login: st } = await this.getWalletSession(payload.nearAccountId);
        this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });
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
    nearAccountId: string;
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
    nearAccountId: string;
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
    rerollRegistrationAttempt?: boolean;
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

  async enrollEmailOtp(payload: {
    nearAccountId: string;
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
    payload: EmailOtpEcdsaCapabilityArgs,
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
    this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });
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
    this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async acknowledgeEmailOtpRecoveryCodeBackup(payload: {
    walletId: string;
    enrollmentId: string;
    enrollmentSealKeyVersion: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeBackupStatus> {
    const res = await this.post<EmailOtpRecoveryCodeBackupStatus>({
      type: 'PM_ACKNOWLEDGE_EMAIL_OTP_RECOVERY_CODE_BACKUP',
      payload,
    });
    return res.result;
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

  async showEmailOtpPendingRecoveryCodeBackup(payload: {
    walletId: string;
    relayUrl?: string;
    appSessionJwt?: string;
  }): Promise<EmailOtpRecoveryCodeStatus> {
    const res = await this.post<EmailOtpRecoveryCodeStatus>(
      {
        type: 'PM_SHOW_EMAIL_OTP_PENDING_RECOVERY_CODE_BACKUP',
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
    this.emitLoginStatusChanged({ isLoggedIn: !!st.isLoggedIn, walletId: st.nearAccountId });
    return sanitizeEmailOtpIframeResult(res.result);
  }

  async checkLoginStatus(): Promise<PostResult<{ isLoggedIn: boolean; walletId: string | null }>> {
    const { login: st } = await this.getWalletSession();
    return {
      ok: true,
      result: {
        isLoggedIn: !!st.isLoggedIn,
        walletId: st.nearAccountId,
      },
    };
  }

  async lock(): Promise<PostResult<void>> {
    await this.post<void>({ type: 'PM_LOCK' });
    this.emitLoginStatusChanged({ isLoggedIn: false, walletId: null });
    return { ok: true, result: undefined };
  }

  async signNep413Message(payload: {
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

  async signTransactionWithKeyPair(payload: {
    signedTransaction: SignedTransaction;
    options?: {
      onEvent?: (ev: SigningFlowEvent) => void;
    };
  }): Promise<ActionResult> {
    // Strip non-cloneable functions from options; host emits PROGRESS events
    const { options } = payload;
    const res = await this.post<ActionResult>({
      type: 'PM_SEND_TRANSACTION',
      payload: {
        signedTransaction: payload.signedTransaction,
        options: options,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async executeAction(payload: {
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
        nearAccountId: payload.nearAccountId,
        receiverId: payload.receiverId,
        actionArgs: payload.actionArgs,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async setConfirmBehavior(behavior: 'requireClick' | 'skipClick'): Promise<void> {
    const { nearAccountId: walletId } = (await this.getWalletSession()).login;
    await this.post<void>({
      type: 'PM_SET_CONFIRM_BEHAVIOR',
      payload: { behavior, walletId },
    });
  }

  async setConfirmationConfig(config: ConfirmationConfig): Promise<void> {
    const { nearAccountId: walletId } = (await this.getWalletSession()).login;
    await this.post<void>({
      type: 'PM_SET_CONFIRMATION_CONFIG',
      payload: { config, walletId },
    });
  }

  async getConfirmationConfig(): Promise<ConfirmationConfig> {
    const res = await this.post<ConfirmationConfig>({ type: 'PM_GET_CONFIRMATION_CONFIG' });
    return res.result;
  }

  async setTheme(theme: 'dark' | 'light'): Promise<void> {
    await this.post<void>({ type: 'PM_SET_THEME', payload: { theme } });
  }

  async prefetchBlockheight(): Promise<void> {
    await this.post<void>({ type: 'PM_PREFETCH_BLOCKHEIGHT' });
  }

  async prefillThresholdEcdsaPresignPool(payload: {
    walletSession: WalletSessionRef;
    options: {
      chainTarget: ThresholdEcdsaChainTarget;
      waitForPoolReady?: boolean;
      poolReadyTimeoutMs?: number;
      poolReadyPollIntervalMs?: number;
      minRemainingUsesBeforePrefill?: number;
    };
  }): Promise<ThresholdEcdsaLoginPrefillResult> {
    const res = await this.post<ThresholdEcdsaLoginPrefillResult>(
      {
        type: 'PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL',
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

  async getRecoveryEmails(
    nearAccountId: string,
  ): Promise<Array<{ hashHex: string; email: string }>> {
    const res = await this.post<Array<{ hashHex: string; email: string }>>({
      type: 'PM_GET_RECOVERY_EMAILS',
      payload: { nearAccountId },
    });
    return Array.isArray(res?.result) ? res.result : [];
  }

  async setRecoveryEmails(payload: {
    nearAccountId: string;
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
        nearAccountId: payload.nearAccountId,
        recoveryEmails: payload.recoveryEmails,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async syncAccount(payload: {
    accountId?: string;
    onEvent?: (ev: AccountSyncFlowEvent) => void;
  }): Promise<SyncAccountResult> {
    const res = await this.post<SyncAccountResult>({
      type: 'PM_SYNC_ACCOUNT_FLOW',
      payload: { ...(payload?.accountId ? { accountId: payload.accountId } : {}) },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isAccountSyncFlowEvent) },
    });
    return res.result as SyncAccountResult;
  }

  async startEmailRecovery(payload: {
    accountId: string;
    onEvent?: (ev: EmailRecoveryFlowEvent) => void;
    options?: {
      confirmerText?: { title?: string; body?: string };
      confirmationConfig?: Partial<ConfirmationConfig>;
    };
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    const res = await this.post<{ mailtoUrl: string; nearPublicKey: string }>({
      type: 'PM_START_EMAIL_RECOVERY',
      payload: {
        accountId: payload.accountId,
        ...(payload.options ? { options: payload.options } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isEmailRecoveryFlowEvent) },
    });
    return res.result as { mailtoUrl: string; nearPublicKey: string };
  }

  async finalizeEmailRecovery(payload: {
    accountId: string;
    nearPublicKey?: string;
    onEvent?: (ev: EmailRecoveryFlowEvent) => void;
  }): Promise<void> {
    await this.post<void>({
      type: 'PM_FINALIZE_EMAIL_RECOVERY',
      payload: {
        accountId: payload.accountId,
        ...(payload.nearPublicKey ? { nearPublicKey: payload.nearPublicKey } : {}),
      },
      options: { onProgress: this.wrapOnEvent(payload?.onEvent, isEmailRecoveryFlowEvent) },
    });
  }

  async stopEmailRecovery(payload?: { accountId?: string; nearPublicKey?: string }): Promise<void> {
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
        ...(payload?.accountId ? { accountId: String(payload.accountId) } : {}),
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
      // Keep the progress subscription alive after the initial QR is returned so Device2 can
      // continue polling and later trigger an in-iframe confirmation + TouchID prompt.
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

  async signAndSendTransactions(payload: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]> {
    const { options } = payload;
    // cannot send objects/functions through postMessage(), clean options first
    const safeOptions = {
      waitUntil: options.waitUntil,
      executionWait: options.executionWait,
      confirmationConfig: options.confirmationConfig,
      ...(typeof options.signerSlot === 'number' ? { signerSlot: options.signerSlot } : {}),
      ...(options.confirmerText ? { confirmerText: options.confirmerText } : {}),
    };

    const res = await this.post<ActionResult[]>({
      type: 'PM_SIGN_AND_SEND_TXS',
      payload: {
        nearAccountId: payload.nearAccountId,
        transactions: payload.transactions,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async hasPasskeyCredential(nearAccountId: string): Promise<boolean> {
    const res = await this.post<boolean>({
      type: 'PM_HAS_PASSKEY',
      payload: { nearAccountId },
    });
    return !!res?.result;
  }

  async viewAccessKeyList(accountId: string): Promise<AccessKeyList> {
    const res = await this.post<AccessKeyList>({
      type: 'PM_VIEW_ACCESS_KEYS',
      payload: { accountId },
    });
    return res.result;
  }

  async deleteDeviceKey(payload: {
    accountId: string;
    publicKeyToDelete: string;
    options: { onEvent?: (ev: SigningFlowEvent) => void };
  }): Promise<ActionResult> {
    const res = await this.post<ActionResult>({
      type: 'PM_DELETE_DEVICE_KEY',
      payload: {
        accountId: payload.accountId,
        publicKeyToDelete: payload.publicKeyToDelete,
        options: {},
      },
      options: { onProgress: this.wrapOnEvent(payload.options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult> {
    // Strip non-cloneable functions from options; host emits PROGRESS events
    const { options } = args;
    const safeOptions = options ? { waitUntil: options.waitUntil } : undefined;

    const res = await this.post<ActionResult>({
      type: 'PM_SEND_TRANSACTION',
      payload: {
        signedTransaction: args.signedTransaction,
        options: safeOptions,
      },
      options: { onProgress: this.wrapOnEvent(options?.onEvent, isSigningFlowEvent) },
    });
    return res.result;
  }

  async exportKeypairWithUI(input: ExportKeypairWithUIInput): Promise<void> {
    const { onEvent, ...messageOptions } = input.options;
    const payload =
      input.kind === 'near'
        ? {
            kind: 'near' as const,
            nearAccount: input.nearAccount,
            options: {
              ...messageOptions,
              chain: 'near' as const,
            },
          }
        : {
            kind: 'ecdsa' as const,
            chainTarget: input.chainTarget,
            walletSession: input.walletSession,
            options: messageOptions,
          };
    await this.post<void>({
      type: 'PM_EXPORT_KEYPAIR_UI',
      payload,
      options: {
        sticky: true,
        onProgress: this.wrapOnEvent(onEvent, isKeyExportFlowEvent),
      },
    });
  }

  async exportThresholdEd25519SeedFromHssReport(args: {
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
    this.hideFrameForActivation();
  }

  async cancelAll(): Promise<void> {
    // Try to cancel all requests on the host, but don't depend on READY/port availability
    await this.post<void>({ type: 'PM_CANCEL', payload: {} }).catch(() => {});
    // Clear all local progress listeners and force-hide the overlay
    this.progressBus.clearAll();
    this.hideFrameForActivation();
  }

  private onPortMessage(e: MessageEvent<ChildToParentEnvelope>) {
    const msg = e.data as ChildToParentEnvelope;
    // Some wallet-host messages are push-style and are not correlated to a requestId.
    if (msg.type === 'PREFERENCES_CHANGED') {
      const payload = msg.payload as PreferencesChangedPayload;
      this.emitPreferencesChanged(payload);
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
        this.overlayState.controller.setSticky(false);
        if (!this.progressBus.wantsVisible()) {
          this.hideFrameForActivation();
        }
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
      case 'PM_REGISTER':
      case 'PM_UNLOCK':
      case 'PM_SIGN_AND_SEND_TXS':
      case 'PM_EXECUTE_ACTION':
      case 'PM_SEND_TRANSACTION':
      case 'PM_SIGN_TXS_WITH_ACTIONS':
      case 'PM_SIGN_DELEGATE_ACTION':
      case 'PM_SIGN_NEP413':
      case 'PM_SIGN_TEMPO':
      case 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION':
      case 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA':
      case 'PM_SHOW_EMAIL_OTP_PENDING_RECOVERY_CODE_BACKUP':
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
function normalizeSignedTransactionObject(result: SignTransactionResult) {
  const arr = Array.isArray(result) ? result : [];
  const normalized = arr.map((entry) => {
    const st = entry?.signedTransaction;
    if (st && isPlainSignedTransactionLike(st)) {
      const nonceLease = (st as { nonceLease?: NonceLeaseRef }).nonceLease;
      entry.signedTransaction = SignedTransaction.fromPlain({
        transaction: st.transaction,
        signature: st.signature,
        borsh_bytes: extractBorshBytesFromPlainSignedTx(st),
        ...(nonceLease ? { nonceLease } : {}),
      });
    }
    return entry;
  });
  return normalized;
}

/**
 * Strips out functions as they cannot be sent over postMessage to iframe
 */
import { stripFunctionsShallow } from '@shared/utils/validation';

function removeFunctionsFromOptions(options?: object): object | undefined {
  if (!options || !isObject(options)) return undefined;
  return stripFunctionsShallow(options);
}
