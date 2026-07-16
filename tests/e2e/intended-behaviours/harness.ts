import {
  test as base,
  type APIRequestContext,
  type BrowserContext,
  type FrameLocator,
  type Page,
  type Response,
  type Route,
  type TestInfo,
} from '@playwright/test';
import * as ed25519 from '@noble/ed25519';
import { base58Decode } from '@shared/utils/encoders';
import { createReadableWalletId } from '@shared/utils/registrationIntent';
import {
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
} from '@shared/utils/routerAbEd25519Yao';
import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  getAddress,
  parseTransaction,
  recoverAddress,
  recoverTransactionAddress,
  serializeTransaction,
} from 'viem';

export type IntendedLifecycleFlow =
  | 'passkey.registration'
  | 'passkey.unlock'
  | 'email_otp.registration'
  | 'email_otp.unlock';

export type IntendedChainTarget = 'near' | 'tempo' | 'arc_evm';

export type IntendedSigningStage =
  | 'post_registration'
  | 'post_unlock'
  | 'after_refresh_recovery'
  | 'after_step_up';

type IntendedWarmSigningStage = Exclude<IntendedSigningStage, 'after_step_up'>;

type IntendedHarnessAction =
  | 'registerPasskeyWallet'
  | 'registerPasskeyEd25519YaoWallet'
  | 'registerPreparedIframePasskeyEd25519YaoWallet'
  | 'addPasskeyEd25519YaoWalletSigner'
  | 'registerEmailOtpWallet'
  | 'unlockPasskeyWallet'
  | 'unlockEmailOtpWallet'
  | 'signNearTransaction'
  | 'signTempoTransaction'
  | 'signArcEvmTransaction'
  | 'exportEd25519Key'
  | 'exportEcdsaKey';

type TraceEntry = {
  atMs: number;
  kind: 'stage' | 'console' | 'pageerror' | 'requestfailed' | 'response' | 'service';
  message: string;
  url?: string;
  status?: number;
};

const ROUTER_AB_ED25519_SIGNING_PATHS = [
  '/router-ab/ed25519/sign/prepare',
  '/router-ab/ed25519/sign',
] as const;

const ROUTER_AB_ED25519_YAO_REGISTRATION_PATHS = [
  ROUTER_AB_ED25519_YAO_REGISTRATION_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_REGISTRATION_EXECUTE_PATH_V1,
] as const;

const ROUTER_AB_ED25519_YAO_RECOVERY_PATHS = [
  ROUTER_AB_ED25519_YAO_RECOVERY_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_EXECUTE_PATH_V1,
  ROUTER_AB_ED25519_YAO_RECOVERY_ACTIVATE_PATH_V1,
] as const;

const ROUTER_AB_ED25519_YAO_WARM_RECOVERY_PATHS = [
  ROUTER_AB_ED25519_YAO_WARM_RECOVERY_BOOTSTRAP_PATH_V1,
  ...ROUTER_AB_ED25519_YAO_RECOVERY_PATHS,
] as const;

const ROUTER_AB_ED25519_YAO_EXPORT_PATHS = [
  ROUTER_AB_ED25519_YAO_EXPORT_ADMISSION_PATH_V1,
  ROUTER_AB_ED25519_YAO_EXPORT_EXECUTE_PATH_V1,
] as const;

type IntendedHarnessConfig = {
  appUrl: string;
  routerUrl: string;
  walletOrigin: string;
  projectEnvironmentId: string;
  publishableKey: string;
  emailOtpAddress: string;
  googleProviderSubjectPrefix: string;
  googleIdToken: string;
  passkeyEcdsaTargetProfile: EcdsaTargetProfileName;
  emailOtpEcdsaTargetProfile: EcdsaTargetProfileName;
  signingSessionDebug: boolean;
};

type IntendedEmailOtpCodeRequestForPage =
  | {
      kind: 'challenge';
      challengeId: string;
      walletId: string;
    }
  | {
      kind: 'latest_for_wallet';
      walletId: string;
      challengeId?: never;
    };

declare global {
  interface Window {
    __seamsIntendedE2EReadEmailOtpCode?: (
      input: IntendedEmailOtpCodeRequestForPage,
    ) => Promise<string>;
    __seamsIntendedConcurrentActionObserver?: IntendedConcurrentActionObserver;
  }
}

type IntendedConcurrentActionObserver = {
  observer: MutationObserver;
  snapshots: unknown[];
};

type LifecycleFailureMatcher = {
  id: string;
  pattern: RegExp;
  reason: string;
};

type IntendedPageLifecycleEvent = {
  index: number;
  payload: unknown;
};

type IntendedPageActionSnapshot =
  | {
      status: 'idle';
      action?: never;
      result?: never;
      error?: never;
    }
  | {
      status: 'running';
      action: IntendedHarnessAction;
      result?: never;
      error?: never;
    }
  | {
      status: 'success';
      action: IntendedHarnessAction;
      result: IntendedActionResultSnapshot;
      error?: never;
    }
  | {
      status: 'error';
      action: IntendedHarnessAction;
      error: string;
      result?: never;
    };

type EcdsaTargetKeySnapshot = {
  chain: 'tempo' | 'arc_evm';
  chainId: number;
  thresholdOwnerAddress: string;
};

type EcdsaTargetProfileName = 'none' | 'tempo' | 'tempo_arc';

type EcdsaTargetKeysSnapshot =
  | {
      kind: 'none';
      tempo?: never;
      arcEvm?: never;
    }
  | {
      kind: 'tempo';
      tempo: EcdsaTargetKeySnapshot;
      arcEvm?: never;
    }
  | {
      kind: 'tempo_arc';
      tempo: EcdsaTargetKeySnapshot;
      arcEvm: EcdsaTargetKeySnapshot;
    };

type EcdsaEnabledSnapshot =
  | {
      ecdsaTargetProfile: 'none';
      thresholdEcdsaEthereumAddress?: never;
      thresholdEcdsaPublicKeyB64u?: never;
      ecdsaTargetKeys: Extract<EcdsaTargetKeysSnapshot, { kind: 'none' }>;
    }
  | {
      ecdsaTargetProfile: 'tempo';
      thresholdEcdsaEthereumAddress: string;
      thresholdEcdsaPublicKeyB64u: string;
      ecdsaTargetKeys: Extract<EcdsaTargetKeysSnapshot, { kind: 'tempo' }>;
    }
  | {
      ecdsaTargetProfile: 'tempo_arc';
      thresholdEcdsaEthereumAddress?: never;
      thresholdEcdsaPublicKeyB64u?: never;
      ecdsaTargetKeys: Extract<EcdsaTargetKeysSnapshot, { kind: 'tempo_arc' }>;
    };

type PasskeyRegistrationResultSnapshot = {
  kind: 'passkey_registration_success';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
} & EcdsaEnabledSnapshot;

type Ed25519AddSignerResultSnapshot = {
  kind: 'near_ed25519_signer_added';
  walletId: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  operationalPublicKey: string;
};

type EmailOtpRegistrationCoreSnapshot = {
  kind: 'email_otp_registration_success';
  initialWalletId: string;
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
};

type EmailOtpRegistrationResultSnapshot = EmailOtpRegistrationCoreSnapshot & EcdsaEnabledSnapshot;

type RegisteredWalletSnapshot =
  | PasskeyRegistrationResultSnapshot
  | EmailOtpRegistrationResultSnapshot;

type NearSigningResultSnapshot = {
  kind: 'near_sign_success';
  walletId: string;
  nearAccountId: string;
  signedTransactionB64: string;
  signedTransactionByteLength: number;
};

type PasskeyUnlockResultSnapshot = {
  kind: 'passkey_unlock_success';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
};

type EmailOtpUnlockCoreSnapshot = {
  kind: 'email_otp_unlock_success';
  walletId: string;
  nearAccountId: string;
  operationalPublicKey: string;
  signingSessionStatus: string;
  remainingUses: number | null;
};

type EmailOtpUnlockResultSnapshot = EmailOtpUnlockCoreSnapshot & EcdsaEnabledSnapshot;

type TempoSigningResultSnapshot = {
  kind: 'tempo_sign_success';
  walletId: string;
  chainId: number;
  senderHashHex: `0x${string}`;
  rawTxHex: `0x${string}`;
};

type ArcEvmSigningResultSnapshot = {
  kind: 'arc_evm_sign_success';
  walletId: string;
  chainId: number;
  txHashHex: `0x${string}`;
  rawTxHex: `0x${string}`;
};

type EcdsaExportResultSnapshot = {
  kind: 'ecdsa_export_success';
  walletId: string;
  chainId: number;
};

type Ed25519ExportResultSnapshot = {
  kind: 'ed25519_export_success';
  walletId: string;
  nearAccountId: string;
};

type IntendedActionResultSnapshot =
  | PasskeyRegistrationResultSnapshot
  | Ed25519AddSignerResultSnapshot
  | EmailOtpRegistrationResultSnapshot
  | NearSigningResultSnapshot
  | PasskeyUnlockResultSnapshot
  | EmailOtpUnlockResultSnapshot
  | TempoSigningResultSnapshot
  | ArcEvmSigningResultSnapshot
  | Ed25519ExportResultSnapshot
  | EcdsaExportResultSnapshot;

type IntendedPageSnapshot = {
  action: IntendedPageActionSnapshot;
  events: readonly IntendedPageLifecycleEvent[];
};

type IntendedLifecycleTracePayload = {
  flow: IntendedLifecycleFlow;
  walletId: string | null;
  appUrl: string;
  routerUrl: string;
  matcherTableVersion: string;
  authPrompts: {
    emailOtp: number;
    passkey: number;
  };
  latestPageSnapshot: IntendedPageSnapshot | null;
  trace: readonly TraceEntry[];
  violations: readonly string[];
};

type WalletIframeAutoConfirmDiagnostics = {
  attempts: number;
  clicked: boolean;
  otpFilled?: boolean;
  otpChallengeMissing?: boolean;
  otpLookupKind?: IntendedEmailOtpCodeRequestForPage['kind'];
  lastOtpError?: string;
  firstIframeAttachedMs?: number;
  firstFrameResolvedMs?: number;
  firstOtpInputVisibleMs?: number;
  firstOtpCodeResolvedMs?: number;
  firstOtpFillDispatchMs?: number;
  firstButtonVisibleMs?: number;
  firstClickDispatchMs?: number;
  firstClickDurationMs?: number;
  totalMs?: number;
};

type WalletIframeAutoConfirmTimingKey =
  | 'firstIframeAttachedMs'
  | 'firstFrameResolvedMs'
  | 'firstOtpInputVisibleMs'
  | 'firstOtpCodeResolvedMs'
  | 'firstOtpFillDispatchMs'
  | 'firstButtonVisibleMs'
  | 'firstClickDispatchMs'
  | 'firstClickDurationMs'
  | 'totalMs';

type NearSignedTransactionParts = {
  unsignedTransactionBytes: Uint8Array;
  signatureKeyType: number;
  signatureBytes64: Uint8Array;
};

type NearUnsignedTransactionSubject = {
  signerId: string;
  publicKey: {
    keyType: number;
    keyData32: Uint8Array;
  };
};

type BorshReadResult<T> = {
  value: T;
  nextOffset: number;
};

type RlpValue =
  | {
      kind: 'bytes';
      bytes: Uint8Array;
    }
  | {
      kind: 'list';
      items: RlpValue[];
    };

type RlpReadResult = {
  value: RlpValue;
  nextOffset: number;
};

type TempoSignedTransactionParts = {
  chainId: number;
  senderSignatureHex: `0x${string}`;
};

type SigningAuthExpectation =
  | 'warm_session'
  | 'passkey_step_up'
  | 'email_otp_step_up';

type SigningAuthEventSummary = {
  phases: readonly string[];
  authenticationMethods: readonly SigningAuthMethod[];
  remainingUses: readonly number[];
  warmSessionClaimed: boolean;
  passkeyPromptStarted: boolean;
  passkeyPromptSucceeded: boolean;
  passkeyAuthenticationComplete: boolean;
  emailOtpChallengeStarted: boolean;
  emailOtpChallengeSent: boolean;
  emailOtpVerifyStarted: boolean;
  emailOtpVerifySucceeded: boolean;
  emailOtpAuthenticationComplete: boolean;
  emailOtpAppSessionExchangeSucceeded: boolean;
  thresholdReconnectStarted: boolean;
  thresholdReconnectSucceeded: boolean;
};

type KeyExportAuthEventSummary = {
  phases: readonly string[];
  passkeyPromptStarted: boolean;
  passkeyPromptSucceeded: boolean;
};

type AuthCounterIncrement = {
  passkeyPrompts: number;
  emailOtpVerifications: number;
};

type SigningAuthMethod = 'passkey' | 'email_otp' | 'warm_session';

const INTENDED_TEMPO_CHAIN_ID = 42_431;
const INTENDED_ARC_EVM_CHAIN_ID = 5_042_002;
const TEMPO_TRANSACTION_TYPE = 0x76;
const MAX_BUDGET_EXHAUSTION_SIGNS = 8;
const SIGNING_AUTH_WARM_SESSION_CLAIMED = 'signing.auth.warm_session.claimed';
const SIGNING_AUTH_PASSKEY_PROMPT_STARTED = 'signing.auth.passkey.prompt.started';
const SIGNING_AUTH_PASSKEY_PROMPT_SUCCEEDED = 'signing.auth.passkey.prompt.succeeded';
const SIGNING_AUTH_EMAIL_OTP_CHALLENGE_STARTED = 'signing.auth.email_otp.challenge.started';
const SIGNING_AUTH_EMAIL_OTP_CHALLENGE_SENT = 'signing.auth.email_otp.challenge.sent';
const SIGNING_AUTH_EMAIL_OTP_VERIFY_STARTED = 'signing.auth.email_otp.verify.started';
const SIGNING_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED = 'signing.auth.email_otp.verify.succeeded';
const SIGNING_AUTHENTICATION_COMPLETE = 'signing.authentication.complete';
const UNLOCK_APP_SESSION_EXCHANGE_SUCCEEDED = 'unlock.app_session.exchange.succeeded';
const SIGNING_THRESHOLD_SESSION_RECONNECT_STARTED = 'signing.threshold_session.reconnect.started';
const SIGNING_THRESHOLD_SESSION_RECONNECT_SUCCEEDED =
  'signing.threshold_session.reconnect.succeeded';
const KEY_EXPORT_AUTH_PASSKEY_PROMPT_STARTED = 'key_export.auth.passkey.prompt.started';
const KEY_EXPORT_AUTH_PASSKEY_PROMPT_SUCCEEDED = 'key_export.auth.passkey.prompt.succeeded';

const LIFECYCLE_FAILURE_MATCHER_TABLE_VERSION = 'refactor-88-2026-07-04';

const LIFECYCLE_FAILURE_MATCHERS: readonly LifecycleFailureMatcher[] = [
  {
    id: 'remaining_spend_indeterminate_budget_unknown',
    pattern: /budget_unknown/i,
    reason: 'remaining spend state was indeterminate in a signing path',
  },
  {
    id: 'exact_lane_selection_failure',
    pattern: /exact selected lane/i,
    reason: 'signing did not use a single exact lane',
  },
  {
    id: 'wallet_runtime_postcondition',
    pattern: /WalletRuntimePostcondition/,
    reason: 'wallet runtime reported a lifecycle postcondition failure',
  },
  {
    id: 'canonical_ecdsa_lane_ambiguous_material',
    pattern: /ambiguous_material/i,
    reason: 'runtime observed multiple canonical ECDSA material groups for one operation',
  },
  {
    id: 'post_step_up_retry_success',
    pattern: /post-step-up transaction failed/i,
    reason: 'first post-step-up transaction failed before a retry could succeed',
  },
] as const;

const EXTERNAL_HOST_PATTERNS = [
  /(^|\.)googleapis\.com$/i,
  /(^|\.)accounts\.google\.com$/i,
  /(^|\.)near\.org$/i,
  /(^|\.)fastnear\.com$/i,
  /^rpc\.moderato\.tempo\.xyz$/i,
  /^rpc\.testnet\.arc\.network$/i,
] as const;

const NEAR_STUB_BLOCK_HASH = '11111111111111111111111111111111';
const SEAMS_INTENDED_PERSIST_TRACE_ENV = 'SEAMS_INTENDED_PERSIST_TRACE';
const SEAMS_INTENDED_TRACE_DIR_ENV = 'SEAMS_INTENDED_TRACE_DIR';

function shouldPersistIntendedLifecycleTrace(): boolean {
  return process.env[SEAMS_INTENDED_PERSIST_TRACE_ENV] === '1';
}

function safeTraceFileSegment(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]/g, '_');
}

function intendedLifecycleTraceDirectory(testInfo: TestInfo): string {
  const configured = process.env[SEAMS_INTENDED_TRACE_DIR_ENV];
  if (configured) return path.resolve(configured);
  return path.resolve(testInfo.config.rootDir, '..', 'test-results', 'intended-lifecycle-traces');
}

function intendedLifecycleTraceFilePath(args: {
  testInfo: TestInfo;
  payload: IntendedLifecycleTracePayload;
}): string {
  const walletId = args.payload.walletId
    ? safeTraceFileSegment(args.payload.walletId)
    : 'no-wallet';
  const flow = safeTraceFileSegment(args.payload.flow);
  const fileName = `${Date.now()}-${flow}-${walletId}-intended-lifecycle-trace.json`;
  return path.join(intendedLifecycleTraceDirectory(args.testInfo), fileName);
}

async function persistIntendedLifecycleTrace(args: {
  testInfo: TestInfo;
  payload: IntendedLifecycleTracePayload;
}): Promise<void> {
  if (!shouldPersistIntendedLifecycleTrace()) return;
  const filePath = intendedLifecycleTraceFilePath(args);
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, JSON.stringify(args.payload, null, 2), 'utf8');
}

function intendedPageActionIsRunning(expectedAction: string): boolean {
  const status = document.querySelector('[data-testid="intended-action-status"]');
  if (!status) return false;
  const state = status.getAttribute('data-state');
  const actionName = status.getAttribute('data-action');
  return actionName === expectedAction && state === 'running';
}

function intendedPageActionIsComplete(expectedAction: string): boolean {
  const status = document.querySelector('[data-testid="intended-action-status"]');
  if (!status) return false;
  const state = status.getAttribute('data-state');
  const actionName = status.getAttribute('data-action');
  return actionName === expectedAction && (state === 'success' || state === 'error');
}

function intendedPageActionStartedOrCompleted(expectedAction: string): boolean {
  const status = document.querySelector('[data-testid="intended-action-status"]');
  if (!status) return false;
  const state = status.getAttribute('data-state');
  const actionName = status.getAttribute('data-action');
  return (
    actionName === expectedAction &&
    (state === 'running' || state === 'success' || state === 'error')
  );
}

function installIntendedConcurrentActionObserver(): void {
  // Playwright serializes this installer alone, so its observer callback must be self-contained.
  function captureSnapshot(): void {
    const state = window.__seamsIntendedConcurrentActionObserver;
    if (!state) return;
    const output = document.querySelector('[data-testid="intended-result-json"]');
    const text = output?.textContent?.trim();
    if (!text) return;
    try {
      state.snapshots.push(JSON.parse(text));
    } catch {
      return;
    }
  }

  window.__seamsIntendedConcurrentActionObserver?.observer.disconnect();
  const output = document.querySelector('[data-testid="intended-result-json"]');
  if (!output) {
    throw new Error('Intended page result output is unavailable for concurrent signing');
  }
  const observer = new MutationObserver(captureSnapshot);
  window.__seamsIntendedConcurrentActionObserver = { observer, snapshots: [] };
  observer.observe(output, { childList: true, characterData: true, subtree: true });
  captureSnapshot();
}

function triggerConcurrentEvmFamilySigning(): void {
  const tempo = document.querySelector<HTMLButtonElement>('[data-testid="intended-sign-tempo"]');
  const arcEvm = document.querySelector<HTMLButtonElement>(
    '[data-testid="intended-sign-arc-evm"]',
  );
  if (!tempo || !arcEvm) {
    throw new Error('Concurrent Tempo/Arc signing controls are unavailable');
  }
  if (tempo.disabled || arcEvm.disabled) {
    throw new Error('Concurrent Tempo/Arc signing controls are disabled');
  }
  tempo.click();
  arcEvm.click();
}

function intendedConcurrentEvmFamilySigningFinished(): boolean {
  const snapshots = window.__seamsIntendedConcurrentActionObserver?.snapshots;
  if (!snapshots) return false;
  let tempoComplete = false;
  let arcEvmComplete = false;
  for (const raw of snapshots) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const action = Reflect.get(raw, 'action');
    if (!action || typeof action !== 'object' || Array.isArray(action)) continue;
    const status = Reflect.get(action, 'status');
    const actionName = Reflect.get(action, 'action');
    if (status !== 'success' && status !== 'error') continue;
    if (actionName === 'signTempoTransaction') tempoComplete = true;
    if (actionName === 'signArcEvmTransaction') arcEvmComplete = true;
  }
  return tempoComplete && arcEvmComplete;
}

function readIntendedConcurrentActionSnapshots(): unknown[] {
  return window.__seamsIntendedConcurrentActionObserver?.snapshots ?? [];
}

function disconnectIntendedConcurrentActionObserver(): void {
  const state = window.__seamsIntendedConcurrentActionObserver;
  if (!state) return;
  state.observer.disconnect();
  delete window.__seamsIntendedConcurrentActionObserver;
}

function nearDemoSignButtonIsActionable(): boolean {
  const buttons = Array.from(document.querySelectorAll('button'));
  for (const button of buttons) {
    if (button.textContent?.trim() !== 'Sign on NEAR') continue;
    return button instanceof HTMLButtonElement && !button.disabled;
  }
  return false;
}

function ignoreNearDemoStatusReadError(): null {
  return null;
}

export class IntendedBehaviourHarness {
  readonly flow: IntendedLifecycleFlow;

  walletId: string;

  readonly trace: TraceEntry[] = [];

  private readonly context: BrowserContext;

  private readonly page: Page;

  private readonly request: APIRequestContext;

  private readonly config: IntendedHarnessConfig;

  private readonly violations: string[] = [];

  private emailOtpVerificationCount = 0;

  private passkeyPromptCount = 0;

  private latestPageSnapshot: IntendedPageSnapshot | null = null;

  private latestWalletIframeAutoConfirmDiagnostics: WalletIframeAutoConfirmDiagnostics | null =
    null;

  private intendedPageReady = false;

  private reloadIntendedPageBeforeNextAction = true;

  private registeredWallet: RegisteredWalletSnapshot | null = null;

  private nearSignerSlot = 1;

  private currentWarmSigningStage: IntendedSigningStage = 'post_registration';

  private latestSigningRemainingUses: number | null = null;

  constructor(args: {
    context: BrowserContext;
    flow: IntendedLifecycleFlow;
    page: Page;
    request: APIRequestContext;
  }) {
    this.context = args.context;
    this.flow = args.flow;
    this.page = args.page;
    this.request = args.request;
    this.config = intendedHarnessConfigFromEnv();
    this.walletId = uniqueWalletId();
  }

  async initialize(): Promise<void> {
    this.recordStage('initialize');
    await this.installRegistrationBenchmarkDiagnosticsFlag();
    await this.installSigningSessionDebugFlag();
    await this.installFailureCollectors();
    await this.installExternalNetworkStubs();
    await this.installWebAuthnVirtualAuthenticator();
    await this.resetBrowserStorage();
    await this.assertServicesReady();
  }

  async registerPasskeyWallet(): Promise<void> {
    this.recordStage('register_passkey_wallet');
    const snapshot = await this.runIntendedPageAction(
      'registerPasskeyWallet',
      'intended-register-passkey',
    );
    const result = requirePasskeyRegistrationResult(snapshot, this.walletId);
    if (snapshot.events.length === 0) {
      throw new Error('Passkey registration did not emit structured lifecycle events');
    }
    this.registeredWallet = result;
    this.nearSignerSlot = 1;
    this.currentWarmSigningStage = 'post_registration';
    this.passkeyPromptCount += 1;
    this.recordService(
      `passkey registration succeeded wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async registerPasskeyEd25519YaoWallet(): Promise<void> {
    this.recordStage('register_passkey_ed25519_yao_wallet');
    const snapshot = await this.runIntendedPageAction(
      'registerPasskeyEd25519YaoWallet',
      'intended-register-passkey-ed25519-yao',
    );
    const result = requirePasskeyRegistrationResult(snapshot, this.walletId);
    if (result.ecdsaTargetProfile !== 'none' || result.ecdsaTargetKeys.kind !== 'none') {
      throw new Error('Ed25519 Yao registration unexpectedly provisioned an ECDSA signer');
    }
    if (snapshot.events.length === 0) {
      throw new Error('Ed25519 Yao passkey registration did not emit lifecycle events');
    }
    this.registeredWallet = result;
    this.nearSignerSlot = 1;
    this.currentWarmSigningStage = 'post_registration';
    this.passkeyPromptCount += 1;
    this.recordService(
      `Ed25519 Yao passkey registration succeeded wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async registerPreparedIframePasskeyEd25519YaoWallet(): Promise<void> {
    this.recordStage('register_prepared_iframe_passkey_ed25519_yao_wallet');
    const snapshot = await this.runIntendedPageAction(
      'registerPreparedIframePasskeyEd25519YaoWallet',
      'intended-register-prepared-iframe-passkey-ed25519-yao',
    );
    const result = requirePasskeyRegistrationResult(snapshot, this.walletId);
    if (result.ecdsaTargetProfile !== 'none' || result.ecdsaTargetKeys.kind !== 'none') {
      throw new Error('Prepared iframe Ed25519 Yao registration provisioned an ECDSA signer');
    }
    if (snapshot.events.length === 0) {
      throw new Error('Prepared iframe Ed25519 Yao registration did not emit lifecycle events');
    }
    this.registeredWallet = result;
    this.nearSignerSlot = 1;
    this.currentWarmSigningStage = 'post_registration';
    this.passkeyPromptCount += 1;
    this.recordService(
      `prepared iframe Ed25519 Yao registration succeeded wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async addPasskeyEd25519YaoWalletSigner(): Promise<void> {
    this.recordStage('add_passkey_ed25519_yao_wallet_signer');
    const previous = requirePasskeyRegisteredWalletSnapshot(
      this.requireRegisteredWalletForSigning(),
    );
    const snapshot = await this.runIntendedPageAction(
      'addPasskeyEd25519YaoWalletSigner',
      'intended-add-passkey-ed25519-yao-signer',
    );
    const result = requireEd25519AddSignerResult(snapshot, this.walletId);
    if (
      result.nearAccountId === previous.nearAccountId ||
      result.nearEd25519SigningKeyId === previous.nearEd25519SigningKeyId ||
      result.operationalPublicKey === previous.operationalPublicKey
    ) {
      throw new Error('Ed25519 add-signer did not create a distinct signer identity');
    }
    if (snapshot.events.length === 0) {
      throw new Error('Ed25519 add-signer did not emit structured lifecycle events');
    }
    this.registeredWallet = {
      kind: 'passkey_registration_success',
      walletId: result.walletId,
      nearAccountId: result.nearAccountId,
      nearEd25519SigningKeyId: result.nearEd25519SigningKeyId,
      operationalPublicKey: result.operationalPublicKey,
      ecdsaTargetProfile: 'none',
      ecdsaTargetKeys: { kind: 'none' },
    };
    this.nearSignerSlot = 2;
    this.currentWarmSigningStage = 'post_registration';
    this.passkeyPromptCount += 1;
    this.recordService(
      `Ed25519 Yao signer added wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async registerEmailOtpWallet(): Promise<void> {
    this.recordStage('register_email_otp_wallet');
    const snapshot = await this.runIntendedPageAction(
      'registerEmailOtpWallet',
      'intended-register-email-otp',
    );
    const result = requireEmailOtpRegistrationResult(snapshot);
    if (snapshot.events.length === 0) {
      throw new Error('Email OTP registration did not emit structured lifecycle events');
    }
    this.walletId = result.walletId;
    this.registeredWallet = result;
    this.nearSignerSlot = 1;
    this.currentWarmSigningStage = 'post_registration';
    this.emailOtpVerificationCount += 1;
    this.recordService(
      `email otp registration succeeded initial=${result.initialWalletId} wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async unlockPasskeyWallet(): Promise<void> {
    this.recordStage('unlock_passkey_wallet');
    const registration = this.requireRegisteredWalletForSigning();
    await this.resetRuntimeOnlyState();
    const traceStartIndex = this.trace.length;
    const snapshot = await this.runIntendedPageAction(
      'unlockPasskeyWallet',
      'intended-unlock-passkey',
    );
    const result = requirePasskeyUnlockResult(snapshot, {
      walletId: this.walletId,
      nearAccountId: registration.nearAccountId,
      operationalPublicKey: registration.operationalPublicKey,
    });
    if (snapshot.events.length === 0) {
      throw new Error('Passkey unlock did not emit structured lifecycle events');
    }
    this.assertRouterAbEd25519YaoRecoveryRoutes(traceStartIndex, 'Passkey unlock');
    this.currentWarmSigningStage = 'post_unlock';
    this.passkeyPromptCount += 1;
    this.recordService(
      `passkey unlock succeeded wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async unlockEmailOtpWallet(): Promise<void> {
    this.recordStage('unlock_email_otp_wallet');
    const registration = this.requireRegisteredWalletForSigning();
    const emailOtpRegistration = requireEmailOtpRegisteredWalletSnapshot(registration);
    await this.resetRuntimeOnlyState();
    const traceStartIndex = this.trace.length;
    const snapshot = await this.runIntendedPageAction(
      'unlockEmailOtpWallet',
      'intended-unlock-email-otp',
    );
    const result = requireEmailOtpUnlockResult(snapshot, emailOtpRegistration);
    if (snapshot.events.length === 0) {
      throw new Error('Email OTP unlock did not emit structured lifecycle events');
    }
    this.assertRouterAbEd25519YaoRecoveryRoutes(traceStartIndex, 'Email OTP cold unlock');
    this.currentWarmSigningStage = 'post_unlock';
    this.emailOtpVerificationCount += 1;
    this.recordService(
      `email otp unlock succeeded wallet=${result.walletId} near=${result.nearAccountId}`,
    );
  }

  async signNearTransaction(stage: IntendedSigningStage): Promise<SigningAuthEventSummary> {
    this.recordStage(`${stage}:near.sign`);
    const registration = this.requireRegisteredWalletForSigning();
    const traceStartIndex = this.trace.length;
    const snapshot = await this.runIntendedPageAction('signNearTransaction', 'intended-sign-near', {
      nearAccountId: registration.nearAccountId,
    });
    const result = requireNearSigningResult(snapshot, {
      walletId: this.walletId,
      nearAccountId: registration.nearAccountId,
    });
    await verifyNearEd25519Signature({ registration, result });
    if (snapshot.events.length === 0) {
      throw new Error('NEAR signing did not emit structured lifecycle events');
    }
    const summary = this.assertSigningAuthEvents(snapshot, stage, 'NEAR signing');
    if (stage === 'after_refresh_recovery') {
      this.assertRouterAbEd25519YaoWarmRecoveryRoutes(traceStartIndex);
    }
    this.assertRouterAbEd25519SigningRoutes(traceStartIndex);
    this.assertNoEd25519YaoRegistrationRoutes(traceStartIndex);
    this.recordSigningRemainingUses(summary);
    this.recordService(
      `near signing signature verified wallet=${result.walletId} near=${result.nearAccountId} bytes=${result.signedTransactionByteLength}`,
    );
    return summary;
  }

  async refreshPagePreservingWalletStorage(): Promise<void> {
    this.recordStage('page_refresh_preserving_wallet_storage');
    this.latestPageSnapshot = null;
    await this.page.goto(this.intendedPageUrl().href, { waitUntil: 'domcontentloaded' });
    await this.page.getByTestId('intended-e2e-page').waitFor({
      state: 'visible',
      timeout: 15_000,
    });
    this.intendedPageReady = true;
    this.reloadIntendedPageBeforeNextAction = false;
    this.recordService('page refreshed preserving wallet storage');
  }

  async assertNearDemoSigningActionable(): Promise<void> {
    this.recordStage('post_registration:near.demo_actionable');
    await this.page.evaluate(navigateWithinSite, '/wallet');
    this.intendedPageReady = false;
    try {
      await this.page.waitForFunction(nearDemoSignButtonIsActionable, undefined, {
        timeout: 20_000,
      });
    } catch (error) {
      const statusText = await this.page
        .locator('.near-funding-status')
        .textContent({ timeout: 1_000 })
        .catch(ignoreNearDemoStatusReadError);
      throw new Error(
        `NEAR demo signing remained unavailable after registration: ${String(statusText || 'no readiness status')}`,
        { cause: error },
      );
    }
    this.recordService('public React wallet projection enabled the NEAR demo signing control');
    await this.page.evaluate(navigateWithinSite, this.intendedPageUrl().href);
    await this.page.getByTestId('intended-e2e-page').waitFor({
      state: 'visible',
      timeout: 15_000,
    });
    this.intendedPageReady = true;
    this.reloadIntendedPageBeforeNextAction = false;
  }

  async signTempoTransaction(stage: IntendedSigningStage): Promise<SigningAuthEventSummary> {
    this.recordStage(`${stage}:tempo.sign`);
    const registration = this.requireRegisteredWalletForSigning();
    const snapshot = await this.runIntendedPageAction(
      'signTempoTransaction',
      'intended-sign-tempo',
    );
    const result = requireTempoSigningResult(snapshot, {
      walletId: this.walletId,
      chainId: INTENDED_TEMPO_CHAIN_ID,
    });
    await verifyTempoEcdsaSignature({ registration, result });
    if (snapshot.events.length === 0) {
      throw new Error('Tempo signing did not emit structured lifecycle events');
    }
    const summary = this.assertSigningAuthEvents(snapshot, stage, 'Tempo signing');
    this.recordSigningRemainingUses(summary);
    this.recordService(
      `tempo signing signature verified wallet=${result.walletId} chainId=${result.chainId}`,
    );
    return summary;
  }

  async signArcEvmTransaction(stage: IntendedSigningStage): Promise<SigningAuthEventSummary> {
    this.recordStage(`${stage}:arc_evm.sign`);
    const registration = this.requireRegisteredWalletForSigning();
    const snapshot = await this.runIntendedPageAction(
      'signArcEvmTransaction',
      'intended-sign-arc-evm',
    );
    const result = requireArcEvmSigningResult(snapshot, {
      walletId: this.walletId,
      chainId: INTENDED_ARC_EVM_CHAIN_ID,
    });
    await verifyArcEvmSignature({ registration, result });
    if (snapshot.events.length === 0) {
      throw new Error('Arc/EVM signing did not emit structured lifecycle events');
    }
    const summary = this.assertSigningAuthEvents(snapshot, stage, 'Arc/EVM signing');
    this.recordSigningRemainingUses(summary);
    this.recordService(
      `arc evm signing signature verified wallet=${result.walletId} chainId=${result.chainId}`,
    );
    return summary;
  }

  async signTempoAndArcEvmConcurrently(stage: IntendedWarmSigningStage): Promise<void> {
    this.recordStage(`${stage}:tempo_arc.concurrent_sign`);
    const registration = this.requireRegisteredWalletForSigning();
    await this.ensureIntendedPageOpen();
    await this.page.evaluate(installIntendedConcurrentActionObserver);
    const diagnostics: WalletIframeAutoConfirmDiagnostics = { attempts: 0, clicked: false };
    let rawSnapshots: unknown[];
    try {
      await this.page.evaluate(triggerConcurrentEvmFamilySigning);
      const completion = this.page.waitForFunction(
        intendedConcurrentEvmFamilySigningFinished,
        undefined,
        { timeout: 120_000 },
      );
      await autoConfirmWalletIframeUntil(this.page, completion, {
        timeoutMs: 120_000,
        intervalMs: 250,
        diagnostics,
      });
      rawSnapshots = await this.page.evaluate(readIntendedConcurrentActionSnapshots);
    } catch (error) {
      throw new Error(
        [
          error instanceof Error ? error.message : String(error),
          `Concurrent wallet iframe auto-confirm diagnostics: ${JSON.stringify(diagnostics)}`,
          this.recentTraceForError(),
        ].join('\n'),
      );
    } finally {
      await this.page.evaluate(disconnectIntendedConcurrentActionObserver);
      this.latestWalletIframeAutoConfirmDiagnostics = diagnostics;
      this.recordService(`concurrent wallet iframe auto-confirm ${JSON.stringify(diagnostics)}`);
    }

    const snapshots = parseIntendedConcurrentActionSnapshots(rawSnapshots);
    const tempoSnapshot = requireConcurrentSigningSuccess(
      snapshots,
      'signTempoTransaction',
    );
    const arcEvmSnapshot = requireConcurrentSigningSuccess(
      snapshots,
      'signArcEvmTransaction',
    );
    const tempoResult = requireTempoSigningResult(tempoSnapshot, {
      walletId: this.walletId,
      chainId: INTENDED_TEMPO_CHAIN_ID,
    });
    const arcEvmResult = requireArcEvmSigningResult(arcEvmSnapshot, {
      walletId: this.walletId,
      chainId: INTENDED_ARC_EVM_CHAIN_ID,
    });
    await verifyTempoEcdsaSignature({ registration, result: tempoResult });
    await verifyArcEvmSignature({ registration, result: arcEvmResult });

    const lifecycleSnapshot = snapshotWithMostLifecycleEvents(tempoSnapshot, arcEvmSnapshot);
    const summary = this.assertSigningAuthEvents(
      lifecycleSnapshot,
      stage,
      'Concurrent Tempo/Arc signing',
    );
    assertConcurrentSharedBudgetExhaustion(summary);
    this.recordSigningRemainingUses(summary);
    this.latestPageSnapshot = lifecycleSnapshot;
    this.recordService(
      `concurrent Tempo/Arc signatures verified wallet=${this.walletId} remainingUses=0`,
    );
  }

  async exhaustSigningBudget(): Promise<void> {
    this.recordStage('remaining_spend.exhaust');
    if (this.latestSigningRemainingUses === 0) {
      this.recordService('signing remaining spend already exhausted');
      return;
    }
    for (let attempt = 1; attempt <= MAX_BUDGET_EXHAUSTION_SIGNS; attempt += 1) {
      const summary = await this.signNearTransaction(this.currentWarmSigningStage);
      const remainingUses = minimumRemainingUse(summary);
      this.recordService(
        `near remaining spend exhaustion attempt=${attempt} remainingUses=${String(remainingUses)}`,
      );
      if (remainingUses === 0) {
        return;
      }
    }
    throw new Error(
      `NEAR remaining spend did not exhaust within ${MAX_BUDGET_EXHAUSTION_SIGNS} warm signs`,
    );
  }

  async exportEcdsaKey(): Promise<void> {
    this.recordStage('ecdsa.export');
    const snapshot = await this.runIntendedPageAction('exportEcdsaKey', 'intended-export-ecdsa');
    const result = requireEcdsaExportResult(snapshot, {
      walletId: this.walletId,
      chainId: INTENDED_ARC_EVM_CHAIN_ID,
    });
    if (snapshot.events.length === 0) {
      throw new Error('ECDSA export did not emit structured lifecycle events');
    }
    this.recordExportAuthCounters(this.assertKeyExportAuthEvents(snapshot, 'ECDSA export'));
    await this.closeExportViewerIfOpen();
    this.recordService(
      `ecdsa export succeeded wallet=${result.walletId} chainId=${result.chainId}`,
    );
  }

  async exportEd25519Key(): Promise<void> {
    this.recordStage('ed25519.export');
    const traceStartIndex = this.trace.length;
    const snapshot = await this.runIntendedPageAction(
      'exportEd25519Key',
      'intended-export-ed25519',
    );
    const registration = this.requireRegisteredWalletForSigning();
    const result = requireEd25519ExportResult(snapshot, {
      walletId: this.walletId,
      nearAccountId: registration.nearAccountId,
    });
    if (snapshot.events.length === 0) {
      throw new Error('Ed25519 export did not emit structured lifecycle events');
    }
    this.recordExportAuthCounters(this.assertKeyExportAuthEvents(snapshot, 'Ed25519 export'));
    this.assertRouterAbEd25519YaoExportRoutes(traceStartIndex);
    await this.closeExportViewerIfOpen();
    this.recordService(
      `ed25519 export succeeded wallet=${result.walletId} nearAccountId=${result.nearAccountId}`,
    );
  }

  assertNoLifecycleViolations(): void {
    if (this.violations.length === 0) return;
    throw new Error(`Intended lifecycle violations:\n${this.violations.join('\n')}`);
  }

  assertNoWrongAuthPath(): void {
    if (this.flow.startsWith('passkey') && this.emailOtpVerificationCount > 0) {
      throw new Error('Passkey lifecycle used Email OTP verification');
    }
    if (this.flow.startsWith('email_otp') && this.passkeyPromptCount > 0) {
      throw new Error('Email OTP lifecycle used passkey/WebAuthn verification');
    }
  }

  async attachTrace(testInfo: TestInfo): Promise<void> {
    const payload: IntendedLifecycleTracePayload = {
      flow: this.flow,
      walletId: this.walletId,
      appUrl: this.config.appUrl,
      routerUrl: this.config.routerUrl,
      matcherTableVersion: LIFECYCLE_FAILURE_MATCHER_TABLE_VERSION,
      authPrompts: {
        emailOtp: this.emailOtpVerificationCount,
        passkey: this.passkeyPromptCount,
      },
      latestPageSnapshot: this.latestPageSnapshot,
      trace: this.trace,
      violations: this.violations,
    };
    await persistIntendedLifecycleTrace({ testInfo, payload });
    await testInfo.attach('intended-lifecycle-trace.json', {
      body: JSON.stringify(payload, null, 2),
      contentType: 'application/json',
    });
  }

  private async installFailureCollectors(): Promise<void> {
    this.page.on('console', this.handleConsoleMessage.bind(this));
    this.page.on('pageerror', this.handlePageError.bind(this));
    this.context.on('requestfailed', this.handleRequestFailed.bind(this));
    this.context.on('response', this.handleResponse.bind(this));
  }

  private async installSigningSessionDebugFlag(): Promise<void> {
    if (!this.config.signingSessionDebug) return;
    await this.context.addInitScript(enableSigningSessionDebugInFrame);
  }

  private async installRegistrationBenchmarkDiagnosticsFlag(): Promise<void> {
    await this.context.addInitScript(enableRegistrationBenchmarkDiagnosticsInFrame);
  }

  private async installExternalNetworkStubs(): Promise<void> {
    await this.context.route('**/*', this.handleExternalRoute.bind(this));
  }

  private async installWebAuthnVirtualAuthenticator(): Promise<void> {
    const client = await this.context.newCDPSession(this.page);
    await client.send('WebAuthn.enable');
    await client.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        hasPrf: true,
        automaticPresenceSimulation: true,
      },
    });
    this.recordService('webauthn virtual authenticator ready');
  }

  private async resetBrowserStorage(): Promise<void> {
    await this.context.clearCookies();
    await this.page.goto(this.config.appUrl, { waitUntil: 'domcontentloaded' });
    await this.page.evaluate(clearBrowserStorage);
    if (this.config.signingSessionDebug) {
      await this.page.evaluate(() => {
        localStorage.setItem('seams:debug:signing-session', '1');
      });
    }
    this.intendedPageReady = false;
    this.reloadIntendedPageBeforeNextAction = true;
    this.recordService('browser storage reset');
  }

  private async assertServicesReady(): Promise<void> {
    await assertHttpOk(this.request, this.config.appUrl, 'site');
    await assertHttpOk(this.request, `${this.config.routerUrl}/healthz`, 'router healthz');
    await assertHttpOk(this.request, `${this.config.routerUrl}/readyz`, 'router readyz');
    this.recordService('site and router ready');
  }

  private intendedPageUrl(): URL {
    const url = new URL('/__intended-e2e', this.config.appUrl);
    url.searchParams.set('flow', this.flow);
    url.searchParams.set('walletId', this.walletId);
    if (this.registeredWallet) {
      url.searchParams.set('nearAccountId', this.registeredWallet.nearAccountId);
      url.searchParams.set('nearSignerSlot', String(this.nearSignerSlot));
    }
    if (this.config.googleIdToken) {
      url.searchParams.set('googleIdToken', this.config.googleIdToken);
    }
    url.searchParams.set('passkeyEcdsaTargetProfile', this.config.passkeyEcdsaTargetProfile);
    url.searchParams.set('emailOtpEcdsaTargetProfile', this.config.emailOtpEcdsaTargetProfile);
    return url;
  }

  private async openIntendedPage(): Promise<void> {
    const url = this.intendedPageUrl();
    await this.page.goto(url.href, { waitUntil: 'domcontentloaded' });
    await this.page.getByTestId('intended-e2e-page').waitFor({
      state: 'visible',
      timeout: 15_000,
    });
    this.intendedPageReady = true;
    this.reloadIntendedPageBeforeNextAction = false;
  }

  private async resetRuntimeOnlyState(): Promise<void> {
    this.latestPageSnapshot = null;
    await this.page.goto('about:blank');
    this.intendedPageReady = false;
    this.reloadIntendedPageBeforeNextAction = true;
    this.recordService('browser runtime reset preserving storage');
  }

  private async ensureIntendedPageOpen(): Promise<void> {
    if (this.intendedPageReady && !this.reloadIntendedPageBeforeNextAction) return;
    await this.openIntendedPage();
  }

  private async runIntendedPageAction(
    action: IntendedHarnessAction,
    buttonTestId: string,
    opts?: {
      nearAccountId?: string;
    },
  ): Promise<IntendedPageSnapshot> {
    if (opts?.nearAccountId && !this.registeredWallet) {
      throw new Error('NEAR signing requires a registered wallet');
    }
    await this.ensureIntendedPageOpen();
    await this.page.getByTestId(buttonTestId).click();
    await this.waitForIntendedPageActionStarted(action);
    const diagnostics: WalletIframeAutoConfirmDiagnostics = { attempts: 0, clicked: false };
    let diagnosticsRecorded = false;
    try {
      const snapshot = await autoConfirmWalletIframeUntil(
        this.page,
        this.waitForIntendedPageActionCompletion(action),
        {
          timeoutMs: 120_000,
          intervalMs: 250,
          diagnostics,
        },
      );
      this.latestPageSnapshot = snapshot;
      return snapshot;
    } catch (error) {
      this.latestWalletIframeAutoConfirmDiagnostics = diagnostics;
      this.recordService(`wallet iframe auto-confirm ${JSON.stringify(diagnostics)}`);
      diagnosticsRecorded = true;
      throw new Error(
        [
          error instanceof Error ? error.message : String(error || 'Intended action failed'),
          `Wallet iframe auto-confirm diagnostics: ${JSON.stringify(diagnostics)}`,
          this.recentTraceForError(),
        ].join('\n'),
      );
    } finally {
      this.latestWalletIframeAutoConfirmDiagnostics = diagnostics;
      if (!diagnosticsRecorded) {
        this.recordService(`wallet iframe auto-confirm ${JSON.stringify(diagnostics)}`);
      }
    }
  }

  private async waitForIntendedPageActionStarted(action: IntendedHarnessAction): Promise<void> {
    try {
      await this.page.waitForFunction(intendedPageActionStartedOrCompleted, action, {
        timeout: 5_000,
      });
    } catch (error) {
      const snapshot = await this.tryReadIntendedPageSnapshot();
      throw new Error(
        [
          `Intended action ${action} did not start after click.`,
          `Page snapshot: ${snapshot ? JSON.stringify(snapshot) : '<unavailable>'}`,
          this.recentTraceForError(),
          `Original error: ${String(error)}`,
        ].join('\n'),
      );
    }
  }

  private async closeExportViewerIfOpen(): Promise<void> {
    const closed = await closeExportViewerFrameButton(this.page);
    if (closed) {
      this.recordService('key export viewer closed');
    }
  }

  private async waitForIntendedPageActionCompletion(
    action: IntendedHarnessAction,
  ): Promise<IntendedPageSnapshot> {
    try {
      await this.page.waitForFunction(intendedPageActionIsComplete, action, { timeout: 120_000 });
    } catch (error) {
      const snapshot = await this.tryReadIntendedPageSnapshot();
      throw new Error(
        [
          `Intended action ${action} did not complete.`,
          `Page snapshot: ${snapshot ? JSON.stringify(snapshot) : '<unavailable>'}`,
          this.recentTraceForError(),
          `Original error: ${String(error)}`,
        ].join('\n'),
      );
    }
    const snapshot = await readIntendedPageSnapshot(this.page);
    if (snapshot.action.status === 'success') return snapshot;
    if (snapshot.action.status === 'error') {
      throw new Error(
        `Intended action ${action} failed: ${snapshot.action.error}\n${this.recentTraceForError()}`,
      );
    }
    throw new Error(`Intended action ${action} ended in invalid state: ${snapshot.action.status}`);
  }

  private async tryReadIntendedPageSnapshot(): Promise<IntendedPageSnapshot | null> {
    try {
      return await readIntendedPageSnapshot(this.page);
    } catch {
      return null;
    }
  }

  private recentTraceForError(): string {
    const recent = this.trace.slice(-30);
    if (recent.length === 0) return 'Recent intended trace: <empty>';
    return [
      'Recent intended trace:',
      ...recent.map((entry) => {
        const status = entry.status ? ` status=${entry.status}` : '';
        const url = entry.url ? ` url=${entry.url}` : '';
        return `- ${entry.kind}${status}${url}: ${entry.message}`;
      }),
    ].join('\n');
  }

  private async handleExternalRoute(route: Route): Promise<void> {
    const request = route.request();
    const url = new URL(request.url());
    if (!isExternalStubHost(url.hostname)) {
      await route.continue();
      return;
    }
    await fulfillExternalStub(route, this.config);
  }

  private handleConsoleMessage(message: { type(): string; text(): string }): void {
    const text = message.text();
    this.trace.push({
      atMs: Date.now(),
      kind: 'console',
      message: `${message.type()}: ${text}`,
    });
    this.recordViolationIfNeeded(text);
  }

  private handlePageError(error: Error): void {
    const text = error.stack || error.message || String(error);
    this.trace.push({ atMs: Date.now(), kind: 'pageerror', message: text });
    this.recordViolationIfNeeded(text);
  }

  private handleRequestFailed(request: {
    url(): string;
    failure(): { errorText: string } | null;
  }): void {
    const failure = request.failure();
    const message = failure?.errorText || 'request failed';
    this.trace.push({
      atMs: Date.now(),
      kind: 'requestfailed',
      message,
      url: request.url(),
    });
    this.recordViolationIfNeeded(message);
  }

  private handleResponse(response: Response): void {
    const status = response.status();
    const signingPath = routerAbEd25519SigningPath(response.url(), this.config.routerUrl);
    const yaoRegistrationPath = routerAbEd25519YaoRegistrationPath(
      response.url(),
      this.config.routerUrl,
    );
    const yaoRecoveryPath = routerAbEd25519YaoWarmRecoveryPath(
      response.url(),
      this.config.routerUrl,
    );
    const yaoExportPath = routerAbEd25519YaoExportPath(response.url(), this.config.routerUrl);
    if (status < 400) {
      const observedPath = signingPath ?? yaoRegistrationPath ?? yaoRecoveryPath ?? yaoExportPath;
      if (observedPath) {
        this.trace.push({
          atMs: Date.now(),
          kind: 'response',
          message: `HTTP ${status} ${observedPath}`,
          status,
          url: response.url(),
        });
      }
      return;
    }
    this.trace.push({
      atMs: Date.now(),
      kind: 'response',
      message: `HTTP ${status}`,
      status,
      url: response.url(),
    });
    void this.captureFailedResponseBody(response);
  }

  private async captureFailedResponseBody(response: Response): Promise<void> {
    const body = await response.text().catch(() => '');
    const bodySnippet = compactResponseBodyForTrace(body);
    if (!bodySnippet) return;
    this.trace.push({
      atMs: Date.now(),
      kind: 'response',
      message: bodySnippet,
      status: response.status(),
      url: response.url(),
    });
    this.recordViolationIfNeeded(bodySnippet);
  }

  private recordStage(message: string): void {
    this.trace.push({ atMs: Date.now(), kind: 'stage', message });
  }

  private assertRouterAbEd25519SigningRoutes(traceStartIndex: number): void {
    const observedPaths = new Set(
      this.trace
        .slice(traceStartIndex)
        .map((entry) => routerAbEd25519SigningPath(entry.url, this.config.routerUrl))
        .filter((path): path is (typeof ROUTER_AB_ED25519_SIGNING_PATHS)[number] => !!path),
    );
    for (const expectedPath of ROUTER_AB_ED25519_SIGNING_PATHS) {
      if (!observedPaths.has(expectedPath)) {
        throw new Error(`NEAR signing did not traverse ${expectedPath}`);
      }
    }
    this.recordService('NEAR signing traversed Router A/B Ed25519 prepare and finalize routes');
  }

  private assertNoEd25519YaoRegistrationRoutes(traceStartIndex: number): void {
    const observedPaths = this.trace
      .slice(traceStartIndex)
      .map((entry) => routerAbEd25519YaoRegistrationPath(entry.url, this.config.routerUrl))
      .filter((path): path is (typeof ROUTER_AB_ED25519_YAO_REGISTRATION_PATHS)[number] => !!path);
    if (observedPaths.length > 0) {
      throw new Error(
        `Ordinary NEAR signing invoked Ed25519 Yao activation routes: ${observedPaths.join(', ')}`,
      );
    }
    this.recordService('ordinary NEAR signing made zero Ed25519 Yao activation route calls');
  }

  private assertRouterAbEd25519YaoRecoveryRoutes(
    traceStartIndex: number,
    flowLabel: 'Passkey unlock' | 'Email OTP cold unlock',
  ): void {
    const observedPaths = new Set<(typeof ROUTER_AB_ED25519_YAO_RECOVERY_PATHS)[number]>();
    for (const entry of this.trace.slice(traceStartIndex)) {
      const path = routerAbEd25519YaoRecoveryPath(entry.url, this.config.routerUrl);
      if (path) observedPaths.add(path);
    }
    for (const expectedPath of ROUTER_AB_ED25519_YAO_RECOVERY_PATHS) {
      if (!observedPaths.has(expectedPath)) {
        throw new Error(`${flowLabel} did not traverse ${expectedPath}`);
      }
    }
    this.recordService(`${flowLabel} traversed all Router A/B Yao recovery routes`);
  }

  private assertRouterAbEd25519YaoWarmRecoveryRoutes(traceStartIndex: number): void {
    const observedPaths = new Set<
      (typeof ROUTER_AB_ED25519_YAO_WARM_RECOVERY_PATHS)[number]
    >();
    for (const entry of this.trace.slice(traceStartIndex)) {
      const path = routerAbEd25519YaoWarmRecoveryPath(entry.url, this.config.routerUrl);
      if (path) observedPaths.add(path);
    }
    if (observedPaths.size === 0) {
      this.recordService('Post-refresh NEAR signing reused the active wallet-worker Yao capability');
      return;
    }
    for (const expectedPath of ROUTER_AB_ED25519_YAO_WARM_RECOVERY_PATHS) {
      if (!observedPaths.has(expectedPath)) {
        throw new Error(`Post-refresh NEAR signing did not traverse ${expectedPath}`);
      }
    }
    this.recordService(
      'Post-refresh NEAR signing used authenticated warm bootstrap and all Yao recovery routes',
    );
  }

  private assertRouterAbEd25519YaoExportRoutes(traceStartIndex: number): void {
    const observedPaths = new Set<(typeof ROUTER_AB_ED25519_YAO_EXPORT_PATHS)[number]>();
    for (const entry of this.trace.slice(traceStartIndex)) {
      const path = routerAbEd25519YaoExportPath(entry.url, this.config.routerUrl);
      if (path) observedPaths.add(path);
    }
    for (const expectedPath of ROUTER_AB_ED25519_YAO_EXPORT_PATHS) {
      if (!observedPaths.has(expectedPath)) {
        throw new Error(`Ed25519 export did not traverse ${expectedPath}`);
      }
    }
    this.recordService('Ed25519 export traversed all strict Router A/B Yao export routes');
  }

  private recordService(message: string): void {
    this.trace.push({ atMs: Date.now(), kind: 'service', message });
  }

  private recordViolationIfNeeded(message: string): void {
    const matched = LIFECYCLE_FAILURE_MATCHERS.find((matcher) => matcher.pattern.test(message));
    if (!matched) return;
    this.violations.push(`${matched.id}: ${message}`);
  }

  private assertSigningAuthEvents(
    snapshot: IntendedPageSnapshot,
    stage: IntendedSigningStage,
    label: string,
  ): SigningAuthEventSummary {
    const expectation = signingAuthExpectationForStage(this.flow, stage);
    const summary = summarizeSigningAuthEvents(snapshot);
    assertSigningAuthExpectation({
      label,
      stage,
      expectation,
      summary,
    });
    if (stage === 'after_step_up') {
      assertStepUpTransactionConsumedSingleUseBudget({ label, summary });
    }
    this.passkeyPromptCount += signingPasskeyPromptCount(summary);
    this.emailOtpVerificationCount += signingEmailOtpVerificationCount(summary);
    return summary;
  }

  private assertKeyExportAuthEvents(
    snapshot: IntendedPageSnapshot,
    label: string,
  ): AuthCounterIncrement {
    const summary = summarizeKeyExportAuthEvents(snapshot);
    const diagnostics = this.latestWalletIframeAutoConfirmDiagnostics;
    if (this.flow.startsWith('passkey')) {
      assertPasskeyKeyExportAuth({ label, summary, diagnostics });
      return { passkeyPrompts: 1, emailOtpVerifications: 0 };
    }
    assertEmailOtpKeyExportAuth({ label, summary, diagnostics });
    return { passkeyPrompts: 0, emailOtpVerifications: 1 };
  }

  private recordExportAuthCounters(increment: AuthCounterIncrement): void {
    this.passkeyPromptCount += increment.passkeyPrompts;
    this.emailOtpVerificationCount += increment.emailOtpVerifications;
  }

  private recordSigningRemainingUses(summary: SigningAuthEventSummary): void {
    const remainingUses = minimumRemainingUse(summary);
    if (remainingUses === null) return;
    this.latestSigningRemainingUses = remainingUses;
  }

  private requireRegisteredWalletForSigning(): RegisteredWalletSnapshot {
    if (this.registeredWallet) return this.registeredWallet;
    throw new Error('Signing requires a registered wallet');
  }
}

function navigateWithinSite(targetHref: string): void {
  const target = new URL(targetHref, window.location.origin);
  if (target.origin !== window.location.origin) {
    throw new Error(`Refusing cross-origin client navigation to ${target.origin}`);
  }
  const relativeHref = `${target.pathname}${target.search}${target.hash}`;
  window.history.pushState({}, '', relativeHref);
  window.dispatchEvent(new Event('site:navigate'));
  window.scrollTo({ top: 0, left: 0, behavior: 'auto' });
}

function requireEmailOtpRegisteredWalletSnapshot(
  registration: RegisteredWalletSnapshot,
): EmailOtpRegistrationResultSnapshot {
  if (registration.kind === 'email_otp_registration_success') return registration;
  throw new Error('Email OTP unlock requires an Email OTP registration snapshot');
}

function requirePasskeyRegisteredWalletSnapshot(
  registration: RegisteredWalletSnapshot,
): PasskeyRegistrationResultSnapshot {
  switch (registration.kind) {
    case 'passkey_registration_success':
      return registration;
    case 'email_otp_registration_success':
      throw new Error('Passkey signer addition requires a passkey-registered wallet');
    default:
      return assertNever(registration);
  }
}

export const intendedTest = base.extend<{
  harness: IntendedBehaviourHarness;
}>({
  harness: async ({ context, page, request }, use, testInfo) => {
    const flow = lifecycleFlowFromTestFile(testInfo.file);
    const harness = new IntendedBehaviourHarness({ context, flow, page, request });
    await harness.initialize();
    await use(harness);
    await harness.attachTrace(testInfo);
    harness.assertNoLifecycleViolations();
    harness.assertNoWrongAuthPath();
  },
});

function intendedHarnessConfigFromEnv(): IntendedHarnessConfig {
  return {
    appUrl: process.env.SEAMS_INTENDED_APP_URL || 'https://localhost',
    routerUrl: process.env.SEAMS_INTENDED_ROUTER_URL || 'https://localhost:9444',
    walletOrigin: process.env.SEAMS_INTENDED_WALLET_ORIGIN || 'https://localhost:8443',
    projectEnvironmentId: process.env.SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID || 'local-env',
    publishableKey: process.env.SEAMS_INTENDED_PUBLISHABLE_KEY || 'pk_local',
    emailOtpAddress: process.env.SEAMS_INTENDED_EMAIL || 'alice@example.test',
    googleProviderSubjectPrefix:
      process.env.SEAMS_INTENDED_GOOGLE_SUBJECT_PREFIX || 'intended-google-subject',
    googleIdToken: process.env.SEAMS_INTENDED_GOOGLE_ID_TOKEN || '',
    passkeyEcdsaTargetProfile: ecdsaTargetProfileFromEnv({
      raw: process.env.SEAMS_INTENDED_PASSKEY_ECDSA_TARGET_PROFILE,
      name: 'SEAMS_INTENDED_PASSKEY_ECDSA_TARGET_PROFILE',
    }),
    emailOtpEcdsaTargetProfile: emailOtpEcdsaTargetProfileFromEnv(
      process.env.SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE,
    ),
    signingSessionDebug: process.env.SEAMS_INTENDED_SIGNING_SESSION_DEBUG === '1',
  };
}

function emailOtpEcdsaTargetProfileFromEnv(raw: string | undefined): EcdsaTargetProfileName {
  return ecdsaTargetProfileFromEnv({
    raw,
    name: 'SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE',
  });
}

function ecdsaTargetProfileFromEnv(args: {
  raw: string | undefined;
  name: string;
}): EcdsaTargetProfileName {
  const value = String(args.raw || 'tempo_arc').trim();
  switch (value) {
    case 'none':
    case 'tempo':
    case 'tempo_arc':
      return value;
    default:
      throw new Error(`Unknown ${args.name}: ${value}`);
  }
}

function uniqueWalletId(): string {
  return String(createReadableWalletId());
}

function lifecycleFlowFromTestFile(filePath: string): IntendedLifecycleFlow {
  const normalized = filePath.replaceAll('\\', '/');
  if (
    normalized.endsWith('passkey.registration.contract.test.ts') ||
    normalized.endsWith('passkey.ed25519-yao-local.contract.test.ts') ||
    normalized.endsWith('passkey.registration.benchmark.test.ts')
  ) {
    return 'passkey.registration';
  }
  if (normalized.endsWith('passkey.unlock.contract.test.ts')) return 'passkey.unlock';
  if (
    normalized.endsWith('email-otp.registration.contract.test.ts') ||
    normalized.endsWith('email-otp.registration.benchmark.test.ts')
  ) {
    return 'email_otp.registration';
  }
  if (
    normalized.endsWith('email-otp.unlock.contract.test.ts') ||
    normalized.endsWith('email-otp.unlock.benchmark.test.ts')
  ) {
    return 'email_otp.unlock';
  }
  throw new Error(`Unknown intended lifecycle contract file: ${filePath}`);
}

async function clearBrowserStorage(): Promise<void> {
  localStorage.clear();
  sessionStorage.clear();
  const databases = await indexedDB.databases().catch((): IDBDatabaseInfo[] => []);
  const deletions: Promise<void>[] = [];
  for (const database of databases) {
    const name = database.name;
    if (!name) continue;
    deletions.push(
      new Promise((resolve) => {
        const request = indexedDB.deleteDatabase(name);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      }),
    );
  }
  await Promise.all(deletions);
}

function enableSigningSessionDebugInFrame(): void {
  try {
    localStorage.setItem('seams:debug:signing-session', '1');
  } catch {}
}

function enableRegistrationBenchmarkDiagnosticsInFrame(): void {
  (
    globalThis as {
      __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: boolean;
    }
  ).__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS = true;
}

async function assertHttpOk(request: APIRequestContext, url: string, label: string): Promise<void> {
  const response = await request.get(url, { ignoreHTTPSErrors: true, timeout: 5_000 });
  if (response.ok()) return;
  throw new Error(`${label} is not ready at ${url}: HTTP ${response.status()}`);
}

function isExternalStubHost(hostname: string): boolean {
  return EXTERNAL_HOST_PATTERNS.some((pattern) => pattern.test(hostname));
}

async function fulfillExternalStub(route: Route, config: IntendedHarnessConfig): Promise<void> {
  const request = route.request();
  const url = new URL(request.url());
  if (url.hostname.includes('googleapis.com') || url.hostname.includes('accounts.google.com')) {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        sub: `${config.googleProviderSubjectPrefix}-stub`,
        email: config.emailOtpAddress,
        email_verified: true,
        aud: config.publishableKey,
      }),
    });
    return;
  }
  if (url.hostname.endsWith('near.org')) {
    await fulfillNearRpcStub(route);
    return;
  }
  if (url.hostname.endsWith('fastnear.com')) {
    await fulfillNearRpcStub(route);
    return;
  }
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ jsonrpc: '2.0', id: 'intended-evm', result: '0x1' }),
  });
}

async function fulfillNearRpcStub(route: Route): Promise<void> {
  const request = parseJsonRpcRequest(route.request().postData() || '{}');
  await route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      result: nearRpcStubResult(request),
    }),
  });
}

function parseJsonRpcRequest(body: string): { id: unknown; method: string; params: unknown } {
  try {
    const parsed = JSON.parse(body);
    if (!isRecord(parsed)) {
      return { id: 'intended-near', method: 'unknown', params: null };
    }
    return {
      id: parsed.id ?? 'intended-near',
      method: typeof parsed.method === 'string' ? parsed.method : 'unknown',
      params: parsed.params,
    };
  } catch {
    return { id: 'intended-near', method: 'unknown', params: null };
  }
}

function nearRpcStubResult(request: { method: string; params: unknown }): unknown {
  switch (request.method) {
    case 'query':
      return nearRpcQueryStubResult(request.params);
    case 'block':
      return {
        author: 'intended-e2e',
        chunks: [],
        header: {
          hash: NEAR_STUB_BLOCK_HASH,
          height: 1,
          prev_hash: NEAR_STUB_BLOCK_HASH,
        },
      };
    case 'send_tx':
      return {
        status: { SuccessValue: '' },
        transaction: { hash: 'intended-near-tx' },
        transaction_outcome: {
          id: 'intended-near-tx',
          outcome: { status: { SuccessValue: '' } },
        },
        receipts_outcome: [],
      };
    default:
      return {};
  }
}

function compactResponseBodyForTrace(body: string): string {
  const trimmed = body.trim();
  if (!trimmed) return '';
  return trimmed.length <= 2_000 ? trimmed : `${trimmed.slice(0, 2_000)}...<truncated>`;
}

function nearRpcQueryStubResult(params: unknown): unknown {
  if (!isRecord(params)) return {};
  const requestType = params.request_type;
  switch (requestType) {
    case 'view_access_key':
      return {
        nonce: 1,
        block_hash: NEAR_STUB_BLOCK_HASH,
        permission: 'FullAccess',
      };
    case 'view_access_key_list':
      return {
        keys: [],
      };
    case 'view_account':
      return {
        amount: '1000000000000000000000000',
        locked: '0',
        code_hash: NEAR_STUB_BLOCK_HASH,
        storage_usage: 0,
        storage_paid_at: 0,
        block_height: 1,
        block_hash: NEAR_STUB_BLOCK_HASH,
      };
    case 'call_function':
      return {
        result: Array.from(new TextEncoder().encode(JSON.stringify('Hello from local NEAR'))),
        logs: [],
        block_height: 1,
        block_hash: NEAR_STUB_BLOCK_HASH,
      };
    default:
      return {};
  }
}

function signingAuthExpectationForStage(
  flow: IntendedLifecycleFlow,
  stage: IntendedSigningStage,
): SigningAuthExpectation {
  switch (stage) {
    case 'post_registration':
    case 'post_unlock':
    case 'after_refresh_recovery':
      return 'warm_session';
    case 'after_step_up':
      return flow.startsWith('passkey') ? 'passkey_step_up' : 'email_otp_step_up';
    default:
      return assertNever(stage);
  }
}

function summarizeSigningAuthEvents(snapshot: IntendedPageSnapshot): SigningAuthEventSummary {
  const phases: string[] = [];
  const authenticationMethods: SigningAuthMethod[] = [];
  const remainingUses: number[] = [];
  let warmSessionClaimed = false;
  let passkeyPromptStarted = false;
  let passkeyPromptSucceeded = false;
  let passkeyAuthenticationComplete = false;
  let emailOtpChallengeStarted = false;
  let emailOtpChallengeSent = false;
  let emailOtpVerifyStarted = false;
  let emailOtpVerifySucceeded = false;
  let emailOtpAuthenticationComplete = false;
  let emailOtpAppSessionExchangeSucceeded = false;
  let thresholdReconnectStarted = false;
  let thresholdReconnectSucceeded = false;

  for (const event of snapshot.events) {
    const phase = signingEventPhase(event.payload);
    if (!phase) continue;
    phases.push(phase);
    const maybeRemainingUses = signingEventRemainingUses(event.payload);
    if (maybeRemainingUses !== null) remainingUses.push(maybeRemainingUses);
    const completedAuthMethod = signingAuthenticationCompleteAuthMethod(event.payload, phase);
    if (completedAuthMethod) {
      authenticationMethods.push(completedAuthMethod);
      switch (completedAuthMethod) {
        case 'passkey':
          passkeyAuthenticationComplete = true;
          break;
        case 'email_otp':
          emailOtpAuthenticationComplete = true;
          break;
        case 'warm_session':
          break;
        default:
          assertNever(completedAuthMethod);
      }
    }
    switch (phase) {
      case SIGNING_AUTH_WARM_SESSION_CLAIMED:
        warmSessionClaimed = true;
        break;
      case SIGNING_AUTH_PASSKEY_PROMPT_STARTED:
        passkeyPromptStarted = true;
        break;
      case SIGNING_AUTH_PASSKEY_PROMPT_SUCCEEDED:
        passkeyPromptSucceeded = true;
        break;
      case SIGNING_AUTH_EMAIL_OTP_CHALLENGE_STARTED:
        emailOtpChallengeStarted = true;
        break;
      case SIGNING_AUTH_EMAIL_OTP_CHALLENGE_SENT:
        emailOtpChallengeSent = true;
        break;
      case SIGNING_AUTH_EMAIL_OTP_VERIFY_STARTED:
        emailOtpVerifyStarted = true;
        break;
      case SIGNING_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED:
        emailOtpVerifySucceeded = true;
        break;
      case UNLOCK_APP_SESSION_EXCHANGE_SUCCEEDED:
        emailOtpAppSessionExchangeSucceeded =
          emailOtpAppSessionExchangeSucceeded || eventAuthMethod(event.payload) === 'email_otp';
        break;
      case SIGNING_THRESHOLD_SESSION_RECONNECT_STARTED:
        thresholdReconnectStarted = true;
        break;
      case SIGNING_THRESHOLD_SESSION_RECONNECT_SUCCEEDED:
        thresholdReconnectSucceeded = true;
        break;
      default:
        break;
    }
  }

  return {
    phases,
    authenticationMethods,
    remainingUses,
    warmSessionClaimed,
    passkeyPromptStarted,
    passkeyPromptSucceeded,
    passkeyAuthenticationComplete,
    emailOtpChallengeStarted,
    emailOtpChallengeSent,
    emailOtpVerifyStarted,
    emailOtpVerifySucceeded,
    emailOtpAuthenticationComplete,
    emailOtpAppSessionExchangeSucceeded,
    thresholdReconnectStarted,
    thresholdReconnectSucceeded,
  };
}

function assertSigningAuthExpectation(input: {
  label: string;
  stage: IntendedSigningStage;
  expectation: SigningAuthExpectation;
  summary: SigningAuthEventSummary;
}): void {
  switch (input.expectation) {
    case 'warm_session':
      assertWarmSessionSigningAuth(input);
      return;
    case 'passkey_step_up':
      assertPasskeyStepUpSigningAuth(input);
      return;
    case 'email_otp_step_up':
      assertEmailOtpStepUpSigningAuth(input);
      return;
    default:
      return assertNever(input.expectation);
  }
}

function signingAuthSummaryDetails(summary: SigningAuthEventSummary): string {
  return JSON.stringify({
    phases: summary.phases,
    authenticationMethods: summary.authenticationMethods,
    remainingUses: summary.remainingUses,
    warmSessionClaimed: summary.warmSessionClaimed,
    passkeyPromptStarted: summary.passkeyPromptStarted,
    passkeyPromptSucceeded: summary.passkeyPromptSucceeded,
    passkeyAuthenticationComplete: summary.passkeyAuthenticationComplete,
    emailOtpChallengeStarted: summary.emailOtpChallengeStarted,
    emailOtpChallengeSent: summary.emailOtpChallengeSent,
    emailOtpVerifyStarted: summary.emailOtpVerifyStarted,
    emailOtpVerifySucceeded: summary.emailOtpVerifySucceeded,
    emailOtpAuthenticationComplete: summary.emailOtpAuthenticationComplete,
    emailOtpAppSessionExchangeSucceeded: summary.emailOtpAppSessionExchangeSucceeded,
    thresholdReconnectStarted: summary.thresholdReconnectStarted,
    thresholdReconnectSucceeded: summary.thresholdReconnectSucceeded,
  });
}

function assertWarmSessionSigningAuth(input: {
  label: string;
  stage: IntendedSigningStage;
  summary: SigningAuthEventSummary;
}): void {
  const usedNoPromptReconnect =
    input.summary.thresholdReconnectSucceeded &&
    !input.summary.passkeyPromptStarted &&
    !input.summary.passkeyPromptSucceeded &&
    !input.summary.passkeyAuthenticationComplete &&
    !hasAnyEmailOtpSigningEvent(input.summary);
  if (!input.summary.warmSessionClaimed && !usedNoPromptReconnect) {
    throw new Error(
      `${input.label} at ${input.stage} did not claim a warm signing session; observed ${signingAuthSummaryDetails(input.summary)}`,
    );
  }
  if (
    input.summary.passkeyPromptStarted ||
    input.summary.passkeyPromptSucceeded ||
    input.summary.passkeyAuthenticationComplete
  ) {
    throw new Error(`${input.label} at ${input.stage} prompted for passkey before exhaustion`);
  }
  if (hasAnyEmailOtpSigningEvent(input.summary)) {
    throw new Error(`${input.label} at ${input.stage} used Email OTP before exhaustion`);
  }
  if (input.summary.remainingUses.length === 0 && !usedNoPromptReconnect) {
    throw new Error(`${input.label} at ${input.stage} did not report remaining signing uses`);
  }
}

function assertPasskeyStepUpSigningAuth(input: {
  label: string;
  stage: IntendedSigningStage;
  summary: SigningAuthEventSummary;
}): void {
  const performedPasskeyAuth =
    input.summary.passkeyPromptStarted ||
    input.summary.passkeyPromptSucceeded ||
    input.summary.passkeyAuthenticationComplete;
  if (!performedPasskeyAuth) {
    throw new Error(
      `${input.label} at ${input.stage} did not perform passkey step-up; observed ${signingAuthSummaryDetails(input.summary)}`,
    );
  }
  if (hasAnyEmailOtpSigningEvent(input.summary)) {
    throw new Error(`${input.label} at ${input.stage} used Email OTP in a passkey lifecycle`);
  }
}

function assertEmailOtpStepUpSigningAuth(input: {
  label: string;
  stage: IntendedSigningStage;
  summary: SigningAuthEventSummary;
}): void {
  const performedEmailOtpAuth =
    input.summary.emailOtpChallengeSent ||
    input.summary.emailOtpVerifySucceeded ||
    input.summary.emailOtpAuthenticationComplete ||
    input.summary.emailOtpAppSessionExchangeSucceeded;
  if (!performedEmailOtpAuth) {
    throw new Error(
      `${input.label} at ${input.stage} did not perform Email OTP step-up; observed ${signingAuthSummaryDetails(input.summary)}`,
    );
  }
  if (
    input.summary.passkeyPromptStarted ||
    input.summary.passkeyPromptSucceeded ||
    input.summary.passkeyAuthenticationComplete
  ) {
    throw new Error(`${input.label} at ${input.stage} used passkey in an Email OTP lifecycle`);
  }
}

function summarizeKeyExportAuthEvents(snapshot: IntendedPageSnapshot): KeyExportAuthEventSummary {
  const phases: string[] = [];
  let passkeyPromptStarted = false;
  let passkeyPromptSucceeded = false;

  for (const event of snapshot.events) {
    const phase = signingEventPhase(event.payload);
    if (!phase) continue;
    phases.push(phase);
    switch (phase) {
      case KEY_EXPORT_AUTH_PASSKEY_PROMPT_STARTED:
        passkeyPromptStarted = true;
        break;
      case KEY_EXPORT_AUTH_PASSKEY_PROMPT_SUCCEEDED:
        passkeyPromptSucceeded = true;
        break;
      default:
        break;
    }
  }

  return {
    phases,
    passkeyPromptStarted,
    passkeyPromptSucceeded,
  };
}

function assertPasskeyKeyExportAuth(input: {
  label: string;
  summary: KeyExportAuthEventSummary;
  diagnostics: WalletIframeAutoConfirmDiagnostics | null;
}): void {
  if (!input.summary.passkeyPromptStarted || !input.summary.passkeyPromptSucceeded) {
    throw new Error(
      `${input.label} did not require fresh passkey export authorization; observed ${keyExportAuthSummaryDetails(input.summary)}`,
    );
  }
  if (input.diagnostics?.otpFilled) {
    throw new Error(`${input.label} filled Email OTP in a passkey lifecycle`);
  }
}

function assertEmailOtpKeyExportAuth(input: {
  label: string;
  summary: KeyExportAuthEventSummary;
  diagnostics: WalletIframeAutoConfirmDiagnostics | null;
}): void {
  if (input.summary.passkeyPromptStarted || input.summary.passkeyPromptSucceeded) {
    throw new Error(`${input.label} used passkey export authorization in an Email OTP lifecycle`);
  }
  if (!input.diagnostics?.otpFilled) {
    throw new Error(
      `${input.label} did not fill a fresh Email OTP export authorization; diagnostics ${JSON.stringify(input.diagnostics)}`,
    );
  }
}

function keyExportAuthSummaryDetails(summary: KeyExportAuthEventSummary): string {
  return JSON.stringify({
    phases: summary.phases,
    passkeyPromptStarted: summary.passkeyPromptStarted,
    passkeyPromptSucceeded: summary.passkeyPromptSucceeded,
  });
}

function hasAnyEmailOtpSigningEvent(summary: SigningAuthEventSummary): boolean {
  return (
    summary.emailOtpChallengeStarted ||
    summary.emailOtpChallengeSent ||
    summary.emailOtpVerifyStarted ||
    summary.emailOtpVerifySucceeded ||
    summary.emailOtpAuthenticationComplete ||
    summary.emailOtpAppSessionExchangeSucceeded
  );
}

function signingPasskeyPromptCount(summary: SigningAuthEventSummary): number {
  return summary.passkeyPromptStarted ||
    summary.passkeyPromptSucceeded ||
    summary.passkeyAuthenticationComplete
    ? 1
    : 0;
}

function signingEmailOtpVerificationCount(summary: SigningAuthEventSummary): number {
  return hasAnyEmailOtpSigningEvent(summary) ? 1 : 0;
}

function minimumRemainingUse(summary: SigningAuthEventSummary): number | null {
  if (summary.remainingUses.length === 0) return null;
  return Math.min(...summary.remainingUses);
}

function assertConcurrentSharedBudgetExhaustion(summary: SigningAuthEventSummary): void {
  const observed = new Set(summary.remainingUses);
  if (!observed.has(1) || !observed.has(0)) {
    throw new Error(
      `Concurrent Tempo/Arc signing did not consume the final two shared budget uses: ${JSON.stringify(summary.remainingUses)}`,
    );
  }
}

function assertStepUpTransactionConsumedSingleUseBudget(input: {
  label: string;
  summary: SigningAuthEventSummary;
}): void {
  const remainingUses = minimumRemainingUse(input.summary);
  if (remainingUses !== 0) {
    throw new Error(
      `${input.label} did not consume its single-use step-up budget: ${JSON.stringify(input.summary.remainingUses)}`,
    );
  }
}

function signingEventPhase(payload: unknown): string | null {
  if (!isRecord(payload)) return null;
  const phase = payload.phase;
  return typeof phase === 'string' ? phase : null;
}

function signingEventRemainingUses(payload: unknown): number | null {
  if (!isRecord(payload)) return null;
  const data = payload.data;
  if (!isRecord(data)) return null;
  const remainingUses = data.remainingUses;
  if (typeof remainingUses !== 'number' || !Number.isFinite(remainingUses)) return null;
  return remainingUses;
}

function signingAuthenticationCompleteAuthMethod(
  payload: unknown,
  phase: string,
): SigningAuthMethod | null {
  if (phase !== SIGNING_AUTHENTICATION_COMPLETE) return null;
  return eventAuthMethod(payload);
}

function eventAuthMethod(payload: unknown): SigningAuthMethod | null {
  if (!isRecord(payload)) return null;
  const authMethod = payload.authMethod;
  if (authMethod === 'passkey' || authMethod === 'email_otp' || authMethod === 'warm_session') {
    return authMethod;
  }
  return null;
}

function requirePasskeyRegistrationResult(
  snapshot: IntendedPageSnapshot,
  expectedWalletId: string,
): PasskeyRegistrationResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Passkey registration did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'passkey_registration_success') {
    throw new Error(`Passkey registration returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expectedWalletId) {
    throw new Error(`Passkey registration wallet mismatch: ${result.walletId}`);
  }
  if (!result.nearAccountId) {
    throw new Error('Passkey registration result is missing nearAccountId');
  }
  if (!result.nearEd25519SigningKeyId) {
    throw new Error('Passkey registration result is missing nearEd25519SigningKeyId');
  }
  if (!result.operationalPublicKey) {
    throw new Error('Passkey registration result is missing operationalPublicKey');
  }
  return result;
}

function requireEd25519AddSignerResult(
  snapshot: IntendedPageSnapshot,
  expectedWalletId: string,
): Ed25519AddSignerResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Ed25519 add-signer did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'near_ed25519_signer_added') {
    throw new Error(`Ed25519 add-signer returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expectedWalletId) {
    throw new Error(`Ed25519 add-signer wallet mismatch: ${result.walletId}`);
  }
  if (!result.nearAccountId || !result.nearEd25519SigningKeyId || !result.operationalPublicKey) {
    throw new Error('Ed25519 add-signer result is missing signer identity');
  }
  return result;
}

function requireEmailOtpRegistrationResult(
  snapshot: IntendedPageSnapshot,
): EmailOtpRegistrationResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Email OTP registration did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'email_otp_registration_success') {
    throw new Error(`Email OTP registration returned unexpected result kind: ${result.kind}`);
  }
  if (!result.initialWalletId) {
    throw new Error('Email OTP registration result is missing initialWalletId');
  }
  if (!result.walletId) {
    throw new Error('Email OTP registration result is missing walletId');
  }
  if (result.walletId === result.initialWalletId) {
    throw new Error('Email OTP registration did not reroll the initial wallet id');
  }
  if (!result.nearAccountId) {
    throw new Error('Email OTP registration result is missing nearAccountId');
  }
  if (!result.operationalPublicKey) {
    throw new Error('Email OTP registration result is missing operationalPublicKey');
  }
  if (result.signingSessionStatus !== 'active') {
    throw new Error(
      `Email OTP registration signing session is not active: ${result.signingSessionStatus}`,
    );
  }
  return result;
}

function requireNearSigningResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    nearAccountId: string;
  },
): NearSigningResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`NEAR signing did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'near_sign_success') {
    throw new Error(`NEAR signing returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`NEAR signing wallet mismatch: ${result.walletId}`);
  }
  if (result.nearAccountId !== expected.nearAccountId) {
    throw new Error(`NEAR signing account mismatch: ${result.nearAccountId}`);
  }
  if (!result.signedTransactionB64) {
    throw new Error('NEAR signing result is missing signedTransactionB64');
  }
  if (result.signedTransactionByteLength <= 0) {
    throw new Error('NEAR signing result is missing signed transaction bytes');
  }
  return result;
}

function requirePasskeyUnlockResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    nearAccountId: string;
    operationalPublicKey: string;
  },
): PasskeyUnlockResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Passkey unlock did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'passkey_unlock_success') {
    throw new Error(`Passkey unlock returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`Passkey unlock wallet mismatch: ${result.walletId}`);
  }
  if (result.nearAccountId !== expected.nearAccountId) {
    throw new Error(`Passkey unlock NEAR account mismatch: ${result.nearAccountId}`);
  }
  if (result.operationalPublicKey !== expected.operationalPublicKey) {
    throw new Error('Passkey unlock operational public key mismatch');
  }
  if (result.signingSessionStatus !== 'active') {
    throw new Error(`Passkey unlock signing session is not active: ${result.signingSessionStatus}`);
  }
  return result;
}

function requireEmailOtpUnlockResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    nearAccountId: string;
    operationalPublicKey: string;
  } & EcdsaEnabledSnapshot,
): EmailOtpUnlockResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Email OTP unlock did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'email_otp_unlock_success') {
    throw new Error(`Email OTP unlock returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`Email OTP unlock wallet mismatch: ${result.walletId}`);
  }
  if (result.nearAccountId !== expected.nearAccountId) {
    throw new Error(`Email OTP unlock NEAR account mismatch: ${result.nearAccountId}`);
  }
  if (result.operationalPublicKey !== expected.operationalPublicKey) {
    throw new Error('Email OTP unlock operational public key mismatch');
  }
  assertEcdsaEnabledSnapshotsMatch({
    actual: result,
    expected,
    label: 'Email OTP unlock',
  });
  if (result.signingSessionStatus !== 'active') {
    throw new Error(
      `Email OTP unlock signing session is not active: ${result.signingSessionStatus}`,
    );
  }
  return result;
}

function assertEcdsaEnabledSnapshotsMatch(args: {
  actual: EcdsaEnabledSnapshot;
  expected: EcdsaEnabledSnapshot;
  label: string;
}): void {
  if (args.actual.ecdsaTargetProfile !== args.expected.ecdsaTargetProfile) {
    throw new Error(
      `${args.label} ECDSA target profile mismatch: ${args.actual.ecdsaTargetProfile}`,
    );
  }
  switch (args.actual.ecdsaTargetProfile) {
    case 'none':
      return;
    case 'tempo':
      if (args.expected.ecdsaTargetProfile !== 'tempo') {
        throw new Error(`${args.label} ECDSA expected profile mismatch`);
      }
      assertSameEcdsaAddress({
        actual: args.actual.thresholdEcdsaEthereumAddress,
        expected: args.expected.thresholdEcdsaEthereumAddress,
        label: `${args.label} threshold ECDSA address`,
      });
      if (args.actual.thresholdEcdsaPublicKeyB64u !== args.expected.thresholdEcdsaPublicKeyB64u) {
        throw new Error(`${args.label} threshold ECDSA public key mismatch`);
      }
      assertEcdsaTargetKeysMatch({
        actual: args.actual.ecdsaTargetKeys,
        expected: args.expected.ecdsaTargetKeys,
        label: `${args.label} ECDSA target keys`,
      });
      return;
    case 'tempo_arc':
      if (args.expected.ecdsaTargetProfile !== 'tempo_arc') {
        throw new Error(`${args.label} ECDSA expected profile mismatch`);
      }
      assertEcdsaTargetKeysMatch({
        actual: args.actual.ecdsaTargetKeys,
        expected: args.expected.ecdsaTargetKeys,
        label: `${args.label} ECDSA target keys`,
      });
      return;
    default:
      return assertNever(args.actual);
  }
}

function assertEcdsaTargetKeysMatch(args: {
  actual: EcdsaTargetKeysSnapshot;
  expected: EcdsaTargetKeysSnapshot;
  label: string;
}): void {
  if (args.actual.kind !== args.expected.kind) {
    throw new Error(`${args.label} profile mismatch: ${args.actual.kind}`);
  }
  switch (args.actual.kind) {
    case 'none':
      return;
    case 'tempo':
      if (args.expected.kind !== 'tempo') {
        throw new Error(`${args.label} expected profile mismatch`);
      }
      assertEcdsaTargetKeyMatch({
        actual: args.actual.tempo,
        expected: args.expected.tempo,
        label: `${args.label} Tempo`,
      });
      return;
    case 'tempo_arc':
      if (args.expected.kind !== 'tempo_arc') {
        throw new Error(`${args.label} expected profile mismatch`);
      }
      assertEcdsaTargetKeyMatch({
        actual: args.actual.tempo,
        expected: args.expected.tempo,
        label: `${args.label} Tempo`,
      });
      assertEcdsaTargetKeyMatch({
        actual: args.actual.arcEvm,
        expected: args.expected.arcEvm,
        label: `${args.label} Arc/EVM`,
      });
      return;
    default:
      return assertNever(args.actual);
  }
}

function assertEcdsaTargetKeyMatch(args: {
  actual: EcdsaTargetKeySnapshot;
  expected: EcdsaTargetKeySnapshot;
  label: string;
}): void {
  if (args.actual.chain !== args.expected.chain) {
    throw new Error(`${args.label} chain mismatch: ${args.actual.chain}`);
  }
  if (args.actual.chainId !== args.expected.chainId) {
    throw new Error(`${args.label} chainId mismatch: ${args.actual.chainId}`);
  }
  if (
    getAddress(args.actual.thresholdOwnerAddress) !==
    getAddress(args.expected.thresholdOwnerAddress)
  ) {
    throw new Error(`${args.label} threshold owner mismatch`);
  }
}

function requireTempoSigningResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    chainId: number;
  },
): TempoSigningResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Tempo signing did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'tempo_sign_success') {
    throw new Error(`Tempo signing returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`Tempo signing wallet mismatch: ${result.walletId}`);
  }
  if (result.chainId !== expected.chainId) {
    throw new Error(`Tempo signing chainId mismatch: ${result.chainId}`);
  }
  return result;
}

function requireArcEvmSigningResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    chainId: number;
  },
): ArcEvmSigningResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Arc/EVM signing did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'arc_evm_sign_success') {
    throw new Error(`Arc/EVM signing returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`Arc/EVM signing wallet mismatch: ${result.walletId}`);
  }
  if (result.chainId !== expected.chainId) {
    throw new Error(`Arc/EVM signing chainId mismatch: ${result.chainId}`);
  }
  return result;
}

function requireEcdsaExportResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    chainId: number;
  },
): EcdsaExportResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`ECDSA export did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'ecdsa_export_success') {
    throw new Error(`ECDSA export returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`ECDSA export wallet mismatch: ${result.walletId}`);
  }
  if (result.chainId !== expected.chainId) {
    throw new Error(`ECDSA export chainId mismatch: ${result.chainId}`);
  }
  return result;
}

function requireEd25519ExportResult(
  snapshot: IntendedPageSnapshot,
  expected: {
    walletId: string;
    nearAccountId: string;
  },
): Ed25519ExportResultSnapshot {
  if (snapshot.action.status !== 'success') {
    throw new Error(`Ed25519 export did not succeed: ${snapshot.action.status}`);
  }
  const result = snapshot.action.result;
  if (result.kind !== 'ed25519_export_success') {
    throw new Error(`Ed25519 export returned unexpected result kind: ${result.kind}`);
  }
  if (result.walletId !== expected.walletId) {
    throw new Error(`Ed25519 export wallet mismatch: ${result.walletId}`);
  }
  if (result.nearAccountId !== expected.nearAccountId) {
    throw new Error(`Ed25519 export NEAR account mismatch: ${result.nearAccountId}`);
  }
  return result;
}

async function verifyNearEd25519Signature(args: {
  registration: RegisteredWalletSnapshot;
  result: NearSigningResultSnapshot;
}): Promise<void> {
  const registeredPublicKey = parseNearEd25519PublicKey(args.registration.operationalPublicKey);
  const signedTransaction = decodeNearSignedTransactionB64(args.result.signedTransactionB64);
  const decodedLength = signedTransaction.unsignedTransactionBytes.length + 65;
  if (decodedLength !== args.result.signedTransactionByteLength) {
    throw new Error(
      `NEAR signed transaction length mismatch: decoded=${decodedLength} reported=${args.result.signedTransactionByteLength}`,
    );
  }
  if (signedTransaction.signatureKeyType !== 0) {
    throw new Error(
      `NEAR signature key type must be Ed25519, received ${signedTransaction.signatureKeyType}`,
    );
  }
  const subject = parseNearUnsignedTransactionSubject(signedTransaction.unsignedTransactionBytes);
  if (subject.signerId !== args.result.nearAccountId) {
    throw new Error(`NEAR transaction signer mismatch: ${subject.signerId}`);
  }
  if (subject.publicKey.keyType !== 0) {
    throw new Error(
      `NEAR transaction public key type must be Ed25519, received ${subject.publicKey.keyType}`,
    );
  }
  assertEqualBytes(
    subject.publicKey.keyData32,
    registeredPublicKey.keyData32,
    'NEAR transaction public key does not match registered wallet key',
  );
  const signedMessageHash = sha256Bytes(signedTransaction.unsignedTransactionBytes);
  const verified = await ed25519.verifyAsync(
    signedTransaction.signatureBytes64,
    signedMessageHash,
    registeredPublicKey.keyData32,
  );
  if (!verified) {
    throw new Error('NEAR Ed25519 signature verification failed');
  }
}

async function verifyTempoEcdsaSignature(args: {
  registration: RegisteredWalletSnapshot;
  result: TempoSigningResultSnapshot;
}): Promise<void> {
  const targetKey = requireTempoEcdsaTargetKey(args.registration.ecdsaTargetKeys);
  const parts = decodeTempoSignedTransaction(args.result.rawTxHex);
  if (parts.chainId !== args.result.chainId) {
    throw new Error(`Tempo raw transaction chainId mismatch: ${parts.chainId}`);
  }
  const recovered = await recoverAddress({
    hash: args.result.senderHashHex,
    signature: parts.senderSignatureHex,
  });
  assertSameEcdsaAddress({
    actual: recovered,
    expected: targetKey.thresholdOwnerAddress,
    label: 'Tempo recovered signer',
  });
}

async function verifyArcEvmSignature(args: {
  registration: RegisteredWalletSnapshot;
  result: ArcEvmSigningResultSnapshot;
}): Promise<void> {
  const targetKey = requireArcEvmEcdsaTargetKey(args.registration.ecdsaTargetKeys);
  const transaction = parseTransaction(args.result.rawTxHex);
  if (Number(transaction.chainId) !== args.result.chainId) {
    throw new Error(`Arc/EVM raw transaction chainId mismatch: ${String(transaction.chainId)}`);
  }
  const recovered = await recoverTransactionAddress({
    serializedTransaction: serializeTransaction(transaction),
  });
  assertSameEcdsaAddress({
    actual: recovered,
    expected: targetKey.thresholdOwnerAddress,
    label: 'Arc/EVM recovered signer',
  });
}

function requireTempoEcdsaTargetKey(keys: EcdsaTargetKeysSnapshot): EcdsaTargetKeySnapshot {
  switch (keys.kind) {
    case 'tempo':
    case 'tempo_arc':
      return keys.tempo;
    case 'none':
      throw new Error('Tempo signing requires a Tempo ECDSA target key');
    default:
      return assertNever(keys);
  }
}

function requireArcEvmEcdsaTargetKey(keys: EcdsaTargetKeysSnapshot): EcdsaTargetKeySnapshot {
  switch (keys.kind) {
    case 'tempo_arc':
      return keys.arcEvm;
    case 'none':
    case 'tempo':
      throw new Error('Arc/EVM signing requires an Arc/EVM ECDSA target key');
    default:
      return assertNever(keys);
  }
}

function parseNearEd25519PublicKey(publicKey: string): { keyData32: Uint8Array } {
  const value = publicKey.trim();
  const prefix = 'ed25519:';
  if (!value.startsWith(prefix)) {
    throw new Error(`NEAR operational public key must use ed25519 prefix: ${value}`);
  }
  const keyData32 = base58Decode(value.slice(prefix.length));
  if (keyData32.length !== 32) {
    throw new Error(
      `NEAR operational public key must decode to 32 bytes, received ${keyData32.length}`,
    );
  }
  return { keyData32 };
}

function decodeNearSignedTransactionB64(base64: string): NearSignedTransactionParts {
  const bytes = Buffer.from(base64, 'base64');
  if (bytes.length <= 65) {
    throw new Error(`NEAR signed transaction is too short: ${bytes.length} bytes`);
  }
  const signatureStart = bytes.length - 65;
  return {
    unsignedTransactionBytes: bytes.slice(0, signatureStart),
    signatureKeyType: bytes[signatureStart],
    signatureBytes64: bytes.slice(signatureStart + 1),
  };
}

function parseNearUnsignedTransactionSubject(bytes: Uint8Array): NearUnsignedTransactionSubject {
  const signer = readBorshString(bytes, 0, 'NEAR transaction signerId');
  const publicKey = readNearPublicKey(bytes, signer.nextOffset);
  return {
    signerId: signer.value,
    publicKey: publicKey.value,
  };
}

function readNearPublicKey(
  bytes: Uint8Array,
  offset: number,
): BorshReadResult<NearUnsignedTransactionSubject['publicKey']> {
  requireByteRange(bytes, offset, 33, 'NEAR transaction publicKey');
  return {
    value: {
      keyType: bytes[offset],
      keyData32: bytes.slice(offset + 1, offset + 33),
    },
    nextOffset: offset + 33,
  };
}

function readBorshString(
  bytes: Uint8Array,
  offset: number,
  label: string,
): BorshReadResult<string> {
  const length = readBorshU32(bytes, offset, `${label} length`);
  const valueStart = offset + 4;
  requireByteRange(bytes, valueStart, length, label);
  return {
    value: new TextDecoder().decode(bytes.slice(valueStart, valueStart + length)),
    nextOffset: valueStart + length,
  };
}

function readBorshU32(bytes: Uint8Array, offset: number, label: string): number {
  requireByteRange(bytes, offset, 4, label);
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 4);
  return view.getUint32(0, true);
}

function requireByteRange(bytes: Uint8Array, offset: number, length: number, label: string): void {
  if (offset < 0 || length < 0 || offset + length > bytes.length) {
    throw new Error(`${label} exceeds byte length ${bytes.length}`);
  }
}

function sha256Bytes(bytes: Uint8Array): Uint8Array {
  return createHash('sha256').update(bytes).digest();
}

function assertEqualBytes(actual: Uint8Array, expected: Uint8Array, message: string): void {
  if (actual.length !== expected.length) {
    throw new Error(`${message}: length ${actual.length} !== ${expected.length}`);
  }
  for (let index = 0; index < actual.length; index += 1) {
    if (actual[index] === expected[index]) continue;
    throw new Error(`${message}: byte ${index} differs`);
  }
}

function assertSameEcdsaAddress(args: { actual: string; expected: string; label: string }): void {
  const actual = getAddress(args.actual);
  const expected = getAddress(args.expected);
  if (actual !== expected) {
    throw new Error(`${args.label} mismatch: ${actual} !== ${expected}`);
  }
}

function decodeTempoSignedTransaction(rawTxHex: `0x${string}`): TempoSignedTransactionParts {
  const bytes = hexToBytes(rawTxHex);
  if (bytes[0] !== TEMPO_TRANSACTION_TYPE) {
    throw new Error(`Tempo raw transaction must start with type 0x76, received ${bytes[0]}`);
  }
  const decoded = readRlpValue(bytes, 1);
  if (decoded.nextOffset !== bytes.length) {
    throw new Error('Tempo raw transaction has trailing bytes after RLP payload');
  }
  if (decoded.value.kind !== 'list') {
    throw new Error('Tempo raw transaction payload must be an RLP list');
  }
  const fields = decoded.value.items;
  if (fields.length !== 14) {
    throw new Error(`Tempo raw transaction must contain 14 fields, received ${fields.length}`);
  }
  const chainId = rlpBytesToSafeInteger(requireRlpBytes(fields[0], 'Tempo chainId'));
  requireEmptyRlpList(fields[12], 'Tempo AA authorization list');
  const signatureBytes = requireRlpBytes(fields[13], 'Tempo sender signature');
  if (signatureBytes.length !== 65) {
    throw new Error(`Tempo sender signature must be 65 bytes, received ${signatureBytes.length}`);
  }
  return {
    chainId,
    senderSignatureHex: bytesToHex(signatureBytes),
  };
}

function readRlpValue(bytes: Uint8Array, offset: number): RlpReadResult {
  requireByteRange(bytes, offset, 1, 'RLP prefix');
  const prefix = bytes[offset];
  if (prefix <= 0x7f) {
    return {
      value: { kind: 'bytes', bytes: bytes.slice(offset, offset + 1) },
      nextOffset: offset + 1,
    };
  }
  if (prefix <= 0xb7) {
    const length = prefix - 0x80;
    return readRlpShortBytes(bytes, offset + 1, length);
  }
  if (prefix <= 0xbf) {
    const lengthOfLength = prefix - 0xb7;
    const length = readRlpLength(bytes, offset + 1, lengthOfLength, 'RLP long bytes');
    return readRlpShortBytes(bytes, offset + 1 + lengthOfLength, length);
  }
  if (prefix <= 0xf7) {
    const length = prefix - 0xc0;
    return readRlpList(bytes, offset + 1, length);
  }
  const lengthOfLength = prefix - 0xf7;
  const length = readRlpLength(bytes, offset + 1, lengthOfLength, 'RLP long list');
  return readRlpList(bytes, offset + 1 + lengthOfLength, length);
}

function readRlpShortBytes(bytes: Uint8Array, offset: number, length: number): RlpReadResult {
  requireByteRange(bytes, offset, length, 'RLP bytes');
  return {
    value: { kind: 'bytes', bytes: bytes.slice(offset, offset + length) },
    nextOffset: offset + length,
  };
}

function readRlpList(bytes: Uint8Array, offset: number, length: number): RlpReadResult {
  requireByteRange(bytes, offset, length, 'RLP list');
  const endOffset = offset + length;
  const items: RlpValue[] = [];
  let cursor = offset;
  while (cursor < endOffset) {
    const item = readRlpValue(bytes, cursor);
    items.push(item.value);
    cursor = item.nextOffset;
  }
  if (cursor !== endOffset) {
    throw new Error('RLP list item exceeded declared length');
  }
  return {
    value: { kind: 'list', items },
    nextOffset: endOffset,
  };
}

function readRlpLength(
  bytes: Uint8Array,
  offset: number,
  lengthOfLength: number,
  label: string,
): number {
  requireByteRange(bytes, offset, lengthOfLength, label);
  let value = 0;
  for (let index = 0; index < lengthOfLength; index += 1) {
    value = value * 256 + bytes[offset + index];
  }
  if (!Number.isSafeInteger(value)) {
    throw new Error(`${label} is too large`);
  }
  return value;
}

function requireRlpBytes(value: RlpValue | undefined, label: string): Uint8Array {
  if (!value || value.kind !== 'bytes') {
    throw new Error(`${label} must be RLP bytes`);
  }
  return value.bytes;
}

function requireEmptyRlpList(value: RlpValue | undefined, label: string): void {
  if (!value || value.kind !== 'list' || value.items.length !== 0) {
    throw new Error(`${label} must be an empty RLP list`);
  }
}

function rlpBytesToSafeInteger(bytes: Uint8Array): number {
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
  }
  if (!Number.isSafeInteger(value)) {
    throw new Error('RLP integer is too large');
  }
  return value;
}

function hexToBytes(hex: `0x${string}`): Uint8Array {
  const raw = hex.slice(2);
  if (raw.length % 2 !== 0) {
    throw new Error('hex string must have even length');
  }
  const bytes = new Uint8Array(raw.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    const value = Number.parseInt(raw.slice(index * 2, index * 2 + 2), 16);
    if (!Number.isFinite(value)) {
      throw new Error('hex string contains invalid bytes');
    }
    bytes[index] = value;
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`;
}

async function readIntendedPageSnapshot(page: Page): Promise<IntendedPageSnapshot> {
  const text = await page.getByTestId('intended-result-json').textContent();
  if (!text) throw new Error('Intended page snapshot is empty');
  return parseIntendedPageSnapshot(JSON.parse(text));
}

function parseIntendedConcurrentActionSnapshots(rawSnapshots: readonly unknown[]): IntendedPageSnapshot[] {
  const snapshots: IntendedPageSnapshot[] = [];
  for (const raw of rawSnapshots) {
    snapshots.push(parseIntendedPageSnapshot(raw));
  }
  return snapshots;
}

function requireConcurrentSigningSuccess(
  snapshots: readonly IntendedPageSnapshot[],
  action: 'signTempoTransaction' | 'signArcEvmTransaction',
): IntendedPageSnapshot {
  let success: IntendedPageSnapshot | null = null;
  for (const snapshot of snapshots) {
    if (snapshot.action.status === 'error' && snapshot.action.action === action) {
      throw new Error(`Concurrent ${action} failed: ${snapshot.action.error}`);
    }
    if (snapshot.action.status === 'success' && snapshot.action.action === action) {
      success = snapshot;
    }
  }
  if (success) return success;
  throw new Error(`Concurrent ${action} did not produce a success result`);
}

function snapshotWithMostLifecycleEvents(
  left: IntendedPageSnapshot,
  right: IntendedPageSnapshot,
): IntendedPageSnapshot {
  return left.events.length >= right.events.length ? left : right;
}

function parseIntendedPageSnapshot(raw: unknown): IntendedPageSnapshot {
  const record = requireRecord(raw, 'intended page snapshot');
  return {
    action: parseIntendedPageActionSnapshot(record.action),
    events: parseIntendedPageLifecycleEvents(record.events),
  };
}

function parseIntendedPageLifecycleEvents(raw: unknown): readonly IntendedPageLifecycleEvent[] {
  if (!Array.isArray(raw)) {
    throw new Error('intended page snapshot events must be an array');
  }
  return raw.map(parseIntendedPageLifecycleEvent);
}

function parseIntendedPageLifecycleEvent(raw: unknown): IntendedPageLifecycleEvent {
  const record = requireRecord(raw, 'intended page lifecycle event');
  const index = Number(record.index);
  if (!Number.isInteger(index) || index < 0) {
    throw new Error('intended page lifecycle event index must be a non-negative integer');
  }
  return {
    index,
    payload: record.payload,
  };
}

function parseIntendedPageActionSnapshot(raw: unknown): IntendedPageActionSnapshot {
  const record = requireRecord(raw, 'intended page action');
  const status = requireString(record.status, 'intended page action status');
  switch (status) {
    case 'idle':
      return { status };
    case 'running':
      return { status, action: parseIntendedHarnessAction(record.action) };
    case 'success':
      return {
        status,
        action: parseIntendedHarnessAction(record.action),
        result: parseIntendedActionResultSnapshot(record.result),
      };
    case 'error':
      return {
        status,
        action: parseIntendedHarnessAction(record.action),
        error: requireString(record.error, 'intended page action error'),
      };
    default:
      throw new Error(`Unknown intended page action status: ${status}`);
  }
}

function parseIntendedActionResultSnapshot(raw: unknown): IntendedActionResultSnapshot {
  const record = requireRecord(raw, 'intended action result');
  const kind = requireString(record.kind, 'intended action result kind');
  switch (kind) {
    case 'passkey_registration_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'passkey registration walletId'),
        nearAccountId: requireString(record.nearAccountId, 'passkey registration nearAccountId'),
        nearEd25519SigningKeyId: requireString(
          record.nearEd25519SigningKeyId,
          'passkey registration nearEd25519SigningKeyId',
        ),
        operationalPublicKey: requireString(
          record.operationalPublicKey,
          'passkey registration operationalPublicKey',
        ),
        ...parseEcdsaEnabledSnapshot(record, 'passkey registration'),
      };
    case 'near_ed25519_signer_added':
      return {
        kind,
        walletId: requireString(record.walletId, 'Ed25519 add-signer walletId'),
        nearAccountId: requireString(record.nearAccountId, 'Ed25519 add-signer nearAccountId'),
        nearEd25519SigningKeyId: requireString(
          record.nearEd25519SigningKeyId,
          'Ed25519 add-signer nearEd25519SigningKeyId',
        ),
        operationalPublicKey: requireString(
          record.operationalPublicKey,
          'Ed25519 add-signer operationalPublicKey',
        ),
      };
    case 'near_sign_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'NEAR signing walletId'),
        nearAccountId: requireString(record.nearAccountId, 'NEAR signing nearAccountId'),
        signedTransactionB64: requireString(
          record.signedTransactionB64,
          'NEAR signing signedTransactionB64',
        ),
        signedTransactionByteLength: requirePositiveInteger(
          record.signedTransactionByteLength,
          'NEAR signing signedTransactionByteLength',
        ),
      };
    case 'email_otp_registration_success':
      return {
        kind,
        initialWalletId: requireString(
          record.initialWalletId,
          'Email OTP registration initialWalletId',
        ),
        walletId: requireString(record.walletId, 'Email OTP registration walletId'),
        nearAccountId: requireString(record.nearAccountId, 'Email OTP registration nearAccountId'),
        operationalPublicKey: requireString(
          record.operationalPublicKey,
          'Email OTP registration operationalPublicKey',
        ),
        signingSessionStatus: requireString(
          record.signingSessionStatus,
          'Email OTP registration signingSessionStatus',
        ),
        remainingUses: nullableNumber(record.remainingUses, 'Email OTP registration remainingUses'),
        ...parseEcdsaEnabledSnapshot(record, 'Email OTP registration'),
      };
    case 'passkey_unlock_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'passkey unlock walletId'),
        nearAccountId: requireString(record.nearAccountId, 'passkey unlock nearAccountId'),
        operationalPublicKey: requireString(
          record.operationalPublicKey,
          'passkey unlock operationalPublicKey',
        ),
        signingSessionStatus: requireString(
          record.signingSessionStatus,
          'passkey unlock signingSessionStatus',
        ),
        remainingUses: nullableNumber(record.remainingUses, 'passkey unlock remainingUses'),
      };
    case 'email_otp_unlock_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'Email OTP unlock walletId'),
        nearAccountId: requireString(record.nearAccountId, 'Email OTP unlock nearAccountId'),
        operationalPublicKey: requireString(
          record.operationalPublicKey,
          'Email OTP unlock operationalPublicKey',
        ),
        signingSessionStatus: requireString(
          record.signingSessionStatus,
          'Email OTP unlock signingSessionStatus',
        ),
        remainingUses: nullableNumber(record.remainingUses, 'Email OTP unlock remainingUses'),
        ...parseEcdsaEnabledSnapshot(record, 'Email OTP unlock'),
      };
    case 'tempo_sign_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'Tempo signing walletId'),
        chainId: requirePositiveInteger(record.chainId, 'Tempo signing chainId'),
        senderHashHex: requireHexString(record.senderHashHex, 'Tempo signing senderHashHex'),
        rawTxHex: requireHexString(record.rawTxHex, 'Tempo signing rawTxHex'),
      };
    case 'arc_evm_sign_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'Arc/EVM signing walletId'),
        chainId: requirePositiveInteger(record.chainId, 'Arc/EVM signing chainId'),
        txHashHex: requireHexString(record.txHashHex, 'Arc/EVM signing txHashHex'),
        rawTxHex: requireHexString(record.rawTxHex, 'Arc/EVM signing rawTxHex'),
      };
    case 'ecdsa_export_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'ECDSA export walletId'),
        chainId: requirePositiveInteger(record.chainId, 'ECDSA export chainId'),
      };
    case 'ed25519_export_success':
      return {
        kind,
        walletId: requireString(record.walletId, 'Ed25519 export walletId'),
        nearAccountId: requireString(record.nearAccountId, 'Ed25519 export nearAccountId'),
      };
    default:
      throw new Error(`Unknown intended action result kind: ${kind}`);
  }
}

function parseEcdsaEnabledSnapshot(
  raw: Record<string, unknown>,
  label: string,
): EcdsaEnabledSnapshot {
  const profile = parseEcdsaTargetProfileName(recordValue(raw, 'ecdsaTargetProfile'), label);
  const ecdsaTargetKeys = parseEcdsaTargetKeys(raw.ecdsaTargetKeys, label);
  switch (profile) {
    case 'none':
      if (ecdsaTargetKeys.kind !== 'none') {
        throw new Error(`${label} ECDSA target key profile mismatch: ${ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'none',
        ecdsaTargetKeys,
      };
    case 'tempo':
      if (ecdsaTargetKeys.kind !== 'tempo') {
        throw new Error(`${label} ECDSA target key profile mismatch: ${ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'tempo',
        thresholdEcdsaEthereumAddress: requireString(
          raw.thresholdEcdsaEthereumAddress,
          `${label} thresholdEcdsaEthereumAddress`,
        ),
        thresholdEcdsaPublicKeyB64u: requireString(
          raw.thresholdEcdsaPublicKeyB64u,
          `${label} thresholdEcdsaPublicKeyB64u`,
        ),
        ecdsaTargetKeys,
      };
    case 'tempo_arc':
      if (ecdsaTargetKeys.kind !== 'tempo_arc') {
        throw new Error(`${label} ECDSA target key profile mismatch: ${ecdsaTargetKeys.kind}`);
      }
      return {
        ecdsaTargetProfile: 'tempo_arc',
        ecdsaTargetKeys,
      };
    default:
      return assertNever(profile);
  }
}

function parseEcdsaTargetProfileName(raw: unknown, label: string): EcdsaTargetProfileName {
  const value = requireString(raw, `${label} ecdsaTargetProfile`);
  switch (value) {
    case 'none':
    case 'tempo':
    case 'tempo_arc':
      return value;
    default:
      throw new Error(`${label} ecdsaTargetProfile is invalid: ${value}`);
  }
}

function recordValue(record: Record<string, unknown>, key: string): unknown {
  return record[key];
}

function parseEcdsaTargetKeys(raw: unknown, label: string): EcdsaTargetKeysSnapshot {
  const record = requireRecord(raw, `${label} ECDSA target keys`);
  const kind = parseEcdsaTargetProfileName(record.kind, `${label} ECDSA target keys`);
  switch (kind) {
    case 'none':
      return { kind: 'none' };
    case 'tempo':
      return {
        kind: 'tempo',
        tempo: parseEcdsaTargetKey(record.tempo, 'tempo', `${label} Tempo ECDSA target key`),
      };
    case 'tempo_arc':
      return {
        kind: 'tempo_arc',
        tempo: parseEcdsaTargetKey(record.tempo, 'tempo', `${label} Tempo ECDSA target key`),
        arcEvm: parseEcdsaTargetKey(record.arcEvm, 'arc_evm', `${label} Arc/EVM ECDSA target key`),
      };
    default:
      return assertNever(kind);
  }
}

function parseEcdsaTargetKey(
  raw: unknown,
  expectedChain: EcdsaTargetKeySnapshot['chain'],
  label: string,
): EcdsaTargetKeySnapshot {
  const record = requireRecord(raw, label);
  const chain = requireString(record.chain, `${label} chain`);
  if (chain !== expectedChain) {
    throw new Error(`${label} chain mismatch: ${chain}`);
  }
  return {
    chain: expectedChain,
    chainId: requirePositiveInteger(record.chainId, `${label} chainId`),
    thresholdOwnerAddress: getAddress(
      requireString(record.thresholdOwnerAddress, `${label} thresholdOwnerAddress`),
    ),
  };
}

function parseIntendedHarnessAction(raw: unknown): IntendedHarnessAction {
  const action = requireString(raw, 'intended action');
  switch (action) {
    case 'registerPasskeyWallet':
    case 'registerPasskeyEd25519YaoWallet':
    case 'registerPreparedIframePasskeyEd25519YaoWallet':
    case 'addPasskeyEd25519YaoWalletSigner':
    case 'registerEmailOtpWallet':
    case 'unlockPasskeyWallet':
    case 'unlockEmailOtpWallet':
    case 'signNearTransaction':
    case 'signTempoTransaction':
    case 'signArcEvmTransaction':
    case 'exportEd25519Key':
    case 'exportEcdsaKey':
      return action;
    default:
      throw new Error(`Unknown intended action: ${action}`);
  }
}

function routerAbEd25519SigningPath(
  rawUrl: string | undefined,
  routerUrl: string,
): (typeof ROUTER_AB_ED25519_SIGNING_PATHS)[number] | null {
  if (!rawUrl) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.origin !== new URL(routerUrl).origin) return null;
  for (const path of ROUTER_AB_ED25519_SIGNING_PATHS) {
    if (url.pathname === path) return path;
  }
  return null;
}

function routerAbEd25519YaoRegistrationPath(
  rawUrl: string | undefined,
  routerUrl: string,
): (typeof ROUTER_AB_ED25519_YAO_REGISTRATION_PATHS)[number] | null {
  if (!rawUrl) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.origin !== new URL(routerUrl).origin) return null;
  for (const path of ROUTER_AB_ED25519_YAO_REGISTRATION_PATHS) {
    if (url.pathname === path) return path;
  }
  return null;
}

function routerAbEd25519YaoRecoveryPath(
  rawUrl: string | undefined,
  routerUrl: string,
): (typeof ROUTER_AB_ED25519_YAO_RECOVERY_PATHS)[number] | null {
  if (!rawUrl) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.origin !== new URL(routerUrl).origin) return null;
  for (const path of ROUTER_AB_ED25519_YAO_RECOVERY_PATHS) {
    if (url.pathname === path) return path;
  }
  return null;
}

function routerAbEd25519YaoWarmRecoveryPath(
  rawUrl: string | undefined,
  routerUrl: string,
): (typeof ROUTER_AB_ED25519_YAO_WARM_RECOVERY_PATHS)[number] | null {
  if (!rawUrl) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.origin !== new URL(routerUrl).origin) return null;
  for (const path of ROUTER_AB_ED25519_YAO_WARM_RECOVERY_PATHS) {
    if (url.pathname === path) return path;
  }
  return null;
}

function routerAbEd25519YaoExportPath(
  rawUrl: string | undefined,
  routerUrl: string,
): (typeof ROUTER_AB_ED25519_YAO_EXPORT_PATHS)[number] | null {
  if (!rawUrl) return null;
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.origin !== new URL(routerUrl).origin) return null;
  for (const path of ROUTER_AB_ED25519_YAO_EXPORT_PATHS) {
    if (url.pathname === path) return path;
  }
  return null;
}

function requireRecord(raw: unknown, label: string): Record<string, unknown> {
  if (!isRecord(raw)) {
    throw new Error(`${label} must be an object`);
  }
  return raw;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return !!raw && typeof raw === 'object' && !Array.isArray(raw);
}

function requireString(raw: unknown, label: string): string {
  if (typeof raw !== 'string') {
    throw new Error(`${label} must be a string`);
  }
  const value = raw.trim();
  if (!value) {
    throw new Error(`${label} must be non-empty`);
  }
  return value;
}

function requireHexString(raw: unknown, label: string): `0x${string}` {
  const value = requireString(raw, label);
  if (!/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new Error(`${label} must be 0x-prefixed hex`);
  }
  return value as `0x${string}`;
}

function nullableNumber(raw: unknown, label: string): number | null {
  if (raw === null) return null;
  if (typeof raw !== 'number' || !Number.isFinite(raw)) {
    throw new Error(`${label} must be a finite number or null`);
  }
  return raw;
}

function requirePositiveInteger(raw: unknown, label: string): number {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function assertNever(value: never): never {
  throw new Error(`Unexpected intended e2e value: ${String(value)}`);
}

function recordAutoConfirmMark(
  diagnostics: WalletIframeAutoConfirmDiagnostics | undefined,
  startedAtMs: number | undefined,
  key: WalletIframeAutoConfirmTimingKey,
  valueMs?: number,
): void {
  if (!diagnostics || startedAtMs == null) return;
  if (diagnostics[key] != null) return;
  diagnostics[key] = Math.max(0, Math.round(valueMs ?? Date.now() - startedAtMs));
}

async function fillWalletIframeEmailOtpIfAvailable(
  page: Page,
  frame: FrameLocator,
  opts?: {
    timeoutMs?: number;
    diagnostics?: WalletIframeAutoConfirmDiagnostics;
    diagnosticsStartedAtMs?: number;
  },
): Promise<boolean> {
  const timeoutMs = Math.max(50, Math.floor(opts?.timeoutMs ?? 500));
  const input = frame.locator('#email-otp-confirm-code, #drawer-email-otp-confirm-code').first();
  const visible = await input
    .waitFor({ state: 'visible', timeout: timeoutMs })
    .then(() => true)
    .catch(() => false);
  if (!visible) return false;
  recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstOtpInputVisibleMs');
  let challengeId: string | null = null;
  try {
    challengeId = await input.evaluate(readWalletIframeEmailOtpChallengeId);
  } catch (error) {
    if (opts?.diagnostics) {
      opts.diagnostics.lastOtpError = `challenge probe failed: ${compactUnknownErrorForDiagnostics(error)}`;
    }
  }
  const walletId = await page.getByTestId('intended-e2e-page').getAttribute('data-wallet-id');
  if (!walletId) {
    throw new Error('Email OTP auto-confirm requires current intended wallet id');
  }
  const otpLookup: IntendedEmailOtpCodeRequestForPage = challengeId
    ? {
        kind: 'challenge',
        challengeId,
        walletId,
      }
    : {
        kind: 'latest_for_wallet',
        walletId,
      };
  if (opts?.diagnostics) {
    opts.diagnostics.otpLookupKind = otpLookup.kind;
  }
  let otpCode: string;
  try {
    otpCode = await page.evaluate(readIntendedEmailOtpCodeFromPage, otpLookup);
  } catch (error) {
    if (opts?.diagnostics) {
      opts.diagnostics.lastOtpError = compactUnknownErrorForDiagnostics(error);
    }
    return false;
  }
  if (!challengeId && opts?.diagnostics) {
    opts.diagnostics.otpChallengeMissing = true;
  }
  recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstOtpCodeResolvedMs');
  try {
    await input.fill(otpCode, { timeout: timeoutMs });
  } catch (error) {
    if (opts?.diagnostics) {
      opts.diagnostics.lastOtpError = compactUnknownErrorForDiagnostics(error);
    }
    return false;
  }
  if (opts?.diagnostics) {
    opts.diagnostics.otpFilled = true;
  }
  recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstOtpFillDispatchMs');
  return true;
}

function compactUnknownErrorForDiagnostics(error: unknown): string {
  const text = error instanceof Error ? error.message || String(error) : String(error || '');
  return text.replace(/\s+/g, ' ').slice(0, 300);
}

function readWalletIframeEmailOtpChallengeId(anchor: Element): string | null {
  const roots: Array<Document | ShadowRoot> = [anchor.ownerDocument];
  for (let rootIndex = 0; rootIndex < roots.length; rootIndex += 1) {
    const root = roots[rootIndex];
    const elements = Array.from(root.querySelectorAll('*'));
    for (const element of elements) {
      const promptElement = element as HTMLElement & {
        emailOtpPrompt?: { challengeId?: unknown };
      };
      const challengeId = String(promptElement.emailOtpPrompt?.challengeId || '').trim();
      if (challengeId) return challengeId;
      const shadowRoot = (element as HTMLElement).shadowRoot;
      if (shadowRoot) {
        roots.push(shadowRoot);
      }
    }
  }
  return null;
}

async function readIntendedEmailOtpCodeFromPage(
  input: IntendedEmailOtpCodeRequestForPage,
): Promise<string> {
  const reader = window.__seamsIntendedE2EReadEmailOtpCode;
  if (typeof reader !== 'function') {
    throw new Error('Intended page Email OTP reader is not installed');
  }
  const otpCode = String(await reader(input)).trim();
  if (!/^\d{6}$/.test(otpCode)) {
    throw new Error('Intended page Email OTP reader returned an invalid OTP code');
  }
  return otpCode;
}

async function clickWalletIframeConfirm(
  page: Page,
  opts?: {
    timeoutMs?: number;
    diagnostics?: WalletIframeAutoConfirmDiagnostics;
    diagnosticsStartedAtMs?: number;
  },
): Promise<boolean> {
  const timeoutMs = Math.max(50, Math.floor(opts?.timeoutMs ?? 15_000));
  if (opts?.diagnostics) {
    opts.diagnostics.attempts += 1;
  }
  try {
    const iframeEl = page.locator('iframe[allow*="publickey-credentials-get"]').last();
    const attached = await iframeEl
      .waitFor({ state: 'attached', timeout: timeoutMs })
      .then(() => true)
      .catch(() => false);
    if (!attached) return false;
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstIframeAttachedMs');
    const frame = iframeEl.contentFrame();
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstFrameResolvedMs');

    const otpFilled = await fillWalletIframeEmailOtpIfAvailable(page, frame, {
      timeoutMs: Math.min(500, timeoutMs),
      diagnostics: opts?.diagnostics,
      diagnosticsStartedAtMs: opts?.diagnosticsStartedAtMs,
    });
    if (otpFilled) return true;

    const confirmBtn = frame
      .locator(
        [
          '[data-seams-registration-activation-start="true"]',
          '#w3a-confirm-portal button.btn-confirm',
          '#w3a-confirm-portal button.confirm',
        ].join(', '),
      )
      .first();
    await confirmBtn.waitFor({ state: 'visible', timeout: timeoutMs });
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstButtonVisibleMs');
    const clickStartedAtMs = Date.now();
    await confirmBtn.click({ timeout: timeoutMs });
    if (opts?.diagnostics) {
      opts.diagnostics.clicked = true;
    }
    recordAutoConfirmMark(opts?.diagnostics, opts?.diagnosticsStartedAtMs, 'firstClickDispatchMs');
    recordAutoConfirmMark(
      opts?.diagnostics,
      opts?.diagnosticsStartedAtMs,
      'firstClickDurationMs',
      Date.now() - clickStartedAtMs,
    );
    return true;
  } catch {
    return false;
  }
}

async function closeExportViewerFrameButton(page: Page): Promise<boolean> {
  for (const frame of page.frames()) {
    const closeButton = frame.getByRole('button', { name: 'Close' }).first();
    const visible = await closeButton
      .waitFor({ state: 'visible', timeout: 500 })
      .then(() => true)
      .catch(() => false);
    if (!visible) continue;
    await closeButton.click({ timeout: 2_000 });
    return true;
  }
  return false;
}

async function autoConfirmWalletIframeUntil<T>(
  page: Page,
  task: Promise<T>,
  opts?: {
    timeoutMs?: number;
    intervalMs?: number;
    retryDelayMs?: number;
    stopAfterClick?: boolean;
    diagnostics?: WalletIframeAutoConfirmDiagnostics;
  },
): Promise<T> {
  const timeoutMs = Math.max(250, Math.floor(opts?.timeoutMs ?? 55_000));
  const intervalMs = Math.max(50, Math.floor(opts?.intervalMs ?? 250));
  const retryDelayMs = Math.max(0, Math.floor(opts?.retryDelayMs ?? intervalMs));
  const stopAfterClick = opts?.stopAfterClick === true;
  let done = false;
  const startedAtMs = Date.now();
  const diagnostics = opts?.diagnostics;
  if (diagnostics) {
    diagnostics.attempts = 0;
    diagnostics.clicked = false;
  }

  const loop = runWalletIframeAutoConfirmLoop({
    page,
    timeoutMs,
    intervalMs,
    retryDelayMs,
    stopAfterClick,
    diagnostics,
    startedAtMs,
    isDone: () => done,
  });

  try {
    return await task;
  } finally {
    done = true;
    if (diagnostics) {
      diagnostics.totalMs = Math.max(0, Math.round(Date.now() - startedAtMs));
    }
    await loop.catch(() => undefined);
  }
}

async function runWalletIframeAutoConfirmLoop(args: {
  page: Page;
  timeoutMs: number;
  intervalMs: number;
  retryDelayMs: number;
  stopAfterClick: boolean;
  diagnostics?: WalletIframeAutoConfirmDiagnostics;
  startedAtMs: number;
  isDone: () => boolean;
}): Promise<void> {
  const deadline = Date.now() + args.timeoutMs;
  while (!args.isDone() && Date.now() < deadline) {
    const clicked = await clickWalletIframeConfirm(args.page, {
      timeoutMs: Math.min(500, args.intervalMs),
      diagnostics: args.diagnostics,
      diagnosticsStartedAtMs: args.startedAtMs,
    });
    if (clicked && args.stopAfterClick) return;
    if (args.retryDelayMs > 0) {
      await args.page.waitForTimeout(args.retryDelayMs);
    }
  }
}
