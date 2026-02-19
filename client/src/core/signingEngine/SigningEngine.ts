import type { ClientAuthenticatorData, ClientUserData } from '../indexedDB';
import type { StoreUserDataInput } from '../indexedDB/passkeyClientDB.types';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import type { NonceManager } from '../rpcClients/near/nonceManager';
import { toAccountId, type AccountId } from '../types/accountIds';
import type { ActionArgsWasm, TransactionInputWasm } from '../types/actions';
import type { AuthenticatorOptions } from '../types/authenticatorOptions';
import type { DelegateActionInput } from '../types/delegate';
import type { onProgressEvents } from '../types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
  WasmSignedDelegate,
} from '../types/signer-worker';
import type { SignTransactionResult, SigningSessionStatus, TatchiConfigs, ThemeName } from '../types/tatchi';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../types';
import type { UserPreferencesManager } from './api/userPreferences';
import type { ThresholdEcdsaSecp256k1KeyRef } from './interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from './orchestration/activation';
import type { SignerWorkerManager } from './workers/signerWorkerManager';
import type { RegistrationCredentialConfirmationPayload } from './workers/signerWorkerManager/internal/validation';
import type { SecureConfirmWorkerManager } from './secureConfirm';
import type { TouchIdPrompt } from './signers/webauthn/prompt/touchIdPrompt';
import type { WebAuthnAllowCredential } from './signers/webauthn/credentials';
import type { TempoSecp256k1SigningRequest, TempoSigningRequest } from './chainAdaptors/tempo/types';
import type { TempoSignedResult } from './chainAdaptors/tempo/tempoAdapter';
import { getPrfResultsFromCredential } from './signers/webauthn/credentials/credentialExtensions';
import { deriveThresholdSecp256k1ClientShareWasm } from './signers/wasm/ethSignerWasm';
import {
  connectThresholdEd25519SessionLiteValue,
  bootstrapThresholdEcdsaSessionLiteValue,
} from './api/thresholdLifecycle/thresholdSessionActivation';
import {
  deriveThresholdEd25519ClientVerifyingShareFromCredential as deriveThresholdEd25519ClientVerifyingShareFromCredentialValue,
  enrollThresholdEd25519Key as enrollThresholdEd25519KeyValue,
  enrollThresholdEd25519KeyPostRegistration as enrollThresholdEd25519KeyPostRegistrationValue,
  rotateThresholdEd25519KeyPostRegistration as rotateThresholdEd25519KeyPostRegistrationValue,
} from './api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  persistThresholdEcdsaBootstrapChainAccount as persistThresholdEcdsaBootstrapChainAccountValue,
  type ThresholdEcdsaSmartAccountBootstrapInput,
} from './api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import {
  signDelegateAction as signDelegateActionValue,
  signNEP413Message as signNEP413MessageValue,
  signTransactionsWithActions as signTransactionsWithActionsValue,
} from './api/signing/nearSigning';
import { signTempo as signTempoValue } from './api/signing/tempoSigning';
import { withThresholdEcdsaSignInFlightGate } from './api/thresholdLifecycle/thresholdEcdsaSignInFlightGate';
import {
  deriveNearKeypairAndEncryptFromSerialized as deriveNearKeypairAndEncryptFromSerializedValue,
  deriveNearKeypairFromCredentialViaWorker as deriveNearKeypairFromCredentialViaWorkerValue,
} from './api/recovery/nearKeyDerivation';
import { exportPrivateKeysWithUI as exportPrivateKeysWithUIValue } from './api/recovery/privateKeyExportRecovery';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
} from './api/registration/registrationSession';
import {
  atomicStoreRegistrationData as atomicStoreRegistrationDataValue,
  hasPasskeyCredential as hasPasskeyCredentialValue,
  initializeCurrentUser as initializeCurrentUserValue,
  rollbackUserRegistration as rollbackUserRegistrationValue,
  storeAuthenticator as storeAuthenticatorValue,
  storeUserData as storeUserDataValue,
  type StoreAuthenticatorInput,
} from './api/registration/registrationAccountLifecycle';
import {
  extractCosePublicKey as extractCosePublicKeyValue,
  generateEphemeralNearKeypair as generateEphemeralNearKeypairValue,
  signNearWithIntent as signNearWithIntentValue,
  signTransactionWithKeyPair as signTransactionWithKeyPairValue,
} from './api/signing/signerWorkerBridge';
import { initializeRuntimeBootstrap } from './api/bootstrap/runtimeBootstrap';
import { createManagerAssembly } from './api/bootstrap/managerAssembly';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './api/bootstrap/orchestrationDependencyFactory';

export type { ThresholdEcdsaSessionBootstrapResult } from './orchestration/activation';

/**
 * SigningEngine is the signing composition root:
 * - owns bootstrap/lifecycle for worker managers
 * - exposes direct public signing/session/recovery/persistence methods
 * - keeps only shared runtime/config helpers and orchestration deps internally
 */
export class SigningEngine {
  // Kept as fields for low-level tests that intentionally access internals.
  private readonly secureConfirmWorkerManager: SecureConfirmWorkerManager;
  private readonly signerWorkerManager: SignerWorkerManager;
  private readonly touchIdPrompt: TouchIdPrompt;
  private readonly userPreferencesManager: UserPreferencesManager;
  private readonly nearClient: NearClient;
  private readonly nonceManager: NonceManager;
  private workerBaseOrigin: string = '';
  private theme: ThemeName = 'dark';
  private readonly activeSigningSessionIds: Map<string, string> = new Map();
  private readonly thresholdEcdsaBootstrapQueueByAccount: Map<string, Promise<void>> = new Map();
  private readonly thresholdEcdsaSignInFlightByAccount: Set<string> = new Set();
  private readonly orchestrationDeps: OrchestrationDependencyBundle;

  readonly tatchiPasskeyConfigs: TatchiConfigs;

  constructor(tatchiPasskeyConfigs: TatchiConfigs, nearClient: NearClient) {
    this.tatchiPasskeyConfigs = tatchiPasskeyConfigs;
    this.nearClient = nearClient;

    const assembly = createManagerAssembly({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      getTheme: () => this.theme,
      getAppearanceTokens: () => this.tatchiPasskeyConfigs.appearance?.tokens,
    });

    this.touchIdPrompt = assembly.touchIdPrompt;
    this.userPreferencesManager = assembly.userPreferencesManager;
    this.nonceManager = assembly.nonceManager;
    this.secureConfirmWorkerManager = assembly.secureConfirmWorkerManager;
    this.signerWorkerManager = assembly.signerWorkerManager;

    this.orchestrationDeps = createOrchestrationDependencyBundle({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      nearClient: this.nearClient,
      touchIdPrompt: this.touchIdPrompt,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      signerWorkerManager: this.signerWorkerManager,
      activeSigningSessionIds: this.activeSigningSessionIds,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      getTheme: () => this.theme,
      signTempo: (args) => this.signTempo(args),
      signTransactionsWithActions: (args) => this.signTransactionsWithActions(args),
      signNearWithIntent: signNearWithIntentValue,
      deriveNearKeypairFromCredentialViaWorker: (args) =>
        this.deriveNearKeypairFromCredentialViaWorker(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        this.initializeCurrentUser(nearAccountId, nearClientArg),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        this.persistThresholdEcdsaBootstrapChainAccount(args),
    });

    initializeRuntimeBootstrap({
      tatchiPasskeyConfigs: this.tatchiPasskeyConfigs,
      userPreferencesManager: this.userPreferencesManager,
      getWorkerBaseOrigin: () => this.workerBaseOrigin,
      setWorkerBaseOrigin: (origin: string) => {
        this.workerBaseOrigin = origin;
        this.signerWorkerManager.setWorkerBaseOrigin(origin);
        this.secureConfirmWorkerManager.setWorkerBaseOrigin?.(origin);
      },
    });
  }

  private async withThresholdEcdsaBootstrapQueue<T>(
    nearAccountId: AccountId,
    task: () => Promise<T>,
  ): Promise<T> {
    const accountKey = String(toAccountId(String(nearAccountId || '').trim()));
    const previous = this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) || Promise.resolve();
    const waitForPrevious = previous.catch(() => undefined);

    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const next = waitForPrevious.then(() => gate);
    this.thresholdEcdsaBootstrapQueueByAccount.set(accountKey, next);

    await waitForPrevious;
    try {
      return await task();
    } finally {
      release();
      if (this.thresholdEcdsaBootstrapQueueByAccount.get(accountKey) === next) {
        this.thresholdEcdsaBootstrapQueueByAccount.delete(accountKey);
      }
    }
  }

  prewarmSignerWorkers(): void {
    this.orchestrationDeps.getManagerConvenienceDeps().prewarmSignerWorkers();
  }

  async warmCriticalResources(nearAccountId?: string): Promise<void> {
    await this.orchestrationDeps
      .getManagerConvenienceDeps()
      .warmCriticalResources(nearAccountId);
  }

  getRpId(): string {
    return this.touchIdPrompt.getRpId();
  }

  getNonceManager(): NonceManager {
    return this.nonceManager;
  }

  setTheme(next: ThemeName): void {
    if (next !== 'light' && next !== 'dark') return;
    this.theme = next;
  }

  getTheme(): ThemeName {
    return this.theme;
  }

  getUserPreferences(): UserPreferencesManager {
    return this.userPreferencesManager;
  }

  async signTransactionsWithActions(args: {
    transactions: TransactionInputWasm[];
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
    sessionId?: string;
  }): Promise<SignTransactionResult[]> {
    return await signTransactionsWithActionsValue(this.orchestrationDeps.nearSigningDeps, args);
  }

  async signDelegateAction(args: {
    delegate: DelegateActionInput;
    rpcCall: RpcCallPayload;
    deviceNumber?: number;
    signerMode: SignerMode;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    title?: string;
    body?: string;
    onEvent?: (update: onProgressEvents) => void;
  }): Promise<{
    signedDelegate: WasmSignedDelegate;
    hash: string;
    nearAccountId: AccountId;
    logs?: string[];
  }> {
    return await signDelegateActionValue(this.orchestrationDeps.nearSigningDeps, args);
  }

  async signNEP413Message(payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: AccountId;
    signerMode: SignerMode;
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<{
    success: boolean;
    accountId: string;
    publicKey: string;
    signature: string;
    state?: string;
    error?: string;
  }> {
    return await signNEP413MessageValue(this.orchestrationDeps.nearSigningDeps, payload);
  }

  async signTempo(args: {
    nearAccountId: string;
    request: TempoSigningRequest;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  }): Promise<TempoSignedResult> {
    return await withThresholdEcdsaSignInFlightGate({
      inFlightByAccount: this.thresholdEcdsaSignInFlightByAccount,
      nearAccountId: args.nearAccountId,
      enabled: args.request.senderSignatureAlgorithm === 'secp256k1',
      task: async () => await signTempoValue(this.orchestrationDeps.tempoSigningDeps, args),
    });
  }

  async signTempoWithThresholdEcdsa(args: {
    nearAccountId: string;
    request: TempoSecp256k1SigningRequest;
    thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<TempoSignedResult> {
    if (args.request.senderSignatureAlgorithm !== 'secp256k1') {
      throw new Error(
        '[SigningEngine] signTempoWithThresholdEcdsa requires senderSignatureAlgorithm=secp256k1',
      );
    }

    return await this.signTempo({
      nearAccountId: args.nearAccountId,
      request: args.request,
      thresholdEcdsaKeyRef: args.thresholdEcdsaKeyRef,
      confirmationConfigOverride: args.confirmationConfigOverride,
    });
  }

  storeUserData(userData: StoreUserDataInput): Promise<void> {
    return storeUserDataValue(this.orchestrationDeps.registrationAccountLifecycleDeps, userData);
  }

  getAllUsers(): Promise<ClientUserData[]> {
    return this.orchestrationDeps.indexedDB.clientDB.listNearAccountProjections();
  }

  getUserByDevice(nearAccountId: AccountId, deviceNumber: number): Promise<ClientUserData | null> {
    return this.orchestrationDeps.indexedDB.clientDB.getNearAccountProjection(nearAccountId, deviceNumber);
  }

  getLastUser(): Promise<ClientUserData | null> {
    return this.orchestrationDeps.indexedDB.clientDB.getLastSelectedNearAccountProjection();
  }

  getAuthenticatorsByUser(nearAccountId: AccountId): Promise<ClientAuthenticatorData[]> {
    return this.orchestrationDeps.indexedDB.clientDB.listNearAuthenticators(nearAccountId);
  }

  updateLastLogin(nearAccountId: AccountId): Promise<void> {
    return this.orchestrationDeps.indexedDB.clientDB.touchLastLoginForNearAccount(nearAccountId);
  }

  setLastUser(nearAccountId: AccountId, deviceNumber: number = 1): Promise<void> {
    return this.orchestrationDeps.indexedDB.clientDB.setLastProfileStateForNearAccount(
      nearAccountId,
      deviceNumber,
    );
  }

  initializeCurrentUser(nearAccountId: AccountId, nearClientArg?: NearClient): Promise<void> {
    return initializeCurrentUserValue(this.orchestrationDeps.registrationAccountLifecycleDeps, {
      nearAccountId,
      nearClient: nearClientArg,
    });
  }

  storeAuthenticator(authenticatorData: StoreAuthenticatorInput): Promise<void> {
    return storeAuthenticatorValue(this.orchestrationDeps.registrationAccountLifecycleDeps, authenticatorData);
  }

  rollbackUserRegistration(nearAccountId: AccountId): Promise<void> {
    return rollbackUserRegistrationValue(this.orchestrationDeps.registrationAccountLifecycleDeps, nearAccountId);
  }

  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean> {
    return hasPasskeyCredentialValue(this.orchestrationDeps.registrationAccountLifecycleDeps, nearAccountId);
  }

  atomicStoreRegistrationData(args: {
    nearAccountId: AccountId;
    credential: WebAuthnRegistrationCredential;
    publicKey: string;
  }): Promise<void> {
    return atomicStoreRegistrationDataValue(this.orchestrationDeps.registrationAccountLifecycleDeps, args);
  }

  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload> {
    return requestRegistrationCredentialConfirmationValue(this.orchestrationDeps.registrationSessionDeps, params);
  }

  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential> {
    return getAuthenticationCredentialsSerializedValue(this.orchestrationDeps.registrationSessionDeps, args);
  }

  deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: string;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
      persistToDb?: boolean;
    };
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    publicKey: string;
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
    encryptedSk?: string;
    error?: string;
  }> {
    return deriveNearKeypairAndEncryptFromSerializedValue(this.orchestrationDeps.nearKeyDerivationDeps, args);
  }

  deriveNearKeypairFromCredentialViaWorker(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  }): Promise<{ publicKey: string; privateKey: string }> {
    return deriveNearKeypairFromCredentialViaWorkerValue(this.orchestrationDeps.nearKeyDerivationDeps, args);
  }

  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
    return extractCosePublicKeyValue(this.orchestrationDeps.signerWorkerBridgeDeps, attestationObjectBase64url);
  }

  exportPrivateKeysWithUI(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
    return exportPrivateKeysWithUIValue(this.orchestrationDeps.privateKeyExportRecoveryDeps, {
      nearAccountId,
      options,
    });
  }

  signTransactionWithKeyPair(args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }> {
    return signTransactionWithKeyPairValue(this.orchestrationDeps.signerWorkerBridgeDeps, args);
  }

  generateEphemeralNearKeypair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    return generateEphemeralNearKeypairValue(this.orchestrationDeps.signerWorkerBridgeDeps);
  }

  connectThresholdEd25519SessionLite(
    args: Parameters<typeof connectThresholdEd25519SessionLiteValue>[1],
  ): ReturnType<typeof connectThresholdEd25519SessionLiteValue> {
    return connectThresholdEd25519SessionLiteValue(
      this.orchestrationDeps.thresholdSessionActivationDeps,
      args,
    );
  }

  async bootstrapThresholdEcdsaSessionLite(
    args: Parameters<typeof bootstrapThresholdEcdsaSessionLiteValue>[1],
  ): Promise<ThresholdEcdsaSessionBootstrapResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    return await this.withThresholdEcdsaBootstrapQueue(nearAccountId, async () => {
      return await bootstrapThresholdEcdsaSessionLiteValue(
        this.orchestrationDeps.thresholdSessionActivationDeps,
        {
          ...args,
          nearAccountId,
        },
      );
    });
  }

  persistThresholdEcdsaBootstrapChainAccount(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }): Promise<void> {
    return persistThresholdEcdsaBootstrapChainAccountValue({
      indexedDB: this.orchestrationDeps.indexedDB,
      nearAccountId: toAccountId(args.nearAccountId),
      chain: args.chain,
      bootstrap: args.bootstrap,
      smartAccount: args.smartAccount,
    });
  }

  getWarmSigningSessionStatus(
    nearAccountId: AccountId | string,
  ): Promise<SigningSessionStatus | null> {
    return this.orchestrationDeps
      .getManagerConvenienceDeps()
      .getWarmSigningSessionStatus(nearAccountId);
  }

  setActiveSigningSessionId(nearAccountId: AccountId | string, sessionId: string): void {
    const accountKey = String(toAccountId(nearAccountId));
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) {
      this.activeSigningSessionIds.delete(accountKey);
      return;
    }
    this.activeSigningSessionIds.set(accountKey, normalizedSessionId);
  }

  putPrfFirstForThresholdSession(args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
  }): Promise<void> {
    return this.secureConfirmWorkerManager.putPrfFirstForThresholdSession(args);
  }

  async clearWarmSigningSessions(nearAccountId?: AccountId | string): Promise<void> {
    const sessionIds: string[] = [];
    if (nearAccountId != null) {
      const accountKey = String(toAccountId(nearAccountId));
      const sessionId = String(this.activeSigningSessionIds.get(accountKey) || '').trim();
      if (sessionId) sessionIds.push(sessionId);
      this.activeSigningSessionIds.delete(accountKey);
    } else {
      for (const sessionIdRaw of this.activeSigningSessionIds.values()) {
        const sessionId = String(sessionIdRaw || '').trim();
        if (sessionId) sessionIds.push(sessionId);
      }
      this.activeSigningSessionIds.clear();
    }

    await Promise.all(
      sessionIds.map((sessionId) =>
        this.secureConfirmWorkerManager
          .clearPrfFirstForThresholdSession({ sessionId })
          .catch(() => undefined)),
    );
  }

  deriveThresholdEd25519ClientVerifyingShareFromCredential(
    args: Parameters<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>[1],
  ): ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue> {
    return deriveThresholdEd25519ClientVerifyingShareFromCredentialValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  async deriveThresholdEcdsaClientVerifyingShareFromCredential(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  }): Promise<
    Awaited<ReturnType<typeof deriveThresholdEd25519ClientVerifyingShareFromCredentialValue>>
  > {
    const nearAccountId = toAccountId(args.nearAccountId);
    try {
      const prfFirstB64u = String(getPrfResultsFromCredential(args.credential).first || '').trim();
      if (!prfFirstB64u) {
        throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
      }
      const workerCtx = this.orchestrationDeps.thresholdSessionActivationDeps.getSignerWorkerContext();
      const derived = await deriveThresholdSecp256k1ClientShareWasm({
        prfFirstB64u,
        userId: nearAccountId,
        workerCtx,
      });
      return {
        success: true,
        nearAccountId,
        clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
      };
    } catch (error: unknown) {
      const message = String((error as { message?: unknown })?.message ?? error);
      return {
        success: false,
        nearAccountId,
        clientVerifyingShareB64u: '',
        error: message,
      };
    }
  }

  enrollThresholdEd25519KeyPostRegistration(
    args: Parameters<typeof enrollThresholdEd25519KeyPostRegistrationValue>[1],
  ): ReturnType<typeof enrollThresholdEd25519KeyPostRegistrationValue> {
    return enrollThresholdEd25519KeyPostRegistrationValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  rotateThresholdEd25519KeyPostRegistration(
    args: Parameters<typeof rotateThresholdEd25519KeyPostRegistrationValue>[1],
  ): ReturnType<typeof rotateThresholdEd25519KeyPostRegistrationValue> {
    return rotateThresholdEd25519KeyPostRegistrationValue(
      this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      args,
    );
  }

  enrollThresholdEd25519Key(
    args: Parameters<typeof enrollThresholdEd25519KeyValue>[1],
  ): ReturnType<typeof enrollThresholdEd25519KeyValue> {
    return enrollThresholdEd25519KeyValue(this.orchestrationDeps.thresholdEd25519LifecycleDeps, args);
  }

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceManager.clear();
    this.activeSigningSessionIds.clear();
  }
}

/**
 * Boundary-facing API contract for SigningEngine consumers.
 * Keep this narrow and intentional; prefer adding methods here explicitly.
 */
export type SigningEnginePublic = Pick<
  SigningEngine,
  | 'tatchiPasskeyConfigs'
  | 'setTheme'
  | 'getUserPreferences'
  | 'getRpId'
  | 'getNonceManager'
  | 'warmCriticalResources'
  | 'signTransactionsWithActions'
  | 'signDelegateAction'
  | 'signNEP413Message'
  | 'signTempo'
  | 'signTempoWithThresholdEcdsa'
  | 'storeUserData'
  | 'getAllUsers'
  | 'getUserByDevice'
  | 'getLastUser'
  | 'getAuthenticatorsByUser'
  | 'updateLastLogin'
  | 'setLastUser'
  | 'initializeCurrentUser'
  | 'storeAuthenticator'
  | 'rollbackUserRegistration'
  | 'hasPasskeyCredential'
  | 'atomicStoreRegistrationData'
  | 'requestRegistrationCredentialConfirmation'
  | 'getAuthenticationCredentialsSerialized'
  | 'deriveNearKeypairAndEncryptFromSerialized'
  | 'extractCosePublicKey'
  | 'exportPrivateKeysWithUI'
  | 'signTransactionWithKeyPair'
  | 'generateEphemeralNearKeypair'
  | 'connectThresholdEd25519SessionLite'
  | 'bootstrapThresholdEcdsaSessionLite'
  | 'persistThresholdEcdsaBootstrapChainAccount'
  | 'getWarmSigningSessionStatus'
  | 'setActiveSigningSessionId'
  | 'putPrfFirstForThresholdSession'
  | 'clearWarmSigningSessions'
  | 'deriveThresholdEd25519ClientVerifyingShareFromCredential'
  | 'deriveThresholdEcdsaClientVerifyingShareFromCredential'
  | 'enrollThresholdEd25519KeyPostRegistration'
  | 'rotateThresholdEd25519KeyPostRegistration'
>;
