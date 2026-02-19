import type { NearClient } from '../../near/NearClient';
import type { NonceManager } from '../../near/nonceManager';
import { toAccountId, type AccountId } from '../../types/accountIds';
import type { TatchiConfigs, ThemeName } from '../../types/tatchi';
import type { UserPreferencesManager } from './userPreferences';
import type { SignerWorkerManager } from '../workers/signerWorkerManager';
import type { SecureConfirmWorkerManager } from '../secureConfirm';
import type { TouchIdPrompt } from '../webauthn/prompt/touchIdPrompt';
import { signNearWithIntent as signNearWithIntentValue } from './signing/signerWorkerBridge';
import { initializeRuntimeBootstrap } from './bootstrap/runtimeBootstrap';
import { createManagerAssembly } from './bootstrap/managerAssembly';
import {
  createOrchestrationDependencyBundle,
  type OrchestrationDependencyBundle,
} from './bootstrap/orchestrationDependencyFactory';
import {
  createIndexedDbRegistrationSurface,
  type IndexedDbRegistrationSurface,
} from './apiSurfaces/indexedDbRegistrationSurface';
import {
  createSigningActionsSurface,
  type SigningActionsSurface,
} from './apiSurfaces/signingActionsSurface';
import {
  createCredentialRecoverySurface,
  type CredentialRecoverySurface,
} from './apiSurfaces/credentialRecoverySurface';
import {
  createThresholdSessionSurface,
  type ThresholdSessionSurface,
} from './apiSurfaces/thresholdSessionSurface';
import {
  createThresholdKeyLifecycleSurface,
  type ThresholdKeyLifecycleSurface,
} from './apiSurfaces/thresholdKeyLifecycleSurface';

export type { ThresholdEcdsaSessionBootstrapResult } from '../orchestration/activation';

/**
 * WebAuthnManager is now a composition root:
 * - owns bootstrap/lifecycle for worker managers
 * - exposes domain surfaces for signing, sessions, recovery, and persistence
 * - keeps only shared runtime/config helpers at this level
 */
export class WebAuthnManager {
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

  readonly indexedDbRegistration: IndexedDbRegistrationSurface;
  readonly signingActions: SigningActionsSurface;
  readonly credentialRecovery: CredentialRecoverySurface;
  readonly thresholdSession: ThresholdSessionSurface;
  readonly thresholdKeyLifecycle: ThresholdKeyLifecycleSurface;
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
      signTempo: (args) => this.signingActions.signTempo(args),
      signTransactionsWithActions: (args) => this.signingActions.signTransactionsWithActions(args),
      signNearWithIntent: signNearWithIntentValue,
      deriveNearKeypairFromCredentialViaWorker: (args) =>
        this.credentialRecovery.deriveNearKeypairFromCredentialViaWorker(args),
      extractCosePublicKey: (attestationObjectBase64url: string) =>
        this.credentialRecovery.extractCosePublicKey(attestationObjectBase64url),
      initializeCurrentUser: (nearAccountId: AccountId, nearClientArg?: NearClient) =>
        this.indexedDbRegistration.initializeCurrentUser(nearAccountId, nearClientArg),
      persistThresholdEcdsaBootstrapChainAccount: (args) =>
        this.thresholdSession.persistThresholdEcdsaBootstrapChainAccount(args),
    });

    this.indexedDbRegistration = createIndexedDbRegistrationSurface({
      indexedDB: this.orchestrationDeps.indexedDB,
      registrationAccountLifecycleDeps: this.orchestrationDeps.registrationAccountLifecycleDeps,
    });
    this.signingActions = createSigningActionsSurface({
      nearSigningDeps: this.orchestrationDeps.nearSigningDeps,
      tempoSigningDeps: this.orchestrationDeps.tempoSigningDeps,
      getManagerConvenienceDeps: this.orchestrationDeps.getManagerConvenienceDeps,
      thresholdEcdsaSignInFlightByAccount: this.thresholdEcdsaSignInFlightByAccount,
    });
    this.credentialRecovery = createCredentialRecoverySurface({
      registrationSessionDeps: this.orchestrationDeps.registrationSessionDeps,
      nearKeyDerivationDeps: this.orchestrationDeps.nearKeyDerivationDeps,
      privateKeyExportRecoveryDeps: this.orchestrationDeps.privateKeyExportRecoveryDeps,
      signerWorkerBridgeDeps: this.orchestrationDeps.signerWorkerBridgeDeps,
    });
    this.thresholdSession = createThresholdSessionSurface({
      thresholdSessionActivationDeps: this.orchestrationDeps.thresholdSessionActivationDeps,
      getManagerConvenienceDeps: this.orchestrationDeps.getManagerConvenienceDeps,
      secureConfirmWorkerManager: this.secureConfirmWorkerManager,
      activeSigningSessionIds: this.activeSigningSessionIds,
      withThresholdEcdsaBootstrapQueue: <T>(
        nearAccountId: AccountId,
        task: () => Promise<T>,
      ): Promise<T> => this.withThresholdEcdsaBootstrapQueue(nearAccountId, task),
    });
    this.thresholdKeyLifecycle = createThresholdKeyLifecycleSurface({
      thresholdEd25519LifecycleDeps: this.orchestrationDeps.thresholdEd25519LifecycleDeps,
      thresholdSessionActivationDeps: this.orchestrationDeps.thresholdSessionActivationDeps,
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

  destroy(): void {
    this.userPreferencesManager.destroy();
    this.nonceManager.clear();
    this.activeSigningSessionIds.clear();
  }
}
