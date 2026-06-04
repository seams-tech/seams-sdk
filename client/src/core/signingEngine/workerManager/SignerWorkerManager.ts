import { type NearClient } from '@/core/rpcClients/near/NearClient';
import type { UiConfirmSigningSessionPort } from '../uiConfirm/types';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { NearSigningKeyMaterialStorePort, NearSigningRuntimeDeps } from '../interfaces/runtime';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from './workerTypes';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { ThemeName, SeamsChainConfig } from '@/core/types/seams';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import type { WorkerTransport } from './workerTransport';
import { createNearKeyOps } from './nearKeyOps/createNearKeyOps';

export interface SignerWorkerManagerContext extends NearSigningRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
}

export type SignerWorkerManagerDeps = {
  nearKeyMaterialStore: NearSigningKeyMaterialStorePort;
  touchIdPrompt: TouchIdPrompt;
  touchConfirm: UiConfirmSigningSessionPort;
  nearClient: NearClient;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  relayerUrl: string;
  workerTransport: WorkerTransport;
  chains?: readonly SeamsChainConfig[];
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  getTheme?: () => ThemeName;
};

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: This stack is WebAuthn-only; challenges are either server-minted
 * (e.g. login) or derived from intent/session digests (e.g. threshold sessions).
 */
export class SignerWorkerManager {
  private nearKeyMaterialStore: NearSigningKeyMaterialStorePort;
  private touchIdPrompt: TouchIdPrompt;
  private touchConfirm: UiConfirmSigningSessionPort;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceCoordinator: NonceCoordinator;
  private relayerUrl: string;
  private chains?: readonly SeamsChainConfig[];
  private nearExplorerUrl?: string;
  private tempoExplorerUrl?: string;
  private evmExplorerUrl?: string;
  private getTheme?: () => ThemeName;
  private workerTransport: WorkerTransport;
  readonly nearKeyOps: NearSigningKeyOps;

  constructor(deps: SignerWorkerManagerDeps) {
    this.nearKeyMaterialStore = deps.nearKeyMaterialStore;
    this.touchIdPrompt = deps.touchIdPrompt;
    this.touchConfirm = deps.touchConfirm;
    this.nearClient = deps.nearClient;
    this.userPreferencesManager = deps.userPreferencesManager;
    this.nonceCoordinator = deps.nonceCoordinator;
    this.relayerUrl = deps.relayerUrl;
    this.chains = deps.chains;
    this.nearExplorerUrl = deps.nearExplorerUrl;
    this.tempoExplorerUrl = deps.tempoExplorerUrl;
    this.evmExplorerUrl = deps.evmExplorerUrl;
    this.getTheme = deps.getTheme;
    this.workerTransport = deps.workerTransport;
    this.nearKeyOps = createNearKeyOps(() => this.getContext());
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerTransport.setWorkerBaseOrigin(origin);
  }

  getContext(): SignerWorkerManagerContext {
    return {
      requestWorkerOperation: this.requestWorkerOperation.bind(this),
      nearKeyMaterialStore: this.nearKeyMaterialStore,
      touchIdPrompt: this.touchIdPrompt,
      touchConfirm: this.touchConfirm,
      nearClient: this.nearClient,
      userPreferencesManager: this.userPreferencesManager,
      nonceCoordinator: this.nonceCoordinator,
      chains: this.chains,
      getTheme: this.getTheme,
      rpIdOverride: this.touchIdPrompt.getRpId(),
      nearExplorerUrl: this.nearExplorerUrl,
      tempoExplorerUrl: this.tempoExplorerUrl,
      evmExplorerUrl: this.evmExplorerUrl,
      relayerUrl: this.relayerUrl,
    };
  }

  async prewarmWorkers(): Promise<void> {
    await this.workerTransport.prewarmWorkers();
  }

  requestWorkerOperation<K extends SignerWorkerKind, T extends SignerWorkerOperationType<K>>(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>> {
    return this.workerTransport.requestOperation(args);
  }

  requestExportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult> {
    return this.touchConfirm.exportPrivateKeysWithUi(payload);
  }
}
