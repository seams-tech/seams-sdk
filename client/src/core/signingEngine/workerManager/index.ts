import { UnifiedIndexedDBManager } from '@/core/indexedDB';
import { IndexedDBManager } from '@/core/indexedDB';
import { type NearClient } from '@/core/rpcClients/near/NearClient';
import type { TouchConfirmSigningSessionPort } from '../touchConfirm';
import { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { SigningRuntimeDeps } from '../interfaces/runtime';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from './workerTypes';
import { UserPreferencesManager } from '../api/userPreferences';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { ThemeName, TatchiChainConfig } from '@/core/types/tatchi';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import { WorkerTransport, getWorkerTransport, requestWorkerOperation } from './workerTransport';
import { createNearKeyOps } from './nearKeyOps';

export interface SignerWorkerManagerContext extends SigningRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
}

/**
 * WebAuthnWorkers handles PRF, workers, and COSE operations
 *
 * Note: This stack is WebAuthn-only; challenges are either server-minted
 * (e.g. login) or derived from intent/session digests (e.g. threshold sessions).
 */
export class SignerWorkerManager {
  private indexedDB: UnifiedIndexedDBManager;
  private touchIdPrompt: TouchIdPrompt;
  private touchConfirm: TouchConfirmSigningSessionPort;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceCoordinator: NonceCoordinator;
  private relayerUrl: string;
  private chains?: readonly TatchiChainConfig[];
  private nearExplorerUrl?: string;
  private tempoExplorerUrl?: string;
  private evmExplorerUrl?: string;
  private getTheme?: () => ThemeName;
  private workerTransport: WorkerTransport;
  readonly nearKeyOps: NearSigningKeyOps;

  constructor(
    touchConfirm: TouchConfirmSigningSessionPort,
    nearClient: NearClient,
    userPreferencesManager: UserPreferencesManager,
    nonceCoordinator: NonceCoordinator,
    relayerUrl: string,
    chains?: readonly TatchiChainConfig[],
    rpIdOverride?: string,
    enableSafariGetWebauthnRegistrationFallback: boolean = true,
    nearExplorerUrl?: string,
    tempoExplorerUrl?: string,
    evmExplorerUrl?: string,
    getTheme?: () => ThemeName,
  ) {
    this.indexedDB = IndexedDBManager;
    this.touchIdPrompt = new TouchIdPrompt(
      rpIdOverride,
      enableSafariGetWebauthnRegistrationFallback,
    );
    this.touchConfirm = touchConfirm;
    this.nearClient = nearClient;
    this.userPreferencesManager = userPreferencesManager;
    this.nonceCoordinator = nonceCoordinator;
    this.relayerUrl = relayerUrl;
    this.chains = chains;
    this.nearExplorerUrl = nearExplorerUrl;
    this.tempoExplorerUrl = tempoExplorerUrl;
    this.evmExplorerUrl = evmExplorerUrl;
    this.getTheme = getTheme;
    this.workerTransport = getWorkerTransport();
    this.nearKeyOps = createNearKeyOps(() => this.getContext());
  }

  setWorkerBaseOrigin(origin: string | undefined): void {
    this.workerTransport.setWorkerBaseOrigin(origin);
  }

  getContext(): SignerWorkerManagerContext {
    return {
      requestWorkerOperation: this.requestWorkerOperation.bind(this),
      indexedDB: this.indexedDB,
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
    return requestWorkerOperation(args);
  }

  requestExportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult> {
    return this.touchConfirm.exportPrivateKeysWithUi(payload);
  }
}
