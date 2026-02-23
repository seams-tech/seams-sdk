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
import { NonceManager } from '@/core/rpcClients/near/nonceManager';
import type { ThemeName } from '@/core/types/tatchi';
import type {
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import type { NearSigningKeyOps } from '../interfaces/nearKeyOps';
import {
  WorkerTransport,
  getWorkerTransport,
  requestWorkerOperation,
} from './workerTransport';
import { createNearKeyOps } from './nearKeyOps';

export interface SignerWorkerManagerContext extends SigningRuntimeDeps {
  userPreferencesManager: UserPreferencesManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
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
  private touchConfirmManager: TouchConfirmSigningSessionPort;
  private nearClient: NearClient;
  private userPreferencesManager: UserPreferencesManager;
  private nonceManager: NonceManager;
  private relayerUrl: string;
  private nearExplorerUrl?: string;
  private getTheme?: () => ThemeName;
  private workerTransport: WorkerTransport;
  readonly nearKeyOps: NearSigningKeyOps;

  constructor(
    touchConfirmManager: TouchConfirmSigningSessionPort,
    nearClient: NearClient,
    userPreferencesManager: UserPreferencesManager,
    nonceManager: NonceManager,
    relayerUrl: string,
    rpIdOverride?: string,
    enableSafariGetWebauthnRegistrationFallback: boolean = true,
    nearExplorerUrl?: string,
    getTheme?: () => ThemeName,
  ) {
    this.indexedDB = IndexedDBManager;
    this.touchIdPrompt = new TouchIdPrompt(
      rpIdOverride,
      enableSafariGetWebauthnRegistrationFallback,
    );
    this.touchConfirmManager = touchConfirmManager;
    this.nearClient = nearClient;
    this.userPreferencesManager = userPreferencesManager;
    this.nonceManager = nonceManager;
    this.relayerUrl = relayerUrl;
    this.nearExplorerUrl = nearExplorerUrl;
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
      touchConfirmManager: this.touchConfirmManager,
      nearClient: this.nearClient,
      userPreferencesManager: this.userPreferencesManager,
      nonceManager: this.nonceManager,
      getTheme: this.getTheme,
      rpIdOverride: this.touchIdPrompt.getRpId(),
      nearExplorerUrl: this.nearExplorerUrl,
      relayerUrl: this.relayerUrl,
    };
  }

  async prewarmWorkers(): Promise<void> {
    await this.workerTransport.prewarmWorkers();
  }

  requestWorkerOperation<
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }): Promise<SignerWorkerOperationResult<K, T>> {
    return requestWorkerOperation(args);
  }

  requestExportPrivateKeysWithUi(
    payload: ExportPrivateKeysWithUiWorkerPayload,
  ): Promise<ExportPrivateKeysWithUiWorkerResult> {
    return this.touchConfirmManager.exportPrivateKeysWithUi(payload);
  }
}
