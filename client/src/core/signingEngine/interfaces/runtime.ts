import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { UiConfirmSigningSessionPort } from '../uiConfirm/types';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { ThemeName, SeamsChainConfig } from '../../types/seams';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../workerManager/workerTypes';

/**
 * Runtime dependencies required by chain adapters/handlers.
 * Keeps chain signing logic decoupled from SignerWorkerManager internals.
 */
export interface SigningRuntimeDeps {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  indexedDB: UnifiedIndexedDBManager;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  chains?: readonly SeamsChainConfig[];
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  relayerUrl: string;
  touchConfirm?: UiConfirmSigningSessionPort;
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
}
