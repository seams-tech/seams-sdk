import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { TouchConfirmSigningSessionPort } from '../touchConfirm';
import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from '../api/userPreferences';
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
  touchConfirm?: TouchConfirmSigningSessionPort;
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
}
