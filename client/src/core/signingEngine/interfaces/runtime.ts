import type { UnifiedIndexedDBManager } from '../../indexedDB';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { NonceManager } from '../../rpcClients/near/nonceManager';
import type { TouchConfirmSigningSessionPort } from '../touchConfirm';
import type { TouchIdPrompt } from '../signers/webauthn/prompt/touchIdPrompt';
import type { UserPreferencesManager } from '../api/userPreferences';
import type { ThemeName } from '../../types/tatchi';
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
  nonceManager: NonceManager;
  getTheme?: () => ThemeName;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
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
