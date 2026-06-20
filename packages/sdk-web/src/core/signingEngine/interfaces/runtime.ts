import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type { LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import type { ProfileAccountContextPort } from '@/core/indexedDB/profileAccountProjection';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type { UiConfirmSigningSessionPort } from '../uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { ThemeName, SeamsChainConfig } from '../../types/seams';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../workerManager/workerTypes';

export type NearSigningKeyMaterialStorePort = ProfileAccountContextPort &
  AccountKeyMaterialStorePort & {
    getLastProfileState: () => Promise<LastProfileState | null>;
  };

/**
 * Dependencies required by NEAR signing adapters and handlers.
 * Keeps chain signing logic decoupled from SignerWorkerManager internals.
 */
export interface NearSigningRuntimeDeps {
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  nearKeyMaterialStore: NearSigningKeyMaterialStorePort;
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
