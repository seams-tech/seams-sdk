import type { AccountKeyMaterialStorePort } from '@/core/indexedDB/accountKeyMaterial';
import type { LastProfileState } from '@/core/indexedDB/passkeyClientDB.types';
import type { NearAccountClientDbPort } from '@/core/accountData/near/accountProjection';
import type { NearClient } from '../../rpcClients/near/NearClient';
import type { NonceCoordinator } from '../nonce/NonceCoordinator';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '../uiConfirm/uiConfirm.types';
import type { TouchIdPrompt } from '../stepUpConfirmation/passkeyPrompt/touchIdPrompt';
import type { UserPreferencesManager } from '../session/userPreferences';
import type { ThemeMode, SeamsChainConfig } from '../../types/seams';
import type { WalletId } from './ecdsaChainTarget';
import type { RouterAbOwnerNormalSigningCredential } from '../../rpcClients/relayer/routerAbNormalSigning';
import type {
  SignerWorkerKind,
  SignerWorkerOperationRequest,
  SignerWorkerOperationResult,
  SignerWorkerOperationType,
} from '../workerManager/workerTypes';
import type { Ed25519OperationStepUpProof } from '../threshold/ed25519/walletSession';
import type { WalletCustodyEd25519MaterialStorePort } from '../walletCustody/ed25519SeedMaterial';

export type NearSigningKeyMaterialStorePort = NearAccountClientDbPort &
  AccountKeyMaterialStorePort & {
    getLastProfileState: () => Promise<LastProfileState | null>;
  } & WalletCustodyEd25519MaterialStorePort;

/**
 * Dependencies required by NEAR signing adapters and handlers.
 * Keeps chain signing logic decoupled from SignerWorkerManager internals.
 */
export interface NearSigningRuntimeDeps {
  resolveOperationStepUpCredential: (args: {
    walletId: WalletId;
    relayerUrl: string;
    proof: Ed25519OperationStepUpProof;
  }) => Promise<RouterAbOwnerNormalSigningCredential>;
  touchIdPrompt: TouchIdPrompt;
  nearClient: NearClient;
  nearKeyMaterialStore: NearSigningKeyMaterialStorePort;
  userPreferencesManager: UserPreferencesManager;
  nonceCoordinator: NonceCoordinator;
  chains?: readonly SeamsChainConfig[];
  getTheme?: () => ThemeMode;
  rpIdOverride?: string;
  nearExplorerUrl?: string;
  tempoExplorerUrl?: string;
  evmExplorerUrl?: string;
  relayerUrl: string;
  touchConfirm?: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  requestWorkerOperation: <
    K extends SignerWorkerKind,
    T extends SignerWorkerOperationType<K>,
  >(args: {
    kind: K;
    request: SignerWorkerOperationRequest<K, T>;
  }) => Promise<SignerWorkerOperationResult<K, T>>;
}
