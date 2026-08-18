import type {
  ExecuteSignedDelegateRequest,
  ExecuteSignedDelegateResult,
} from '@seams/wallet-server/cloud-host';

export const WALLET_RUNTIME_SERVICE_ORIGIN_V1 = 'https://wallet-runtime.internal';
export const WALLET_RUNTIME_OPS_BASE_PATH_V1 = '/internal/wallet-runtime/v1';

export const WALLET_RUNTIME_OP_PATHS_V1 = {
  executeSignedDelegate: `${WALLET_RUNTIME_OPS_BASE_PATH_V1}/execute-signed-delegate`,
  relayerAccount: `${WALLET_RUNTIME_OPS_BASE_PATH_V1}/relayer-account`,
} as const;

export interface WalletRuntimeOps {
  executeSignedDelegate(input: ExecuteSignedDelegateRequest): Promise<ExecuteSignedDelegateResult>;
  getRelayerAccount(): Promise<{ accountId: string; publicKey: string }>;
}

export interface WalletRuntimeServiceBinding {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}
