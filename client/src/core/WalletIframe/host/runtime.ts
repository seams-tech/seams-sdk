import type { WalletHostRuntimeRequest, WalletHostRuntimeState } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createWalletIframeHandlers } from './wallet-iframe-handlers';

export type { WalletHostRuntimeRequest, WalletHostRuntimeState };

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createWalletIframeHandlers);
}
