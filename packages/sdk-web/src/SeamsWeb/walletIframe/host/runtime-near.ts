import type { WalletHostRuntimeRequest } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createNearWalletIframeHandlers } from './handlers/near';

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createNearWalletIframeHandlers);
}

