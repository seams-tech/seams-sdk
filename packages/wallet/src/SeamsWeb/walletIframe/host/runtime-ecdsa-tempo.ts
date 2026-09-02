import type { WalletHostRuntimeRequest } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createEcdsaTempoWalletIframeHandlers } from './handlers/ecdsaTempo';

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createEcdsaTempoWalletIframeHandlers);
}

