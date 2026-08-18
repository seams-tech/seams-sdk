import type { WalletHostRuntimeRequest } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createAuthWalletIframeHandlers } from './handlers/auth';

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createAuthWalletIframeHandlers);
}

