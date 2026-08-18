import type { WalletHostRuntimeRequest } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createExportWalletIframeHandlers } from './handlers/export';

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createExportWalletIframeHandlers);
}

