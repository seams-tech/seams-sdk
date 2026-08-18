import type { WalletHostRuntimeRequest } from './runtimeContext';
import { handleWalletHostRuntimeRequestWithHandlers } from './runtimeContext';
import { createEmailOtpWalletIframeHandlers } from './handlers/emailOtp';

export async function handleWalletHostRuntimeRequest(
  input: WalletHostRuntimeRequest,
): Promise<void> {
  await handleWalletHostRuntimeRequestWithHandlers(input, createEmailOtpWalletIframeHandlers);
}

