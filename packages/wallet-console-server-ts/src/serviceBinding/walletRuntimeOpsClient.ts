import type {
  ExecuteSignedDelegateRequest,
  ExecuteSignedDelegateResult,
} from '@seams/wallet-server/cloud-host';
import {
  WALLET_RUNTIME_OP_PATHS_V1,
  WALLET_RUNTIME_SERVICE_ORIGIN_V1,
  type WalletRuntimeOps,
  type WalletRuntimeServiceBinding,
} from './walletRuntimeOps';

async function postJson(
  binding: WalletRuntimeServiceBinding,
  path: string,
  body: unknown,
): Promise<Record<string, unknown>> {
  const response = await binding.fetch(`${WALLET_RUNTIME_SERVICE_ORIGIN_V1}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const parsed: unknown = await response.json().catch(() => null);
  if (!response.ok || !parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error(`Wallet runtime operation failed with HTTP ${response.status}`);
  }
  return parsed as Record<string, unknown>;
}

export function createWalletRuntimeOpsClient(
  binding: WalletRuntimeServiceBinding,
): WalletRuntimeOps {
  return {
    async executeSignedDelegate(
      input: ExecuteSignedDelegateRequest,
    ): Promise<ExecuteSignedDelegateResult> {
      const body = await postJson(binding, WALLET_RUNTIME_OP_PATHS_V1.executeSignedDelegate, input);
      return body.result as ExecuteSignedDelegateResult;
    },
    async getRelayerAccount(): Promise<{ accountId: string; publicKey: string }> {
      const body = await postJson(binding, WALLET_RUNTIME_OP_PATHS_V1.relayerAccount, {});
      const accountId = String(body.accountId || '').trim();
      const publicKey = String(body.publicKey || '').trim();
      if (!accountId || !publicKey)
        throw new Error('Wallet runtime returned an invalid relayer account');
      return { accountId, publicKey };
    },
  };
}
