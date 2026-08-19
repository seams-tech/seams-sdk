import type { SeamsWeb, SigningFlowEvent } from '@seams/wallet';
import {
  thresholdEcdsaChainTargetFromConfig,
  walletSessionRefFromSession,
} from '@seams/wallet/advanced';

export async function executeEvmTransaction(seams: SeamsWeb, walletId: string): Promise<string> {
  const execution = await seams.tempo.executeEvmFamilyTransaction({
    walletSession: walletSessionRefFromSession({ walletId, walletSessionUserId: walletId }),
    chainTarget: thresholdEcdsaChainTargetFromConfig({
      network: 'tempo-testnet',
      rpcUrl: 'https://rpc.moderato.tempo.xyz',
      explorerUrl: 'https://explore.testnet.tempo.xyz',
      chainId: 42431,
    }),
    request: {
      chain: 'evm',
      kind: 'eip1559',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        chainId: 42431,
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 1n,
        gasLimit: 21_000n,
        to: '0x1234567890abcdef1234567890abcdef12345678',
        value: 0n,
        data: '0x',
      },
    },
    options: {
      onEvent: (event: SigningFlowEvent) => console.log(event.phase, event.status, event.message),
    },
  });
  console.log('transaction hash', execution.txHash);
  return execution.txHash;
}
