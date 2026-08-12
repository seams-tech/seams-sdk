import type { SeamsWeb, SigningFlowEvent } from '@seams/sdk';
import {
  thresholdEcdsaChainTargetFromConfig,
  walletSessionRefFromSession,
} from '@seams/sdk/advanced';

function logSigningEvent(event: SigningFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export async function executeEvmTransaction(seams: SeamsWeb, walletId: string): Promise<string> {
  const walletSession = walletSessionRefFromSession({
    walletId,
    walletSessionUserId: walletId,
  });
  const chainTarget = thresholdEcdsaChainTargetFromConfig({
    network: 'tempo-testnet',
    rpcUrl: 'https://rpc.moderato.tempo.xyz',
    explorerUrl: 'https://explore.testnet.tempo.xyz',
    chainId: 42431,
  });
  const request = {
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
  } satisfies Extract<
    Parameters<SeamsWeb['tempo']['executeEvmFamilyTransaction']>[0]['request'],
    { chain: 'evm' }
  >;

  const execution = await seams.tempo.executeEvmFamilyTransaction({
    walletSession,
    chainTarget,
    request,
    options: { onEvent: logSigningEvent },
  });
  console.log('transaction hash', execution.txHash);
  return execution.txHash;
}
