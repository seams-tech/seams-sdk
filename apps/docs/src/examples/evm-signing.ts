import { logWalletEvents, type SeamsWeb } from '@seams/wallet';

export async function executeEvmTransaction(seams: SeamsWeb): Promise<string> {
  // `seams.evm` sends on any configured EVM-family chain — Tempo, Arc,
  // Ethereum. The chain comes from `chainTarget`, and the RPC endpoint from the
  // chain you configured. Omitting `walletSession` targets the authenticated
  // wallet, and `tx.chainId` is filled in from the target.
  const execution = await seams.evm.execute({
    chainTarget: 'tempo-testnet',
    request: {
      chain: 'evm',
      kind: 'eip1559',
      senderSignatureAlgorithm: 'secp256k1',
      tx: {
        maxPriorityFeePerGas: 1n,
        maxFeePerGas: 1n,
        gasLimit: 21_000n,
        to: '0x1234567890abcdef1234567890abcdef12345678',
        value: 0n,
        data: '0x',
      },
    },
    options: { onEvent: logWalletEvents() },
  });
  console.log('transaction hash', execution.txHash);
  return execution.txHash;
}
