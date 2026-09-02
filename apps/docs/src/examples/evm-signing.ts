import { logWalletEvents, type SeamsWeb } from '@seams/wallet';

// EIP-1559 on any configured EVM chain. `seams.tempo` mirrors this API for
// Tempo's EIP-2718 typed transactions; the two stay separate because the
// envelopes and the signed results differ.
export async function executeEvmTransaction(seams: SeamsWeb): Promise<string> {
  const execution = await seams.evm.executeTransaction({
    // A configured network slug. The RPC endpoint comes from that chain, and
    // `tx.chainId` is filled in from it. Omitting `walletSession` targets the
    // authenticated wallet.
    chainTarget: 'ethereum-sepolia',
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
