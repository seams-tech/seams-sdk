import type { ChainAdapter, SigningIntent, SignatureBytes } from '../../interfaces/signing';
import {
  computeEip1559TxHashWasm,
  encodeEip1559SignedTxFromSignature65Wasm,
} from '../../signers/wasm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
import { bytesToHex } from './bytes';
import type { Eip1559UnsignedTx, EvmSigningRequest } from './types';

export type EvmSignedResult = {
  chain: 'evm';
  kind: 'eip1559';
  txHashHex: string;
  rawTxHex: string;
  managedNonce?: ManagedNonceReservationSnapshot;
};

export type EvmIntentUiModel = {
  kind: 'eip1559';
  tx: Eip1559UnsignedTx;
};

export class EvmAdapter implements ChainAdapter<
  EvmSigningRequest,
  EvmIntentUiModel,
  EvmSignedResult
> {
  readonly chain = 'evm' as const;
  private readonly workerCtx: WorkerOperationContext;

  constructor(workerCtx: WorkerOperationContext) {
    this.workerCtx = workerCtx;
  }

  async buildIntent(
    request: EvmSigningRequest,
  ): Promise<SigningIntent<EvmIntentUiModel, EvmSignedResult>> {
    if (request.chain !== 'evm') {
      throw new Error('[EvmAdapter] invalid chain');
    }
    if (request.kind !== 'eip1559') {
      throw new Error('[EvmAdapter] unsupported request kind');
    }

    const txHash = await computeEip1559TxHashWasm(request.tx, this.workerCtx);
    const txHashHex = bytesToHex(txHash);

    return {
      chain: 'evm',
      uiModel: { kind: 'eip1559', tx: request.tx },
      signRequests: [
        {
          kind: 'digest',
          algorithm: 'secp256k1',
          digest32: txHash,
          label: 'evm:eip1559:sender',
        },
      ],
      finalize: async (sigs: SignatureBytes[]) => {
        const raw = await encodeEip1559SignedTxFromSignature65Wasm({
          tx: request.tx,
          signature65: sigs[0]!,
          workerCtx: this.workerCtx,
        });
        return {
          chain: 'evm',
          kind: 'eip1559',
          txHashHex,
          rawTxHex: bytesToHex(raw),
        };
      },
    };
  }
}
