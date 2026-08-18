import type { ChainAdapter, SigningIntent, SignatureBytes } from '../../interfaces/signing';
import { bytesToHex } from '../evm/bytes';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type { ManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
import type { TempoSigningRequest, TempoUnsignedTx } from './tempoSigning.types';
import {
  computeTempoSenderHashWasm,
  encodeTempoSignedTxWasm,
} from './tempoSignerWasm';

export type TempoSignedResult = {
  chain: 'tempo';
  kind: 'tempoTransaction';
  senderHashHex: string;
  rawTxHex: string;
  managedNonce?: ManagedNonceReservationSnapshot;
};

export type TempoIntentUiModel = {
  kind: 'tempoTransaction';
  tx: TempoUnsignedTx;
};

export class TempoAdapter implements ChainAdapter<
  TempoSigningRequest,
  TempoIntentUiModel,
  TempoSignedResult
> {
  readonly chain = 'tempo' as const;
  private readonly workerCtx: WorkerOperationContext;

  constructor(workerCtx: WorkerOperationContext) {
    this.workerCtx = workerCtx;
  }

  async buildIntent(
    request: TempoSigningRequest,
  ): Promise<SigningIntent<TempoIntentUiModel, TempoSignedResult>> {
    if (request.chain !== 'tempo') {
      throw new Error('[TempoAdapter] invalid chain');
    }
    if (request.kind !== 'tempoTransaction') {
      throw new Error('[TempoAdapter] unsupported request kind');
    }

    const senderHash = await computeTempoSenderHashWasm(request.tx, this.workerCtx);
    const senderHashHex = bytesToHex(senderHash);

    return {
      chain: 'tempo',
      uiModel: { kind: 'tempoTransaction', tx: request.tx },
      signRequests: [
        request.senderSignatureAlgorithm === 'webauthnP256'
          ? {
              kind: 'webauthn',
              algorithm: 'webauthnP256',
              challenge32: senderHash,
              label: 'tempo:0x76:sender',
            }
          : {
              kind: 'digest',
              algorithm: 'secp256k1',
              digest32: senderHash,
              label: 'tempo:0x76:sender',
            },
      ],
      finalize: async (sigs: SignatureBytes[]) => {
        const raw = await encodeTempoSignedTxWasm({
          tx: request.tx,
          senderSignature: sigs[0]!,
          workerCtx: this.workerCtx,
        });
        return {
          chain: 'tempo',
          kind: 'tempoTransaction',
          senderHashHex,
          rawTxHex: bytesToHex(raw),
        };
      },
    };
  }
}
