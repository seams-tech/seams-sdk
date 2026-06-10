import type { TempoUnsignedTx } from './types';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

type TempoRlpValueWasm = number[] | TempoRlpValueWasm[];

type TempoTxWasmJson = {
  chainId: number;
  maxPriorityFeePerGas: string;
  maxFeePerGas: string;
  gasLimit: string;
  calls: { to: string; value: string; input?: string }[];
  accessList?: { address: string; storageKeys: string[] }[];
  nonceKey: string;
  nonce: string;
  validBefore?: string | null;
  validAfter?: string | null;
  feeToken?: string | null;
  feePayerSignature?:
    | { kind: 'none' }
    | { kind: 'placeholder' }
    | { kind: 'signed'; v: 0 | 1; r: string; s: string };
  aaAuthorizationList?: TempoRlpValueWasm;
  keyAuthorization?: TempoRlpValueWasm;
};

function toDec(v: bigint): string {
  if (v < 0n) throw new Error('[tempoSignerWasm] negative bigint not supported');
  return v.toString(10);
}

function toChainIdNumber(v: number | bigint): number {
  if (typeof v === 'bigint') {
    if (v < 0n) throw new Error('[tempoSignerWasm] chainId must be a non-negative integer');
    const asNumber = Number(v);
    if (!Number.isSafeInteger(asNumber)) {
      throw new Error('[tempoSignerWasm] chainId must be a non-negative safe integer');
    }
    return asNumber;
  }
  if (!Number.isSafeInteger(v) || v < 0) {
    throw new Error('[tempoSignerWasm] chainId must be a non-negative safe integer');
  }
  return v;
}

function toDecOpt(v: bigint | null | undefined): string | null | undefined {
  if (v === null) return null;
  if (v === undefined) return undefined;
  return toDec(v);
}

function requireTxNonce(nonce: bigint | undefined): bigint {
  if (typeof nonce === 'bigint') return nonce;
  throw new Error('[tempoSignerWasm] missing tx nonce');
}

function toWasmTempoRlpValue(
  value: TempoUnsignedTx['aaAuthorizationList'] | TempoUnsignedTx['keyAuthorization'],
): TempoRlpValueWasm | undefined {
  if (value === undefined) return undefined;
  if (value instanceof Uint8Array) return Array.from(value);
  return value.map((entry) => toWasmTempoRlpValue(entry) as TempoRlpValueWasm);
}

function toWasmTx(tx: TempoUnsignedTx): TempoTxWasmJson {
  return {
    chainId: toChainIdNumber(tx.chainId),
    maxPriorityFeePerGas: toDec(tx.maxPriorityFeePerGas),
    maxFeePerGas: toDec(tx.maxFeePerGas),
    gasLimit: toDec(tx.gasLimit),
    calls: tx.calls.map((c) => ({ to: c.to, value: toDec(c.value), input: c.input ?? '0x' })),
    accessList: (tx.accessList ?? []).map((item) => ({
      address: item.address,
      storageKeys: item.storageKeys,
    })),
    nonceKey: toDec(tx.nonceKey),
    nonce: toDec(requireTxNonce(tx.nonce)),
    validBefore: toDecOpt(tx.validBefore),
    validAfter: toDecOpt(tx.validAfter),
    feeToken: tx.feeToken ?? null,
    feePayerSignature: tx.feePayerSignature ?? { kind: 'none' },
    aaAuthorizationList: toWasmTempoRlpValue(tx.aaAuthorizationList),
    keyAuthorization: toWasmTempoRlpValue(tx.keyAuthorization),
  };
}

const TEMPO_SIGNER_WORKER_KIND = 'tempoSigner' as const;
const TEMPO_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export async function computeTempoSenderHashWasm(
  tx: TempoUnsignedTx,
  workerCtx: WorkerOperationContext,
): Promise<Uint8Array> {
  const ab = await executeWorkerOperation({
    ctx: workerCtx,
    kind: TEMPO_SIGNER_WORKER_KIND,
    request: {
      type: 'computeTempoSenderHash',
      payload: { tx: toWasmTx(tx) },
      timeoutMs: TEMPO_SIGNER_WORKER_TIMEOUT_MS,
    },
  });
  return new Uint8Array(ab);
}

export async function encodeTempoSignedTxWasm(args: {
  tx: TempoUnsignedTx;
  senderSignature: Uint8Array; // TempoSignature bytes
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const sigBuf = args.senderSignature.slice().buffer;
  const ab = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: TEMPO_SIGNER_WORKER_KIND,
    request: {
      type: 'encodeTempoSignedTx',
      payload: { tx: toWasmTx(args.tx), senderSignature: sigBuf },
      timeoutMs: TEMPO_SIGNER_WORKER_TIMEOUT_MS,
      transfer: [sigBuf],
    },
  });
  return new Uint8Array(ab);
}
