import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { type ActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  isExtractCosePublicKeySuccess,
  WorkerRequestType,
  WorkerResponseType,
  type WasmTransactionSignResult,
  type WasmDeriveThresholdEd25519ClientVerifyingShareResult,
} from '@/core/types/signer-worker';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

const NEAR_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export function parseCosePublicKeyBytesFromWorker(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    if (value.byteLength === 0) throw new Error('COSE public key extraction returned empty bytes');
    return new Uint8Array(value);
  }
  if (value instanceof ArrayBuffer) {
    if (value.byteLength === 0) throw new Error('COSE public key extraction returned empty bytes');
    return new Uint8Array(value.slice(0));
  }
  if (ArrayBuffer.isView(value)) {
    if (value.byteLength === 0) throw new Error('COSE public key extraction returned empty bytes');
    return new Uint8Array(value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength));
  }
  if (Array.isArray(value)) {
    if (value.length === 0) throw new Error('COSE public key extraction returned empty bytes');
    const bytes = value.map((entry) => Number(entry));
    if (!bytes.every((entry) => Number.isInteger(entry) && entry >= 0 && entry <= 255)) {
      throw new Error('COSE public key extraction returned invalid byte array');
    }
    return Uint8Array.from(bytes);
  }
  throw new Error('COSE public key extraction returned invalid byte shape');
}

export async function deriveThresholdEd25519ClientVerifyingShareWasm(args: {
  sessionId: string;
  nearAccountId: string;
  prfFirstB64u: string;
  wrapKeySalt: string;
  workerCtx: WorkerOperationContext;
}): Promise<{ nearAccountId: string; clientVerifyingShareB64u: string }> {
  const sessionId = String(args.sessionId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const wrapKeySalt = String(args.wrapKeySalt || '').trim();

  if (!sessionId) throw new Error('Missing sessionId');
  if (!nearAccountId) throw new Error('Missing nearAccountId');
  if (!prfFirstB64u || !wrapKeySalt) {
    throw new Error('Missing PRF.first or wrapKeySalt for share derivation');
  }

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId,
      type: WorkerRequestType.DeriveThresholdEd25519ClientVerifyingShare,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        nearAccountId,
        prfFirstB64u,
        wrapKeySalt,
      },
    },
  });

  if (response.type !== WorkerResponseType.DeriveThresholdEd25519ClientVerifyingShareSuccess) {
    throw new Error('DeriveThresholdEd25519ClientVerifyingShare failed');
  }

  const wasmResult = response.payload as WasmDeriveThresholdEd25519ClientVerifyingShareResult;
  const clientVerifyingShareB64u = String(wasmResult?.clientVerifyingShareB64u || '').trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Missing clientVerifyingShareB64u in worker response');
  }

  return {
    nearAccountId,
    clientVerifyingShareB64u,
  };
}

export async function extractCosePublicKeyWasm(args: {
  attestationObjectBase64url: string;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.ExtractCosePublicKey,
      payload: {
        attestationObjectBase64url: args.attestationObjectBase64url,
      },
    },
  });

  if (!isExtractCosePublicKeySuccess(response)) {
    throw new Error('COSE public key extraction failed in WASM worker');
  }

  return parseCosePublicKeyBytesFromWorker(response.payload.cosePublicKeyBytes);
}

export async function signTransactionWithKeyPairWasm(args: {
  nearPrivateKey: string;
  signerAccountId: string;
  receiverId: string;
  nonce: string;
  blockHash: string;
  actions: ActionArgsWasm[];
  workerCtx: WorkerOperationContext;
}): Promise<{ signedTransaction: SignedTransaction; logs?: string[] }> {
  args.actions.forEach((action) => {
    validateActionArgsWasm(action);
  });

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.SignTransactionWithKeyPair,
      payload: {
        nearPrivateKey: args.nearPrivateKey,
        signerAccountId: args.signerAccountId,
        receiverId: args.receiverId,
        nonce: args.nonce,
        blockHash: args.blockHash,
        actions: args.actions,
      },
    },
  });

  if (response.type !== WorkerResponseType.SignTransactionWithKeyPairSuccess) {
    throw new Error('Transaction signing with private key failed');
  }

  const wasmResult = response.payload as WasmTransactionSignResult;
  if (!wasmResult.success) {
    throw new Error(wasmResult.error || 'Transaction signing failed');
  }

  const signedTransactions = wasmResult.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected 1 signed transaction but received ${signedTransactions.length}`);
  }
  const signedTx = signedTransactions[0];
  if (!signedTx || !signedTx.transaction || !signedTx.signature) {
    throw new Error('Incomplete signed transaction data received');
  }

  return {
    signedTransaction: new SignedTransaction({
      transaction: signedTx.transaction,
      signature: signedTx.signature,
      borsh_bytes: Array.from(signedTx.borshBytes || []),
    }),
    logs: wasmResult.logs,
  };
}

export async function generateEphemeralNearKeypairWasm(args: {
  workerCtx: WorkerOperationContext;
}): Promise<{ publicKey: string; privateKey: string }> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: WorkerRequestType.GenerateEphemeralNearKeypair,
      payload: {},
    },
  });

  if (response.type !== WorkerResponseType.GenerateEphemeralNearKeypairSuccess) {
    throw new Error('Worker failed to generate ephemeral NEAR keypair');
  }

  const publicKey = ensureEd25519Prefix(
    String((response.payload as { publicKey?: unknown }).publicKey || '').trim(),
  );
  const privateKey = ensureEd25519Prefix(
    String((response.payload as { privateKey?: unknown }).privateKey || '').trim(),
  );
  if (!publicKey || !privateKey) {
    throw new Error('Worker returned invalid ephemeral NEAR keypair');
  }

  return { publicKey, privateKey };
}
