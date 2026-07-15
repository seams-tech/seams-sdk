import {
  NearSignerWorkerCustomRequestType,
  WorkerRequestType,
  WorkerResponseType,
  type DelegatePayload,
  type ThresholdEd25519BuildDelegateSigningPayloadResult,
  type ThresholdEd25519ComputeSigningDigestResult,
  type ThresholdEd25519FinalizeNearTxFromSignatureResult,
  type ThresholdEd25519NearTxUnsignedBorsh,
  type ThresholdEd25519DecodeSignedNearTxBorshResult,
  type WasmDeriveThresholdEd25519ClientVerifyingShareResult,
  type WasmSignedDelegate,
  type TransactionPayload,
} from '@/core/types/signer-worker';
import type { TransactionContext } from '@/core/types/rpc';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

const NEAR_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export async function computeThresholdEd25519Nep413SigningDigestWasm(args: {
  sessionId: string;
  message: string;
  recipient: string;
  nonce: string;
  state?: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ComputeSigningDigestResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeNep413SigningDigest,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        message: args.message,
        recipient: args.recipient,
        nonce: args.nonce,
        ...(args.state ? { state: args.state } : {}),
      },
    },
  });
  return requireThresholdEd25519SigningDigestResult(response);
}

export async function computeThresholdEd25519DelegateSigningDigestWasm(args: {
  sessionId: string;
  delegate: DelegatePayload;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ComputeSigningDigestResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ComputeDelegateSigningDigest,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        delegate: args.delegate,
      },
    },
  });
  return requireThresholdEd25519SigningDigestResult(response);
}

export async function buildThresholdEd25519DelegateSigningPayloadWasm(args: {
  sessionId: string;
  delegate: DelegatePayload;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519BuildDelegateSigningPayloadResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519BuildDelegateSigningPayload,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        delegate: args.delegate,
      },
    },
  });
  return requireThresholdEd25519DelegateSigningPayloadResult(response);
}

export async function finalizeThresholdEd25519DelegateFromSignatureWasm(args: {
  sessionId: string;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  signatureB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<WasmSignedDelegate> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeDelegateFromSignature,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        delegate: args.delegate,
        signingDigestB64u: args.signingDigestB64u,
        signatureB64u: args.signatureB64u,
      },
    },
  });
  return requireThresholdEd25519SignedDelegateResult(response);
}

export async function buildThresholdEd25519NearTxUnsignedBorshWasm(args: {
  sessionId: string;
  txSigningRequest: TransactionPayload;
  transactionContext: TransactionContext;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519NearTxUnsignedBorsh> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        txSigningRequests: [args.txSigningRequest],
        transactionContext: args.transactionContext,
      },
    },
  });
  const unsigned = requireThresholdEd25519NearTxUnsignedBorshResult(response);
  const first = unsigned[0];
  if (!first || unsigned.length !== 1) {
    throw new Error('near signer worker returned invalid single-transaction unsigned payload');
  }
  return first;
}

export async function finalizeThresholdEd25519NearTxFromSignatureWasm(args: {
  sessionId: string;
  unsignedTransactionBorshB64u: string;
  signingDigestB64u: string;
  signatureB64u: string;
  expectedNearAccountId: string;
  expectedSignerPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519FinalizeNearTxFromSignatureResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519FinalizeNearTxFromSignature,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        unsignedTransactionBorshB64u: args.unsignedTransactionBorshB64u,
        signingDigestB64u: args.signingDigestB64u,
        signatureB64u: args.signatureB64u,
        expectedNearAccountId: args.expectedNearAccountId,
        expectedSignerPublicKey: args.expectedSignerPublicKey,
      },
    },
  });
  return requireThresholdEd25519FinalizeNearTxFromSignatureResult(response);
}

export async function decodeThresholdEd25519SignedNearTxBorshWasm(args: {
  sessionId: string;
  signedTransactionBorshB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519DecodeSignedNearTxBorshResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519DecodeSignedNearTxBorsh,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        signedTransactionBorshB64u: args.signedTransactionBorshB64u,
      },
    },
  });
  return requireThresholdEd25519DecodeSignedNearTxBorshResult(response);
}

function requireThresholdEd25519SigningDigestResult(
  value: unknown,
): ThresholdEd25519ComputeSigningDigestResult {
  const parsed = value as ThresholdEd25519ComputeSigningDigestResult;
  if (!parsed?.signingDigestB64u) {
    throw new Error('near signer worker returned invalid Ed25519 signing digest result');
  }
  return parsed;
}

function requireThresholdEd25519DelegateSigningPayloadResult(
  value: unknown,
): ThresholdEd25519BuildDelegateSigningPayloadResult {
  const parsed = value as ThresholdEd25519BuildDelegateSigningPayloadResult;
  if (!parsed?.canonicalDelegateBorshB64u || !parsed.signingDigestB64u) {
    throw new Error('near signer worker returned invalid Ed25519 delegate signing payload');
  }
  return parsed;
}

function requireThresholdEd25519SignedDelegateResult(value: unknown): WasmSignedDelegate {
  const parsed = value as WasmSignedDelegate & {
    delegateAction?: unknown;
    signature?: unknown;
    borshBytes?: unknown;
  };
  if (!parsed?.delegateAction || !parsed.signature || !parsed.borshBytes) {
    throw new Error('near signer worker returned invalid Ed25519 signed delegate result');
  }
  return parsed;
}

function requireThresholdEd25519NearTxUnsignedBorshResult(
  value: unknown,
): readonly ThresholdEd25519NearTxUnsignedBorsh[] {
  if (!Array.isArray(value)) {
    throw new Error('near signer worker returned invalid Ed25519 unsigned tx result');
  }
  return value.map((item): ThresholdEd25519NearTxUnsignedBorsh => {
    const parsed = item as ThresholdEd25519NearTxUnsignedBorsh;
    if (!parsed?.unsignedTransactionBorshB64u || !parsed.signingDigestB64u) {
      throw new Error('near signer worker returned invalid Ed25519 unsigned tx item');
    }
    return parsed;
  });
}

function requireThresholdEd25519FinalizeNearTxFromSignatureResult(
  value: unknown,
): ThresholdEd25519FinalizeNearTxFromSignatureResult {
  const parsed = value as ThresholdEd25519FinalizeNearTxFromSignatureResult;
  if (!parsed?.signedTransactionBorshB64u || !parsed.transactionHash) {
    throw new Error('near signer worker returned invalid Ed25519 finalized tx result');
  }
  return parsed;
}

function requireThresholdEd25519DecodeSignedNearTxBorshResult(
  value: unknown,
): ThresholdEd25519DecodeSignedNearTxBorshResult {
  const parsed = value as ThresholdEd25519DecodeSignedNearTxBorshResult & {
    signedTransaction?: { transaction?: unknown; signature?: unknown; borshBytes?: unknown };
  };
  if (
    !parsed?.signedTransaction?.transaction ||
    !parsed.signedTransaction.signature ||
    !parsed.signedTransaction.borshBytes ||
    !parsed.transactionHash
  ) {
    throw new Error('near signer worker returned invalid Ed25519 signed tx decode result');
  }
  return parsed;
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
