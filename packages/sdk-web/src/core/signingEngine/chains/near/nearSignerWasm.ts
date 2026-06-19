import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { type ActionArgsWasm, validateActionArgsWasm } from '@/core/types/actions';
import {
  NearSignerWorkerCustomRequestType,
  isExtractCosePublicKeySuccess,
  WorkerRequestType,
  WorkerResponseType,
  type ThresholdEd25519ClientPresignBurnResult,
  type DelegatePayload,
  type ThresholdEd25519BuildDelegateSigningPayloadResult,
  type ThresholdEd25519ClientPresignCreateResult,
  type ThresholdEd25519ClientPresignSignResult,
  type ThresholdEd25519StoreHssMaterialResult,
  type ThresholdEd25519ValidateHssMaterialResult,
  type ThresholdEd25519ComputeSigningDigestResult,
  type ThresholdEd25519FinalizeNearTxFromSignatureResult,
  type ThresholdEd25519NearTxUnsignedBorsh,
  type ThresholdEd25519DecodeSignedNearTxBorshResult,
  type WasmTransactionSignResult,
  type WasmDeriveThresholdEd25519ClientVerifyingShareResult,
  type WasmSignedDelegate,
  type TransactionPayload,
} from '@/core/types/signer-worker';
import type { TransactionContext } from '@/core/types/rpc';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

const NEAR_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export async function storeThresholdEd25519HssMaterialNearSignerWasm(args: {
  materialHandle: string;
  xClientBaseB64u: string;
  expectedClientVerifyingShareB64u: string;
  bindingDigest: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519StoreHssMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519StoreHssMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: args.materialHandle,
        xClientBaseB64u: args.xClientBaseB64u,
        expectedClientVerifyingShareB64u: args.expectedClientVerifyingShareB64u,
        bindingDigest: args.bindingDigest,
      },
    },
  });
  return requireThresholdEd25519StoreHssMaterialResult(response);
}

export async function validateThresholdEd25519HssMaterialNearSignerWasm(args: {
  materialHandle: string;
  expectedClientVerifyingShareB64u: string;
  expectedBindingDigest: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ValidateHssMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateHssMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: args.materialHandle,
        expectedClientVerifyingShareB64u: args.expectedClientVerifyingShareB64u,
        expectedBindingDigest: args.expectedBindingDigest,
      },
    },
  });
  return requireThresholdEd25519StoreHssMaterialResult(response);
}

export async function createThresholdEd25519ClientPresignWasm(args: {
  sessionId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  xClientBaseB64u: string;
  groupPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignCreateResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreate,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        clientParticipantId: args.clientParticipantId,
        relayerParticipantId: args.relayerParticipantId,
        xClientBaseB64u: args.xClientBaseB64u,
        groupPublicKey: args.groupPublicKey,
      },
    },
  });
  return requireThresholdEd25519ClientPresignCreateResult(response);
}

export async function createThresholdEd25519ClientPresignFromMaterialHandleWasm(args: {
  sessionId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  materialHandle: string;
  expectedClientVerifyingShareB64u: string;
  groupPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignCreateResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignCreateFromMaterialHandle,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        clientParticipantId: args.clientParticipantId,
        relayerParticipantId: args.relayerParticipantId,
        materialHandle: args.materialHandle,
        expectedClientVerifyingShareB64u: args.expectedClientVerifyingShareB64u,
        groupPublicKey: args.groupPublicKey,
      },
    },
  });
  return requireThresholdEd25519ClientPresignCreateResult(response);
}

export async function signThresholdEd25519ClientPresignWasm(args: {
  sessionId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  xClientBaseB64u: string;
  groupPublicKey: string;
  signingDigestB64u: string;
  clientNonceHandleB64u: string;
  clientCommitments: { hiding: string; binding: string };
  relayerCommitments: { hiding: string; binding: string };
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignSignResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSign,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        clientParticipantId: args.clientParticipantId,
        relayerParticipantId: args.relayerParticipantId,
        xClientBaseB64u: args.xClientBaseB64u,
        groupPublicKey: args.groupPublicKey,
        signingDigestB64u: args.signingDigestB64u,
        clientNonceHandleB64u: args.clientNonceHandleB64u,
        clientCommitments: args.clientCommitments,
        relayerCommitments: args.relayerCommitments,
      },
    },
  });
  return requireThresholdEd25519ClientPresignSignResult(response);
}

export async function signThresholdEd25519ClientPresignFromMaterialHandleWasm(args: {
  sessionId: string;
  clientParticipantId?: number;
  relayerParticipantId?: number;
  materialHandle: string;
  expectedClientVerifyingShareB64u: string;
  groupPublicKey: string;
  signingDigestB64u: string;
  clientNonceHandleB64u: string;
  clientCommitments: { hiding: string; binding: string };
  relayerCommitments: { hiding: string; binding: string };
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignSignResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignSignFromMaterialHandle,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        clientParticipantId: args.clientParticipantId,
        relayerParticipantId: args.relayerParticipantId,
        materialHandle: args.materialHandle,
        expectedClientVerifyingShareB64u: args.expectedClientVerifyingShareB64u,
        groupPublicKey: args.groupPublicKey,
        signingDigestB64u: args.signingDigestB64u,
        clientNonceHandleB64u: args.clientNonceHandleB64u,
        clientCommitments: args.clientCommitments,
        relayerCommitments: args.relayerCommitments,
      },
    },
  });
  return requireThresholdEd25519ClientPresignSignResult(response);
}

export async function burnThresholdEd25519ClientPresignWasm(args: {
  sessionId: string;
  clientNonceHandleB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignBurnResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ClientPresignBurn,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        clientNonceHandleB64u: args.clientNonceHandleB64u,
      },
    },
  });
  return requireThresholdEd25519ClientPresignBurnResult(response);
}

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
  txSigningRequests: readonly TransactionPayload[];
  transactionContext: TransactionContext;
  workerCtx: WorkerOperationContext;
}): Promise<readonly ThresholdEd25519NearTxUnsignedBorsh[]> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519BuildNearTxUnsignedBorsh,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        txSigningRequests: args.txSigningRequests,
        transactionContext: args.transactionContext,
      },
    },
  });
  return requireThresholdEd25519NearTxUnsignedBorshResult(response);
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
    return new Uint8Array(
      value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength),
    );
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

function requireThresholdEd25519ClientPresignCreateResult(
  value: unknown,
): ThresholdEd25519ClientPresignCreateResult {
  const parsed = value as ThresholdEd25519ClientPresignCreateResult;
  if (
    !parsed?.clientNonceHandleB64u ||
    !parsed.clientVerifyingShareB64u ||
    !parsed.clientCommitments?.hiding ||
    !parsed.clientCommitments?.binding
  ) {
    throw new Error('near signer worker returned invalid Ed25519 client presign create result');
  }
  return parsed;
}

function requireThresholdEd25519StoreHssMaterialResult(
  value: unknown,
): ThresholdEd25519StoreHssMaterialResult {
  const parsed = value as ThresholdEd25519StoreHssMaterialResult;
  if (!parsed?.materialHandle || !parsed.clientVerifyingShareB64u || !parsed.bindingDigest) {
    throw new Error('near signer worker returned invalid Ed25519 HSS material store result');
  }
  return parsed;
}

function requireThresholdEd25519ClientPresignSignResult(
  value: unknown,
): ThresholdEd25519ClientPresignSignResult {
  const parsed = value as ThresholdEd25519ClientPresignSignResult;
  if (!parsed?.clientSignatureShareB64u) {
    throw new Error('near signer worker returned invalid Ed25519 client presign sign result');
  }
  return parsed;
}

function requireThresholdEd25519ClientPresignBurnResult(
  value: unknown,
): ThresholdEd25519ClientPresignBurnResult {
  const parsed = value as ThresholdEd25519ClientPresignBurnResult;
  if (parsed?.burned !== true) {
    throw new Error('near signer worker returned invalid Ed25519 client presign burn result');
  }
  return parsed;
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
