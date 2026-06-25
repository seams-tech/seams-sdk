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
  type ThresholdEd25519RoleSeparatedNormalSigningClientShareResult,
  type ThresholdEd25519DeleteSealedWorkerMaterialRequest,
  type ThresholdEd25519DeleteSealedWorkerMaterialResult,
  type ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest,
  type ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest,
  type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest,
  type ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest,
  type ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult,
  type ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult,
  type ThresholdEd25519PutSealedWorkerMaterialRequest,
  type ThresholdEd25519PutSealedWorkerMaterialResult,
  type ThresholdEd25519ReadSealedWorkerMaterialRequest,
  type ThresholdEd25519ReadSealedWorkerMaterialResult,
  type ThresholdEd25519RestoreWorkerMaterialRequest,
  type ThresholdEd25519RestoreWorkerMaterialResult,
  type ThresholdEd25519WorkerMaterialFailure,
  type ThresholdEd25519WorkerMaterialResult,
  type ThresholdEd25519StoreWorkerMaterialFromHssOutputResult,
  type ThresholdEd25519WorkerMaterialStoredResult,
  type ThresholdEd25519ValidateWorkerMaterialResult,
  type ThresholdEd25519ComputeSigningDigestResult,
  type ThresholdEd25519FinalizeNearTxFromSignatureResult,
  type ThresholdEd25519NearTxUnsignedBorsh,
  type ThresholdEd25519DecodeSignedNearTxBorshResult,
  type ThresholdEd25519PrepareHssClientOutputMaskHandleRequest,
  type ThresholdEd25519PrepareHssClientOutputMaskHandleResult,
  type ThresholdEd25519WorkerMaterialBinding,
  type ThresholdEd25519WorkerMaterialSessionBinding,
  type ThresholdEd25519WorkerMaterialCredentialAuthorization,
  type ThresholdEd25519WorkerMaterialSealAuthorization,
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
import { digestRouterAbEd25519WorkerMaterialSessionBinding } from '../../threshold/ed25519/workerMaterialBinding';

const NEAR_SIGNER_WORKER_TIMEOUT_MS = 20_000;

function assertWorkerMaterialSessionBindingEnvelope(args: {
  sessionId: string;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  operation: string;
}): void {
  const sessionId = String(args.sessionId || '').trim();
  const bindingSessionId = String(args.expectedSessionBinding.thresholdSessionId || '').trim();
  if (!sessionId || sessionId !== bindingSessionId) {
    throw new Error(
      `${args.operation} sessionId mismatch: envelope sessionId must equal expectedSessionBinding.thresholdSessionId`,
    );
  }
}

export async function storeThresholdEd25519WorkerMaterialFromHssOutputNearSignerWasm(args: {
  evaluatorDriverStateB64u: string;
  clientOutputMessageB64u: string;
  clientOutputMaskHandle: string;
  expectedContextBindingB64u: string;
  nearAccountId: string;
  signerSlot: number;
  signingRootId: string;
  signingRootVersion: string;
  relayerKeyId: string;
  participantIds: number[];
  createdAtMs: number;
  sealAuthorization: ThresholdEd25519WorkerMaterialSealAuthorization;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519StoreWorkerMaterialFromHssOutputResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519StoreWorkerMaterialFromHssOutput,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        evaluatorDriverStateB64u: args.evaluatorDriverStateB64u,
        clientOutputMessageB64u: args.clientOutputMessageB64u,
        clientOutputMask: {
          kind: 'rust_owned_mask_handle_v1',
          clientOutputMaskHandle: args.clientOutputMaskHandle,
        },
        expectedContextBindingB64u: args.expectedContextBindingB64u,
        nearAccountId: args.nearAccountId,
        signerSlot: args.signerSlot,
        signingRootId: args.signingRootId,
        signingRootVersion: args.signingRootVersion,
        relayerKeyId: args.relayerKeyId,
        participantIds: args.participantIds,
        createdAtMs: args.createdAtMs,
        sealAuthorization: args.sealAuthorization,
      },
    },
  });
  return requireThresholdEd25519WorkerMaterialStoredResult(response);
}

export async function prepareThresholdEd25519HssClientOutputMaskHandleNearSignerWasm(args: {
  request: ThresholdEd25519PrepareHssClientOutputMaskHandleRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareHssClientOutputMaskHandleResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareHssClientOutputMaskHandle,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PrepareHssClientOutputMaskHandleResult(response);
}

export async function prepareThresholdEd25519PasskeyPrfWorkerMaterialUnsealAuthorizationNearSignerWasm(args: {
  request: ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorizationRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialUnsealAuthorization,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult(response);
}

export async function prepareThresholdEd25519PasskeyPrfWorkerMaterialSealAuthorizationNearSignerWasm(args: {
  request: ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorizationRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PreparePasskeyPrfWorkerMaterialSealAuthorization,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult(response);
}

export async function prepareThresholdEd25519RecoveryCodeWorkerMaterialSealAuthorizationNearSignerWasm(args: {
  request: ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorizationRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialSealAuthorization,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult(response);
}

export async function prepareThresholdEd25519RecoveryCodeWorkerMaterialUnsealAuthorizationNearSignerWasm(args: {
  request: ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorizationRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PrepareRecoveryCodeWorkerMaterialUnsealAuthorization,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult(response);
}

// TS supplies expected bindings; the worker decides whether the handle currently
// maps to valid material for those bindings.
export async function validateThresholdEd25519WorkerMaterialNearSignerWasm(args: {
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ValidateWorkerMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ValidateWorkerMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: args.materialHandle,
        expectedMaterialBinding: args.expectedMaterialBinding,
      },
    },
  });
  return requireThresholdEd25519WorkerMaterialResult(response);
}

export async function restoreThresholdEd25519WorkerMaterialNearSignerWasm(args: {
  request: ThresholdEd25519RestoreWorkerMaterialRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519RestoreWorkerMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519RestoreWorkerMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519RestoreWorkerMaterialResult(response);
}

export async function putThresholdEd25519SealedWorkerMaterialNearSignerWasm(args: {
  request: ThresholdEd25519PutSealedWorkerMaterialRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519PutSealedWorkerMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519PutSealedWorkerMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519PutSealedWorkerMaterialResult(response);
}

export async function readThresholdEd25519SealedWorkerMaterialNearSignerWasm(args: {
  request: ThresholdEd25519ReadSealedWorkerMaterialRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ReadSealedWorkerMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519ReadSealedWorkerMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519ReadSealedWorkerMaterialResult(response);
}

export async function deleteThresholdEd25519SealedWorkerMaterialNearSignerWasm(args: {
  request: ThresholdEd25519DeleteSealedWorkerMaterialRequest;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519DeleteSealedWorkerMaterialResult> {
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519DeleteSealedWorkerMaterial,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: args.request,
    },
  });
  return requireThresholdEd25519DeleteSealedWorkerMaterialResult(response);
}

export async function createThresholdEd25519ClientPresignFromMaterialHandleWasm(args: {
  sessionId: string;
  clientParticipantId: number;
  relayerParticipantId: number;
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  groupPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignCreateResult> {
  assertWorkerMaterialSessionBindingEnvelope({
    sessionId: args.sessionId,
    expectedSessionBinding: args.expectedSessionBinding,
    operation: 'ThresholdEd25519ClientPresignCreateFromMaterialHandle',
  });
  const expectedSessionBindingDigest =
    await digestRouterAbEd25519WorkerMaterialSessionBinding(args.expectedSessionBinding);
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
        expectedMaterialBinding: args.expectedMaterialBinding,
        expectedSessionBinding: args.expectedSessionBinding,
        expectedSessionBindingDigest,
        groupPublicKey: args.groupPublicKey,
      },
    },
  });
  return requireThresholdEd25519ClientPresignCreateResult(response);
}

export async function signThresholdEd25519ClientPresignFromMaterialHandleWasm(args: {
  sessionId: string;
  clientParticipantId: number;
  relayerParticipantId: number;
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  groupPublicKey: string;
  signingDigestB64u: string;
  clientNonceHandleB64u: string;
  clientCommitments: { hiding: string; binding: string };
  relayerCommitments: { hiding: string; binding: string };
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519ClientPresignSignResult> {
  assertWorkerMaterialSessionBindingEnvelope({
    sessionId: args.sessionId,
    expectedSessionBinding: args.expectedSessionBinding,
    operation: 'ThresholdEd25519ClientPresignSignFromMaterialHandle',
  });
  const expectedSessionBindingDigest =
    await digestRouterAbEd25519WorkerMaterialSessionBinding(args.expectedSessionBinding);
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
        expectedMaterialBinding: args.expectedMaterialBinding,
        expectedSessionBinding: args.expectedSessionBinding,
        expectedSessionBindingDigest,
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

export async function createThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandleNearSignerWasm(args: {
  sessionId: string;
  materialHandle: string;
  expectedMaterialBinding: ThresholdEd25519WorkerMaterialBinding;
  expectedSessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  groupPublicKey: string;
  serverVerifyingShareB64u: string;
  serverCommitments: { hiding: string; binding: string };
  signingDigestB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519RoleSeparatedNormalSigningClientShareResult> {
  assertWorkerMaterialSessionBindingEnvelope({
    sessionId: args.sessionId,
    expectedSessionBinding: args.expectedSessionBinding,
    operation: 'ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle',
  });
  const expectedSessionBindingDigest =
    await digestRouterAbEd25519WorkerMaterialSessionBinding(args.expectedSessionBinding);
  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'nearSigner',
    request: {
      sessionId: args.sessionId,
      type: NearSignerWorkerCustomRequestType.ThresholdEd25519RoleSeparatedNormalSigningClientShareFromMaterialHandle,
      timeoutMs: NEAR_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: args.materialHandle,
        expectedMaterialBinding: args.expectedMaterialBinding,
        expectedSessionBinding: args.expectedSessionBinding,
        expectedSessionBindingDigest,
        groupPublicKey: args.groupPublicKey,
        serverVerifyingShareB64u: args.serverVerifyingShareB64u,
        serverCommitments: args.serverCommitments,
        signingDigestB64u: args.signingDigestB64u,
      },
    },
  });
  return requireThresholdEd25519RoleSeparatedNormalSigningClientShareResult(response);
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

function requireThresholdEd25519WorkerMaterialResult(
  value: unknown,
): ThresholdEd25519WorkerMaterialResult | ThresholdEd25519WorkerMaterialFailure {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  return requireThresholdEd25519WorkerMaterialSuccessResult(value);
}

function requireThresholdEd25519WorkerMaterialSuccessResult(
  value: unknown,
): ThresholdEd25519WorkerMaterialResult {
  const parsed = value as ThresholdEd25519WorkerMaterialResult;
  if (!parsed?.materialHandle || !parsed.clientVerifyingShareB64u || !parsed.bindingDigest) {
    throw new Error('near signer worker returned invalid Ed25519 worker material result');
  }
  return parsed;
}

function requireThresholdEd25519WorkerMaterialStoredResult(
  value: unknown,
): ThresholdEd25519StoreWorkerMaterialFromHssOutputResult {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  const parsed = value as ThresholdEd25519WorkerMaterialStoredResult;
  if (
    parsed?.ok !== true ||
    !parsed.materialHandle ||
    !parsed.materialBindingDigest ||
    !parsed.clientVerifyingShareB64u ||
    !parsed.sealedWorkerMaterialRef ||
    !parsed.sealedWorkerMaterialB64u ||
    !parsed.materialFormatVersion ||
    !parsed.materialKeyId ||
    !parsed.signerSlot
  ) {
    throw new Error('near signer worker returned invalid Ed25519 stored material result');
  }
  return parsed;
}

function requireThresholdEd25519RestoreWorkerMaterialResult(
  value: unknown,
): ThresholdEd25519RestoreWorkerMaterialResult {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  const parsed = value as ThresholdEd25519RestoreWorkerMaterialResult;
  if (
    parsed?.ok !== true ||
    !parsed.materialHandle ||
    !parsed.materialBindingDigest ||
    !parsed.clientVerifyingShareB64u ||
    !parsed.sealedWorkerMaterialRef ||
    !parsed.sealedWorkerMaterialB64u ||
    !parsed.materialFormatVersion ||
    !parsed.materialKeyId ||
    !parsed.signerSlot
  ) {
    throw new Error('near signer worker returned invalid Ed25519 restore result');
  }
  return parsed;
}

function requireThresholdEd25519PrepareHssClientOutputMaskHandleResult(
  value: unknown,
): ThresholdEd25519PrepareHssClientOutputMaskHandleResult {
  const parsed = value as ThresholdEd25519PrepareHssClientOutputMaskHandleResult;
  if (
    parsed?.ok !== true ||
    !parsed.clientOutputMaskHandle ||
    !parsed.contextBindingB64u ||
    !Number.isSafeInteger(Number(parsed.expiresAtMs)) ||
    Number(parsed.expiresAtMs) <= 0 ||
    !Number.isSafeInteger(Number(parsed.remainingUses)) ||
    Number(parsed.remainingUses) <= 0
  ) {
    throw new Error('near signer worker returned invalid Ed25519 HSS output-mask handle result');
  }
  return parsed;
}

function requireThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult(
  value: unknown,
): ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult {
  const parsed = value as ThresholdEd25519PrepareWorkerMaterialUnsealAuthorizationResult;
  if (
    parsed?.ok !== true ||
    !parsed.unsealAuthorization ||
    typeof parsed.unsealAuthorization !== 'object' ||
    !('kind' in parsed.unsealAuthorization) ||
    !Number.isSafeInteger(Number(parsed.remainingUses)) ||
    Number(parsed.remainingUses) <= 0
  ) {
    throw new Error('near signer worker returned invalid Ed25519 unseal authorization result');
  }
  return parsed;
}

function requireThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult(
  value: unknown,
): ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult {
  const parsed = value as ThresholdEd25519PrepareWorkerMaterialSealAuthorizationResult;
  if (
    parsed?.ok !== true ||
    !parsed.materialKeyId ||
    !parsed.sealAuthorization ||
    typeof parsed.sealAuthorization !== 'object' ||
    !('kind' in parsed.sealAuthorization) ||
    !Number.isSafeInteger(Number(parsed.remainingUses)) ||
    Number(parsed.remainingUses) <= 0
  ) {
    throw new Error('near signer worker returned invalid Ed25519 seal authorization result');
  }
  return parsed;
}

function requireThresholdEd25519PutSealedWorkerMaterialResult(
  value: unknown,
): ThresholdEd25519PutSealedWorkerMaterialResult {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  const parsed = value as ThresholdEd25519PutSealedWorkerMaterialResult;
  if (parsed?.ok !== true || !parsed.sealedWorkerMaterialRef || !parsed.materialBindingDigest) {
    throw new Error('near signer worker returned invalid Ed25519 sealed material put result');
  }
  return parsed;
}

function requireThresholdEd25519ReadSealedWorkerMaterialResult(
  value: unknown,
): ThresholdEd25519ReadSealedWorkerMaterialResult {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  const parsed = value as ThresholdEd25519ReadSealedWorkerMaterialResult;
  if (
    parsed?.ok !== true ||
    !parsed.sealedMaterial ||
    typeof parsed.sealedMaterial !== 'object' ||
    !parsed.sealedMaterial.materialBindingDigest
  ) {
    throw new Error('near signer worker returned invalid Ed25519 sealed material read result');
  }
  return parsed;
}

function requireThresholdEd25519DeleteSealedWorkerMaterialResult(
  value: unknown,
): ThresholdEd25519DeleteSealedWorkerMaterialResult {
  if (isThresholdEd25519WorkerMaterialFailure(value)) return value;
  const parsed = value as ThresholdEd25519DeleteSealedWorkerMaterialResult;
  if (parsed?.ok !== true || typeof parsed.deleted !== 'boolean') {
    throw new Error('near signer worker returned invalid Ed25519 sealed material delete result');
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

function requireThresholdEd25519RoleSeparatedNormalSigningClientShareResult(
  value: unknown,
): ThresholdEd25519RoleSeparatedNormalSigningClientShareResult {
  const parsed = value as ThresholdEd25519RoleSeparatedNormalSigningClientShareResult;
  if (
    !parsed?.clientCommitments?.hiding ||
    !parsed.clientCommitments.binding ||
    !parsed.clientVerifyingShareB64u ||
    !parsed.clientSignatureShareB64u
  ) {
    throw new Error(
      'near signer worker returned invalid Ed25519 role-separated normal-signing client share result',
    );
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

function isThresholdEd25519WorkerMaterialFailure(
  value: unknown,
): value is ThresholdEd25519WorkerMaterialFailure {
  const parsed = value as ThresholdEd25519WorkerMaterialFailure | null;
  return (
    parsed?.ok === false &&
    isThresholdEd25519WorkerMaterialErrorCode(parsed.code) &&
    typeof parsed.message === 'string' &&
    parsed.message.trim().length > 0
  );
}

function isThresholdEd25519WorkerMaterialErrorCode(
  value: unknown,
): value is ThresholdEd25519WorkerMaterialFailure['code'] {
  switch (value) {
    case 'material_restore_required':
    case 'material_seal_authorization_required':
    case 'material_unseal_authorization_required':
    case 'material_restore_expired':
    case 'material_binding_mismatch':
    case 'material_scope_mismatch':
    case 'material_handle_not_loaded':
    case 'material_corrupt':
    case 'worker_unavailable':
      return true;
    default:
      return false;
  }
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
