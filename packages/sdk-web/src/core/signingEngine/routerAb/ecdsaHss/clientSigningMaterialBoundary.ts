import {
  mapAdditiveShareToThresholdSignaturesShare2pWasm,
  thresholdEcdsaPresignSessionAbortWasm,
  thresholdEcdsaComputeSignatureShareFromPresignatureHandleWasm,
  thresholdEcdsaPresignSessionInitWasm,
  thresholdEcdsaPresignSessionStepWasm,
  type ThresholdEcdsaPresignProgressWasm,
} from '../../chains/evm/ethSignerWasm';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';

function zeroizeBytes(bytes?: Uint8Array | null): void {
  if (!(bytes instanceof Uint8Array)) return;
  bytes.fill(0);
}

export async function initRouterAbEcdsaHssClientPresignSessionFromAdditiveShare(args: {
  clientSigningShare32: Uint8Array;
  sessionId: string;
  participantIds: number[];
  clientParticipantId: number;
  threshold: number;
  groupPublicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  let clientThresholdSigningShare32: Uint8Array | null = null;
  try {
    clientThresholdSigningShare32 = await mapAdditiveShareToThresholdSignaturesShare2pWasm({
      additiveShare32: args.clientSigningShare32,
      participantId: args.clientParticipantId,
      workerCtx: args.workerCtx,
    });

    return await thresholdEcdsaPresignSessionInitWasm({
      sessionId: args.sessionId,
      participantIds: args.participantIds,
      clientParticipantId: args.clientParticipantId,
      threshold: args.threshold,
      clientThresholdSigningShare32,
      groupPublicKey33: args.groupPublicKey33,
      workerCtx: args.workerCtx,
    });
  } finally {
    zeroizeBytes(args.clientSigningShare32);
    zeroizeBytes(clientThresholdSigningShare32);
  }
}

export async function stepRouterAbEcdsaHssClientPresignSession(args: {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages: Uint8Array[];
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaPresignProgressWasm> {
  return await thresholdEcdsaPresignSessionStepWasm(args);
}

export async function abortRouterAbEcdsaHssClientPresignSession(args: {
  sessionId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  await thresholdEcdsaPresignSessionAbortWasm(args);
}

export async function computeRouterAbEcdsaHssClientSignatureShareFromPresignatureHandle(args: {
  materialHandle: string;
  participantIds: number[];
  clientParticipantId: number;
  groupPublicKey33: Uint8Array;
  expectedPresignBigR33: Uint8Array;
  digest32: Uint8Array;
  entropy32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  return await thresholdEcdsaComputeSignatureShareFromPresignatureHandleWasm(args);
}
