import {
  requireEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import {
  HssClientCustomRequestType,
  HssClientCustomResponseType,
  type HssEcdsaRoleLocalMaterialOperationRequest,
  type HssEcdsaRoleLocalMaterialOperationType,
  type HssEcdsaRoleLocalPresignOperationRequest,
  type HssEcdsaRoleLocalPresignOperationType,
  type HssWorkerOperationRequest,
  type HssWorkerOperationResult,
  type HssWorkerOperationType,
  type StoreThresholdEcdsaRoleLocalSigningMaterialResult,
  type ThresholdEcdsaPresignAbortResult,
  type ThresholdEcdsaPresignProgressResult,
} from '../../workerManager/workerTypes';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand as GeneratedBuildEcdsaRoleLocalExportArtifactCommand,
  BuildEcdsaRoleLocalExportArtifactOutput as GeneratedBuildEcdsaRoleLocalExportArtifactOutput,
  EcdsaRoleLocalReadyStateBlob as GeneratedEcdsaRoleLocalReadyStateBlob,
  FinalizeEcdsaClientBootstrapCommand as GeneratedFinalizeEcdsaClientBootstrapCommand,
  FinalizeEcdsaClientBootstrapOutput as GeneratedFinalizeEcdsaClientBootstrapOutput,
  PrepareEcdsaClientBootstrapCommand as GeneratedPrepareEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapOutput as GeneratedPrepareEcdsaClientBootstrapOutput,
} from '@/core/platform/generated/signerCoreCommands';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
  toWalletId,
  type WalletId,
} from '../../interfaces/ecdsaChainTarget';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
} from '../../session/identity/emailOtpHssIdentity';

const ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export type HssClientThresholdEcdsaPresignProgress = Omit<
  ThresholdEcdsaPresignProgressResult,
  'outgoingMessages' | 'presignatureBigR33'
> & {
  outgoingMessages: Uint8Array[];
  presignatureBigR33?: Uint8Array;
};

async function requestHssEcdsaRoleLocalMaterialOperation<
  T extends HssEcdsaRoleLocalMaterialOperationType,
>(args: {
  workerCtx: WorkerOperationContext;
  request: HssEcdsaRoleLocalMaterialOperationRequest<T>;
}): Promise<HssWorkerOperationResult<T>> {
  type TransportType = Extract<T, HssWorkerOperationType>;
  return (await executeWorkerOperation<'ecdsaHssClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'ecdsaHssClient',
    request: args.request as HssWorkerOperationRequest<TransportType>,
  })) as HssWorkerOperationResult<T>;
}

async function requestHssEcdsaRoleLocalPresignOperation<
  T extends HssEcdsaRoleLocalPresignOperationType,
>(args: {
  workerCtx: WorkerOperationContext;
  request: HssEcdsaRoleLocalPresignOperationRequest<T>;
}): Promise<HssWorkerOperationResult<T>> {
  type TransportType = Extract<T, HssWorkerOperationType>;
  return (await executeWorkerOperation<'ecdsaHssClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'ecdsaHssClient',
    request: args.request as HssWorkerOperationRequest<TransportType>,
  })) as HssWorkerOperationResult<T>;
}

export type ThresholdEcdsaHssStableKeyContext = {
  walletId: WalletId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  signingGrantId?: never;
  thresholdSessionId?: never;
};

declare const serverPlannedEcdsaHssContextBrand: unique symbol;

export type ServerPlannedEcdsaHssContext = ThresholdEcdsaHssStableKeyContext & {
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  readonly [serverPlannedEcdsaHssContextBrand]: true;
};

export type ThresholdEcdsaHssRoleLocalClientContext = ThresholdEcdsaHssStableKeyContext;

function readThresholdEcdsaHssChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  if (typeof value !== 'object' || value === null) {
    throw new Error('[email-otp-hss] chainTarget is required');
  }
  const record = value as Record<string, unknown>;
  return thresholdEcdsaChainTargetFromRequest({
    chain: record.chain,
    kind: record.kind,
    namespace: record.namespace,
    chainId: record.chainId,
    networkSlug: record.networkSlug,
  });
}

function buildThresholdEcdsaHssStableKeyContext(input: {
  walletId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): ThresholdEcdsaHssStableKeyContext {
  return {
    walletId: toWalletId(input.walletId),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: toEcdsaHssSigningRootId(input.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(input.signingRootVersion),
  };
}

export function parseServerPlannedEcdsaHssContext(input: {
  walletId: unknown;
  evmFamilySigningKeySlotId: unknown;
  chainTarget: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): ServerPlannedEcdsaHssContext {
  return {
    ...buildThresholdEcdsaHssStableKeyContext(input),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      input.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    chainTarget: readThresholdEcdsaHssChainTarget(input.chainTarget),
  } as ServerPlannedEcdsaHssContext;
}

export async function prepareEcdsaClientBootstrapCommandWasm(input: {
  command: GeneratedPrepareEcdsaClientBootstrapCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedPrepareEcdsaClientBootstrapOutput> {
  const response = await requestHssEcdsaRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    HssClientCustomResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess
  ) {
    throw new Error('PrepareThresholdEcdsaHssRoleLocalClientBootstrap failed');
  }

  return response.payload as GeneratedPrepareEcdsaClientBootstrapOutput;
}

export async function finalizeEcdsaClientBootstrapCommandWasm(input: {
  command: GeneratedFinalizeEcdsaClientBootstrapCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedFinalizeEcdsaClientBootstrapOutput> {
  const response = await requestHssEcdsaRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    HssClientCustomResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess
  ) {
    throw new Error('FinalizeThresholdEcdsaHssRoleLocalClientBootstrap failed');
  }

  return response.payload as GeneratedFinalizeEcdsaClientBootstrapOutput;
}

export async function buildEcdsaRoleLocalExportArtifactCommandWasm(input: {
  command: GeneratedBuildEcdsaRoleLocalExportArtifactCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedBuildEcdsaRoleLocalExportArtifactOutput> {
  const response = await requestHssEcdsaRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    HssClientCustomResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess
  ) {
    throw new Error('BuildThresholdEcdsaHssRoleLocalExportArtifact failed');
  }

  return response.payload as GeneratedBuildEcdsaRoleLocalExportArtifactOutput;
}

export async function storeEcdsaRoleLocalSigningMaterialWasm(input: {
  materialHandle: string;
  bindingDigest: string;
  stateBlob: GeneratedEcdsaRoleLocalReadyStateBlob;
  workerCtx: WorkerOperationContext;
}): Promise<StoreThresholdEcdsaRoleLocalSigningMaterialResult> {
  const response = await requestHssEcdsaRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        bindingDigest: input.bindingDigest,
        stateBlob: input.stateBlob,
      },
    },
  });

  if (
    response.type !== HssClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess
  ) {
    throw new Error('StoreThresholdEcdsaRoleLocalSigningMaterial failed');
  }

  return response.payload as StoreThresholdEcdsaRoleLocalSigningMaterialResult;
}

function asHssEcdsaPresignProgress(
  raw: ThresholdEcdsaPresignProgressResult,
): HssClientThresholdEcdsaPresignProgress {
  const outgoingMessages = Array.isArray(raw.outgoingMessages)
    ? raw.outgoingMessages.map((entry) => new Uint8Array(entry))
    : [];
  const presignatureHandle = String(raw.presignatureHandle || '').trim();
  const presignatureBigR33 = raw.presignatureBigR33
    ? new Uint8Array(raw.presignatureBigR33)
    : undefined;
  return {
    stage: raw.stage,
    event: raw.event,
    outgoingMessages,
    ...(presignatureHandle ? { presignatureHandle } : {}),
    ...(presignatureBigR33 ? { presignatureBigR33 } : {}),
  };
}

export async function thresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleWasm(input: {
  materialHandle: string;
  expectedBindingDigest: string;
  sessionId: string;
  participantIds: number[];
  clientParticipantId: number;
  threshold: number;
  groupPublicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<HssClientThresholdEcdsaPresignProgress> {
  const groupPublicKey33 = input.groupPublicKey33.slice();
  const response = await requestHssEcdsaRoleLocalPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        expectedBindingDigest: input.expectedBindingDigest,
        sessionId: input.sessionId,
        participantIds: [...input.participantIds],
        clientParticipantId: input.clientParticipantId,
        threshold: input.threshold,
        groupPublicKey33: groupPublicKey33.buffer,
      },
      transfer: [groupPublicKey33.buffer],
    },
  });
  if (
    response.type !==
    HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandleSuccess
  ) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle failed');
  }
  return asHssEcdsaPresignProgress(response.payload);
}

export async function thresholdEcdsaRoleLocalPresignSessionStepWasm(input: {
  sessionId: string;
  relayerParticipantId: number;
  stage: 'triples' | 'presign';
  incomingMessages: Uint8Array[];
  workerCtx: WorkerOperationContext;
}): Promise<HssClientThresholdEcdsaPresignProgress> {
  const incomingMessages = input.incomingMessages.map((entry) => entry.slice());
  const transfer = incomingMessages.map((entry) => entry.buffer);
  const response = await requestHssEcdsaRoleLocalPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionStep,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        sessionId: input.sessionId,
        relayerParticipantId: input.relayerParticipantId,
        stage: input.stage,
        incomingMessages: incomingMessages.map((entry) => entry.buffer),
      },
      transfer,
    },
  });
  if (
    response.type !== HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionStepSuccess
  ) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionStep failed');
  }
  return asHssEcdsaPresignProgress(response.payload);
}

export async function thresholdEcdsaRoleLocalPresignSessionAbortWasm(input: {
  sessionId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestHssEcdsaRoleLocalPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.ThresholdEcdsaRoleLocalPresignSessionAbort,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: { sessionId: input.sessionId },
    },
  });
  if (
    response.type !== HssClientCustomResponseType.ThresholdEcdsaRoleLocalPresignSessionAbortSuccess
  ) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionAbort failed');
  }
  const result = response.payload as ThresholdEcdsaPresignAbortResult;
  if (
    result.kind !== 'threshold_ecdsa_presign_session_aborted' ||
    result.sessionId !== input.sessionId
  ) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionAbort returned invalid result');
  }
}

export async function thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm(input: {
  materialHandle: string;
  participantIds: number[];
  clientParticipantId: number;
  groupPublicKey33: Uint8Array;
  expectedPresignBigR33: Uint8Array;
  digest32: Uint8Array;
  entropy32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const groupPublicKey33 = input.groupPublicKey33.slice();
  const expectedPresignBigR33 = input.expectedPresignBigR33.slice();
  const digest32 = input.digest32.slice();
  const entropy32 = input.entropy32.slice();
  const response = await requestHssEcdsaRoleLocalPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle,
      timeoutMs: ECDSA_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        participantIds: [...input.participantIds],
        clientParticipantId: input.clientParticipantId,
        groupPublicKey33: groupPublicKey33.buffer,
        expectedPresignBigR33: expectedPresignBigR33.buffer,
        digest32: digest32.buffer,
        entropy32: entropy32.buffer,
      },
      transfer: [
        groupPublicKey33.buffer,
        expectedPresignBigR33.buffer,
        digest32.buffer,
        entropy32.buffer,
      ],
    },
  });
  if (
    response.type !==
    HssClientCustomResponseType.ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleSuccess
  ) {
    throw new Error('ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle failed');
  }
  return new Uint8Array(response.payload);
}
