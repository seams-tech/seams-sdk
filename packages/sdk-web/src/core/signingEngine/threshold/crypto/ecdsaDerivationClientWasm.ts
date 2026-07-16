import {
  requireEvmFamilySigningKeySlotId,
  type EvmFamilySigningKeySlotId,
} from '@shared/signing-lanes';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import {
  EcdsaDerivationClientCustomRequestType,
  EcdsaDerivationClientCustomResponseType,
  EcdsaOnlineClientRequestType,
  EcdsaOnlineClientResponseType,
  EcdsaPresignClientRequestType,
  EcdsaPresignClientResponseType,
  type EcdsaDerivationRoleLocalMaterialOperationRequest,
  type EcdsaDerivationRoleLocalMaterialOperationType,
  type EcdsaDerivationWorkerOperationRequest,
  type EcdsaDerivationWorkerOperationResult,
  type EcdsaDerivationWorkerOperationType,
  type EcdsaOnlineClientOperationMap,
  type EcdsaPresignClientOperationMap,
  type SignerWorkerOperationRequest,
  type SignerWorkerOperationResult,
  type StoreThresholdEcdsaRoleLocalSigningMaterialResult,
  type ThresholdEcdsaPresignAbortResult,
  type ThresholdEcdsaPresignProgressResult,
} from '../../workerManager/workerTypes';
import type { ThresholdSecp256k1Ecdsa2pTopologyV1 } from '@shared/threshold/secp256k1';
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
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
} from '../../session/identity/emailOtpEcdsaDerivationIdentity';

const ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS = 20_000;

export type EcdsaDerivationClientThresholdEcdsaPresignProgress = Omit<
  ThresholdEcdsaPresignProgressResult,
  'outgoingMessages' | 'presignatureBigR33'
> & {
  outgoingMessages: Uint8Array[];
  presignatureBigR33?: Uint8Array;
};

async function requestEcdsaDerivationRoleLocalMaterialOperation<
  T extends EcdsaDerivationRoleLocalMaterialOperationType,
>(args: {
  workerCtx: WorkerOperationContext;
  request: EcdsaDerivationRoleLocalMaterialOperationRequest<T>;
}): Promise<EcdsaDerivationWorkerOperationResult<T>> {
  type TransportType = Extract<T, EcdsaDerivationWorkerOperationType>;
  return (await executeWorkerOperation<'ecdsaDerivationClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'ecdsaDerivationClient',
    request: args.request as EcdsaDerivationWorkerOperationRequest<TransportType>,
  })) as EcdsaDerivationWorkerOperationResult<T>;
}

async function requestEcdsaPresignOperation<T extends keyof EcdsaPresignClientOperationMap>(args: {
  workerCtx: WorkerOperationContext;
  request: SignerWorkerOperationRequest<'ecdsaPresignClient', T>;
}): Promise<SignerWorkerOperationResult<'ecdsaPresignClient', T>> {
  return await executeWorkerOperation<'ecdsaPresignClient', T>({
    ctx: args.workerCtx,
    kind: 'ecdsaPresignClient',
    request: args.request,
  });
}

async function requestEcdsaOnlineOperation<T extends keyof EcdsaOnlineClientOperationMap>(args: {
  workerCtx: WorkerOperationContext;
  request: SignerWorkerOperationRequest<'ecdsaOnlineClient', T>;
}): Promise<SignerWorkerOperationResult<'ecdsaOnlineClient', T>> {
  return await executeWorkerOperation<'ecdsaOnlineClient', T>({
    ctx: args.workerCtx,
    kind: 'ecdsaOnlineClient',
    request: args.request,
  });
}

export type ThresholdEcdsaDerivationStableKeyContext = {
  walletId: WalletId;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  signingGrantId?: never;
  thresholdSessionId?: never;
};

declare const serverPlannedEcdsaDerivationContextBrand: unique symbol;

export type ServerPlannedEcdsaDerivationContext = ThresholdEcdsaDerivationStableKeyContext & {
  evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
  chainTarget: ThresholdEcdsaChainTarget;
  readonly [serverPlannedEcdsaDerivationContextBrand]: true;
};

export type ThresholdEcdsaDerivationRoleLocalClientContext =
  ThresholdEcdsaDerivationStableKeyContext;

function readThresholdEcdsaDerivationChainTarget(value: unknown): ThresholdEcdsaChainTarget {
  if (typeof value !== 'object' || value === null) {
    throw new Error('[email-otp-derivation] chainTarget is required');
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

function buildThresholdEcdsaDerivationStableKeyContext(input: {
  walletId: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): ThresholdEcdsaDerivationStableKeyContext {
  return {
    walletId: toWalletId(input.walletId),
    ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: toEcdsaDerivationSigningRootId(input.signingRootId),
    signingRootVersion: toEcdsaDerivationSigningRootVersion(input.signingRootVersion),
  };
}

export function parseServerPlannedEcdsaDerivationContext(input: {
  walletId: unknown;
  evmFamilySigningKeySlotId: unknown;
  chainTarget: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
}): ServerPlannedEcdsaDerivationContext {
  return {
    ...buildThresholdEcdsaDerivationStableKeyContext(input),
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(
      input.evmFamilySigningKeySlotId,
      'evmFamilySigningKeySlotId',
    ),
    chainTarget: readThresholdEcdsaDerivationChainTarget(input.chainTarget),
  } as ServerPlannedEcdsaDerivationContext;
}

export async function prepareEcdsaClientBootstrapCommandWasm(input: {
  command: GeneratedPrepareEcdsaClientBootstrapCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedPrepareEcdsaClientBootstrapOutput> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.PrepareThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess
  ) {
    throw new Error('PrepareThresholdEcdsaDerivationRoleLocalClientBootstrap failed');
  }

  return response.payload as GeneratedPrepareEcdsaClientBootstrapOutput;
}

export async function finalizeEcdsaClientBootstrapCommandWasm(input: {
  command: GeneratedFinalizeEcdsaClientBootstrapCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedFinalizeEcdsaClientBootstrapOutput> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrapSuccess
  ) {
    throw new Error('FinalizeThresholdEcdsaDerivationRoleLocalClientBootstrap failed');
  }

  return response.payload as GeneratedFinalizeEcdsaClientBootstrapOutput;
}

export async function buildEcdsaRoleLocalExportArtifactCommandWasm(input: {
  command: GeneratedBuildEcdsaRoleLocalExportArtifactCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedBuildEcdsaRoleLocalExportArtifactOutput> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.BuildThresholdEcdsaDerivationRoleLocalExportArtifact,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.BuildThresholdEcdsaDerivationRoleLocalExportArtifactSuccess
  ) {
    throw new Error('BuildThresholdEcdsaDerivationRoleLocalExportArtifact failed');
  }

  return response.payload as GeneratedBuildEcdsaRoleLocalExportArtifactOutput;
}

export async function storeEcdsaRoleLocalSigningMaterialWasm(input: {
  materialHandle: string;
  bindingDigest: string;
  stateBlob: GeneratedEcdsaRoleLocalReadyStateBlob;
  workerCtx: WorkerOperationContext;
}): Promise<StoreThresholdEcdsaRoleLocalSigningMaterialResult> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.StoreThresholdEcdsaRoleLocalSigningMaterial,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        bindingDigest: input.bindingDigest,
        stateBlob: input.stateBlob,
      },
    },
  });

  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.StoreThresholdEcdsaRoleLocalSigningMaterialSuccess
  ) {
    throw new Error('StoreThresholdEcdsaRoleLocalSigningMaterial failed');
  }

  return response.payload as StoreThresholdEcdsaRoleLocalSigningMaterialResult;
}

function asEcdsaDerivationPresignProgress(
  raw: ThresholdEcdsaPresignProgressResult,
): EcdsaDerivationClientThresholdEcdsaPresignProgress {
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
  topology: ThresholdSecp256k1Ecdsa2pTopologyV1;
  groupPublicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<EcdsaDerivationClientThresholdEcdsaPresignProgress> {
  const groupPublicKey33 = input.groupPublicKey33.slice();
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.SessionInit,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        authority: {
          kind: 'role_local_derivation_handle',
          materialHandle: input.materialHandle,
          expectedBindingDigest: input.expectedBindingDigest,
        },
        sessionId: input.sessionId,
        topology: input.topology,
        groupPublicKey33: groupPublicKey33.buffer,
      },
      transfer: [groupPublicKey33.buffer],
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.SessionInitSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionInitFromMaterialHandle failed');
  }
  if (response.payload.authority.kind !== 'role_local_derivation_handle') {
    throw new Error('ECDSA role-local presign returned a different authority');
  }
  return asEcdsaDerivationPresignProgress(response.payload.progress);
}

export async function thresholdEcdsaEmailOtpPresignSessionInitWasm(input: {
  emailOtpSessionId: string;
  sessionId: string;
  topology: ThresholdSecp256k1Ecdsa2pTopologyV1;
  groupPublicKey33: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<{
  progress: EcdsaDerivationClientThresholdEcdsaPresignProgress;
  remainingUses: number;
  expiresAtMs: number;
}> {
  const groupPublicKey33 = input.groupPublicKey33.slice();
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.SessionInit,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        authority: {
          kind: 'email_otp_worker_session',
          emailOtpSessionId: input.emailOtpSessionId,
        },
        sessionId: input.sessionId,
        topology: input.topology,
        groupPublicKey33: groupPublicKey33.buffer,
      },
      transfer: [groupPublicKey33.buffer],
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.SessionInitSuccess) {
    throw new Error('Email OTP ECDSA presign initialization failed');
  }
  const authority = response.payload.authority;
  if (authority.kind !== 'email_otp_worker_session') {
    throw new Error('Email OTP ECDSA presign returned a different authority');
  }
  return {
    progress: asEcdsaDerivationPresignProgress(response.payload.progress),
    remainingUses: authority.remainingUses,
    expiresAtMs: authority.expiresAtMs,
  };
}

export async function thresholdEcdsaRoleLocalPresignSessionStepWasm(input: {
  sessionId: string;
  stage: 'triples' | 'presign';
  incomingMessages: Uint8Array[];
  workerCtx: WorkerOperationContext;
}): Promise<EcdsaDerivationClientThresholdEcdsaPresignProgress> {
  const incomingMessages = input.incomingMessages.map((entry) => entry.slice());
  const transfer = incomingMessages.map((entry) => entry.buffer);
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.SessionStep,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        sessionId: input.sessionId,
        stage: input.stage,
        incomingMessages: incomingMessages.map((entry) => entry.buffer),
      },
      transfer,
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.SessionStepSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalPresignSessionStep failed');
  }
  return asEcdsaDerivationPresignProgress(response.payload);
}

export async function thresholdEcdsaRoleLocalPresignSessionAbortWasm(input: {
  sessionId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.SessionAbort,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: { sessionId: input.sessionId },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.SessionAbortSuccess) {
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
  const response = await requestEcdsaOnlineOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaOnlineClientRequestType.ComputeSignatureShare,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
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
  if (response.type !== EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle failed');
  }
  return new Uint8Array(response.payload);
}
