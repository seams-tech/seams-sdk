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
import type {
  CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaPostRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaPostRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaExplicitExportRequestV1,
  FinalizeRouterAbEcdsaExplicitExportResultV1,
  FinalizeRouterAbEcdsaRecoveryActivationRequestV1,
  FinalizeRouterAbEcdsaRecoveryActivationResultV1,
  VerifyRouterAbEcdsaRecoveryClientProofsRequestV1,
  VerifyRouterAbEcdsaRecoveryClientProofsResultV1,
  VerifyRouterAbEcdsaRefreshClientProofsRequestV1,
  VerifyRouterAbEcdsaRefreshClientProofsResultV1,
} from '../../workerManager/ecdsaClientWorkerChannels';
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
import {
  equalEcdsaClientPresignPoolIdentity,
  type EcdsaClientPresignPoolIdentity,
} from '../../workerManager/ecdsaPresignPoolIdentity';
import type {
  CloseRouterAbEcdsaRegistrationCeremonyRequestV1,
  CloseRouterAbEcdsaRegistrationCeremonyResultV1,
  CreateRouterAbEcdsaRegistrationCeremonyRequestV1,
  CreateRouterAbEcdsaRegistrationCeremonyResultV1,
  FinalizeRouterAbEcdsaRegistrationActivationRequestV1,
  FinalizeRouterAbEcdsaRegistrationActivationResultV1,
  VerifyRouterAbEcdsaRegistrationClientProofsRequestV1,
  VerifyRouterAbEcdsaRegistrationClientProofsResultV1,
} from '../../routerAb/ecdsaDerivation/clientCeremony';

const ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS = 20_000;

type ListedClientPresignature = {
  presignatureId: string;
  materialHandle: string;
  bigR33: Uint8Array;
  createdAtMs: number;
  expiresAtMs: number;
};

function parseListedClientPresignature(ref: {
  presignatureId: string;
  materialHandle: string;
  bigR33: ArrayBuffer;
  createdAtMs: number;
  expiresAtMs: number;
}): ListedClientPresignature {
  return {
    presignatureId: ref.presignatureId,
    materialHandle: ref.materialHandle,
    bigR33: new Uint8Array(ref.bigR33),
    createdAtMs: ref.createdAtMs,
    expiresAtMs: ref.expiresAtMs,
  };
}

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

export async function createRouterAbEcdsaRegistrationCeremonyWasm(input: {
  command: CreateRouterAbEcdsaRegistrationCeremonyRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<CreateRouterAbEcdsaRegistrationCeremonyResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaRegistrationCeremony,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaRegistrationCeremonySuccess
  ) {
    throw new Error('Router A/B ECDSA registration ceremony creation failed');
  }
  return response.payload;
}

export async function verifyRouterAbEcdsaRegistrationClientProofsWasm(input: {
  command: VerifyRouterAbEcdsaRegistrationClientProofsRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<VerifyRouterAbEcdsaRegistrationClientProofsResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRegistrationClientProofs,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRegistrationClientProofsSuccess
  ) {
    throw new Error('Router A/B ECDSA registration client proof verification failed');
  }
  return response.payload;
}

export async function finalizeRouterAbEcdsaRegistrationActivationWasm(input: {
  command: FinalizeRouterAbEcdsaRegistrationActivationRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<FinalizeRouterAbEcdsaRegistrationActivationResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRegistrationActivation,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRegistrationActivationSuccess
  ) {
    throw new Error('Router A/B ECDSA registration activation finalization failed');
  }
  return response.payload;
}

export async function closeRouterAbEcdsaRegistrationCeremonyWasm(input: {
  command: CloseRouterAbEcdsaRegistrationCeremonyRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<CloseRouterAbEcdsaRegistrationCeremonyResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaRegistrationCeremony,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaRegistrationCeremonySuccess
  ) {
    throw new Error('Router A/B ECDSA registration ceremony close failed');
  }
  return response.payload;
}

export async function createRouterAbEcdsaPostRegistrationCeremonyWasm(input: {
  command: CreateRouterAbEcdsaPostRegistrationCeremonyRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<CreateRouterAbEcdsaPostRegistrationCeremonyResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.CreateRouterAbEcdsaPostRegistrationCeremony,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.CreateRouterAbEcdsaPostRegistrationCeremonySuccess
  ) {
    throw new Error('Router A/B ECDSA post-registration ceremony creation failed');
  }
  return response.payload;
}

export async function finalizeRouterAbEcdsaExplicitExportWasm(input: {
  command: FinalizeRouterAbEcdsaExplicitExportRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<FinalizeRouterAbEcdsaExplicitExportResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type:
        EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaExplicitExport,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaExplicitExportSuccess
  ) {
    throw new Error('Router A/B ECDSA post-registration client proof finalization failed');
  }
  return response.payload;
}

export async function closeRouterAbEcdsaPostRegistrationCeremonyWasm(input: {
  command: CloseRouterAbEcdsaPostRegistrationCeremonyRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<CloseRouterAbEcdsaPostRegistrationCeremonyResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.CloseRouterAbEcdsaPostRegistrationCeremony,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.CloseRouterAbEcdsaPostRegistrationCeremonySuccess
  ) {
    throw new Error('Router A/B ECDSA post-registration ceremony close failed');
  }
  return response.payload;
}

export async function verifyRouterAbEcdsaRecoveryClientProofsWasm(input: {
  command: VerifyRouterAbEcdsaRecoveryClientProofsRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<VerifyRouterAbEcdsaRecoveryClientProofsResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRecoveryClientProofs,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRecoveryClientProofsSuccess
  ) {
    throw new Error('Router A/B ECDSA recovery client proof verification failed');
  }
  return response.payload;
}

export async function finalizeRouterAbEcdsaRecoveryActivationWasm(input: {
  command: FinalizeRouterAbEcdsaRecoveryActivationRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<FinalizeRouterAbEcdsaRecoveryActivationResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.FinalizeRouterAbEcdsaRecoveryActivation,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.FinalizeRouterAbEcdsaRecoveryActivationSuccess
  ) {
    throw new Error('Router A/B ECDSA recovery activation finalization failed');
  }
  return response.payload;
}

export async function verifyRouterAbEcdsaRefreshClientProofsWasm(input: {
  command: VerifyRouterAbEcdsaRefreshClientProofsRequestV1;
  workerCtx: WorkerOperationContext;
}): Promise<VerifyRouterAbEcdsaRefreshClientProofsResultV1> {
  const response = await requestEcdsaDerivationRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaDerivationClientCustomRequestType.VerifyRouterAbEcdsaRefreshClientProofs,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });
  if (
    response.type !==
    EcdsaDerivationClientCustomResponseType.VerifyRouterAbEcdsaRefreshClientProofsSuccess
  ) {
    throw new Error('Router A/B ECDSA refresh client proof verification failed');
  }
  return response.payload;
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
  durableMaterialRef: string;
  expectedBindingDigest: string;
  sessionId: string;
  groupPublicKey33: Uint8Array;
  materialExpiresAtMs: number;
  poolIdentity: EcdsaClientPresignPoolIdentity;
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
          durableMaterialRef: input.durableMaterialRef,
          expectedBindingDigest: input.expectedBindingDigest,
        },
        sessionId: input.sessionId,
        groupPublicKey33: groupPublicKey33.buffer,
        materialExpiresAtMs: input.materialExpiresAtMs,
        poolIdentity: input.poolIdentity,
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
  groupPublicKey33: Uint8Array;
  materialExpiresAtMs: number;
  poolIdentity: EcdsaClientPresignPoolIdentity;
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
        groupPublicKey33: groupPublicKey33.buffer,
        materialExpiresAtMs: input.materialExpiresAtMs,
        poolIdentity: input.poolIdentity,
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

export async function thresholdEcdsaRoleLocalAdmitPresignatureWasm(input: {
  materialHandle: string;
  expectedPresignatureId: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.Admit,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        expectedPresignatureId: input.expectedPresignatureId,
        poolIdentity: input.poolIdentity,
      },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.AdmitSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalAdmitPresignature failed');
  }
  if (
    response.payload.kind !== 'ecdsa_client_presignature_admitted_v1' ||
    response.payload.materialHandle !== input.materialHandle ||
    response.payload.presignatureId !== input.expectedPresignatureId
  ) {
    throw new Error('ThresholdEcdsaRoleLocalAdmitPresignature returned invalid binding');
  }
}

export async function thresholdEcdsaRoleLocalDestroyPresignatureWasm(input: {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.Destroy,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: { materialHandle: input.materialHandle, poolIdentity: input.poolIdentity },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.DestroySuccess) {
    throw new Error('ThresholdEcdsaRoleLocalDestroyPresignature failed');
  }
  if (
    response.payload.kind !== 'ecdsa_client_presignature_destroyed_v1' ||
    response.payload.materialHandle !== input.materialHandle
  ) {
    throw new Error('ThresholdEcdsaRoleLocalDestroyPresignature returned invalid handle');
  }
}

export async function thresholdEcdsaRoleLocalReservePresignatureWasm(input: {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  requestBinding: string;
  reservationId: string;
  leaseExpiresAtMs: number;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.Reserve,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        poolIdentity: input.poolIdentity,
        requestBinding: input.requestBinding,
        reservationId: input.reservationId,
        leaseExpiresAtMs: input.leaseExpiresAtMs,
      },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.ReserveSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalReservePresignature failed');
  }
}

export async function thresholdEcdsaRoleLocalCommitPresignatureWasm(input: {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  requestBinding: string;
  reservationId: string;
  workerCtx: WorkerOperationContext;
}): Promise<void> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.Commit,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        poolIdentity: input.poolIdentity,
        requestBinding: input.requestBinding,
        reservationId: input.reservationId,
      },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.CommitSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalCommitPresignature failed');
  }
}

export async function thresholdEcdsaRoleLocalListAvailablePresignaturesWasm(input: {
  poolIdentity: EcdsaClientPresignPoolIdentity;
  workerCtx: WorkerOperationContext;
}): Promise<ListedClientPresignature[]> {
  const response = await requestEcdsaPresignOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaPresignClientRequestType.ListAvailable,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: { poolIdentity: input.poolIdentity },
    },
  });
  if (response.type !== EcdsaPresignClientResponseType.ListAvailableSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalListAvailablePresignatures failed');
  }
  return response.payload.map(parseListedClientPresignature);
}

export async function thresholdEcdsaRoleLocalRetirePresignaturePoolWasm(input: {
  poolIdentity: EcdsaClientPresignPoolIdentity;
  reason: 'key_epoch_retired' | 'activation_epoch_retired';
  workerCtx: WorkerOperationContext;
}): Promise<number> {
  const response = await requestEcdsaOnlineOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaOnlineClientRequestType.RetirePool,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: { poolIdentity: input.poolIdentity, reason: input.reason },
    },
  });
  if (response.type !== EcdsaOnlineClientResponseType.RetirePoolSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalRetirePresignaturePool failed');
  }
  if (
    response.payload.kind !== 'ecdsa_client_presignature_pool_retired_v1' ||
    response.payload.reason !== input.reason ||
    !equalEcdsaClientPresignPoolIdentity(response.payload.poolIdentity, input.poolIdentity) ||
    !Number.isSafeInteger(response.payload.retiredCount) ||
    response.payload.retiredCount < 0
  ) {
    throw new Error('ThresholdEcdsaRoleLocalRetirePresignaturePool returned invalid receipt');
  }
  return response.payload.retiredCount;
}

export async function thresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandleWasm(input: {
  materialHandle: string;
  poolIdentity: EcdsaClientPresignPoolIdentity;
  requestBinding: string;
  reservationId: string;
  groupPublicKey33: Uint8Array;
  expectedPresignBigR33: Uint8Array;
  digest32: Uint8Array;
  clientRerandomizationContribution32: Uint8Array;
  signingWorkerRerandomizationContribution32: Uint8Array;
  workerCtx: WorkerOperationContext;
}): Promise<Uint8Array> {
  const groupPublicKey33 = input.groupPublicKey33.slice();
  const expectedPresignBigR33 = input.expectedPresignBigR33.slice();
  const digest32 = input.digest32.slice();
  const clientRerandomizationContribution32 = input.clientRerandomizationContribution32.slice();
  const signingWorkerRerandomizationContribution32 =
    input.signingWorkerRerandomizationContribution32.slice();
  const response = await requestEcdsaOnlineOperation({
    workerCtx: input.workerCtx,
    request: {
      type: EcdsaOnlineClientRequestType.ComputeSignatureShare,
      timeoutMs: ECDSA_DERIVATION_CLIENT_WORKER_TIMEOUT_MS,
      payload: {
        materialHandle: input.materialHandle,
        poolIdentity: input.poolIdentity,
        requestBinding: input.requestBinding,
        reservationId: input.reservationId,
        groupPublicKey33: groupPublicKey33.buffer,
        expectedPresignBigR33: expectedPresignBigR33.buffer,
        digest32: digest32.buffer,
        clientRerandomizationContribution32: clientRerandomizationContribution32.buffer,
        signingWorkerRerandomizationContribution32:
          signingWorkerRerandomizationContribution32.buffer,
      },
      transfer: [
        groupPublicKey33.buffer,
        expectedPresignBigR33.buffer,
        digest32.buffer,
        clientRerandomizationContribution32.buffer,
        signingWorkerRerandomizationContribution32.buffer,
      ],
    },
  });
  if (response.type !== EcdsaOnlineClientResponseType.ComputeSignatureShareSuccess) {
    throw new Error('ThresholdEcdsaRoleLocalComputeSignatureShareFromPresignatureHandle failed');
  }
  return new Uint8Array(response.payload);
}
