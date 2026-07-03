import {
  WorkerRequestType,
  WorkerResponseType,
  type WorkerResponseDiagnostics,
  type WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult,
  type WasmBuildThresholdEd25519SeedExportArtifactResult,
  type WasmDeriveThresholdEd25519HssClientInputsResult,
  type WasmOpenThresholdEd25519HssSeedOutputResult,
  type WasmPrepareThresholdEd25519HssClientRequestResult,
  type WasmPrepareThresholdEd25519HssSessionResult,
} from '@/core/types/signer-worker';
import { base64UrlDecode } from '@shared/utils/encoders';
import { requireEvmFamilySigningKeySlotId, type EvmFamilySigningKeySlotId } from '@shared/signing-lanes';
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
  type HssEd25519ProtocolOperationRequest,
  type HssEd25519ProtocolOperationType,
  type HssWorkerOperationRequest,
  type HssWorkerOperationResult,
  type HssWorkerOperationType,
  type BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleRequest,
  type PrepareThresholdEd25519HssClientOutputMaskHandleResult,
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

const HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export type HssClientThresholdEcdsaPresignProgress = Omit<
  ThresholdEcdsaPresignProgressResult,
  'outgoingMessages' | 'presignatureBigR33'
> & {
  outgoingMessages: Uint8Array[];
  presignatureBigR33?: Uint8Array;
};

function emitHssClientWorkerDiagnostics(
  operation: string,
  diagnostics: WorkerResponseDiagnostics | undefined,
): void {
  if (!diagnostics) return;
  console.info('[threshold-ed25519][client-worker] hss command diagnostics', {
    operation,
    diagnostics,
  });
}

function readFiniteDiagnosticsNumber(value: unknown): number | undefined {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : undefined;
}

function readDiagnosticsNumberRecord(value: unknown): Record<string, number> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const out: Record<string, number> = {};
  for (const [key, entry] of Object.entries(value)) {
    const numberValue = readFiniteDiagnosticsNumber(entry);
    if (numberValue === undefined) return undefined;
    out[key] = numberValue;
  }
  return out;
}

function readHssClientWorkerDiagnostics(response: unknown): WorkerResponseDiagnostics | undefined {
  if (!response || typeof response !== 'object') return undefined;
  const diagnostics = (response as { diagnostics?: unknown }).diagnostics;
  if (!diagnostics || typeof diagnostics !== 'object') return undefined;
  const value = diagnostics as Record<string, unknown>;
  if (value.kind !== 'worker_response_diagnostics_v1') return undefined;
  if (value.worker !== 'hssClient') return undefined;
  const requestType = readFiniteDiagnosticsNumber(value.requestType);
  const queueWaitMs = readFiniteDiagnosticsNumber(value.queueWaitMs);
  const wasmInitWaitMs = readFiniteDiagnosticsNumber(value.wasmInitWaitMs);
  const wasmCallMs = readFiniteDiagnosticsNumber(value.wasmCallMs);
  const totalMs = readFiniteDiagnosticsNumber(value.totalMs);
  const requestPayloadBytes = readFiniteDiagnosticsNumber(value.requestPayloadBytes);
  const responsePayloadBytes = readFiniteDiagnosticsNumber(value.responsePayloadBytes);
  const requestPayloadBreakdown = readDiagnosticsNumberRecord(value.requestPayloadBreakdown);
  const responsePayloadBreakdown = readDiagnosticsNumberRecord(value.responsePayloadBreakdown);
  const wasmOperationTimings = readDiagnosticsNumberRecord(value.wasmOperationTimings);
  if (
    requestType === undefined ||
    queueWaitMs === undefined ||
    wasmInitWaitMs === undefined ||
    wasmCallMs === undefined ||
    totalMs === undefined ||
    requestPayloadBytes === undefined ||
    responsePayloadBytes === undefined ||
    requestPayloadBreakdown === undefined ||
    responsePayloadBreakdown === undefined
  ) {
    return undefined;
  }
  return {
    kind: 'worker_response_diagnostics_v1',
    worker: 'hssClient',
    requestType,
    queueWaitMs,
    wasmInitWaitMs,
    wasmCallMs,
    totalMs,
    requestPayloadBytes,
    responsePayloadBytes,
    requestPayloadBreakdown,
    responsePayloadBreakdown,
    ...(wasmOperationTimings !== undefined ? { wasmOperationTimings } : {}),
  };
}

async function requestHssEd25519ProtocolOperation<T extends HssEd25519ProtocolOperationType>(args: {
  workerCtx: WorkerOperationContext;
  request: HssEd25519ProtocolOperationRequest<T>;
}): Promise<HssWorkerOperationResult<T>> {
  type TransportType = Extract<T, HssWorkerOperationType>;
  return (await executeWorkerOperation<'hssClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'hssClient',
    request: args.request as HssWorkerOperationRequest<TransportType>,
  })) as HssWorkerOperationResult<T>;
}

async function requestHssEcdsaRoleLocalMaterialOperation<
  T extends HssEcdsaRoleLocalMaterialOperationType,
>(args: {
  workerCtx: WorkerOperationContext;
  request: HssEcdsaRoleLocalMaterialOperationRequest<T>;
}): Promise<HssWorkerOperationResult<T>> {
  type TransportType = Extract<T, HssWorkerOperationType>;
  return (await executeWorkerOperation<'hssClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'hssClient',
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
  return (await executeWorkerOperation<'hssClient', TransportType>({
    ctx: args.workerCtx,
    kind: 'hssClient',
    request: args.request as HssWorkerOperationRequest<TransportType>,
  })) as HssWorkerOperationResult<T>;
}

export type ThresholdEd25519HssCanonicalContext = {
  applicationBindingDigestB64u: string;
  participantIds: number[];
};

function requireBase64UrlBytes(input: {
  fieldName: string;
  value: string;
  byteLength: number;
}): string {
  const normalized = String(input.value || '').trim();
  if (!normalized) {
    throw new Error(`${input.fieldName} is required`);
  }
  const decoded = base64UrlDecode(normalized);
  if (decoded.length !== input.byteLength) {
    throw new Error(`${input.fieldName} must decode to ${input.byteLength} bytes`);
  }
  decoded.fill(0);
  return normalized;
}

export type ThresholdEd25519HssClientInputs = {
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
};

export type ThresholdEd25519HssPreparedSessionEnvelope = {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
};

type ThresholdEd25519HssWorkerPreparedSession = {
  workerSessionHandle: string;
};

type ThresholdEd25519HssSerializedPreparedSession = Pick<
  ThresholdEd25519HssPreparedSessionEnvelope,
  'evaluatorDriverStateB64u'
>;

type ThresholdEd25519HssWorkerSessionSource =
  | {
      sessionSource: 'worker_handle';
      workerSessionHandle: string;
      evaluatorDriverStateB64u?: never;
    }
  | {
      sessionSource: 'serialized_state';
      evaluatorDriverStateB64u: string;
      workerSessionHandle?: never;
    };

type ThresholdEd25519HssWorkerHandleSessionSource = Extract<
  ThresholdEd25519HssWorkerSessionSource,
  { sessionSource: 'worker_handle' }
>;

type ThresholdEd25519HssSerializedSessionSource = Extract<
  ThresholdEd25519HssWorkerSessionSource,
  { sessionSource: 'serialized_state' }
>;

function hssWorkerSessionSourceFromPreparedSession(
  preparedSession: ThresholdEd25519HssWorkerPreparedSession,
): ThresholdEd25519HssWorkerHandleSessionSource {
  const workerSessionHandle = String(preparedSession.workerSessionHandle || '').trim();
  if (!workerSessionHandle) {
    throw new Error('workerSessionHandle is required for Ed25519 HSS worker calls');
  }
  return {
    sessionSource: 'worker_handle',
    workerSessionHandle,
  };
}

function assertNeverHssClientSessionResidence(_value: never): never {
  throw new Error('Unexpected Ed25519 HSS client request session residence');
}

function hssSessionSourceFromClientRequest(input: {
  preparedSession: ThresholdEd25519HssSerializedPreparedSession;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): ThresholdEd25519HssWorkerSessionSource {
  switch (input.clientRequest.sessionResidence) {
    case 'worker_handle':
      return hssWorkerSessionSourceFromPreparedSession(input.clientRequest);
    case 'serialized_state':
      return hssSerializedSessionSourceFromPreparedSession(input.preparedSession);
    default:
      return assertNeverHssClientSessionResidence(input.clientRequest);
  }
}

function buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandlePayload(input: {
  sessionSource: ThresholdEd25519HssWorkerSessionSource;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputDelivery: Pick<
    ThresholdEd25519HssServerInputDeliveryEnvelope,
    'serverInputDeliveryB64u'
  >;
  clientOutputMaskHandle: string;
  expectedContextBindingB64u: string;
}): BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleRequest {
  const common = {
    clientRequestMessageB64u: input.clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: input.clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: input.serverInputDelivery.serverInputDeliveryB64u,
    clientOutputMaskHandle: String(input.clientOutputMaskHandle || '').trim(),
    expectedContextBindingB64u: String(input.expectedContextBindingB64u || '').trim(),
  };
  switch (input.sessionSource.sessionSource) {
    case 'worker_handle':
      return {
        sessionSource: 'worker_handle',
        workerSessionHandle: input.sessionSource.workerSessionHandle,
        clientRequestMessageB64u: common.clientRequestMessageB64u,
        evaluatorOtStateB64u: common.evaluatorOtStateB64u,
        serverInputDeliveryB64u: common.serverInputDeliveryB64u,
        clientOutputMaskHandle: common.clientOutputMaskHandle,
        expectedContextBindingB64u: common.expectedContextBindingB64u,
      };
    case 'serialized_state':
      return {
        sessionSource: 'serialized_state',
        evaluatorDriverStateB64u: input.sessionSource.evaluatorDriverStateB64u,
        clientRequestMessageB64u: common.clientRequestMessageB64u,
        evaluatorOtStateB64u: common.evaluatorOtStateB64u,
        serverInputDeliveryB64u: common.serverInputDeliveryB64u,
        clientOutputMaskHandle: common.clientOutputMaskHandle,
        expectedContextBindingB64u: common.expectedContextBindingB64u,
      };
    default:
      return assertNeverHssClientWorkerSessionSource(input.sessionSource);
  }
}

function assertNeverHssClientWorkerSessionSource(_value: never): never {
  throw new Error('Unexpected Ed25519 HSS worker session source');
}

function hssSerializedSessionSourceFromPreparedSession(
  preparedSession: ThresholdEd25519HssSerializedPreparedSession,
): ThresholdEd25519HssSerializedSessionSource {
  const evaluatorDriverStateB64u = String(preparedSession.evaluatorDriverStateB64u || '').trim();
  if (!evaluatorDriverStateB64u) {
    throw new Error('evaluatorDriverStateB64u is required for Ed25519 HSS serialized calls');
  }
  return {
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u,
  };
}

type ThresholdEd25519HssClientRequestEnvelopeBase = {
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
};

export type ThresholdEd25519HssClientRequestEnvelope =
  | (ThresholdEd25519HssClientRequestEnvelopeBase & {
      sessionResidence: 'worker_handle';
      workerSessionHandle: string;
    })
  | (ThresholdEd25519HssClientRequestEnvelopeBase & {
      sessionResidence: 'serialized_state';
      workerSessionHandle?: never;
    });

export type ThresholdEd25519HssServerVisibleClientRequestEnvelope = {
  clientRequestMessageB64u: string;
};

export type ThresholdEd25519HssServerInputDeliveryEnvelope = {
  contextBindingB64u: string;
  serverInputDeliveryB64u: string;
};

export type ThresholdEd25519HssServerAssistInitEnvelope = {
  contextBindingB64u: string;
  serverAssistInitMessageB64u: string;
};

export type ThresholdEd25519HssStagedEvaluatorArtifactEnvelope = {
  contextBindingB64u: string;
  stagedEvaluatorArtifactB64u: string;
};

export type ThresholdEd25519HssFinalizedReportEnvelope = {
  contextBindingB64u: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u?: string;
};

export type ThresholdEd25519HssOpenedSeedOutput = {
  contextBindingB64u: string;
  canonicalSeedB64u: string;
};

export type ThresholdEd25519SeedExportArtifact = {
  artifactKind: string;
  seedB64u: string;
  publicKey: string;
  privateKey: string;
};

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

function normalizeParticipantIds(value: unknown): number[] {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    return Array.from(value as ArrayLike<number>, (entry) => Number(entry));
  }
  return [];
}

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
    evmFamilySigningKeySlotId: requireEvmFamilySigningKeySlotId(input.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
    chainTarget: readThresholdEcdsaHssChainTarget(input.chainTarget),
  } as ServerPlannedEcdsaHssContext;
}

export async function deriveThresholdEd25519HssClientInputsWasm(args: {
  sessionId: string;
  applicationBindingDigestB64u: string;
  participantIds: number[];
  prfFirstB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<{
  applicationBindingDigestB64u: string;
  participantIds: number[];
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}> {
  const sessionId = String(args.sessionId || '').trim();
  const applicationBindingDigestB64u = requireBase64UrlBytes({
    fieldName: 'applicationBindingDigestB64u',
    value: args.applicationBindingDigestB64u,
    byteLength: 32,
  });
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const participantIds = Array.isArray(args.participantIds)
    ? args.participantIds.map((value) => Number(value))
    : [];

  if (!sessionId) throw new Error('Missing sessionId');
  if (!prfFirstB64u) throw new Error('Missing prfFirstB64u');

  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: args.workerCtx,
    request: {
      sessionId,
      type: WorkerRequestType.DeriveThresholdEd25519HssClientInputs,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        applicationBindingDigestB64u,
        participantIds,
        prfFirstB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.DeriveThresholdEd25519HssClientInputsSuccess) {
    throw new Error('DeriveThresholdEd25519HssClientInputs failed');
  }

  const wasmResult = response.payload as WasmDeriveThresholdEd25519HssClientInputsResult;
  const contextBindingB64u = String(wasmResult?.contextBindingB64u || '').trim();
  const yClientB64u = String(wasmResult?.yClientB64u || '').trim();
  const tauClientB64u = String(wasmResult?.tauClientB64u || '').trim();
  const normalizedParticipantIds = normalizeParticipantIds(wasmResult?.participantIds);

  if (!contextBindingB64u || !yClientB64u || !tauClientB64u) {
    throw new Error('Threshold Ed25519 HSS client input derivation returned incomplete data');
  }

  return {
    applicationBindingDigestB64u: String(
      wasmResult?.applicationBindingDigestB64u || applicationBindingDigestB64u,
    ).trim(),
    participantIds: normalizedParticipantIds,
    contextBindingB64u,
    yClientB64u,
    tauClientB64u,
  };
}

export async function prepareThresholdEd25519HssSessionWasm(input: {
  context: ThresholdEd25519HssCanonicalContext;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssPreparedSessionEnvelope> {
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: WorkerRequestType.PrepareThresholdEd25519HssSession,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        applicationBindingDigestB64u: input.context.applicationBindingDigestB64u,
        participantIds: input.context.participantIds,
      },
    },
  });

  if (response.type !== WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess) {
    throw new Error('PrepareThresholdEd25519HssSession failed');
  }
  emitHssClientWorkerDiagnostics('prepare_session', readHssClientWorkerDiagnostics(response));

  const result = response.payload as WasmPrepareThresholdEd25519HssSessionResult;
  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    evaluatorDriverStateB64u: String(result.evaluatorDriverStateB64u || '').trim(),
  };
}

export async function prepareThresholdEd25519HssClientRequestWasm(input: {
  evaluatorDriverStateB64u: string;
  clientOtOfferMessageB64u: string;
  clientInputs: ThresholdEd25519HssClientInputs;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssClientRequestEnvelope> {
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: WorkerRequestType.PrepareThresholdEd25519HssClientRequest,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        ...hssSerializedSessionSourceFromPreparedSession({
          evaluatorDriverStateB64u: input.evaluatorDriverStateB64u,
        }),
        clientOtOfferMessageB64u: input.clientOtOfferMessageB64u,
        yClientB64u: input.clientInputs.yClientB64u,
        tauClientB64u: input.clientInputs.tauClientB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess) {
    throw new Error('PrepareThresholdEd25519HssClientRequest failed');
  }
  emitHssClientWorkerDiagnostics(
    'prepare_client_request',
    readHssClientWorkerDiagnostics(response),
  );

  const result = response.payload as WasmPrepareThresholdEd25519HssClientRequestResult;
  const clientRequestBase = {
    clientRequestMessageB64u: String(result.clientRequestMessageB64u || '').trim(),
    evaluatorOtStateB64u: String(result.evaluatorOtStateB64u || '').trim(),
  };
  const workerSessionHandle = String(result.workerSessionHandle || '').trim();
  if (workerSessionHandle) {
    return {
      ...clientRequestBase,
      sessionResidence: 'worker_handle',
      workerSessionHandle,
    };
  }
  return {
    ...clientRequestBase,
    sessionResidence: 'serialized_state',
  };
}

export async function prepareThresholdEd25519HssClientOutputMaskHandleWasm(input: {
  clientRecoverableSecretB64u: string;
  context: ThresholdEd25519HssCanonicalContext & {
    contextBindingB64u: string;
    operation: string;
    relayerKeyId: string;
  };
  expiresAtMs: number;
  workerCtx: WorkerOperationContext;
}): Promise<PrepareThresholdEd25519HssClientOutputMaskHandleResult> {
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.PrepareThresholdEd25519HssClientOutputMaskHandle,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        applicationBindingDigestB64u: input.context.applicationBindingDigestB64u,
        participantIds: input.context.participantIds,
        contextBindingB64u: input.context.contextBindingB64u,
        operation: input.context.operation,
        relayerKeyId: input.context.relayerKeyId,
        clientRecoverableSecretB64u: input.clientRecoverableSecretB64u,
        expiresAtMs: input.expiresAtMs,
      },
    },
  });

  if (
    response.type !==
    HssClientCustomResponseType.PrepareThresholdEd25519HssClientOutputMaskHandleSuccess
  ) {
    throw new Error('PrepareThresholdEd25519HssClientOutputMaskHandle failed');
  }

  const result = response.payload as PrepareThresholdEd25519HssClientOutputMaskHandleResult;
  const clientOutputMaskHandle = String(result.clientOutputMaskHandle || '').trim();
  const contextBindingB64u = String(result.contextBindingB64u || '').trim();
  const expiresAtMs = Math.floor(Number(result.expiresAtMs));
  const remainingUses = Math.floor(Number(result.remainingUses));
  if (
    !clientOutputMaskHandle ||
    !contextBindingB64u ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0 ||
    remainingUses !== 1
  ) {
    throw new Error('Threshold Ed25519 HSS client output mask handle returned invalid data');
  }
  return {
    clientOutputMaskHandle,
    contextBindingB64u,
    expiresAtMs,
    remainingUses,
  };
}

export async function buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateB64u'>;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputDelivery: Pick<
    ThresholdEd25519HssServerInputDeliveryEnvelope,
    'serverInputDeliveryB64u'
  >;
  clientOutputMaskHandle: string;
  expectedContextBindingB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssStagedEvaluatorArtifactEnvelope> {
  const sessionSource = hssSessionSourceFromClientRequest({
    preparedSession: input.preparedSession,
    clientRequest: input.clientRequest,
  });
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: HssClientCustomRequestType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandlePayload({
        sessionSource,
        clientRequest: input.clientRequest,
        serverInputDelivery: input.serverInputDelivery,
        clientOutputMaskHandle: input.clientOutputMaskHandle,
        expectedContextBindingB64u: input.expectedContextBindingB64u,
      }),
    },
  });

  if (
    response.type !==
    HssClientCustomResponseType.BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandleSuccess
  ) {
    throw new Error(
      'BuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactFromMaskHandle failed',
    );
  }
  emitHssClientWorkerDiagnostics(
    'build_client_owned_staged_evaluator_artifact',
    readHssClientWorkerDiagnostics(response),
  );

  const result =
    response.payload as WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactResult;
  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    stagedEvaluatorArtifactB64u: String(result.stagedEvaluatorArtifactB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssSeedOutputWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateB64u'>;
  finalizedReport: { seedOutputMessageB64u: string };
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssOpenedSeedOutput> {
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: WorkerRequestType.OpenThresholdEd25519HssSeedOutput,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        ...hssSerializedSessionSourceFromPreparedSession(input.preparedSession),
        seedOutputMessageB64u: input.finalizedReport.seedOutputMessageB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.OpenThresholdEd25519HssSeedOutputSuccess) {
    throw new Error('OpenThresholdEd25519HssSeedOutput failed');
  }

  const result = response.payload as WasmOpenThresholdEd25519HssSeedOutputResult;
  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    canonicalSeedB64u: String(result.canonicalSeedB64u || '').trim(),
  };
}

export async function buildThresholdEd25519SeedExportArtifactWasm(input: {
  seedB64u: string;
  expectedPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519SeedExportArtifact> {
  const response = await requestHssEd25519ProtocolOperation({
    workerCtx: input.workerCtx,
    request: {
      type: WorkerRequestType.BuildThresholdEd25519SeedExportArtifact,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        seedB64u: input.seedB64u,
        expectedPublicKey: input.expectedPublicKey,
      },
    },
  });

  if (response.type !== WorkerResponseType.BuildThresholdEd25519SeedExportArtifactSuccess) {
    throw new Error('BuildThresholdEd25519SeedExportArtifact failed');
  }

  const result = response.payload as WasmBuildThresholdEd25519SeedExportArtifactResult;
  return {
    artifactKind: String(result.artifactKind || '').trim(),
    seedB64u: String(result.seedB64u || '').trim(),
    publicKey: String(result.publicKey || '').trim(),
    privateKey: String(result.privateKey || '').trim(),
  };
}

export async function prepareEcdsaClientBootstrapCommandWasm(input: {
  command: GeneratedPrepareEcdsaClientBootstrapCommand;
  workerCtx: WorkerOperationContext;
}): Promise<GeneratedPrepareEcdsaClientBootstrapOutput> {
  const response = await requestHssEcdsaRoleLocalMaterialOperation({
    workerCtx: input.workerCtx,
    request: {
      type: WorkerRequestType.PrepareThresholdEcdsaHssRoleLocalClientBootstrap,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !== WorkerResponseType.PrepareThresholdEcdsaHssRoleLocalClientBootstrapSuccess
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
      type: WorkerRequestType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrap,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (
    response.type !== WorkerResponseType.FinalizeThresholdEcdsaHssRoleLocalClientBootstrapSuccess
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
      type: WorkerRequestType.BuildThresholdEcdsaHssRoleLocalExportArtifact,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: input.command,
    },
  });

  if (response.type !== WorkerResponseType.BuildThresholdEcdsaHssRoleLocalExportArtifactSuccess) {
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
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
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
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
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
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
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
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
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
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
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
