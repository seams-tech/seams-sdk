import {
  WorkerRequestType,
  WorkerResponseType,
  type WasmBuildThresholdEd25519SeedExportArtifactResult,
  type WasmDeriveThresholdEd25519HssClientInputsResult,
  type WasmDeriveThresholdEd25519HssPublicKeyResult,
  type WasmOpenThresholdEd25519HssClientOutputResult,
  type WasmOpenThresholdEd25519HssSeedOutputResult,
  type WasmPrepareThresholdEd25519HssClientRequestResult,
  type WasmPrepareThresholdEd25519HssSessionResult,
} from '@/core/types/signer-worker';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';

const HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export type ThresholdEd25519HssCanonicalContext = {
  orgId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
};

export type ThresholdEd25519HssClientInputs = {
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
};

export type ThresholdEd25519HssPreparedSessionEnvelope = ThresholdEd25519HssCanonicalContext & {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
};

export type ThresholdEd25519HssClientRequestEnvelope = {
  contextBindingB64u: string;
  clientRequestMessageB64u: string;
  evaluatorOtStateB64u: string;
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
  evaluationReportJson: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u: string;
  serverOutputMessageB64u: string;
};

export type ThresholdEd25519HssOpenedClientOutput = {
  contextBindingB64u: string;
  xClientBaseB64u: string;
};

export type ThresholdEd25519HssOpenedServerOutput = {
  contextBindingB64u: string;
  xRelayerBaseB64u: string;
};

export type ThresholdEd25519HssOpenedSeedOutput = {
  contextBindingB64u: string;
  canonicalSeedB64u: string;
};

export type ThresholdEd25519HssDerivedPublicKey = {
  publicKeyB64u: string;
};

export type ThresholdEd25519SeedExportArtifact = {
  artifactKind: string;
  seedB64u: string;
  publicKey: string;
  privateKey: string;
};

function normalizeParticipantIds(value: unknown): number[] {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    return Array.from(value as ArrayLike<number>, (entry) => Number(entry));
  }
  return [];
}

export async function deriveThresholdEd25519HssClientInputsWasm(args: {
  sessionId: string;
  orgId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  prfFirstB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<{
  orgId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
}> {
  const sessionId = String(args.sessionId || '').trim();
  const orgId = String(args.orgId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const keyPurpose = String(args.keyPurpose || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const participantIds = Array.isArray(args.participantIds)
    ? args.participantIds.map((value) => Number(value))
    : [];
  const derivationVersion = Number(args.derivationVersion);

  if (!sessionId) throw new Error('Missing sessionId');
  if (!orgId) throw new Error('Missing orgId');
  if (!nearAccountId) throw new Error('Missing nearAccountId');
  if (!keyPurpose) throw new Error('Missing keyPurpose');
  if (!keyVersion) throw new Error('Missing keyVersion');
  if (!prfFirstB64u) throw new Error('Missing prfFirstB64u');
  if (!Number.isInteger(derivationVersion) || derivationVersion < 0) {
    throw new Error('Invalid derivationVersion');
  }

  const response = await executeWorkerOperation({
    ctx: args.workerCtx,
    kind: 'hssClient',
    request: {
      sessionId,
      type: WorkerRequestType.DeriveThresholdEd25519HssClientInputs,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        orgId,
        nearAccountId,
        keyPurpose,
        keyVersion,
        participantIds,
        derivationVersion,
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
    orgId: String(wasmResult?.orgId || orgId).trim(),
    nearAccountId: String(wasmResult?.nearAccountId || nearAccountId).trim(),
    keyPurpose: String(wasmResult?.keyPurpose || keyPurpose).trim(),
    keyVersion: String(wasmResult?.keyVersion || keyVersion).trim(),
    participantIds: normalizedParticipantIds,
    derivationVersion: Number(wasmResult?.derivationVersion ?? derivationVersion),
    contextBindingB64u,
    yClientB64u,
    tauClientB64u,
  };
}

export async function prepareThresholdEd25519HssSessionWasm(input: {
  context: ThresholdEd25519HssCanonicalContext;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssPreparedSessionEnvelope> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.PrepareThresholdEd25519HssSession,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        orgId: input.context.orgId,
        nearAccountId: input.context.nearAccountId,
        keyPurpose: input.context.keyPurpose,
        keyVersion: input.context.keyVersion,
        participantIds: input.context.participantIds,
        derivationVersion: input.context.derivationVersion,
      },
    },
  });

  if (response.type !== WorkerResponseType.PrepareThresholdEd25519HssSessionSuccess) {
    throw new Error('PrepareThresholdEd25519HssSession failed');
  }

  const result = response.payload as WasmPrepareThresholdEd25519HssSessionResult;
  return {
    orgId: String(result.orgId || '').trim(),
    nearAccountId: String(result.nearAccountId || '').trim(),
    keyPurpose: String(result.keyPurpose || '').trim(),
    keyVersion: String(result.keyVersion || '').trim(),
    participantIds: normalizeParticipantIds(result.participantIds),
    derivationVersion: Number(result.derivationVersion),
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
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.PrepareThresholdEd25519HssClientRequest,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        evaluatorDriverStateB64u: input.evaluatorDriverStateB64u,
        clientOtOfferMessageB64u: input.clientOtOfferMessageB64u,
        yClientB64u: input.clientInputs.yClientB64u,
        tauClientB64u: input.clientInputs.tauClientB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.PrepareThresholdEd25519HssClientRequestSuccess) {
    throw new Error('PrepareThresholdEd25519HssClientRequest failed');
  }

  const result = response.payload as WasmPrepareThresholdEd25519HssClientRequestResult;
  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    clientRequestMessageB64u: String(result.clientRequestMessageB64u || '').trim(),
    evaluatorOtStateB64u: String(result.evaluatorOtStateB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssClientOutputWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateB64u'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'clientOutputMessageB64u'>;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssOpenedClientOutput> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.OpenThresholdEd25519HssClientOutput,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        evaluatorDriverStateB64u: input.preparedSession.evaluatorDriverStateB64u,
        clientOutputMessageB64u: input.finalizedReport.clientOutputMessageB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.OpenThresholdEd25519HssClientOutputSuccess) {
    throw new Error('OpenThresholdEd25519HssClientOutput failed');
  }

  const result = response.payload as WasmOpenThresholdEd25519HssClientOutputResult;
  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    xClientBaseB64u: String(result.xClientBaseB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssSeedOutputWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateB64u'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'seedOutputMessageB64u'>;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssOpenedSeedOutput> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.OpenThresholdEd25519HssSeedOutput,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        evaluatorDriverStateB64u: input.preparedSession.evaluatorDriverStateB64u,
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

export async function deriveThresholdEd25519HssPublicKeyWasm(input: {
  xClientBaseB64u: string;
  xRelayerBaseB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519HssDerivedPublicKey> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.DeriveThresholdEd25519HssPublicKey,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        xClientBaseB64u: input.xClientBaseB64u,
        xRelayerBaseB64u: input.xRelayerBaseB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.DeriveThresholdEd25519HssPublicKeySuccess) {
    throw new Error('DeriveThresholdEd25519HssPublicKey failed');
  }

  const result = response.payload as WasmDeriveThresholdEd25519HssPublicKeyResult;
  return {
    publicKeyB64u: String(result.publicKeyB64u || '').trim(),
  };
}

export async function buildThresholdEd25519SeedExportArtifactWasm(input: {
  seedB64u: string;
  expectedPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEd25519SeedExportArtifact> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
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
