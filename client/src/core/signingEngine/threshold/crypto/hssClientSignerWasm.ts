import {
  WorkerRequestType,
  WorkerResponseType,
  type WasmBuildThresholdEd25519SeedExportArtifactResult,
  type WasmDeriveThresholdEd25519HssClientInputsResult,
  type WasmFinalizeThresholdEcdsaHssClientRequestResult,
  type WasmOpenThresholdEd25519HssClientOutputResult,
  type WasmOpenThresholdEd25519HssSeedOutputResult,
  type WasmPrepareThresholdEcdsaHssClientRequestResult,
  type WasmPrepareThresholdEcdsaHssSessionResult,
  type WasmPrepareThresholdEd25519HssClientRequestResult,
  type WasmPrepareThresholdEd25519HssSessionResult,
} from '@/core/types/signer-worker';
import {
  executeWorkerOperation,
  type WorkerOperationContext,
} from '../../workerManager/executeWorkerOperation';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
  type WalletSubjectId,
} from '../../interfaces/ecdsaChainTarget';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
  toEcdsaHssWalletSubjectId,
  toWalletSessionUserId,
  type EcdsaThresholdKeyId,
  type SigningRootId,
  type SigningRootVersion,
  type WalletSessionUserId,
} from '../../session/identity/emailOtpHssIdentity';

const HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS = 20_000;

export type ThresholdEd25519HssCanonicalContext = {
  signingRootId: string;
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

export type ThresholdEd25519HssPreparedSessionEnvelope = {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
};

export type ThresholdEd25519HssClientRequestEnvelope = {
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
  clientOutputMessageB64u: string;
  seedOutputMessageB64u?: string;
};

export type ThresholdEd25519HssOpenedClientOutput = {
  contextBindingB64u: string;
  xClientBaseB64u: string;
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
  walletSessionUserId: WalletSessionUserId;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: SigningRootId;
  signingRootVersion: SigningRootVersion;
  walletSigningSessionId?: never;
  thresholdSessionId?: never;
  keyPurpose: string;
  keyVersion: string;
};

declare const serverPlannedEcdsaHssContextBrand: unique symbol;

export type ServerPlannedEcdsaHssContext = ThresholdEcdsaHssStableKeyContext & {
  readonly [serverPlannedEcdsaHssContextBrand]: true;
};

export type ThresholdEcdsaHssPreparedSessionEnvelope = {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
};

export type ThresholdEcdsaHssClientRequestEnvelope = {
  clientEvalRequestB64u: string;
};

export type ThresholdEcdsaHssClientFinalizeEnvelope = {
  clientEvalFinalizeB64u: string;
};

function buildThresholdEcdsaClientRootSharePayload(args: {
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
}): { clientRootShare32: Uint8Array } | { clientRootShare32B64u: string } {
  if (args.clientRootShare32 instanceof Uint8Array) {
    if (args.clientRootShare32.length !== 32) {
      throw new Error('clientRootShare32 must be 32 bytes');
    }
    return {
      clientRootShare32: Uint8Array.from(args.clientRootShare32),
    };
  }

  const clientRootShare32B64u = String(args.clientRootShare32B64u || '').trim();
  if (!clientRootShare32B64u) {
    throw new Error('Missing clientRootShare32');
  }
  return { clientRootShare32B64u };
}

function zeroizeThresholdEcdsaClientRootSharePayload(
  payload: { clientRootShare32: Uint8Array } | { clientRootShare32B64u: string },
): void {
  if ('clientRootShare32' in payload) {
    payload.clientRootShare32.fill(0);
  }
}

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
  walletSessionUserId: unknown;
  subjectId: unknown;
  chainTarget: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  keyPurpose: unknown;
  keyVersion: unknown;
}): ThresholdEcdsaHssStableKeyContext {
  const keyPurpose = String(input.keyPurpose || '').trim();
  const keyVersion = String(input.keyVersion || '').trim();
  if (!keyPurpose) throw new Error('[email-otp-hss] keyPurpose is required');
  if (!keyVersion) throw new Error('[email-otp-hss] keyVersion is required');
  return {
    walletSessionUserId: toWalletSessionUserId(input.walletSessionUserId),
    subjectId: toEcdsaHssWalletSubjectId(input.subjectId),
    chainTarget: readThresholdEcdsaHssChainTarget(input.chainTarget),
    ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId(input.ecdsaThresholdKeyId),
    signingRootId: toEcdsaHssSigningRootId(input.signingRootId),
    signingRootVersion: toEcdsaHssSigningRootVersion(input.signingRootVersion),
    keyPurpose,
    keyVersion,
  };
}

export function parseServerPlannedEcdsaHssContext(input: {
  walletSessionUserId: unknown;
  subjectId: unknown;
  chainTarget: unknown;
  ecdsaThresholdKeyId: unknown;
  signingRootId: unknown;
  signingRootVersion: unknown;
  keyPurpose: unknown;
  keyVersion: unknown;
}): ServerPlannedEcdsaHssContext {
  // Provider subjects authorize Email OTP enrollment. Wallet/session IDs scope
  // HSS audit and session policy. Server prepare owns ECDSA HSS key context.
  return buildThresholdEcdsaHssStableKeyContext(input) as ServerPlannedEcdsaHssContext;
}

export async function deriveThresholdEd25519HssClientInputsWasm(args: {
  sessionId: string;
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  prfFirstB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<{
  signingRootId: string;
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
  const signingRootId = String(args.signingRootId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const keyPurpose = String(args.keyPurpose || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const participantIds = Array.isArray(args.participantIds)
    ? args.participantIds.map((value) => Number(value))
    : [];
  const derivationVersion = Number(args.derivationVersion);

  if (!sessionId) throw new Error('Missing sessionId');
  if (!signingRootId) throw new Error('Missing signingRootId');
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
        signingRootId,
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
    signingRootId: String(wasmResult?.signingRootId || signingRootId).trim(),
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
        signingRootId: input.context.signingRootId,
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
  finalizedReport: { seedOutputMessageB64u: string };
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

export async function prepareThresholdEcdsaHssSessionWasm(input: {
  context: ServerPlannedEcdsaHssContext;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaHssPreparedSessionEnvelope> {
  const clientRootSharePayload = buildThresholdEcdsaClientRootSharePayload(input);
  try {
    const response = await executeWorkerOperation({
      ctx: input.workerCtx,
      kind: 'hssClient',
      request: {
        type: WorkerRequestType.PrepareThresholdEcdsaHssSession,
        timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
        payload: {
          walletSessionUserId: input.context.walletSessionUserId,
          subjectId: input.context.subjectId,
          chainTarget: thresholdEcdsaChainTargetKey(input.context.chainTarget),
          ecdsaThresholdKeyId: input.context.ecdsaThresholdKeyId,
          signingRootId: input.context.signingRootId,
          signingRootVersion: input.context.signingRootVersion,
          keyPurpose: input.context.keyPurpose,
          keyVersion: input.context.keyVersion,
          ...clientRootSharePayload,
        },
      },
    });

    if (response.type !== WorkerResponseType.PrepareThresholdEcdsaHssSessionSuccess) {
      throw new Error('PrepareThresholdEcdsaHssSession failed');
    }

    const result = response.payload as WasmPrepareThresholdEcdsaHssSessionResult;
    return {
      contextBindingB64u: String(result.contextBindingB64u || '').trim(),
      evaluatorDriverStateB64u: String(result.evaluatorDriverStateB64u || '').trim(),
    };
  } finally {
    zeroizeThresholdEcdsaClientRootSharePayload(clientRootSharePayload);
  }
}

export async function prepareThresholdEcdsaHssClientRequestWasm(input: {
  evaluatorDriverStateB64u: string;
  serverAssistInitMessageB64u: string;
  clientRootShare32?: Uint8Array;
  clientRootShare32B64u?: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaHssClientRequestEnvelope> {
  const clientRootSharePayload = buildThresholdEcdsaClientRootSharePayload(input);
  try {
    const response = await executeWorkerOperation({
      ctx: input.workerCtx,
      kind: 'hssClient',
      request: {
        type: WorkerRequestType.PrepareThresholdEcdsaHssClientRequest,
        timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
        payload: {
          evaluatorDriverStateB64u: input.evaluatorDriverStateB64u,
          serverAssistInitMessageB64u: input.serverAssistInitMessageB64u,
          ...clientRootSharePayload,
        },
      },
    });

    if (response.type !== WorkerResponseType.PrepareThresholdEcdsaHssClientRequestSuccess) {
      throw new Error('PrepareThresholdEcdsaHssClientRequest failed');
    }

    const result = response.payload as WasmPrepareThresholdEcdsaHssClientRequestResult;
    return {
      clientEvalRequestB64u: String(result.clientEvalRequestB64u || '').trim(),
    };
  } finally {
    zeroizeThresholdEcdsaClientRootSharePayload(clientRootSharePayload);
  }
}

export async function finalizeThresholdEcdsaHssClientRequestWasm(input: {
  evaluatorDriverStateB64u: string;
  serverEvalResponseB64u: string;
  workerCtx: WorkerOperationContext;
}): Promise<ThresholdEcdsaHssClientFinalizeEnvelope> {
  const response = await executeWorkerOperation({
    ctx: input.workerCtx,
    kind: 'hssClient',
    request: {
      type: WorkerRequestType.FinalizeThresholdEcdsaHssClientRequest,
      timeoutMs: HSS_CLIENT_SIGNER_WORKER_TIMEOUT_MS,
      payload: {
        evaluatorDriverStateB64u: input.evaluatorDriverStateB64u,
        serverEvalResponseB64u: input.serverEvalResponseB64u,
      },
    },
  });

  if (response.type !== WorkerResponseType.FinalizeThresholdEcdsaHssClientRequestSuccess) {
    throw new Error('FinalizeThresholdEcdsaHssClientRequest failed');
  }

  const result = response.payload as WasmFinalizeThresholdEcdsaHssClientRequestResult;
  return {
    clientEvalFinalizeB64u: String(result.clientEvalFinalizeB64u || '').trim(),
  };
}
