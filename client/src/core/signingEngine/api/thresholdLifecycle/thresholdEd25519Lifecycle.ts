import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import { getPrfResultsFromCredential } from '../../signers/webauthn/credentials/credentialExtensions';
import type { NearSigningKeyOps } from '../../interfaces/nearKeyOps';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import { persistStoredThresholdEd25519SessionClientBase } from './thresholdSessionStore';
import {
  buildThresholdEd25519SeedExportArtifactWasm,
  openThresholdEd25519HssClientOutputWasm,
  openThresholdEd25519HssSeedOutputWasm,
  prepareThresholdEd25519HssClientRequestWasm,
  type ThresholdEd25519HssCanonicalContext,
  type ThresholdEd25519HssClientRequestEnvelope,
  type ThresholdEd25519HssClientInputs,
  type ThresholdEd25519HssFinalizedReportEnvelope,
  type ThresholdEd25519HssOpenedClientOutput,
  type ThresholdEd25519HssOpenedSeedOutput,
  type ThresholdEd25519HssPreparedSessionEnvelope,
  type ThresholdEd25519SeedExportArtifact,
} from '../../signers/wasm/hssClientSignerWasm';
import { THRESHOLD_ED25519_WRAP_KEY_SALT_B64U } from '../../threshold/ed25519WrapKeySalt';

export type ThresholdEd25519LifecycleDeps = {
  signingKeyOps: Pick<
    NearSigningKeyOps,
    'deriveThresholdEd25519ClientVerifyingShare' | 'deriveThresholdEd25519HssClientInputs'
  >;
  createSessionId: (prefix: string) => string;
  getSignerWorkerContext: () => WorkerOperationContext;
};

export type DeriveThresholdEd25519ClientVerifyingShareResult = {
  success: boolean;
  nearAccountId: string;
  clientVerifyingShareB64u: string;
  error?: string;
};

export type DeriveThresholdEd25519HssClientInputsResult = {
  success: boolean;
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
  error?: string;
};

export type PrepareThresholdEd25519HssClientCeremonyResult = {
  success: boolean;
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
  contextBindingB64u: string;
  yClientB64u: string;
  tauClientB64u: string;
  error?: string;
};

export type CompleteThresholdEd25519HssClientCeremonyResult = {
  success: boolean;
  contextBindingB64u: string;
  preparedSession?: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport?: ThresholdEd25519HssFinalizedReportEnvelope;
  clientOutput?: ThresholdEd25519HssOpenedClientOutput;
  persistedThresholdSessionId?: string;
  error?: string;
};

export type PrepareThresholdEd25519HssServerCeremonyWithSessionResult = {
  success: boolean;
  contextBindingB64u: string;
  ceremonyHandle?: string;
  preparedSession?: ThresholdEd25519HssPreparedSessionEnvelope;
  clientOtOfferMessageB64u?: string;
  error?: string;
};

export type ThresholdEd25519HssSessionOperation =
  | 'tx_signing'
  | 'link_device'
  | 'email_recovery'
  | 'warm_session_reconstruction'
  | 'explicit_key_export';

export type RespondThresholdEd25519HssServerCeremonyWithSessionResult = {
  success: boolean;
  contextBindingB64u: string;
  error?: string;
};

export type FinalizeThresholdEd25519HssServerCeremonyWithSessionResult = {
  success: boolean;
  contextBindingB64u: string;
  finalizedReport?: ThresholdEd25519HssFinalizedReportEnvelope;
  error?: string;
};

export type OpenThresholdEd25519HssSeedOutputResult = {
  success: boolean;
  contextBindingB64u: string;
  seedOutput?: ThresholdEd25519HssOpenedSeedOutput;
  error?: string;
};

export type BuildThresholdEd25519SeedExportArtifactResult = {
  success: boolean;
  contextBindingB64u: string;
  seedOutput?: ThresholdEd25519HssOpenedSeedOutput;
  artifact?: ThresholdEd25519SeedExportArtifact;
  error?: string;
};

function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, '');
}

function utf8Bytes(value: string): number {
  return new TextEncoder().encode(value).length;
}

function jsonBytes(value: unknown): number {
  return utf8Bytes(JSON.stringify(value));
}

function summarizePrepareRequestSize(args: {
  relayerKeyId: string;
  context: {
    signingRootId: string;
    nearAccountId: string;
    keyPurpose: string;
    keyVersion: string;
    participantIds: number[];
    derivationVersion: number;
  };
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
}): Record<string, number> {
  return {
    relayerKeyIdBytes: utf8Bytes(args.relayerKeyId),
    contextBytes: jsonBytes(args.context),
    preparedSessionBytes: jsonBytes(args.preparedSession),
    preparedSessionContextBindingBytes: utf8Bytes(args.preparedSession.contextBindingB64u),
    preparedSessionEvaluatorDriverStateBytes: utf8Bytes(
      args.preparedSession.evaluatorDriverStateB64u,
    ),
  };
}

function summarizeRespondRequestSize(args: {
  ceremonyHandle: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): Record<string, number> {
  return {
    ceremonyHandleBytes: utf8Bytes(args.ceremonyHandle),
    clientRequestBytes: jsonBytes(args.clientRequest),
    clientRequestMessageBytes: utf8Bytes(args.clientRequest.clientRequestMessageB64u),
    clientRequestEvaluatorOtStateBytes: utf8Bytes(args.clientRequest.evaluatorOtStateB64u),
  };
}

function requirePrfFirstB64uFromCredential(
  credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential,
): string {
  const value = getPrfResultsFromCredential(credential).first;
  if (!value) {
    throw new Error('Missing PRF.first output from credential (requires a PRF-enabled passkey)');
  }
  return value;
}

export async function deriveThresholdEd25519ClientVerifyingShareFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId | string;
  },
): Promise<DeriveThresholdEd25519ClientVerifyingShareResult> {
  const nearAccountId = toAccountId(args.nearAccountId);
  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-client-share');
    return await deps.signingKeyOps.deriveThresholdEd25519ClientVerifyingShare({
      sessionId,
      nearAccountId,
      prfFirstB64u,
      wrapKeySalt: THRESHOLD_ED25519_WRAP_KEY_SALT_B64U,
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      nearAccountId,
      clientVerifyingShareB64u: '',
      error: message,
    };
  }
}

export async function deriveThresholdEd25519HssClientInputsFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    signingRootId: string;
    nearAccountId: AccountId | string;
    keyPurpose: string;
    keyVersion: string;
    participantIds: number[];
    derivationVersion: number;
  },
): Promise<DeriveThresholdEd25519HssClientInputsResult> {
  const signingRootId = String(args.signingRootId || '').trim();
  const nearAccountId = toAccountId(args.nearAccountId);
  const keyPurpose = String(args.keyPurpose || '').trim();
  const keyVersion = String(args.keyVersion || '').trim();
  const participantIds = Array.isArray(args.participantIds)
    ? args.participantIds.map((value) => Number(value))
    : [];
  const derivationVersion = Number(args.derivationVersion);

  try {
    const prfFirstB64u = requirePrfFirstB64uFromCredential(args.credential);
    const sessionId = deps.createSessionId('threshold-ed25519-hss-client-inputs');
    return await deps.signingKeyOps.deriveThresholdEd25519HssClientInputs({
      sessionId,
      signingRootId,
      nearAccountId,
      keyPurpose,
      keyVersion,
      participantIds,
      derivationVersion,
      prfFirstB64u,
    });
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      signingRootId,
      nearAccountId,
      keyPurpose,
      keyVersion,
      participantIds,
      derivationVersion,
      contextBindingB64u: '',
      yClientB64u: '',
      tauClientB64u: '',
      error: message,
    };
  }
}

export async function prepareThresholdEd25519HssClientCeremonyFromCredential(
  deps: ThresholdEd25519LifecycleDeps,
  args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    signingRootId: string;
    nearAccountId: AccountId | string;
    keyPurpose: string;
    keyVersion: string;
    participantIds: number[];
    derivationVersion: number;
    onProgress?: (message: string) => void;
  },
): Promise<PrepareThresholdEd25519HssClientCeremonyResult> {
  args.onProgress?.('Deriving threshold Ed25519 client inputs from passkey...');
  const derived = await deriveThresholdEd25519HssClientInputsFromCredential(deps, args);
  if (!derived.success) {
    return {
      success: false,
      signingRootId: derived.signingRootId,
      nearAccountId: derived.nearAccountId,
      keyPurpose: derived.keyPurpose,
      keyVersion: derived.keyVersion,
      participantIds: derived.participantIds,
      derivationVersion: derived.derivationVersion,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
      error: derived.error,
    };
  }

  try {
    return {
      success: true,
      signingRootId: derived.signingRootId,
      nearAccountId: derived.nearAccountId,
      keyPurpose: derived.keyPurpose,
      keyVersion: derived.keyVersion,
      participantIds: derived.participantIds,
      derivationVersion: derived.derivationVersion,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      signingRootId: derived.signingRootId,
      nearAccountId: derived.nearAccountId,
      keyPurpose: derived.keyPurpose,
      keyVersion: derived.keyVersion,
      participantIds: derived.participantIds,
      derivationVersion: derived.derivationVersion,
      contextBindingB64u: derived.contextBindingB64u,
      yClientB64u: derived.yClientB64u,
      tauClientB64u: derived.tauClientB64u,
      error: message,
    };
  }
}

export async function completeThresholdEd25519HssClientCeremony(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  workerCtx: WorkerOperationContext;
  persistToThresholdSessionId?: string;
}): Promise<CompleteThresholdEd25519HssClientCeremonyResult> {
  const contextBindingB64u = String(args.preparedSession.contextBindingB64u || '').trim();
  try {
    if (String(args.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }

    const clientOutput = await openThresholdEd25519HssClientOutputWasm({
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      workerCtx: args.workerCtx,
    });

    if (clientOutput.contextBindingB64u !== contextBindingB64u) {
      throw new Error('HSS client output context binding mismatch');
    }

    const persistToThresholdSessionId = String(args.persistToThresholdSessionId || '').trim();
    if (persistToThresholdSessionId) {
      const persisted = persistStoredThresholdEd25519SessionClientBase({
        thresholdSessionId: persistToThresholdSessionId,
        xClientBaseB64u: clientOutput.xClientBaseB64u,
      });
      if (!persisted) {
        throw new Error('Failed to persist HSS client output to the threshold session store');
      }
    }

    return {
      success: true,
      contextBindingB64u,
      preparedSession: args.preparedSession,
      finalizedReport: args.finalizedReport,
      clientOutput,
      ...(persistToThresholdSessionId
        ? { persistedThresholdSessionId: persistToThresholdSessionId }
        : {}),
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u,
      error: message,
    };
  }
}

export async function prepareThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  thresholdSessionJwt: string;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
}): Promise<PrepareThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = '';
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const thresholdSessionJwt = String(args.thresholdSessionJwt || '').trim();
    const relayerKeyId = String(args.relayerKeyId || '').trim();
    const operation = String(args.operation || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server prepare');
    if (!thresholdSessionJwt) {
      throw new Error('Missing threshold session JWT for Ed25519 HSS server prepare');
    }
    if (!relayerKeyId) throw new Error('Missing relayerKeyId for Ed25519 HSS server prepare');
    if (!operation) throw new Error('Missing operation for Ed25519 HSS server prepare');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server prepare');
    }

    const requestPayload = {
      relayerKeyId,
      operation,
      context: args.context,
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = summarizePrepareRequestSize({
      relayerKeyId,
      context: requestPayload.context,
      preparedSession: {
        contextBindingB64u: '',
        evaluatorDriverStateB64u: '',
      },
    });

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}/threshold-ed25519/hss/prepare`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${thresholdSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      ceremonyHandle: string;
      preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
      clientOtOfferMessageB64u: string;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    const ceremonyHandle = String(data.ceremonyHandle || '').trim();
    const preparedSession =
      data.preparedSession &&
      typeof data.preparedSession === 'object' &&
      !Array.isArray(data.preparedSession)
        ? (data.preparedSession as ThresholdEd25519HssPreparedSessionEnvelope)
        : undefined;
    const clientOtOfferMessageB64u = String(data.clientOtOfferMessageB64u || '').trim();
    if (!response.ok || data.ok !== true || !ceremonyHandle || !clientOtOfferMessageB64u || !preparedSession) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    const responsePayload = {
      ceremonyHandle,
      preparedSession,
      clientOtOfferMessageB64u,
    };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {
      ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
      preparedSessionBytes: jsonBytes(preparedSession),
      clientOtOfferMessageBytes: utf8Bytes(clientOtOfferMessageB64u),
    };
    console.info('[threshold-ed25519][client] hss prepare timings', {
      relayerKeyId,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      success: true,
      contextBindingB64u: String(preparedSession.contextBindingB64u || '').trim(),
      ceremonyHandle,
      preparedSession,
      clientOtOfferMessageB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u,
      error: message,
    };
  }
}

export async function respondThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  thresholdSessionJwt: string;
  ceremonyHandle: string;
  contextBindingB64u: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): Promise<RespondThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = String(args.contextBindingB64u || '').trim();
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const thresholdSessionJwt = String(args.thresholdSessionJwt || '').trim();
    const ceremonyHandle = String(args.ceremonyHandle || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server respond');
    if (!thresholdSessionJwt) {
      throw new Error('Missing threshold session JWT for Ed25519 HSS server respond');
    }
    if (!ceremonyHandle) throw new Error('Missing ceremonyHandle for Ed25519 HSS server respond');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server respond');
    }

    const requestPayload = {
      ceremonyHandle,
      clientRequest: args.clientRequest,
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = summarizeRespondRequestSize({
      ceremonyHandle,
      clientRequest: args.clientRequest,
    });

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}/threshold-ed25519/hss/respond`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${thresholdSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    if (!response.ok || data.ok !== true) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    const responsePayload = { ok: true };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {};
    console.info('[threshold-ed25519][client] hss respond timings', {
      ceremonyHandle,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      success: true,
      contextBindingB64u,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u,
      error: message,
    };
  }
}

export async function finalizeThresholdEd25519HssServerCeremonyWithSession(args: {
  relayerUrl: string;
  thresholdSessionJwt: string;
  ceremonyHandle: string;
  contextBindingB64u: string;
}): Promise<FinalizeThresholdEd25519HssServerCeremonyWithSessionResult> {
  const contextBindingB64u = String(args.contextBindingB64u || '').trim();
  try {
    const startedAt = Date.now();
    const relayerUrl = stripTrailingSlashes(String(args.relayerUrl || '').trim());
    const thresholdSessionJwt = String(args.thresholdSessionJwt || '').trim();
    const ceremonyHandle = String(args.ceremonyHandle || '').trim();
    if (!relayerUrl) throw new Error('Missing relayerUrl for Ed25519 HSS server finalize');
    if (!thresholdSessionJwt) {
      throw new Error('Missing threshold session JWT for Ed25519 HSS server finalize');
    }
    if (!ceremonyHandle) throw new Error('Missing ceremonyHandle for Ed25519 HSS server finalize');
    if (typeof fetch !== 'function') {
      throw new Error('fetch is not available for Ed25519 HSS server finalize');
    }

    const requestPayload = {
      ceremonyHandle,
    };
    const serializeStartedAt = Date.now();
    const requestBody = JSON.stringify(requestPayload);
    const serializeMs = Date.now() - serializeStartedAt;
    const requestBytes = utf8Bytes(requestBody);
    const requestSizeBreakdown = {
      ceremonyHandleBytes: utf8Bytes(ceremonyHandle),
    };

    const fetchStartedAt = Date.now();
    const response = await fetch(`${relayerUrl}/threshold-ed25519/hss/finalize`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${thresholdSessionJwt}`,
      },
      credentials: 'omit',
      body: requestBody,
    });
    const fetchMs = Date.now() - fetchStartedAt;

    const parseStartedAt = Date.now();
    const data = (await response.json().catch(() => ({}))) as Partial<{
      ok: boolean;
      finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
      code: string;
      message: string;
    }>;
    const parseMs = Date.now() - parseStartedAt;
    if (!response.ok || data.ok !== true || !data.finalizedReport) {
      throw new Error(data.message || data.code || `HTTP ${response.status}`);
    }
    if (String(data.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }
    const responsePayload = {
      finalizedReport: data.finalizedReport,
    };
    const responseBytes = jsonBytes(responsePayload);
    const responseSizeBreakdown = {
      finalizedReportBytes: jsonBytes(data.finalizedReport),
      clientOutputMessageBytes: utf8Bytes(data.finalizedReport.clientOutputMessageB64u),
      seedOutputMessageBytes: utf8Bytes(String(data.finalizedReport.seedOutputMessageB64u || '')),
    };
    console.info('[threshold-ed25519][client] hss finalize timings', {
      ceremonyHandle,
      serializeMs,
      fetchMs,
      parseMs,
      requestBytes,
      requestSizeBreakdown,
      responseBytes,
      responseSizeBreakdown,
      totalMs: Date.now() - startedAt,
    });
    return {
      success: true,
      contextBindingB64u,
      finalizedReport: data.finalizedReport,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u,
      error: message,
    };
  }
}

export async function runThresholdEd25519HssCeremonyWithSession(args: {
  relayerUrl: string;
  thresholdSessionJwt: string;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
  clientInputs: ThresholdEd25519HssClientInputs;
  workerCtx: WorkerOperationContext;
  persistToThresholdSessionId?: string;
}): Promise<CompleteThresholdEd25519HssClientCeremonyResult> {
  const startedAt = Date.now();
  const prepared = await prepareThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    thresholdSessionJwt: args.thresholdSessionJwt,
    relayerKeyId: args.relayerKeyId,
    operation: args.operation,
    context: args.context,
  });
  if (
    !prepared.success ||
    !prepared.ceremonyHandle ||
    !prepared.clientOtOfferMessageB64u ||
    !prepared.preparedSession
  ) {
    return {
      success: false,
      contextBindingB64u: prepared.contextBindingB64u,
      error: prepared.error,
    };
  }

  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    evaluatorDriverStateB64u: prepared.preparedSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: prepared.clientOtOfferMessageB64u,
    clientInputs: args.clientInputs,
    workerCtx: args.workerCtx,
  });

  const responded = await respondThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    thresholdSessionJwt: args.thresholdSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
    clientRequest,
  });
  if (!responded.success) {
    return {
      success: false,
      contextBindingB64u: responded.contextBindingB64u,
      error: responded.error,
    };
  }

  const evaluateMs = 0;

  const finalized = await finalizeThresholdEd25519HssServerCeremonyWithSession({
    relayerUrl: args.relayerUrl,
    thresholdSessionJwt: args.thresholdSessionJwt,
    ceremonyHandle: prepared.ceremonyHandle,
    contextBindingB64u: prepared.preparedSession.contextBindingB64u,
  });
  if (!finalized.success || !finalized.finalizedReport) {
    return {
      success: false,
      contextBindingB64u: finalized.contextBindingB64u,
      error: finalized.error,
    };
  }

  const completeStartedAt = Date.now();
  const completed = await completeThresholdEd25519HssClientCeremony({
    preparedSession: prepared.preparedSession,
    finalizedReport: finalized.finalizedReport,
    workerCtx: args.workerCtx,
    persistToThresholdSessionId: args.persistToThresholdSessionId,
  });
  const completeMs = Date.now() - completeStartedAt;
  console.info('[threshold-ed25519][client] hss ceremony timings', {
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    evaluateMs,
    completeMs,
    totalMs: Date.now() - startedAt,
  });
  return {
    ...completed,
    preparedSession: prepared.preparedSession,
    ...(finalized.finalizedReport ? { finalizedReport: finalized.finalizedReport } : {}),
  };
}

export async function openThresholdEd25519HssSeedOutput(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  workerCtx: WorkerOperationContext;
}): Promise<OpenThresholdEd25519HssSeedOutputResult> {
  const contextBindingB64u = String(args.preparedSession.contextBindingB64u || '').trim();
  try {
    if (String(args.finalizedReport.contextBindingB64u || '').trim() !== contextBindingB64u) {
      throw new Error('HSS finalized report context binding mismatch');
    }
    if (!String(args.finalizedReport.seedOutputMessageB64u || '').trim()) {
      throw new Error('HSS finalized report is missing seed output');
    }

    const seedOutput = await openThresholdEd25519HssSeedOutputWasm({
      preparedSession: args.preparedSession,
      finalizedReport: {
        seedOutputMessageB64u: String(args.finalizedReport.seedOutputMessageB64u || '').trim(),
      },
      workerCtx: args.workerCtx,
    });

    if (seedOutput.contextBindingB64u !== contextBindingB64u) {
      throw new Error('HSS seed output context binding mismatch');
    }

    return {
      success: true,
      contextBindingB64u,
      seedOutput,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u,
      error: message,
    };
  }
}

export async function buildThresholdEd25519SeedExportArtifactFromHssReport(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  expectedPublicKey: string;
  workerCtx: WorkerOperationContext;
}): Promise<BuildThresholdEd25519SeedExportArtifactResult> {
  const seedResult = await openThresholdEd25519HssSeedOutput({
    preparedSession: args.preparedSession,
    finalizedReport: args.finalizedReport,
    workerCtx: args.workerCtx,
  });
  if (!seedResult.success || !seedResult.seedOutput) {
    return {
      success: false,
      contextBindingB64u: seedResult.contextBindingB64u,
      error: seedResult.error,
    };
  }

  try {
    const artifact = await buildThresholdEd25519SeedExportArtifactWasm({
      seedB64u: seedResult.seedOutput.canonicalSeedB64u,
      expectedPublicKey: String(args.expectedPublicKey || '').trim(),
      workerCtx: args.workerCtx,
    });
    return {
      success: true,
      contextBindingB64u: seedResult.contextBindingB64u,
      seedOutput: seedResult.seedOutput,
      artifact,
    };
  } catch (error: unknown) {
    const message = String((error as { message?: unknown })?.message ?? error);
    return {
      success: false,
      contextBindingB64u: seedResult.contextBindingB64u,
      seedOutput: seedResult.seedOutput,
      error: message,
    };
  }
}
