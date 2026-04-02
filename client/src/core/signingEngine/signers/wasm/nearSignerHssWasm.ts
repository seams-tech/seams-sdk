import initSignerWasm, {
  init_worker,
  threshold_ed25519_hss_evaluate_result,
  threshold_ed25519_hss_open_client_output,
  threshold_ed25519_hss_open_seed_output,
  threshold_ed25519_hss_prepare_client_request,
  threshold_ed25519_hss_prepare_session,
  threshold_ed25519_hss_public_key_from_base_shares,
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { InitInput } from '../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';

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
  garblerDriverStateJson: string;
  evaluatorDriverStateJson: string;
  clientOtOfferMessageB64u: string;
};

export type ThresholdEd25519HssClientRequestEnvelope = {
  contextBindingB64u: string;
  clientRequestMessageB64u: string;
  evaluatorOtStateJson: string;
};

export type ThresholdEd25519HssServerMessageEnvelope = {
  contextBindingB64u: string;
  serverMessageB64u: string;
};

export type ThresholdEd25519HssEvaluationResultEnvelope = {
  contextBindingB64u: string;
  evaluationResultMessageB64u: string;
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

const wasmUrl = resolveWasmUrl('wasm_signer_worker_bg.wasm', 'NEAR Signer HSS');
let thresholdEd25519HssWasmInitPromise: Promise<void> | null = null;
let thresholdEd25519HssWasmReady = false;

async function initThresholdEd25519HssSignerWasm(input: {
  module_or_path: InitInput;
}): Promise<void> {
  await initSignerWasm(input);
  init_worker();
  thresholdEd25519HssWasmReady = true;
}

export async function ensureThresholdEd25519HssClientWasm(): Promise<void> {
  if (thresholdEd25519HssWasmInitPromise) return thresholdEd25519HssWasmInitPromise;
  thresholdEd25519HssWasmInitPromise = initializeWasm({
    workerName: 'NEAR Signer HSS',
    wasmUrl,
    initFunction: initThresholdEd25519HssSignerWasm,
  }).then(() => undefined);
  return thresholdEd25519HssWasmInitPromise;
}

function requireThresholdEd25519HssClientWasmReady(): void {
  if (!thresholdEd25519HssWasmReady) {
    throw new Error('[threshold-ed25519-hss] signer WASM is not initialized');
  }
}

function normalizeParticipantIds(value: unknown): number[] {
  if (Array.isArray(value) || ArrayBuffer.isView(value)) {
    return Array.from(value as ArrayLike<number>, (entry) => Number(entry));
  }
  return [];
}

export async function prepareThresholdEd25519HssSessionWasm(input: {
  context: ThresholdEd25519HssCanonicalContext;
}): Promise<ThresholdEd25519HssPreparedSessionEnvelope> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_prepare_session({
    orgId: input.context.orgId,
    nearAccountId: input.context.nearAccountId,
    keyPurpose: input.context.keyPurpose,
    keyVersion: input.context.keyVersion,
    participantIds: input.context.participantIds,
    derivationVersion: input.context.derivationVersion,
  }) as ThresholdEd25519HssPreparedSessionEnvelope;

  return {
    orgId: String(result.orgId || '').trim(),
    nearAccountId: String(result.nearAccountId || '').trim(),
    keyPurpose: String(result.keyPurpose || '').trim(),
    keyVersion: String(result.keyVersion || '').trim(),
    participantIds: normalizeParticipantIds(
      (result as { participantIds?: unknown }).participantIds,
    ),
    derivationVersion: Number(result.derivationVersion),
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    garblerDriverStateJson: String(result.garblerDriverStateJson || '').trim(),
    evaluatorDriverStateJson: String(result.evaluatorDriverStateJson || '').trim(),
    clientOtOfferMessageB64u: String(result.clientOtOfferMessageB64u || '').trim(),
  };
}

export async function prepareThresholdEd25519HssClientRequestWasm(input: {
  preparedSession: Pick<
    ThresholdEd25519HssPreparedSessionEnvelope,
    'evaluatorDriverStateJson' | 'clientOtOfferMessageB64u'
  >;
  clientInputs: ThresholdEd25519HssClientInputs;
}): Promise<ThresholdEd25519HssClientRequestEnvelope> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_prepare_client_request({
    evaluatorDriverStateJson: input.preparedSession.evaluatorDriverStateJson,
    clientOtOfferMessageB64u: input.preparedSession.clientOtOfferMessageB64u,
    yClientB64u: input.clientInputs.yClientB64u,
    tauClientB64u: input.clientInputs.tauClientB64u,
  }) as ThresholdEd25519HssClientRequestEnvelope;

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    clientRequestMessageB64u: String(result.clientRequestMessageB64u || '').trim(),
    evaluatorOtStateJson: String(result.evaluatorOtStateJson || '').trim(),
  };
}

export async function evaluateThresholdEd25519HssResultWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateJson'>;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverMessage: ThresholdEd25519HssServerMessageEnvelope;
}): Promise<ThresholdEd25519HssEvaluationResultEnvelope> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_evaluate_result({
    evaluatorDriverStateJson: input.preparedSession.evaluatorDriverStateJson,
    clientRequestMessageB64u: input.clientRequest.clientRequestMessageB64u,
    evaluatorOtStateJson: input.clientRequest.evaluatorOtStateJson,
    serverMessageB64u: input.serverMessage.serverMessageB64u,
  }) as ThresholdEd25519HssEvaluationResultEnvelope;

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    evaluationResultMessageB64u: String(result.evaluationResultMessageB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssClientOutputWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateJson'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'clientOutputMessageB64u'>;
}): Promise<ThresholdEd25519HssOpenedClientOutput> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_open_client_output({
    evaluatorDriverStateJson: input.preparedSession.evaluatorDriverStateJson,
    clientOutputMessageB64u: input.finalizedReport.clientOutputMessageB64u,
  }) as ThresholdEd25519HssOpenedClientOutput;

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    xClientBaseB64u: String(result.xClientBaseB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssSeedOutputWasm(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateJson'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'seedOutputMessageB64u'>;
}): Promise<ThresholdEd25519HssOpenedSeedOutput> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_open_seed_output({
    evaluatorDriverStateJson: input.preparedSession.evaluatorDriverStateJson,
    seedOutputMessageB64u: input.finalizedReport.seedOutputMessageB64u,
  }) as ThresholdEd25519HssOpenedSeedOutput;

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    canonicalSeedB64u: String(result.canonicalSeedB64u || '').trim(),
  };
}

export async function deriveThresholdEd25519HssPublicKeyWasm(input: {
  xClientBaseB64u: string;
  xRelayerBaseB64u: string;
}): Promise<ThresholdEd25519HssDerivedPublicKey> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_hss_public_key_from_base_shares({
    xClientBaseB64u: input.xClientBaseB64u,
    xRelayerBaseB64u: input.xRelayerBaseB64u,
  }) as ThresholdEd25519HssDerivedPublicKey;

  return {
    publicKeyB64u: String(result.publicKeyB64u || '').trim(),
  };
}

export async function buildThresholdEd25519SeedExportArtifactWasm(input: {
  seedB64u: string;
  expectedPublicKey: string;
}): Promise<ThresholdEd25519SeedExportArtifact> {
  await ensureThresholdEd25519HssClientWasm();
  requireThresholdEd25519HssClientWasmReady();

  const result = threshold_ed25519_seed_export_artifact_from_seed({
    seedB64u: input.seedB64u,
    expectedPublicKey: input.expectedPublicKey,
  }) as ThresholdEd25519SeedExportArtifact;

  return {
    artifactKind: String(result.artifactKind || '').trim(),
    seedB64u: String(result.seedB64u || '').trim(),
    publicKey: String(result.publicKey || '').trim(),
    privateKey: String(result.privateKey || '').trim(),
  };
}
