import wasmSignerServerDefault, {
  init_worker as init_worker_server,
  threshold_ed25519_hss_finalize_report as threshold_ed25519_hss_finalize_report_server,
  threshold_ed25519_hss_open_seed_output as threshold_ed25519_hss_open_seed_output_server,
  threshold_ed25519_hss_open_server_output as threshold_ed25519_hss_open_server_output_server,
  threshold_ed25519_hss_public_key_from_base_shares as threshold_ed25519_hss_public_key_from_base_shares_server,
  threshold_ed25519_hss_prepare_server_message as threshold_ed25519_hss_prepare_server_message_server,
  threshold_ed25519_hss_server_inputs as threshold_ed25519_hss_server_inputs_server,
  threshold_ed25519_hss_verifying_share_from_signing_share as threshold_ed25519_hss_verifying_share_from_signing_share_server,
  threshold_ed25519_recovery_keypair_from_seed as threshold_ed25519_recovery_keypair_from_seed_server,
} from '../../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import type { InitInput } from '../../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import { createWasmLoader } from '../wasm-loader';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
  ThresholdEd25519HssDerivedPublicKey,
  ThresholdEd25519HssEvaluationResultEnvelope,
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssOpenedSeedOutput,
  ThresholdEd25519HssOpenedServerOutput,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerInputs,
  ThresholdEd25519HssServerMessageEnvelope,
} from '../types';

const SIGNER_WASM_PATH_CANDIDATES = [
  '../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../workers/wasm_signer_worker_bg.wasm',
  '../../../workers/wasm_signer_worker_bg.wasm',
];

function getSignerWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of SIGNER_WASM_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore invalid candidate
    }
  }
  return resolved;
}

let thresholdEd25519HssWasmInitPromise: Promise<void> | null = null;
let thresholdEd25519HssWasmReady = false;

async function initThresholdEd25519HssSignerWasm(input: {
  module_or_path: InitInput;
}): Promise<void> {
  await wasmSignerServerDefault(input);
  init_worker_server();
  thresholdEd25519HssWasmReady = true;
}

export async function ensureThresholdEd25519HssWasm(): Promise<void> {
  if (thresholdEd25519HssWasmInitPromise) return thresholdEd25519HssWasmInitPromise;
  const loader = createWasmLoader(initThresholdEd25519HssSignerWasm, {
    logPrefix: 'threshold-ed25519-hss',
    baseUrl: import.meta.url,
    fallbackUrls: getSignerWasmUrls(),
  });
  thresholdEd25519HssWasmInitPromise = loader.load();
  return thresholdEd25519HssWasmInitPromise;
}

function requireThresholdEd25519HssWasmReady(): void {
  if (!thresholdEd25519HssWasmReady) {
    throw new Error('[threshold-ed25519-hss] signer WASM is not initialized');
  }
}

export async function deriveThresholdEd25519HssServerInputs(input: {
  masterSecretB64u: string;
  context: ThresholdEd25519HssCanonicalContext;
}): Promise<ThresholdEd25519HssCanonicalContext & ThresholdEd25519HssServerInputs> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_server_inputs_server({
    masterSecretB64u: input.masterSecretB64u,
    orgId: input.context.orgId,
    nearAccountId: input.context.nearAccountId,
    keyPurpose: input.context.keyPurpose,
    keyVersion: input.context.keyVersion,
    participantIds: input.context.participantIds,
    derivationVersion: input.context.derivationVersion,
  }) as {
    orgId: string;
    nearAccountId: string;
    keyPurpose: string;
    keyVersion: string;
    participantIds: number[];
    derivationVersion: number;
    contextBindingB64u: string;
    yRelayerB64u: string;
    tauRelayerB64u: string;
  };

  const participantIdsValue = (result as { participantIds?: ArrayLike<number> | number[] })
    .participantIds;

  return {
    orgId: String(result.orgId || '').trim(),
    nearAccountId: String(result.nearAccountId || '').trim(),
    keyPurpose: String(result.keyPurpose || '').trim(),
    keyVersion: String(result.keyVersion || '').trim(),
    participantIds:
      Array.isArray(participantIdsValue) || ArrayBuffer.isView(participantIdsValue)
        ? Array.from(participantIdsValue, (value) => Number(value))
        : [],
    derivationVersion: Number(result.derivationVersion),
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    yRelayerB64u: String(result.yRelayerB64u || '').trim(),
    tauRelayerB64u: String(result.tauRelayerB64u || '').trim(),
  };
}

export async function prepareThresholdEd25519HssServerMessage(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'garblerDriverStateB64u'>;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputs: ThresholdEd25519HssServerInputs;
}): Promise<ThresholdEd25519HssServerMessageEnvelope> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_prepare_server_message_server({
    garblerDriverStateB64u: input.preparedSession.garblerDriverStateB64u,
    clientRequestMessageB64u: input.clientRequest.clientRequestMessageB64u,
    yRelayerB64u: input.serverInputs.yRelayerB64u,
    tauRelayerB64u: input.serverInputs.tauRelayerB64u,
  }) as {
    contextBindingB64u: string;
    serverMessageB64u: string;
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    serverMessageB64u: String(result.serverMessageB64u || '').trim(),
  };
}

export async function prepareThresholdEd25519HssServerCeremony(input: {
  context: ThresholdEd25519HssCanonicalContext;
  masterSecretB64u: string;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
}): Promise<{
  serverInputs: ThresholdEd25519HssServerInputs;
  serverMessage: ThresholdEd25519HssServerMessageEnvelope;
}> {
  const serverInputs = await deriveThresholdEd25519HssServerInputs({
    masterSecretB64u: input.masterSecretB64u,
    context: input.context,
  });

  const expectedBinding = String(input.preparedSession.contextBindingB64u || '').trim();
  if (
    !expectedBinding ||
    serverInputs.contextBindingB64u !== expectedBinding ||
    String(input.clientRequest.contextBindingB64u || '').trim() !== expectedBinding
  ) {
    throw new Error(
      '[threshold-ed25519-hss] context binding mismatch during server ceremony preparation',
    );
  }

  const serverMessage = await prepareThresholdEd25519HssServerMessage({
    preparedSession: input.preparedSession,
    clientRequest: input.clientRequest,
    serverInputs,
  });

  if (serverMessage.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] server message context binding mismatch');
  }

  return { serverInputs, serverMessage };
}

export async function finalizeThresholdEd25519HssReport(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'garblerDriverStateB64u'>;
  evaluationResult: ThresholdEd25519HssEvaluationResultEnvelope;
}): Promise<ThresholdEd25519HssFinalizedReportEnvelope> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_finalize_report_server({
    garblerDriverStateB64u: input.preparedSession.garblerDriverStateB64u,
    evaluationResultMessageB64u: input.evaluationResult.evaluationResultMessageB64u,
  }) as {
    contextBindingB64u: string;
    evaluationReportJson: string;
    clientOutputMessageB64u: string;
    seedOutputMessageB64u: string;
    serverOutputMessageB64u: string;
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    evaluationReportJson: String(result.evaluationReportJson || '').trim(),
    clientOutputMessageB64u: String(result.clientOutputMessageB64u || '').trim(),
    seedOutputMessageB64u: String(result.seedOutputMessageB64u || '').trim(),
    serverOutputMessageB64u: String(result.serverOutputMessageB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssServerOutput(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'garblerDriverStateB64u'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'serverOutputMessageB64u'>;
}): Promise<ThresholdEd25519HssOpenedServerOutput> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_open_server_output_server({
    garblerDriverStateB64u: input.preparedSession.garblerDriverStateB64u,
    serverOutputMessageB64u: input.finalizedReport.serverOutputMessageB64u,
  }) as {
    contextBindingB64u: string;
    xRelayerBaseB64u: string;
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    xRelayerBaseB64u: String(result.xRelayerBaseB64u || '').trim(),
  };
}

export async function openThresholdEd25519HssSeedOutput(input: {
  preparedSession: Pick<ThresholdEd25519HssPreparedSessionEnvelope, 'evaluatorDriverStateB64u'>;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'seedOutputMessageB64u'>;
}): Promise<ThresholdEd25519HssOpenedSeedOutput> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_open_seed_output_server({
    evaluatorDriverStateB64u: input.preparedSession.evaluatorDriverStateB64u,
    seedOutputMessageB64u: input.finalizedReport.seedOutputMessageB64u,
  }) as {
    contextBindingB64u: string;
    canonicalSeedB64u: string;
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    canonicalSeedB64u: String(result.canonicalSeedB64u || '').trim(),
  };
}

export async function finalizeThresholdEd25519HssServerCeremony(input: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  evaluationResult: ThresholdEd25519HssEvaluationResultEnvelope;
}): Promise<{
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  serverOutput: ThresholdEd25519HssOpenedServerOutput;
}> {
  const expectedBinding = String(input.preparedSession.contextBindingB64u || '').trim();
  if (
    !expectedBinding ||
    String(input.evaluationResult.contextBindingB64u || '').trim() !== expectedBinding
  ) {
    throw new Error('[threshold-ed25519-hss] evaluation result context binding mismatch');
  }

  const finalizedReport = await finalizeThresholdEd25519HssReport({
    preparedSession: input.preparedSession,
    evaluationResult: input.evaluationResult,
  });

  if (finalizedReport.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] finalized report context binding mismatch');
  }

  const serverOutput = await openThresholdEd25519HssServerOutput({
    preparedSession: input.preparedSession,
    finalizedReport,
  });

  if (serverOutput.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] server output context binding mismatch');
  }

  return { finalizedReport, serverOutput };
}

export async function deriveThresholdEd25519HssPublicKey(input: {
  xClientBaseB64u: string;
  xRelayerBaseB64u: string;
}): Promise<ThresholdEd25519HssDerivedPublicKey> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_public_key_from_base_shares_server({
    xClientBaseB64u: input.xClientBaseB64u,
    xRelayerBaseB64u: input.xRelayerBaseB64u,
  }) as {
    publicKeyB64u: string;
  };

  return {
    publicKeyB64u: String(result.publicKeyB64u || '').trim(),
  };
}

export async function deriveThresholdEd25519VerifyingShareFromSigningShare(input: {
  signingShareB64u: string;
}): Promise<{ verifyingShareB64u: string }> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_verifying_share_from_signing_share_server({
    signingShareB64u: input.signingShareB64u,
  }) as {
    verifyingShareB64u: string;
  };

  return {
    verifyingShareB64u: String(result.verifyingShareB64u || '').trim(),
  };
}

export async function deriveThresholdEd25519KeypairFromSeed(input: {
  seedB64u: string;
}): Promise<{ publicKey: string; privateKey: string }> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_recovery_keypair_from_seed_server({
    seedB64u: input.seedB64u,
  }) as {
    publicKey: string;
    privateKey: string;
  };

  return {
    publicKey: String(result.publicKey || '').trim(),
    privateKey: String(result.privateKey || '').trim(),
  };
}

export async function deriveThresholdEd25519RegistrationMaterialFromHssFinalize(input: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
}): Promise<{
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
}> {
  const expectedBinding = String(input.preparedSession.contextBindingB64u || '').trim();
  if (
    !expectedBinding ||
    String(input.finalizedReport.contextBindingB64u || '').trim() !== expectedBinding
  ) {
    throw new Error('[threshold-ed25519-hss] finalized report context binding mismatch');
  }

  const [seedOutput, serverOutput] = await Promise.all([
    openThresholdEd25519HssSeedOutput({
      preparedSession: input.preparedSession,
      finalizedReport: input.finalizedReport,
    }),
    openThresholdEd25519HssServerOutput({
      preparedSession: input.preparedSession,
      finalizedReport: input.finalizedReport,
    }),
  ]);

  if (
    seedOutput.contextBindingB64u !== expectedBinding ||
    serverOutput.contextBindingB64u !== expectedBinding
  ) {
    throw new Error('[threshold-ed25519-hss] opened registration material context mismatch');
  }

  const [keypair, relayerVerifyingShare] = await Promise.all([
    deriveThresholdEd25519KeypairFromSeed({
      seedB64u: seedOutput.canonicalSeedB64u,
    }),
    deriveThresholdEd25519VerifyingShareFromSigningShare({
      signingShareB64u: serverOutput.xRelayerBaseB64u,
    }),
  ]);

  const publicKey = String(keypair.publicKey || '').trim();
  const relayerSigningShareB64u = String(serverOutput.xRelayerBaseB64u || '').trim();
  const relayerVerifyingShareB64u = String(relayerVerifyingShare.verifyingShareB64u || '').trim();
  const keyVersion = String(input.preparedSession.keyVersion || '').trim();
  if (!publicKey || !relayerSigningShareB64u || !relayerVerifyingShareB64u || !keyVersion) {
    throw new Error('[threshold-ed25519-hss] incomplete registration material derived');
  }

  return {
    publicKey,
    relayerKeyId: publicKey,
    keyVersion,
    recoveryExportCapable: true,
    relayerSigningShareB64u,
    relayerVerifyingShareB64u,
  };
}
