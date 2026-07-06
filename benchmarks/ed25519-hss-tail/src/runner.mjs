import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { deflateSync, gzipSync, gunzipSync, inflateSync } from 'node:zlib';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  derive_threshold_ed25519_hss_client_inputs,
  initSync as initHssClientSignerWasmSync,
  threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact,
  threshold_ed25519_hss_derive_client_output_mask,
  threshold_ed25519_hss_prepare_add_stage_request_message,
  threshold_ed25519_hss_prepare_client_request,
} from '../../../wasm/hss_client_signer/pkg/hss_client_signer.js';
import {
  initSync as initNearSignerWasmSync,
  init_worker,
  threshold_ed25519_hss_advance_server_eval_state,
  threshold_ed25519_hss_boundary_copy_probe,
  threshold_ed25519_hss_finalize_advanced_report,
  threshold_ed25519_hss_prepare_role_separated_server_input_delivery,
  threshold_ed25519_hss_prepare_server_session,
  threshold_ed25519_hss_server_eval_state_size_census,
} from '../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import {
  init_threshold_prf,
  initSync as initThresholdPrfWasmSync,
  threshold_prf_derive_ed25519_hss_server_inputs,
} from '../../../wasm/threshold_prf/pkg/threshold_prf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '../../..');
const OUT_ROOT = path.join(REPO_ROOT, 'benchmarks', 'ed25519-hss-tail', 'out');
const HSS_CLIENT_SIGNER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'hss_client_signer',
  'pkg',
  'hss_client_signer_bg.wasm',
);
const NEAR_SIGNER_SERVER_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'near_signer',
  'pkg-server',
  'wasm_signer_worker_bg.wasm',
);
const THRESHOLD_PRF_WASM_PATH = path.join(
  REPO_ROOT,
  'wasm',
  'threshold_prf',
  'pkg',
  'threshold_prf_bg.wasm',
);

const WASM_ARTIFACTS = [
  {
    name: 'near_signer_server',
    wasmPath: NEAR_SIGNER_SERVER_WASM_PATH,
    sourceRoots: [
      'wasm/near_signer/src',
      'wasm/near_signer/Cargo.toml',
      'crates/ed25519-hss/src',
      'crates/ed25519-hss/Cargo.toml',
      'crates/signer-core/src',
      'crates/signer-core/Cargo.toml',
    ],
  },
  {
    name: 'hss_client_signer',
    wasmPath: HSS_CLIENT_SIGNER_WASM_PATH,
    sourceRoots: [
      'wasm/hss_client_signer/src',
      'wasm/hss_client_signer/Cargo.toml',
      'crates/ed25519-hss/src',
      'crates/ed25519-hss/Cargo.toml',
      'crates/signer-core/src',
      'crates/signer-core/Cargo.toml',
    ],
  },
  {
    name: 'threshold_prf',
    wasmPath: THRESHOLD_PRF_WASM_PATH,
    sourceRoots: [
      'wasm/threshold_prf/src',
      'wasm/threshold_prf/Cargo.toml',
      'crates/threshold-prf/src',
      'crates/threshold-prf/Cargo.toml',
    ],
  },
];
const PRUNED_DIR_NAMES = new Set(['target', 'pkg', 'pkg-server', 'node_modules', '.git', 'dist']);

const SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1 =
  'seams-sdk:ed25519-hss:application-binding:v1';
const BINDING_FACTS = {
  nearEd25519SigningKeyId: 'near-ed25519:hss-tail-benchmark',
  signingRootId: 'project_single_key_hss:env_single_key_hss',
  signingRootVersion: 'root-v1',
};
const CANONICAL_CONTEXT = {
  signingRootId: BINDING_FACTS.signingRootId,
  nearAccountId: 'single-key-hss-tail-benchmark.testnet',
  keyPurpose: 'near-ed25519-signing',
  keyVersion: BINDING_FACTS.signingRootVersion,
  participantIds: [1, 2],
  derivationVersion: 1,
  applicationBindingDigestB64u: computeApplicationBindingDigestB64u(BINDING_FACTS),
};
const RELAYER_KEY_ID = 'registration:hss-tail-benchmark';
const PRF_FIRST_B64U = Buffer.alloc(32, 11).toString('base64url');
const THRESHOLD_PRF_THRESHOLD = 2;
const THRESHOLD_PRF_SHARE_COUNT = 3;
const SIGNING_ROOT_SHARE_WIRE_HEX = [
  '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
];

const CLI_ARGS = parseArgs(process.argv.slice(2));
const WARMUP = numberOption('--warmup', 1);
const ITERATIONS = numberOption('--iterations', 5);
const DRIFT_ITERATIONS = numberOption('--drift-iterations', 0);
const ALLOW_STALE_ARTIFACT = Boolean(CLI_ARGS.get('--allow-stale-artifact'));
const CLIENT_SESSION_SOURCE = stringOption('--client-session-source', 'serialized_state');
const VALID_CLIENT_SESSION_SOURCES = new Set(['serialized_state', 'worker_handle']);
if (!VALID_CLIENT_SESSION_SOURCES.has(CLIENT_SESSION_SOURCE)) {
  throw new Error(
    `Invalid --client-session-source=${CLIENT_SESSION_SOURCE}; expected serialized_state or worker_handle`,
  );
}

const ORDERED_BUCKETS = [
  'prepareAddStageRequestMs',
  'clientArtifactMs',
  'clientArtifactDecodeClientOutputMaskMs',
  'clientArtifactDecodeEvaluatorOtStateMs',
  'clientArtifactDecodeServerInputDeliveryMs',
  'clientArtifactDecodeClientRequestMessageMs',
  'clientArtifactDecodeEvaluatorDriverStateMs',
  'clientArtifactMaterializeSessionMs',
  'clientArtifactBuildArtifactMs',
  'clientArtifactEncodeArtifactMs',
  'clientArtifactHiddenEvalTotalMs',
  'clientArtifactHiddenEvalInputSharingMs',
  'clientArtifactHiddenEvalAddStageMs',
  'clientArtifactHiddenEvalMessageScheduleMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationXorAbMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationSumMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationAXorCarryMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationCarryGateMs',
  'clientArtifactHiddenEvalMessageScheduleAccumulationNextCarryMs',
  'clientArtifactHiddenEvalRoundCoreMs',
  'clientArtifactHiddenEvalRoundSigma0Ms',
  'clientArtifactHiddenEvalRoundSigma1Ms',
  'clientArtifactHiddenEvalRoundChMs',
  'clientArtifactHiddenEvalRoundMajMs',
  'clientArtifactHiddenEvalRoundState3Ms',
  'clientArtifactHiddenEvalRoundTemp1Ms',
  'clientArtifactHiddenEvalRoundTemp1XorAbMs',
  'clientArtifactHiddenEvalRoundTemp1SumMs',
  'clientArtifactHiddenEvalRoundTemp1AXorCarryMs',
  'clientArtifactHiddenEvalRoundTemp1CarryGateMs',
  'clientArtifactHiddenEvalRoundTemp1NextCarryMs',
  'clientArtifactHiddenEvalRoundTemp2Ms',
  'clientArtifactHiddenEvalRoundNewABitsMs',
  'clientArtifactHiddenEvalRoundNewEBitsMs',
  'clientArtifactHiddenEvalOutputProjectorMs',
  'clientArtifactHiddenEvalOutputProjectorCoreMs',
  'clientArtifactHiddenEvalOutputProjectorClampAMs',
  'clientArtifactHiddenEvalOutputProjectorReduceAMs',
  'clientArtifactHiddenEvalOutputProjectorTauMs',
  'clientArtifactHiddenEvalOutputProjectorMaskShareMs',
  'clientArtifactHiddenEvalOutputProjectorMaskAddMs',
  'clientArtifactHiddenEvalOutputProjectorClientBaseMs',
  'clientArtifactHiddenEvalOutputProjectorClientOutputMs',
  'clientArtifactHiddenEvalOutputProjectorTauDoubleMs',
  'clientArtifactHiddenEvalOutputProjectorServerOutputMs',
  'clientArtifactHiddenEvalOutputProjectorBundleBuildMs',
  'boundaryCopyAdvancePayloadWallMs',
  'boundaryCopyAdvancePayloadDecodeArgsMs',
  'boundaryCopyAdvancePayloadSummarizeMs',
  'advanceWallMs',
  'advanceDecodeStateMs',
  'advanceSerializedSessionMaterializeMs',
  'advanceSerializedSessionDecodeMs',
  'advanceMaterializeRuntimeMs',
  'advanceMaterializeEvaluatorSessionMs',
  'advanceMaterializeGarblerSessionMs',
  'advanceAddStageResponseMs',
  'advanceMessageScheduleRoundsMs',
  'advanceRoundCoreRoundsMs',
  'advanceOutputProjectionMs',
  'advanceEncodeAdvancedStateMs',
  'advancedStateCensusWallMs',
  'advancedStateCensusDecodeStateMs',
  'advancedStateCensusSummarizeMs',
  'boundaryCopyFinalizePayloadWallMs',
  'boundaryCopyFinalizePayloadDecodeArgsMs',
  'boundaryCopyFinalizePayloadSummarizeMs',
  'finalizeWallMs',
  'finalizeDecodeArtifactMs',
  'finalizeSerializedSessionMaterializeMs',
  'finalizeSerializedSessionDecodeMs',
  'finalizeMaterializeRuntimeMs',
  'finalizeMaterializeEvaluatorSessionMs',
  'finalizeMaterializeGarblerSessionMs',
  'finalizeOutputProjectionMs',
  'finalizeReportMs',
  'finalizePacketAssemblyMs',
  'finalizeEncodeReportMs',
  'openServerOutputMs',
  'openSeedOutputMs',
];

let wasmReady = false;
let hssClientSignerWasmExports = null;
let nearSignerServerWasmExports = null;
let thresholdPrfWasmExports = null;

function parseArgs(argv) {
  const out = new Map();
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith('--')) continue;
    const [key, inlineValue] = arg.split('=', 2);
    if (inlineValue !== undefined) {
      out.set(key, inlineValue);
      continue;
    }
    const next = argv[index + 1];
    if (next && !next.startsWith('--')) {
      out.set(key, next);
      index += 1;
      continue;
    }
    out.set(key, true);
  }
  return out;
}

function numberOption(name, fallback) {
  const raw = CLI_ARGS.get(name);
  if (raw === undefined || raw === true) return fallback;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : fallback;
}

function stringOption(name, fallback) {
  const raw = CLI_ARGS.get(name);
  if (typeof raw !== 'string') return fallback;
  return raw.trim() || fallback;
}

function ensureWasm() {
  if (wasmReady) return;
  hssClientSignerWasmExports = initHssClientSignerWasmSync({
    module: readFileSync(HSS_CLIENT_SIGNER_WASM_PATH),
  });
  nearSignerServerWasmExports = initNearSignerWasmSync({
    module: readFileSync(NEAR_SIGNER_SERVER_WASM_PATH),
  });
  init_worker();
  thresholdPrfWasmExports = initThresholdPrfWasmSync({
    module: readFileSync(THRESHOLD_PRF_WASM_PATH),
  });
  init_threshold_prf();
  wasmReady = true;
}

function computeApplicationBindingDigestB64u(input) {
  return createHash('sha256').update(encodeApplicationBindingFacts(input)).digest('base64url');
}

function encodeApplicationBindingFacts(input) {
  const out = [];
  const domainBytes = new TextEncoder().encode(SDK_ED25519_HSS_APPLICATION_BINDING_DOMAIN_V1);
  pushU32(out, domainBytes.length);
  out.push(...domainBytes);
  pushLengthDelimitedField(out, 'nearEd25519SigningKeyId', input.nearEd25519SigningKeyId);
  pushLengthDelimitedField(out, 'signingRootId', input.signingRootId);
  pushLengthDelimitedField(out, 'signingRootVersion', input.signingRootVersion);
  return new Uint8Array(out);
}

function pushLengthDelimitedField(out, label, value) {
  const labelBytes = new TextEncoder().encode(label);
  const valueBytes = new TextEncoder().encode(requireNonEmptyString(value, label));
  pushU32(out, labelBytes.length);
  out.push(...labelBytes);
  pushU32(out, valueBytes.length);
  out.push(...valueBytes);
}

function pushU32(out, value) {
  out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
}

function requireNonEmptyString(value, field) {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function b64uToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'base64url'));
}

function bytesToB64u(value) {
  return Buffer.from(requireBytes(value, 'bytes')).toString('base64url');
}

function hexToBytes(value) {
  return new Uint8Array(Buffer.from(value, 'hex'));
}

function shareWireSetBytes(hexValues) {
  const chunks = hexValues.map(hexToBytes);
  const out = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function requireBytes(value, field) {
  if (value instanceof Uint8Array) return value;
  throw new Error(`${field} must be Uint8Array`);
}

function assertContextBinding(label, actual, expected) {
  if (String(actual || '') !== String(expected || '')) {
    throw new Error(`${label} context binding mismatch`);
  }
}

function b64uByteLength(value) {
  return Buffer.byteLength(Buffer.from(String(value || ''), 'base64url'));
}

function createBenchmarkFixture() {
  const preparedServerSession = threshold_ed25519_hss_prepare_server_session(CANONICAL_CONTEXT);
  const durablePreparedServerSession = {
    preparedSessionHandle: '',
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    garblerDriverStateB64u: preparedServerSession.garblerDriverStateB64u,
  };
  const clientInputs = derive_threshold_ed25519_hss_client_inputs({
    ...CANONICAL_CONTEXT,
    prfFirstB64u: PRF_FIRST_B64U,
  });
  const serverInputs = threshold_prf_derive_ed25519_hss_server_inputs(
    THRESHOLD_PRF_THRESHOLD,
    THRESHOLD_PRF_SHARE_COUNT,
    shareWireSetBytes(SIGNING_ROOT_SHARE_WIRE_HEX),
    b64uToBytes(CANONICAL_CONTEXT.applicationBindingDigestB64u),
  );
  const clientOutputMask = threshold_ed25519_hss_derive_client_output_mask({
    ...CANONICAL_CONTEXT,
    contextBindingB64u: preparedServerSession.contextBindingB64u,
    operation: 'registration',
    relayerKeyId: RELAYER_KEY_ID,
    clientRecoverableSecretB64u: PRF_FIRST_B64U,
  });
  assertContextBinding(
    'client inputs',
    clientInputs.contextBindingB64u,
    preparedServerSession.contextBindingB64u,
  );
  assertContextBinding(
    'server inputs',
    bytesToB64u(serverInputs.contextBinding),
    preparedServerSession.contextBindingB64u,
  );

  const clientRequest = threshold_ed25519_hss_prepare_client_request({
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientOtOfferMessageB64u: preparedServerSession.clientOtOfferMessageB64u,
    yClientB64u: clientInputs.yClientB64u,
    tauClientB64u: clientInputs.tauClientB64u,
  });
  const delivery = threshold_ed25519_hss_prepare_role_separated_server_input_delivery({
    operation: 'registration',
    preparedSessionHandle: preparedServerSession.preparedSessionHandle,
    garblerDriverStateBytes: b64uToBytes(preparedServerSession.garblerDriverStateB64u),
    clientRequestMessageBytes: b64uToBytes(clientRequest.clientRequestMessageB64u),
    yRelayerBytes: requireBytes(serverInputs.yRelayer, 'serverInputs.yRelayer'),
    tauRelayerBytes: requireBytes(serverInputs.tauRelayer, 'serverInputs.tauRelayer'),
  });
  assertContextBinding(
    'server delivery',
    delivery.contextBindingB64u,
    preparedServerSession.contextBindingB64u,
  );

  const addStage = threshold_ed25519_hss_prepare_add_stage_request_message({
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u: preparedServerSession.evaluatorDriverStateB64u,
    clientRequestMessageB64u: clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: delivery.serverInputDeliveryB64u,
  });
  assertContextBinding(
    'add-stage request',
    addStage.contextBindingB64u,
    preparedServerSession.contextBindingB64u,
  );

  return {
    kind: 'ed25519_hss_tail_fixture_v1',
    context: CANONICAL_CONTEXT,
    projectionMode: 'registration_seed_and_output',
    expectedContextBindingB64u: preparedServerSession.contextBindingB64u,
    durablePreparedServerSession,
    clientRequest,
    delivery,
    addStage,
    clientOutputMaskB64u: clientOutputMask.clientOutputMaskB64u,
  };
}

function buildArtifact(fixture, addStage) {
  const started = performance.now();
  const artifact = threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact({
    ...clientSessionSourceArgs(fixture),
    clientRequestMessageB64u: fixture.clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: fixture.clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: fixture.delivery.serverInputDeliveryB64u,
    clientOutputMaskB64u: fixture.clientOutputMaskB64u,
    expectedAddStageRequestMessageB64u: addStage.addStageRequestMessageB64u,
  });
  const wallMs = performance.now() - started;
  assertContextBinding(
    'client artifact',
    artifact.contextBindingB64u,
    fixture.expectedContextBindingB64u,
  );
  return { artifact, wallMs };
}

function measureBoundaryCopyProbe(input) {
  const started = performance.now();
  const output = threshold_ed25519_hss_boundary_copy_probe(input);
  const wallMs = performance.now() - started;
  return {
    wallMs,
    decodeArgsMs: numberTiming(output.timings?.decodeArgsMs),
    summarizeMs: numberTiming(output.timings?.summarizeMs),
    totalPayloadBytes: Number(output.totalPayloadBytes || 0),
    checksum: Number(output.checksum || 0),
  };
}

function measureAdvancedStateCensus(advanced) {
  const started = performance.now();
  const output = threshold_ed25519_hss_server_eval_state_size_census({
    serverEvalStateBytes: b64uToBytes(advanced.advancedServerEvalStateB64u),
  });
  const wallMs = performance.now() - started;
  return {
    wallMs,
    totalMessagepackBytes: Number(output.totalMessagepackBytes || 0),
    status: String(output.status || ''),
    currentStage: String(output.currentStage || ''),
    operation: String(output.operation || ''),
    executionStateKind: String(output.executionStateKind || ''),
    fields: normalizeStateFieldSizes(output.fields),
    executionStateFields: normalizeStateFieldSizes(output.executionStateFields),
    timings: {
      decodeStateMs: numberTiming(output.timings?.decodeStateMs),
      summarizeMs: numberTiming(output.timings?.summarizeMs),
    },
  };
}

function measureAdvancedStateStorageEncoding(advanced) {
  const raw = Buffer.from(String(advanced.advancedServerEvalStateB64u || ''), 'base64url');
  const base64UrlTextBytes = Buffer.byteLength(String(advanced.advancedServerEvalStateB64u || ''));
  const jsonEnvelopeBytes = Buffer.byteLength(
    JSON.stringify({
      advancedServerEvalStateB64u: String(advanced.advancedServerEvalStateB64u || ''),
    }),
  );
  const gzipCompressed = measureSyncOperation(() => gzipSync(raw));
  const gzipDecompressed = measureSyncOperation(() => gunzipSync(gzipCompressed.value));
  const deflateCompressed = measureSyncOperation(() => deflateSync(raw));
  const deflateDecompressed = measureSyncOperation(() => inflateSync(deflateCompressed.value));
  if (gzipDecompressed.value.length !== raw.length) {
    throw new Error('gzip advanced-state roundtrip length mismatch');
  }
  if (deflateDecompressed.value.length !== raw.length) {
    throw new Error('deflate advanced-state roundtrip length mismatch');
  }
  return {
    rawBytes: raw.length,
    base64UrlTextBytes,
    jsonEnvelopeBytes,
    gzipBytes: gzipCompressed.value.length,
    gzipCompressMs: gzipCompressed.wallMs,
    gzipDecompressMs: gzipDecompressed.wallMs,
    deflateBytes: deflateCompressed.value.length,
    deflateCompressMs: deflateCompressed.wallMs,
    deflateDecompressMs: deflateDecompressed.wallMs,
  };
}

function measureSyncOperation(operation) {
  const started = performance.now();
  const value = operation();
  return {
    value,
    wallMs: performance.now() - started,
  };
}

function normalizeStateFieldSizes(fields) {
  if (!Array.isArray(fields)) return [];
  return fields
    .map((field) => ({
      label: String(field?.label || ''),
      messagepackBytes: Number(field?.messagepackBytes || 0),
    }))
    .filter((field) => field.label && Number.isFinite(field.messagepackBytes))
    .sort((left, right) => right.messagepackBytes - left.messagepackBytes);
}

function runTailIteration(fixture) {
  const prepareAddStageRequestStarted = performance.now();
  const addStage = threshold_ed25519_hss_prepare_add_stage_request_message({
    ...clientSessionSourceArgs(fixture),
    clientRequestMessageB64u: fixture.clientRequest.clientRequestMessageB64u,
    evaluatorOtStateB64u: fixture.clientRequest.evaluatorOtStateB64u,
    serverInputDeliveryB64u: fixture.delivery.serverInputDeliveryB64u,
  });
  const prepareAddStageRequestMs = performance.now() - prepareAddStageRequestStarted;
  assertContextBinding(
    'iteration add-stage request',
    addStage.contextBindingB64u,
    fixture.expectedContextBindingB64u,
  );

  const { artifact, wallMs: clientArtifactMs } = buildArtifact(fixture, addStage);

  const advanceBoundaryCopyProbe = measureBoundaryCopyProbe({
    evaluatorDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.evaluatorDriverStateB64u,
    ),
    garblerDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.garblerDriverStateB64u,
    ),
    serverEvalStateBytes: b64uToBytes(fixture.delivery.serverEvalStateB64u),
    addStageRequestMessageBytes: b64uToBytes(addStage.addStageRequestMessageB64u),
  });

  const advanceStarted = performance.now();
  const advanced = threshold_ed25519_hss_advance_server_eval_state({
    preparedSessionHandle: '',
    evaluatorDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.evaluatorDriverStateB64u,
    ),
    garblerDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.garblerDriverStateB64u,
    ),
    serverEvalStateBytes: b64uToBytes(fixture.delivery.serverEvalStateB64u),
    addStageRequestMessageBytes: b64uToBytes(addStage.addStageRequestMessageB64u),
    projectionMode: fixture.projectionMode,
  });
  const advanceWallMs = performance.now() - advanceStarted;
  assertContextBinding('advance', advanced.contextBindingB64u, fixture.expectedContextBindingB64u);

  const advancedStateCensus = measureAdvancedStateCensus(advanced);
  const advancedStateStorageEncoding = measureAdvancedStateStorageEncoding(advanced);

  const finalizeBoundaryCopyProbe = measureBoundaryCopyProbe({
    evaluatorDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.evaluatorDriverStateB64u,
    ),
    garblerDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.garblerDriverStateB64u,
    ),
    stagedEvaluatorArtifactBytes: b64uToBytes(artifact.stagedEvaluatorArtifactB64u),
    advancedServerEvalStateBytes: b64uToBytes(advanced.advancedServerEvalStateB64u),
    finalizeContextBytes: b64uToBytes(advanced.finalizeContextB64u),
    priorStageResponseMessageBytes: b64uToBytes(advanced.priorStageResponseMessageB64u),
  });

  const finalizeStarted = performance.now();
  const finalized = threshold_ed25519_hss_finalize_advanced_report({
    preparedSessionHandle: '',
    evaluatorDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.evaluatorDriverStateB64u,
    ),
    garblerDriverStateBytes: b64uToBytes(
      fixture.durablePreparedServerSession.garblerDriverStateB64u,
    ),
    stagedEvaluatorArtifactBytes: b64uToBytes(artifact.stagedEvaluatorArtifactB64u),
    advancedServerEvalStateBytes: b64uToBytes(advanced.advancedServerEvalStateB64u),
    finalizeContextBytes: b64uToBytes(advanced.finalizeContextB64u),
    priorStageResponseMessageBytes: b64uToBytes(advanced.priorStageResponseMessageB64u),
    openSeedOutput: true,
  });
  const finalizeWallMs = performance.now() - finalizeStarted;
  assertContextBinding(
    'finalize',
    finalized.contextBindingB64u,
    fixture.expectedContextBindingB64u,
  );
  if (!String(finalized.xRelayerBaseB64u || '').trim()) {
    throw new Error('finalize did not return opened server output');
  }
  if (!String(finalized.canonicalSeedB64u || '').trim()) {
    throw new Error('finalize did not return opened seed output');
  }

  return {
    prepareAddStageRequestMs,
    clientArtifactMs,
    clientArtifactDecodeClientOutputMaskMs: numberTiming(
      artifact.timings?.decodeClientOutputMaskMs,
    ),
    clientArtifactDecodeEvaluatorOtStateMs: numberTiming(
      artifact.timings?.decodeEvaluatorOtStateMs,
    ),
    clientArtifactDecodeServerInputDeliveryMs: numberTiming(
      artifact.timings?.decodeServerInputDeliveryMs,
    ),
    clientArtifactDecodeClientRequestMessageMs: numberTiming(
      artifact.timings?.decodeClientRequestMessageMs,
    ),
    clientArtifactDecodeEvaluatorDriverStateMs: numberTiming(
      artifact.timings?.decodeEvaluatorDriverStateMs,
    ),
    clientArtifactMaterializeSessionMs: numberTiming(artifact.timings?.materializeSessionMs),
    clientArtifactBuildArtifactMs: numberTiming(artifact.timings?.buildArtifactMs),
    clientArtifactEncodeArtifactMs: numberTiming(artifact.timings?.encodeArtifactMs),
    clientArtifactHiddenEvalTotalMs: numberTiming(artifact.timings?.hiddenEvalTotalMs),
    clientArtifactHiddenEvalInputSharingMs: numberTiming(
      artifact.timings?.hiddenEvalInputSharingMs,
    ),
    clientArtifactHiddenEvalAddStageMs: numberTiming(artifact.timings?.hiddenEvalAddStageMs),
    clientArtifactHiddenEvalMessageScheduleMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationXorAbMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationXorAbMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationSumMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationSumMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationAXorCarryMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationAXorCarryMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationCarryGateMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationCarryGateMs,
    ),
    clientArtifactHiddenEvalMessageScheduleAccumulationNextCarryMs: numberTiming(
      artifact.timings?.hiddenEvalMessageScheduleAccumulationNextCarryMs,
    ),
    clientArtifactHiddenEvalRoundCoreMs: numberTiming(artifact.timings?.hiddenEvalRoundCoreMs),
    clientArtifactHiddenEvalRoundSigma0Ms: numberTiming(artifact.timings?.hiddenEvalRoundSigma0Ms),
    clientArtifactHiddenEvalRoundSigma1Ms: numberTiming(artifact.timings?.hiddenEvalRoundSigma1Ms),
    clientArtifactHiddenEvalRoundChMs: numberTiming(artifact.timings?.hiddenEvalRoundChMs),
    clientArtifactHiddenEvalRoundMajMs: numberTiming(artifact.timings?.hiddenEvalRoundMajMs),
    clientArtifactHiddenEvalRoundState3Ms: numberTiming(artifact.timings?.hiddenEvalRoundState3Ms),
    clientArtifactHiddenEvalRoundTemp1Ms: numberTiming(artifact.timings?.hiddenEvalRoundTemp1Ms),
    clientArtifactHiddenEvalRoundTemp1XorAbMs: numberTiming(
      artifact.timings?.hiddenEvalRoundTemp1XorAbMs,
    ),
    clientArtifactHiddenEvalRoundTemp1SumMs: numberTiming(
      artifact.timings?.hiddenEvalRoundTemp1SumMs,
    ),
    clientArtifactHiddenEvalRoundTemp1AXorCarryMs: numberTiming(
      artifact.timings?.hiddenEvalRoundTemp1AXorCarryMs,
    ),
    clientArtifactHiddenEvalRoundTemp1CarryGateMs: numberTiming(
      artifact.timings?.hiddenEvalRoundTemp1CarryGateMs,
    ),
    clientArtifactHiddenEvalRoundTemp1NextCarryMs: numberTiming(
      artifact.timings?.hiddenEvalRoundTemp1NextCarryMs,
    ),
    clientArtifactHiddenEvalRoundTemp2Ms: numberTiming(artifact.timings?.hiddenEvalRoundTemp2Ms),
    clientArtifactHiddenEvalRoundNewABitsMs: numberTiming(
      artifact.timings?.hiddenEvalRoundNewABitsMs,
    ),
    clientArtifactHiddenEvalRoundNewEBitsMs: numberTiming(
      artifact.timings?.hiddenEvalRoundNewEBitsMs,
    ),
    clientArtifactHiddenEvalOutputProjectorMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorMs,
    ),
    clientArtifactHiddenEvalOutputProjectorCoreMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorCoreMs,
    ),
    clientArtifactHiddenEvalOutputProjectorClampAMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorClampAMs,
    ),
    clientArtifactHiddenEvalOutputProjectorReduceAMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorReduceAMs,
    ),
    clientArtifactHiddenEvalOutputProjectorTauMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorTauMs,
    ),
    clientArtifactHiddenEvalOutputProjectorMaskShareMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorMaskShareMs,
    ),
    clientArtifactHiddenEvalOutputProjectorMaskAddMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorMaskAddMs,
    ),
    clientArtifactHiddenEvalOutputProjectorClientBaseMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorClientBaseMs,
    ),
    clientArtifactHiddenEvalOutputProjectorClientOutputMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorClientOutputMs,
    ),
    clientArtifactHiddenEvalOutputProjectorTauDoubleMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorTauDoubleMs,
    ),
    clientArtifactHiddenEvalOutputProjectorServerOutputMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorServerOutputMs,
    ),
    clientArtifactHiddenEvalOutputProjectorBundleBuildMs: numberTiming(
      artifact.timings?.hiddenEvalOutputProjectorBundleBuildMs,
    ),
    boundaryCopyAdvancePayloadWallMs: advanceBoundaryCopyProbe.wallMs,
    boundaryCopyAdvancePayloadDecodeArgsMs: advanceBoundaryCopyProbe.decodeArgsMs,
    boundaryCopyAdvancePayloadSummarizeMs: advanceBoundaryCopyProbe.summarizeMs,
    advanceWallMs,
    advanceDecodeStateMs: numberTiming(advanced.timings?.decodeStateMs),
    advanceSerializedSessionMaterializeMs: numberTiming(
      advanced.timings?.serializedSessionMaterializeMs,
    ),
    advanceSerializedSessionDecodeMs: numberTiming(advanced.timings?.serializedSessionDecodeMs),
    advanceMaterializeRuntimeMs: numberTiming(advanced.timings?.materializeRuntimeMs),
    advanceMaterializeEvaluatorSessionMs: numberTiming(
      advanced.timings?.materializeEvaluatorSessionMs,
    ),
    advanceMaterializeGarblerSessionMs: numberTiming(advanced.timings?.materializeGarblerSessionMs),
    advanceAddStageResponseMs: numberTiming(advanced.timings?.advanceAddStageResponseMs),
    advanceMessageScheduleRoundsMs: numberTiming(advanced.timings?.advanceMessageScheduleRoundsMs),
    advanceRoundCoreRoundsMs: numberTiming(advanced.timings?.advanceRoundCoreRoundsMs),
    advanceOutputProjectionMs: numberTiming(advanced.timings?.advanceOutputProjectionMs),
    advanceEncodeAdvancedStateMs: numberTiming(advanced.timings?.encodeAdvancedStateMs),
    advancedStateCensusWallMs: advancedStateCensus.wallMs,
    advancedStateCensusDecodeStateMs: advancedStateCensus.timings.decodeStateMs,
    advancedStateCensusSummarizeMs: advancedStateCensus.timings.summarizeMs,
    boundaryCopyFinalizePayloadWallMs: finalizeBoundaryCopyProbe.wallMs,
    boundaryCopyFinalizePayloadDecodeArgsMs: finalizeBoundaryCopyProbe.decodeArgsMs,
    boundaryCopyFinalizePayloadSummarizeMs: finalizeBoundaryCopyProbe.summarizeMs,
    finalizeWallMs,
    finalizeDecodeArtifactMs: numberTiming(finalized.timings?.decodeArtifactMs),
    finalizeSerializedSessionMaterializeMs: numberTiming(
      finalized.timings?.serializedSessionMaterializeMs,
    ),
    finalizeSerializedSessionDecodeMs: numberTiming(finalized.timings?.serializedSessionDecodeMs),
    finalizeMaterializeRuntimeMs: numberTiming(finalized.timings?.materializeRuntimeMs),
    finalizeMaterializeEvaluatorSessionMs: numberTiming(
      finalized.timings?.materializeEvaluatorSessionMs,
    ),
    finalizeMaterializeGarblerSessionMs: numberTiming(
      finalized.timings?.materializeGarblerSessionMs,
    ),
    finalizeOutputProjectionMs: numberTiming(finalized.timings?.advanceOutputProjectionMs),
    finalizeReportMs: numberTiming(finalized.timings?.finalizeReportMs),
    finalizePacketAssemblyMs: numberTiming(finalized.timings?.finalizePacketAssemblyMs),
    finalizeEncodeReportMs: numberTiming(finalized.timings?.encodeReportMs),
    openServerOutputMs: numberTiming(finalized.timings?.openServerOutputMs),
    openSeedOutputMs: numberTiming(finalized.timings?.openSeedOutputMs),
    artifactBytes: b64uByteLength(artifact.stagedEvaluatorArtifactB64u),
    advancedServerEvalStateBytes: b64uByteLength(advanced.advancedServerEvalStateB64u),
    advancedStateRawBytes: advancedStateStorageEncoding.rawBytes,
    advancedStateBase64UrlTextBytes: advancedStateStorageEncoding.base64UrlTextBytes,
    advancedStateJsonEnvelopeBytes: advancedStateStorageEncoding.jsonEnvelopeBytes,
    advancedStateGzipBytes: advancedStateStorageEncoding.gzipBytes,
    advancedStateGzipCompressMs: advancedStateStorageEncoding.gzipCompressMs,
    advancedStateGzipDecompressMs: advancedStateStorageEncoding.gzipDecompressMs,
    advancedStateDeflateBytes: advancedStateStorageEncoding.deflateBytes,
    advancedStateDeflateCompressMs: advancedStateStorageEncoding.deflateCompressMs,
    advancedStateDeflateDecompressMs: advancedStateStorageEncoding.deflateDecompressMs,
    finalizeContextBytes: b64uByteLength(advanced.finalizeContextB64u),
    boundaryCopyAdvancePayloadBytes: advanceBoundaryCopyProbe.totalPayloadBytes,
    boundaryCopyFinalizePayloadBytes: finalizeBoundaryCopyProbe.totalPayloadBytes,
    boundaryCopyChecksum: advanceBoundaryCopyProbe.checksum ^ finalizeBoundaryCopyProbe.checksum,
    advancedStateCensus,
    fingerprint: {
      contextBindingB64u: finalized.contextBindingB64u,
      addStageRequestDigestB64u: advanced.addStageRequestDigestB64u,
      serverOutputDigestB64u: digestB64uField(finalized.serverOutputMessageB64u),
      seedOutputDigestB64u: digestB64uField(finalized.seedOutputMessageB64u),
    },
  };
}

function clientSessionSourceArgs(fixture) {
  switch (CLIENT_SESSION_SOURCE) {
    case 'worker_handle': {
      const workerSessionHandle = String(fixture.clientRequest.workerSessionHandle || '').trim();
      if (!workerSessionHandle) {
        throw new Error('worker_handle client-session benchmark requires workerSessionHandle');
      }
      return {
        sessionSource: 'worker_handle',
        workerSessionHandle,
      };
    }
    case 'serialized_state':
      return {
        sessionSource: 'serialized_state',
        evaluatorDriverStateB64u: fixture.durablePreparedServerSession.evaluatorDriverStateB64u,
      };
    default:
      throw new Error(`Unexpected client session source: ${CLIENT_SESSION_SOURCE}`);
  }
}

function numberTiming(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : 0;
}

function digestB64uField(value) {
  return createHash('sha256')
    .update(Buffer.from(String(value || ''), 'base64url'))
    .digest('base64url');
}

function measureTail(fixture) {
  for (let index = 0; index < WARMUP; index += 1) {
    runTailIteration(fixtureForTailIteration(fixture));
  }
  const samples = [];
  for (let index = 0; index < ITERATIONS; index += 1) {
    samples.push(roundSample(runTailIteration(fixtureForTailIteration(fixture))));
  }
  const firstStableFingerprint = JSON.stringify(stableFingerprint(samples[0]?.fingerprint || {}));
  for (const sample of samples) {
    if (JSON.stringify(stableFingerprint(sample.fingerprint)) !== firstStableFingerprint) {
      throw new Error('tail benchmark stable binding fingerprint changed across samples');
    }
  }
  return {
    label: 'node_registration_tail_durable_wasm',
    warmup: WARMUP,
    iterations: ITERATIONS,
    timingBuckets: ORDERED_BUCKETS.map((label) => ({
      label,
      ...stats(samples.map((sample) => sample[label])),
    })),
    stageLoopBenchmarks: stageLoopBenchmarks(samples),
    storageEncodingBenchmarks: storageEncodingBenchmarks(samples),
    sizes: [
      {
        label: 'staged_evaluator_artifact_bytes',
        ...stats(samples.map((sample) => sample.artifactBytes)),
      },
      {
        label: 'advanced_server_eval_state_bytes',
        ...stats(samples.map((sample) => sample.advancedServerEvalStateBytes)),
      },
      {
        label: 'finalize_context_bytes',
        ...stats(samples.map((sample) => sample.finalizeContextBytes)),
      },
      {
        label: 'boundary_copy_advance_payload_bytes',
        ...stats(samples.map((sample) => sample.boundaryCopyAdvancePayloadBytes)),
      },
      {
        label: 'boundary_copy_finalize_payload_bytes',
        ...stats(samples.map((sample) => sample.boundaryCopyFinalizePayloadBytes)),
      },
    ],
    samples,
    drift: measureDrift(fixture),
    fingerprint: samples[0]?.fingerprint ?? null,
    advancedStateCensus: samples[0]?.advancedStateCensus ?? null,
  };
}

function storageEncodingBenchmarks(samples) {
  return {
    sizes: [
      {
        label: 'advanced_state_raw_messagepack_bytes',
        ...stats(samples.map((sample) => sample.advancedStateRawBytes)),
      },
      {
        label: 'advanced_state_base64url_text_bytes',
        ...stats(samples.map((sample) => sample.advancedStateBase64UrlTextBytes)),
      },
      {
        label: 'advanced_state_json_envelope_bytes',
        ...stats(samples.map((sample) => sample.advancedStateJsonEnvelopeBytes)),
      },
      {
        label: 'advanced_state_gzip_bytes',
        ...stats(samples.map((sample) => sample.advancedStateGzipBytes)),
      },
      {
        label: 'advanced_state_deflate_bytes',
        ...stats(samples.map((sample) => sample.advancedStateDeflateBytes)),
      },
    ],
    timings: [
      {
        label: 'advanced_state_gzip_compress_ms',
        ...stats(samples.map((sample) => sample.advancedStateGzipCompressMs)),
      },
      {
        label: 'advanced_state_gzip_decompress_ms',
        ...stats(samples.map((sample) => sample.advancedStateGzipDecompressMs)),
      },
      {
        label: 'advanced_state_deflate_compress_ms',
        ...stats(samples.map((sample) => sample.advancedStateDeflateCompressMs)),
      },
      {
        label: 'advanced_state_deflate_decompress_ms',
        ...stats(samples.map((sample) => sample.advancedStateDeflateDecompressMs)),
      },
    ],
  };
}

function measureDrift(fixture) {
  if (DRIFT_ITERATIONS <= 0) return null;
  const samples = [];
  for (let index = 0; index < DRIFT_ITERATIONS; index += 1) {
    const iterationFixture = fixtureForTailIteration(fixture);
    const before = memorySnapshot();
    const sample = roundSample(runTailIteration(iterationFixture));
    const after = memorySnapshot();
    samples.push(projectDriftSample(index, sample, before, after));
  }
  const firstStableFingerprint = JSON.stringify(stableFingerprint(samples[0]?.fingerprint || {}));
  for (const sample of samples) {
    if (JSON.stringify(stableFingerprint(sample.fingerprint)) !== firstStableFingerprint) {
      throw new Error('tail benchmark drift binding fingerprint changed across samples');
    }
  }
  return {
    label: 'node_registration_tail_sequential_drift',
    iterations: DRIFT_ITERATIONS,
    timingBuckets: DRIFT_BUCKETS.map((label) => ({
      label,
      ...stats(samples.map((sample) => sample[label])),
    })),
    memory: [
      {
        label: 'near_signer_server_wasm_memory_bytes_after',
        ...stats(samples.map((sample) => sample.nearSignerServerWasmMemoryBytesAfter)),
      },
      {
        label: 'hss_client_signer_wasm_memory_bytes_after',
        ...stats(samples.map((sample) => sample.hssClientSignerWasmMemoryBytesAfter)),
      },
      {
        label: 'node_heap_used_bytes_after',
        ...stats(samples.map((sample) => sample.nodeHeapUsedBytesAfter)),
      },
      {
        label: 'node_rss_bytes_after',
        ...stats(samples.map((sample) => sample.nodeRssBytesAfter)),
      },
    ],
    deltas: driftDeltas(samples),
    samples,
  };
}

function fixtureForTailIteration(fixture) {
  if (CLIENT_SESSION_SOURCE === 'worker_handle') {
    return createBenchmarkFixture();
  }
  return fixture;
}

const DRIFT_BUCKETS = [
  'clientArtifactMs',
  'advanceWallMs',
  'advanceMessageScheduleRoundsMs',
  'advanceRoundCoreRoundsMs',
  'advanceOutputProjectionMs',
  'finalizeWallMs',
];

function projectDriftSample(index, sample, before, after) {
  return {
    iteration: index + 1,
    clientArtifactMs: sample.clientArtifactMs,
    advanceWallMs: sample.advanceWallMs,
    advanceMessageScheduleRoundsMs: sample.advanceMessageScheduleRoundsMs,
    advanceRoundCoreRoundsMs: sample.advanceRoundCoreRoundsMs,
    advanceOutputProjectionMs: sample.advanceOutputProjectionMs,
    finalizeWallMs: sample.finalizeWallMs,
    nearSignerServerWasmMemoryBytesBefore: before.nearSignerServerWasmMemoryBytes,
    nearSignerServerWasmMemoryBytesAfter: after.nearSignerServerWasmMemoryBytes,
    hssClientSignerWasmMemoryBytesBefore: before.hssClientSignerWasmMemoryBytes,
    hssClientSignerWasmMemoryBytesAfter: after.hssClientSignerWasmMemoryBytes,
    thresholdPrfWasmMemoryBytesBefore: before.thresholdPrfWasmMemoryBytes,
    thresholdPrfWasmMemoryBytesAfter: after.thresholdPrfWasmMemoryBytes,
    nodeHeapUsedBytesBefore: before.nodeHeapUsedBytes,
    nodeHeapUsedBytesAfter: after.nodeHeapUsedBytes,
    nodeRssBytesBefore: before.nodeRssBytes,
    nodeRssBytesAfter: after.nodeRssBytes,
    fingerprint: sample.fingerprint,
  };
}

function memorySnapshot() {
  const nodeMemory = process.memoryUsage();
  return {
    nearSignerServerWasmMemoryBytes: wasmMemoryBytes(nearSignerServerWasmExports),
    hssClientSignerWasmMemoryBytes: wasmMemoryBytes(hssClientSignerWasmExports),
    thresholdPrfWasmMemoryBytes: wasmMemoryBytes(thresholdPrfWasmExports),
    nodeHeapUsedBytes: nodeMemory.heapUsed,
    nodeRssBytes: nodeMemory.rss,
  };
}

function wasmMemoryBytes(exports) {
  const byteLength = exports?.memory?.buffer?.byteLength;
  return Number.isFinite(byteLength) ? byteLength : 0;
}

function driftDeltas(samples) {
  if (samples.length === 0) {
    return {
      nearSignerServerWasmMemoryBytes: 0,
      hssClientSignerWasmMemoryBytes: 0,
      thresholdPrfWasmMemoryBytes: 0,
      nodeHeapUsedBytes: 0,
      nodeRssBytes: 0,
    };
  }
  const first = samples[0];
  const last = samples[samples.length - 1];
  return {
    nearSignerServerWasmMemoryBytes:
      last.nearSignerServerWasmMemoryBytesAfter - first.nearSignerServerWasmMemoryBytesBefore,
    hssClientSignerWasmMemoryBytes:
      last.hssClientSignerWasmMemoryBytesAfter - first.hssClientSignerWasmMemoryBytesBefore,
    thresholdPrfWasmMemoryBytes:
      last.thresholdPrfWasmMemoryBytesAfter - first.thresholdPrfWasmMemoryBytesBefore,
    nodeHeapUsedBytes: last.nodeHeapUsedBytesAfter - first.nodeHeapUsedBytesBefore,
    nodeRssBytes: last.nodeRssBytesAfter - first.nodeRssBytesBefore,
  };
}

function stageLoopBenchmarks(samples) {
  const derived = [
    {
      label: 'advance_message_schedule_rounds_ms',
      values: samples.map((sample) => sample.advanceMessageScheduleRoundsMs),
    },
    {
      label: 'advance_round_core_rounds_ms',
      values: samples.map((sample) => sample.advanceRoundCoreRoundsMs),
    },
    {
      label: 'advance_message_schedule_plus_round_core_ms',
      values: samples.map(
        (sample) => sample.advanceMessageScheduleRoundsMs + sample.advanceRoundCoreRoundsMs,
      ),
    },
    {
      label: 'advance_output_projection_ms',
      values: samples.map((sample) => sample.advanceOutputProjectionMs),
    },
    {
      label: 'client_hidden_eval_message_schedule_ms',
      values: samples.map((sample) => sample.clientArtifactHiddenEvalMessageScheduleMs),
    },
    {
      label: 'client_hidden_eval_round_core_ms',
      values: samples.map((sample) => sample.clientArtifactHiddenEvalRoundCoreMs),
    },
    {
      label: 'client_hidden_eval_output_projector_ms',
      values: samples.map((sample) => sample.clientArtifactHiddenEvalOutputProjectorMs),
    },
    {
      label: 'client_hidden_eval_total_ms',
      values: samples.map((sample) => sample.clientArtifactHiddenEvalTotalMs),
    },
    {
      label: 'client_hidden_eval_unattributed_ms',
      values: samples.map(
        (sample) =>
          sample.clientArtifactHiddenEvalTotalMs -
          sample.clientArtifactHiddenEvalMessageScheduleMs -
          sample.clientArtifactHiddenEvalRoundCoreMs -
          sample.clientArtifactHiddenEvalOutputProjectorMs,
      ),
    },
  ];
  return derived.map((entry) => ({
    label: entry.label,
    ...stats(entry.values),
  }));
}

function stableFingerprint(fingerprint) {
  return {
    contextBindingB64u: fingerprint.contextBindingB64u,
  };
}

function roundSample(sample) {
  const out = {};
  for (const [key, value] of Object.entries(sample)) {
    out[key] = typeof value === 'number' ? Number(value.toFixed(3)) : value;
  }
  return out;
}

function stats(values) {
  const finite = values.filter((value) => Number.isFinite(value));
  if (finite.length === 0) return { median: 0, p95: 0, mean: 0, min: 0, max: 0 };
  const sorted = [...finite].sort((left, right) => left - right);
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  const p95Index = Math.min(sorted.length - 1, Math.ceil(sorted.length * 0.95) - 1);
  const mean = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  return {
    median: Number(median.toFixed(3)),
    p95: Number(sorted[p95Index].toFixed(3)),
    mean: Number(mean.toFixed(3)),
    min: Number(sorted[0].toFixed(3)),
    max: Number(sorted[sorted.length - 1].toFixed(3)),
  };
}

function newestPathMtime(targetPath) {
  const entry = statSync(targetPath);
  if (!entry.isDirectory()) return { mtimeMs: entry.mtimeMs, path: targetPath };
  let newest = { mtimeMs: entry.mtimeMs, path: targetPath };
  for (const child of readdirSync(targetPath, { withFileTypes: true })) {
    if (child.isDirectory() && PRUNED_DIR_NAMES.has(child.name)) continue;
    const candidate = newestPathMtime(path.join(targetPath, child.name));
    if (candidate.mtimeMs > newest.mtimeMs) newest = candidate;
  }
  return newest;
}

function collectArtifactProvenance() {
  return WASM_ARTIFACTS.map((artifact) => {
    const wasmStat = statSync(artifact.wasmPath);
    const sha256 = createHash('sha256').update(readFileSync(artifact.wasmPath)).digest('hex');
    let newestSource = { mtimeMs: 0, path: '' };
    for (const root of artifact.sourceRoots) {
      const absolute = path.join(REPO_ROOT, root);
      let candidate;
      try {
        candidate = newestPathMtime(absolute);
      } catch {
        continue;
      }
      if (candidate.mtimeMs > newestSource.mtimeMs) newestSource = candidate;
    }
    return {
      name: artifact.name,
      wasmPath: path.relative(REPO_ROOT, artifact.wasmPath),
      sha256,
      builtAtMs: Math.round(wasmStat.mtimeMs),
      builtAtIso: new Date(wasmStat.mtimeMs).toISOString(),
      newestSourceMtimeMs: Math.round(newestSource.mtimeMs),
      newestSourceIso: new Date(newestSource.mtimeMs).toISOString(),
      newestSourcePath: newestSource.path ? path.relative(REPO_ROOT, newestSource.path) : '',
      stale: newestSource.mtimeMs > wasmStat.mtimeMs,
    };
  });
}

function assertArtifactsFresh(artifacts) {
  const stale = artifacts.filter((artifact) => artifact.stale);
  if (stale.length === 0) return;
  const details = stale
    .map(
      (artifact) =>
        `${artifact.name}: ${artifact.wasmPath} built ${artifact.builtAtIso}, but ${artifact.newestSourcePath} changed ${artifact.newestSourceIso}`,
    )
    .join('\n  ');
  if (ALLOW_STALE_ARTIFACT) {
    console.warn(`[benchmark] WARNING: measuring STALE artifacts:\n  ${details}`);
    return;
  }
  throw new Error(
    `Refusing to benchmark stale WASM artifacts:\n  ${details}\nRun \`pnpm build:wasm\` first, or pass --allow-stale-artifact.`,
  );
}

function renderMarkdown(summary) {
  const bench = summary.benchmark;
  const lines = [];
  lines.push(`# Ed25519 HSS Tail Benchmark ${summary.runId}`);
  lines.push('');
  lines.push(`Fixture: \`${summary.fixture.kind}\``);
  lines.push('');
  lines.push('## Timing Buckets');
  lines.push('');
  lines.push('| Bucket | Median | P95 | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const bucket of bench.timingBuckets) {
    lines.push(
      `| \`${bucket.label}\` | \`${bucket.median}ms\` | \`${bucket.p95}ms\` | \`${bucket.mean}ms\` | \`${bucket.min}ms\` | \`${bucket.max}ms\` |`,
    );
  }
  appendStageLoopBenchmarksMarkdown(lines, bench.stageLoopBenchmarks);
  appendSequentialDriftMarkdown(lines, bench.drift);
  appendStorageEncodingMarkdown(lines, bench.storageEncodingBenchmarks);
  lines.push('');
  lines.push('## Sizes');
  lines.push('');
  lines.push('| Payload | Median bytes | P95 | Max |');
  lines.push('| --- | ---: | ---: | ---: |');
  for (const size of bench.sizes) {
    lines.push(`| \`${size.label}\` | \`${size.median}\` | \`${size.p95}\` | \`${size.max}\` |`);
  }
  appendAdvancedStateCensusMarkdown(lines, bench.advancedStateCensus);
  lines.push('');
  lines.push('## Artifact Provenance');
  lines.push('');
  lines.push('| Artifact | Built | SHA-256 (12) | Freshness |');
  lines.push('| --- | --- | --- | --- |');
  for (const artifact of summary.artifacts) {
    const freshness = artifact.stale
      ? `**STALE** (\`${artifact.newestSourcePath}\` changed ${artifact.newestSourceIso})`
      : 'fresh';
    lines.push(
      `| \`${artifact.name}\` | ${artifact.builtAtIso} | \`${artifact.sha256.slice(0, 12)}\` | ${freshness} |`,
    );
  }
  lines.push('');
  lines.push('Notes:');
  lines.push(
    '- This harness forces `preparedSessionHandle: ""` to model durable Worker/D1 execution.',
  );
  lines.push('- The client artifact path supplies `expectedAddStageRequestMessageB64u`.');
  lines.push('- Server output and seed output opening are folded into durable finalize.');
  return `${lines.join('\n')}\n`;
}

function appendStorageEncodingMarkdown(lines, storageEncoding) {
  if (!storageEncoding) return;
  lines.push('');
  lines.push('## Advanced State Storage Encoding');
  lines.push('');
  lines.push('| Encoding | Median bytes | P95 | Max |');
  lines.push('| --- | ---: | ---: | ---: |');
  for (const size of storageEncoding.sizes || []) {
    lines.push(`| \`${size.label}\` | \`${size.median}\` | \`${size.p95}\` | \`${size.max}\` |`);
  }
  lines.push('');
  lines.push('| Operation | Median | P95 | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const timing of storageEncoding.timings || []) {
    lines.push(
      `| \`${timing.label}\` | \`${timing.median}ms\` | \`${timing.p95}ms\` | \`${timing.mean}ms\` | \`${timing.min}ms\` | \`${timing.max}ms\` |`,
    );
  }
}

function appendSequentialDriftMarkdown(lines, drift) {
  if (!drift) return;
  lines.push('');
  lines.push('## Sequential Drift');
  lines.push('');
  lines.push(`Iterations: \`${drift.iterations}\``);
  lines.push('');
  lines.push('| Bucket | Median | P95 | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const bucket of drift.timingBuckets) {
    lines.push(
      `| \`${bucket.label}\` | \`${bucket.median}ms\` | \`${bucket.p95}ms\` | \`${bucket.mean}ms\` | \`${bucket.min}ms\` | \`${bucket.max}ms\` |`,
    );
  }
  lines.push('');
  lines.push('| Memory | Median bytes | P95 | Min | Max | Delta first-before to last-after |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const memory of drift.memory) {
    lines.push(
      `| \`${memory.label}\` | \`${memory.median}\` | \`${memory.p95}\` | \`${memory.min}\` | \`${memory.max}\` | \`${driftMemoryDelta(drift.deltas, memory.label)}\` |`,
    );
  }
}

function driftMemoryDelta(deltas, label) {
  switch (label) {
    case 'near_signer_server_wasm_memory_bytes_after':
      return deltas.nearSignerServerWasmMemoryBytes;
    case 'hss_client_signer_wasm_memory_bytes_after':
      return deltas.hssClientSignerWasmMemoryBytes;
    case 'node_heap_used_bytes_after':
      return deltas.nodeHeapUsedBytes;
    case 'node_rss_bytes_after':
      return deltas.nodeRssBytes;
    default:
      return 0;
  }
}

function appendStageLoopBenchmarksMarkdown(lines, stageLoopBenchmarks) {
  if (!Array.isArray(stageLoopBenchmarks) || stageLoopBenchmarks.length === 0) return;
  lines.push('');
  lines.push('## Stage Loop Microbenchmarks');
  lines.push('');
  lines.push('| Loop | Median | P95 | Mean | Min | Max |');
  lines.push('| --- | ---: | ---: | ---: | ---: | ---: |');
  for (const bucket of stageLoopBenchmarks) {
    lines.push(
      `| \`${bucket.label}\` | \`${bucket.median}ms\` | \`${bucket.p95}ms\` | \`${bucket.mean}ms\` | \`${bucket.min}ms\` | \`${bucket.max}ms\` |`,
    );
  }
}

function appendAdvancedStateCensusMarkdown(lines, census) {
  if (!census) return;
  lines.push('');
  lines.push('## Advanced State Census');
  lines.push('');
  lines.push(`Total MessagePack bytes: \`${census.totalMessagepackBytes}\``);
  lines.push(`Execution state: \`${census.executionStateKind}\``);
  lines.push('');
  lines.push('| Field | MessagePack bytes |');
  lines.push('| --- | ---: |');
  for (const field of (census.fields || []).slice(0, 8)) {
    lines.push(`| \`${field.label}\` | \`${field.messagepackBytes}\` |`);
  }
  if ((census.executionStateFields || []).length > 0) {
    lines.push('');
    lines.push('| Execution field | MessagePack bytes |');
    lines.push('| --- | ---: |');
    for (const field of census.executionStateFields.slice(0, 8)) {
      lines.push(`| \`${field.label}\` | \`${field.messagepackBytes}\` |`);
    }
  }
}

async function main() {
  const artifacts = collectArtifactProvenance();
  assertArtifactsFresh(artifacts);
  ensureWasm();
  const fixture = createBenchmarkFixture();
  const benchmark = measureTail(fixture);
  const runId = new Date().toISOString().replace(/[:.]/g, '-');
  const outDir = path.join(OUT_ROOT, runId);
  mkdirSync(outDir, { recursive: true });
  const summary = {
    kind: 'ed25519_hss_tail_benchmark_summary_v1',
    runId,
    options: {
      warmup: WARMUP,
      iterations: ITERATIONS,
      driftIterations: DRIFT_ITERATIONS,
      clientSessionSource: CLIENT_SESSION_SOURCE,
      allowStaleArtifact: ALLOW_STALE_ARTIFACT,
    },
    artifacts,
    fixture: {
      kind: fixture.kind,
      context: fixture.context,
      projectionMode: fixture.projectionMode,
      expectedContextBindingB64u: fixture.expectedContextBindingB64u,
    },
    benchmark,
  };
  const rawSummaryPath = path.join(outDir, 'raw-summary.json');
  const markdownPath = path.join(outDir, 'summary.md');
  writeFileSync(rawSummaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  writeFileSync(markdownPath, renderMarkdown(summary));

  console.log(`[benchmark] run_id=${runId}`);
  console.log(`[benchmark] summary_json=${rawSummaryPath}`);
  console.log(`[benchmark] summary_markdown=${markdownPath}`);
  for (const bucket of benchmark.timingBuckets) {
    if (
      bucket.label === 'clientArtifactMs' ||
      bucket.label === 'boundaryCopyAdvancePayloadWallMs' ||
      bucket.label === 'advanceWallMs' ||
      bucket.label === 'boundaryCopyFinalizePayloadWallMs' ||
      bucket.label === 'finalizeWallMs' ||
      bucket.label === 'openServerOutputMs' ||
      bucket.label === 'openSeedOutputMs'
    ) {
      console.log(`[benchmark] ${bucket.label} median_ms=${bucket.median} p95_ms=${bucket.p95}`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
