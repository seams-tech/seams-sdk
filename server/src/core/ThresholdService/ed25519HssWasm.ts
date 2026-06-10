import wasmSignerServerDefault, {
  init_worker as init_worker_server,
  threshold_ed25519_hss_finalize_report as threshold_ed25519_hss_finalize_report_server,
  threshold_ed25519_hss_open_seed_output as threshold_ed25519_hss_open_seed_output_server,
  threshold_ed25519_hss_open_server_output as threshold_ed25519_hss_open_server_output_server,
  threshold_ed25519_hss_public_key_from_base_shares as threshold_ed25519_hss_public_key_from_base_shares_server,
  threshold_ed25519_hss_prepare_server_ceremony as threshold_ed25519_hss_prepare_server_ceremony_server,
  threshold_ed25519_hss_release_prepared_server_session as threshold_ed25519_hss_release_prepared_server_session_server,
  threshold_ed25519_hss_release_staged_evaluator_artifact as threshold_ed25519_hss_release_staged_evaluator_artifact_server,
  threshold_ed25519_hss_verifying_share_from_signing_share as threshold_ed25519_hss_verifying_share_from_signing_share_server,
  threshold_ed25519_recovery_keypair_from_seed as threshold_ed25519_recovery_keypair_from_seed_server,
} from '../../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import * as wasmSignerServerModule from '../../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import type { InitInput } from '../../../../wasm/near_signer/pkg-server/wasm_signer_worker.js';
import { createWasmLoader, isNodeEnvironment } from '../wasm-loader';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientRequestEnvelope,
  ThresholdEd25519HssDerivedPublicKey,
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssOpenedSeedOutput,
  ThresholdEd25519HssOpenedServerOutput,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssPreparedServerSessionEnvelope,
  ThresholdEd25519HssPrepareServerSessionTimings,
  ThresholdEd25519HssServerInputDeliveryEnvelope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdEd25519HssSessionOperation,
  ThresholdEd25519HssStoredPreparedServerSession,
  ThresholdEd25519HssStoredServerInputs,
  ThresholdEd25519HssStoredStagedEvaluatorArtifact,
  ThresholdEd25519HssStagedEvaluatorArtifactEnvelope,
} from '../types';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';

const SIGNER_WASM_PATH_CANDIDATES = [
  '../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../../../wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm',
  '../../../../workers/wasm_signer_worker_bg.wasm',
  '../../../workers/wasm_signer_worker_bg.wasm',
];

const NATIVE_DRIVER_PATH_CANDIDATES = [
  '../../../../crates/ed25519-hss/target/release/prime_order_succinct_hss_driver',
  '../../../../../crates/ed25519-hss/target/release/prime_order_succinct_hss_driver',
  '../../../../../../crates/ed25519-hss/target/release/prime_order_succinct_hss_driver',
];

const NATIVE_MANIFEST_PATH_CANDIDATES = [
  '../../../../crates/ed25519-hss/Cargo.toml',
  '../../../../../crates/ed25519-hss/Cargo.toml',
  '../../../../../../crates/ed25519-hss/Cargo.toml',
];

const threshold_ed25519_hss_prepare_server_session_server = (
  wasmSignerServerModule as Record<string, unknown>
).threshold_ed25519_hss_prepare_server_session as (args: {
  signingRootId: string;
  nearAccountId: string;
  keyPurpose: string;
  keyVersion: string;
  participantIds: number[];
  derivationVersion: number;
}) => {
  contextBindingB64u: string;
  evaluatorDriverStateB64u: string;
  garblerDriverStateB64u: string;
  clientOtOfferMessageB64u: string;
  preparedSessionHandle: string;
};

const threshold_ed25519_hss_prepare_role_separated_server_input_delivery_server = (
  wasmSignerServerModule as Record<string, unknown>
).threshold_ed25519_hss_prepare_role_separated_server_input_delivery as (args: {
  operation: ThresholdEd25519HssSessionOperation | 'registration';
  preparedSessionHandle: string;
  garblerDriverStateBytes: Uint8Array;
  clientRequestMessageBytes: Uint8Array;
  yRelayerBytes: Uint8Array;
  tauRelayerBytes: Uint8Array;
}) => {
  contextBindingB64u: string;
  serverInputDeliveryB64u: string;
  timings?: {
    decodeMessagesMs?: number;
    materializeSessionMs?: number;
    prepareDeliveryMs?: number;
    encodeDeliveryMs?: number;
  };
};

type ThresholdEd25519HssServerCeremonyTimings = {
  decodeStatesMs: number;
  decodeMessagesMs: number;
  materializeRuntimeMs: number;
  materializeSessionsMs: number;
  ceremonyCoreMs: number;
  ceremonyOtOpenJoinMs: number;
  ceremonyOtBranchKeyDerivationMs: number;
  ceremonyOtBranchDecryptMs: number;
  ceremonyOtPointScalarReconstructionMs: number;
  ceremonyOtCommitmentVerificationMs: number;
  ceremonyServerInputOpenMs: number;
  ceremonyServerInputShareMs: number;
  ceremonyServerInputCommitmentMs: number;
  ceremonyServerInputTranscriptMs: number;
  ceremonyAddStageMs: number;
  ceremonyMessageScheduleMs: number;
  ceremonyRoundCoreMs: number;
  ceremonyOutputProjectorMs: number;
  ceremonyResultAssemblyMs: number;
  ceremonyOutputSealingFinalizationMs: number;
  encodeArtifactMs: number;
};

type ThresholdEd25519HssServerInputDeliveryTimings = {
  decodeMessagesMs: number;
  materializeSessionMs: number;
  prepareDeliveryMs: number;
  deliveryOtOpenJoinMs: number;
  deliveryServerInputOpenMs: number;
  deliveryServerInputShareMs: number;
  deliveryServerInputCommitmentMs: number;
  deliveryServerInputTranscriptMs: number;
  deliveryServerInputSealMs: number;
  encodeDeliveryMs: number;
};

type ThresholdEd25519HssFinalizeReportTimings = {
  decodeArtifactMs: number;
  serializedSessionMaterializeMs: number;
  finalizeReportMs: number;
  encodeReportMs: number;
};

type ThresholdEd25519HssFinalizeForRegistrationTimings =
  ThresholdEd25519HssFinalizeReportTimings & {
    openServerOutputMs: number;
    openSeedOutputMs: number;
    deriveSeedKeypairMs: number;
    deriveRelayerVerifyingShareMs: number;
    keyStorePutMs: number;
  };

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

function getNativeDriverUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of NATIVE_DRIVER_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore invalid candidate
    }
  }
  return resolved;
}

function getNativeManifestUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of NATIVE_MANIFEST_PATH_CANDIDATES) {
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
let thresholdEd25519HssNativeDriverPathPromise: Promise<string | null> | null = null;

function isThresholdEd25519HssNativeDriverDisabled(): boolean {
  if (!isNodeEnvironment()) return true;
  const raw = String(process.env.THRESHOLD_ED25519_HSS_DISABLE_NATIVE_DRIVER || '')
    .trim()
    .toLowerCase();
  return raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on';
}

async function initThresholdEd25519HssSignerWasm(input: {
  module_or_path: InitInput;
}): Promise<void> {
  await wasmSignerServerDefault(input);
  init_worker_server();
  thresholdEd25519HssWasmReady = true;
}

function getNativeDriverExecutableName(): string {
  return process.platform === 'win32'
    ? 'prime_order_succinct_hss_driver.exe'
    : 'prime_order_succinct_hss_driver';
}

async function resolveExistingNativeDriverPath(): Promise<string | null> {
  if (!isNodeEnvironment()) return null;
  const [{ access, constants }, { fileURLToPath }] = await Promise.all([
    import('node:fs/promises'),
    import('node:url'),
  ]);
  for (const url of getNativeDriverUrls()) {
    const path = fileURLToPath(url);
    try {
      await access(path, constants.F_OK);
      return path;
    } catch {
      // try next candidate
    }
  }
  return null;
}

async function newestPathMtimeMs(path: string): Promise<number> {
  const [{ readdir, stat }, pathMod] = await Promise.all([
    import('node:fs/promises'),
    import('node:path'),
  ]);
  const entry = await stat(path);
  if (!entry.isDirectory()) return entry.mtimeMs;

  let newest = entry.mtimeMs;
  const children = await readdir(path, { withFileTypes: true });
  for (const child of children) {
    newest = Math.max(newest, await newestPathMtimeMs(pathMod.join(path, child.name)));
  }
  return newest;
}

async function nativeDriverNeedsRebuild(
  binaryPath: string,
  manifestPath: string,
): Promise<boolean> {
  const [{ stat }, pathMod] = await Promise.all([import('node:fs/promises'), import('node:path')]);
  let binaryMtimeMs = 0;
  try {
    binaryMtimeMs = (await stat(binaryPath)).mtimeMs;
  } catch {
    return true;
  }

  const crateDir = pathMod.dirname(manifestPath);
  const workspaceDir = pathMod.resolve(crateDir, '..', '..');
  const candidateInputs = [
    manifestPath,
    pathMod.join(crateDir, 'Cargo.lock'),
    pathMod.join(crateDir, 'src'),
    pathMod.join(workspaceDir, 'Cargo.lock'),
    pathMod.join(workspaceDir, 'wasm', 'near_signer', 'Cargo.toml'),
    pathMod.join(workspaceDir, 'wasm', 'near_signer', 'Cargo.lock'),
    pathMod.join(workspaceDir, 'wasm', 'near_signer', 'src'),
    pathMod.join(workspaceDir, 'wasm', 'hss_client_signer', 'Cargo.toml'),
    pathMod.join(workspaceDir, 'wasm', 'hss_client_signer', 'Cargo.lock'),
    pathMod.join(workspaceDir, 'wasm', 'hss_client_signer', 'src'),
  ];
  let newestSourceMtimeMs = 0;
  for (const candidate of candidateInputs) {
    try {
      newestSourceMtimeMs = Math.max(newestSourceMtimeMs, await newestPathMtimeMs(candidate));
    } catch {
      // ignore missing candidate
    }
  }

  return newestSourceMtimeMs > binaryMtimeMs;
}

async function buildNativeDriverFromManifest(manifestPath: string): Promise<string | null> {
  const [{ spawn }, pathMod] = await Promise.all([
    import('node:child_process'),
    import('node:path'),
  ]);
  const binaryPath = pathMod.join(
    pathMod.dirname(manifestPath),
    'target',
    'release',
    getNativeDriverExecutableName(),
  );
  await new Promise<void>((resolve, reject) => {
    const child = spawn(
      'cargo',
      [
        'build',
        '--release',
        '--manifest-path',
        manifestPath,
        '--bin',
        'prime_order_succinct_hss_driver',
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr += String(chunk || '');
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(
        new Error(
          `[threshold-ed25519-hss] failed to build native driver (exit ${String(code)}): ${stderr.trim()}`,
        ),
      );
    });
  });
  const { access, constants } = await import('node:fs/promises');
  try {
    await access(binaryPath, constants.F_OK);
    return binaryPath;
  } catch {
    return null;
  }
}

async function ensureThresholdEd25519HssNativeDriverPath(): Promise<string | null> {
  if (!isNodeEnvironment()) return null;
  if (isThresholdEd25519HssNativeDriverDisabled()) return null;
  if (thresholdEd25519HssNativeDriverPathPromise) {
    return thresholdEd25519HssNativeDriverPathPromise;
  }
  thresholdEd25519HssNativeDriverPathPromise = (async () => {
    const [{ fileURLToPath }, pathMod] = await Promise.all([
      import('node:url'),
      import('node:path'),
    ]);
    for (const manifestUrl of getNativeManifestUrls()) {
      try {
        const manifestPath = fileURLToPath(manifestUrl);
        const binaryPath = pathMod.join(
          pathMod.dirname(manifestPath),
          'target',
          'release',
          getNativeDriverExecutableName(),
        );
        if (!(await nativeDriverNeedsRebuild(binaryPath, manifestPath))) {
          return binaryPath;
        }
        const built = await buildNativeDriverFromManifest(manifestPath);
        if (built) return built;
      } catch {
        // try next manifest candidate
      }
    }
    const existing = await resolveExistingNativeDriverPath();
    if (existing) return existing;
    return null;
  })();
  return thresholdEd25519HssNativeDriverPathPromise;
}

async function prepareThresholdEd25519HssServerCeremonyNative(input: {
  operation: ThresholdEd25519HssSessionOperation | 'registration';
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
  expectedContextBindingB64u: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputs: ThresholdEd25519HssStoredServerInputs;
}): Promise<{
  evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
  timings?: ThresholdEd25519HssServerCeremonyTimings;
}> {
  const driverPath = await ensureThresholdEd25519HssNativeDriverPath();
  if (!driverPath) {
    throw new Error('[threshold-ed25519-hss] native driver unavailable');
  }

  const { spawn } = await import('node:child_process');
  const payload = JSON.stringify({
    preparedServerSession: {
      evaluatorDriverStateB64u: base64UrlEncode(
        input.preparedServerSession.evaluatorDriverStateBytes,
      ),
      garblerDriverStateB64u: base64UrlEncode(input.preparedServerSession.garblerDriverStateBytes),
    },
    clientRequest: {
      clientRequestMessageB64u: input.clientRequest.clientRequestMessageB64u,
      evaluatorOtStateB64u: input.clientRequest.evaluatorOtStateB64u,
    },
    serverInputs: {
      yRelayerB64u: base64UrlEncode(input.serverInputs.yRelayerBytes),
      tauRelayerB64u: base64UrlEncode(input.serverInputs.tauRelayerBytes),
    },
    operation: input.operation,
  });

  const stdout = await new Promise<string>((resolve, reject) => {
    const child = spawn(driverPath, ['server-ceremony-json'], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (chunk) => {
      out += String(chunk || '');
    });
    child.stderr.on('data', (chunk) => {
      err += String(chunk || '');
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (code === 0) {
        resolve(out);
        return;
      }
      reject(
        new Error(
          `[threshold-ed25519-hss] native driver ceremony failed (exit ${String(code)}): ${err.trim()}`,
        ),
      );
    });
    child.stdin.end(payload);
  });

  const result = JSON.parse(stdout) as {
    contextBindingB64u: string;
    stagedEvaluatorArtifactB64u: string;
  };

  return {
    evaluationResult: {
      contextBindingB64u: String(result.contextBindingB64u || '').trim(),
      stagedEvaluatorArtifactBytes: base64UrlDecode(
        String(result.stagedEvaluatorArtifactB64u || '').trim(),
      ),
    },
  };
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

export async function prepareThresholdEd25519HssServerSession(input: {
  context: ThresholdEd25519HssCanonicalContext;
}): Promise<ThresholdEd25519HssPreparedServerSessionEnvelope> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_prepare_server_session_server({
    signingRootId: input.context.signingRootId,
    nearAccountId: input.context.nearAccountId,
    keyPurpose: input.context.keyPurpose,
    keyVersion: input.context.keyVersion,
    participantIds: input.context.participantIds,
    derivationVersion: input.context.derivationVersion,
  }) as {
    contextBindingB64u: string;
    evaluatorDriverStateB64u: string;
    garblerDriverStateB64u: string;
    clientOtOfferMessageB64u: string;
    preparedSessionHandle: string;
    timings?: {
      prepareSessionMs?: number;
      extractDriverStatesMs?: number;
      clientOfferMessageMs?: number;
      cachePreparedSessionMs?: number;
      encodeStatesMs?: number;
    };
  };
  const timings: ThresholdEd25519HssPrepareServerSessionTimings = {
    prepareSessionMs: Number(result.timings?.prepareSessionMs || 0),
    extractDriverStatesMs: Number(result.timings?.extractDriverStatesMs || 0),
    clientOfferMessageMs: Number(result.timings?.clientOfferMessageMs || 0),
    cachePreparedSessionMs: Number(result.timings?.cachePreparedSessionMs || 0),
    encodeStatesMs: Number(result.timings?.encodeStatesMs || 0),
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    evaluatorDriverStateB64u: String(result.evaluatorDriverStateB64u || '').trim(),
    garblerDriverStateB64u: String(result.garblerDriverStateB64u || '').trim(),
    clientOtOfferMessageB64u: String(result.clientOtOfferMessageB64u || '').trim(),
    preparedSessionHandle: String(result.preparedSessionHandle || '').trim(),
    timings,
  };
}

export function releaseThresholdEd25519HssPreparedServerSession(handleRaw: unknown): void {
  const handle = String(handleRaw || '').trim();
  if (!handle || !thresholdEd25519HssWasmReady) return;
  threshold_ed25519_hss_release_prepared_server_session_server(handle);
}

export function releaseThresholdEd25519HssStagedEvaluatorArtifact(handleRaw: unknown): void {
  const handle = String(handleRaw || '').trim();
  if (!handle || !thresholdEd25519HssWasmReady) return;
  threshold_ed25519_hss_release_staged_evaluator_artifact_server(handle);
}

export async function prepareThresholdEd25519HssServerCeremony(input: {
  operation: ThresholdEd25519HssSessionOperation | 'registration';
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
  expectedContextBindingB64u: string;
  clientRequest: ThresholdEd25519HssClientRequestEnvelope;
  serverInputs: ThresholdEd25519HssStoredServerInputs;
}): Promise<{
  engine: 'native' | 'wasm';
  evaluationResult: ThresholdEd25519HssStagedEvaluatorArtifactEnvelope;
  timings?: ThresholdEd25519HssServerCeremonyTimings;
}> {
  const expectedBinding = String(input.expectedContextBindingB64u || '').trim();
  if (!expectedBinding) {
    throw new Error(
      '[threshold-ed25519-hss] context binding mismatch during server ceremony preparation',
    );
  }

  const nativeDriverPath = await ensureThresholdEd25519HssNativeDriverPath();
  if (nativeDriverPath) {
    const nativeResult = await prepareThresholdEd25519HssServerCeremonyNative(input);
    if (nativeResult.evaluationResult.contextBindingB64u !== expectedBinding) {
      throw new Error(
        '[threshold-ed25519-hss] native staged evaluator artifact context binding mismatch',
      );
    }
    return { engine: 'native', ...nativeResult };
  }

  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_prepare_server_ceremony_server({
    operation: input.operation,
    preparedSessionHandle: String(input.preparedServerSession.preparedSessionHandle || '').trim(),
    evaluatorDriverStateBytes: input.preparedServerSession.evaluatorDriverStateBytes,
    garblerDriverStateBytes: input.preparedServerSession.garblerDriverStateBytes,
    clientRequestMessageBytes: base64UrlDecode(input.clientRequest.clientRequestMessageB64u),
    evaluatorOtStateBytes: base64UrlDecode(input.clientRequest.evaluatorOtStateB64u),
    yRelayerBytes: input.serverInputs.yRelayerBytes,
    tauRelayerBytes: input.serverInputs.tauRelayerBytes,
  }) as {
    contextBindingB64u: string;
    stagedEvaluatorArtifactHandle: string;
    timings?: {
      decodeStatesMs?: number;
      decodeMessagesMs?: number;
      materializeRuntimeMs?: number;
      materializeSessionsMs?: number;
      ceremonyCoreMs?: number;
      ceremonyOtOpenJoinMs?: number;
      ceremonyOtBranchKeyDerivationMs?: number;
      ceremonyOtBranchDecryptMs?: number;
      ceremonyOtPointScalarReconstructionMs?: number;
      ceremonyOtCommitmentVerificationMs?: number;
      ceremonyServerInputOpenMs?: number;
      ceremonyServerInputShareMs?: number;
      ceremonyServerInputCommitmentMs?: number;
      ceremonyServerInputTranscriptMs?: number;
      ceremonyAddStageMs?: number;
      ceremonyMessageScheduleMs?: number;
      ceremonyRoundCoreMs?: number;
      ceremonyOutputProjectorMs?: number;
      ceremonyResultAssemblyMs?: number;
      ceremonyOutputSealingFinalizationMs?: number;
      encodeArtifactMs?: number;
    };
  };

  const evaluationResult = {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    stagedEvaluatorArtifactHandle: String(result.stagedEvaluatorArtifactHandle || '').trim(),
  };
  if (evaluationResult.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] staged evaluator artifact context binding mismatch');
  }

  return {
    engine: 'wasm',
    evaluationResult,
    timings: result.timings
      ? {
          decodeStatesMs: Number(result.timings.decodeStatesMs || 0),
          decodeMessagesMs: Number(result.timings.decodeMessagesMs || 0),
          materializeRuntimeMs: Number(result.timings.materializeRuntimeMs || 0),
          materializeSessionsMs: Number(result.timings.materializeSessionsMs || 0),
          ceremonyCoreMs: Number(result.timings.ceremonyCoreMs || 0),
          ceremonyOtOpenJoinMs: Number(result.timings.ceremonyOtOpenJoinMs || 0),
          ceremonyOtBranchKeyDerivationMs: Number(
            result.timings.ceremonyOtBranchKeyDerivationMs || 0,
          ),
          ceremonyOtBranchDecryptMs: Number(result.timings.ceremonyOtBranchDecryptMs || 0),
          ceremonyOtPointScalarReconstructionMs: Number(
            result.timings.ceremonyOtPointScalarReconstructionMs || 0,
          ),
          ceremonyOtCommitmentVerificationMs: Number(
            result.timings.ceremonyOtCommitmentVerificationMs || 0,
          ),
          ceremonyServerInputOpenMs: Number(result.timings.ceremonyServerInputOpenMs || 0),
          ceremonyServerInputShareMs: Number(result.timings.ceremonyServerInputShareMs || 0),
          ceremonyServerInputCommitmentMs: Number(
            result.timings.ceremonyServerInputCommitmentMs || 0,
          ),
          ceremonyServerInputTranscriptMs: Number(
            result.timings.ceremonyServerInputTranscriptMs || 0,
          ),
          ceremonyAddStageMs: Number(result.timings.ceremonyAddStageMs || 0),
          ceremonyMessageScheduleMs: Number(result.timings.ceremonyMessageScheduleMs || 0),
          ceremonyRoundCoreMs: Number(result.timings.ceremonyRoundCoreMs || 0),
          ceremonyOutputProjectorMs: Number(result.timings.ceremonyOutputProjectorMs || 0),
          ceremonyResultAssemblyMs: Number(result.timings.ceremonyResultAssemblyMs || 0),
          ceremonyOutputSealingFinalizationMs: Number(
            result.timings.ceremonyOutputSealingFinalizationMs || 0,
          ),
          encodeArtifactMs: Number(result.timings.encodeArtifactMs || 0),
        }
      : undefined,
  };
}

export async function prepareThresholdEd25519HssRoleSeparatedServerInputDelivery(input: {
  operation: ThresholdEd25519HssSessionOperation | 'registration';
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
  expectedContextBindingB64u: string;
  clientRequest: ThresholdEd25519HssServerVisibleClientRequestEnvelope;
  serverInputs: ThresholdEd25519HssStoredServerInputs;
}): Promise<{
  engine: 'wasm';
  serverInputDelivery: ThresholdEd25519HssServerInputDeliveryEnvelope;
  timings?: ThresholdEd25519HssServerInputDeliveryTimings;
}> {
  const expectedBinding = String(input.expectedContextBindingB64u || '').trim();
  if (!expectedBinding) {
    throw new Error(
      '[threshold-ed25519-hss] context binding mismatch during server-input delivery preparation',
    );
  }

  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_prepare_role_separated_server_input_delivery_server({
    operation: input.operation,
    preparedSessionHandle: String(input.preparedServerSession.preparedSessionHandle || '').trim(),
    garblerDriverStateBytes: input.preparedServerSession.garblerDriverStateBytes,
    clientRequestMessageBytes: base64UrlDecode(input.clientRequest.clientRequestMessageB64u),
    yRelayerBytes: input.serverInputs.yRelayerBytes,
    tauRelayerBytes: input.serverInputs.tauRelayerBytes,
  }) as {
    contextBindingB64u: string;
    serverInputDeliveryB64u: string;
    timings?: {
      decodeMessagesMs?: number;
      materializeSessionMs?: number;
      prepareDeliveryMs?: number;
      deliveryOtOpenJoinMs?: number;
      deliveryServerInputOpenMs?: number;
      deliveryServerInputShareMs?: number;
      deliveryServerInputCommitmentMs?: number;
      deliveryServerInputTranscriptMs?: number;
      deliveryServerInputSealMs?: number;
      encodeDeliveryMs?: number;
    };
  };

  const serverInputDelivery = {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    serverInputDeliveryB64u: String(result.serverInputDeliveryB64u || '').trim(),
  };
  if (serverInputDelivery.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] server-input delivery context binding mismatch');
  }
  if (!serverInputDelivery.serverInputDeliveryB64u) {
    throw new Error('[threshold-ed25519-hss] server-input delivery is empty');
  }

  return {
    engine: 'wasm',
    serverInputDelivery,
    timings: result.timings
      ? {
          decodeMessagesMs: Number(result.timings.decodeMessagesMs || 0),
          materializeSessionMs: Number(result.timings.materializeSessionMs || 0),
          prepareDeliveryMs: Number(result.timings.prepareDeliveryMs || 0),
          deliveryOtOpenJoinMs: Number(result.timings.deliveryOtOpenJoinMs || 0),
          deliveryServerInputOpenMs: Number(result.timings.deliveryServerInputOpenMs || 0),
          deliveryServerInputShareMs: Number(result.timings.deliveryServerInputShareMs || 0),
          deliveryServerInputCommitmentMs: Number(
            result.timings.deliveryServerInputCommitmentMs || 0,
          ),
          deliveryServerInputTranscriptMs: Number(
            result.timings.deliveryServerInputTranscriptMs || 0,
          ),
          deliveryServerInputSealMs: Number(result.timings.deliveryServerInputSealMs || 0),
          encodeDeliveryMs: Number(result.timings.encodeDeliveryMs || 0),
        }
      : undefined,
  };
}

export async function finalizeThresholdEd25519HssReport(input: {
  preparedServerSession: Pick<
    ThresholdEd25519HssStoredPreparedServerSession,
    'preparedSessionHandle' | 'garblerDriverStateBytes'
  >;
  evaluationResult: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
}): Promise<{
  contextBindingB64u: string;
  clientOutputMessageB64u: string;
  seedOutputMessageB64u: string;
  serverOutputMessageB64u: string;
  timings?: ThresholdEd25519HssFinalizeReportTimings;
}> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_finalize_report_server({
    preparedSessionHandle: String(input.preparedServerSession.preparedSessionHandle || '').trim(),
    garblerDriverStateBytes: input.preparedServerSession.garblerDriverStateBytes,
    stagedEvaluatorArtifactHandle: String(
      input.evaluationResult.stagedEvaluatorArtifactHandle || '',
    ).trim(),
    stagedEvaluatorArtifactBytes:
      input.evaluationResult.stagedEvaluatorArtifactBytes ?? new Uint8Array(),
  }) as {
    contextBindingB64u: string;
    evaluationReportJson: string;
    clientOutputMessageB64u: string;
    seedOutputMessageB64u: string;
    serverOutputMessageB64u: string;
    timings?: {
      decodeArtifactMs?: number;
      serializedSessionMaterializeMs?: number;
      finalizeReportMs?: number;
      encodeReportMs?: number;
    };
  };

  return {
    contextBindingB64u: String(result.contextBindingB64u || '').trim(),
    clientOutputMessageB64u: String(result.clientOutputMessageB64u || '').trim(),
    seedOutputMessageB64u: String(result.seedOutputMessageB64u || '').trim(),
    serverOutputMessageB64u: String(result.serverOutputMessageB64u || '').trim(),
    timings: result.timings
      ? {
          decodeArtifactMs: Number(result.timings.decodeArtifactMs || 0),
          serializedSessionMaterializeMs: Number(
            result.timings.serializedSessionMaterializeMs || 0,
          ),
          finalizeReportMs: Number(result.timings.finalizeReportMs || 0),
          encodeReportMs: Number(result.timings.encodeReportMs || 0),
        }
      : undefined,
  };
}

export async function openThresholdEd25519HssServerOutput(input: {
  preparedServerSession: Pick<
    ThresholdEd25519HssStoredPreparedServerSession,
    'preparedSessionHandle' | 'garblerDriverStateBytes'
  >;
  finalizedReport: { serverOutputMessageB64u: string };
}): Promise<ThresholdEd25519HssOpenedServerOutput> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_open_server_output_server({
    preparedSessionHandle: String(input.preparedServerSession.preparedSessionHandle || '').trim(),
    garblerDriverStateBytes: input.preparedServerSession.garblerDriverStateBytes,
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
  preparedServerSession: Pick<
    ThresholdEd25519HssStoredPreparedServerSession,
    'preparedSessionHandle'
  >;
  finalizedReport: Pick<ThresholdEd25519HssFinalizedReportEnvelope, 'seedOutputMessageB64u'>;
}): Promise<ThresholdEd25519HssOpenedSeedOutput> {
  await ensureThresholdEd25519HssWasm();
  requireThresholdEd25519HssWasmReady();

  const result = threshold_ed25519_hss_open_seed_output_server({
    preparedSessionHandle: String(input.preparedServerSession.preparedSessionHandle || '').trim(),
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
  operation: ThresholdEd25519HssSessionOperation | 'registration';
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession;
  evaluationResult: ThresholdEd25519HssStoredStagedEvaluatorArtifact;
  expectedContextBindingB64u: string;
}): Promise<{
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  serverOutput: ThresholdEd25519HssOpenedServerOutput;
  finalizeReportTimings?: ThresholdEd25519HssFinalizeForRegistrationTimings;
}> {
  const expectedBinding = String(
    input.expectedContextBindingB64u || input.preparedSession.contextBindingB64u || '',
  ).trim();
  if (!expectedBinding) {
    throw new Error('[threshold-ed25519-hss] evaluation result context binding mismatch');
  }

  const finalizedReport = await finalizeThresholdEd25519HssReport({
    preparedServerSession: input.preparedServerSession,
    evaluationResult: input.evaluationResult,
  });

  if (finalizedReport.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] finalized report context binding mismatch');
  }

  const openServerOutputStartedAt = Date.now();
  const serverOutput = await openThresholdEd25519HssServerOutput({
    preparedServerSession: input.preparedServerSession,
    finalizedReport: {
      serverOutputMessageB64u: finalizedReport.serverOutputMessageB64u,
    },
  });
  const openServerOutputMs = Date.now() - openServerOutputStartedAt;

  if (serverOutput.contextBindingB64u !== expectedBinding) {
    throw new Error('[threshold-ed25519-hss] server output context binding mismatch');
  }

  return {
    finalizedReport: {
      contextBindingB64u: finalizedReport.contextBindingB64u,
      clientOutputMessageB64u: finalizedReport.clientOutputMessageB64u,
      ...(input.operation === 'explicit_key_export' || input.operation === 'registration'
        ? { seedOutputMessageB64u: finalizedReport.seedOutputMessageB64u }
        : {}),
    },
    serverOutput,
    finalizeReportTimings: {
      decodeArtifactMs: finalizedReport.timings?.decodeArtifactMs ?? 0,
      serializedSessionMaterializeMs: finalizedReport.timings?.serializedSessionMaterializeMs ?? 0,
      finalizeReportMs: finalizedReport.timings?.finalizeReportMs ?? 0,
      encodeReportMs: finalizedReport.timings?.encodeReportMs ?? 0,
      openServerOutputMs,
      openSeedOutputMs: 0,
      deriveSeedKeypairMs: 0,
      deriveRelayerVerifyingShareMs: 0,
      keyStorePutMs: 0,
    },
  };
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
  preparedServerSession: Pick<
    ThresholdEd25519HssStoredPreparedServerSession,
    'preparedSessionHandle'
  >;
  keyVersion: string;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  serverOutput: ThresholdEd25519HssOpenedServerOutput;
}): Promise<{
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  relayerSigningShareB64u: string;
  relayerVerifyingShareB64u: string;
  timings: Pick<
    ThresholdEd25519HssFinalizeForRegistrationTimings,
    'openSeedOutputMs' | 'deriveSeedKeypairMs' | 'deriveRelayerVerifyingShareMs'
  >;
}> {
  const expectedBinding = String(input.preparedSession.contextBindingB64u || '').trim();
  if (
    !expectedBinding ||
    String(input.finalizedReport.contextBindingB64u || '').trim() !== expectedBinding
  ) {
    throw new Error('[threshold-ed25519-hss] finalized report context binding mismatch');
  }

  const seedOutputMessageB64u = String(input.finalizedReport.seedOutputMessageB64u || '').trim();
  if (!seedOutputMessageB64u) {
    throw new Error('[threshold-ed25519-hss] registration finalize is missing seed output');
  }

  const openSeedOutputStartedAt = Date.now();
  const seedOutput = await openThresholdEd25519HssSeedOutput({
    preparedSession: input.preparedSession,
    preparedServerSession: input.preparedServerSession,
    finalizedReport: {
      seedOutputMessageB64u,
    },
  });
  const openSeedOutputMs = Date.now() - openSeedOutputStartedAt;
  const serverOutput = input.serverOutput;

  if (
    seedOutput.contextBindingB64u !== expectedBinding ||
    serverOutput.contextBindingB64u !== expectedBinding
  ) {
    throw new Error('[threshold-ed25519-hss] opened registration material context mismatch');
  }

  let deriveSeedKeypairMs = 0;
  let deriveRelayerVerifyingShareMs = 0;
  const [keypair, relayerVerifyingShare] = await Promise.all([
    (async () => {
      const startedAt = Date.now();
      const result = await deriveThresholdEd25519KeypairFromSeed({
        seedB64u: seedOutput.canonicalSeedB64u,
      });
      deriveSeedKeypairMs = Date.now() - startedAt;
      return result;
    })(),
    (async () => {
      const startedAt = Date.now();
      const result = await deriveThresholdEd25519VerifyingShareFromSigningShare({
        signingShareB64u: serverOutput.xRelayerBaseB64u,
      });
      deriveRelayerVerifyingShareMs = Date.now() - startedAt;
      return result;
    })(),
  ]);

  const publicKey = String(keypair.publicKey || '').trim();
  const relayerSigningShareB64u = String(serverOutput.xRelayerBaseB64u || '').trim();
  const relayerVerifyingShareB64u = String(relayerVerifyingShare.verifyingShareB64u || '').trim();
  const keyVersion = String(input.keyVersion || '').trim();
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
    timings: {
      openSeedOutputMs,
      deriveSeedKeypairMs,
      deriveRelayerVerifyingShareMs,
    },
  };
}
