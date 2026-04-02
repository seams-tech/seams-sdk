import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import { getStoredThresholdEd25519SessionRecordByThresholdSessionId } from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { runThresholdEd25519HssCeremonyWithSession } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle';
import { deriveThresholdEd25519HssClientInputsWasm } from '@/core/signingEngine/signers/wasm/nearSignerWasm';
import {
  prepareThresholdEd25519HssClientRequestWasm,
  prepareThresholdEd25519HssSessionWasm,
} from '@/core/signingEngine/signers/wasm/nearSignerHssWasm';

export const THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE = 'near-ed25519-signing';
export const THRESHOLD_ED25519_HSS_DERIVATION_VERSION = 1;

export async function ensureThresholdEd25519HssClientBase(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionJwt?: string;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  keyVersion: string;
  participantIds: number[];
  prfFirstB64u: string;
  keyPurpose?: string;
  derivationVersion?: number;
  onProgress?: (message: string) => void;
}): Promise<string | undefined> {
  const startedAt = Date.now();
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  const existing = String(record?.xClientBaseB64u || '').trim();
  if (existing) {
    console.info('[threshold-ed25519][client-base] cache hit', {
      thresholdSessionId,
      durationMs: Date.now() - startedAt,
    });
    return existing;
  }

  const hasCanonicalRuntimeScope = Boolean(
    String(record?.runtimeSnapshotScope?.orgId || '').trim() &&
    String(record?.runtimeSnapshotScope?.environmentId || '').trim(),
  );
  const orgId = String(record?.runtimeSnapshotScope?.orgId || '').trim();
  const thresholdSessionJwt =
    String(args.thresholdSessionJwt || '').trim() ||
    String(record?.thresholdSessionJwt || '').trim();
  if (hasCanonicalRuntimeScope && !orgId) {
    throw new Error(
      'Threshold Ed25519 session is missing canonical Option A org scope for HSS reconstruction',
    );
  }
  if (hasCanonicalRuntimeScope && !thresholdSessionJwt) {
    throw new Error(
      'Threshold Ed25519 session is bound to canonical Option A scope but is missing threshold session JWT for HSS reconstruction',
    );
  }
  if (!orgId || !thresholdSessionJwt) {
    return undefined;
  }

  const keyPurpose =
    String(args.keyPurpose || '').trim() || THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE;
  const derivationVersion = Number(
    args.derivationVersion ?? THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  );

  const prepareSessionStartedAt = Date.now();
  args.onProgress?.('Preparing threshold Ed25519 signing material...');
  const preparedSession = await prepareThresholdEd25519HssSessionWasm({
    context: {
      orgId,
      nearAccountId: String(args.nearAccountId || '').trim(),
      keyPurpose,
      keyVersion: String(args.keyVersion || '').trim(),
      participantIds: Array.isArray(args.participantIds)
        ? args.participantIds.map((value) => Number(value))
        : [],
      derivationVersion,
    },
  });
  const prepareSessionMs = Date.now() - prepareSessionStartedAt;

  const deriveClientInputsStartedAt = Date.now();
  args.onProgress?.('Deriving threshold Ed25519 client inputs...');
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `${thresholdSessionId}:hss-client-inputs`,
    orgId,
    nearAccountId: String(args.nearAccountId || '').trim(),
    keyPurpose,
    keyVersion: String(args.keyVersion || '').trim(),
    participantIds: preparedSession.participantIds,
    derivationVersion,
    prfFirstB64u: String(args.prfFirstB64u || '').trim(),
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
  });
  const deriveClientInputsMs = Date.now() - deriveClientInputsStartedAt;

  const prepareClientRequestStartedAt = Date.now();
  args.onProgress?.('Preparing threshold Ed25519 relay request...');
  const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
    preparedSession,
    clientInputs,
  });
  const prepareClientRequestMs = Date.now() - prepareClientRequestStartedAt;

  const relayCeremonyStartedAt = Date.now();
  args.onProgress?.('Finalizing threshold Ed25519 signing material...');
  const completed = await runThresholdEd25519HssCeremonyWithSession({
    relayerUrl: String(args.relayerUrl || '').trim(),
    thresholdSessionJwt,
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    preparedSession,
    clientRequest,
    persistToThresholdSessionId: thresholdSessionId,
  });
  const relayCeremonyMs = Date.now() - relayCeremonyStartedAt;
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Failed to reconstruct threshold Ed25519 Option A client base share',
    );
  }
  console.info('[threshold-ed25519][client-base] lazy reconstruction timings', {
    thresholdSessionId,
    nearAccountId: String(args.nearAccountId || '').trim(),
    prepareSessionMs,
    deriveClientInputsMs,
    prepareClientRequestMs,
    relayCeremonyMs,
    totalMs: Date.now() - startedAt,
  });
  return String(completed.clientOutput.xClientBaseB64u || '').trim() || undefined;
}
