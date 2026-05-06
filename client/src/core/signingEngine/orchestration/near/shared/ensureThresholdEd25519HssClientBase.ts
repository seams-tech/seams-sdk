import type { SigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  persistStoredThresholdEd25519SessionClientBase,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import { runThresholdEd25519HssCeremonyWithSession } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  deriveThresholdEd25519HssClientInputsWasm,
} from '@/core/signingEngine/signers/wasm/hssClientSignerWasm';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export const THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE = 'near-ed25519-signing';
export const THRESHOLD_ED25519_HSS_DERIVATION_VERSION = 1;

export async function ensureThresholdEd25519HssClientBase(args: {
  ctx: SigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdSessionAuthToken?: string;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  keyVersion: string;
  participantIds: number[];
  prfFirstB64u: string;
  keyPurpose?: string;
  derivationVersion?: number;
  onProgress?: (message: string) => void;
  forceRefresh?: boolean;
}): Promise<string | undefined> {
  const startedAt = Date.now();
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  const existing = String(record?.xClientBaseB64u || '').trim();
  if (existing && !args.forceRefresh) {
    console.info('[threshold-ed25519][client-base] cache hit', {
      thresholdSessionId,
      durationMs: Date.now() - startedAt,
    });
    return existing;
  }

  const hasCanonicalRuntimeScope = Boolean(
    String(record?.runtimePolicyScope?.orgId || '').trim() &&
    String(record?.runtimePolicyScope?.projectId || '').trim() &&
    String(record?.runtimePolicyScope?.envId || '').trim(),
  );
  const signingRootId = record?.runtimePolicyScope
    ? signingRootScopeFromRuntimePolicyScope(record.runtimePolicyScope).signingRootId
    : '';
  const thresholdSessionAuthToken =
    String(args.thresholdSessionAuthToken || '').trim() ||
    String(record?.thresholdSessionAuthToken || '').trim();
  if (hasCanonicalRuntimeScope && !signingRootId) {
    throw new Error(
      'Threshold Ed25519 session is missing canonical signing-root scope for HSS reconstruction',
    );
  }
  if (hasCanonicalRuntimeScope && !thresholdSessionAuthToken) {
    throw new Error(
      'Threshold Ed25519 session is bound to canonical single-key HSS scope but is missing threshold session JWT for reconstruction',
    );
  }
  if (!signingRootId) {
    throw new Error(
      'Threshold Ed25519 session is missing signing-root scope for single-key HSS reconstruction',
    );
  }
  if (!thresholdSessionAuthToken) {
    throw new Error(
      'Threshold Ed25519 session is missing threshold session JWT for single-key HSS reconstruction',
    );
  }

  const keyPurpose =
    String(args.keyPurpose || '').trim() || THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE;
  const derivationVersion = Number(
    args.derivationVersion ?? THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  );

  const context = {
    signingRootId,
    nearAccountId: String(args.nearAccountId || '').trim(),
    keyPurpose,
    keyVersion: String(args.keyVersion || '').trim(),
    participantIds: Array.isArray(args.participantIds)
      ? args.participantIds.map((value) => Number(value))
      : [],
    derivationVersion,
  };

  const deriveClientInputsStartedAt = Date.now();
  args.onProgress?.('Deriving threshold Ed25519 client inputs...');
  const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
    sessionId: `${thresholdSessionId}:hss-client-inputs`,
    signingRootId: context.signingRootId,
    nearAccountId: context.nearAccountId,
    keyPurpose: context.keyPurpose,
    keyVersion: context.keyVersion,
    participantIds: context.participantIds,
    derivationVersion: context.derivationVersion,
    prfFirstB64u: String(args.prfFirstB64u || '').trim(),
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
  });
  const deriveClientInputsMs = Date.now() - deriveClientInputsStartedAt;

  const relayCeremonyStartedAt = Date.now();
  args.onProgress?.('Finalizing threshold Ed25519 signing material...');
  const completed = await runThresholdEd25519HssCeremonyWithSession({
    relayerUrl: String(args.relayerUrl || '').trim(),
    thresholdSessionAuthToken,
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    operation: 'warm_session_reconstruction',
    context,
    clientInputs,
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
  });
  const relayCeremonyMs = Date.now() - relayCeremonyStartedAt;
  if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
    throw new Error(
      completed.error || 'Failed to reconstruct threshold Ed25519 single-key HSS client base share',
    );
  }
  const xClientBaseB64u = String(completed.clientOutput.xClientBaseB64u || '').trim();
  const persisted = xClientBaseB64u
    ? persistStoredThresholdEd25519SessionClientBase({
        thresholdSessionId,
        xClientBaseB64u,
      })
    : null;
  if (!persisted) {
    console.warn('[threshold-ed25519][client-base] cache write skipped', {
      thresholdSessionId,
    });
  }
  console.info('[threshold-ed25519][client-base] lazy reconstruction timings', {
    thresholdSessionId,
    nearAccountId: String(args.nearAccountId || '').trim(),
    deriveClientInputsMs,
    relayCeremonyMs,
    totalMs: Date.now() - startedAt,
  });
  return xClientBaseB64u || undefined;
}
