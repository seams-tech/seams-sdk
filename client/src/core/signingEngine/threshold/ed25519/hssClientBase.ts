import type { NearSigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import { runThresholdEd25519HssCeremonyWithSession } from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
import {
  deriveThresholdEd25519HssClientInputsWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';

export const THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE = 'near-ed25519-signing';
export const THRESHOLD_ED25519_HSS_DERIVATION_VERSION = 1;

export async function ensureThresholdEd25519HssClientBase(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  existingXClientBaseB64u?: string;
  thresholdSessionAuthToken?: string;
  signingRootId: string;
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
  persistClientBase?: (xClientBaseB64u: string) => boolean | void;
}): Promise<string | undefined> {
  const startedAt = Date.now();
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  const existing = String(args.existingXClientBaseB64u || '').trim();
  if (existing && !args.forceRefresh) {
    console.info('[threshold-ed25519][client-base] cache hit', {
      thresholdSessionId,
      durationMs: Date.now() - startedAt,
    });
    return existing;
  }

  const signingRootId = String(args.signingRootId || '').trim();
  const thresholdSessionAuthToken = String(args.thresholdSessionAuthToken || '').trim();
  if (!signingRootId) {
    throw new Error(
      'Threshold Ed25519 session is missing signing-root scope for single-key HSS reconstruction',
    );
  }
  if (!thresholdSessionAuthToken) {
    throw new Error(
      'Threshold Ed25519 session is missing threshold session auth token for single-key HSS reconstruction',
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
    outputProjection: {
      kind: 'client-masked-projection',
      clientRecoverableSecretB64u: String(args.prfFirstB64u || '').trim(),
    },
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
  });
  const relayCeremonyMs = Date.now() - relayCeremonyStartedAt;
  if (!completed.ok || !completed.clientOutput.xClientBaseB64u) {
    throw new Error(
      completed.message ||
        'Failed to reconstruct threshold Ed25519 single-key HSS client base share',
    );
  }
  const xClientBaseB64u = String(completed.clientOutput.xClientBaseB64u || '').trim();
  const persisted = xClientBaseB64u
    ? args.persistClientBase?.(xClientBaseB64u)
    : null;
  if (args.persistClientBase && persisted === false) {
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
