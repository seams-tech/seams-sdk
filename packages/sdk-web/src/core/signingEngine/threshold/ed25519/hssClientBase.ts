import { runThresholdEd25519HssCeremonyWithSession } from '@/core/signingEngine/threshold/ed25519/hssLifecycle';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  deriveThresholdEd25519RoleSeparatedClientVerifyingShareWasm,
  storeThresholdEd25519HssMaterialHandleWasm,
  validateThresholdEd25519HssMaterialHandleWasm,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import {
  storeThresholdEd25519HssMaterialNearSignerWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  buildRouterAbEd25519SigningMaterialPersistedHandle,
  type Ed25519HssMaterialHandle,
  type RouterAbEd25519SigningMaterialBindingInput,
  type RouterAbEd25519SigningMaterialPersistedHandle,
} from './hssMaterialBinding';

export const THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE = 'near-ed25519-signing';
export const THRESHOLD_ED25519_HSS_DERIVATION_VERSION = 1;

export type { Ed25519HssMaterialHandle } from './hssMaterialBinding';

export type Ed25519HssMaterialCache = {
  kind: 'ed25519_hss_material_cache_v1';
  xClientBaseB64u: string;
  clientVerifyingShareB64u: string;
};

export type RouterAbEd25519SigningMaterialReady = {
  kind: 'router_ab_ed25519_signing_material_ready_v1';
  materialHandle: Ed25519HssMaterialHandle;
  bindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  relayerKeyId: string;
  participantIds: number[];
  signingWorkerId: string;
  clientVerifyingShareB64u: string;
  xClientBaseB64u?: never;
};

export function ed25519HssMaterialCacheFromRaw(args: {
  xClientBaseB64u?: unknown;
  clientVerifyingShareB64u?: unknown;
}): Ed25519HssMaterialCache | undefined {
  const xClientBaseB64u = String(args.xClientBaseB64u || '').trim();
  const clientVerifyingShareB64u = String(args.clientVerifyingShareB64u || '').trim();
  if (!xClientBaseB64u || !clientVerifyingShareB64u) return undefined;
  return {
    kind: 'ed25519_hss_material_cache_v1',
    xClientBaseB64u,
    clientVerifyingShareB64u,
  };
}

export async function storeRouterAbEd25519SigningMaterialHandleWasm(input: {
  workerCtx: WorkerOperationContext;
  materialCache: Ed25519HssMaterialCache;
} & Omit<RouterAbEd25519SigningMaterialBindingInput, 'clientVerifyingShareB64u'>): Promise<RouterAbEd25519SigningMaterialReady> {
  const materialCache = input.materialCache;
  const persistedHandle = await buildRouterAbEd25519SigningMaterialPersistedHandle({
    ...input,
    clientVerifyingShareB64u: materialCache.clientVerifyingShareB64u,
  });
  const participantIds = input.participantIds.map((id) => Number(id));
  const stored = await storeThresholdEd25519HssMaterialHandleWasm({
    materialHandle: persistedHandle.materialHandle,
    xClientBaseB64u: materialCache.xClientBaseB64u,
    expectedClientVerifyingShareB64u: persistedHandle.clientVerifyingShareB64u,
    bindingDigest: persistedHandle.bindingDigest,
    workerCtx: input.workerCtx,
  });
  const storedNearSigner = await storeThresholdEd25519HssMaterialNearSignerWasm({
    materialHandle: persistedHandle.materialHandle,
    xClientBaseB64u: materialCache.xClientBaseB64u,
    expectedClientVerifyingShareB64u: persistedHandle.clientVerifyingShareB64u,
    bindingDigest: persistedHandle.bindingDigest,
    workerCtx: input.workerCtx,
  });
  if (stored.clientVerifyingShareB64u !== persistedHandle.clientVerifyingShareB64u) {
    throw new Error('Router A/B Ed25519 signing material worker binding mismatch');
  }
  if (
    stored.bindingDigest !== persistedHandle.bindingDigest ||
    stored.materialHandle !== persistedHandle.materialHandle
  ) {
    throw new Error('Router A/B Ed25519 signing material worker handle mismatch');
  }
  if (
    storedNearSigner.clientVerifyingShareB64u !== persistedHandle.clientVerifyingShareB64u ||
    storedNearSigner.bindingDigest !== persistedHandle.bindingDigest ||
    storedNearSigner.materialHandle !== persistedHandle.materialHandle
  ) {
    throw new Error('Router A/B Ed25519 signing material Near signer worker handle mismatch');
  }
  return {
    kind: 'router_ab_ed25519_signing_material_ready_v1',
    materialHandle: persistedHandle.materialHandle,
    bindingDigest: persistedHandle.bindingDigest,
    thresholdSessionId: String(input.thresholdSessionId || '').trim(),
    signingGrantId: String(input.signingGrantId || '').trim(),
    signingRootId: String(input.signingRootId || '').trim(),
    signingRootVersion: String(input.signingRootVersion || '').trim(),
    expiresAtMs: Math.floor(Number(input.expiresAtMs)),
    nearAccountId: String(input.nearAccountId || '').trim(),
    relayerKeyId: String(input.relayerKeyId || '').trim(),
    participantIds,
    signingWorkerId: String(input.signingWorkerId || '').trim(),
    clientVerifyingShareB64u: persistedHandle.clientVerifyingShareB64u,
  };
}

export async function ensureThresholdEd25519HssClientBase(args: {
  ctx: WorkerOperationContext;
  thresholdSessionId: string;
  existingMaterialCache?: Ed25519HssMaterialCache;
  walletSessionJwt?: string;
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
  persistClientBase?: (
    xClientBaseB64u: string,
    clientVerifyingShareB64u: string,
  ) => boolean | void;
}): Promise<Ed25519HssMaterialCache | undefined> {
  const startedAt = Date.now();
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return undefined;

  const existing = String(args.existingMaterialCache?.xClientBaseB64u || '').trim();
  if (existing && !args.forceRefresh) {
    const expectedClientVerifyingShareB64u = String(
      args.existingMaterialCache?.clientVerifyingShareB64u || '',
    ).trim();
    if (!expectedClientVerifyingShareB64u) {
      console.warn('[threshold-ed25519][client-base] cache missing verifying-share binding', {
        thresholdSessionId,
        durationMs: Date.now() - startedAt,
      });
    } else {
      const cachedClientVerifyingShare =
        await deriveThresholdEd25519RoleSeparatedClientVerifyingShareWasm({
          xClientBaseB64u: existing,
          workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
        });
      const actualClientVerifyingShareB64u = String(
        cachedClientVerifyingShare.clientVerifyingShareB64u || '',
      ).trim();
      if (actualClientVerifyingShareB64u === expectedClientVerifyingShareB64u) {
        console.info('[threshold-ed25519][client-base] cache hit', {
          thresholdSessionId,
          durationMs: Date.now() - startedAt,
        });
        return {
          kind: 'ed25519_hss_material_cache_v1',
          xClientBaseB64u: existing,
          clientVerifyingShareB64u: actualClientVerifyingShareB64u,
        };
      }
      console.warn('[threshold-ed25519][client-base] cache verifying-share mismatch', {
        thresholdSessionId,
        durationMs: Date.now() - startedAt,
      });
    }
  }

  if (!String(args.prfFirstB64u || '').trim()) {
    throw new Error(
      'Threshold Ed25519 cached client base is missing or stale; PRF.first is required to reconstruct signing material',
    );
  }

  if (existing && !args.forceRefresh) {
    console.info('[threshold-ed25519][client-base] cache miss after binding validation', {
      thresholdSessionId,
      durationMs: Date.now() - startedAt,
    });
  }

  const signingRootId = String(args.signingRootId || '').trim();
  const walletSessionJwt = String(args.walletSessionJwt || '').trim();
  if (!signingRootId) {
    throw new Error(
      'Threshold Ed25519 session is missing signing-root scope for single-key HSS reconstruction',
    );
  }
  if (!walletSessionJwt) {
    throw new Error(
      'Threshold Ed25519 session is missing Wallet Session JWT for single-key HSS reconstruction',
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
    walletSessionJwt,
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
  const clientVerifyingShare = xClientBaseB64u
    ? await deriveThresholdEd25519RoleSeparatedClientVerifyingShareWasm({
        xClientBaseB64u,
        workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
      })
    : null;
  const clientVerifyingShareB64u = String(
    clientVerifyingShare?.clientVerifyingShareB64u || '',
  ).trim();
  if (!clientVerifyingShareB64u) {
    throw new Error('Failed to derive threshold Ed25519 client verifying share from HSS base');
  }
  const persisted = xClientBaseB64u
    ? args.persistClientBase?.(xClientBaseB64u, clientVerifyingShareB64u)
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
  return ed25519HssMaterialCacheFromRaw({
    xClientBaseB64u,
    clientVerifyingShareB64u,
  });
}

export async function ensureThresholdEd25519HssSigningMaterial(args: {
  ctx: WorkerOperationContext;
  thresholdSessionId: string;
  signingGrantId: string;
  existingMaterialCache?: Ed25519HssMaterialCache;
  existingMaterialHandle?: string;
  existingMaterialBindingDigest?: string;
  existingMaterialClientVerifierB64u?: string;
  walletSessionJwt?: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  relayerUrl: string;
  relayerKeyId: string;
  nearAccountId: string;
  keyVersion: string;
  participantIds: number[];
  signingWorkerId: string;
  prfFirstB64u: string;
  keyPurpose?: string;
  derivationVersion?: number;
  onProgress?: (message: string) => void;
  forceRefresh?: boolean;
  persistClientBase?: (
    xClientBaseB64u: string,
    clientVerifyingShareB64u: string,
  ) => boolean | void;
  persistSigningMaterial?: (
    material: RouterAbEd25519SigningMaterialPersistedHandle,
  ) => boolean | void;
}): Promise<RouterAbEd25519SigningMaterialReady> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const signingRootId = String(args.signingRootId || '').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const signingWorkerId = String(args.signingWorkerId || '').trim();
  const existingMaterialHandle = String(args.existingMaterialHandle || '').trim();
  const existingMaterialBindingDigest = String(args.existingMaterialBindingDigest || '').trim();
  const existingMaterialClientVerifierB64u = String(
    args.existingMaterialClientVerifierB64u || '',
  ).trim();
  if (!thresholdSessionId || !signingGrantId || !signingRootId || !signingRootVersion) {
    throw new Error('Router A/B Ed25519 signing material is missing session or signing-root scope');
  }
  if (!nearAccountId || !relayerKeyId || !signingWorkerId) {
    throw new Error('Router A/B Ed25519 signing material is missing account or worker scope');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('Router A/B Ed25519 signing material is expired');
  }
  const participantIds = args.participantIds.map((id) => Number(id));
  if (existingMaterialHandle && existingMaterialBindingDigest && existingMaterialClientVerifierB64u) {
    try {
      const workerCtx = { requestWorkerOperation: args.ctx.requestWorkerOperation };
      const hssClientMaterial = await validateThresholdEd25519HssMaterialHandleWasm({
        workerCtx,
        materialHandle: existingMaterialHandle,
        expectedClientVerifyingShareB64u: existingMaterialClientVerifierB64u,
        expectedBindingDigest: existingMaterialBindingDigest,
      });
      if (
        hssClientMaterial.materialHandle === existingMaterialHandle &&
        hssClientMaterial.bindingDigest === existingMaterialBindingDigest &&
        hssClientMaterial.clientVerifyingShareB64u === existingMaterialClientVerifierB64u
      ) {
        return {
          kind: 'router_ab_ed25519_signing_material_ready_v1',
          materialHandle: existingMaterialHandle as Ed25519HssMaterialHandle,
          bindingDigest: existingMaterialBindingDigest,
          thresholdSessionId,
          signingGrantId,
          signingRootId,
          signingRootVersion,
          expiresAtMs,
          nearAccountId,
          relayerKeyId,
          participantIds,
          signingWorkerId,
          clientVerifyingShareB64u: existingMaterialClientVerifierB64u,
        };
      }
    } catch {
      // The handle is not loaded in this browser worker instance; reconstruct below.
    }
  }
  const materialCache = await ensureThresholdEd25519HssClientBase(args);
  if (!materialCache) {
    throw new Error('Router A/B Ed25519 signing material could not be loaded');
  }
  const signingMaterial = await storeRouterAbEd25519SigningMaterialHandleWasm({
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
    materialCache,
    thresholdSessionId,
    signingGrantId,
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId,
    relayerKeyId,
    participantIds,
    signingWorkerId,
  });
  const persisted = args.persistSigningMaterial?.({
    materialHandle: signingMaterial.materialHandle,
    bindingDigest: signingMaterial.bindingDigest,
    clientVerifyingShareB64u: signingMaterial.clientVerifyingShareB64u,
  });
  if (args.persistSigningMaterial && persisted === false) {
    console.warn('[threshold-ed25519][client-base] material handle cache write skipped', {
      thresholdSessionId,
    });
  }
  return signingMaterial;
}

export async function requireThresholdEd25519HssSigningMaterialHandle(args: {
  ctx: WorkerOperationContext;
  thresholdSessionId: string;
  signingGrantId: string;
  existingMaterialHandle?: string;
  existingMaterialBindingDigest?: string;
  existingMaterialClientVerifierB64u?: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  relayerKeyId: string;
  nearAccountId: string;
  participantIds: number[];
  signingWorkerId: string;
}): Promise<RouterAbEd25519SigningMaterialReady> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const signingGrantId = String(args.signingGrantId || '').trim();
  const signingRootId = String(args.signingRootId || '').trim();
  const signingRootVersion = String(args.signingRootVersion || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const nearAccountId = String(args.nearAccountId || '').trim();
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  const signingWorkerId = String(args.signingWorkerId || '').trim();
  const existingMaterialHandle = String(args.existingMaterialHandle || '').trim();
  const existingMaterialBindingDigest = String(args.existingMaterialBindingDigest || '').trim();
  const existingMaterialClientVerifierB64u = String(
    args.existingMaterialClientVerifierB64u || '',
  ).trim();
  if (!thresholdSessionId || !signingGrantId || !signingRootId || !signingRootVersion) {
    throw new Error('Router A/B Ed25519 signing material is missing session or signing-root scope');
  }
  if (!nearAccountId || !relayerKeyId || !signingWorkerId) {
    throw new Error('Router A/B Ed25519 signing material is missing account or worker scope');
  }
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('Router A/B Ed25519 signing material is expired');
  }
  if (!existingMaterialHandle || !existingMaterialBindingDigest || !existingMaterialClientVerifierB64u) {
    throw new Error('Router A/B Ed25519 signing material handle is missing');
  }

  const hssClientMaterial = await validateThresholdEd25519HssMaterialHandleWasm({
    workerCtx: { requestWorkerOperation: args.ctx.requestWorkerOperation },
    materialHandle: existingMaterialHandle,
    expectedClientVerifyingShareB64u: existingMaterialClientVerifierB64u,
    expectedBindingDigest: existingMaterialBindingDigest,
  });
  if (
    hssClientMaterial.materialHandle !== existingMaterialHandle ||
    hssClientMaterial.bindingDigest !== existingMaterialBindingDigest ||
    hssClientMaterial.clientVerifyingShareB64u !== existingMaterialClientVerifierB64u
  ) {
    throw new Error('Router A/B Ed25519 signing material handle binding mismatch');
  }
  return {
    kind: 'router_ab_ed25519_signing_material_ready_v1',
    materialHandle: existingMaterialHandle as Ed25519HssMaterialHandle,
    bindingDigest: existingMaterialBindingDigest,
    thresholdSessionId,
    signingGrantId,
    signingRootId,
    signingRootVersion,
    expiresAtMs,
    nearAccountId,
    relayerKeyId,
    participantIds: args.participantIds.map((id) => Number(id)),
    signingWorkerId,
    clientVerifyingShareB64u: existingMaterialClientVerifierB64u,
  };
}
