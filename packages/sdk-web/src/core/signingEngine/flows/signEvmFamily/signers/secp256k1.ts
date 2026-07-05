import type { SignRequest, SignatureBytes } from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  scheduleRouterAbEcdsaHssClientPresignaturePoolRefill,
  signRouterAbEcdsaHssDigestWithPool,
} from '../../../routerAb/ecdsaHss/presignaturePool';
import { getSessionJwtExpiresAtMs } from '@shared/utils/sessionTokens';
import type { ReadyEcdsaSignerSession } from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  loadRouterAbEcdsaHssSigningMaterialSource,
  type LoadedRouterAbEcdsaHssSigningMaterialSource,
} from './ecdsaHssClientSigningMaterialSource';
import { parseEcdsaKeyHandle } from '../../../session/keyMaterialBrands';

type Secp256k1DigestSignRequest = Extract<SignRequest, { kind: 'digest' }> & {
  algorithm: 'secp256k1';
};

export type ReadySecp256k1SigningMaterial = {
  kind: 'ready_secp256k1_signing_material';
  walletId: string;
  signerSession: ReadyEcdsaSignerSession;
  singleUseEmailOtpSession: boolean;
};

export type ReadySecp256k1Signer = {
  readonly algorithm: 'secp256k1';
  signReady: (req: SignRequest, material: ReadySecp256k1SigningMaterial) => Promise<SignatureBytes>;
};

type BuildReadySecp256k1SigningMaterialInputBase = {
  walletId: unknown;
  singleUseEmailOtpSession: boolean;
};

export type BuildReadySecp256k1SigningMaterialInput =
  BuildReadySecp256k1SigningMaterialInputBase & {
    signerSession: ReadyEcdsaSignerSession;
  };

type RouterAbEcdsaHssSigningRefillTrigger = 'commit_start' | 'post_sign_success';

function resolveRouterAbEcdsaHssPoolFillExpiresAtMs(
  signerSession: ReadyEcdsaSignerSession,
): number {
  const policyExpiresAtMs = Math.floor(Number(signerSession.session.policy.expiresAtMs));
  const walletSessionExpiresAtMs = getSessionJwtExpiresAtMs(
    signerSession.routerAbEcdsaHssNormalSigning.credential.walletSessionJwt,
  );
  const expiresAtMs = Math.min(
    policyExpiresAtMs,
    walletSessionExpiresAtMs ?? 0,
    Date.now() + 60_000,
  );
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('[multichain] Router A/B ECDSA-HSS wallet-session expiry is unavailable');
  }
  return expiresAtMs;
}

export function buildReadySecp256k1SigningMaterial(
  args: BuildReadySecp256k1SigningMaterialInput,
): ReadySecp256k1SigningMaterial {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[multichain] Missing wallet id for ready secp256k1 signing material');
  }
  const signerSession = args.signerSession;
  return {
    kind: 'ready_secp256k1_signing_material',
    walletId,
    signerSession,
    singleUseEmailOtpSession: args.singleUseEmailOtpSession,
  };
}

function isSecp256k1DigestSignRequest(req: SignRequest): req is Secp256k1DigestSignRequest {
  return req.kind === 'digest' && req.algorithm === 'secp256k1';
}

function scheduleRouterAbEcdsaHssSigningRefill(args: {
  trigger: RouterAbEcdsaHssSigningRefillTrigger;
  loadedMaterial: LoadedRouterAbEcdsaHssSigningMaterialSource;
  workerCtx: WorkerOperationContext;
}): void {
  const signerSession = args.loadedMaterial.signerSession;
  const publicFacts = signerSession.publicFacts;
  const signingMaterial = signerSession.transport.signingMaterial;
  const participantIds = publicFacts.participantIds.map((participantId) => Number(participantId));
  scheduleRouterAbEcdsaHssClientPresignaturePoolRefill({
    relayerUrl: signerSession.transport.relayerUrl,
    keyHandle: parseEcdsaKeyHandle(publicFacts.keyHandle),
    ecdsaThresholdKeyId: signingMaterial.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: signingMaterial.clientVerifier33B64u,
    participantIds,
    clientSigningMaterial: args.loadedMaterial.clientSigningMaterial,
    thresholdEcdsaPublicKeyB64u: publicFacts.publicKeyB64u,
    relayerVerifyingShareB64u: signerSession.transport.relayerVerifyingShareB64u,
    credential: signerSession.routerAbEcdsaHssNormalSigning.credential,
    routerAbEcdsaHssPoolFill: {
      kind: 'router_ab_ecdsa_hss_signing_worker_pool',
      scope: signerSession.routerAbEcdsaHssNormalSigning.state.scope,
      expiresAtMs: resolveRouterAbEcdsaHssPoolFillExpiresAtMs(signerSession),
    },
    workerCtx: args.workerCtx,
    ...(args.trigger === 'commit_start' ? { triggerIfDepthAtOrBelow: 0 } : {}),
  });
}

export type ThresholdEcdsaCommitQueueEnqueueFn = <T>(args: {
  walletId: WalletId;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<T>;
}) => Promise<T>;

export class Secp256k1Engine {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly enqueueThresholdEcdsaCommit?: ThresholdEcdsaCommitQueueEnqueueFn;
  private readonly shouldAbort?: () => boolean;
  private readonly workerCtx: WorkerOperationContext;

  constructor(opts: {
    getRpId?: () => string | null;
    enqueueThresholdEcdsaCommit?: ThresholdEcdsaCommitQueueEnqueueFn;
    shouldAbort?: () => boolean;
    workerCtx: WorkerOperationContext;
  }) {
    this.getRpId = opts.getRpId;
    this.enqueueThresholdEcdsaCommit = opts.enqueueThresholdEcdsaCommit;
    this.shouldAbort = opts.shouldAbort;
    this.workerCtx = opts.workerCtx;
  }

  private async signReadySecp256k1Digest(
    req: Secp256k1DigestSignRequest,
    material: ReadySecp256k1SigningMaterial,
  ): Promise<SignatureBytes> {
    const loadedMaterial = await loadRouterAbEcdsaHssSigningMaterialSource({
      signerSession: material.signerSession,
      workerCtx: this.workerCtx,
    });
    scheduleRouterAbEcdsaHssSigningRefill({
      trigger: 'commit_start',
      loadedMaterial,
      workerCtx: this.workerCtx,
    });
    const signerSession = loadedMaterial.signerSession;
    const publicFacts = signerSession.publicFacts;
    const participantIds = publicFacts.participantIds.map((participantId) => Number(participantId));
    const signerTransport = signerSession.transport;

    try {
      const signed = await signRouterAbEcdsaHssDigestWithPool({
        relayerUrl: signerTransport.relayerUrl,
        scope: signerSession.routerAbEcdsaHssNormalSigning.state.scope,
        credential: signerSession.routerAbEcdsaHssNormalSigning.credential,
        keyHandle: parseEcdsaKeyHandle(publicFacts.keyHandle),
        signingDigest32: req.digest32,
        clientSigningMaterial: loadedMaterial.clientSigningMaterial,
        participantIds,
        expiresAtMs: resolveRouterAbEcdsaHssPoolFillExpiresAtMs(signerSession),
        workerCtx: this.workerCtx,
      });
      if (!signed.ok) {
        throw new Error(
          signed.message || signed.code || '[multichain] Router A/B ECDSA-HSS signing failed',
        );
      }

      scheduleRouterAbEcdsaHssSigningRefill({
        trigger: 'post_sign_success',
        loadedMaterial,
        workerCtx: this.workerCtx,
      });
      return signed.signature65;
    } finally {
      await loadedMaterial.cleanupAfterSign({
        singleUseEmailOtpSession: material.singleUseEmailOtpSession,
      });
    }
  }

  async signReady(
    req: SignRequest,
    material: ReadySecp256k1SigningMaterial,
  ): Promise<SignatureBytes> {
    if (!isSecp256k1DigestSignRequest(req)) {
      throw new Error('[Secp256k1Engine] unsupported sign request');
    }
    if (req.digest32.length !== 32) {
      throw new Error('[Secp256k1Engine] digest32 must be 32 bytes');
    }
    const runCommit = async (): Promise<SignatureBytes> => {
      if (this.shouldAbort?.()) {
        const aborted = new Error('Request cancelled') as Error & { code: 'cancelled' };
        aborted.code = 'cancelled';
        throw aborted;
      }
      return await this.signReadySecp256k1Digest(req, material);
    };
    if (this.enqueueThresholdEcdsaCommit) {
      return await this.enqueueThresholdEcdsaCommit({
        walletId: toWalletId(material.walletId),
        thresholdSessionId: String(material.signerSession.session.thresholdSessionId),
        shouldAbort: this.shouldAbort,
        task: runCommit,
      });
    }
    return await runCommit();
  }
}
