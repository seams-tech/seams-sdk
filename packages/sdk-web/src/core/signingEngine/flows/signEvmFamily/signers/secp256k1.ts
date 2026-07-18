import type { SignRequest, SignatureBytes } from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import {
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill,
  signRouterAbEcdsaDerivationDigestWithPool,
} from '../../../routerAb/ecdsaDerivation/presignaturePool';
import { getSessionJwtExpiresAtMs } from '@shared/utils/sessionTokens';
import type { ReadyEcdsaSignerSession } from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  loadRouterAbEcdsaDerivationSigningMaterialSource,
  type LoadedRouterAbEcdsaDerivationSigningMaterialSource,
} from './ecdsaDerivationClientSigningMaterialSource';
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

type RouterAbEcdsaDerivationSigningRefillTrigger = 'commit_start' | 'post_sign_success';

// The SigningWorker admits at most five minutes; retain one minute for transit and clock skew.
const ROUTER_AB_ECDSA_DERIVATION_PRESIGN_MATERIAL_TTL_MS = 4 * 60_000;

function resolveRouterAbEcdsaDerivationPresignMaterialExpiresAtMs(
  signerSession: ReadyEcdsaSignerSession,
): number {
  const policyExpiresAtMs = Math.floor(Number(signerSession.session.policy.expiresAtMs));
  const walletSessionExpiresAtMs = getSessionJwtExpiresAtMs(
    signerSession.routerAbEcdsaDerivationNormalSigning.credential.walletSessionJwt,
  );
  const expiresAtMs = Math.min(
    policyExpiresAtMs,
    walletSessionExpiresAtMs ?? 0,
    Date.now() + ROUTER_AB_ECDSA_DERIVATION_PRESIGN_MATERIAL_TTL_MS,
  );
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('[multichain] Router A/B ECDSA derivation wallet-session expiry is unavailable');
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

function scheduleRouterAbEcdsaDerivationSigningRefill(args: {
  trigger: RouterAbEcdsaDerivationSigningRefillTrigger;
  loadedMaterial: LoadedRouterAbEcdsaDerivationSigningMaterialSource;
  workerCtx: WorkerOperationContext;
}): void {
  const signerSession = args.loadedMaterial.signerSession;
  const publicFacts = signerSession.publicFacts;
  const signingMaterial = signerSession.transport.signingMaterial;
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill({
    relayerUrl: signerSession.transport.relayerUrl,
    keyHandle: parseEcdsaKeyHandle(publicFacts.keyHandle),
    ecdsaThresholdKeyId: signingMaterial.ecdsaThresholdKeyId,
    clientVerifyingShareB64u: signingMaterial.clientVerifier33B64u,
    clientSigningMaterial: args.loadedMaterial.clientSigningMaterial,
    thresholdEcdsaPublicKeyB64u: publicFacts.publicKeyB64u,
    relayerVerifyingShareB64u: signerSession.transport.relayerVerifyingShareB64u,
    credential: signerSession.routerAbEcdsaDerivationNormalSigning.credential,
    routerAbEcdsaDerivationPoolFill: {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
      expiresAtMs: resolveRouterAbEcdsaDerivationPresignMaterialExpiresAtMs(signerSession),
    },
    workerCtx: args.workerCtx,
    ...(args.trigger === 'commit_start' ? { triggerIfDepthAtOrBelow: 0 } : {}),
  });
}

export class Secp256k1Engine {
  readonly algorithm = 'secp256k1' as const;

  private readonly getRpId?: () => string | null;
  private readonly shouldAbort?: () => boolean;
  private readonly workerCtx: WorkerOperationContext;

  constructor(opts: {
    getRpId?: () => string | null;
    shouldAbort?: () => boolean;
    workerCtx: WorkerOperationContext;
  }) {
    this.getRpId = opts.getRpId;
    this.shouldAbort = opts.shouldAbort;
    this.workerCtx = opts.workerCtx;
  }

  private async signReadySecp256k1Digest(
    req: Secp256k1DigestSignRequest,
    material: ReadySecp256k1SigningMaterial,
  ): Promise<SignatureBytes> {
    const loadedMaterial = await loadRouterAbEcdsaDerivationSigningMaterialSource({
      signerSession: material.signerSession,
      workerCtx: this.workerCtx,
    });
    scheduleRouterAbEcdsaDerivationSigningRefill({
      trigger: 'commit_start',
      loadedMaterial,
      workerCtx: this.workerCtx,
    });
    const signerSession = loadedMaterial.signerSession;
    const publicFacts = signerSession.publicFacts;
    const signerTransport = signerSession.transport;

    try {
      const signed = await signRouterAbEcdsaDerivationDigestWithPool({
        relayerUrl: signerTransport.relayerUrl,
        scope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
        credential: signerSession.routerAbEcdsaDerivationNormalSigning.credential,
        keyHandle: parseEcdsaKeyHandle(publicFacts.keyHandle),
        signingDigest32: req.digest32,
        clientSigningMaterial: loadedMaterial.clientSigningMaterial,
        expiresAtMs: resolveRouterAbEcdsaDerivationPresignMaterialExpiresAtMs(signerSession),
        workerCtx: this.workerCtx,
      });
      if (!signed.ok) {
        throw new Error(
          signed.message || signed.code || '[multichain] Router A/B ECDSA derivation signing failed',
        );
      }

      scheduleRouterAbEcdsaDerivationSigningRefill({
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
    if (this.shouldAbort?.()) {
      const aborted = new Error('Request cancelled') as Error & { code: 'cancelled' };
      aborted.code = 'cancelled';
      throw aborted;
    }
    return await this.signReadySecp256k1Digest(req, material);
  }
}
