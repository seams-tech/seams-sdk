import type { SignRequest, SignatureBytes } from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import { toWalletId, type WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { signRouterAbEcdsaHssDigestWithPool } from '../../../routerAb/ecdsaHss/presignaturePool';
import type { ReadyEcdsaSignerSession } from '../../../session/identity/evmFamilyEcdsaIdentity';
import { loadRouterAbEcdsaHssSigningMaterialSource } from './ecdsaHssClientSigningMaterialSource';
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
        workerCtx: this.workerCtx,
      });
      if (!signed.ok) {
        throw new Error(
          signed.message || signed.code || '[multichain] Router A/B ECDSA-HSS signing failed',
        );
      }

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
