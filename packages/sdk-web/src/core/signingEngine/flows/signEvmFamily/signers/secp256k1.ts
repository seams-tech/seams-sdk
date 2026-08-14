import type { SignRequest, SignatureBytes } from '../../../interfaces/signing';
import type { WorkerOperationContext } from '../../../workerManager/executeWorkerOperation';
import {
  scheduleRouterAbEcdsaDerivationClientPresignaturePoolRefill,
  signRouterAbEcdsaDerivationDigestWithPool,
} from '../../../routerAb/ecdsaDerivation/presignaturePool';
import type { HydratedEcdsaSignerMaterial } from '../../../session/identity/evmFamilyEcdsaIdentity';
import {
  loadRouterAbEcdsaDerivationSigningMaterialSource,
  type LoadedRouterAbEcdsaDerivationSigningMaterialSource,
} from './ecdsaDerivationClientSigningMaterialSource';
import { parseEcdsaKeyHandle } from '../../../session/keyMaterialBrands';
import type { EvmFamilyThresholdEcdsaOperation } from '../thresholdAdmission';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
import type { RouterAbNormalSigningAuthorizationWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEcdsaOperationStepUpPreparationV1Wire } from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbOwnerNormalSigningCredential } from '@/core/rpcClients/relayer/routerAbNormalSigning';

export type ReusableEcdsaSigningAuthorization = Extract<
  RouterAbNormalSigningAuthorizationWire,
  { readonly kind: 'reusable_wallet_session' }
>;

type Secp256k1DigestSignRequest = Extract<SignRequest, { kind: 'digest' }> & {
  algorithm: 'secp256k1';
};

export type ReusableEcdsaSigningCredential = {
  readonly kind: 'reusable_wallet_session';
  readonly walletSessionToken: string;
};

export type OperationStepUpEcdsaSigningCredential =
  | {
      readonly kind: 'operation_step_up';
    };

type ReadySecp256k1SigningMaterialBase = {
  kind: 'ready_secp256k1_signing_material';
  walletId: string;
  signerSession: HydratedEcdsaSignerMaterial;
  expiresAtMs: number;
  singleUseEmailOtpSession: boolean;
};

export type ReadySecp256k1SigningMaterial =
  | (ReadySecp256k1SigningMaterialBase & {
      authorization: ReusableEcdsaSigningAuthorization;
      credential: ReusableEcdsaSigningCredential;
      operationStepUpPreparation?: never;
    })
  | (ReadySecp256k1SigningMaterialBase & {
      authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'operation_step_up' }
      >;
      credential: OperationStepUpEcdsaSigningCredential;
      operationStepUpPreparation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    });

export type ReadySecp256k1Signer = {
  readonly algorithm: 'secp256k1';
  signReady: (
    req: SignRequest,
    material: ReadySecp256k1SigningMaterial,
    operation: EvmFamilyThresholdEcdsaOperation,
    operationDigests: OperationDigestSet,
  ) => Promise<SignatureBytes>;
};

type BuildReadySecp256k1SigningMaterialInputBase = {
  walletId: unknown;
  expiresAtMs: number;
  singleUseEmailOtpSession: boolean;
  signerSession: HydratedEcdsaSignerMaterial;
};

export type BuildReadySecp256k1SigningMaterialInput =
  | (BuildReadySecp256k1SigningMaterialInputBase & {
      authorization: ReusableEcdsaSigningAuthorization;
      credential: ReusableEcdsaSigningCredential;
      operationStepUpPreparation?: never;
    })
  | (BuildReadySecp256k1SigningMaterialInputBase & {
      authorization: Extract<
        RouterAbNormalSigningAuthorizationWire,
        { readonly kind: 'operation_step_up' }
      >;
      credential: OperationStepUpEcdsaSigningCredential;
      operationStepUpPreparation: RouterAbEcdsaOperationStepUpPreparationV1Wire;
    });

type RouterAbEcdsaDerivationSigningRefillTrigger = 'commit_start' | 'post_sign_success';

export function buildReadySecp256k1SigningMaterial(
  args: BuildReadySecp256k1SigningMaterialInput,
): ReadySecp256k1SigningMaterial {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[multichain] Missing wallet id for ready secp256k1 signing material');
  }
  const signerSession = args.signerSession;
  if (walletId !== String(signerSession.walletId)) {
    throw new Error('[multichain] ready secp256k1 material wallet identity mismatch');
  }
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
    throw new Error('[multichain] ready secp256k1 authorization expiry is invalid');
  }
  const base = {
    kind: 'ready_secp256k1_signing_material',
    walletId,
    signerSession,
    expiresAtMs,
    singleUseEmailOtpSession: args.singleUseEmailOtpSession,
  } as const;
  switch (args.authorization.kind) {
    case 'reusable_wallet_session': {
      if (args.credential.kind !== 'reusable_wallet_session') {
        throw new Error('[multichain] reusable authorization requires an opaque Wallet Session');
      }
      return { ...base, authorization: args.authorization, credential: args.credential };
    }
    case 'operation_step_up': {
      if (!args.operationStepUpPreparation) {
        throw new Error('[multichain] operation step-up preparation is required');
      }
      return {
        ...base,
        authorization: args.authorization,
        credential: args.credential,
        operationStepUpPreparation: args.operationStepUpPreparation,
      };
    }
  }
}

function isSecp256k1DigestSignRequest(req: SignRequest): req is Secp256k1DigestSignRequest {
  return req.kind === 'digest' && req.algorithm === 'secp256k1';
}

function requireEvmSigningOperationId(operation: EvmFamilyThresholdEcdsaOperation): string {
  const operationId = String(operation.intent.operationId || '').trim();
  if (!operationId) {
    throw new Error('[multichain] exact EVM signing operation id is required');
  }
  return operationId;
}

function routerAbTransportCredential(
  credential: ReusableEcdsaSigningCredential | OperationStepUpEcdsaSigningCredential,
): RouterAbOwnerNormalSigningCredential {
  switch (credential.kind) {
    case 'reusable_wallet_session':
      return { kind: 'wallet_session_opaque', walletSessionToken: credential.walletSessionToken };
    case 'operation_step_up':
      return { kind: 'operation_step_up' };
  }
  credential satisfies never;
  throw new Error('[multichain] unsupported ECDSA signing credential');
}

function scheduleRouterAbEcdsaDerivationSigningRefill(args: {
  trigger: RouterAbEcdsaDerivationSigningRefillTrigger;
  loadedMaterial: LoadedRouterAbEcdsaDerivationSigningMaterialSource;
  workerCtx: WorkerOperationContext;
  credential: RouterAbOwnerNormalSigningCredential;
  expiresAtMs: number;
  authorization: ReusableEcdsaSigningAuthorization;
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
    credential: args.credential,
    materialActivation: routerAbMpcMaterialActivationRefToWire(
      signerSession.materialActivation,
    ),
    routerAbEcdsaDerivationPoolFill: {
      kind: 'router_ab_ecdsa_derivation_signing_worker_pool',
      scope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
      expiresAtMs: args.expiresAtMs,
    },
    workerCtx: args.workerCtx,
    authorization: args.authorization,
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
    operation: EvmFamilyThresholdEcdsaOperation,
    operationDigests: OperationDigestSet,
  ): Promise<SignatureBytes> {
    const loadedMaterial = await loadRouterAbEcdsaDerivationSigningMaterialSource({
      signerSession: material.signerSession,
      workerCtx: this.workerCtx,
    });
    if (material.authorization.kind === 'reusable_wallet_session') {
      scheduleRouterAbEcdsaDerivationSigningRefill({
        trigger: 'commit_start',
        loadedMaterial,
        workerCtx: this.workerCtx,
        credential: routerAbTransportCredential(material.credential),
        expiresAtMs: material.expiresAtMs,
        authorization: material.authorization,
      });
    }
    const signerSession = loadedMaterial.signerSession;
    const publicFacts = signerSession.publicFacts;
    const signerTransport = signerSession.transport;
    const operationId = requireEvmSigningOperationId(operation);
    const transportCredential = routerAbTransportCredential(material.credential);

    try {
      const signingInput = {
        relayerUrl: signerTransport.relayerUrl,
        scope: signerSession.routerAbEcdsaDerivationNormalSigning.state.scope,
        operationId,
        operationDigests: {
          lane_digest_b64u: operationDigests.laneDigest,
          intent_digest_b64u: operationDigests.intentDigest,
          display_digest_b64u: operationDigests.displayDigest,
        },
        materialActivation: routerAbMpcMaterialActivationRefToWire(
          signerSession.materialActivation,
        ),
        credential: transportCredential,
        keyHandle: parseEcdsaKeyHandle(publicFacts.keyHandle),
        signingDigest32: req.digest32,
        clientSigningMaterial: loadedMaterial.clientSigningMaterial,
        expiresAtMs: material.expiresAtMs,
        workerCtx: this.workerCtx,
      } as const;
      let signed;
      if (material.authorization.kind === 'reusable_wallet_session') {
        signed = await signRouterAbEcdsaDerivationDigestWithPool({
          ...signingInput,
          authorization: material.authorization,
        });
      } else {
        const operationStepUpPreparation = material.operationStepUpPreparation;
        if (!operationStepUpPreparation) {
          throw new Error('[multichain] operation step-up preparation is required for signing');
        }
        signed = await signRouterAbEcdsaDerivationDigestWithPool({
          ...signingInput,
          authorization: material.authorization,
          operation: operationStepUpPreparation,
        });
      }
      if (!signed.ok) {
        throw new Error(
          signed.message || signed.code || '[multichain] Router A/B ECDSA derivation signing failed',
        );
      }

      if (material.authorization.kind === 'reusable_wallet_session') {
        scheduleRouterAbEcdsaDerivationSigningRefill({
          trigger: 'post_sign_success',
          loadedMaterial,
          workerCtx: this.workerCtx,
          credential: transportCredential,
          expiresAtMs: material.expiresAtMs,
          authorization: material.authorization,
        });
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
    operation: EvmFamilyThresholdEcdsaOperation,
    operationDigests: OperationDigestSet,
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
    return await this.signReadySecp256k1Digest(req, material, operation, operationDigests);
  }
}
