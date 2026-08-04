import type {
  NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
  NearEd25519YaoMaterialExecutor,
  NearEd25519YaoOperationMaterial,
  NearEd25519StepUpAuthorization,
} from '../../../interfaces/near';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import type { NearEd25519YaoSigningPreparation } from '../../../session/material/nearEd25519YaoSigningPreparation';
import type {
  MpcMaterialActivationRef,
  ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../../session/material/nearEd25519YaoMaterialActivation';
import { requireNearOperationStepUpMaterialActivation } from './operationStepUpPreparation';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';

export type NearEd25519AuthorizationResult = {
  thresholdSessionId: ThresholdEd25519SessionId;
  material: NearEd25519YaoOperationMaterial;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
};

export type NearOperationStepUpMaterial =
  | {
      kind: 'passkey_live';
      materialActivation: MpcMaterialActivationRef;
      material: NearEd25519YaoOperationMaterial;
      rehydrate?: never;
      authorizeAndRehydrate?: never;
    }
  | {
      kind: 'email_otp_live';
      materialActivation: MpcMaterialActivationRef;
      material: NearEd25519YaoOperationMaterial;
      rehydrate?: never;
      authorizeAndRehydrate?: never;
    }
  | {
      kind: 'passkey_sealed';
      materialActivation: MpcMaterialActivationRef;
      facts: NearEd25519YaoOperationMaterial['facts'];
      material?: never;
      authorizeAndRehydrate?: never;
      rehydrate: (
        credential: WebAuthnAuthenticationCredential,
      ) => Promise<NearEd25519YaoOperationMaterial>;
    }
  | ({
      kind: 'email_otp_sealed';
      material?: never;
      rehydrate?: never;
    } & Omit<
      Extract<NearEmailOtpEd25519OperationStepUpCapabilityPreparation, { kind: 'sealed' }>,
      'kind'
    >);

export type ResolvedNearOperationStepUpMaterial = {
  material: NearEd25519YaoOperationMaterial;
  issuedAuthorization: Awaited<
    ReturnType<
      Extract<
        NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
        { kind: 'sealed' }
      >['authorizeAndRehydrate']
    >
  >['issuedAuthorization'] | null;
};

export function nearOperationStepUpMaterialFacts(
  material: NearOperationStepUpMaterial,
): NearEd25519YaoOperationMaterial['facts'] {
  switch (material.kind) {
    case 'passkey_live':
    case 'email_otp_live':
      return material.material.facts;
    case 'passkey_sealed':
    case 'email_otp_sealed':
      return material.facts;
    default:
      material satisfies never;
      throw new Error('[SigningEngine][near] unsupported operation material');
  }
}

export async function resolvePreparedNearEd25519YaoMaterial(
  preparation: NearEd25519YaoSigningPreparation,
  executor: NearEd25519YaoMaterialExecutor,
): Promise<NearEd25519YaoOperationMaterial> {
  switch (preparation.hydration.kind) {
    case 'use_live_runtime':
    case 'rehydrate_material_activation':
      return await executor.resolve(preparation);
    case 'reauthorize_public_anchor':
      throw new Error('[SigningEngine][near] material requires public-anchor reauthorization');
    case 'blocked':
      throw new Error(
        `[SigningEngine][near] material hydration is blocked: ${preparation.hydration.reason}`,
      );
    default:
      preparation.hydration satisfies never;
      throw new Error('[SigningEngine][near] unsupported Ed25519 Yao hydration plan');
  }
}

export async function prepareNearOperationStepUpMaterial(args: {
  method: SignerAuthMethod;
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
}): Promise<NearOperationStepUpMaterial> {
  if (
    args.method === 'passkey' &&
    args.preparation.hydration.kind === 'rehydrate_material_activation'
  ) {
    const prepared = await args.executor.preparePasskeyOperationStepUp(args.preparation);
    return {
      kind: 'passkey_sealed',
      materialActivation: prepared.materialActivation,
      facts: prepared.facts,
      rehydrate: prepared.rehydrate,
    };
  }
  if (args.method === 'email_otp') {
    const prepared = await args.executor.prepareEmailOtpOperationStepUp(args.preparation);
    switch (prepared.kind) {
      case 'live':
        return {
          kind: 'email_otp_live',
          materialActivation: prepared.materialActivation,
          material: prepared.material,
        };
      case 'sealed':
        return {
          kind: 'email_otp_sealed',
          materialActivation: prepared.materialActivation,
          facts: prepared.facts,
          authorizeAndRehydrate: prepared.authorizeAndRehydrate,
        };
      default:
        prepared satisfies never;
        throw new Error('[SigningEngine][near] unsupported Email OTP operation material');
    }
  }
  const material = await resolvePreparedNearEd25519YaoMaterial(
    args.preparation,
    args.executor,
  );
  return {
    kind: 'passkey_live',
    materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
      material.activeClient.metadata(),
    ),
    material,
  };
}

type ResolveNearOperationStepUpMaterialArgs =
  | {
      kind: 'passkey';
      material: Extract<
        NearOperationStepUpMaterial,
        { kind: 'passkey_live' | 'passkey_sealed' }
      >;
      expectedActivation: MpcMaterialActivationRef;
      credential: WebAuthnAuthenticationCredential;
      normalSigningRequest?: never;
      displayDigest?: never;
      proof?: never;
    }
  | {
      kind: 'email_otp_live';
      material: Extract<NearOperationStepUpMaterial, { kind: 'email_otp_live' }>;
      expectedActivation: MpcMaterialActivationRef;
      normalSigningRequest?: never;
      displayDigest?: never;
      proof?: never;
      credential?: never;
    }
  | {
      kind: 'email_otp_sealed';
      material: Extract<NearOperationStepUpMaterial, { kind: 'email_otp_sealed' }>;
      expectedActivation: MpcMaterialActivationRef;
      normalSigningRequest: Parameters<
        Extract<
          NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
          { kind: 'sealed' }
        >['authorizeAndRehydrate']
      >[0]['normalSigningRequest'];
      displayDigest: string;
      proof: Parameters<
        Extract<
          NearEmailOtpEd25519OperationStepUpCapabilityPreparation,
          { kind: 'sealed' }
        >['authorizeAndRehydrate']
      >[0]['proof'];
      credential?: never;
    };

export async function resolveNearOperationStepUpMaterial(
  args: ResolveNearOperationStepUpMaterialArgs,
): Promise<ResolvedNearOperationStepUpMaterial> {
  requireNearOperationStepUpMaterialActivation({
    expected: args.expectedActivation,
    actual: args.material.materialActivation,
  });
  let material: NearEd25519YaoOperationMaterial;
  let issuedAuthorization: ResolvedNearOperationStepUpMaterial['issuedAuthorization'] = null;
  if (args.kind === 'email_otp_live' || args.kind === 'email_otp_sealed') {
    if (args.kind === 'email_otp_live') {
      material = args.material.material;
    } else {
      const resolved = await args.material.authorizeAndRehydrate({
        normalSigningRequest: args.normalSigningRequest,
        displayDigest: args.displayDigest,
        proof: args.proof,
      });
      material = resolved.material;
      issuedAuthorization = resolved.issuedAuthorization;
    }
  } else {
    material =
      args.material.kind === 'passkey_live'
        ? args.material.material
        : await args.material.rehydrate(args.credential);
  }
  try {
    requireNearOperationStepUpMaterialActivation({
      expected: args.expectedActivation,
      actual: nearEd25519YaoMaterialActivationFromMetadata(material.activeClient.metadata()),
    });
    return { material, issuedAuthorization };
  } catch (error) {
    if (
      args.material.kind === 'passkey_sealed' ||
      args.material.kind === 'email_otp_sealed'
    ) {
      material.activeClient.dispose();
    }
    throw error;
  }
}

export async function resolveConfirmedNearEd25519YaoCapability(args: {
  authorization: Extract<NearEd25519StepUpAuthorization, { kind: 'warm_session' }>;
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
}): Promise<NearEd25519AuthorizationResult> {
  const material = await resolvePreparedNearEd25519YaoMaterial(
    args.preparation,
    args.executor,
  );
  return {
    thresholdSessionId: material.facts.thresholdSessionId,
    material,
    walletSessionState: await args.executor.resolveWalletSessionState(),
  };
}
