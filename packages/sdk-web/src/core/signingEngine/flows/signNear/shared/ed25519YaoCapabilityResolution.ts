import type {
  NearEd25519YaoMaterialExecutor,
  NearEd25519StepUpAuthorization,
  NearEd25519YaoSigningCapability,
} from '../../../interfaces/near';
import type { NearEd25519YaoSigningPreparation } from '../../../session/material/nearEd25519YaoSigningPreparation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../../session/material/nearEd25519YaoMaterialActivation';
import { requireNearOperationStepUpMaterialActivation } from './operationStepUpPreparation';

export type NearEd25519AuthorizationResult = {
  sessionId: string;
  capability: NearEd25519YaoSigningCapability;
};

export type NearSignatureOnlyOperationStepUpMaterial =
  | {
      kind: 'passkey_live';
      materialActivation: MpcMaterialActivationRef;
      walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
      capability: NearEd25519YaoSigningCapability;
      rehydrate?: never;
    }
  | {
      kind: 'email_otp_live';
      materialActivation: MpcMaterialActivationRef;
      walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
      capability: NearEd25519YaoSigningCapability;
      rehydrate?: never;
    }
  | {
      kind: 'passkey_sealed';
      materialActivation: MpcMaterialActivationRef;
      walletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
      capability?: never;
      rehydrate: (
        credential: WebAuthnAuthenticationCredential,
      ) => Promise<NearEd25519YaoSigningCapability>;
    };

export async function resolvePreparedNearEd25519YaoMaterial(
  preparation: NearEd25519YaoSigningPreparation,
  executor: NearEd25519YaoMaterialExecutor,
): Promise<NearEd25519YaoSigningCapability> {
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

export async function prepareNearSignatureOnlyOperationStepUpMaterial(args: {
  method: 'passkey' | 'email_otp';
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
}): Promise<NearSignatureOnlyOperationStepUpMaterial> {
  if (
    args.method === 'passkey' &&
    args.preparation.hydration.kind === 'rehydrate_material_activation'
  ) {
    const prepared = await args.executor.preparePasskeyOperationStepUp(args.preparation);
    return {
      kind: 'passkey_sealed',
      materialActivation: prepared.materialActivation,
      walletSessionState: prepared.walletSessionState,
      rehydrate: prepared.rehydrate,
    };
  }
  const capability = await resolvePreparedNearEd25519YaoMaterial(
    args.preparation,
    args.executor,
  );
  return {
    kind: args.method === 'passkey' ? 'passkey_live' : 'email_otp_live',
    materialActivation: nearEd25519YaoMaterialActivationFromMetadata(
      capability.activeClient.metadata(),
    ),
    walletSessionState: capability.walletSessionState,
    capability,
  };
}

type ResolveNearSignatureOnlyOperationStepUpCapabilityArgs =
  | {
      kind: 'passkey';
      material: Extract<
        NearSignatureOnlyOperationStepUpMaterial,
        { kind: 'passkey_live' | 'passkey_sealed' }
      >;
      expectedActivation: MpcMaterialActivationRef;
      credential: WebAuthnAuthenticationCredential;
    }
  | {
      kind: 'email_otp';
      material: Extract<NearSignatureOnlyOperationStepUpMaterial, { kind: 'email_otp_live' }>;
      expectedActivation: MpcMaterialActivationRef;
      credential?: never;
    };

export async function resolveNearSignatureOnlyOperationStepUpCapability(
  args: ResolveNearSignatureOnlyOperationStepUpCapabilityArgs,
): Promise<NearEd25519YaoSigningCapability> {
  requireNearOperationStepUpMaterialActivation({
    expected: args.expectedActivation,
    actual: args.material.materialActivation,
  });
  let capability: NearEd25519YaoSigningCapability;
  if (args.kind === 'email_otp') {
    capability = args.material.capability;
  } else {
    capability =
      args.material.kind === 'passkey_live'
        ? args.material.capability
        : await args.material.rehydrate(args.credential);
  }
  try {
    requireNearOperationStepUpMaterialActivation({
      expected: args.expectedActivation,
      actual: nearEd25519YaoMaterialActivationFromMetadata(capability.activeClient.metadata()),
    });
    return capability;
  } catch (error) {
    if (args.material.kind === 'passkey_sealed') capability.activeClient.dispose();
    throw error;
  }
}

export async function resolveConfirmedNearEd25519YaoCapability(args: {
  authorization: NearEd25519StepUpAuthorization;
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
}): Promise<NearEd25519AuthorizationResult> {
  switch (args.authorization.kind) {
    case 'warm_session': {
      const capability = await resolvePreparedNearEd25519YaoMaterial(
        args.preparation,
        args.executor,
      );
      return {
        sessionId: capability.walletSessionState.thresholdSessionId,
        capability,
      };
    }
    case 'passkey': {
      const capability = await resolvePreparedNearEd25519YaoMaterial(
        args.preparation,
        args.executor,
      );
      if (
        capability.walletSessionState.thresholdSessionId !==
        args.authorization.plannedPasskeyOperationStepUp.sessionId
      ) {
        throw new Error(
          '[SigningEngine] passkey signing capability does not match the confirmed material session',
        );
      }
      return {
        sessionId: capability.walletSessionState.thresholdSessionId,
        capability,
      };
    }
    case 'email_otp': {
      const capability = await resolvePreparedNearEd25519YaoMaterial(
        args.preparation,
        args.executor,
      );
      return {
        sessionId: capability.walletSessionState.thresholdSessionId,
        capability,
      };
    }
    default:
      return assertNeverNearEd25519StepUpAuthorization(args.authorization);
  }
}

function assertNeverNearEd25519StepUpAuthorization(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 step-up authorization: ${String(value)}`,
  );
}
