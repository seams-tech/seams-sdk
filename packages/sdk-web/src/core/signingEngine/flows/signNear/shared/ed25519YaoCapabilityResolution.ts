import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519YaoMaterialExecutor,
  NearEd25519StepUpAuthorization,
  NearEd25519YaoSigningCapability,
  NearEmailOtpEd25519ReauthorizationHook,
} from '../../../interfaces/near';
import type { NearEd25519YaoSigningPreparation } from '../../../session/material/nearEd25519YaoSigningPreparation';

export type NearEd25519AuthorizationResult = {
  sessionId: string;
  capability: NearEd25519YaoSigningCapability;
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

export async function reauthorizeNearEmailOtpEd25519(args: {
  authorization: NearEd25519EmailOtpStepUpAuthorization;
  hook: NearEmailOtpEd25519ReauthorizationHook | null | undefined;
  requiredSignatureUses: number;
}): Promise<NearEd25519AuthorizationResult> {
  if (!args.hook) {
    throw new Error('[SigningEngine] Email OTP reconnect runner is unavailable');
  }
  const refreshed = await args.hook.authorize({
    authorization: args.authorization,
    requiredSignatureUses: args.requiredSignatureUses,
  });
  return nearEd25519AuthorizationResult(refreshed);
}

export async function resolveConfirmedNearEd25519YaoCapability(args: {
  authorization: NearEd25519StepUpAuthorization;
  preparation: NearEd25519YaoSigningPreparation;
  executor: NearEd25519YaoMaterialExecutor;
  emailOtpReauthorization: NearEmailOtpEd25519ReauthorizationHook | null;
  requiredSignatureUses: number;
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
    case 'email_otp':
      if (!args.emailOtpReauthorization) {
        const capability = await resolvePreparedNearEd25519YaoMaterial(
          args.preparation,
          args.executor,
        );
        return {
          sessionId: capability.walletSessionState.thresholdSessionId,
          capability,
        };
      }
      return await reauthorizeNearEmailOtpEd25519({
        authorization: args.authorization,
        hook: args.emailOtpReauthorization,
        requiredSignatureUses: args.requiredSignatureUses,
      });
    default:
      return assertNeverNearEd25519StepUpAuthorization(args.authorization);
  }
}

function nearEd25519AuthorizationResult(args: {
  sessionId: string;
  activeClient: NearEd25519YaoSigningCapability['activeClient'];
  sessionState: NearEd25519YaoSigningCapability['walletSessionState'];
}): NearEd25519AuthorizationResult {
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('[SigningEngine][near] reconnect did not return a threshold session id');
  }
  if (args.sessionState.thresholdSessionId !== sessionId) {
    throw new Error('[SigningEngine][near] reconnect session state does not match its session id');
  }
  return {
    sessionId,
    capability: {
      activeClient: args.activeClient,
      walletSessionState: args.sessionState,
    },
  };
}

function assertNeverNearEd25519StepUpAuthorization(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 step-up authorization: ${String(value)}`,
  );
}
