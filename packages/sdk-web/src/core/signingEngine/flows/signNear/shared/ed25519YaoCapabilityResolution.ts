import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519YaoCommittedCapability,
  NearEd25519YaoSigningCapability,
  NearEmailOtpEd25519ReauthorizationHook,
} from '../../../interfaces/near';

export type NearEd25519AuthorizationResult = {
  sessionId: string;
  capability: NearEd25519YaoSigningCapability;
};

export async function resolveNearEd25519YaoCommittedCapability(
  committed: NearEd25519YaoCommittedCapability,
): Promise<NearEd25519YaoSigningCapability> {
  switch (committed.kind) {
    case 'live_runtime':
      return committed.capability;
    case 'sealed_material_activation':
      return await committed.hydrate();
    default:
      return assertNeverNearEd25519YaoCommittedCapability(committed);
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
  committed: NearEd25519YaoCommittedCapability | null;
  emailOtpReauthorization: NearEmailOtpEd25519ReauthorizationHook | null;
  requiredSignatureUses: number;
}): Promise<NearEd25519AuthorizationResult> {
  switch (args.authorization.kind) {
    case 'warm_session': {
      const capability = await resolveNearEd25519YaoCommittedCapability(
        requireCommittedNearEd25519YaoCapability(args.committed),
      );
      return {
        sessionId: capability.walletSessionState.thresholdSessionId,
        capability,
      };
    }
    case 'passkey': {
      const capability = await resolveNearEd25519YaoCommittedCapability(
        requireCommittedNearEd25519YaoCapability(args.committed),
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
        const capability = await resolveNearEd25519YaoCommittedCapability(
          requireCommittedNearEd25519YaoCapability(args.committed),
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

function requireCommittedNearEd25519YaoCapability(
  value: NearEd25519YaoCommittedCapability | null,
): NearEd25519YaoCommittedCapability {
  if (!value) {
    throw new Error('[SigningEngine][near] committed Ed25519 Yao capability is unavailable');
  }
  return value;
}

function assertNeverNearEd25519YaoCommittedCapability(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 Yao capability source: ${String(value)}`,
  );
}

function assertNeverNearEd25519StepUpAuthorization(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 step-up authorization: ${String(value)}`,
  );
}
