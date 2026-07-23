import type {
  NearEd25519EmailOtpStepUpAuthorization,
  NearEd25519PasskeyStepUpAuthorization,
  NearEd25519StepUpAuthorization,
  NearEd25519YaoCapabilitySource,
  NearEd25519YaoSigningCapability,
  NearEmailOtpEd25519ReconnectHook,
  NearPasskeyEd25519ReconnectHook,
} from '../../../interfaces/near';

export type NearEd25519ReconnectResult = {
  sessionId: string;
  capability: NearEd25519YaoSigningCapability;
};

export async function resolveNearEd25519YaoCapabilitySource(
  source: NearEd25519YaoCapabilitySource,
): Promise<NearEd25519YaoSigningCapability> {
  switch (source.kind) {
    case 'active_capability':
      return source.capability;
    case 'capability_rehydration':
      return await source.rehydrate();
    case 'email_otp_reconnect':
      throw new Error(
        '[SigningEngine][near] confirmed Email OTP reconnect did not activate an Ed25519 Yao capability',
      );
    default:
      return assertNeverNearEd25519YaoCapabilitySource(source);
  }
}

export function nearEd25519YaoResolutionRequiresBudgetReadmission(
  source: NearEd25519YaoCapabilitySource,
): boolean {
  switch (source.kind) {
    case 'active_capability':
      return false;
    case 'capability_rehydration':
    case 'email_otp_reconnect':
      return true;
    default:
      return assertNeverNearEd25519YaoCapabilitySource(source);
  }
}

export async function reconnectNearPasskeyEd25519(args: {
  authorization: NearEd25519PasskeyStepUpAuthorization;
  hook: NearPasskeyEd25519ReconnectHook | null | undefined;
  requiredSignatureUses: number;
}): Promise<NearEd25519ReconnectResult> {
  if (!args.hook) {
    throw new Error('[SigningEngine] passkey reconnect runner is unavailable');
  }
  if (!args.authorization.credential) {
    throw new Error('[SigningEngine] missing WebAuthn credential for passkey session reconnect');
  }
  const refreshed = await args.hook.reconnect({
    authorization: args.authorization,
    requiredSignatureUses: args.requiredSignatureUses,
  });
  return nearEd25519ReconnectResult(refreshed);
}

export async function reconnectNearEmailOtpEd25519(args: {
  authorization: NearEd25519EmailOtpStepUpAuthorization;
  hook: NearEmailOtpEd25519ReconnectHook | null | undefined;
  requiredSignatureUses: number;
}): Promise<NearEd25519ReconnectResult> {
  if (!args.hook) {
    throw new Error('[SigningEngine] Email OTP reconnect runner is unavailable');
  }
  const refreshed = await args.hook.reconnect({
    authorization: args.authorization,
    requiredSignatureUses: args.requiredSignatureUses,
  });
  return nearEd25519ReconnectResult(refreshed);
}

export async function resolveConfirmedNearEd25519YaoCapability(args: {
  authorization: NearEd25519StepUpAuthorization;
  source: NearEd25519YaoCapabilitySource;
  passkeyReconnect: NearPasskeyEd25519ReconnectHook | null;
  emailOtpReconnect: NearEmailOtpEd25519ReconnectHook | null;
  requiredSignatureUses: number;
}): Promise<NearEd25519ReconnectResult> {
  switch (args.authorization.kind) {
    case 'warm_session': {
      const capability = await resolveNearEd25519YaoCapabilitySource(args.source);
      return {
        sessionId: capability.walletSessionState.thresholdSessionId,
        capability,
      };
    }
    case 'passkey': {
      if (!args.passkeyReconnect) {
        const capability = await resolveNearEd25519YaoCapabilitySource(args.source);
        return {
          sessionId: capability.walletSessionState.thresholdSessionId,
          capability,
        };
      }
      const refreshed = await reconnectNearPasskeyEd25519({
        authorization: args.authorization,
        hook: args.passkeyReconnect,
        requiredSignatureUses: args.requiredSignatureUses,
      });
      if (refreshed.sessionId !== args.authorization.plannedPasskeyReconnect.sessionId) {
        throw new Error(
          '[SigningEngine] passkey signing returned a different threshold session id than the confirmed session policy',
        );
      }
      return refreshed;
    }
    case 'email_otp':
      if (!args.emailOtpReconnect) {
        const capability = await resolveNearEd25519YaoCapabilitySource(args.source);
        return {
          sessionId: capability.walletSessionState.thresholdSessionId,
          capability,
        };
      }
      return await reconnectNearEmailOtpEd25519({
        authorization: args.authorization,
        hook: args.emailOtpReconnect,
        requiredSignatureUses: args.requiredSignatureUses,
      });
    default:
      return assertNeverNearEd25519StepUpAuthorization(args.authorization);
  }
}

function nearEd25519ReconnectResult(args: {
  sessionId: string;
  activeClient: NearEd25519YaoSigningCapability['activeClient'];
  sessionState: NearEd25519YaoSigningCapability['walletSessionState'];
}): NearEd25519ReconnectResult {
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

function assertNeverNearEd25519YaoCapabilitySource(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 Yao capability source: ${String(value)}`,
  );
}

function assertNeverNearEd25519StepUpAuthorization(value: never): never {
  throw new Error(
    `[SigningEngine][near] unsupported Ed25519 step-up authorization: ${String(value)}`,
  );
}
