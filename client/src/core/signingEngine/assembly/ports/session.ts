import { configuredThresholdEcdsaChainTargets } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UiConfirmRuntimeBridgePort } from '../../uiConfirm/types';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import type { SessionPublicDeps } from '../../session/public';
import type { CreateSigningEnginePortsArgs } from './shared';

export function createSessionPublicDeps(args: {
  seamsPasskeyConfigs: CreateSigningEnginePortsArgs['seamsPasskeyConfigs'];
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  touchConfirm: UiConfirmRuntimeBridgePort;
  emailOtpSessions: {
    restorePersistedSessionsForAccount: SessionPublicDeps['restore']['emailOtp'];
  };
}): SessionPublicDeps {
  const passkeyRestore = args.touchConfirm.restorePersistedSessionsForAccount
    ? (restoreArgs: Parameters<NonNullable<SessionPublicDeps['restore']['passkey']>>[0]) =>
        args.touchConfirm.restorePersistedSessionsForAccount!(restoreArgs)
    : undefined;

  return {
    availableLanes: {
      ecdsaSessions: args.ecdsaSessions,
      statusReader: args.touchConfirm,
    },
    ecdsaSessions: args.ecdsaSessions,
    signingSessionSeal: args.seamsPasskeyConfigs.signing.sessionSeal,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsPasskeyConfigs.network.chains),
    restore: {
      emailOtp: (restoreArgs) => args.emailOtpSessions.restorePersistedSessionsForAccount(restoreArgs),
      ...(passkeyRestore ? { passkey: passkeyRestore } : {}),
    },
  };
}
