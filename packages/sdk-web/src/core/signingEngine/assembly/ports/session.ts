import type { SeamsConfigsReadonly } from '@/core/types/seams';
import { configuredThresholdEcdsaChainTargets } from '../../interfaces/ecdsaChainTarget';
import type { SigningSessionStatusReader } from '../../session/lifecycle/walletSessionStatus';
import type { EmailOtpWalletSessionCoordinator } from '../../session/emailOtp/EmailOtpWalletSessionCoordinator';
import type { SessionPublicDeps } from '../../session/public';
import type {
  PasskeyMpcSessionPort,
  UiConfirmRuntimeBridgePort,
} from '../../uiConfirm/uiConfirm.types';
import type { PersistedAvailableSigningLanesDeps } from '../../session/availability/persistedAvailableSigningLanes';
import { SIGNING_SESSION_SEAL_GROUP_ID } from '@shared/utils/signingSessionSeal';

export function createSessionPublicDeps(args: {
  seamsWebConfigs: SeamsConfigsReadonly;
  touchConfirm: UiConfirmRuntimeBridgePort;
  passkeyMpcSession: PasskeyMpcSessionPort;
  emailOtpSessions: EmailOtpWalletSessionCoordinator;
  listEcdsaSigningCapabilitiesForWallet: PersistedAvailableSigningLanesDeps['listEcdsaSigningCapabilitiesForWallet'];
  getWalletSessionStatus: SigningSessionStatusReader;
}): SessionPublicDeps {
  const sessionDiscovery: SessionPublicDeps['discovery'] = {
    emailOtp: (discoveryArgs) =>
      args.emailOtpSessions.discoverPersistedSessionsForWallet(discoveryArgs),
    passkey: (discoveryArgs) =>
      args.passkeyMpcSession.discoverPersistedSessionsForWallet(discoveryArgs),
  };
  return {
    availableLanes: {
      listEcdsaSigningCapabilitiesForWallet: args.listEcdsaSigningCapabilitiesForWallet,
    },
    signingSessionSeal:
      args.seamsWebConfigs.signing.sessionSeal.mode === 'sealed_refresh_v1'
        ? { groupId: SIGNING_SESSION_SEAL_GROUP_ID }
        : undefined,
    getConfiguredEcdsaChainTargets: () =>
      configuredThresholdEcdsaChainTargets(args.seamsWebConfigs.network.chains),
    discovery: sessionDiscovery,
  };
}
