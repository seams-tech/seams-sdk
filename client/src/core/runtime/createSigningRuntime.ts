import type {
  SigningRuntime,
  SigningRuntimeDeps,
  SigningRuntimeStatePorts,
} from './types';
import { createProvisionEcdsaUseCase } from '@/core/signingEngine/useCases/provisionEcdsa';
import { createEcdsaRegistrationBootstrapService } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap';
import { createEcdsaWalletRecordsService } from '@/core/signingEngine/flows/registration/services/ecdsaWalletRecords';
import { createEcdsaRegistrationSessionsService } from '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions';
import { createWarmSessionHydrationService } from '@/core/signingEngine/session/passkey/warmSessionHydration';
import { createNearKeyOperationsService } from '@/core/signingEngine/useCases/nearKeyOperations';
import { createRegistrationAccountsService } from '@/core/signingEngine/flows/registration/services/registrationAccounts';
import { signNear } from '@/core/signingEngine/flows/signNear/signNear';
import {
  reconcileTempoNonceLane,
  reportTempoBroadcastAccepted,
  reportTempoBroadcastRejected,
  reportTempoDroppedOrReplaced,
  reportTempoFinalized,
  signTempo,
} from '@/core/signingEngine/flows/signEvmFamily/signEvmFamily';

export function createSigningRuntimeStatePorts(): SigningRuntimeStatePorts {
  return {
    ecdsaSessions: {
      recordsByLane: new Map(),
      exportArtifactsByLane: new Map(),
    },
  };
}

export function createSigningRuntime(deps: SigningRuntimeDeps): SigningRuntime {
  const ecdsaRegistrationBootstrap = createEcdsaRegistrationBootstrapService({
    signerCrypto: deps.platformRuntime.signerCrypto,
    emailOtpWorker: deps.workers.emailOtp,
  });
  const warmSessions = createWarmSessionHydrationService({
    getWarmSessionMaterialWriter: deps.ui.warmSessions.getWarmSessionMaterialWriter,
  });
  return {
    ...deps,
    services: {
      warmSessions,
      nearKeyOperations: createNearKeyOperationsService(deps.nearKeyOps),
      registrationAccounts: createRegistrationAccountsService(
        deps.registration.accountLifecycle,
      ),
      nearSigning: {
        signNear: (request) => signNear(deps.signing.near.getDeps(), request),
      },
      evmFamilySigning: {
        signTempo: (args) => signTempo(deps.signing.evmFamily.getDeps(), args),
        reportTempoBroadcastAccepted: (args) =>
          reportTempoBroadcastAccepted(deps.signing.evmFamily.getDeps(), args),
        reportTempoBroadcastRejected: (args) =>
          reportTempoBroadcastRejected(deps.signing.evmFamily.getDeps(), args),
        reportTempoFinalized: (args) =>
          reportTempoFinalized(deps.signing.evmFamily.getDeps(), args),
        reportTempoDroppedOrReplaced: (args) =>
          reportTempoDroppedOrReplaced(deps.signing.evmFamily.getDeps(), args),
        reconcileTempoNonceLane: (args) =>
          reconcileTempoNonceLane(deps.signing.evmFamily.getDeps(), args),
      },
      ecdsaRegistrationBootstrap,
      ecdsaRegistrationSessions: createEcdsaRegistrationSessionsService({
        registrationBootstrap: ecdsaRegistrationBootstrap,
        bootstrapStore: deps.registration.ecdsaBootstrapStore,
        sessionStore: deps.state.ecdsaSessions,
        warmSessions,
        signingSessionSeal: deps.config.signing.sessionSeal,
      }),
      ecdsaWalletRecords: createEcdsaWalletRecordsService({
        accountLifecycle: deps.registration.accountLifecycle,
      }),
      ecdsaProvisioning: createProvisionEcdsaUseCase({
        authenticator: deps.platformRuntime.authenticator,
        signerCrypto: deps.platformRuntime.signerCrypto,
        storage: deps.platformRuntime.storage,
        relayer: deps.relayers.ecdsa,
        clock: deps.platformRuntime.clock,
      }),
    },
  };
}
