import type {
  SigningRuntime,
  SigningRuntimeDeps,
  SigningRuntimeServices,
  SigningRuntimeStatePorts,
} from './runtime.types';

type AsyncServiceFactory<TService> = () => Promise<TService>;

function memoizeService<TService>(
  factory: AsyncServiceFactory<TService>,
): AsyncServiceFactory<TService> {
  let servicePromise: Promise<TService> | undefined;
  return () => {
    servicePromise ??= factory().catch((error) => {
      servicePromise = undefined;
      throw error;
    });
    return servicePromise;
  };
}

export function createSigningRuntimeStatePorts(): SigningRuntimeStatePorts {
  return {
    ecdsaSessions: {
      recordsByLane: new Map(),
      exportArtifactsByLane: new Map(),
    },
  };
}

export function createSigningRuntime(deps: SigningRuntimeDeps): SigningRuntime {
  const getWarmSessions = memoizeService(async () => {
    const { createWarmSessionHydrationService } = await import(
      '@/core/signingEngine/session/passkey/warmSessionHydration'
    );
    return createWarmSessionHydrationService({
      getWarmSessionMaterialWriter: deps.ui.warmSessions.getWarmSessionMaterialWriter,
    });
  });
  const warmSessions: SigningRuntimeServices['warmSessions'] = {
    hydrateSigningSession: async (input) =>
      (await getWarmSessions()).hydrateSigningSession(input),
  };

  const getRegistrationAccounts = memoizeService(async () => {
    const { createRegistrationAccountsService } = await import(
      '@/core/signingEngine/flows/registration/services/registrationAccounts'
    );
    return createRegistrationAccountsService(deps.registration.accountLifecycle);
  });
  const registrationAccounts: SigningRuntimeServices['registrationAccounts'] = {
    storeUserData: async (userData) => (await getRegistrationAccounts()).storeUserData(userData),
    getAllUsers: async () => (await getRegistrationAccounts()).getAllUsers(),
    getUserBySignerSlot: async (nearAccountId, signerSlot) =>
      (await getRegistrationAccounts()).getUserBySignerSlot(nearAccountId, signerSlot),
    getLastUser: async () => (await getRegistrationAccounts()).getLastUser(),
    nearAuthenticatorsByAccount: async (nearAccountId) =>
      (await getRegistrationAccounts()).nearAuthenticatorsByAccount(nearAccountId),
    updateLastLogin: async (nearAccountId) =>
      (await getRegistrationAccounts()).updateLastLogin(nearAccountId),
    setLastUser: async (nearAccountId, signerSlot) =>
      (await getRegistrationAccounts()).setLastUser(nearAccountId, signerSlot),
    activateAuthenticatedWalletState: async (input) =>
      (await getRegistrationAccounts()).activateAuthenticatedWalletState(input),
    storeAuthenticator: async (authenticatorData) =>
      (await getRegistrationAccounts()).storeAuthenticator(authenticatorData),
    rollbackUserRegistration: async (nearAccountId) =>
      (await getRegistrationAccounts()).rollbackUserRegistration(nearAccountId),
    hasPasskeyCredential: async (nearAccountId) =>
      (await getRegistrationAccounts()).hasPasskeyCredential(nearAccountId),
    storeWalletEd25519RegistrationData: async (input) =>
      (await getRegistrationAccounts()).storeWalletEd25519RegistrationData(input),
    storeWalletEmailOtpEd25519RegistrationData: async (input) =>
      (await getRegistrationAccounts()).storeWalletEmailOtpEd25519RegistrationData(input),
    finalizeWalletEd25519SignerRegistration: async (input) =>
      (await getRegistrationAccounts()).finalizeWalletEd25519SignerRegistration(input),
  };

  const getEcdsaRegistrationBootstrap = memoizeService(async () => {
    const { createEcdsaRegistrationBootstrapService } = await import(
      '@/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap'
    );
    return createEcdsaRegistrationBootstrapService({
      signerCrypto: deps.runtimePorts.signerCrypto,
      emailOtpWorker: deps.workers.emailOtp,
    });
  });
  const ecdsaRegistrationBootstrap: SigningRuntimeServices['ecdsaRegistrationBootstrap'] = {
    preparePasskeyClientBootstrap: async (input) =>
      (await getEcdsaRegistrationBootstrap()).preparePasskeyClientBootstrap(input),
    prepareEmailOtpClientBootstrap: async (input) =>
      (await getEcdsaRegistrationBootstrap()).prepareEmailOtpClientBootstrap(input),
    finalizeClientBootstrap: async (input) =>
      (await getEcdsaRegistrationBootstrap()).finalizeClientBootstrap(input),
    storeClientSigningMaterial: async (input) =>
      (await getEcdsaRegistrationBootstrap()).storeClientSigningMaterial(input),
  };

  const getEcdsaRegistrationSessions = memoizeService(async () => {
    const { createEcdsaRegistrationSessionsService } = await import(
      '@/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions'
    );
    return createEcdsaRegistrationSessionsService({
      registrationBootstrap: ecdsaRegistrationBootstrap,
      bootstrapStore: deps.registration.ecdsaBootstrapStore,
      sessionStore: deps.state.ecdsaSessions,
      warmSessions,
      signingSessionSeal: deps.config.signing.sessionSeal,
    });
  });
  const ecdsaRegistrationSessions: SigningRuntimeServices['ecdsaRegistrationSessions'] = {
    finalizeWalletRegistrationEcdsaSessions: async (input) =>
      (await getEcdsaRegistrationSessions()).finalizeWalletRegistrationEcdsaSessions(input),
  };

  const getEcdsaWalletRecords = memoizeService(async () => {
    const { createEcdsaWalletRecordsService } = await import(
      '@/core/signingEngine/flows/registration/services/ecdsaWalletRecords'
    );
    return createEcdsaWalletRecordsService({
      accountLifecycle: deps.registration.accountLifecycle,
    });
  });
  const ecdsaWalletRecords: SigningRuntimeServices['ecdsaWalletRecords'] = {
    storeWalletEcdsaSignerRecords: async (input) =>
      (await getEcdsaWalletRecords()).storeWalletEcdsaSignerRecords(input),
    storeWalletEmailOtpEcdsaSignerRecords: async (input) =>
      (await getEcdsaWalletRecords()).storeWalletEmailOtpEcdsaSignerRecords(input),
    finalizeWalletEcdsaRegistration: async (input) =>
      (await getEcdsaWalletRecords()).finalizeWalletEcdsaRegistration(input),
    storeWalletEmailOtpEcdsaRegistrationData: async (input) =>
      (await getEcdsaWalletRecords()).storeWalletEmailOtpEcdsaRegistrationData(input),
  };

  const getEcdsaProvisioning = memoizeService(async () => {
    const { createProvisionEcdsaUseCase } = await import(
      '@/core/signingEngine/useCases/provisionEcdsa'
    );
    return createProvisionEcdsaUseCase({
      authenticator: deps.runtimePorts.authenticator,
      signerCrypto: deps.runtimePorts.signerCrypto,
      storage: deps.runtimePorts.storage,
      relayer: deps.relayers.ecdsa,
      clock: deps.runtimePorts.clock,
    });
  });
  const ecdsaProvisioning: SigningRuntimeServices['ecdsaProvisioning'] = {
    provision: async (input) => (await getEcdsaProvisioning()).provision(input),
  };

  const nearSigning: SigningRuntimeServices['nearSigning'] = {
    signNear: async (request) => {
      const { signNear } = await import('@/core/signingEngine/flows/signNear/signNear');
      return signNear(deps.signing.near.getDeps(), request);
    },
  };

  const evmFamilySigning: SigningRuntimeServices['evmFamilySigning'] = {
    signEvmFamily: async (args) => {
      const { signEvmFamily } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return signEvmFamily(deps.signing.evmFamily.getDeps(), args);
    },
    reportTempoBroadcastAccepted: async (args) => {
      const { reportTempoBroadcastAccepted } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return reportTempoBroadcastAccepted(deps.signing.evmFamily.getDeps(), args);
    },
    reportTempoBroadcastRejected: async (args) => {
      const { reportTempoBroadcastRejected } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return reportTempoBroadcastRejected(deps.signing.evmFamily.getDeps(), args);
    },
    reportTempoFinalized: async (args) => {
      const { reportTempoFinalized } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return reportTempoFinalized(deps.signing.evmFamily.getDeps(), args);
    },
    reportTempoDroppedOrReplaced: async (args) => {
      const { reportTempoDroppedOrReplaced } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return reportTempoDroppedOrReplaced(deps.signing.evmFamily.getDeps(), args);
    },
    reconcileTempoNonceLane: async (args) => {
      const { reconcileTempoNonceLane } = await import(
        '@/core/signingEngine/flows/signEvmFamily/signEvmFamily'
      );
      return reconcileTempoNonceLane(deps.signing.evmFamily.getDeps(), args);
    },
  };

  return {
    ...deps,
    services: {
      warmSessions,
      nearKeyOperations: {
        signTransactionWithKeyPair: (input) => deps.nearKeyOps.signTransactionWithKeyPair(input),
        generateEphemeralNearKeypair: () => deps.nearKeyOps.generateEphemeralNearKeypair(),
      },
      registrationAccounts,
      nearSigning,
      evmFamilySigning,
      ecdsaRegistrationBootstrap,
      ecdsaRegistrationSessions,
      ecdsaWalletRecords,
      ecdsaProvisioning,
    },
  };
}
