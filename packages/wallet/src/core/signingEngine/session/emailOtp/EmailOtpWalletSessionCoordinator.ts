import {
  EmailOtpWalletSessionRuntime,
  type EmailOtpWalletSessionCoordinatorDeps,
} from './coordinatorRuntime';

export type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
export type {
  EmailOtpCoordinatorRuntimePorts,
  EmailOtpEcdsaSessionPorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpWalletSessionCoordinatorDeps,
} from './ports';

export class EmailOtpWalletSessionCoordinator {
  private readonly runtime: EmailOtpWalletSessionRuntime;

  constructor(deps: EmailOtpWalletSessionCoordinatorDeps) {
    this.runtime = new EmailOtpWalletSessionRuntime(deps);
  }

  persistEcdsaSessionForRefresh(
    args: Parameters<EmailOtpWalletSessionRuntime['persistEcdsaSessionForRefresh']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['persistEcdsaSessionForRefresh']> {
    return this.runtime.persistEcdsaSessionForRefresh(args);
  }

  discoverPersistedSessionsForWallet(
    args: Parameters<EmailOtpWalletSessionRuntime['discoverPersistedSessionsForWallet']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['discoverPersistedSessionsForWallet']> {
    return this.runtime.discoverPersistedSessionsForWallet(args);
  }

  restorePersistedSessionForSigning(
    args: Parameters<EmailOtpWalletSessionRuntime['restorePersistedSessionForSigning']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['restorePersistedSessionForSigning']> {
    return this.runtime.restorePersistedSessionForSigning(args);
  }

  readWarmSessionStatusOnly(
    target: Parameters<EmailOtpWalletSessionRuntime['readWarmSessionStatusOnly']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['readWarmSessionStatusOnly']> {
    return this.runtime.readWarmSessionStatusOnly(target);
  }

  consumeWarmSessionUses(
    args: Parameters<EmailOtpWalletSessionRuntime['consumeWarmSessionUses']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['consumeWarmSessionUses']> {
    return this.runtime.consumeWarmSessionUses(args);
  }

  clearVolatileWarmSessionMaterial(
    target: Parameters<EmailOtpWalletSessionRuntime['clearVolatileWarmSessionMaterial']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['clearVolatileWarmSessionMaterial']> {
    return this.runtime.clearVolatileWarmSessionMaterial(target);
  }

  async requestTransactionSigningChallenge(
    args: Parameters<EmailOtpWalletSessionRuntime['requestTransactionSigningChallenge']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['requestTransactionSigningChallenge']> {
    return await this.runtime.requestTransactionSigningChallenge(args);
  }

  async requestExportChallenge(
    args: Parameters<EmailOtpWalletSessionRuntime['requestExportChallenge']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['requestExportChallenge']> {
    return await this.runtime.requestExportChallenge(args);
  }

  exportEcdsaKeyWithDurableAuthorization(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithDurableAuthorization']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithDurableAuthorization']> {
    return this.runtime.exportEcdsaKeyWithDurableAuthorization(args);
  }

  exportEd25519YaoSeedWithFreshEmailOtpLane(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEd25519YaoSeedWithFreshEmailOtpLane']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEd25519YaoSeedWithFreshEmailOtpLane']> {
    return this.runtime.exportEd25519YaoSeedWithFreshEmailOtpLane(args);
  }

  loginWithEcdsaCapabilityForSigning(
    args: Parameters<EmailOtpWalletSessionRuntime['loginWithEcdsaCapabilityForSigning']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['loginWithEcdsaCapabilityForSigning']> {
    return this.runtime.loginWithEcdsaCapabilityForSigning(args);
  }

  loginWithEcdsaCapabilityInternal(
    args: Parameters<EmailOtpWalletSessionRuntime['loginWithEcdsaCapabilityInternal']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['loginWithEcdsaCapabilityInternal']> {
    return this.runtime.loginWithEcdsaCapabilityInternal(args);
  }
}
