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

  rememberAppSessionJwt(
    args: Parameters<EmailOtpWalletSessionRuntime['rememberAppSessionJwt']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['rememberAppSessionJwt']> {
    return this.runtime.rememberAppSessionJwt(args);
  }

  rememberAppSessionBinding(
    binding: Parameters<EmailOtpWalletSessionRuntime['rememberAppSessionBinding']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['rememberAppSessionBinding']> {
    return this.runtime.rememberAppSessionBinding(binding);
  }

  resolveAppSessionJwt(
    args: Parameters<EmailOtpWalletSessionRuntime['resolveAppSessionJwt']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['resolveAppSessionJwt']> {
    return this.runtime.resolveAppSessionJwt(args);
  }

  resolveAppSessionJwtForWallet(
    args: Parameters<EmailOtpWalletSessionRuntime['resolveAppSessionJwtForWallet']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['resolveAppSessionJwtForWallet']> {
    return this.runtime.resolveAppSessionJwtForWallet(args);
  }

  resolveAppSessionJwtForProviderSubject(
    args: Parameters<EmailOtpWalletSessionRuntime['resolveAppSessionJwtForProviderSubject']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['resolveAppSessionJwtForProviderSubject']> {
    return this.runtime.resolveAppSessionJwtForProviderSubject(args);
  }

  async requestTransactionSigningChallenge(
    args: Parameters<EmailOtpWalletSessionRuntime['requestTransactionSigningChallenge']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['requestTransactionSigningChallenge']> {
    return await this.runtime.requestTransactionSigningChallenge(args);
  }

  async requestCapabilityStepUpTransactionSigningChallenge(
    args: Parameters<
      EmailOtpWalletSessionRuntime['requestCapabilityStepUpTransactionSigningChallenge']
    >[0],
  ): ReturnType<
    EmailOtpWalletSessionRuntime['requestCapabilityStepUpTransactionSigningChallenge']
  > {
    return await this.runtime.requestCapabilityStepUpTransactionSigningChallenge(args);
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
