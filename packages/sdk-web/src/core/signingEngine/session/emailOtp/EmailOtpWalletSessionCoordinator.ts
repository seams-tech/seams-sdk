import {
  EmailOtpWalletSessionRuntime,
  type EmailOtpWalletSessionCoordinatorDeps,
} from './coordinatorRuntime';

export type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
export type {
  EmailOtpThresholdEcdsaEnrollmentResult,
  EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
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

  persistEd25519YaoSessionForRefresh(
    args: Parameters<EmailOtpWalletSessionRuntime['persistEd25519YaoSessionForRefresh']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['persistEd25519YaoSessionForRefresh']> {
    return this.runtime.persistEd25519YaoSessionForRefresh(args);
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

  readPersistedSessionSnapshot(
    args: Parameters<EmailOtpWalletSessionRuntime['readPersistedSessionSnapshot']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['readPersistedSessionSnapshot']> {
    return this.runtime.readPersistedSessionSnapshot(args);
  }

  readWarmSessionStatusOnly(
    sessionId: Parameters<EmailOtpWalletSessionRuntime['readWarmSessionStatusOnly']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['readWarmSessionStatusOnly']> {
    return this.runtime.readWarmSessionStatusOnly(sessionId);
  }

  claimWarmSessionMaterial(
    args: Parameters<EmailOtpWalletSessionRuntime['claimWarmSessionMaterial']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['claimWarmSessionMaterial']> {
    return this.runtime.claimWarmSessionMaterial(args);
  }

  consumeWarmSessionUses(
    args: Parameters<EmailOtpWalletSessionRuntime['consumeWarmSessionUses']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['consumeWarmSessionUses']> {
    return this.runtime.consumeWarmSessionUses(args);
  }

  clearVolatileWarmSessionMaterial(
    sessionId: Parameters<EmailOtpWalletSessionRuntime['clearVolatileWarmSessionMaterial']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['clearVolatileWarmSessionMaterial']> {
    return this.runtime.clearVolatileWarmSessionMaterial(sessionId);
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

  exportEcdsaKeyWithAuthorization(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithAuthorization']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithAuthorization']> {
    return this.runtime.exportEcdsaKeyWithAuthorization(args);
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

  enrollAndLoginWithEcdsaCapabilityInternal(
    args: Parameters<EmailOtpWalletSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']> {
    return this.runtime.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }
}
