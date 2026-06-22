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
  LoginEmailOtpEd25519CapabilityArgs,
} from './ed25519Warmup';
export type {
  EmailOtpCoordinatorRuntimePorts,
  EmailOtpEcdsaSessionPorts,
  EmailOtpEd25519SessionPorts,
  EmailOtpEd25519PersistencePorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpWalletSessionCoordinatorDeps,
} from './ports';

export class EmailOtpWalletSessionCoordinator {
  private readonly runtime: EmailOtpWalletSessionRuntime;

  constructor(deps: EmailOtpWalletSessionCoordinatorDeps) {
    this.runtime = new EmailOtpWalletSessionRuntime(deps);
  }

  restorePersistedSessionsForWallet(
    args: Parameters<EmailOtpWalletSessionRuntime['restorePersistedSessionsForWallet']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['restorePersistedSessionsForWallet']> {
    return this.runtime.restorePersistedSessionsForWallet(args);
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

  attachEd25519SessionToEmailOtpSigningSessionSeal(
    args: Parameters<
      EmailOtpWalletSessionRuntime['attachEd25519SessionToEmailOtpSigningSessionSeal']
    >[0],
  ): ReturnType<
    EmailOtpWalletSessionRuntime['attachEd25519SessionToEmailOtpSigningSessionSeal']
  > {
    return this.runtime.attachEd25519SessionToEmailOtpSigningSessionSeal(args);
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

  resolveAppSessionJwt(
    args: Parameters<EmailOtpWalletSessionRuntime['resolveAppSessionJwt']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['resolveAppSessionJwt']> {
    return this.runtime.resolveAppSessionJwt(args);
  }

  isEd25519WarmupPending(
    args: Parameters<EmailOtpWalletSessionRuntime['isEd25519WarmupPending']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['isEd25519WarmupPending']> {
    return this.runtime.isEd25519WarmupPending(args);
  }

  waitForPendingEd25519Warmup(
    args: Parameters<EmailOtpWalletSessionRuntime['waitForPendingEd25519Warmup']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['waitForPendingEd25519Warmup']> {
    return this.runtime.waitForPendingEd25519Warmup(args);
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

  exportEd25519SeedWithAuthorization(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEd25519SeedWithAuthorization']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEd25519SeedWithAuthorization']> {
    return this.runtime.exportEd25519SeedWithAuthorization(args);
  }

  exportEcdsaKeyWithAuthorization(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithAuthorization']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithAuthorization']> {
    return this.runtime.exportEcdsaKeyWithAuthorization(args);
  }

  exportEcdsaKeyWithFreshEmailOtpLane(
    args: Parameters<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithFreshEmailOtpLane']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['exportEcdsaKeyWithFreshEmailOtpLane']> {
    return this.runtime.exportEcdsaKeyWithFreshEmailOtpLane(args);
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

  loginWithEd25519CapabilityInternal(
    args: Parameters<EmailOtpWalletSessionRuntime['loginWithEd25519CapabilityInternal']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['loginWithEd25519CapabilityInternal']> {
    return this.runtime.loginWithEd25519CapabilityInternal(args);
  }

  enrollAndLoginWithEcdsaCapabilityInternal(
    args: Parameters<EmailOtpWalletSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']> {
    return this.runtime.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }

  loginWithEd25519CapabilityForSigning(
    args: Parameters<EmailOtpWalletSessionRuntime['loginWithEd25519CapabilityForSigning']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['loginWithEd25519CapabilityForSigning']> {
    return this.runtime.loginWithEd25519CapabilityForSigning(args);
  }

  reconstructEd25519Session(
    args: Parameters<EmailOtpWalletSessionRuntime['reconstructEd25519Session']>[0],
  ): ReturnType<EmailOtpWalletSessionRuntime['reconstructEd25519Session']> {
    return this.runtime.reconstructEd25519Session(args);
  }
}
