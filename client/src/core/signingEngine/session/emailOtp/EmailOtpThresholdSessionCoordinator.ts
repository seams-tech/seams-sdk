import {
  EmailOtpThresholdSessionRuntime,
  type EmailOtpThresholdSessionCoordinatorDeps,
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
  EmailOtpEd25519SessionPorts,
  EmailOtpEd25519PersistencePorts,
  EmailOtpSealedSessionStorePorts,
  EmailOtpThresholdSessionCoordinatorDeps,
} from './ports';

export class EmailOtpThresholdSessionCoordinator {
  private readonly runtime: EmailOtpThresholdSessionRuntime;

  constructor(deps: EmailOtpThresholdSessionCoordinatorDeps) {
    this.runtime = new EmailOtpThresholdSessionRuntime(deps);
  }

  restorePersistedSessionsForWallet(
    args: Parameters<EmailOtpThresholdSessionRuntime['restorePersistedSessionsForWallet']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['restorePersistedSessionsForWallet']> {
    return this.runtime.restorePersistedSessionsForWallet(args);
  }

  restorePersistedSessionForSigning(
    args: Parameters<EmailOtpThresholdSessionRuntime['restorePersistedSessionForSigning']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['restorePersistedSessionForSigning']> {
    return this.runtime.restorePersistedSessionForSigning(args);
  }

  readPersistedSessionSnapshot(
    args: Parameters<EmailOtpThresholdSessionRuntime['readPersistedSessionSnapshot']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['readPersistedSessionSnapshot']> {
    return this.runtime.readPersistedSessionSnapshot(args);
  }

  attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(
    args: Parameters<
      EmailOtpThresholdSessionRuntime['attachEd25519SessionToEmailOtpSigningSessionSealBestEffort']
    >[0],
  ): ReturnType<
    EmailOtpThresholdSessionRuntime['attachEd25519SessionToEmailOtpSigningSessionSealBestEffort']
  > {
    return this.runtime.attachEd25519SessionToEmailOtpSigningSessionSealBestEffort(args);
  }

  readWarmSessionStatusOnly(
    sessionId: Parameters<EmailOtpThresholdSessionRuntime['readWarmSessionStatusOnly']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['readWarmSessionStatusOnly']> {
    return this.runtime.readWarmSessionStatusOnly(sessionId);
  }

  claimWarmSessionMaterial(
    args: Parameters<EmailOtpThresholdSessionRuntime['claimWarmSessionMaterial']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['claimWarmSessionMaterial']> {
    return this.runtime.claimWarmSessionMaterial(args);
  }

  consumeWarmSessionUses(
    args: Parameters<EmailOtpThresholdSessionRuntime['consumeWarmSessionUses']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['consumeWarmSessionUses']> {
    return this.runtime.consumeWarmSessionUses(args);
  }

  clearVolatileWarmSessionMaterial(
    sessionId: Parameters<EmailOtpThresholdSessionRuntime['clearVolatileWarmSessionMaterial']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['clearVolatileWarmSessionMaterial']> {
    return this.runtime.clearVolatileWarmSessionMaterial(sessionId);
  }

  rememberAppSessionJwt(
    args: Parameters<EmailOtpThresholdSessionRuntime['rememberAppSessionJwt']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['rememberAppSessionJwt']> {
    return this.runtime.rememberAppSessionJwt(args);
  }

  resolveAppSessionJwt(
    args: Parameters<EmailOtpThresholdSessionRuntime['resolveAppSessionJwt']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['resolveAppSessionJwt']> {
    return this.runtime.resolveAppSessionJwt(args);
  }

  isEd25519WarmupPending(
    args: Parameters<EmailOtpThresholdSessionRuntime['isEd25519WarmupPending']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['isEd25519WarmupPending']> {
    return this.runtime.isEd25519WarmupPending(args);
  }

  waitForPendingEd25519Warmup(
    args: Parameters<EmailOtpThresholdSessionRuntime['waitForPendingEd25519Warmup']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['waitForPendingEd25519Warmup']> {
    return this.runtime.waitForPendingEd25519Warmup(args);
  }

  async requestTransactionSigningChallenge(
    args: Parameters<EmailOtpThresholdSessionRuntime['requestTransactionSigningChallenge']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['requestTransactionSigningChallenge']> {
    return await this.runtime.requestTransactionSigningChallenge(args);
  }

  async requestExportChallenge(
    args: Parameters<EmailOtpThresholdSessionRuntime['requestExportChallenge']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['requestExportChallenge']> {
    return await this.runtime.requestExportChallenge(args);
  }

  recoverEd25519ExportPrfFirst(
    args: Parameters<EmailOtpThresholdSessionRuntime['recoverEd25519ExportPrfFirst']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['recoverEd25519ExportPrfFirst']> {
    return this.runtime.recoverEd25519ExportPrfFirst(args);
  }

  exportEcdsaKeyWithAuthorization(
    args: Parameters<EmailOtpThresholdSessionRuntime['exportEcdsaKeyWithAuthorization']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['exportEcdsaKeyWithAuthorization']> {
    return this.runtime.exportEcdsaKeyWithAuthorization(args);
  }

  exportEcdsaKeyWithFreshEmailOtpLane(
    args: Parameters<EmailOtpThresholdSessionRuntime['exportEcdsaKeyWithFreshEmailOtpLane']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['exportEcdsaKeyWithFreshEmailOtpLane']> {
    return this.runtime.exportEcdsaKeyWithFreshEmailOtpLane(args);
  }

  loginWithEcdsaCapabilityForSigning(
    args: Parameters<EmailOtpThresholdSessionRuntime['loginWithEcdsaCapabilityForSigning']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['loginWithEcdsaCapabilityForSigning']> {
    return this.runtime.loginWithEcdsaCapabilityForSigning(args);
  }

  loginWithEcdsaCapabilityInternal(
    args: Parameters<EmailOtpThresholdSessionRuntime['loginWithEcdsaCapabilityInternal']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['loginWithEcdsaCapabilityInternal']> {
    return this.runtime.loginWithEcdsaCapabilityInternal(args);
  }

  enrollAndLoginWithEcdsaCapabilityInternal(
    args: Parameters<EmailOtpThresholdSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['enrollAndLoginWithEcdsaCapabilityInternal']> {
    return this.runtime.enrollAndLoginWithEcdsaCapabilityInternal(args);
  }

  loginWithEd25519CapabilityForSigning(
    args: Parameters<EmailOtpThresholdSessionRuntime['loginWithEd25519CapabilityForSigning']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['loginWithEd25519CapabilityForSigning']> {
    return this.runtime.loginWithEd25519CapabilityForSigning(args);
  }

  reconstructEd25519Session(
    args: Parameters<EmailOtpThresholdSessionRuntime['reconstructEd25519Session']>[0],
  ): ReturnType<EmailOtpThresholdSessionRuntime['reconstructEd25519Session']> {
    return this.runtime.reconstructEd25519Session(args);
  }
}
