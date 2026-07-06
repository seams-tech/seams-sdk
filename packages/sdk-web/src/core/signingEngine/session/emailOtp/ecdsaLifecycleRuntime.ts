import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpRuntimeConfig } from './runtimeConfig';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import {
  loginWithEmailOtpEcdsaCapability,
  loginWithEmailOtpEcdsaCapabilityForSigning,
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
} from './ecdsaLogin';
import {
  enrollAndLoginWithEmailOtpEcdsaCapability,
  type EmailOtpThresholdEcdsaEnrollmentResult,
  type EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
import type {
  EmailOtpThresholdEd25519ProvisioningResult,
  ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  EmailOtpEd25519RecoveryCodeSigningSessionHydration,
} from './recoveryCodeWarmSessionHydration';

export class EmailOtpEcdsaLifecycleRuntime {
  constructor(
    private readonly ports: {
      configs: SeamsConfigsReadonly;
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      runtimeConfig: EmailOtpRuntimeConfig;
      rememberAppSessionJwt: (args: {
        walletSession: WalletSessionRef;
        appSessionJwt?: string;
      }) => void;
      publicationPorts: () => EmailOtpEcdsaPublicationPorts;
      reconstructEd25519Session: (
        args: ReconstructEmailOtpEd25519SessionArgs,
      ) => Promise<EmailOtpThresholdEd25519ProvisioningResult>;
      getThresholdEd25519SessionRecordByThresholdSessionId: (
        thresholdSessionId: string,
      ) => ThresholdEd25519SessionRecord | null;
      recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
    },
  ) {}

  async loginWithEcdsaCapabilityForSigning(
    args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapabilityForSigning(args, {
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      loginWithEcdsaCapabilityInternal: (request) => this.loginWithEcdsaCapabilityInternal(request),
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.ports.runtimeConfig.requireShamirPrimeB64u(),
      requireRpId: (operation) => this.ports.runtimeConfig.requireRpId(operation),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
      reconstructEd25519Session: (request) => this.ports.reconstructEd25519Session(request),
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      recoveryCodeSigningSessionHydration: this.ports.recoveryCodeSigningSessionHydration,
    });
  }

  async enrollAndLoginWithEcdsaCapabilityInternal(
    args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
    return await enrollAndLoginWithEmailOtpEcdsaCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.ports.runtimeConfig.requireShamirPrimeB64u(),
      requireRpId: (operation) => this.ports.runtimeConfig.requireRpId(operation),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
    });
  }
}
