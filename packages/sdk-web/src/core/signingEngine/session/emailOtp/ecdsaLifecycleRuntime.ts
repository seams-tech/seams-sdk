import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpRuntimeConfig } from './runtimeConfig';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';
import type { ThresholdEcdsaActivationRequest } from '../passkey/ecdsaSessionProvision';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  loginWithEmailOtpEcdsaCapability,
  loginWithEmailOtpEcdsaCapabilityForSigning,
  loginWithEmailOtpEcdsaPublicReauthCapabilityForSigning,
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
  type LoginEmailOtpEcdsaPublicReauthCapabilityForSigningArgs,
} from './ecdsaLogin';
import {
  enrollAndLoginWithEmailOtpEcdsaCapability,
  type EmailOtpThresholdEcdsaEnrollmentResult,
  type EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';

export class EmailOtpEcdsaLifecycleRuntime {
  constructor(
    private readonly ports: {
      configs: SeamsConfigsReadonly;
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      provisionThresholdEcdsaSession: (
        request: ThresholdEcdsaActivationRequest,
      ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
      runtimeConfig: EmailOtpRuntimeConfig;
      rememberAppSessionJwt: (args: {
        walletId: WalletSessionRef['walletId'];
        appSessionJwt: string;
      }) => void;
      publicationPorts: () => EmailOtpEcdsaPublicationPorts;
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

  async loginWithEcdsaPublicReauthCapabilityForSigning(
    args: LoginEmailOtpEcdsaPublicReauthCapabilityForSigningArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaPublicReauthCapabilityForSigning(args, {
      loginWithEcdsaCapabilityInternal: (request) => this.loginWithEcdsaCapabilityInternal(request),
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      provisionThresholdEcdsaSession: this.ports.provisionThresholdEcdsaSession,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.ports.runtimeConfig.requireShamirPrimeB64u(),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
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
      provisionThresholdEcdsaSession: this.ports.provisionThresholdEcdsaSession,
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
    });
  }
}
