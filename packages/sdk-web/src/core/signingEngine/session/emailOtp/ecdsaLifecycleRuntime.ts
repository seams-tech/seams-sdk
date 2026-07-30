import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpRuntimeConfig } from './runtimeConfig';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';
import type {
  ThresholdEcdsaActivationRequest,
  ThresholdEcdsaEmailOtpExportActivationRequest,
} from '../passkey/ecdsaSessionProvision';
import type { EmailOtpEcdsaExplicitExportBootstrapResult } from '../passkey/ecdsaBootstrap';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../threshold/ecdsa/activation';
import {
  loginWithEmailOtpEcdsaCapability,
  loginWithEmailOtpEcdsaCapabilityForSigning,
  prepareEmailOtpEcdsaExportCapability,
  type EmailOtpThresholdEcdsaExportPreparation,
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
  type LoginEmailOtpEcdsaCapabilityForSigningArgs,
  type PrepareEmailOtpEcdsaExportCapabilityArgs,
} from './ecdsaLogin';

export class EmailOtpEcdsaLifecycleRuntime {
  constructor(
    private readonly ports: {
      configs: SeamsConfigsReadonly;
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      provisionThresholdEcdsaSession: (
        request: ThresholdEcdsaActivationRequest,
      ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
      provisionEmailOtpEcdsaExplicitExportSession: (
        request: ThresholdEcdsaEmailOtpExportActivationRequest,
      ) => Promise<EmailOtpEcdsaExplicitExportBootstrapResult>;
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

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      provisionThresholdEcdsaSession: this.ports.provisionThresholdEcdsaSession,
      provisionEmailOtpEcdsaExplicitExportSession:
        this.ports.provisionEmailOtpEcdsaExplicitExportSession,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.ports.runtimeConfig.requireShamirPrimeB64u(),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
    });
  }

  async prepareEcdsaExportCapability(
    args: PrepareEmailOtpEcdsaExportCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaExportPreparation> {
    return await prepareEmailOtpEcdsaExportCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      provisionThresholdEcdsaSession: this.ports.provisionThresholdEcdsaSession,
      provisionEmailOtpEcdsaExplicitExportSession:
        this.ports.provisionEmailOtpEcdsaExplicitExportSession,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireShamirPrimeB64u: () => this.ports.runtimeConfig.requireShamirPrimeB64u(),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
    });
  }
}
