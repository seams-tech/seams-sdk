import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpRuntimeConfig } from './runtimeConfig';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';
import type { EmailOtpWalletSessionCoordinatorDeps } from './ports';
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
      loadWalletCustodyEd25519Material: EmailOtpWalletSessionCoordinatorDeps['loadWalletCustodyEd25519Material'];
      provisionThresholdEcdsaSession: (
        request: ThresholdEcdsaActivationRequest,
      ) => Promise<ThresholdEcdsaSessionBootstrapResult>;
      provisionEmailOtpEcdsaExplicitExportSession: (
        request: ThresholdEcdsaEmailOtpExportActivationRequest,
      ) => Promise<EmailOtpEcdsaExplicitExportBootstrapResult>;
      runtimeConfig: EmailOtpRuntimeConfig;
      resolveCurrentEcdsaCapabilityRuntime: EmailOtpWalletSessionCoordinatorDeps['resolveCurrentEcdsaCapabilityRuntime'];
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
      resolveCurrentEcdsaCapabilityRuntime: this.ports.resolveCurrentEcdsaCapabilityRuntime,
      loginWithEcdsaCapabilityInternal: (request) => this.loginWithEcdsaCapabilityInternal(request),
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapability(args, {
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      loadWalletCustodyEd25519Material: this.ports.loadWalletCustodyEd25519Material,
      provisionThresholdEcdsaSession: this.ports.provisionThresholdEcdsaSession,
      provisionEmailOtpEcdsaExplicitExportSession:
        this.ports.provisionEmailOtpEcdsaExplicitExportSession,
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      requireSigningSessionSealGroupId: () =>
        this.ports.runtimeConfig.requireSigningSessionSealGroupId(),
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
      requireSigningSessionSealGroupId: () =>
        this.ports.runtimeConfig.requireSigningSessionSealGroupId(),
      rememberAppSessionJwt: (request) => this.ports.rememberAppSessionJwt(request),
      publicationPorts: this.ports.publicationPorts(),
    });
  }
}
