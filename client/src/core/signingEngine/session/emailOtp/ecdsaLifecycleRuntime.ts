import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpRuntimeConfig } from './runtimeConfig';
import type { EmailOtpEcdsaPublicationPorts } from './ecdsaPublication';
import {
  loginWithEmailOtpEcdsaCapability,
  loginWithEmailOtpEcdsaCapabilityForSigning,
  type EmailOtpThresholdEcdsaLoginResult,
  type LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import {
  enrollAndLoginWithEmailOtpEcdsaCapability,
  type EmailOtpThresholdEcdsaEnrollmentResult,
  type EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaEnrollment';
import type {
  EmailOtpThresholdEd25519ProvisioningResult,
  ProvisionEmailOtpThresholdEd25519CapabilityArgs,
} from './provisioning';

export type LoginEmailOtpEcdsaCapabilityForSigningArgs = {
  walletSession: WalletSessionRef;
  subjectId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  record?: ThresholdEcdsaSessionRecord;
  routeAuth?: AppOrThresholdSessionAuth;
  authLane?: EmailOtpAuthLane;
};

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
      resolveAppSessionJwt: (args: {
        walletSession: WalletSessionRef;
        relayUrl: string;
      }) => Promise<string>;
      publicationPorts: () => EmailOtpEcdsaPublicationPorts;
      provisionEd25519Capability: (
        args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
      ) => Promise<EmailOtpThresholdEd25519ProvisioningResult>;
      scheduleEd25519CapabilityProvisioning: (
        args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
      ) => void;
    },
  ) {}

  async loginWithEcdsaCapabilityForSigning(
    args: LoginEmailOtpEcdsaCapabilityForSigningArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    return await loginWithEmailOtpEcdsaCapabilityForSigning(args, {
      requireRelayUrl: () => this.ports.runtimeConfig.requireRelayUrl(),
      resolveAppSessionJwt: (request) => this.ports.resolveAppSessionJwt(request),
      loginWithEcdsaCapabilityInternal: (request) =>
        this.loginWithEcdsaCapabilityInternal(request),
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
      provisionEd25519Capability: (request) =>
        this.ports.provisionEd25519Capability(request),
      scheduleEd25519CapabilityProvisioning: (request) =>
        this.ports.scheduleEd25519CapabilityProvisioning(request),
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
      provisionEd25519Capability: (request) =>
        this.ports.provisionEd25519Capability(request),
    });
  }
}
