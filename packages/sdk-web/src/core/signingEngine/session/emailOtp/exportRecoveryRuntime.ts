import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpEd25519YaoActiveCapabilityDescriptorV1 } from '@/core/signingEngine/workerManager/workerTypes';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpEcdsaSigningSessionAuthority } from './ecdsaSigningSessionAuthority';
import { buildEmailOtpSigningSessionRoutePlan } from './routePlan';
import {
  exportEd25519YaoSeedWithFreshEmailOtpLane,
  exportEcdsaKeyWithDurableAuthorization,
  requestExportChallenge,
  requestTransactionSigningChallenge,
  type EmailOtpEcdsaExportArtifact,
} from './exportRecovery';
import type {
  EmailOtpThresholdEcdsaExportPreparation,
  PrepareEmailOtpEcdsaExportCapabilityArgs,
} from './ecdsaLogin';
import type { EmailOtpTransactionSigningChallenge } from './publicTypes';
import type { PersistedEcdsaRoleLocalMaterial } from '../material/ecdsaRoleLocalMaterialResolver';
import type { EcdsaExplicitExportOperationAuthorization } from '../../threshold/ecdsa/activation';
export type { EmailOtpEcdsaExportArtifact } from './exportRecovery';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
export type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;

export type RequestEmailOtpChallengeArgs =
  | {
      kind: 'wallet_session_challenge';
      walletSession: WalletSessionRef;
      chain: EmailOtpRouteChain;
      authLane: EmailOtpSigningSessionAuthLane;
      routeAuth?: never;
    }
  | {
      kind: 'near_account_challenge';
      walletSession: WalletSessionRef;
      nearAccountId: AccountId;
      chain: 'near';
      authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
      routeAuth?: never;
    }
  | {
      kind: 'wallet_capability_step_up_challenge';
      walletSession: WalletSessionRef;
      chain: EmailOtpEcdsaRouteChain;
      appSessionJwt: string;
      authLane?: never;
      routeAuth?: never;
    };

export type RequestEmailOtpExportChallengeArgs = Exclude<
  RequestEmailOtpChallengeArgs,
  { kind: 'wallet_capability_step_up_challenge' }
>;

export type ExportEcdsaKeyWithDurableAuthorizationArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
};

export type ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs = {
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  providerSubjectId: string;
  walletSessionJwt: string;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  signerSlot: number;
  thresholdSessionId: string;
  signingGrantId: string;
  authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
};

export class EmailOtpExportRecoveryRuntime {
  constructor(
    private readonly ports: {
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      requireRelayUrl: () => string;
      requireShamirPrimeB64u: () => string;
      prepareEcdsaExportCapability: (
        args: PrepareEmailOtpEcdsaExportCapabilityArgs,
      ) => Promise<EmailOtpThresholdEcdsaExportPreparation>;
    },
  ) {}

  async requestTransactionSigningChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<EmailOtpTransactionSigningChallenge> {
    return await requestTransactionSigningChallenge(this.workerPorts(), args);
  }

  async requestExportChallenge(
    args: RequestEmailOtpExportChallengeArgs,
  ): Promise<EmailOtpTransactionSigningChallenge> {
    return await requestExportChallenge(this.workerPorts(), args);
  }

  async exportEcdsaKeyWithDurableAuthorization(
    args: ExportEcdsaKeyWithDurableAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await exportEcdsaKeyWithDurableAuthorization(
      {
        getSignerWorkerContext: this.ports.getSignerWorkerContext,
        requireRelayUrl: this.ports.requireRelayUrl,
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
      },
      {
        walletSession: args.walletSession,
        chainTarget: args.chainTarget,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        publicFacts: args.publicFacts,
        runtimePolicyScope: args.runtimePolicyScope,
        signingSessionAuthority: args.signingSessionAuthority,
        persistedMaterial: args.persistedMaterial,
        explicitExportAuthorization: args.explicitExportAuthorization,
        prepareEcdsaExportCapability: this.ports.prepareEcdsaExportCapability,
      },
    );
  }

  async exportEd25519YaoSeedWithFreshEmailOtpLane(
    args: ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs,
  ): Promise<{ artifactKind: 'near-ed25519-seed-v1'; publicKey: string; privateKey: string }> {
    return await exportEd25519YaoSeedWithFreshEmailOtpLane(
      {
        getSignerWorkerContext: this.ports.getSignerWorkerContext,
        requireRelayUrl: this.ports.requireRelayUrl,
        requireShamirPrimeB64u: this.ports.requireShamirPrimeB64u,
        buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
      },
      args,
    );
  }

  private workerPorts() {
    return {
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: this.ports.requireRelayUrl,
      requireShamirPrimeB64u: this.ports.requireShamirPrimeB64u,
      buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
    };
  }

  private signingSessionWorkerPorts() {
    return {
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: this.ports.requireRelayUrl,
      requireShamirPrimeB64u: this.ports.requireShamirPrimeB64u,
      buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
    };
  }
}
