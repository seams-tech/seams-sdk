import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ResolvedWalletCustodyEd25519ExportV1 } from './ed25519ExportContext';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
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
      chain: EmailOtpRouteChain;
      appSessionJwt: string;
      authLane?: never;
      routeAuth?: never;
    };

export type RequestEmailOtpExportChallengeArgs =
  | Exclude<RequestEmailOtpChallengeArgs, { kind: 'wallet_capability_step_up_challenge' }>
  | {
      kind: 'wallet_capability_export_challenge';
      walletSession: WalletSessionRef;
      chain: EmailOtpEcdsaRouteChain;
      appSessionJwt: string;
      authLane?: never;
    };

export type ExportEcdsaKeyWithDurableAuthorizationArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  publicFacts: VerifiedEcdsaPublicFacts;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  authority: EmailOtpWalletAuthAuthority;
  persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  explicitExportAuthorization: EcdsaExplicitExportOperationAuthorization;
};

export type ExportEd25519YaoSeedWithFreshEmailOtpLaneArgs = {
  challengeId: string;
  otpCode: string;
  exportContext: ResolvedWalletCustodyEd25519ExportV1;
};

export class EmailOtpExportRecoveryRuntime {
  constructor(
    private readonly ports: {
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      requireRelayUrl: () => string;
      requireSigningSessionSealGroupId: () => string;
      resolveAppSessionJwtForWallet: (args: {
        walletId: WalletId;
        relayUrl: string;
      }) => Promise<string>;
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
      },
      {
        walletSession: args.walletSession,
        chainTarget: args.chainTarget,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        publicFacts: args.publicFacts,
        runtimePolicyScope: args.runtimePolicyScope,
        authority: args.authority,
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
        requireSigningSessionSealGroupId: this.ports.requireSigningSessionSealGroupId,
        resolveAppSessionJwtForWallet: this.ports.resolveAppSessionJwtForWallet,
      },
      args,
    );
  }

  private workerPorts() {
    return {
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: this.ports.requireRelayUrl,
      requireSigningSessionSealGroupId: this.ports.requireSigningSessionSealGroupId,
      buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
    };
  }

  private signingSessionWorkerPorts() {
    return {
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: this.ports.requireRelayUrl,
      requireSigningSessionSealGroupId: this.ports.requireSigningSessionSealGroupId,
      buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
    };
  }
}
