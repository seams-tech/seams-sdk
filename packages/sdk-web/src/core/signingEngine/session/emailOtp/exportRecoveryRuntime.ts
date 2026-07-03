import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  EmailOtpAuthLane,
  EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EcdsaExportLane } from '../../flows/recovery/ecdsaExportMaterial';
import { appSessionJwtFromEmailOtpAuthLane } from './appSessionJwtCache';
import {
  buildEmailOtpSigningSessionRoutePlan,
  buildFreshEmailOtpRoutePlan,
} from './routePlan';
import {
  exportEcdsaKeyWithAuthorization,
  exportEcdsaKeyWithFreshEmailOtpLane,
  exportEd25519SeedWithAuthorization,
  requestExportChallenge,
  requestTransactionSigningChallenge,
  type EmailOtpEcdsaExportArtifact,
  type EmailOtpEd25519ExportArtifact,
} from './exportRecovery';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import type {
  EmailOtpEd25519CommittedSessionRecord,
  RecordBackedEd25519CommittedLane,
} from './ed25519CommittedLane';

export type { EmailOtpEcdsaExportArtifact, EmailOtpEd25519ExportArtifact } from './exportRecovery';

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
      kind: 'wallet_session_fresh_login_challenge';
      walletSession: WalletSessionRef;
      chain: EmailOtpEcdsaRouteChain;
      authLane?: never;
      routeAuth?: never;
    }
	  | {
	      kind: 'near_account_challenge';
	      walletSession: WalletSessionRef;
	      nearAccountId: AccountId;
	      chain: 'near';
	      authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
	      routeAuth?: never;
	    };

export type EmailOtpEd25519ExportSessionRecord = EmailOtpEd25519CommittedSessionRecord & {
  walletSessionJwt: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

export type Ed25519ExportFacts = {
  participantIds: number[];
  relayerKeyId: string;
  expectedPublicKey: string;
};

export type Ed25519ExportLane = RecordBackedEd25519CommittedLane<
  EmailOtpEd25519ExportSessionRecord,
  Ed25519ExportFacts
>;

export type ExportEd25519SeedWithAuthorizationArgs = {
  nearAccountId: AccountId;
  challengeId: string;
  otpCode: string;
  committedLane: Ed25519ExportLane;
  record?: never;
  participantIds?: never;
  thresholdSessionId?: never;
  walletSessionJwt?: never;
  relayerKeyId?: never;
  expectedPublicKey?: never;
  routeAuth?: never;
  authLane?: never;
};

export type ExportEcdsaKeyWithAuthorizationArgs = {
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
  record?: never;
  routeAuth?: never;
  authLane?: never;
};

export type ExportEcdsaKeyWithFreshEmailOtpLaneArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  publicFacts: VerifiedEcdsaPublicFacts;
  providerUserId?: string;
  emailHashHex: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
};

export class EmailOtpExportRecoveryRuntime {
  constructor(
    private readonly ports: {
      getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
      requireRelayUrl: () => string;
      requireShamirPrimeB64u: () => string;
      resolveAppSessionJwt: (args: {
        walletSession: WalletSessionRef;
        relayUrl: string;
      }) => Promise<string>;
      loginWithEcdsaCapabilityInternal: (
        args: LoginEmailOtpEcdsaCapabilityArgs,
      ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
    },
  ) {}

  async requestTransactionSigningChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await requestTransactionSigningChallenge(this.workerPorts(), args);
  }

  async requestExportChallenge(
    args: RequestEmailOtpChallengeArgs,
  ): Promise<{ challengeId: string; emailHint?: string }> {
    return await requestExportChallenge(this.workerPorts(), args);
  }

  async exportEd25519SeedWithAuthorization(
    args: ExportEd25519SeedWithAuthorizationArgs,
  ): Promise<EmailOtpEd25519ExportArtifact> {
    return await exportEd25519SeedWithAuthorization(this.signingSessionWorkerPorts(), args);
  }

  async exportEcdsaKeyWithAuthorization(
    args: ExportEcdsaKeyWithAuthorizationArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await exportEcdsaKeyWithAuthorization(this.signingSessionWorkerPorts(), args);
  }

  async exportEcdsaKeyWithFreshEmailOtpLane(
    args: ExportEcdsaKeyWithFreshEmailOtpLaneArgs,
  ): Promise<EmailOtpEcdsaExportArtifact> {
    return await exportEcdsaKeyWithFreshEmailOtpLane(
      {
        requireRelayUrl: this.ports.requireRelayUrl,
        resolveAppSessionJwt: this.ports.resolveAppSessionJwt,
        buildRoutePlan: buildFreshEmailOtpRoutePlan,
      },
      {
        ...args,
        loginWithEcdsaCapabilityInternal: this.ports.loginWithEcdsaCapabilityInternal,
      },
    );
  }

  private workerPorts() {
    return {
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      requireRelayUrl: this.ports.requireRelayUrl,
      requireShamirPrimeB64u: this.ports.requireShamirPrimeB64u,
      resolveAppSessionJwt: this.ports.resolveAppSessionJwt,
      buildRoutePlan: buildFreshEmailOtpRoutePlan,
      buildSigningSessionRoutePlan: buildEmailOtpSigningSessionRoutePlan,
      appSessionJwtFromLane: appSessionJwtFromEmailOtpAuthLane,
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
