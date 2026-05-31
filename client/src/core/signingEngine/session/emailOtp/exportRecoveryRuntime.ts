import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type { VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
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

export type { EmailOtpEcdsaExportArtifact, EmailOtpEd25519ExportArtifact } from './exportRecovery';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
export type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;

export type RequestEmailOtpChallengeArgs =
  | {
      kind: 'wallet_session_challenge';
      walletSession: WalletSessionRef;
      chain: EmailOtpRouteChain;
      routeAuth?: AppOrThresholdSessionAuth;
      authLane?: EmailOtpAuthLane;
    }
  | {
      kind: 'near_account_challenge';
      nearAccountId: AccountId;
      chain: EmailOtpRouteChain;
      routeAuth?: AppOrThresholdSessionAuth;
      authLane?: EmailOtpAuthLane;
      walletSession?: never;
    };

export type ExportEd25519SeedWithAuthorizationArgs = {
  nearAccountId: AccountId;
  challengeId: string;
  otpCode: string;
  record: ThresholdEd25519SessionRecord;
  signingRootId: string;
  keyVersion: string;
  participantIds: number[];
  thresholdSessionId: string;
  thresholdSessionAuthToken: string;
  relayerKeyId: string;
  expectedPublicKey: string;
  routeAuth?: AppOrThresholdSessionAuth;
  authLane?: EmailOtpAuthLane;
};

export type ExportEcdsaKeyWithAuthorizationArgs = {
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  record: ThresholdEcdsaSessionRecord;
  rpId: string;
  routeAuth?: AppOrThresholdSessionAuth;
  authLane?: EmailOtpAuthLane;
};

export type ExportEcdsaKeyWithFreshEmailOtpLaneArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  publicFacts: VerifiedEcdsaPublicFacts;
  authSubjectId?: string;
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
