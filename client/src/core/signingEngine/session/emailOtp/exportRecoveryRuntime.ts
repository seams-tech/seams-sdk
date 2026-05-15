import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
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
  recoverEd25519ExportPrfFirst,
  requestExportChallenge,
  requestTransactionSigningChallenge,
  type EmailOtpEcdsaExportArtifact,
} from './exportRecovery';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';

export type { EmailOtpEcdsaExportArtifact } from './exportRecovery';

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
      nearAccountId: AccountId | string;
      chain: EmailOtpRouteChain;
      routeAuth?: AppOrThresholdSessionAuth;
      authLane?: EmailOtpAuthLane;
      walletSession?: never;
    };

export type RecoverEd25519ExportPrfFirstArgs = {
  nearAccountId: AccountId | string;
  challengeId: string;
  otpCode: string;
  record: ThresholdEd25519SessionRecord;
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
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
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

  async recoverEd25519ExportPrfFirst(
    args: RecoverEd25519ExportPrfFirstArgs,
  ): Promise<{ prfFirstB64u: string }> {
    return await recoverEd25519ExportPrfFirst(this.signingSessionWorkerPorts(), args);
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
