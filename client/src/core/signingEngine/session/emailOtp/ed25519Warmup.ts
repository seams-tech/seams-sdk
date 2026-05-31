import type { AccountId } from '@/core/types/accountIds';
import type { SeamsConfigsReadonly } from '@/core/types/seams';
import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import type {
  BuildCurrentSealedSessionRecordInput,
  BuildCurrentSealedSessionRecordBaseInput,
  readExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import {
  authLaneToRouteAuth,
  resolveEmailOtpAuthLane,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpSigningSessionRoutePlan,
  buildFreshEmailOtpRoutePlan,
  type EmailOtpEcdsaBootstrapRouteAuth,
} from './routePlan';
import {
  selectEmailOtpEcdsaRecordForEd25519Signing,
} from './companionSessions';
import {
  EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
  reconstructEmailOtpEd25519Session,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';

function emailOtpEcdsaBootstrapRouteAuthFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EmailOtpEcdsaBootstrapRouteAuth {
  const jwt = String(record.thresholdSessionAuthToken || '').trim();
  const lane = resolveEmailOtpAuthLane({
    routeAuth: jwt ? { kind: 'threshold_session', jwt } : undefined,
    thresholdSessionId: record.thresholdSessionId,
    authorizingWalletSigningSessionId: record.walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
  });
  if (!lane || lane.kind !== 'signing_session' || lane.curve !== 'ecdsa') {
    throw new Error('Email OTP Ed25519 signing requires companion ECDSA session auth');
  }
  return {
    kind: 'threshold_ecdsa_session',
    jwt: lane.jwt,
    curve: 'ecdsa',
    thresholdSessionId: lane.thresholdSessionId,
    walletSigningSessionId: lane.authorizingWalletSigningSessionId,
    chainTarget: lane.chainTarget,
  };
}

export type EmailOtpEd25519WarmupPorts = {
  configs: SeamsConfigsReadonly;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (
    args: PersistWarmSessionEd25519CapabilityArgs,
  ) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: WarmSessionSealTransportInput;
  }) => Promise<void>;
  readExactSealedSession: typeof readExactSealedSession;
  getThresholdEcdsaSessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEcdsaSessionRecord | null;
  getThresholdEd25519SessionRecordByThresholdSessionId: (
    thresholdSessionId: string,
  ) => ThresholdEd25519SessionRecord | null;
  registerSigningSession: (
    record: BuildCurrentSealedSessionRecordInput,
  ) => Promise<void>;
  requireRelayUrl: () => string;
  resolveAppSessionJwt: (args: {
    walletSession: WalletSessionRef;
    relayUrl: string;
  }) => Promise<string>;
  listThresholdEcdsaSessionRecordsForWallet?: typeof listStoredThresholdEcdsaSessionRecordsForWallet;
  loginWithEcdsaCapabilityInternal: (
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ) => Promise<EmailOtpThresholdEcdsaLoginResult>;
};

export class EmailOtpEd25519Warmup {
  constructor(private readonly ports: EmailOtpEd25519WarmupPorts) {}

  isPending(_args: { nearAccountId: AccountId }): boolean {
    return false;
  }

  async waitForPending(_args: { nearAccountId: AccountId }): Promise<boolean> {
    return false;
  }

  async reconstructSession(
    args: ReconstructEmailOtpEd25519SessionArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    return await reconstructEmailOtpEd25519Session({
      input: args,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      persistWarmSessionEd25519Capability: this.ports.persistWarmSessionEd25519Capability,
      hydrateSigningSession: this.ports.hydrateSigningSession,
      sessionPersistenceMode: this.ports.configs.signing.sessionPersistenceMode,
      readExactSealedSession: this.ports.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: (record) => this.ports.registerSigningSession(record),
    });
  }

  async loginForSigning(args: {
    nearAccountId: AccountId;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
    remainingUses?: number;
  }): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
    const nearAccountId = args.nearAccountId;
    const relayUrl = String(args.record.relayerUrl || this.ports.requireRelayUrl()).trim();
    const providedAuthLane = args.authLane;
    const providedRouteAuth = providedAuthLane
      ? authLaneToRouteAuth(providedAuthLane)
      : args.routeAuth;
    const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    const routePlan =
      providedAuthLane || providedRouteAuth
        ? buildEmailOtpSigningSessionRoutePlan({
            authLane: assertEmailOtpSigningSessionAuthLane(
              providedAuthLane?.kind === 'signing_session'
                ? providedAuthLane
                : resolveEmailOtpAuthLane({
                    routeAuth: providedRouteAuth,
                    thresholdSessionId: args.record.thresholdSessionId,
                    authorizingWalletSigningSessionId: args.record.walletSigningSessionId,
                    curve: 'ed25519',
                  }),
            ),
            operation,
          })
        : buildFreshEmailOtpRoutePlan({
            freshRouteFamily: 'login',
            authLane:
              resolveEmailOtpAuthLane({
                appSessionJwt: await this.ports.resolveAppSessionJwt({
                  walletSession: walletSessionRefFromSession({
                    walletId: nearAccountId,
                    walletSessionUserId: nearAccountId,
                  }),
                  relayUrl,
                }),
                sessionKind: 'jwt',
              }) || (() => {
                throw new Error('Email OTP login requires route auth');
              })(),
            operation,
          });
    const defaultRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
    const ecdsaRecord = selectEmailOtpEcdsaRecordForEd25519Signing({
      walletId: toWalletId(nearAccountId),
      walletSigningSessionFilter: args.record.walletSigningSessionId,
      listThresholdEcdsaSessionRecordsForWallet:
        this.ports.listThresholdEcdsaSessionRecordsForWallet,
    });
    if (!ecdsaRecord) {
      throw new Error(
        'Email OTP Ed25519 signing requires an exact concrete ECDSA bootstrap lane',
      );
    }
    const ecdsaBootstrapRouteAuth = emailOtpEcdsaBootstrapRouteAuthFromRecord(ecdsaRecord);
    const ecdsaLogin = await this.ports.loginWithEcdsaCapabilityInternal({
      walletSession: walletSessionRefFromSession({
        walletId: nearAccountId,
        walletSessionUserId: nearAccountId,
      }),
      relayUrl,
      chainTarget: ecdsaRecord.chainTarget,
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      participantIds: ecdsaRecord.participantIds || args.record.participantIds,
      sessionKind: args.record.thresholdSessionKind,
      routePlan,
      ecdsaBootstrapAuthorization: {
        kind: 'explicit_route_auth',
        routeAuth: ecdsaBootstrapRouteAuth,
      },
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      remainingUses: defaultRemainingUses,
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: args.record.runtimePolicyScope
        ? {
            kind: 'reconstruct',
            ed25519Key: {
              relayerKeyId: args.record.relayerKeyId,
              keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
              participantIds: args.record.participantIds,
            },
            runtimePolicyScope: args.record.runtimePolicyScope,
          }
        : {
            kind: 'defer',
            reason: 'missing_runtime_policy_scope',
            ed25519Key: {
              relayerKeyId: args.record.relayerKeyId,
              keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
              participantIds: args.record.participantIds,
            },
          },
    });
    if (ecdsaLogin.ed25519Reconstruction.kind !== 'completed') {
      throw new Error('Email OTP Ed25519 signing did not provision an Ed25519 signing session');
    }
    const provisioned = ecdsaLogin.ed25519Reconstruction.sessionMaterial;
    const refreshedRecord = this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(
      provisioned.sessionId,
    );
    return {
      sessionId: provisioned.sessionId,
      ...(refreshedRecord ? { record: refreshedRecord } : {}),
    };
  }

}
