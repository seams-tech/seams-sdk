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
} from './routePlan';
import {
  selectEmailOtpEcdsaRecordForEd25519Signing,
} from './companionSessions';
import {
  EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
  reconstructEmailOtpEd25519Session,
  registerEmailOtpEd25519Capability,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
  type RegisterEmailOtpEd25519CapabilityArgs,
} from './provisioning';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';

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
  private warmupByAccount: Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> =
    new Map();

  constructor(private readonly ports: EmailOtpEd25519WarmupPorts) {}

  isPending(args: { nearAccountId: AccountId }): boolean {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    return Boolean(accountId && this.getWarmupMap().has(accountId));
  }

  async waitForPending(args: { nearAccountId: AccountId }): Promise<boolean> {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return false;
    const pending = this.getWarmupMap().get(accountId);
    if (!pending) return false;
    await pending;
    return true;
  }

  scheduleProvisioning(
    args: RegisterEmailOtpEd25519CapabilityArgs,
    options?: {
      provisionCapability?: (
        args: RegisterEmailOtpEd25519CapabilityArgs,
      ) => Promise<EmailOtpThresholdEd25519ProvisioningResult>;
    },
  ): void {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return;
    const warmupMap = this.getWarmupMap();
    if (warmupMap.has(accountId)) return;
    const provisionCapability =
      options?.provisionCapability || ((request) => this.provisionCapability(request));
    const pending = provisionCapability(args);
    warmupMap.set(accountId, pending);
    void pending
      .catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error || 'unknown error');
        console.warn('[email-otp] background threshold-ed25519 warm-up failed', {
          nearAccountId: accountId,
          message,
        });
      })
      .finally(() => {
        const currentWarmupMap = this.getWarmupMap();
        if (currentWarmupMap.get(accountId) === pending) {
          currentWarmupMap.delete(accountId);
        }
      });
  }

  async provisionCapability(
    args: RegisterEmailOtpEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    return await registerEmailOtpEd25519Capability({
      input: args,
      configs: this.ports.configs,
      getSignerWorkerContext: this.ports.getSignerWorkerContext,
      persistEmailOtpThresholdEd25519LocalMetadata:
        this.ports.persistEmailOtpThresholdEd25519LocalMetadata,
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
      participantIds: ecdsaRecord?.participantIds || args.record.participantIds,
      ed25519ParticipantIds: args.record.participantIds,
      sessionKind: args.record.thresholdSessionKind,
      routePlan,
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
          },
    });
    const provisioned = ecdsaLogin.ed25519SessionMaterial;
    if (!provisioned?.sessionId) {
      throw new Error('Email OTP Ed25519 signing did not provision an Ed25519 signing session');
    }
    const refreshedRecord = this.ports.getThresholdEd25519SessionRecordByThresholdSessionId(
      provisioned.sessionId,
    );
    return {
      sessionId: provisioned.sessionId,
      ...(refreshedRecord ? { record: refreshedRecord } : {}),
    };
  }

  private normalizeWarmupAccountId(nearAccountId: AccountId): string {
    return String(nearAccountId || '').trim();
  }

  private getWarmupMap(): Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> {
    if (!(this.warmupByAccount instanceof Map)) {
      this.warmupByAccount = new Map();
    }
    return this.warmupByAccount;
  }
}
