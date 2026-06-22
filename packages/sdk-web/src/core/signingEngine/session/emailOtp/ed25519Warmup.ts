import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import type {
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  toWalletId,
  walletSessionRefFromSession,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import {
  generateSigningGrantId,
  parseThresholdRuntimePolicyScopeFromJwt,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpWorkerProgressEvent } from '@/core/signingEngine/workerManager/workerTypes';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import {
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  BuildCurrentSealedSessionRecordInput,
  readExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  authLaneToRouteAuth,
  resolveEmailOtpAuthLane,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpSigningSessionRoutePlan,
  buildFreshEmailOtpRoutePlan,
  routeAuthFromEmailOtpRoutePlan,
  type EmailOtpEcdsaBootstrapRouteAuth,
} from './routePlan';
import {
  selectEmailOtpEcdsaRecordForEd25519Signing,
  type EmailOtpEcdsaRecordForEd25519SigningSelectionResult,
} from './companionSessions';
import {
  EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
  reconstructEmailOtpEd25519Session,
  type EmailOtpEd25519SessionReconstructionPlan,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import {
  unlockEmailOtpWalletForEd25519Session,
} from './walletUnlock';
import type {
  EmailOtpEd25519RecoveryCodeSigningSessionHydration,
} from './recoveryCodeWarmSessionHydration';

export type LoginEmailOtpEd25519CapabilityArgs = {
  walletSession: WalletSessionRef;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  routeAuth?: AppOrWalletSessionAuth;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  ed25519SessionReconstruction: Extract<
    EmailOtpEd25519SessionReconstructionPlan,
    { kind: 'reconstruct' }
  >;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

function assertNeverEmailOtpEcdsaRecordSelection(
  selection: never,
): never {
  throw new Error(
    `[EmailOtpSession] unsupported ECDSA companion selection: ${String(
      (selection as { kind?: unknown })?.kind || '',
    )}`,
  );
}

function requireExactEmailOtpEcdsaRecordForEd25519Signing(
  selection: EmailOtpEcdsaRecordForEd25519SigningSelectionResult,
): ThresholdEcdsaSessionRecord {
  switch (selection.kind) {
    case 'exact_match':
      return selection.record;
    case 'ambiguous':
      throw new Error(
        `[EmailOtpSession] Email OTP Ed25519 signing ECDSA bootstrap lane is ambiguous: exact matches=${selection.exactMatchCount}`,
      );
    case 'not_found':
      throw new Error(
        'Email OTP Ed25519 signing requires an exact concrete ECDSA bootstrap lane',
      );
    case 'display_only_fallback':
      throw new Error(
        'Email OTP Ed25519 signing cannot use display-only ECDSA bootstrap lane fallback',
      );
    default:
      return assertNeverEmailOtpEcdsaRecordSelection(selection);
  }
}

function routerAbNormalSigningStateFromConfigs(
  configs: SeamsConfigsReadonly,
): RouterAbEd25519NormalSigningState {
  const normalSigning = configs.signing.routerAb.normalSigning;
  switch (normalSigning.mode) {
    case 'enabled':
      return {
        kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
        signingWorkerId: normalSigning.signingWorkerId,
      };
    case 'disabled':
      throw new Error(
        '[SigningEngine][email-otp] Router A/B normal signing must be enabled for Ed25519 login',
      );
    default: {
      const exhaustive: never = normalSigning;
      throw new Error(
        `[SigningEngine][email-otp] Unsupported Router A/B normal-signing mode: ${String(
          (exhaustive as { mode?: unknown })?.mode || '',
        )}`,
      );
    }
  }
}

function emailOtpEcdsaBootstrapRouteAuthFromRecord(
  record: ThresholdEcdsaSessionRecord,
): EmailOtpEcdsaBootstrapRouteAuth {
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (walletSessionAuth.kind !== 'ready') {
    throw new Error('Email OTP Ed25519 signing requires companion ECDSA Wallet Session auth');
  }
  const jwt = walletSessionAuth.walletSessionJwt;
  const lane = resolveEmailOtpAuthLane({
    routeAuth: jwt ? { kind: 'wallet_session', jwt } : undefined,
    thresholdSessionId: record.thresholdSessionId,
    authorizingSigningGrantId: record.signingGrantId,
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
    signingGrantId: lane.authorizingSigningGrantId,
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
  recoveryCodeSigningSessionHydration: EmailOtpEd25519RecoveryCodeSigningSessionHydration;
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
  requireShamirPrimeB64u: () => string;
  requireRpId: (operation: string) => string;
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
      recoveryCodeSigningSessionHydration: this.ports.recoveryCodeSigningSessionHydration,
      sessionPersistenceMode: this.ports.configs.signing.sessionPersistenceMode,
      readExactSealedSession: this.ports.readExactSealedSession,
      getThresholdEcdsaSessionRecordByThresholdSessionId:
        this.ports.getThresholdEcdsaSessionRecordByThresholdSessionId,
      getThresholdEd25519SessionRecordByThresholdSessionId:
        this.ports.getThresholdEd25519SessionRecordByThresholdSessionId,
      registerSigningSession: (record) => this.ports.registerSigningSession(record),
    });
  }

  async loginWithEd25519CapabilityInternal(
    args: LoginEmailOtpEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    const nearAccountId = toAccountId(args.walletSession.walletId);
    const relayUrl = String(args.relayUrl || this.ports.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(args.shamirPrimeB64u || this.ports.requireShamirPrimeB64u()).trim();
    const rpId = this.ports.requireRpId('Email OTP Ed25519 login');
    const sessionKind = 'jwt';
    const authLane =
      resolveEmailOtpAuthLane({
        routeAuth: args.routeAuth,
        appSessionJwt: args.appSessionJwt,
        sessionKind,
      }) ||
      (() => {
        throw new Error('Email OTP Ed25519 login requires route auth');
      })();
    const routePlan = buildFreshEmailOtpRoutePlan({
      freshRouteFamily: 'login',
      authLane,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
    if (!routeAuth) {
      throw new Error('Email OTP Ed25519 login requires bearer route auth');
    }
    const runtimePolicyScope =
      args.runtimePolicyScope ||
      parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt) ||
      parseThresholdRuntimePolicyScopeFromJwt(routeAuth.jwt);
    if (!runtimePolicyScope) {
      throw new Error('Email OTP Ed25519 login requires runtimePolicyScope');
    }
    const workerCtx = this.ports.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP Ed25519 login requires the dedicated emailOtp worker');
    }
    const workerResult = await unlockEmailOtpWalletForEd25519Session({
      walletSession: args.walletSession,
      relayUrl,
      shamirPrimeB64u,
      otpCode: args.otpCode,
      routePlan,
      workerCtx,
      runtimePolicyScope,
      ...(args.challengeId ? { challengeId: args.challengeId } : {}),
      ...(args.onProgress ? { onProgress: args.onProgress } : {}),
    });
    const recoveryCodeSecret32B64u = String(
      workerResult.recovery.thresholdEd25519RecoveryCodeSecret32B64u || '',
    ).trim();
    if (!recoveryCodeSecret32B64u) {
      throw new Error('Email OTP Ed25519 login did not return recovery-code material');
    }
    const emailOtpAuthContext = {
      policy: args.emailOtpAuthPolicy || this.ports.configs.signing.emailOtp.authPolicy,
      retention: 'session' as const,
      reason: 'login' as const,
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    return await this.reconstructSession({
      kind: 'session_ed25519_reconstruction',
      nearAccountId,
      relayUrl,
      rpId,
      recoveryCodeSecret32B64u,
      emailOtpAuthContext,
      routeAuth,
      runtimePolicyScope,
      routerAbNormalSigning: routerAbNormalSigningStateFromConfigs(this.ports.configs),
      ed25519Key: args.ed25519SessionReconstruction.ed25519Key,
      signingGrantId: generateSigningGrantId(),
      ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
      ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    });
  }

  async loginForSigning(args: {
    nearAccountId: AccountId;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrWalletSessionAuth;
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
                    authorizingSigningGrantId: args.record.signingGrantId,
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
    const signingGrantId = String(args.record.signingGrantId || '').trim();
    if (!signingGrantId) {
      throw new Error('Email OTP Ed25519 signing requires a signing-grant identity');
    }
    const ecdsaRecord = requireExactEmailOtpEcdsaRecordForEd25519Signing(
      selectEmailOtpEcdsaRecordForEd25519Signing({
        kind: 'signing_grant_exact',
        walletId: toWalletId(nearAccountId),
        signingGrantId,
        listThresholdEcdsaSessionRecordsForWallet:
          this.ports.listThresholdEcdsaSessionRecordsForWallet,
      }),
    );
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
      sessionKind: 'jwt',
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
