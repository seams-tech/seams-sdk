import type { AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, SeamsConfigsReadonly } from '@/core/types/seams';
import type {
  listStoredThresholdEcdsaSessionRecordsForWallet,
  ThresholdEcdsaSessionRecord,
  ThresholdEd25519SessionRecord,
} from '@/core/signingEngine/session/persistence/records';
import { thresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/persistence/records';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpAuthContextForWalletAuthMethod,
  emailOtpAuthContextEmailHashHex,
} from '../identity/laneIdentity';
import {
  ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import type {
  BuildCurrentSealedSessionRecordInput,
  readExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import type { PersistWarmSessionEd25519CapabilityArgs } from '../warmCapabilities/persistence';
import {
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import { appSessionSubjectFromEmailOtpAuthLane } from './appSessionJwtCache';
import {
  assertEmailOtpSigningSessionAuthLane,
  buildEmailOtpSigningSessionRoutePlan,
  routeAuthFromEmailOtpRoutePlan,
  type EmailOtpEcdsaBootstrapRouteAuth,
} from './routePlan';
import {
  selectEmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionLaneForEd25519Signing,
  type EmailOtpEcdsaCompanionSelectionResult,
} from './companionSessions';
import {
  EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
  reconstructEmailOtpEd25519Session,
  type EmailOtpEd25519SessionReconstructionKey,
  type EmailOtpEd25519SessionReconstructionPlan,
  type EmailOtpThresholdEd25519ProvisioningResult,
  type ReconstructEmailOtpEd25519SessionArgs,
} from './provisioning';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import { emailOtpEcdsaProviderIdentityFromRecord } from './ecdsaLogin';
import { unlockEmailOtpWalletForEd25519Session } from './walletUnlock';
import type { EmailOtpEd25519RecoveryCodeSigningSessionHydration } from './recoveryCodeWarmSessionHydration';
import {
  buildNearEd25519SignerBinding,
  nearAccountBindingFromRaw,
} from '@shared/utils/walletCapabilityBindings';
import type {
  EmailOtpEd25519CommittedSessionRecord,
  RecordBackedEd25519CommittedLane,
} from './ed25519CommittedLane';
import type { EmailOtpEd25519SigningSessionAuthority } from './ed25519SigningSessionAuthority';
import { walletAuthAuthoritiesMatch } from '@shared/utils/walletAuthAuthority';

export type LoginEmailOtpEd25519CapabilityArgs = {
  walletSession: WalletSessionRef;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: never;
  routeAuth?: never;
  sessionKind?: never;
  routePlan: EmailOtpRoutePlan;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  ttlMs?: number;
  remainingUses?: number;
  emailOtpAuthorityEmail?: string;
  emailHashHex: string;
  ed25519SessionReconstruction: Extract<
    EmailOtpEd25519SessionReconstructionPlan,
    { kind: 'reconstruct' }
  >;
  onProgress?: (progress: EmailOtpWorkerProgressEvent) => void;
};

export type Ed25519SigningSessionRecord = EmailOtpEd25519CommittedSessionRecord;

export type Ed25519SigningLane = RecordBackedEd25519CommittedLane<Ed25519SigningSessionRecord>;

export function buildEd25519SigningLane(args: {
  record: ThresholdEd25519SessionRecord;
  authority: EmailOtpEd25519SigningSessionAuthority;
}): Ed25519SigningLane {
  if (args.record.source !== 'email_otp') {
    throw new Error('Email OTP Ed25519 signing committed lane requires Email OTP record');
  }
  const emailOtpAuthContext = args.record.emailOtpAuthContext;
  if (!emailOtpAuthContext) {
    throw new Error('Email OTP Ed25519 signing committed lane requires bound Email OTP authority');
  }
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const signingGrantId = String(args.record.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error('Email OTP Ed25519 signing committed lane requires session identity');
  }
  if (!walletAuthAuthoritiesMatch(emailOtpAuthContext.authority, args.authority.authority)) {
    throw new Error('Email OTP Ed25519 signing committed lane authority drifted');
  }
  if (
    args.authority.authLane.thresholdSessionId !== thresholdSessionId ||
    args.authority.authLane.authorizingSigningGrantId !== signingGrantId
  ) {
    throw new Error('Email OTP Ed25519 signing committed lane authority drifted');
  }
  return {
    source: 'record_backed',
    record: {
      ...args.record,
      source: 'email_otp',
      signingGrantId,
      emailOtpAuthContext,
    },
    authority: args.authority.authority,
    authLane: args.authority.authLane,
    walletSessionAuthority: {
      kind: 'wallet_session_authority',
      walletSessionJwt: args.authority.authLane.jwt,
      thresholdSessionId,
      signingGrantId,
    },
  };
}

function assertNeverEmailOtpEcdsaCompanionSelection(selection: never): never {
  throw new Error(
    `[EmailOtpSession] unsupported ECDSA companion selection: ${String(
      (selection as { kind?: unknown })?.kind || '',
    )}`,
  );
}

function requireEmailOtpEcdsaCompanionLaneForEd25519Signing(
  selection: EmailOtpEcdsaCompanionSelectionResult,
): EmailOtpEcdsaCompanionLaneForEd25519Signing {
  switch (selection.kind) {
    case 'ready':
      switch (selection.companion.kind) {
        case 'single_companion_lane':
          return selection.companion.lane;
        case 'chain_distinct_companion_lanes':
          return selection.companion.primaryLane;
      }
      selection.companion satisfies never;
      throw new Error('[EmailOtpSession] unsupported ready ECDSA companion selection');
    case 'duplicate_chain_lanes':
      throw new Error(
        `[EmailOtpSession] Email OTP Ed25519 signing ECDSA bootstrap lane has duplicate chain records: chain=${selection.chainTargetKey}, count=${selection.count}`,
      );
    case 'not_found':
      throw new Error('Email OTP Ed25519 signing requires an exact concrete ECDSA bootstrap lane');
    case 'display_only_fallback':
      throw new Error(
        'Email OTP Ed25519 signing cannot use display-only ECDSA bootstrap lane fallback',
      );
    default:
      return assertNeverEmailOtpEcdsaCompanionSelection(selection);
  }
}

function emailOtpProviderUserIdForEd25519Login(args: {
  routePlan: EmailOtpRoutePlan;
  walletSession: WalletSessionRef;
}): string {
  const providerUserId = String(
    appSessionSubjectFromEmailOtpAuthLane(args.routePlan.authLane) ||
      args.walletSession.walletSessionUserId ||
      '',
  ).trim();
  if (!providerUserId) {
    throw new Error('Email OTP Ed25519 login requires providerUserId');
  }
  return providerUserId;
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

function ed25519ReconstructionKeyFromRecord(
  record: ThresholdEd25519SessionRecord,
): EmailOtpEd25519SessionReconstructionKey {
  const nearAccountId = String(record.nearAccountId || '').trim();
  const signerSlot = Number(record.signerSlot);
  if (!Number.isSafeInteger(signerSlot) || signerSlot < 0) {
    throw new Error('Email OTP Ed25519 reconstruction requires signerSlot');
  }
  const account = nearAccountBindingFromRaw({
    kind:
      nearAccountId.length === 64 && /^[0-9a-f]+$/i.test(nearAccountId)
        ? 'implicit_near_account'
        : 'named_near_account',
    wallet: { walletId: record.walletId },
    nearAccountId,
  });
  if (!account.ok) {
    throw new Error(account.error.message);
  }
  return {
    signer: buildNearEd25519SignerBinding({
      account: account.value,
      nearEd25519SigningKeyId: record.nearEd25519SigningKeyId,
      signerSlot,
    }),
    relayerKeyId: record.relayerKeyId,
    keyVersion: EMAIL_OTP_THRESHOLD_ED25519_HSS_KEY_VERSION,
    participantIds: record.participantIds,
  };
}

function emailOtpEcdsaBootstrapRouteAuthFromCompanionLane(
  companionLane: EmailOtpEcdsaCompanionLaneForEd25519Signing,
): EmailOtpEcdsaBootstrapRouteAuth {
  const authLane = companionLane.committedLane.authLane;
  if (authLane.kind !== 'signing_session' || authLane.curve !== 'ecdsa') {
    throw new Error('Email OTP Ed25519 signing requires companion ECDSA session auth');
  }
  return {
    kind: 'threshold_ecdsa_session',
    jwt: authLane.jwt,
    curve: 'ecdsa',
    thresholdSessionId: authLane.thresholdSessionId,
    signingGrantId: authLane.authorizingSigningGrantId,
    chainTarget: authLane.chainTarget,
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
  registerSigningSession: (record: BuildCurrentSealedSessionRecordInput) => Promise<void>;
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
    const relayUrl = String(args.relayUrl || this.ports.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(
      args.shamirPrimeB64u || this.ports.requireShamirPrimeB64u(),
    ).trim();
    const rpId = this.ports.requireRpId('Email OTP Ed25519 login');
    const routePlan = args.routePlan;
    const routeAuth = routeAuthFromEmailOtpRoutePlan(routePlan);
    if (!routeAuth) {
      throw new Error('Email OTP Ed25519 login requires bearer route auth');
    }
    const runtimePolicyScope =
      args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(routeAuth.jwt);
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
    const emailOtpAuthContext = buildEmailOtpAuthContextForWalletAuthMethod({
      policy: args.emailOtpAuthPolicy || this.ports.configs.signing.emailOtp.authPolicy,
      walletId: args.walletSession.walletId,
      emailHashHex: args.emailHashHex,
      retention: 'session',
      reason: 'login',
      provider: 'google',
      providerUserId: emailOtpProviderUserIdForEd25519Login({
        routePlan,
        walletSession: args.walletSession,
      }),
    });
    return await this.reconstructSession({
      kind: 'session_ed25519_reconstruction',
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
    committedLane: Ed25519SigningLane;
    record?: never;
    routeAuth?: never;
    authLane?: never;
    remainingUses?: number;
  }): Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }> {
    const nearAccountId = args.nearAccountId;
    const record = args.committedLane.record;
    const relayUrl = String(record.relayerUrl || this.ports.requireRelayUrl()).trim();
    const operation = WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
    const walletIdRaw = String(record.walletId || '').trim();
    if (!walletIdRaw) {
      throw new Error('Email OTP Ed25519 signing requires wallet identity');
    }
    const walletId = toWalletId(walletIdRaw);
    const routePlan = buildEmailOtpSigningSessionRoutePlan({
      authLane: assertEmailOtpSigningSessionAuthLane(args.committedLane.authLane),
      operation,
    });
    const defaultRemainingUses = Math.max(1, Math.floor(Number(args.remainingUses) || 1));
    const signingGrantId = String(record.signingGrantId || '').trim();
    if (!signingGrantId) {
      throw new Error('Email OTP Ed25519 signing requires a signing-grant identity');
    }
    const ecdsaCompanionLane = requireEmailOtpEcdsaCompanionLaneForEd25519Signing(
      selectEmailOtpEcdsaCompanionLaneForEd25519Signing({
        kind: 'signing_grant_exact',
        walletId,
        signingGrantId,
        listThresholdEcdsaSessionRecordsForWallet:
          this.ports.listThresholdEcdsaSessionRecordsForWallet,
      }),
    );
    const ecdsaBootstrapRouteAuth =
      emailOtpEcdsaBootstrapRouteAuthFromCompanionLane(ecdsaCompanionLane);
    const ecdsaCompanionRecord = ecdsaCompanionLane.committedLane.record;
    if (ecdsaCompanionRecord.source !== 'email_otp') {
      throw new Error('Email OTP Ed25519 warm-up requires an Email OTP ECDSA companion record');
    }
    const ecdsaCompanionAuthContext = thresholdEcdsaEmailOtpAuthContext(ecdsaCompanionRecord);
    if (!ecdsaCompanionAuthContext) {
      throw new Error('Email OTP Ed25519 warm-up requires Email OTP ECDSA auth context');
    }
    const ecdsaLogin = await this.ports.loginWithEcdsaCapabilityInternal({
      walletSession: walletSessionRefFromSession({
        walletId,
        walletSessionUserId: walletId,
      }),
      relayUrl,
      chainTarget: ecdsaCompanionRecord.chainTarget,
      emailOtpAuthPolicy: 'per_operation',
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation,
      participantIds: ecdsaCompanionRecord.participantIds || record.participantIds,
      routePlan,
      ecdsaBootstrapAuthorization: {
        kind: 'explicit_route_auth',
        routeAuth: ecdsaBootstrapRouteAuth,
      },
      emailHashHex: emailOtpAuthContextEmailHashHex(ecdsaCompanionAuthContext),
      providerIdentity: emailOtpEcdsaProviderIdentityFromRecord(ecdsaCompanionRecord),
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
      remainingUses: defaultRemainingUses,
      ed25519ReconstructionMode: 'await',
      ed25519SessionReconstruction: record.runtimePolicyScope
        ? {
            kind: 'reconstruct',
            ed25519Key: ed25519ReconstructionKeyFromRecord(record),
            runtimePolicyScope: record.runtimePolicyScope,
          }
        : {
            kind: 'defer',
            reason: 'missing_runtime_policy_scope',
            ed25519Key: ed25519ReconstructionKeyFromRecord(record),
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
