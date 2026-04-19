import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy, TatchiConfigsReadonly } from '@/core/types/tatchi';
import type { TouchIdPrompt } from '@/core/signingEngine/signers/webauthn/prompt/touchIdPrompt';
import type { SignerWorkerManager } from '@/core/signingEngine/workerManager';
import type {
  WarmSessionClaimResult,
  WarmSessionStatusResult,
} from '@/core/signingEngine/touchConfirm/types';
import type {
  ThresholdEd25519SessionRecord,
  ThresholdEcdsaEmailOtpAuthContext,
  ThresholdEcdsaSessionRecord,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '@/core/signingEngine/orchestration/thresholdActivation';
import type { WarmSessionEcdsaCapabilityState } from '@/core/signingEngine/session/warmSessionTypes';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/session/sessionPolicy';
import {
  buildEd25519SessionPolicy,
  generateWalletSigningSessionId,
  normalizeThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/session/sessionPolicy';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import {
  createEmailOtpWalletAuthAdapter,
  createPasskeyWalletAuthAdapter,
  createWalletAuthModeResolver,
  WalletAuthPolicyError,
  type WalletAuthCurve,
  type WalletAuthIntent,
} from '@/core/signingEngine/auth';
import {
  UserConfirmationType,
  type UserConfirmDecision,
  type UserConfirmRequest,
} from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import {
  deriveThresholdEd25519HssClientInputsWasm,
  prepareThresholdEd25519HssClientRequestWasm,
} from '@/core/signingEngine/signers/wasm/hssClientSignerWasm';
import { runThresholdEd25519HssCeremonyWithSession as runThresholdEd25519HssCeremonyWithSessionValue } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle';
import {
  THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
  THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
} from '@/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import { isAppSessionJwt, isSessionJwtUnexpired } from '@shared/utils/sessionTokens';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpChannel,
  type WalletEmailOtpLoginOperation,
} from '@shared/utils/emailOtpDomain';
import {
  THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
  normalizeThresholdEd25519ParticipantIds,
} from '@shared/threshold/participants';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { SIGNER_AUTH_METHODS } from '@shared/utils/signerDomain';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import type { ThresholdEcdsaSmartAccountBootstrapInput } from '@/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';
import type { EmailOtpEnrollmentResult } from '@/core/TatchiPasskey/emailOtp';

export type EmailOtpSigningOperation = WalletEmailOtpLoginOperation;

export type EmailOtpBootstrapRecovery = {
  loginGrant: string;
  challengeId: string;
  emailOtpKeyVersion: string;
  unlockChallengeId: string;
  unlockChallengeB64u: string;
  unlockPublicKeyB64u: string;
  unlockSignatureB64u: string;
  thresholdEd25519PrfFirstB64u?: string;
};

export type EmailOtpThresholdEcdsaLoginResult = {
  recovery: EmailOtpBootstrapRecovery;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpThresholdEcdsaEnrollmentResult = {
  enrollment: EmailOtpEnrollmentResult;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  warmCapability: WarmSessionEcdsaCapabilityState;
};

export type EmailOtpThresholdEd25519ProvisioningResult = {
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  participantIds: number[];
  jwt: string;
  xClientBaseB64u?: string;
};

type ManagedRegistrationBootstrapGrant = {
  token: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type RegistrationTransport =
  | { mode: 'managed'; relayerUrl: string; environmentId: string; publishableKey: string }
  | { mode: 'backend_proxy'; bootstrapUrl: string; relayerUrl: string };

function createExportUiRequestId(prefix: string): string {
  const randomPart =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `${prefix}-${randomPart}`;
}

export type ProvisionEmailOtpThresholdEd25519CapabilityArgs = {
  nearAccountId: AccountId | string;
  relayUrl: string;
  rpId: string;
  prfFirstB64u: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
  appSessionJwt?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  registrationAttemptId?: string;
  participantIds?: number[];
  ttlMs?: number;
  remainingUses?: number;
  walletSigningSessionId?: string;
};

export type LoginEmailOtpEcdsaCapabilityArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  emailOtpAuthReason?: 'login' | 'sign';
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  operation?: WalletEmailOtpLoginOperation;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
};

export type EnrollAndLoginEmailOtpEcdsaCapabilityArgs = {
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  thresholdRouteAuth?: AppOrThresholdSessionAuth;
  ecdsaThresholdKeyId?: string;
  participantIds?: number[];
  sessionKind?: 'jwt' | 'cookie';
  sessionId?: string;
  walletSigningSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
  clientSecret32?: Uint8Array;
  otpChannel?: WalletEmailOtpChannel;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  registrationAttemptId?: string;
};

export type EmailOtpThresholdSessionCoordinatorDeps = {
  configs: TatchiConfigsReadonly;
  signerWorkerManager: SignerWorkerManager;
  touchIdPrompt: TouchIdPrompt;
  requestUserConfirmation: (request: UserConfirmRequest) => Promise<UserConfirmDecision>;
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  refreshAppSessionJwt?: (args: { relayUrl: string }) => Promise<string>;
  commitWorkerProvisionedThresholdEcdsaSessions: (args: {
    nearAccountId: AccountId | string;
    primaryChain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: 'email_otp';
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    smartAccount?: ThresholdEcdsaSmartAccountBootstrapInput;
  }) => Promise<{
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    warmCapability: WarmSessionEcdsaCapabilityState;
  }>;
  getThresholdEcdsaKeyRefForSigning: (args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  }) => ThresholdEcdsaSecp256k1KeyRef | Promise<ThresholdEcdsaSecp256k1KeyRef>;
  persistEmailOtpThresholdEd25519LocalMetadata: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    publicKey: string;
    relayerKeyId: string;
    keyVersion: string;
    participantIds: number[];
  }) => Promise<void>;
  persistWarmSessionEd25519Capability: (args: {
    nearAccountId: AccountId;
    rpId: string;
    relayerUrl: string;
    relayerKeyId: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    participantIds: number[];
    sessionKind: 'jwt' | 'cookie';
    sessionId: string;
    walletSigningSessionId?: string;
    expiresAtMs: number;
    remainingUses: number;
    jwt: string;
    emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
    source: 'email_otp';
  }) => unknown | Promise<unknown>;
  hydrateSigningSession: (args: {
    sessionId: string;
    prfFirstB64u: string;
    expiresAtMs: number;
    remainingUses: number;
    transport?: {
      curve?: 'ed25519' | 'ecdsa';
      relayerUrl?: string;
      thresholdSessionJwt?: string;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  }) => Promise<void>;
};

export class EmailOtpThresholdSessionCoordinator {
  private appSessionJwtByAccount: Map<string, string> = new Map();
  private ed25519WarmupByAccount: Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> =
    new Map();

  constructor(private readonly deps: EmailOtpThresholdSessionCoordinatorDeps) {}

  async getWarmSessionStatus(sessionId: string): Promise<WarmSessionStatusResult> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      return await this.deps.signerWorkerManager.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'getEmailOtpWarmSessionStatus',
          timeoutMs: 5_000,
          payload: { sessionId: normalizedSessionId },
        },
      });
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  async claimWarmSessionMaterial(args: {
    sessionId: string;
    uses?: number;
  }): Promise<WarmSessionClaimResult> {
    const normalizedSessionId = String(args.sessionId || '').trim();
    if (!normalizedSessionId) {
      return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
    }
    try {
      return await this.deps.signerWorkerManager.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'claimEmailOtpWarmSessionMaterial',
          timeoutMs: 5_000,
          payload: {
            sessionId: normalizedSessionId,
            ...(typeof args.uses === 'number' ? { uses: args.uses } : {}),
          },
        },
      });
    } catch (error) {
      return {
        ok: false,
        code: 'worker_error',
        message: error instanceof Error ? error.message : String(error || 'Email OTP worker error'),
      };
    }
  }

  async clearWarmSessionMaterial(sessionId: string): Promise<void> {
    const normalizedSessionId = String(sessionId || '').trim();
    if (!normalizedSessionId) return;
    await this.deps.signerWorkerManager
      .requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'clearEmailOtpWarmSessionMaterial',
          timeoutMs: 5_000,
          payload: { sessionId: normalizedSessionId },
        },
      })
      .catch(() => undefined);
  }

  rememberAppSessionJwt(args: { nearAccountId: AccountId | string; appSessionJwt?: string }): void {
    const jwt = String(args.appSessionJwt || '').trim();
    if (!jwt) return;
    if (!isAppSessionJwt(jwt)) return;
    const accountId = String(args.nearAccountId || '').trim();
    if (!accountId) return;
    if (!(this.appSessionJwtByAccount instanceof Map)) {
      this.appSessionJwtByAccount = new Map();
    }
    this.appSessionJwtByAccount.set(accountId, jwt);
  }

  async resolveAppSessionJwt(args: {
    nearAccountId: AccountId | string;
    relayUrl: string;
  }): Promise<string> {
    const accountId = String(args.nearAccountId || '').trim();
    if (!(this.appSessionJwtByAccount instanceof Map)) {
      this.appSessionJwtByAccount = new Map();
    }
    const cached = accountId ? String(this.appSessionJwtByAccount.get(accountId) || '').trim() : '';
    if (cached && isAppSessionJwt(cached) && isSessionJwtUnexpired(cached, { skewMs: 30_000 })) {
      return cached;
    }
    if (accountId) this.appSessionJwtByAccount.delete(accountId);
    const refreshed = this.deps.refreshAppSessionJwt
      ? await this.deps.refreshAppSessionJwt({ relayUrl: args.relayUrl })
      : await this.refreshAppSessionJwt({ relayUrl: args.relayUrl });
    if (accountId && refreshed) {
      this.appSessionJwtByAccount.set(accountId, refreshed);
    }
    return refreshed;
  }

  private async refreshAppSessionJwt(args: { relayUrl: string }): Promise<string> {
    const relayUrl = String(args.relayUrl || '').trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url for Email OTP export session refresh');
    }
    const response = await fetch(joinNormalizedUrl(relayUrl, '/session/refresh'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ session_kind: 'jwt' }),
    });
    const json = (await response.json().catch(() => null)) as Record<string, unknown> | null;
    if (!response.ok || !json || json.ok === false) {
      const message =
        (typeof json?.message === 'string' && json.message.trim()) ||
        `Email OTP export session refresh failed (HTTP ${response.status})`;
      throw new Error(message);
    }
    const jwt = typeof json.jwt === 'string' ? json.jwt.trim() : '';
    if (!jwt) {
      throw new Error('Email OTP export session refresh did not return a JWT');
    }
    return jwt;
  }

  appSessionRouteAuth(appSessionJwt?: string): AppOrThresholdSessionAuth | undefined {
    const jwt = String(appSessionJwt || '').trim();
    return jwt ? { kind: 'app_session', jwt } : undefined;
  }

  resolveAppSessionJwtFromRouteAuth(args: {
    nearAccountId: AccountId | string;
    appSessionJwt?: string;
    thresholdRouteAuth?: AppOrThresholdSessionAuth;
  }): string {
    const jwt = String(
      args.appSessionJwt ||
        (args.thresholdRouteAuth?.kind === 'app_session' &&
        isAppSessionJwt(args.thresholdRouteAuth.jwt)
          ? args.thresholdRouteAuth.jwt
          : ''),
    ).trim();
    this.rememberAppSessionJwt({ nearAccountId: args.nearAccountId, appSessionJwt: jwt });
    return jwt;
  }

  isEd25519WarmupPending(args: { nearAccountId: AccountId | string }): boolean {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    return Boolean(accountId && this.getEd25519WarmupMap().has(accountId));
  }

  async waitForPendingEd25519Warmup(args: { nearAccountId: AccountId | string }): Promise<boolean> {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return false;
    const pending = this.getEd25519WarmupMap().get(accountId);
    if (!pending) return false;
    await pending;
    return true;
  }

  scheduleEd25519CapabilityProvisioning(
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ): void {
    const accountId = this.normalizeWarmupAccountId(args.nearAccountId);
    if (!accountId) return;
    const warmupMap = this.getEd25519WarmupMap();
    if (warmupMap.has(accountId)) return;
    const pending = this.provisionEd25519Capability(args);
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
        const currentWarmupMap = this.getEd25519WarmupMap();
        if (currentWarmupMap.get(accountId) === pending) {
          currentWarmupMap.delete(accountId);
        }
      });
  }

  async requestChallengeForSigning(args: {
    nearAccountId: AccountId | string;
    chain: 'near' | ThresholdEcdsaActivationChain;
    operation?: EmailOtpSigningOperation;
    appSessionJwt?: string;
  }): Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }> {
    void args.chain;
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = this.requireRelayUrl();
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP signing requires the dedicated emailOtp worker');
    }
    const appSessionJwt =
      String(args.appSessionJwt || '').trim() ||
      (await this.resolveAppSessionJwt({
        nearAccountId,
        relayUrl,
      }));
    const response = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'requestEmailOtpChallenge',
        timeoutMs: 30_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          ...(appSessionJwt ? { appSessionJwt } : {}),
          otpChannel: EMAIL_OTP_CHANNEL,
          operation: args.operation || WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        },
      },
    });
    const challengeId = String(response.challengeId || '').trim();
    if (!challengeId) {
      throw new Error('Email OTP signing challenge response did not include challengeId');
    }
    return {
      challengeId,
      ...(String(response.emailHint || '').trim()
        ? { emailHint: String(response.emailHint || '').trim() }
        : {}),
      ...(appSessionJwt ? { appSessionJwt } : {}),
    };
  }

  async requestExportAuthorization(args: {
    nearAccountId: AccountId | string;
    chain: 'near' | ThresholdEcdsaActivationChain;
    publicKey: string;
    curve: WalletAuthCurve;
    appSessionJwt?: string;
  }): Promise<{ challengeId: string; otpCode: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const exportIntent: WalletAuthIntent =
      args.curve === 'ed25519' ? 'ed25519_export' : 'ecdsa_export';
    const requestExportChallenge = async () => {
      const challenge = await this.requestChallengeForSigning({
        nearAccountId,
        chain: args.chain,
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        ...(args.appSessionJwt ? { appSessionJwt: args.appSessionJwt } : {}),
      });
      const challengeId = String(challenge.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('Email OTP export challenge response did not include challengeId');
      }
      return {
        challengeId,
        emailHint: String(challenge.emailHint || '').trim(),
      };
    };
    const resolver = createWalletAuthModeResolver({
      passkey: createPasskeyWalletAuthAdapter({
        challenge: async () => {
          throw new WalletAuthPolicyError({
            code: 'fresh_email_otp_required',
            policy: 'sensitive_operation_requires_fresh_email_otp',
            intent: exportIntent,
            message: 'Email OTP export requires Email OTP authorization',
          });
        },
        complete: async () => {
          throw new WalletAuthPolicyError({
            code: 'fresh_email_otp_required',
            policy: 'sensitive_operation_requires_fresh_email_otp',
            intent: exportIntent,
            message: 'Email OTP export requires Email OTP authorization',
          });
        },
      }),
      emailOtp: createEmailOtpWalletAuthAdapter({
        challenge: async () => {
          const challenge = await requestExportChallenge();
          return {
            challengeId: challenge.challengeId,
            email: challenge.emailHint,
          };
        },
        complete: async ({ challengeId, code }) => ({
          method: 'email_otp',
          emailOtpAuthentication: { challengeId, otpCode: code },
        }),
      }),
    });
    const walletAuthPlan = await resolver.resolveWalletAuthPlan({
      accountId: nearAccountId,
      accountAuth: {
        primaryAuthMethod: 'email_otp',
        linkedAuthMethods: ['email_otp'],
      },
      intent: exportIntent,
      curve: args.curve,
    });
    if (walletAuthPlan.kind !== 'emailOtpReauth') {
      throw new WalletAuthPolicyError({
        code: 'fresh_email_otp_required',
        policy: 'sensitive_operation_requires_fresh_email_otp',
        intent: exportIntent,
        message: 'Email OTP export requires Email OTP authorization',
      });
    }
    const firstChallenge = await walletAuthPlan.challenge();
    let challenge = {
      challengeId: firstChallenge.challengeId,
      ...(firstChallenge.email ? { emailHint: firstChallenge.email } : {}),
    };
    const decision = await this.deps.requestUserConfirmation({
      requestId: createExportUiRequestId(`export-${args.curve}-email-otp-auth`),
      type: UserConfirmationType.SIGN_INTENT_DIGEST,
      summary: {
        operation: 'Export Private Key',
        accountId: nearAccountId,
        publicKey: args.publicKey,
        warning:
          'Enter the email code to export this key. Anyone with the private key can fully control the account.',
      },
      payload: {
        nearAccountId,
        publicKey: args.publicKey,
        challengeB64u: challenge.challengeId,
        signingAuthPlan: {
          kind: 'emailOtpReauth',
          method: 'email_otp',
          emailOtpPrompt: {
            challengeId: challenge.challengeId,
            ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
            title: 'Enter email code to export',
            body: 'This one-time code authorizes private key export only.',
            helperText:
              'Key export is sensitive. The recovered export material is discarded after the viewer closes.',
            onResend: async () => {
              const nextChallenge = await walletAuthPlan.challenge();
              challenge = {
                challengeId: nextChallenge.challengeId,
                ...(nextChallenge.email ? { emailHint: nextChallenge.email } : {}),
              };
              return challenge;
            },
          },
        },
        emailOtpPrompt: {
          challengeId: challenge.challengeId,
          ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
          title: 'Enter email code to export',
          body: 'This one-time code authorizes private key export only.',
          helperText:
            'Key export is sensitive. The recovered export material is discarded after the viewer closes.',
          onResend: async () => {
            challenge = await requestExportChallenge();
            return challenge;
          },
        },
      },
      intentDigest: `export-keys:${nearAccountId}:${args.chain}:${args.curve}:email-otp`,
    });
    if (!decision.confirmed) {
      throw new Error(decision.error || 'User cancelled Email OTP export request');
    }
    const otpCode = String(decision.otpCode || '')
      .replace(/\D/g, '')
      .slice(0, 6);
    if (otpCode.length !== 6) {
      throw new Error('Email OTP export requires a 6-digit code');
    }
    const responseChallengeId = String(
      decision.emailOtpChallengeId || challenge.challengeId,
    ).trim();
    const proof = await walletAuthPlan.complete({
      challengeId: responseChallengeId,
      code: otpCode,
    });
    const authorization = proof.emailOtpAuthentication as {
      challengeId?: string;
      otpCode?: string;
    };
    return {
      challengeId: String(authorization.challengeId || responseChallengeId).trim(),
      otpCode: String(authorization.otpCode || otpCode).trim(),
    };
  }

  async loginWithEcdsaCapabilityForSigning(args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    operation?: EmailOtpSigningOperation;
    appSessionJwt?: string;
  }): Promise<ThresholdEcdsaSecp256k1KeyRef> {
    const record = args.record;
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(record.relayerUrl || this.requireRelayUrl()).trim();
    const existingEmailOtpAuthContext = record.emailOtpAuthContext;
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? 'per_operation'
        : existingEmailOtpAuthContext?.policy || this.deps.configs.signing.emailOtp.authPolicy;
    const remainingUses =
      emailOtpAuthPolicy === 'per_operation'
        ? 1
        : Math.max(
            1,
            Math.floor(Number(record.remainingUses) || 0),
            Math.floor(Number(this.deps.configs.signing.sessionDefaults?.remainingUses) || 0),
          );
    const appSessionJwt =
      String(args.appSessionJwt || '').trim() ||
      (await this.resolveAppSessionJwt({
        nearAccountId,
        relayUrl,
      }));
    const thresholdRouteAuth = this.appSessionRouteAuth(appSessionJwt);
    const isExportOperation = args.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION;
    await this.loginWithEcdsaCapabilityInternal({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
      emailOtpAuthPolicy,
      emailOtpAuthReason: 'sign',
      challengeId: args.challengeId,
      otpCode: args.otpCode,
      operation: args.operation || WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
      participantIds: record.participantIds,
      sessionKind: record.thresholdSessionKind,
      ...(isExportOperation ? {} : { sessionId: record.thresholdSessionId }),
      ...(thresholdRouteAuth ? { thresholdRouteAuth } : {}),
      ...(appSessionJwt ? { appSessionJwt } : {}),
      remainingUses,
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    });
    return this.deps.getThresholdEcdsaKeyRefForSigning({
      nearAccountId: args.nearAccountId,
      chain: args.chain,
    });
  }

  async loginWithEcdsaCapabilityInternal(
    args: LoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaLoginResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.emailOtpAuthPolicy || this.deps.configs.signing.emailOtp.authPolicy;
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy: emailOtpAuthPolicy,
      retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
      reason: args.emailOtpAuthReason || 'login',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    const relayUrl = String(args.relayUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(args.shamirPrimeB64u || this.requireShamirPrimeB64u()).trim();
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerCtx = this.deps.getSignerWorkerContext();
    const thresholdRouteAuth = args.thresholdRouteAuth;
    const sessionKind = args.sessionKind || 'jwt';
    const walletSigningSessionId =
      String(args.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
    const rpId = this.requireRpId('Email OTP login');

    if (!workerCtx) {
      throw new Error('Email OTP login requires the dedicated emailOtp worker');
    }
    if (!thresholdRouteAuth && sessionKind !== 'cookie') {
      throw new Error('Email OTP ECDSA bootstrap requires app-session route auth for JWT sessions');
    }
    if (thresholdRouteAuth && thresholdRouteAuth.kind !== 'app_session') {
      throw new Error('Email OTP ECDSA bootstrap requires app-session route auth');
    }
    const appSessionJwt = this.resolveAppSessionJwtFromRouteAuth({
      nearAccountId,
      appSessionJwt: args.appSessionJwt,
      ...(thresholdRouteAuth ? { thresholdRouteAuth } : {}),
    });
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpAndBootstrapEcdsaSession',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(nearAccountId),
          ...(args.challengeId ? { challengeId: args.challengeId } : {}),
          otpCode: args.otpCode,
          shamirPrimeB64u,
          ...(appSessionJwt ? { appSessionJwt } : {}),
          ...(args.operation ? { operation: args.operation } : {}),
          otpChannel: EMAIL_OTP_CHANNEL,
          rpId,
          ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
          ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
            ? { participantIds: args.participantIds }
            : {}),
          sessionKind,
          ...(args.sessionId ? { sessionId: args.sessionId } : {}),
          walletSigningSessionId,
          ...(thresholdRouteAuth ? { thresholdRouteAuth } : {}),
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        },
      },
    });
    const { bootstrap, warmCapability } =
      await this.deps.commitWorkerProvisionedThresholdEcdsaSessions({
        nearAccountId,
        primaryChain: chain,
        bootstrap: workerResult.bootstrap,
        source: 'email_otp',
        emailOtpAuthContext,
        ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
      });
    const thresholdEd25519PrfFirstB64u = String(
      workerResult.recovery?.thresholdEd25519PrfFirstB64u || '',
    ).trim();
    if (thresholdEd25519PrfFirstB64u) {
      this.scheduleEd25519CapabilityProvisioning({
        nearAccountId,
        relayUrl,
        rpId,
        prfFirstB64u: thresholdEd25519PrfFirstB64u,
        emailOtpAuthContext,
        ...(appSessionJwt ? { appSessionJwt } : {}),
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
        ...(Array.isArray(args.participantIds) ? { participantIds: args.participantIds } : {}),
        ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
        ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
        walletSigningSessionId,
      });
    }
    return {
      recovery: workerResult.recovery,
      bootstrap,
      warmCapability,
    };
  }

  async enrollAndLoginWithEcdsaCapabilityInternal(
    args: EnrollAndLoginEmailOtpEcdsaCapabilityArgs,
  ): Promise<EmailOtpThresholdEcdsaEnrollmentResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const chain: ThresholdEcdsaActivationChain = args.chain || 'tempo';
    const emailOtpAuthPolicy: EmailOtpAuthPolicy =
      args.emailOtpAuthPolicy || this.deps.configs.signing.emailOtp.authPolicy;
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy: emailOtpAuthPolicy,
      retention: emailOtpAuthPolicy === 'per_operation' ? 'single_use' : 'session',
      reason: 'login',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    const relayUrl = String(args.relayUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = String(args.shamirPrimeB64u || this.requireShamirPrimeB64u()).trim();
    const thresholdRouteAuth = args.thresholdRouteAuth;
    const sessionKind = args.sessionKind || 'jwt';
    const walletSigningSessionId =
      String(args.walletSigningSessionId || '').trim() || generateWalletSigningSessionId();
    if (!thresholdRouteAuth && sessionKind !== 'cookie') {
      throw new Error(
        'Email OTP enrollment login requires threshold route auth for JWT ECDSA bootstrap',
      );
    }
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP enrollment login requires the dedicated emailOtp worker');
    }
    const rpId = this.requireRpId('Email OTP enrollment login');
    const appSessionJwt = this.resolveAppSessionJwtFromRouteAuth({
      nearAccountId,
      appSessionJwt: args.appSessionJwt,
      ...(thresholdRouteAuth ? { thresholdRouteAuth } : {}),
    });
    const remainingUses =
      typeof args.remainingUses === 'number'
        ? args.remainingUses
        : emailOtpAuthPolicy === 'per_operation'
          ? 1
          : undefined;
    const workerClientSecret32 = args.clientSecret32 ? Uint8Array.from(args.clientSecret32) : null;
    try {
      const workerResult = await workerCtx.requestWorkerOperation({
        kind: 'emailOtp',
        request: {
          type: 'enrollEmailOtpWalletAndBootstrapEcdsaSession',
          timeoutMs: 60_000,
          payload: {
            relayUrl,
            walletId: String(nearAccountId),
            userId: String(nearAccountId),
            ...(args.challengeId ? { challengeId: args.challengeId } : {}),
            otpCode: args.otpCode,
            shamirPrimeB64u,
            ...(appSessionJwt ? { appSessionJwt } : {}),
            otpChannel: EMAIL_OTP_CHANNEL,
            ...(workerClientSecret32
              ? { clientSecret32: workerClientSecret32.buffer.slice(0) }
              : {}),
            rpId,
            ...(args.ecdsaThresholdKeyId ? { ecdsaThresholdKeyId: args.ecdsaThresholdKeyId } : {}),
            ...(Array.isArray(args.participantIds) && args.participantIds.length > 0
              ? { participantIds: args.participantIds }
              : {}),
            sessionKind,
            ...(args.sessionId ? { sessionId: args.sessionId } : {}),
            walletSigningSessionId,
            ...(thresholdRouteAuth ? { thresholdRouteAuth } : {}),
            ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
            ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
            ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          },
        },
      });
      const { bootstrap, warmCapability } =
        await this.deps.commitWorkerProvisionedThresholdEcdsaSessions({
          nearAccountId,
          primaryChain: chain,
          bootstrap: workerResult.bootstrap,
          source: 'email_otp',
          emailOtpAuthContext,
          ...(args.smartAccount ? { smartAccount: args.smartAccount } : {}),
        });
      const thresholdEd25519PrfFirstB64u = String(
        workerResult.enrollment?.thresholdEd25519PrfFirstB64u || '',
      ).trim();
      if (thresholdEd25519PrfFirstB64u) {
        await this.provisionEd25519Capability({
          nearAccountId,
          relayUrl,
          rpId,
          prfFirstB64u: thresholdEd25519PrfFirstB64u,
          emailOtpAuthContext,
          ...(appSessionJwt ? { appSessionJwt } : {}),
          ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
          ...(args.registrationAttemptId
            ? { registrationAttemptId: args.registrationAttemptId }
            : {}),
          ...(Array.isArray(args.participantIds) ? { participantIds: args.participantIds } : {}),
          ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
          ...(typeof remainingUses === 'number' ? { remainingUses } : {}),
          walletSigningSessionId,
        });
      }
      return {
        enrollment: workerResult.enrollment,
        bootstrap,
        warmCapability,
      };
    } finally {
      workerClientSecret32?.fill(0);
    }
  }

  async loginWithEd25519CapabilityForSigning(args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    operation?: EmailOtpSigningOperation;
    appSessionJwt?: string;
    remainingUses?: number;
  }): Promise<{ sessionId: string }> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayUrl = String(args.record.relayerUrl || this.requireRelayUrl()).trim();
    const shamirPrimeB64u = this.requireShamirPrimeB64u();
    const rpId =
      String(args.record.rpId || '').trim() ||
      (typeof (this.deps.touchIdPrompt as { getRpId?: unknown } | undefined)?.getRpId === 'function'
        ? String(this.deps.touchIdPrompt.getRpId() || '').trim()
        : '');
    if (!rpId) {
      throw new Error('Email OTP Ed25519 signing requires an RP ID');
    }
    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error('Email OTP Ed25519 signing requires the dedicated emailOtp worker');
    }
    const appSessionJwt =
      String(args.appSessionJwt || '').trim() ||
      (await this.resolveAppSessionJwt({
        nearAccountId,
        relayUrl,
      }));
    this.rememberAppSessionJwt({ nearAccountId, appSessionJwt });
    const workerResult = await workerCtx.requestWorkerOperation({
      kind: 'emailOtp',
      request: {
        type: 'loginWithEmailOtpWallet',
        timeoutMs: 60_000,
        payload: {
          relayUrl,
          walletId: String(nearAccountId),
          userId: String(nearAccountId),
          challengeId: args.challengeId,
          otpCode: args.otpCode,
          operation: args.operation || WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
          shamirPrimeB64u,
          ...(appSessionJwt ? { appSessionJwt } : {}),
          otpChannel: EMAIL_OTP_CHANNEL,
        },
      },
    });
    const prfFirstB64u = String(workerResult.recovery?.thresholdEd25519PrfFirstB64u || '').trim();
    if (!prfFirstB64u) {
      throw new Error('Email OTP Ed25519 signing did not recover client seed material');
    }
    const existingEmailOtpAuthContext = args.record.emailOtpAuthContext;
    const retention = existingEmailOtpAuthContext?.retention || 'single_use';
    const emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext = {
      policy:
        existingEmailOtpAuthContext?.policy ||
        (retention === 'session' ? 'session' : 'per_operation'),
      retention,
      reason: 'sign',
      authMethod: SIGNER_AUTH_METHODS.emailOtp,
    };
    const defaultRemainingUses =
      args.operation === WALLET_EMAIL_OTP_EXPORT_OPERATION
        ? 2
        : retention === 'session'
          ? Math.max(
              2,
              Math.floor(Number(args.remainingUses) || 0),
              Math.floor(Number(args.record.remainingUses) || 0),
              Math.floor(Number(this.deps.configs.signing.sessionDefaults.remainingUses) || 0),
            )
          : Math.max(2, Math.floor(Number(args.remainingUses) || 0));
    const provisioned = await this.provisionEd25519Capability({
      nearAccountId,
      relayUrl,
      rpId,
      prfFirstB64u,
      emailOtpAuthContext,
      ...(appSessionJwt ? { appSessionJwt } : {}),
      ...(args.record.runtimePolicyScope
        ? { runtimePolicyScope: args.record.runtimePolicyScope }
        : {}),
      participantIds: args.record.participantIds,
      remainingUses: defaultRemainingUses,
    });
    return { sessionId: provisioned.sessionId };
  }

  async provisionEd25519Capability(
    args: ProvisionEmailOtpThresholdEd25519CapabilityArgs,
  ): Promise<EmailOtpThresholdEd25519ProvisioningResult> {
    const nearAccountId = toAccountId(args.nearAccountId);
    const relayerUrl = String(args.relayUrl || '').trim();
    const rpId = String(args.rpId || '').trim();
    const prfFirstB64u = String(args.prfFirstB64u || '').trim();
    if (!relayerUrl)
      throw new Error('Email OTP threshold-ed25519 provisioning requires relayerUrl');
    if (!rpId) throw new Error('Email OTP threshold-ed25519 provisioning requires rpId');
    if (!prfFirstB64u) {
      throw new Error('Email OTP threshold-ed25519 provisioning requires client seed material');
    }

    const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds) || [
      ...THRESHOLD_ED25519_2P_PARTICIPANT_IDS,
    ];
    const keyVersion = 'threshold-ed25519-hss-v1';
    const registrationTransport = resolveRegistrationTransportFromConfig({
      configs: this.deps.configs,
      relayerUrl,
    });

    let runtimePolicyScope = args.runtimePolicyScope;
    let managedGrantForNextRegistrationRequest: ManagedRegistrationBootstrapGrant | null = null;
    if (!runtimePolicyScope && registrationTransport.mode === 'managed') {
      managedGrantForNextRegistrationRequest = await requestManagedRegistrationBootstrapGrant({
        relayerUrl: registrationTransport.relayerUrl,
        environmentId: registrationTransport.environmentId,
        publishableKey: registrationTransport.publishableKey,
        nearAccountId: String(nearAccountId),
        rpId,
      });
      runtimePolicyScope = managedGrantForNextRegistrationRequest.runtimePolicyScope;
    }
    const orgId = String(runtimePolicyScope?.orgId || '').trim();
    const signingRootId = runtimePolicyScope
      ? signingRootScopeFromRuntimePolicyScope(runtimePolicyScope).signingRootId
      : '';
    if (!orgId || !signingRootId) {
      throw new Error(
        'Email OTP threshold-ed25519 provisioning requires canonical signing-root scope',
      );
    }

    const workerCtx = this.deps.getSignerWorkerContext();
    if (!workerCtx) {
      throw new Error(
        'Email OTP threshold-ed25519 provisioning requires the dedicated emailOtp worker',
      );
    }
    const context = {
      signingRootId,
      nearAccountId: String(nearAccountId),
      keyPurpose: THRESHOLD_ED25519_HSS_SIGNING_KEY_PURPOSE,
      keyVersion,
      participantIds,
      derivationVersion: THRESHOLD_ED25519_HSS_DERIVATION_VERSION,
    };
    const clientInputs = await deriveThresholdEd25519HssClientInputsWasm({
      sessionId: `email-otp-ed25519-registration:${String(nearAccountId)}`,
      ...context,
      prfFirstB64u,
      workerCtx,
    });

    const registrationHeaders = async (): Promise<Record<string, string>> => {
      if (registrationTransport.mode !== 'managed') return {};
      if (managedGrantForNextRegistrationRequest) {
        const grant = managedGrantForNextRegistrationRequest;
        managedGrantForNextRegistrationRequest = null;
        return { Authorization: `Bearer ${grant.token}` };
      }
      const grant = await requestManagedRegistrationBootstrapGrant({
        relayerUrl: registrationTransport.relayerUrl,
        environmentId: registrationTransport.environmentId,
        publishableKey: registrationTransport.publishableKey,
        nearAccountId: String(nearAccountId),
        rpId,
      });
      return { Authorization: `Bearer ${grant.token}` };
    };
    const registrationUrl = (path: string): string => {
      if (registrationTransport.mode === 'managed') {
        return joinUrlPath(registrationTransport.relayerUrl, path);
      }
      return (
        replaceUrlPathSuffix(registrationTransport.bootstrapUrl, '/registration/bootstrap', path) ||
        joinUrlPath(registrationTransport.bootstrapUrl || registrationTransport.relayerUrl, path)
      );
    };

    const prepared = await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/prepare'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration prepare',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        context,
      },
    });
    const ceremonyHandle = String(prepared.ceremonyHandle || '').trim();
    const preparedSession = prepared.preparedSession as {
      contextBindingB64u?: string;
      evaluatorDriverStateB64u?: string;
    };
    const clientOtOfferMessageB64u = String(prepared.clientOtOfferMessageB64u || '').trim();
    if (!ceremonyHandle || !preparedSession || !clientOtOfferMessageB64u) {
      throw new Error('Email OTP threshold-ed25519 registration prepare returned incomplete data');
    }
    const clientRequest = await prepareThresholdEd25519HssClientRequestWasm({
      evaluatorDriverStateB64u: String(preparedSession.evaluatorDriverStateB64u || '').trim(),
      clientOtOfferMessageB64u,
      clientInputs,
      workerCtx,
    });
    await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/respond'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration respond',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        ceremonyHandle,
        clientRequest,
      },
    });
    const finalized = await postJsonExpectOk({
      url: registrationUrl('/registration/threshold-ed25519/hss/finalize'),
      headers: await registrationHeaders(),
      operation: 'Email OTP threshold-ed25519 registration finalize',
      body: {
        new_account_id: String(nearAccountId),
        rp_id: rpId,
        ceremonyHandle,
        account_provisioning: { mode: 'create_if_missing' },
        ...(args.registrationAttemptId
          ? { google_email_otp_registration_attempt_id: args.registrationAttemptId }
          : {}),
      },
    });
    const publicKey = String(finalized.publicKey || '').trim();
    const relayerKeyId = String(finalized.relayerKeyId || '').trim();
    if (!publicKey || !relayerKeyId) {
      throw new Error('Email OTP threshold-ed25519 registration finalize returned incomplete data');
    }
    const accountProvisioning = finalized.accountProvisioning as
      | { mode?: unknown; status?: unknown }
      | undefined;
    if (
      String(accountProvisioning?.mode || '').trim() !== 'create_if_missing' ||
      !['created', 'already_ready'].includes(String(accountProvisioning?.status || '').trim())
    ) {
      throw new Error(
        'Email OTP threshold-ed25519 registration did not provision the finalized public key on-chain',
      );
    }

    await this.deps.persistEmailOtpThresholdEd25519LocalMetadata({
      nearAccountId,
      rpId,
      relayerUrl,
      publicKey,
      relayerKeyId,
      keyVersion,
      participantIds,
    });

    const { policy } = await buildEd25519SessionPolicy({
      nearAccountId,
      rpId,
      relayerKeyId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      participantIds,
      walletSigningSessionId: args.walletSigningSessionId,
      ttlMs: args.ttlMs,
      remainingUses: args.remainingUses,
    });
    const minted = await postJsonExpectOk({
      url: joinUrlPath(relayerUrl, '/threshold-ed25519/session'),
      headers: args.appSessionJwt ? { Authorization: `Bearer ${args.appSessionJwt}` } : {},
      credentials: 'include',
      operation: 'Email OTP threshold-ed25519 session mint',
      body: {
        sessionKind: 'jwt',
        relayerKeyId,
        sessionPolicy: policy,
      },
    });
    const sessionId = String(minted.sessionId || policy.sessionId || '').trim();
    const jwt = String(minted.jwt || '').trim();
    const expiresAtMs = Number.isFinite(Number(minted.expiresAtMs))
      ? Math.floor(Number(minted.expiresAtMs))
      : minted.expiresAt
        ? Date.parse(String(minted.expiresAt))
        : Date.now() + policy.ttlMs;
    const remainingUses = Number.isFinite(Number(minted.remainingUses))
      ? Math.floor(Number(minted.remainingUses))
      : policy.remainingUses;
    const sessionScope =
      normalizeThresholdRuntimePolicyScope(minted.runtimePolicyScope) || runtimePolicyScope;
    if (!sessionId || !jwt || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
      throw new Error('Email OTP threshold-ed25519 session mint returned incomplete data');
    }

    await this.deps.persistWarmSessionEd25519Capability({
      nearAccountId,
      rpId,
      relayerUrl,
      relayerKeyId,
      ...(sessionScope ? { runtimePolicyScope: sessionScope } : {}),
      participantIds,
      sessionKind: 'jwt',
      sessionId,
      ...(policy.walletSigningSessionId
        ? { walletSigningSessionId: policy.walletSigningSessionId }
        : {}),
      expiresAtMs,
      remainingUses,
      jwt,
      emailOtpAuthContext: args.emailOtpAuthContext,
      source: 'email_otp',
    });
    await this.deps.hydrateSigningSession({
      sessionId,
      prfFirstB64u,
      expiresAtMs,
      remainingUses,
      transport: {
        curve: 'ed25519',
        relayerUrl,
        thresholdSessionJwt: jwt,
      },
    });

    const completed = await runThresholdEd25519HssCeremonyWithSessionValue({
      relayerUrl,
      thresholdSessionJwt: jwt,
      relayerKeyId,
      operation: 'warm_session_reconstruction',
      context: {
        ...context,
        signingRootId: sessionScope
          ? signingRootScopeFromRuntimePolicyScope(sessionScope).signingRootId
          : signingRootId,
      },
      clientInputs,
      workerCtx,
      persistToThresholdSessionId: sessionId,
    });
    if (!completed.success || !completed.clientOutput?.xClientBaseB64u) {
      throw new Error(
        completed.error || 'Email OTP threshold-ed25519 client-base reconstruction failed',
      );
    }

    return {
      publicKey,
      relayerKeyId,
      keyVersion,
      sessionId,
      expiresAtMs,
      remainingUses,
      participantIds,
      jwt,
      xClientBaseB64u: completed.clientOutput.xClientBaseB64u,
    };
  }

  private normalizeWarmupAccountId(nearAccountId: AccountId | string): string {
    return String(nearAccountId || '').trim();
  }

  private getEd25519WarmupMap(): Map<string, Promise<EmailOtpThresholdEd25519ProvisioningResult>> {
    if (!(this.ed25519WarmupByAccount instanceof Map)) {
      this.ed25519WarmupByAccount = new Map();
    }
    return this.ed25519WarmupByAccount;
  }

  private requireRelayUrl(): string {
    const relayUrl = String(this.deps.configs.network.relayer?.url || '').trim();
    if (!relayUrl) {
      throw new Error('Missing relayer url (configs.network.relayer.url)');
    }
    return relayUrl;
  }

  private requireShamirPrimeB64u(): string {
    const shamirPrimeB64u = String(
      this.deps.configs.signing.sessionSeal?.shamirPrimeB64u || '',
    ).trim();
    if (!shamirPrimeB64u) {
      throw new Error('Missing shamir prime for Email OTP runtime');
    }
    return shamirPrimeB64u;
  }

  private requireRpId(operation: string): string {
    const rpId =
      typeof (this.deps.touchIdPrompt as { getRpId?: unknown } | undefined)?.getRpId === 'function'
        ? String(this.deps.touchIdPrompt.getRpId() || '').trim()
        : '';
    if (!rpId) {
      throw new Error(`${operation} requires an RP ID for ECDSA bootstrap`);
    }
    return rpId;
  }
}

function joinUrlPath(baseUrl: string, path: string): string {
  const base = String(baseUrl || '')
    .trim()
    .replace(/\/+$/, '');
  const suffix = String(path || '').trim();
  if (!base) return '';
  return `${base}${suffix.startsWith('/') ? suffix : `/${suffix}`}`;
}

function replaceUrlPathSuffix(url: string, fromPath: string, toPath: string): string {
  const raw = String(url || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.pathname === fromPath || parsed.pathname === `${fromPath}/`) {
      parsed.pathname = toPath;
      return parsed.toString();
    }
  } catch {}
  if (raw.endsWith(fromPath)) return `${raw.slice(0, raw.length - fromPath.length)}${toPath}`;
  if (raw.endsWith(`${fromPath}/`)) {
    return `${raw.slice(0, raw.length - fromPath.length - 1)}${toPath}`;
  }
  return '';
}

function resolveRegistrationTransportFromConfig(args: {
  configs: TatchiConfigsReadonly;
  relayerUrl: string;
}): RegistrationTransport {
  const registration = args.configs.registration;
  if (registration.mode === 'managed') {
    return {
      mode: 'managed',
      relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
      environmentId: String(registration.environmentId || '').trim(),
      publishableKey: String(registration.publishableKey || '').trim(),
    };
  }
  return {
    mode: 'backend_proxy',
    bootstrapUrl: String(registration.bootstrapUrl || '').trim(),
    relayerUrl: String(args.relayerUrl || args.configs.network.relayer.url || '').trim(),
  };
}

async function readJsonObjectResponse(response: Response): Promise<Record<string, unknown>> {
  const parsed = await response.json().catch(() => ({}));
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

async function postJsonExpectOk(args: {
  url: string;
  headers?: Record<string, string>;
  body: unknown;
  credentials?: RequestCredentials;
  operation: string;
}): Promise<Record<string, unknown>> {
  const response = await fetch(args.url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(args.headers || {}) },
    credentials: args.credentials || 'omit',
    body: JSON.stringify(args.body),
  });
  const data = await readJsonObjectResponse(response);
  if (!response.ok || data.ok === false) {
    throw new Error(
      String(data.message || data.code || `${args.operation} failed with HTTP ${response.status}`),
    );
  }
  return data;
}

async function requestManagedRegistrationBootstrapGrant(args: {
  relayerUrl: string;
  environmentId: string;
  publishableKey: string;
  nearAccountId: string;
  rpId: string;
}): Promise<ManagedRegistrationBootstrapGrant> {
  const data = await postJsonExpectOk({
    url: joinUrlPath(args.relayerUrl, '/v1/registration/bootstrap-grants'),
    headers: { Authorization: `Bearer ${args.publishableKey}` },
    operation: 'Managed registration bootstrap grant',
    body: {
      environmentId: args.environmentId,
      newAccountId: args.nearAccountId,
      rpId: args.rpId,
      flow: 'registration_v1',
    },
  });
  const grant =
    data.grant && typeof data.grant === 'object' && !Array.isArray(data.grant)
      ? (data.grant as Record<string, unknown>)
      : {};
  const token = String(grant.token || '').trim();
  const orgId = String(grant.orgId || '').trim();
  const projectId = String(grant.projectId || '').trim();
  const envId = String(grant.envId || '').trim();
  if (!token || !orgId || !projectId || !envId) {
    throw new Error('Managed registration grant response missing token or runtime scope');
  }
  return {
    token,
    runtimePolicyScope: {
      orgId,
      projectId,
      envId,
    },
  };
}
