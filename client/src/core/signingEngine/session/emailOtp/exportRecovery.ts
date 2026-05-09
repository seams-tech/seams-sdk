import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletSubjectId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { AppOrThresholdSessionAuth } from '@shared/utils/sessionTokens';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  authLaneToRouteAuth,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;
export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

export const EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE =
  'Email OTP signing-session authority is unavailable; unlock wallet again';

export type EmailOtpEcdsaExportArtifact = {
  publicKeyHex: string;
  privateKeyHex: string;
  ethereumAddress: string;
};

type EmailOtpWorkerPorts = {
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  requireRelayUrl: () => string;
  requireShamirPrimeB64u: () => string;
  resolveAppSessionJwt: (args: {
    nearAccountId: AccountId | string;
    relayUrl: string;
  }) => Promise<string>;
  buildRoutePlan: (args: {
    freshRouteFamily: 'login' | 'registration';
    routeAuth?: AppOrThresholdSessionAuth;
    appSessionJwt?: string;
    sessionKind?: 'jwt' | 'cookie';
    thresholdSessionId?: string;
    walletSigningSessionId?: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    operation?: WalletEmailOtpLoginOperation;
  }) => EmailOtpRoutePlan;
  buildSigningSessionRoutePlan: (args: {
    authLane?: EmailOtpAuthLane;
    routeAuth?: AppOrThresholdSessionAuth;
    thresholdSessionId?: string;
    walletSigningSessionId?: string;
    curve?: 'ed25519' | 'ecdsa';
    chainTarget?: ThresholdEcdsaChainTarget;
    operation: EmailOtpSigningSessionChallengeOperation;
  }) => EmailOtpRoutePlan;
  appSessionJwtFromLane: (authLane?: EmailOtpAuthLane) => string;
};

async function requestEmailOtpChallengeWithRoutePlan(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'appSessionJwtFromLane'
  >,
  args: {
    nearAccountId: AccountId | string;
    routePlan: EmailOtpRoutePlan;
  },
): Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayUrl = ports.requireRelayUrl();
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP signing requires the dedicated emailOtp worker');
  }
  const response = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'requestEmailOtpChallenge',
      timeoutMs: 30_000,
      payload: {
        relayUrl,
        walletId: String(nearAccountId),
        routePlan: args.routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
      },
    },
  });
  const challengeId = String(response.challengeId || '').trim();
  if (!challengeId) {
    throw new Error('Email OTP signing challenge response did not include challengeId');
  }
  const appSessionJwt = ports.appSessionJwtFromLane(args.routePlan.authLane);
  return {
    challengeId,
    ...(String(response.emailHint || '').trim()
      ? { emailHint: String(response.emailHint || '').trim() }
      : {}),
    ...(appSessionJwt ? { appSessionJwt } : {}),
  };
}

export async function requestTransactionSigningChallenge(
  ports: EmailOtpWorkerPorts,
  args: {
    nearAccountId: AccountId | string;
    chain: EmailOtpRouteChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan =
    !providedAuthLane && !providedRouteAuth
      ? ports.buildRoutePlan({
          freshRouteFamily: 'login',
          appSessionJwt: await ports.resolveAppSessionJwt({
            nearAccountId: args.nearAccountId,
            relayUrl: ports.requireRelayUrl(),
          }),
          sessionKind: 'jwt',
          curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
          operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        })
      : ports.buildSigningSessionRoutePlan({
          authLane: providedAuthLane,
          routeAuth: providedRouteAuth,
          curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
          operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        });
  const challenge = await requestEmailOtpChallengeWithRoutePlan(ports, {
    nearAccountId: args.nearAccountId,
    routePlan,
  });
  return { challengeId: challenge.challengeId, ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}) };
}

export async function requestExportChallenge(
  ports: EmailOtpWorkerPorts,
  args: {
    nearAccountId: AccountId | string;
    chain: EmailOtpRouteChain;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<{ challengeId: string; emailHint?: string }> {
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan =
    !providedAuthLane && !providedRouteAuth && args.chain !== 'near'
      ? ports.buildRoutePlan({
          freshRouteFamily: 'login',
          appSessionJwt: await ports.resolveAppSessionJwt({
            nearAccountId: args.nearAccountId,
            relayUrl: ports.requireRelayUrl(),
          }),
          sessionKind: 'jwt',
          curve: 'ecdsa',
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        })
      : ports.buildSigningSessionRoutePlan({
          authLane: providedAuthLane,
          routeAuth: providedRouteAuth,
          curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        });
  const challenge = await requestEmailOtpChallengeWithRoutePlan(ports, {
    nearAccountId: args.nearAccountId,
    routePlan,
  });
  return { challengeId: challenge.challengeId, ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}) };
}

export async function recoverEd25519ExportPrfFirst(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'requireShamirPrimeB64u' | 'buildSigningSessionRoutePlan'
  >,
  args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEd25519SessionRecord;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<{ prfFirstB64u: string }> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayUrl = String(args.record.relayerUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(ports.requireShamirPrimeB64u()).trim();
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP Ed25519 export requires the dedicated emailOtp worker');
  }
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: providedAuthLane,
    routeAuth: providedRouteAuth,
    thresholdSessionId: args.record.thresholdSessionId,
    walletSigningSessionId: args.record.walletSigningSessionId,
    curve: 'ed25519',
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  const workerResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'recoverEmailOtpEd25519ExportPrfFirst',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(nearAccountId),
        userId: String(args.record.emailOtpAuthContext?.authSubjectId || nearAccountId),
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        ...(args.record.runtimePolicyScope
          ? { runtimePolicyScope: args.record.runtimePolicyScope }
          : {}),
      },
    },
  });
  const prfFirstB64u = String(workerResult.thresholdEd25519PrfFirstB64u || '').trim();
  if (!prfFirstB64u) {
    throw new Error('Email OTP Ed25519 export did not recover client seed material');
  }
  return { prfFirstB64u };
}

export async function exportEcdsaKeyWithAuthorization(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'requireShamirPrimeB64u' | 'buildSigningSessionRoutePlan'
  >,
  args: {
    nearAccountId: AccountId | string;
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const relayUrl = String(args.record.relayerUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(ports.requireShamirPrimeB64u()).trim();
  const ecdsaThresholdKeyId = String(args.record.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error('Email OTP ECDSA export requires ecdsaThresholdKeyId');
  }
  const thresholdSessionAuthToken = String(args.record.thresholdSessionAuthToken || '').trim();
  const sessionKind = args.record.thresholdSessionKind || 'jwt';
  if (!thresholdSessionAuthToken && sessionKind !== 'cookie') {
    throw new Error('Email OTP ECDSA export requires threshold session route auth');
  }
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP ECDSA export requires the dedicated emailOtp worker');
  }
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: providedAuthLane,
    routeAuth: providedRouteAuth,
    thresholdSessionId: args.record.thresholdSessionId,
    walletSigningSessionId: args.record.walletSigningSessionId,
    curve: 'ecdsa',
    chainTarget: args.record.chainTarget,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(nearAccountId),
        userId: String(args.record.emailOtpAuthContext?.authSubjectId || nearAccountId),
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        rpId: args.rpId,
        thresholdSessionAuthToken,
        sessionKind,
        subjectId: args.record.subjectId,
        ecdsaThresholdKeyId,
        chainTarget: args.record.chainTarget,
        ...(args.record.runtimePolicyScope
          ? { runtimePolicyScope: args.record.runtimePolicyScope }
          : {}),
      },
    },
  });
}

export async function exportEcdsaKeyWithFreshEmailOtpLane(
  ports: Pick<EmailOtpWorkerPorts, 'requireRelayUrl' | 'resolveAppSessionJwt' | 'buildRoutePlan'>,
  args: {
    nearAccountId: AccountId | string;
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ecdsaThresholdKeyId: string;
    participantIds: number[];
    authSubjectId?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    loginWithEcdsaCapabilityInternal: (args: {
      nearAccountId: AccountId | string;
      subjectId: WalletSubjectId;
      chainTarget: ThresholdEcdsaChainTarget;
      relayUrl: string;
      emailOtpAuthPolicy: 'per_operation';
      emailOtpAuthReason: 'sign';
      challengeId: string;
      otpCode: string;
      operation: WalletEmailOtpExportOperation;
      routePlan: EmailOtpRoutePlan;
      ecdsaThresholdKeyId: string;
      participantIds: number[];
      remainingUses: 1;
      authSubjectId?: string;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      includeEcdsaExportArtifact: true;
    }) => Promise<{
      bootstrap: { thresholdEcdsaKeyRef: { ecdsaHssExportArtifact?: EmailOtpEcdsaExportArtifact } };
    }>;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const relayUrl = ports.requireRelayUrl();
  const operation = WALLET_EMAIL_OTP_EXPORT_OPERATION;
  const appSessionJwt = await ports.resolveAppSessionJwt({
    nearAccountId: args.nearAccountId,
    relayUrl,
  });
  const routePlan = ports.buildRoutePlan({
    freshRouteFamily: 'login',
    appSessionJwt,
    sessionKind: 'jwt',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    operation,
  });
  const result = await args.loginWithEcdsaCapabilityInternal({
    nearAccountId: args.nearAccountId,
    subjectId: args.subjectId,
    relayUrl,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation,
    routePlan,
    ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
    participantIds: args.participantIds,
    remainingUses: 1,
    ...(args.authSubjectId ? { authSubjectId: args.authSubjectId } : {}),
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    includeEcdsaExportArtifact: true,
  });
  const artifact = result.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
  if (!artifact) {
    throw new Error('Email OTP ECDSA export did not return an export artifact');
  }
  return artifact;
}
