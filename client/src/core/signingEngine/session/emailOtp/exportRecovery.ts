import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  deriveBaseEcdsaSubjectIdFromWalletId,
  toEvmFamilyEcdsaKeyHandle,
  type VerifiedEcdsaPublicFacts,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { walletSessionRefFromSession } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  resolveEmailOtpAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { RequestEmailOtpChallengeArgs } from './exportRecoveryRuntime';
import type { RecoverEd25519ExportPrfFirstArgs } from './exportRecoveryRuntime';

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
    walletSession: WalletSessionRef;
    relayUrl: string;
  }) => Promise<string>;
  buildRoutePlan: (args: {
    freshRouteFamily: 'login' | 'registration';
    authLane: EmailOtpAuthLane;
    operation?: WalletEmailOtpLoginOperation;
  }) => EmailOtpRoutePlan;
  buildSigningSessionRoutePlan: (args: {
    authLane: EmailOtpSigningSessionAuthLane;
    operation: EmailOtpSigningSessionChallengeOperation;
  }) => EmailOtpRoutePlan;
  appSessionJwtFromLane: (authLane?: EmailOtpAuthLane) => string;
};

function requireProvidedEmailOtpSigningSessionAuthLane(args: {
  authLane?: EmailOtpAuthLane;
  routeAuth?: AppOrThresholdSessionAuth;
  chain: EmailOtpRouteChain;
  chainTarget?: ThresholdEcdsaChainTarget;
}): EmailOtpSigningSessionAuthLane {
  const authLane =
    args.authLane?.kind === 'signing_session'
      ? args.authLane
      : resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          curve: args.chain === 'near' ? 'ed25519' : 'ecdsa',
          chainTarget: args.chain === 'near' ? undefined : args.chainTarget,
        });
  if (authLane?.kind !== 'signing_session') {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return authLane;
}

type EmailOtpRecordBackedSigningSessionIdentity =
  | {
      thresholdSessionId: string;
      walletSigningSessionId: string;
      chain: 'near';
      chainTarget?: never;
    }
  | {
      thresholdSessionId: string;
      walletSigningSessionId: string;
      chain: EmailOtpEcdsaRouteChain;
      chainTarget: ThresholdEcdsaChainTarget;
    };

function requireRecordBackedEmailOtpSigningSessionAuthLane(args: {
  authLane?: EmailOtpAuthLane;
  routeAuth?: AppOrThresholdSessionAuth;
  recordIdentity: EmailOtpRecordBackedSigningSessionIdentity;
}): EmailOtpSigningSessionAuthLane {
  const authLane =
    args.authLane?.kind === 'signing_session'
      ? args.authLane
      : resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          thresholdSessionId: args.recordIdentity.thresholdSessionId,
          authorizingWalletSigningSessionId: args.recordIdentity.walletSigningSessionId,
          curve: args.recordIdentity.chain === 'near' ? 'ed25519' : 'ecdsa',
          chainTarget:
            args.recordIdentity.chain === 'near' ? undefined : args.recordIdentity.chainTarget,
        });
  if (authLane?.kind !== 'signing_session') {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return authLane;
}

function requireWalletSigningSessionIdForEmailOtpSigningSession(
  walletSigningSessionId: string | undefined,
): string {
  const normalized = String(walletSigningSessionId || '').trim();
  if (!normalized) {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return normalized;
}

async function requestEmailOtpChallengeWithRoutePlan(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'appSessionJwtFromLane'
  >,
  args:
    | {
        kind: 'wallet_session';
        walletId: WalletId;
        routePlan: EmailOtpRoutePlan;
      }
    | {
        kind: 'near_account';
        nearAccountId: AccountId;
        routePlan: EmailOtpRoutePlan;
      },
): Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }> {
  const walletId = args.kind === 'wallet_session' ? args.walletId : args.nearAccountId;
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
        walletId: String(walletId),
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

function resolveChallengeWalletSession(args: RequestEmailOtpChallengeArgs): WalletSessionRef {
  switch (args.kind) {
    case 'wallet_session_challenge':
      return args.walletSession;
    case 'near_account_challenge':
      return walletSessionRefFromSession({
        walletId: args.nearAccountId,
        walletSessionUserId: args.nearAccountId,
      });
  }
}

export async function requestTransactionSigningChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<{ challengeId: string; emailHint?: string }> {
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan =
    !providedAuthLane && !providedRouteAuth
      ? ports.buildRoutePlan({
          freshRouteFamily: 'login',
          authLane:
            resolveEmailOtpAuthLane({
              appSessionJwt: await ports.resolveAppSessionJwt({
                walletSession: resolveChallengeWalletSession(args),
                relayUrl: ports.requireRelayUrl(),
              }),
              sessionKind: 'jwt',
            }) ||
            (() => {
              throw new Error('Email OTP login requires route auth');
            })(),
          operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        })
      : ports.buildSigningSessionRoutePlan({
          authLane: requireProvidedEmailOtpSigningSessionAuthLane({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            chain: args.chain,
          }),
          operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
        });
  const challenge =
    args.kind === 'wallet_session_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'wallet_session',
          walletId: args.walletSession.walletId,
          routePlan,
        })
      : await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          nearAccountId: args.nearAccountId,
          routePlan,
        });
  return {
    challengeId: challenge.challengeId,
    ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
  };
}

export async function requestExportChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<{ challengeId: string; emailHint?: string }> {
  const providedAuthLane = args.authLane;
  const providedRouteAuth = providedAuthLane
    ? authLaneToRouteAuth(providedAuthLane)
    : args.routeAuth;
  const routePlan =
    !providedAuthLane && !providedRouteAuth && args.chain !== 'near'
      ? ports.buildRoutePlan({
          freshRouteFamily: 'login',
          authLane:
            resolveEmailOtpAuthLane({
              appSessionJwt: await ports.resolveAppSessionJwt({
                walletSession: resolveChallengeWalletSession(args),
                relayUrl: ports.requireRelayUrl(),
              }),
              sessionKind: 'jwt',
            }) ||
            (() => {
              throw new Error('Email OTP login requires route auth');
            })(),
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        })
      : ports.buildSigningSessionRoutePlan({
          authLane: requireProvidedEmailOtpSigningSessionAuthLane({
            authLane: providedAuthLane,
            routeAuth: providedRouteAuth,
            chain: args.chain,
          }),
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        });
  const challenge =
    args.kind === 'wallet_session_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'wallet_session',
          walletId: args.walletSession.walletId,
          routePlan,
        })
      : await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          nearAccountId: args.nearAccountId,
          routePlan,
        });
  return {
    challengeId: challenge.challengeId,
    ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
  };
}

export async function recoverEd25519ExportPrfFirst(
  ports: Pick<
    EmailOtpWorkerPorts,
    | 'getSignerWorkerContext'
    | 'requireRelayUrl'
    | 'requireShamirPrimeB64u'
    | 'buildSigningSessionRoutePlan'
  >,
  args: RecoverEd25519ExportPrfFirstArgs,
): Promise<{ prfFirstB64u: string }> {
  const nearAccountId = args.nearAccountId;
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
    authLane: requireRecordBackedEmailOtpSigningSessionAuthLane({
      authLane: providedAuthLane,
      routeAuth: providedRouteAuth,
      recordIdentity: {
        thresholdSessionId: args.record.thresholdSessionId,
        walletSigningSessionId: requireWalletSigningSessionIdForEmailOtpSigningSession(
          args.record.walletSigningSessionId,
        ),
        chain: 'near',
      },
    }),
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
    | 'getSignerWorkerContext'
    | 'requireRelayUrl'
    | 'requireShamirPrimeB64u'
    | 'buildSigningSessionRoutePlan'
  >,
  args: {
    walletSession: WalletSessionRef;
    challengeId: string;
    otpCode: string;
    record: ThresholdEcdsaSessionRecord;
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const relayUrl = String(args.record.relayerUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(ports.requireShamirPrimeB64u()).trim();
  const keyHandle = String(toEvmFamilyEcdsaKeyHandle(args.record.keyHandle));
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
    authLane: requireRecordBackedEmailOtpSigningSessionAuthLane({
      authLane: providedAuthLane,
      routeAuth: providedRouteAuth,
      recordIdentity: {
        thresholdSessionId: args.record.thresholdSessionId,
        walletSigningSessionId: args.record.walletSigningSessionId,
        chain: args.record.chainTarget.kind,
        chainTarget: args.record.chainTarget,
      },
    }),
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: args.walletSession.walletId,
        userId: String(
          args.record.emailOtpAuthContext?.authSubjectId || args.walletSession.walletSessionUserId,
        ),
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        rpId: args.rpId,
        thresholdSessionAuthToken,
        sessionKind,
        subjectId: deriveBaseEcdsaSubjectIdFromWalletId(args.walletSession.walletId),
        keyHandle,
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
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    publicFacts: VerifiedEcdsaPublicFacts;
    authSubjectId?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
    loginWithEcdsaCapabilityInternal: (args: {
      walletSession: WalletSessionRef;
      subjectId?: never;
      chainTarget: ThresholdEcdsaChainTarget;
      relayUrl: string;
      emailOtpAuthPolicy: 'per_operation';
      emailOtpAuthReason: 'sign';
      challengeId: string;
      otpCode: string;
      operation: WalletEmailOtpExportOperation;
      routePlan: EmailOtpRoutePlan;
      keyHandle: string;
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
    walletSession: args.walletSession,
    relayUrl,
  });
  const routePlan = ports.buildRoutePlan({
    freshRouteFamily: 'login',
    authLane:
      resolveEmailOtpAuthLane({
        appSessionJwt,
        sessionKind: 'jwt',
      }) ||
      (() => {
        throw new Error('Email OTP login requires route auth');
      })(),
    operation,
  });
  const result = await args.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    relayUrl,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation,
    routePlan,
    keyHandle: String(args.publicFacts.keyHandle),
    participantIds: args.publicFacts.participantIds.map((participantId) => Number(participantId)),
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
