import type { AccountId } from '@/core/types/accountIds';
import { toAccountId } from '@/core/types/accountIds';
import type { ThresholdEcdsaSessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import {
  toEvmFamilyEcdsaKeyHandle,
  type VerifiedEcdsaPublicFacts,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpEd25519SessionReconstructionPlan } from './provisioning';
import type { EmailOtpEcdsaBootstrapAuthorization } from './routePlan';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
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
import type { ExportEd25519SeedWithAuthorizationArgs } from './exportRecoveryRuntime';
import {
  parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial,
  type EcdsaRoleLocalExportMaterial,
} from '../persistence/ecdsaRoleLocalRecords';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';

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

export type EmailOtpEd25519ExportArtifact = {
  publicKey: string;
  privateKey: string;
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

type EmailOtpEcdsaExportBaseInput = {
  mode: 'export_step_up';
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  relayUrl: string;
  routePlan: EmailOtpRoutePlan;
};

export type EmailOtpEcdsaAuthorizedExportStepUpInput = EmailOtpEcdsaExportBaseInput & {
  source: 'authorized_signing_session';
  record: ThresholdEcdsaSessionRecord;
  shamirPrimeB64u: string;
  keyHandle: string;
  roleLocalMaterial: EcdsaRoleLocalExportMaterial;
};

type EmailOtpEcdsaFreshExportSubjectInput =
  | {
      authSubjectMode: 'explicit_auth_subject';
      authSubjectId: string;
    }
  | {
      authSubjectMode: 'wallet_session_subject';
      authSubjectId?: never;
    };

export type EmailOtpEcdsaFreshLoginExportStepUpInput = EmailOtpEcdsaExportBaseInput &
  EmailOtpEcdsaFreshExportSubjectInput & {
    source: 'fresh_login';
    chainTarget: ThresholdEcdsaChainTarget;
    publicFacts: VerifiedEcdsaPublicFacts;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  };

export type EmailOtpEcdsaExportStepUpInput =
  | EmailOtpEcdsaAuthorizedExportStepUpInput
  | EmailOtpEcdsaFreshLoginExportStepUpInput;

function requireProvidedEmailOtpSigningSessionAuthLane(args: {
  authLane?: EmailOtpAuthLane;
  routeAuth?: AppOrWalletSessionAuth;
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
      signingGrantId: string;
      chain: 'near';
      chainTarget?: never;
    }
  | {
      thresholdSessionId: string;
      signingGrantId: string;
      chain: EmailOtpEcdsaRouteChain;
      chainTarget: ThresholdEcdsaChainTarget;
    };

function requireRecordBackedEmailOtpSigningSessionAuthLane(args: {
  authLane?: EmailOtpAuthLane;
  routeAuth?: AppOrWalletSessionAuth;
  recordIdentity: EmailOtpRecordBackedSigningSessionIdentity;
}): EmailOtpSigningSessionAuthLane {
  const authLane =
    args.authLane?.kind === 'signing_session'
      ? args.authLane
      : resolveEmailOtpAuthLane({
          routeAuth: args.routeAuth,
          thresholdSessionId: args.recordIdentity.thresholdSessionId,
          authorizingSigningGrantId: args.recordIdentity.signingGrantId,
          curve: args.recordIdentity.chain === 'near' ? 'ed25519' : 'ecdsa',
          chainTarget:
            args.recordIdentity.chain === 'near' ? undefined : args.recordIdentity.chainTarget,
        });
  if (authLane?.kind !== 'signing_session') {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return authLane;
}

function requireSigningGrantIdForEmailOtpSigningSession(
  signingGrantId: string | undefined,
): string {
  const normalized = String(signingGrantId || '').trim();
  if (!normalized) {
    throw new Error(EMAIL_OTP_SIGNING_SESSION_AUTH_UNAVAILABLE);
  }
  return normalized;
}

function resolveEmailOtpEcdsaAuthorizedExportStepUpInput(
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
    routeAuth?: AppOrWalletSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): EmailOtpEcdsaAuthorizedExportStepUpInput {
  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(
    args.record,
  );
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
        signingGrantId: args.record.signingGrantId,
        chain: args.record.chainTarget.kind,
        chainTarget: args.record.chainTarget,
      },
    }),
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return {
    mode: 'export_step_up',
    source: 'authorized_signing_session',
    walletSession: args.walletSession,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    relayUrl: String(args.record.relayerUrl || ports.requireRelayUrl()).trim(),
    shamirPrimeB64u: String(ports.requireShamirPrimeB64u()).trim(),
    routePlan,
    record: args.record,
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(args.record.keyHandle)),
    roleLocalMaterial,
  };
}

async function resolveEmailOtpEcdsaFreshLoginExportStepUpInput(
  ports: Pick<EmailOtpWorkerPorts, 'requireRelayUrl' | 'resolveAppSessionJwt' | 'buildRoutePlan'>,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    publicFacts: VerifiedEcdsaPublicFacts;
    authSubjectId?: string;
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  },
): Promise<EmailOtpEcdsaFreshLoginExportStepUpInput> {
  if (!args.runtimePolicyScope) {
    throw new Error('Email OTP ECDSA fresh export requires runtimePolicyScope');
  }
  const relayUrl = ports.requireRelayUrl();
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
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  const authSubjectId = String(args.authSubjectId || '').trim();
  const base = {
    mode: 'export_step_up' as const,
    source: 'fresh_login' as const,
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    publicFacts: args.publicFacts,
    relayUrl,
    routePlan,
    runtimePolicyScope: args.runtimePolicyScope,
  };
  if (authSubjectId) {
    return {
      ...base,
      authSubjectMode: 'explicit_auth_subject',
      authSubjectId,
    };
  }
  return {
    ...base,
    authSubjectMode: 'wallet_session_subject',
  };
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
	        walletSession: WalletSessionRef;
	        nearAccountId: AccountId;
	        routePlan: EmailOtpRoutePlan;
	      },
): Promise<{ challengeId: string; emailHint?: string; appSessionJwt?: string }> {
  const walletId = args.kind === 'wallet_session' ? args.walletId : args.walletSession.walletId;
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
      return args.walletSession;
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
          walletSession: args.walletSession,
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
          walletSession: args.walletSession,
          nearAccountId: args.nearAccountId,
          routePlan,
        });
  return {
    challengeId: challenge.challengeId,
    ...(challenge.emailHint ? { emailHint: challenge.emailHint } : {}),
  };
}

function requireEmailOtpExportAuthSubject(args: {
  record: ThresholdEcdsaSessionRecord | ThresholdEd25519SessionRecord;
  walletSessionUserId: string;
}): string {
  if (args.record.source === 'email_otp') {
    const authSubjectId = String(args.record.emailOtpAuthContext?.authSubjectId || '').trim();
    if (!authSubjectId) {
      throw new Error('Email OTP export requires record authSubjectId');
    }
    return authSubjectId;
  }
  const walletSessionUserId = String(args.walletSessionUserId || '').trim();
  if (!walletSessionUserId) {
    throw new Error('Email OTP export requires walletSessionUserId');
  }
  return walletSessionUserId;
}

export async function exportEd25519SeedWithAuthorization(
  ports: Pick<
    EmailOtpWorkerPorts,
    | 'getSignerWorkerContext'
    | 'requireRelayUrl'
    | 'requireShamirPrimeB64u'
    | 'buildSigningSessionRoutePlan'
  >,
	  args: ExportEd25519SeedWithAuthorizationArgs,
): Promise<EmailOtpEd25519ExportArtifact> {
  const nearAccountId = args.nearAccountId;
  const walletId = args.record.walletId;
  if (String(args.record.nearAccountId) !== String(nearAccountId)) {
    throw new Error('Email OTP Ed25519 export nearAccountId mismatch');
  }
  const relayUrl = String(args.record.relayerUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(ports.requireShamirPrimeB64u()).trim();
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP Ed25519 export requires the dedicated emailOtp worker');
  }
  const runtimePolicyScope = args.record.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('Email OTP Ed25519 export requires runtime policy scope');
  }
  const userId = requireEmailOtpExportAuthSubject({
    record: args.record,
    walletSessionUserId: String(walletId),
  });
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
        signingGrantId: requireSigningGrantIdForEmailOtpSigningSession(
          args.record.signingGrantId,
        ),
        chain: 'near',
      },
    }),
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  const workerResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportEmailOtpEd25519SeedWithAuthorization',
      timeoutMs: 60_000,
		      payload: {
        relayUrl,
        walletId: String(walletId),
        nearAccountId: String(nearAccountId),
        nearEd25519SigningKeyId: String(args.record.nearEd25519SigningKeyId || '').trim(),
        userId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        runtimePolicyScope,
        participantIds: args.participantIds,
        thresholdSessionId: args.thresholdSessionId,
        walletSessionJwt: args.walletSessionJwt,
        relayerKeyId: args.relayerKeyId,
        expectedPublicKey: args.expectedPublicKey,
      },
    },
  });
  const publicKey = String(workerResult.publicKey || '').trim();
  const privateKey = String(workerResult.privateKey || '').trim();
  if (!publicKey || !privateKey) {
    throw new Error('Email OTP Ed25519 export did not return a seed artifact');
  }
  return { publicKey, privateKey };
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
    routeAuth?: AppOrWalletSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const exportInput = resolveEmailOtpEcdsaAuthorizedExportStepUpInput(ports, args);
  const record = exportInput.record;
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (walletSessionAuth.kind !== 'ready') {
    throw new Error('Email OTP ECDSA export requires Wallet Session route auth');
  }
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP ECDSA export requires the dedicated emailOtp worker');
  }
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportThresholdEcdsaHssKeyWithEmailOtpAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl: exportInput.relayUrl,
        walletId: exportInput.walletSession.walletId,
        userId: requireEmailOtpExportAuthSubject({
          record,
          walletSessionUserId: exportInput.walletSession.walletSessionUserId,
        }),
        challengeId: exportInput.challengeId,
        otpCode: exportInput.otpCode,
        shamirPrimeB64u: exportInput.shamirPrimeB64u,
        routePlan: exportInput.routePlan,
        evmFamilySigningKeySlotId: record.evmFamilySigningKeySlotId,
        walletSessionJwt: walletSessionAuth.walletSessionJwt,
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        relayerKeyId: record.relayerKeyId,
        readyRecord: exportInput.roleLocalMaterial.readyRecord,
        thresholdSessionId: record.thresholdSessionId,
        signingGrantId: record.signingGrantId,
        thresholdExpiresAtMs: record.expiresAtMs,
        participantIds: record.participantIds,
        keyHandle: exportInput.keyHandle,
        ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
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
      ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
      ed25519ReconstructionMode: 'await' | 'skip';
      ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan;
      includeEcdsaExportArtifact: true;
    }) => Promise<{
      bootstrap: { thresholdEcdsaKeyRef: { ecdsaHssExportArtifact?: EmailOtpEcdsaExportArtifact } };
    }>;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const exportInput = await resolveEmailOtpEcdsaFreshLoginExportStepUpInput(ports, args);
  const result = await args.loginWithEcdsaCapabilityInternal({
    walletSession: exportInput.walletSession,
    relayUrl: exportInput.relayUrl,
    chainTarget: exportInput.chainTarget,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    challengeId: exportInput.challengeId,
    otpCode: exportInput.otpCode,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    routePlan: exportInput.routePlan,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    keyHandle: String(exportInput.publicFacts.keyHandle),
    participantIds: exportInput.publicFacts.participantIds.map((participantId) =>
      Number(participantId),
    ),
    remainingUses: 1,
    ...(exportInput.authSubjectMode === 'explicit_auth_subject'
      ? { authSubjectId: exportInput.authSubjectId }
      : {}),
    runtimePolicyScope: exportInput.runtimePolicyScope,
    ed25519ReconstructionMode: 'skip',
    ed25519SessionReconstruction: {
      kind: 'defer',
      reason: 'not_needed_for_ecdsa',
    },
    includeEcdsaExportArtifact: true,
  });
  const artifact = result.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact;
  if (!artifact) {
    throw new Error('Email OTP ECDSA export did not return an export artifact');
  }
  return artifact;
}
