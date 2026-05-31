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
import { walletSessionRefFromSession } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpEd25519SessionReconstructionPlan } from './provisioning';
import type { EmailOtpEcdsaBootstrapAuthorization } from './routePlan';
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
import type { ExportEd25519SeedWithAuthorizationArgs } from './exportRecoveryRuntime';
import {
  parseThresholdEcdsaSessionRecordAsRoleLocalWorkerExportMaterial,
  type EcdsaRoleLocalWorkerExportMaterial,
} from '@/core/platform/ecdsaRoleLocalRecords';

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
  rpId: string;
  shamirPrimeB64u: string;
  keyHandle: string;
  roleLocalMaterial: EcdsaRoleLocalWorkerExportMaterial;
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

function requiredEmailOtpExportString(value: unknown, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) {
    throw new Error(`Email OTP ECDSA export requires ${field}`);
  }
  return normalized;
}

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
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): EmailOtpEcdsaAuthorizedExportStepUpInput {
  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalWorkerExportMaterial(
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
        walletSigningSessionId: args.record.walletSigningSessionId,
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
    rpId: requiredEmailOtpExportString(args.rpId, 'rpId'),
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
      type: 'exportEmailOtpEd25519SeedWithAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(nearAccountId),
        nearAccountId: String(nearAccountId),
        userId: String(
          args.record.source === 'email_otp'
            ? args.record.emailOtpAuthContext?.authSubjectId || nearAccountId
            : nearAccountId,
        ),
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        ...(args.record.runtimePolicyScope
          ? { runtimePolicyScope: args.record.runtimePolicyScope }
          : {}),
        signingRootId: args.signingRootId,
        keyVersion: args.keyVersion,
        participantIds: args.participantIds,
        thresholdSessionId: args.thresholdSessionId,
        thresholdSessionAuthToken: args.thresholdSessionAuthToken,
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
    rpId: string;
    routeAuth?: AppOrThresholdSessionAuth;
    authLane?: EmailOtpAuthLane;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const exportInput = resolveEmailOtpEcdsaAuthorizedExportStepUpInput(ports, args);
  const record = exportInput.record;
  const thresholdSessionAuthToken = String(args.record.thresholdSessionAuthToken || '').trim();
  const sessionKind = args.record.thresholdSessionKind || 'jwt';
  if (!thresholdSessionAuthToken && sessionKind !== 'cookie') {
    throw new Error('Email OTP ECDSA export requires threshold session route auth');
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
        userId: String(
          record.source === 'email_otp'
            ? record.emailOtpAuthContext.authSubjectId ||
                exportInput.walletSession.walletSessionUserId
            : exportInput.walletSession.walletSessionUserId,
        ),
        challengeId: exportInput.challengeId,
        otpCode: exportInput.otpCode,
        shamirPrimeB64u: exportInput.shamirPrimeB64u,
        routePlan: exportInput.routePlan,
        rpId: exportInput.rpId,
        thresholdSessionAuthToken,
        sessionKind,
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        signingRootId: record.signingRootId,
        signingRootVersion: record.signingRootVersion,
        relayerKeyId: record.relayerKeyId,
        roleLocalState: exportInput.roleLocalMaterial.roleLocalState,
        thresholdSessionId: record.thresholdSessionId,
        walletSigningSessionId: record.walletSigningSessionId,
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
