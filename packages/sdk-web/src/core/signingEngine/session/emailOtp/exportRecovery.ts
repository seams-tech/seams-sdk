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
import { throwEmailOtpSigningSessionAuthStateError } from './routePlan';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  EcdsaExportLane,
  EmailOtpEcdsaExportSessionRecord,
} from '../../flows/recovery/ecdsaExportMaterial';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpLoginOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  resolveEmailOtpAuthLane,
  type EmailOtpAuthLane,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import { emailOtpAuthContextProviderUserId } from '../identity/laneIdentity';
import type { RequestEmailOtpChallengeArgs } from './exportRecoveryRuntime';
import type { ExportEd25519SeedWithAuthorizationArgs } from './exportRecoveryRuntime';
import {
  parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial,
  type EcdsaRoleLocalExportMaterial,
} from '../persistence/ecdsaRoleLocalRecords';
import type { EmailOtpEcdsaProviderIdentity } from './ecdsaLogin';

type EmailOtpEcdsaRouteChain = ThresholdEcdsaChainTarget['kind'];
type EmailOtpRouteChain = 'near' | EmailOtpEcdsaRouteChain;
export type EmailOtpSigningSessionChallengeOperation =
  | WalletEmailOtpTransactionSignOperation
  | WalletEmailOtpExportOperation;

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
  appSessionJwtFromLane: (authLane: EmailOtpAuthLane) => string;
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
  record: EmailOtpEcdsaExportSessionRecord;
  shamirPrimeB64u: string;
  keyHandle: string;
  roleLocalMaterial: EcdsaRoleLocalExportMaterial;
};

type EmailOtpEcdsaFreshExportSubjectInput =
  | {
      providerIdentityMode: 'explicit_provider_user';
      providerUserId: string;
    }
  | {
      providerIdentityMode: 'wallet_session_subject';
      providerUserId?: never;
    };

export type EmailOtpEcdsaFreshLoginExportStepUpInput = EmailOtpEcdsaExportBaseInput &
  EmailOtpEcdsaFreshExportSubjectInput & {
    source: 'fresh_login';
    chainTarget: ThresholdEcdsaChainTarget;
  publicFacts: VerifiedEcdsaPublicFacts;
  emailHashHex: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  };

function providerIdentityFromFreshEcdsaExportInput(
  input: EmailOtpEcdsaFreshLoginExportStepUpInput,
): EmailOtpEcdsaProviderIdentity {
  switch (input.providerIdentityMode) {
    case 'explicit_provider_user':
      return {
        kind: 'explicit_provider_user',
        providerUserId: input.providerUserId,
      };
    case 'wallet_session_subject':
      return { kind: 'derive_from_route_auth' };
  }
  input satisfies never;
  throw new Error('Unsupported Email OTP ECDSA export provider identity mode');
}

export type EmailOtpEcdsaExportStepUpInput =
  | EmailOtpEcdsaAuthorizedExportStepUpInput
  | EmailOtpEcdsaFreshLoginExportStepUpInput;

function emailOtpExpectedCurveForRouteChain(chain: EmailOtpRouteChain): 'ed25519' | 'ecdsa' {
  return chain === 'near' ? 'ed25519' : 'ecdsa';
}

function requireProvidedEmailOtpSigningSessionAuthLane(args: {
  authLane: EmailOtpSigningSessionAuthLane;
  chain: EmailOtpRouteChain;
  chainTarget?: ThresholdEcdsaChainTarget;
}): EmailOtpSigningSessionAuthLane {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'provided_route_auth',
      expectedCurve: emailOtpExpectedCurveForRouteChain(args.chain),
    });
  }
  return authLane;
}

function assertEmailOtpEcdsaExportCommittedLaneMatchesRecord(args: {
  committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
}): void {
  const record = args.committedLane.record;
  const authority = args.committedLane.walletSessionAuthority;
  if (
    authority.thresholdSessionId !== record.thresholdSessionId ||
    authority.signingGrantId !== record.signingGrantId
  ) {
    throw new Error(
      'Email OTP ECDSA export committed lane authority does not match the session record',
    );
  }
  if (
    args.committedLane.authLane.thresholdSessionId !== record.thresholdSessionId ||
    args.committedLane.authLane.authorizingSigningGrantId !== record.signingGrantId
  ) {
    throw new Error('Email OTP ECDSA export auth lane does not match the session record');
  }
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
    committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
  },
): EmailOtpEcdsaAuthorizedExportStepUpInput {
  assertEmailOtpEcdsaExportCommittedLaneMatchesRecord({
    committedLane: args.committedLane,
  });
  const record = args.committedLane.record;
  const roleLocalMaterial = parseThresholdEcdsaSessionRecordAsRoleLocalExportMaterial(record);
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: args.committedLane.authLane,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return {
    mode: 'export_step_up',
    source: 'authorized_signing_session',
    walletSession: args.walletSession,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    relayUrl: String(record.relayerUrl || ports.requireRelayUrl()).trim(),
    shamirPrimeB64u: String(ports.requireShamirPrimeB64u()).trim(),
    routePlan,
    record,
    keyHandle: String(toEvmFamilyEcdsaKeyHandle(record.keyHandle)),
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
    providerUserId?: string;
    emailHashHex: string;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  },
): Promise<EmailOtpEcdsaFreshLoginExportStepUpInput> {
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
  const providerUserId = String(args.providerUserId || '').trim();
  const base = {
    mode: 'export_step_up' as const,
    source: 'fresh_login' as const,
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    publicFacts: args.publicFacts,
    emailHashHex: args.emailHashHex,
    relayUrl,
    routePlan,
    runtimePolicyScope: args.runtimePolicyScope,
  };
  if (providerUserId) {
    return {
      ...base,
      providerIdentityMode: 'explicit_provider_user',
      providerUserId,
    };
  }
  return {
    ...base,
    providerIdentityMode: 'wallet_session_subject',
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
    case 'wallet_session_fresh_login_challenge':
      return args.walletSession;
    case 'near_account_challenge':
      return args.walletSession;
  }
}

export async function requestTransactionSigningChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<{ challengeId: string; emailHint?: string }> {
  if (args.kind === 'wallet_session_fresh_login_challenge') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'provided_route_auth',
      expectedCurve: 'ecdsa',
    });
  }
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: requireProvidedEmailOtpSigningSessionAuthLane({
      authLane: args.authLane,
      chain: args.chain,
    }),
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  const challenge =
    args.kind === 'near_account_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          walletSession: args.walletSession,
          nearAccountId: args.nearAccountId,
          routePlan,
        })
      : await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'wallet_session',
          walletId: args.walletSession.walletId,
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
  const routePlan =
    args.kind === 'wallet_session_fresh_login_challenge'
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
            authLane: args.authLane,
            chain: args.chain,
          }),
          operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
        });
  const challenge =
    args.kind === 'near_account_challenge'
      ? await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'near_account',
          walletSession: args.walletSession,
          nearAccountId: args.nearAccountId,
          routePlan,
        })
      : await requestEmailOtpChallengeWithRoutePlan(ports, {
          kind: 'wallet_session',
          walletId: args.walletSession.walletId,
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
    if (!args.record.emailOtpAuthContext) {
      throw new Error('Email OTP export requires record auth context');
    }
    const providerUserId = String(
      emailOtpAuthContextProviderUserId(args.record.emailOtpAuthContext),
    ).trim();
    if (!providerUserId) {
      throw new Error('Email OTP export requires record provider user ID');
    }
    return providerUserId;
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
  const record = args.committedLane.record;
  const walletId = record.walletId;
  if (String(record.nearAccountId) !== String(nearAccountId)) {
    throw new Error('Email OTP Ed25519 export nearAccountId mismatch');
  }
  const relayUrl = String(record.relayerUrl || ports.requireRelayUrl()).trim();
  const shamirPrimeB64u = String(ports.requireShamirPrimeB64u()).trim();
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP Ed25519 export requires the dedicated emailOtp worker');
  }
  const runtimePolicyScope = args.committedLane.record.runtimePolicyScope;
  const userId = requireEmailOtpExportAuthSubject({
    record,
    walletSessionUserId: String(walletId),
  });
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: args.committedLane.authLane,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  const walletSessionAuthority = args.committedLane.walletSessionAuthority;
  const workerResult = await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportEmailOtpEd25519SeedWithAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: String(walletId),
        nearAccountId: String(nearAccountId),
        nearEd25519SigningKeyId: String(record.nearEd25519SigningKeyId || '').trim(),
        userId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u,
        routePlan,
        otpChannel: EMAIL_OTP_CHANNEL,
        runtimePolicyScope,
        participantIds: args.committedLane.participantIds,
        thresholdSessionId: walletSessionAuthority.thresholdSessionId,
        walletSessionJwt: walletSessionAuthority.walletSessionJwt,
        relayerKeyId: args.committedLane.relayerKeyId,
        expectedPublicKey: args.committedLane.expectedPublicKey,
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
    committedLane: EcdsaExportLane<EmailOtpWalletAuthAuthority>;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const exportInput = resolveEmailOtpEcdsaAuthorizedExportStepUpInput(ports, args);
  const record = exportInput.record;
  const walletSessionAuthority = args.committedLane.walletSessionAuthority;
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
        walletSessionJwt: walletSessionAuthority.walletSessionJwt,
        ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
        relayerKeyId: walletSessionAuthority.relayerKeyId,
        readyRecord: exportInput.roleLocalMaterial.readyRecord,
        thresholdSessionId: walletSessionAuthority.thresholdSessionId,
        signingGrantId: walletSessionAuthority.signingGrantId,
        thresholdExpiresAtMs: walletSessionAuthority.thresholdExpiresAtMs,
        participantIds: walletSessionAuthority.participantIds.map(Number),
        keyHandle: exportInput.keyHandle,
        runtimePolicyScope: record.runtimePolicyScope,
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
    providerUserId?: string;
    emailHashHex: string;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
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
      emailHashHex: string;
      providerIdentity: EmailOtpEcdsaProviderIdentity;
      authSubjectId?: never;
      runtimePolicyScope: ThresholdRuntimePolicyScope;
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
    emailHashHex: exportInput.emailHashHex,
    providerIdentity: providerIdentityFromFreshEcdsaExportInput(exportInput),
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
