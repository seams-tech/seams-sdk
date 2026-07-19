import type { AccountId } from '@/core/types/accountIds';
import { type VerifiedEcdsaPublicFacts } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import type { EmailOtpEd25519YaoActiveCapabilityDescriptorV1 } from '@/core/signingEngine/workerManager/workerTypes';
import { throwEmailOtpSigningSessionAuthStateError } from './routePlan';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  EcdsaExportLane,
  EmailOtpEcdsaPublicReauthExportAuthority,
} from '../../flows/recovery/ecdsaExportMaterial';
import {
  EMAIL_OTP_CHANNEL,
  WALLET_EMAIL_OTP_EXPORT_OPERATION,
  WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  type WalletEmailOtpExportOperation,
  type WalletEmailOtpTransactionSignOperation,
} from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  emailOtpAuthContextEmailHashHex,
  emailOtpAuthContextProviderUserId,
} from '../identity/laneIdentity';
import type { RequestEmailOtpChallengeArgs } from './exportRecoveryRuntime';
import type {
  EmailOtpThresholdEcdsaLoginResult,
  LoginEmailOtpEcdsaCapabilityArgs,
} from './ecdsaLogin';
import type { EmailOtpEcdsaSigningSessionAuthority } from './ecdsaSigningSessionAuthority';
import { exportEcdsaDerivationKeyWithEmailOtpSession } from '../../flows/recovery/ecdsaDerivationExport';

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

type EmailOtpEcdsaExportLogin = (
  args: LoginEmailOtpEcdsaCapabilityArgs,
) => Promise<EmailOtpThresholdEcdsaLoginResult>;

type EmailOtpWorkerPorts = {
  getSignerWorkerContext: () => WorkerOperationContext | null | undefined;
  requireRelayUrl: () => string;
  requireShamirPrimeB64u: () => string;
  buildSigningSessionRoutePlan: (args: {
    authLane: EmailOtpSigningSessionAuthLane;
    operation: EmailOtpSigningSessionChallengeOperation;
  }) => EmailOtpRoutePlan;
};

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

async function requestEmailOtpChallengeWithRoutePlan(
  ports: Pick<EmailOtpWorkerPorts, 'getSignerWorkerContext' | 'requireRelayUrl'>,
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
): Promise<{ challengeId: string; emailHint?: string }> {
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
  return {
    challengeId,
    ...(String(response.emailHint || '').trim()
      ? { emailHint: String(response.emailHint || '').trim() }
      : {}),
  };
}

export async function requestTransactionSigningChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<{ challengeId: string; emailHint?: string }> {
  const routePlan = buildTransactionSigningChallengeRoutePlan(ports, args);
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

function buildTransactionSigningChallengeRoutePlan(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): EmailOtpRoutePlan {
  switch (args.kind) {
    case 'wallet_public_reauth_challenge':
      return buildEmailOtpRoutePlan({
        routeFamily: 'login',
        authLane: { kind: 'app_session', jwt: args.appSessionJwt },
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
    case 'wallet_session_challenge':
    case 'near_account_challenge':
      return ports.buildSigningSessionRoutePlan({
        authLane: requireProvidedEmailOtpSigningSessionAuthLane({
          authLane: args.authLane,
          chain: args.chain,
        }),
        operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
      });
  }
}

export async function requestExportChallenge(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): Promise<{ challengeId: string; emailHint?: string }> {
  const routePlan = buildExportChallengeRoutePlan(ports, args);
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

function buildExportChallengeRoutePlan(
  ports: EmailOtpWorkerPorts,
  args: RequestEmailOtpChallengeArgs,
): EmailOtpRoutePlan {
  switch (args.kind) {
    case 'wallet_public_reauth_challenge':
      return buildEmailOtpRoutePlan({
        routeFamily: 'login',
        authLane: { kind: 'app_session', jwt: args.appSessionJwt },
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      });
    case 'wallet_session_challenge':
    case 'near_account_challenge':
      return ports.buildSigningSessionRoutePlan({
        authLane: requireProvidedEmailOtpSigningSessionAuthLane({
          authLane: args.authLane,
          chain: args.chain,
        }),
        operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
      });
  }
}

export async function exportEd25519YaoSeedWithFreshEmailOtpLane(
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
    providerSubjectId: string;
    walletSessionJwt: string;
    nearAccountId: string;
    nearEd25519SigningKeyId: string;
    signerSlot: number;
    thresholdSessionId: string;
    signingGrantId: string;
    authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    capability: EmailOtpEd25519YaoActiveCapabilityDescriptorV1;
  },
): Promise<{ artifactKind: 'near-ed25519-seed-v1'; publicKey: string; privateKey: string }> {
  const workerCtx = ports.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP Ed25519 Yao export requires the dedicated emailOtp worker');
  }
  const relayUrl = ports.requireRelayUrl();
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: args.authLane,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await workerCtx.requestWorkerOperation({
    kind: 'emailOtp',
    request: {
      type: 'exportEmailOtpEd25519YaoSeedWithAuthorization',
      timeoutMs: 60_000,
      payload: {
        relayUrl,
        walletId: args.walletSession.walletId,
        userId: args.providerSubjectId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u: ports.requireShamirPrimeB64u(),
        routePlan,
        walletSessionJwt: args.walletSessionJwt,
        nearAccountId: args.nearAccountId,
        nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
        signerSlot: args.signerSlot,
        thresholdSessionId: args.thresholdSessionId,
        signingGrantId: args.signingGrantId,
        runtimePolicyScope: args.runtimePolicyScope,
        capability: args.capability,
      },
    },
  });
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
    loginWithEcdsaCapabilityInternal: EmailOtpEcdsaExportLogin;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  assertEmailOtpEcdsaExportCommittedLaneMatchesRecord({
    committedLane: args.committedLane,
  });
  const record = args.committedLane.record;
  if (record.source !== 'email_otp' || !record.emailOtpAuthContext) {
    throw new Error('Email OTP ECDSA export requires Email OTP record authority');
  }
  if (!record.runtimePolicyScope) {
    throw new Error('Email OTP ECDSA export requires runtime policy scope');
  }
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: args.committedLane.authLane,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await exportEcdsaKeyWithFreshLoginAuthorization({
    walletSession: args.walletSession,
    chainTarget: record.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    routePlan,
    keyHandle: record.keyHandle,
    participantIds: record.participantIds.map(Number),
    emailHashHex: emailOtpAuthContextEmailHashHex(record.emailOtpAuthContext),
    providerUserId: emailOtpAuthContextProviderUserId(record.emailOtpAuthContext),
    runtimePolicyScope: record.runtimePolicyScope,
    relayUrl: String(record.relayerUrl || ports.requireRelayUrl()).trim(),
    getSignerWorkerContext: ports.getSignerWorkerContext,
    loginWithEcdsaCapabilityInternal: args.loginWithEcdsaCapabilityInternal,
  });
}

export async function exportEcdsaKeyWithDurableAuthorization(
  ports: Pick<
    EmailOtpWorkerPorts,
    'getSignerWorkerContext' | 'requireRelayUrl' | 'buildSigningSessionRoutePlan'
  >,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    publicFacts: VerifiedEcdsaPublicFacts;
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    signingSessionAuthority: EmailOtpEcdsaSigningSessionAuthority;
    loginWithEcdsaCapabilityInternal: EmailOtpEcdsaExportLogin;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const routePlan = ports.buildSigningSessionRoutePlan({
    authLane: args.signingSessionAuthority.authLane,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await exportEcdsaKeyWithFreshLoginAuthorization({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    routePlan,
    keyHandle: String(args.publicFacts.keyHandle),
    participantIds: args.publicFacts.participantIds.map(Number),
    emailHashHex: args.signingSessionAuthority.authority.verifier.emailHashHex,
    providerUserId: args.signingSessionAuthority.authority.factor.providerUserId,
    runtimePolicyScope: args.runtimePolicyScope,
    relayUrl: ports.requireRelayUrl(),
    getSignerWorkerContext: ports.getSignerWorkerContext,
    loginWithEcdsaCapabilityInternal: args.loginWithEcdsaCapabilityInternal,
  });
}

export async function exportEcdsaKeyWithPublicReauthAuthorization(
  ports: Pick<EmailOtpWorkerPorts, 'getSignerWorkerContext' | 'requireRelayUrl'>,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    appSessionJwt: string;
    publicReauthAuthority: EmailOtpEcdsaPublicReauthExportAuthority;
    loginWithEcdsaCapabilityInternal: EmailOtpEcdsaExportLogin;
  },
): Promise<EmailOtpEcdsaExportArtifact> {
  const authority = args.publicReauthAuthority;
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'login',
    authLane: { kind: 'app_session', jwt: args.appSessionJwt },
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
  });
  return await exportEcdsaKeyWithFreshLoginAuthorization({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    routePlan,
    keyHandle: authority.keyHandle,
    participantIds: authority.participantIds.map(Number),
    emailHashHex: authority.emailHashHex,
    providerUserId: authority.providerSubjectId,
    runtimePolicyScope: authority.runtimePolicyScope,
    relayUrl: ports.requireRelayUrl(),
    getSignerWorkerContext: ports.getSignerWorkerContext,
    loginWithEcdsaCapabilityInternal: args.loginWithEcdsaCapabilityInternal,
  });
}

type ExportEcdsaKeyWithFreshLoginAuthorizationArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  routePlan: EmailOtpRoutePlan;
  keyHandle: string;
  participantIds: number[];
  emailHashHex: string;
  providerUserId: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayUrl: string;
  getSignerWorkerContext: EmailOtpWorkerPorts['getSignerWorkerContext'];
  loginWithEcdsaCapabilityInternal: EmailOtpEcdsaExportLogin;
};

async function exportEcdsaKeyWithFreshLoginAuthorization(
  args: ExportEcdsaKeyWithFreshLoginAuthorizationArgs,
): Promise<EmailOtpEcdsaExportArtifact> {
  const result = await args.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    relayUrl: args.relayUrl,
    emailOtpAuthPolicy: 'per_operation',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_EXPORT_OPERATION,
    routePlan: args.routePlan,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    keyHandle: args.keyHandle,
    participantIds: args.participantIds,
    remainingUses: 1,
    emailHashHex: args.emailHashHex,
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: args.providerUserId,
    },
    runtimePolicyScope: args.runtimePolicyScope,
    ed25519YaoRecovery: { kind: 'not_requested' },
  });
  const workerCtx = args.getSignerWorkerContext();
  if (!workerCtx) {
    throw new Error('Email OTP ECDSA export requires the dedicated signer worker');
  }
  return await exportEcdsaDerivationKeyWithEmailOtpSession(
    { getSignerWorkerContext: () => workerCtx },
    {
      walletSessionUserId: args.walletSession.walletSessionUserId,
      bootstrap: result.bootstrap,
    },
  );
}
