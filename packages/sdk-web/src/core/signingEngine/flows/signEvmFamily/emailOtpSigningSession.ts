import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION } from '@shared/utils/emailOtpDomain';
import {
  buildEmailOtpRoutePlan,
  type EmailOtpSigningSessionAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { EmailOtpEcdsaSigningBootstrapResult } from '../../interfaces/operationDeps';
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import type { ExactEcdsaSealedRuntime } from '../../session/material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';
import { resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime } from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { ThresholdEcdsaSessionStoreDeps } from '../../session/persistence/records';
import {
} from '../../session/persistence/records';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RequestEmailOtpChallengeArgs } from '../../session/emailOtp/exportRecoveryRuntime';
import {
  type VerifiedEcdsaPublicFacts,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { emitEvmFamilySigningEvent } from './events';
import { type ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import {
  throwEmailOtpSigningSessionAuthStateError,
  type EmailOtpEcdsaBootstrapAuthorization,
} from '../../session/emailOtp/routePlan';
import {
  type EmailOtpEcdsaProviderIdentity,
  type EmailOtpThresholdEcdsaLoginResult,
} from '../../session/emailOtp/ecdsaLogin';
import {
  type EmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import type { EmailOtpEcdsaCommittedLane, EmailOtpEcdsaPublicReauthLane } from './ecdsaSelection';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import { demoEmailOtpCodeFromDelivery } from '../../session/emailOtp/challengeDelivery';

type WalletSessionEmailOtpChallengeArgs = Extract<
  RequestEmailOtpChallengeArgs,
  { kind: 'wallet_session_challenge' }
>;

export type EmailOtpEcdsaSigningSessionDeps = {
  ecdsaSessions: ThresholdEcdsaSessionStoreDeps;
  emailOtpSessions: {
    requestTransactionSigningChallenge: (
      args: WalletSessionEmailOtpChallengeArgs,
    ) => Promise<EmailOtpTransactionSigningChallenge>;
    loginWithEcdsaCapabilityInternal: (args: {
      walletSession: WalletSessionRef;
      subjectId?: never;
      chainTarget: ThresholdEcdsaChainTarget;
      emailOtpAuthPolicy?: EmailOtpAuthPolicy;
      emailOtpAuthReason?: 'login' | 'sign';
      challengeId?: string;
      otpCode: string;
      operation?: typeof WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION;
      routePlan: ReturnType<typeof buildEmailOtpRoutePlan>;
      publicFacts: VerifiedEcdsaPublicFacts;
      participantIds?: never;
      ttlMs?: number;
      remainingUses?: number;
      runtimePolicyScope?: ThresholdRuntimePolicyScope;
      routeAuth?: never;
      ecdsaBootstrapAuthorization: EmailOtpEcdsaBootstrapAuthorization;
      providerIdentity: EmailOtpEcdsaProviderIdentity;
      emailHashHex: string;
      authSubjectId?: never;
    }) => Promise<EmailOtpThresholdEcdsaLoginResult>;
  };
};

export type EvmFamilyEmailOtpTransactionSigningBridge = {
  challenge: () => Promise<{
    challengeId: string;
    email: string;
  }>;
};

export type EmailOtpEcdsaStepUpAuthority =
  | {
      kind: 'live_session';
      committedLane: EmailOtpEcdsaCommittedLane;
      reauthLane?: never;
    }
  | {
      kind: 'public_reauth_anchor';
      reauthLane: EmailOtpEcdsaPublicReauthLane;
      committedLane?: never;
    };

export type EmailOtpEcdsaChallengeAuthority =
  | {
      kind: 'live_session';
      authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
      reauthLane?: never;
    }
  | {
      kind: 'public_reauth_anchor';
      reauthLane: EmailOtpEcdsaPublicReauthLane;
      authLane?: never;
    };

function emailOtpEcdsaChallengeAuthority(
  authority: EmailOtpEcdsaStepUpAuthority,
): EmailOtpEcdsaChallengeAuthority {
  switch (authority.kind) {
    case 'live_session':
      return {
        kind: 'live_session',
        authLane: authority.committedLane.authLane,
      };
    case 'public_reauth_anchor':
      return {
        kind: 'public_reauth_anchor',
        reauthLane: authority.reauthLane,
      };
  }
}

export function createEmailOtpEcdsaTransactionSigningBridge(args: {
  walletId: string;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  selectedLane?: ResolvedEvmFamilyEcdsaSigningLane;
  authority: EmailOtpEcdsaStepUpAuthority;
  onEvent?: EvmFamilyLifecycleEventCallback;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authority: EmailOtpEcdsaChallengeAuthority;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
}): EvmFamilyEmailOtpTransactionSigningBridge {
  return {
    challenge: async () => {
      if (typeof args.requestEmailOtpTransactionSigningChallenge !== 'function') {
        throw new Error('[SigningEngine] Email OTP ECDSA signing step-up is not configured');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED,
        status: 'running',
        walletId: args.walletId,
        interaction: { kind: 'none', overlay: 'none' },
      });
      emitSigningBoundaryTrace(
        'evm-family',
        createSigningBoundaryTraceEvent({
          event: 'auth_side_effect_started',
          lane: args.selectedLane,
          sideEffect: 'email_otp_challenge',
          phase: 'confirmed',
        }),
      );
      const challenge = await args.requestEmailOtpTransactionSigningChallenge({
        walletSession: args.walletSession,
        chain: args.chain,
        authority: emailOtpEcdsaChallengeAuthority(args.authority),
      });
      const challengeId = String(challenge.challengeId || '').trim();
      if (!challengeId) {
        throw new Error('[SigningEngine] Email OTP challenge response did not include challengeId');
      }
      emitEvmFamilySigningEvent(args.onEvent, {
        phase: SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED,
        status: 'waiting_for_user',
        walletId: args.walletId,
        interaction: { kind: 'otp_input', overlay: 'show' },
        data: {
          emailHint: challenge.emailHint,
          demoOtpCode: demoEmailOtpCodeFromDelivery(challenge.delivery),
        },
      });
      return {
        challengeId,
        email: String(challenge.emailHint || '').trim(),
      };
    },
  };
}

/** Canonical Email OTP signing-session resolution: the manifest proves exact
 * material, the sealed runtime supplies session-scoped facts and the Email OTP
 * binding, and the reusable Wallet Session is resolved independently. Refresh
 * must land on the same material activation it started from, so the caller
 * checks that before and after; nothing here invokes Yao recovery or device
 * linking. */
async function resolveEmailOtpEcdsaSigningSessionAuth(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<{
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  authority: EmailOtpEcdsaSigningSessionAuthority;
}> {
  const resolved = await resolveActiveEcdsaCapabilityRuntime({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
  });
  if (resolved.kind !== 'resolved') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'evm_signing_refresh',
      expectedCurve: 'ecdsa',
    });
  }
  const authorizationRead = await walletSessionAuthorizations.readActiveForWallet(args.walletId);
  if (authorizationRead.kind !== 'found') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'evm_signing_refresh',
      expectedCurve: 'ecdsa',
    });
  }
  const authorityResolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
    runtime: resolved.runtime,
    authorization: authorizationRead.projection,
  });
  if (authorityResolution.kind !== 'ready') {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'evm_signing_refresh',
      expectedCurve: 'ecdsa',
    });
  }
  return {
    manifest: resolved.manifest,
    runtime: resolved.runtime,
    authority: authorityResolution.authority,
  };
}

export async function requestEmailOtpSigningSessionChallenge(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<EmailOtpTransactionSigningChallenge> {
  const { authority } = await resolveEmailOtpEcdsaSigningSessionAuth({
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  return await deps.emailOtpSessions.requestTransactionSigningChallenge({
    kind: 'wallet_session_challenge',
    walletSession: args.walletSession,
    chain: args.chainTarget.kind,
    authLane: authority.authLane,
  });
}

export async function refreshEmailOtpSigningSession(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
    challengeId: string;
    otpCode: string;
    ttlMs?: number;
    remainingUses?: number;
  },
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const { manifest, runtime, authority } = await resolveEmailOtpEcdsaSigningSessionAuth({
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  const activationBeforeRefresh = runtime.materialActivation;
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane: authority.authLane,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  // Public facts are the manifest's half of the capability split.
  const publicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(String(manifest.durableMaterial.roleLocalPublicFacts.keyHandle)),
    publicKeyB64u: runtime.thresholdEcdsaPublicKeyB64u,
    participantIds: [...runtime.participantIds],
    thresholdOwnerAddress: manifest.durableMaterial.roleLocalPublicFacts.ethereumAddress,
  });
  const emailOtpBinding = runtime.authBinding;
  if (emailOtpBinding.kind !== 'email_otp') {
    throw new Error('Email OTP signing-session refresh requires an Email OTP sealed runtime');
  }
  const refreshed = await deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
    walletSession: args.walletSession,
    chainTarget: args.chainTarget,
    emailOtpAuthPolicy: 'session',
    emailOtpAuthReason: 'sign',
    challengeId: args.challengeId,
    otpCode: args.otpCode,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    routePlan,
    publicFacts,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    providerIdentity: {
      kind: 'explicit_provider_user',
      providerUserId: emailOtpBinding.providerSubjectId,
    },
    emailHashHex: emailOtpBinding.emailHashHex,
    ...(typeof args.ttlMs === 'number' ? { ttlMs: args.ttlMs } : {}),
    ...(typeof args.remainingUses === 'number' ? { remainingUses: args.remainingUses } : {}),
    ...(runtime.runtimePolicyScope ? { runtimePolicyScope: runtime.runtimePolicyScope } : {}),
  });
  // Refresh renews authorization over the same material; it must never land on
  // a different activation, and it never invokes recovery or device linking.
  const activationAfterRefresh = (
    await resolveActiveEcdsaCapabilityRuntime({
      walletId: args.walletSession.walletId,
      chainTarget: args.chainTarget,
    })
  );
  if (
    activationAfterRefresh.kind === 'resolved' &&
    !mpcMaterialActivationRefsEqual(
      activationAfterRefresh.runtime.materialActivation,
      activationBeforeRefresh,
    )
  ) {
    throw new Error(
      '[SigningEngine][ecdsa] Email OTP signing-session refresh changed the material activation',
    );
  }
  return refreshed;
}
