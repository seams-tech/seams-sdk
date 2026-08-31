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
import { resolveActiveEcdsaCapabilityRuntime } from '../../session/material/activeEcdsaCapabilityRuntime';
import type { ExactEcdsaSealedRuntime } from '../../session/material/ecdsaSealedRuntime';
import type { ActiveEcdsaCapabilityManifest } from '../../session/material/ecdsaCapabilityManifest';
import {
  emailOtpEcdsaSigningSessionAuthLane,
  resolveExactEmailOtpEcdsaSigningSessionAuthority,
} from '../../session/emailOtp/ecdsaSigningSessionAuthority';
import type { ExactEvmFamilyWalletSessionAuthorization } from '../../session/material/ecdsaSigningCapability';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  isEmailOtpWalletAuthAuthority,
  walletAuthAuthoritiesMatch,
  type EmailOtpWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../../session/material/ecdsaSigningCapability';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '../../threshold/sessionPolicy';
import type { RequestEmailOtpChallengeArgs } from '../../session/emailOtp/exportRecoveryRuntime';
import type { VerifiedEcdsaPublicFacts } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyChain, EvmFamilyLifecycleEventCallback } from './types';
import { emitEvmFamilySigningEvent } from './events';
import { type ResolvedEvmFamilyEcdsaSigningLane } from './ecdsaLanes';
import {
  throwEmailOtpSigningSessionAuthStateError,
  type EmailOtpEcdsaBootstrapAuthorization,
} from '../../session/emailOtp/routePlan';
import type {
  EmailOtpEcdsaProviderIdentity,
  EmailOtpThresholdEcdsaLoginResult,
} from '../../session/emailOtp/ecdsaLogin';
import type { EmailOtpAuthoritySelector } from '../../workerManager/workerTypes';
import { walletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { EmailOtpEcdsaSigningSessionCommittedLane } from './ecdsaSelection';
import type { EmailOtpTransactionSigningChallenge } from '../../session/emailOtp/publicTypes';
import { demoEmailOtpCodeFromDelivery } from '../../session/emailOtp/challengeDelivery';
import { resolveThresholdEcdsaSigningQueueKey } from '../../threshold/ecdsa/signingQueue';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

type WalletSessionEmailOtpChallengeArgs = Extract<
  RequestEmailOtpChallengeArgs,
  { kind: 'wallet_session_challenge' }
>;

export type EmailOtpEcdsaSigningSessionDeps = {
  resolveSigningSessionAuth: typeof resolveEmailOtpEcdsaSigningSessionAuth;
  withThresholdEcdsaSigningQueue: <T>(args: {
    queueKey: string;
    walletId: WalletId;
    enabled: boolean;
    task: () => Promise<T>;
  }) => Promise<T>;
  emailOtpSessions: {
    requestTransactionSigningChallenge: (
      args: WalletSessionEmailOtpChallengeArgs,
    ) => Promise<EmailOtpTransactionSigningChallenge>;
    loginWithEcdsaCapabilityInternal: (args: {
      walletSession: WalletSessionRef;
      authoritySelector: EmailOtpAuthoritySelector;
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

/** Auth-neutral material authorized by its own Email OTP factor. There is no
 * warm signing lane and no reauth anchor to name, so the authority is the
 * capability's own: the provider identity and email binding the manifest
 * already carries. The exact operation is named here too, so one challenge
 * cannot be minted for one operation and spent on another. */
export type EmailOtpEcdsaCapabilityStepUpAuthority = {
  kind: 'capability_step_up';
  capabilityAuthority: EmailOtpWalletAuthAuthority;
  materialActivation: MpcMaterialActivationRef;
  operationFingerprint: string;
  committedLane?: never;
  reauthLane?: never;
};

export type EmailOtpEcdsaStepUpAuthority =
  | {
      kind: 'live_session';
      committedLane: EmailOtpEcdsaSigningSessionCommittedLane;
      reauthLane?: never;
      capabilityAuthority?: never;
      materialActivation?: never;
      operationFingerprint?: never;
    }
  | EmailOtpEcdsaCapabilityStepUpAuthority;

export type EmailOtpEcdsaChallengeAuthority =
  | {
      kind: 'live_session';
      authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
      reauthLane?: never;
      capabilityAuthority?: never;
      materialActivation?: never;
      operationFingerprint?: never;
    }
  | (Omit<EmailOtpEcdsaCapabilityStepUpAuthority, 'committedLane' | 'reauthLane'> & {
      authLane?: never;
      reauthLane?: never;
    });

/** The capability is the authority. Anything the caller or the confirmation
 * plan supplies must agree with it exactly, or the OTP would be sent to a
 * different mailbox than the one bound to the material being signed with. */
export function emailOtpEcdsaCapabilityStepUpAuthority(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  materialActivation: MpcMaterialActivationRef;
  operationFingerprint: string;
  claimedAuthority?: WalletAuthAuthority;
}): EmailOtpEcdsaCapabilityStepUpAuthority {
  const capabilityAuthority = args.capability.authority;
  if (!isEmailOtpWalletAuthAuthority(capabilityAuthority)) {
    throw new Error(
      '[SigningEngine] Email OTP operation step-up requires an Email OTP capability authority',
    );
  }
  if (
    args.claimedAuthority &&
    !walletAuthAuthoritiesMatch(capabilityAuthority, args.claimedAuthority)
  ) {
    throw new Error(
      '[SigningEngine] Email OTP step-up authority does not match the selected capability',
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      args.capability.manifest.activation.materialActivation,
      args.materialActivation,
    )
  ) {
    throw new Error(
      '[SigningEngine] Email OTP step-up material activation does not match the selected capability',
    );
  }
  const operationFingerprint = String(args.operationFingerprint || '').trim();
  if (!operationFingerprint) {
    throw new Error(
      '[SigningEngine] Email OTP operation step-up requires an operation fingerprint',
    );
  }
  return {
    kind: 'capability_step_up',
    capabilityAuthority,
    materialActivation: args.materialActivation,
    operationFingerprint,
  };
}

function emailOtpEcdsaChallengeAuthority(
  authority: EmailOtpEcdsaStepUpAuthority,
): EmailOtpEcdsaChallengeAuthority {
  switch (authority.kind) {
    case 'live_session':
      if (authority.committedLane.authority.factor.kind !== 'email_otp') {
        throw new Error('[SigningEngine][ecdsa] Email OTP challenge requires Email OTP authority');
      }
      return {
        kind: 'live_session',
        authLane: authority.committedLane.authLane,
      };
    case 'capability_step_up':
      return {
        kind: 'capability_step_up',
        capabilityAuthority: authority.capabilityAuthority,
        materialActivation: authority.materialActivation,
        operationFingerprint: authority.operationFingerprint,
      };
  }
}

export function createEmailOtpEcdsaTransactionSigningBridge(args: {
  walletId: string;
  walletSession: WalletSessionRef;
  chain: EvmFamilyChain;
  selectedLane?: ResolvedEvmFamilyEcdsaSigningLane;
  authority: EmailOtpEcdsaStepUpAuthority;
  operationFingerprintDigest: DigestB64u;
  onEvent?: EvmFamilyLifecycleEventCallback;
  requestEmailOtpTransactionSigningChallenge?: (args: {
    walletSession: WalletSessionRef;
    chain: EvmFamilyChain;
    authority: EmailOtpEcdsaChallengeAuthority;
    operationFingerprintDigest: DigestB64u;
  }) => Promise<EmailOtpTransactionSigningChallenge>;
}): EvmFamilyEmailOtpTransactionSigningBridge {
  // One challenge belongs to one operation. A capability step-up mints its
  // challenge against the operation named in the authority, so re-minting for
  // a different operation would let a code approved for one transaction
  // authorize another.
  let mintedForOperationFingerprint: string | null = null;
  return {
    challenge: async () => {
      if (typeof args.requestEmailOtpTransactionSigningChallenge !== 'function') {
        throw new Error('[SigningEngine] Email OTP ECDSA signing step-up is not configured');
      }
      if (args.authority.kind === 'capability_step_up') {
        if (
          mintedForOperationFingerprint !== null &&
          mintedForOperationFingerprint !== args.authority.operationFingerprint
        ) {
          throw new Error(
            '[SigningEngine] Email OTP step-up challenge is bound to a different operation',
          );
        }
        mintedForOperationFingerprint = args.authority.operationFingerprint;
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
        operationFingerprintDigest: args.operationFingerprintDigest,
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
export async function resolveEmailOtpEcdsaSigningSessionAuth(args: {
  walletId: WalletId;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<{
  manifest: ActiveEcdsaCapabilityManifest;
  runtime: ExactEcdsaSealedRuntime;
  authority: ExactEvmFamilyWalletSessionAuthorization;
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
  const authority = await resolveExactEmailOtpEcdsaSigningSessionAuthority({
    walletId: args.walletId,
    chainTarget: args.chainTarget,
    manifest: resolved.manifest,
    runtime: resolved.runtime,
  });
  if (!authority) {
    throwEmailOtpSigningSessionAuthStateError({
      kind: 'auth_lane_missing',
      source: 'evm_signing_refresh',
      expectedCurve: 'ecdsa',
    });
  }
  return {
    manifest: resolved.manifest,
    runtime: resolved.runtime,
    authority,
  };
}

export async function requestEmailOtpSigningSessionChallenge(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: {
    walletSession: WalletSessionRef;
    chainTarget: ThresholdEcdsaChainTarget;
  },
): Promise<EmailOtpTransactionSigningChallenge> {
  const { authority } = await deps.resolveSigningSessionAuth({
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  return await deps.emailOtpSessions.requestTransactionSigningChallenge({
    kind: 'wallet_session_challenge',
    walletSession: args.walletSession,
    chain: args.chainTarget.kind,
    authLane: emailOtpEcdsaSigningSessionAuthLane(authority),
  });
}

type RefreshEmailOtpSigningSessionArgs = {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  ttlMs?: number;
  remainingUses?: number;
};

async function resolveFencedEmailOtpSigningSessionAuth(input: {
  deps: EmailOtpEcdsaSigningSessionDeps;
  args: RefreshEmailOtpSigningSessionArgs;
  activationBeforeRefresh: MpcMaterialActivationRef;
  phase: 'before use' | 'during refresh';
}): ReturnType<EmailOtpEcdsaSigningSessionDeps['resolveSigningSessionAuth']> {
  let current: Awaited<ReturnType<EmailOtpEcdsaSigningSessionDeps['resolveSigningSessionAuth']>>;
  try {
    current = await input.deps.resolveSigningSessionAuth({
      walletId: input.args.walletSession.walletId,
      chainTarget: input.args.chainTarget,
    });
  } catch {
    throw new Error(
      `[SigningEngine][ecdsa] Email OTP signing-session refresh material was superseded ${input.phase}`,
    );
  }
  if (
    !mpcMaterialActivationRefsEqual(
      current.runtime.materialActivation,
      input.activationBeforeRefresh,
    )
  ) {
    throw new Error(
      `[SigningEngine][ecdsa] Email OTP signing-session refresh material was superseded ${input.phase}`,
    );
  }
  return current;
}

async function runFencedEmailOtpSigningSessionRefresh(input: {
  deps: EmailOtpEcdsaSigningSessionDeps;
  args: RefreshEmailOtpSigningSessionArgs;
  activationBeforeRefresh: MpcMaterialActivationRef;
}): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const { manifest, runtime, authority } = await resolveFencedEmailOtpSigningSessionAuth({
    deps: input.deps,
    args: input.args,
    activationBeforeRefresh: input.activationBeforeRefresh,
    phase: 'before use',
  });
  const routePlan = buildEmailOtpRoutePlan({
    routeFamily: 'signing_session',
    authLane: emailOtpEcdsaSigningSessionAuthLane(authority),
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
  });
  // Public facts are the manifest's half of the capability split.
  const publicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: toEvmFamilyEcdsaKeyHandle(
      String(manifest.durableMaterial.roleLocalPublicFacts.keyHandle),
    ),
    publicKeyB64u: runtime.thresholdEcdsaPublicKeyB64u,
    participantIds: [...runtime.participantIds],
    thresholdOwnerAddress: manifest.durableMaterial.roleLocalPublicFacts.ethereumAddress,
  });
  const emailOtpBinding = runtime.authBinding;
  if (emailOtpBinding.kind !== 'email_otp') {
    throw new Error('Email OTP signing-session refresh requires an Email OTP sealed runtime');
  }
  const refreshed = await input.deps.emailOtpSessions.loginWithEcdsaCapabilityInternal({
    walletSession: input.args.walletSession,
    authoritySelector: {
      kind: 'wallet_auth_method',
      walletAuthMethodId: String(
        (await walletAuthAuthorityRef({ authority: emailOtpBinding.emailOtpAuthority }))
          .walletAuthMethodId,
      ),
    },
    chainTarget: input.args.chainTarget,
    emailOtpAuthPolicy: 'session',
    emailOtpAuthReason: 'sign',
    challengeId: input.args.challengeId,
    otpCode: input.args.otpCode,
    operation: WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION,
    routePlan,
    publicFacts,
    ecdsaBootstrapAuthorization: { kind: 'route_plan_auth' },
    providerIdentity: {
      kind: 'explicit_provider_user',
      provider: emailOtpBinding.emailOtpAuthority.factor.provider,
      providerUserId: emailOtpBinding.providerSubjectId,
    },
    emailHashHex: emailOtpBinding.emailHashHex,
    ...(typeof input.args.ttlMs === 'number' ? { ttlMs: input.args.ttlMs } : {}),
    ...(typeof input.args.remainingUses === 'number'
      ? { remainingUses: input.args.remainingUses }
      : {}),
    ...(runtime.runtimePolicyScope ? { runtimePolicyScope: runtime.runtimePolicyScope } : {}),
  });
  // Refresh renews authorization over the same material; it must never land on
  // a different activation, and it never invokes recovery or device linking.
  await resolveFencedEmailOtpSigningSessionAuth({
    deps: input.deps,
    args: input.args,
    activationBeforeRefresh: input.activationBeforeRefresh,
    phase: 'during refresh',
  });
  return refreshed;
}

export async function refreshEmailOtpSigningSession(
  deps: EmailOtpEcdsaSigningSessionDeps,
  args: RefreshEmailOtpSigningSessionArgs,
): Promise<EmailOtpThresholdEcdsaLoginResult> {
  const initial = await deps.resolveSigningSessionAuth({
    walletId: args.walletSession.walletId,
    chainTarget: args.chainTarget,
  });
  const activationBeforeRefresh = initial.runtime.materialActivation;
  return await deps.withThresholdEcdsaSigningQueue({
    queueKey: resolveThresholdEcdsaSigningQueueKey({
      materialActivation: activationBeforeRefresh,
    }),
    walletId: args.walletSession.walletId,
    enabled: true,
    task: runFencedEmailOtpSigningSessionRefresh.bind(undefined, {
      deps,
      args,
      activationBeforeRefresh,
    }),
  });
}
