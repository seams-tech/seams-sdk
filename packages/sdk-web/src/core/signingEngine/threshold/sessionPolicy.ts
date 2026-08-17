import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
  MAX_WALLET_SESSION_REMAINING_USES,
  MAX_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import type { WebAuthnRpId } from '@shared/utils/domainIds';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { SigningOperationId } from '../session/operationState/types';

export type ThresholdRuntimePolicyScope = RuntimePolicyScope;

export const THRESHOLD_SESSION_POLICY_VERSION = 'threshold_session_v1' as const;

export type Ed25519AuthorityScope =
  | {
      kind: 'passkey_rp';
      rpId: WebAuthnRpId;
      proofKind?: never;
      email?: never;
      provider?: never;
      providerUserId?: never;
      challengeId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    }
  | {
      kind: 'email_otp';
      provider: 'google' | 'email';
      providerUserId: string;
      proofKind?: never;
      rpId?: never;
      email?: never;
      challengeId?: never;
      googleEmailOtpRegistrationAttemptId?: never;
      googleEmailOtpRegistrationOfferId?: never;
      googleEmailOtpRegistrationCandidateId?: never;
    };

export type Ed25519SessionPolicyAuthority = {
  kind: 'wallet_auth_authority';
  authority: WalletAuthAuthority;
  authorityScope?: never;
  rpId?: never;
};

export type PasskeyEd25519SessionPolicyAuthority = {
  kind: 'wallet_auth_authority';
  authority: PasskeyWalletAuthAuthority;
  authorityScope?: never;
  rpId?: never;
};

export type EmailOtpEd25519SessionPolicyAuthority = {
  kind: 'wallet_auth_authority';
  authority: EmailOtpWalletAuthAuthority;
  authorityScope?: never;
  rpId?: never;
};

export function normalizeThresholdRuntimePolicyScope(
  value: unknown,
): ThresholdRuntimePolicyScope | undefined {
  try {
    return normalizeRuntimePolicyScope(value);
  } catch {
    return undefined;
  }
}

export type Ed25519SessionPolicy = {
  version: typeof THRESHOLD_SESSION_POLICY_VERSION;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authority: WalletAuthAuthority;
  relayerKeyId: string;
  thresholdSessionId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  /**
   * Optional signer set binding (participant ids).
   *
   * When present, the relayer must bind the session token to this signer set and ensure
   * downstream signature share usage is scoped to the same set.
   */
  participantIds?: number[];
  ttlMs: number;
  remainingUses: number;
};

type Ed25519SessionPolicyBuildResult = Promise<{
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
}>;

type Ed25519SessionPolicyBaseParams = {
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  participantIds?: number[];
  thresholdSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
};

export type BuildPasskeyEd25519SessionPolicyParams = Ed25519SessionPolicyBaseParams & {
  authority: PasskeyWalletAuthAuthority;
  authorityScope?: never;
  rpId?: never;
};

export type BuildEmailOtpEd25519SessionPolicyParams = Ed25519SessionPolicyBaseParams & {
  authority: EmailOtpWalletAuthAuthority;
  rpId?: never;
  authorityScope?: never;
};

type BuildExactEd25519SessionPolicyParams = Ed25519SessionPolicyBaseParams & {
  authority: WalletAuthAuthority;
  rpId?: never;
  authorityScope?: never;
};

// Upper bounds to avoid unbounded TTL/use values while still supporting practical
// "login once, sign many times" sessions.
export const THRESHOLD_SESSION_POLICY_MAX_TTL_MS = MAX_WALLET_SESSION_TTL_MS;
export const THRESHOLD_SESSION_POLICY_MAX_USES = MAX_WALLET_SESSION_REMAINING_USES;
export const DEFAULT_THRESHOLD_SESSION_TTL_MS = DEFAULT_WALLET_SESSION_TTL_MS;

// Default policy used when callers do not specify a policy explicitly.
// The use budget still limits authority during the longer wallet-unlock interval.
export const DEFAULT_THRESHOLD_SESSION_POLICY: Pick<
  Ed25519SessionPolicy,
  'ttlMs' | 'remainingUses'
> = {
  ttlMs: DEFAULT_THRESHOLD_SESSION_TTL_MS,
  remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
};

export const DEFAULT_UNLOCK_REMAINING_USES = DEFAULT_WALLET_SESSION_REMAINING_USES;

export type PositiveRemainingUses = number & {
  readonly __brand: 'PositiveRemainingUses';
};

export function parsePositiveSessionUses(value: unknown, fieldName: string): PositiveRemainingUses {
  const remainingUses = Math.floor(Number(value) || 0);
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error(`[ThresholdSessionPolicy] ${fieldName} must be a positive integer`);
  }
  return remainingUses as PositiveRemainingUses;
}

export function resolveWalletUnlockSessionUsesFromRequestedUses(args: {
  requestedRemainingUses: unknown;
}): number | null {
  const normalized = Math.floor(Number(args.requestedRemainingUses) || 0);
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  return Math.min(normalized, DEFAULT_UNLOCK_REMAINING_USES);
}

export function clampThresholdSessionPolicy(input: { ttlMs: number; remainingUses: number }): {
  ttlMs: number;
  remainingUses: number;
} {
  const ttlMs = Math.max(0, Math.floor(Number(input.ttlMs) || 0));
  const remainingUses = Math.max(0, Math.floor(Number(input.remainingUses) || 0));
  return {
    ttlMs: Math.min(ttlMs, THRESHOLD_SESSION_POLICY_MAX_TTL_MS),
    remainingUses: Math.min(remainingUses, THRESHOLD_SESSION_POLICY_MAX_USES),
  };
}

export function generateThresholdSessionId(): string {
  return secureRandomId('tsess', 32, 'threshold session IDs');
}

export async function computeEd25519SessionPolicyDigest32(
  policy: Ed25519SessionPolicy,
): Promise<string> {
  const json = alphabetizeStringify(policy);
  const bytes = await sha256BytesUtf8(json);
  return base64UrlEncode(bytes);
}

export async function buildEd25519SessionPolicy(params: {
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authority: Ed25519SessionPolicyAuthority;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  participantIds?: number[];
  thresholdSessionId?: string;
  ttlMs?: number;
  remainingUses?: number;
}): Ed25519SessionPolicyBuildResult {
  return buildExactEd25519SessionPolicy({
    nearAccountId: params.nearAccountId,
    nearEd25519SigningKeyId: params.nearEd25519SigningKeyId,
    authority: params.authority.authority,
    relayerKeyId: params.relayerKeyId,
    runtimePolicyScope: params.runtimePolicyScope,
    routerAbNormalSigning: params.routerAbNormalSigning,
    participantIds: params.participantIds,
    thresholdSessionId: params.thresholdSessionId,
    ttlMs: params.ttlMs,
    remainingUses: params.remainingUses,
  });
}

export async function buildPasskeyEd25519SessionPolicy(
  params: BuildPasskeyEd25519SessionPolicyParams,
): Ed25519SessionPolicyBuildResult {
  return buildExactEd25519SessionPolicy({
    nearAccountId: params.nearAccountId,
    nearEd25519SigningKeyId: params.nearEd25519SigningKeyId,
    authority: params.authority,
    relayerKeyId: params.relayerKeyId,
    runtimePolicyScope: params.runtimePolicyScope,
    routerAbNormalSigning: params.routerAbNormalSigning,
    participantIds: params.participantIds,
    thresholdSessionId: params.thresholdSessionId,
    ttlMs: params.ttlMs,
    remainingUses: params.remainingUses,
  });
}

export async function buildEmailOtpEd25519SessionPolicy(
  params: BuildEmailOtpEd25519SessionPolicyParams,
): Ed25519SessionPolicyBuildResult {
  return buildExactEd25519SessionPolicy({
    nearAccountId: params.nearAccountId,
    nearEd25519SigningKeyId: params.nearEd25519SigningKeyId,
    authority: params.authority,
    relayerKeyId: params.relayerKeyId,
    runtimePolicyScope: params.runtimePolicyScope,
    routerAbNormalSigning: params.routerAbNormalSigning,
    participantIds: params.participantIds,
    thresholdSessionId: params.thresholdSessionId,
    ttlMs: params.ttlMs,
    remainingUses: params.remainingUses,
  });
}

async function buildExactEd25519SessionPolicy(
  params: BuildExactEd25519SessionPolicyParams,
): Ed25519SessionPolicyBuildResult {
  const thresholdSessionId = params.thresholdSessionId || generateThresholdSessionId();
  const { ttlMs, remainingUses } = clampThresholdSessionPolicy({
    ttlMs: params.ttlMs ?? DEFAULT_THRESHOLD_SESSION_POLICY.ttlMs,
    remainingUses: params.remainingUses ?? DEFAULT_THRESHOLD_SESSION_POLICY.remainingUses,
  });
  const participantIds = normalizeThresholdEd25519ParticipantIds(params.participantIds);
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(params.runtimePolicyScope);
  const policy: Ed25519SessionPolicy = {
    version: THRESHOLD_SESSION_POLICY_VERSION,
    nearAccountId: params.nearAccountId,
    nearEd25519SigningKeyId: params.nearEd25519SigningKeyId,
    authority: params.authority,
    relayerKeyId: params.relayerKeyId,
    thresholdSessionId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    routerAbNormalSigning: params.routerAbNormalSigning,
    ...(participantIds ? { participantIds } : {}),
    ttlMs,
    remainingUses,
  };
  const sessionPolicyDigest32 = await computeEd25519SessionPolicyDigest32(policy);
  return { policy, policyJson: JSON.stringify(policy), sessionPolicyDigest32 };
}

export function isThresholdSignerMissingKeyError(err: unknown): boolean {
  const msg = (err instanceof Error ? err.message : String(err)).toLowerCase();
  return (
    msg.includes('"code":"missing_key"') ||
    msg.includes('missing_key') ||
    msg.includes('unknown relayerkeyid')
  );
}
