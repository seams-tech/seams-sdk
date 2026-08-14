import {
  isEmailOtpWalletAuthAuthority,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import { type EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { CanonicalEvmFamilyEcdsaSigningCapability } from '../material/ecdsaSigningCapability';
import {
  walletSessionThresholdSessionIdForCurve,
  walletSessionTokenForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type EmailOtpEcdsaSigningSessionAuthority = {
  authLane: Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ecdsa' }>;
  authority: EmailOtpWalletAuthAuthority;
};

export function buildEmailOtpEcdsaSigningSessionAuthority(args: {
  authLane: EmailOtpAuthLane | null | undefined;
  authority: EmailOtpWalletAuthAuthority;
}): EmailOtpEcdsaSigningSessionAuthority | null {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ecdsa') return null;
  return {
    authLane,
    authority: args.authority,
  };
}

export type EmailOtpEcdsaSigningSessionAuthorityResolution =
  | {
      kind: 'ready';
      authority: EmailOtpEcdsaSigningSessionAuthority;
    }
  | {
      kind: 'record_missing';
      authority?: never;
    }
  | {
      kind: 'wallet_session_auth_unavailable';
      reason: 'cookie_session' | 'missing_wallet_session_token';
      authority?: never;
    }
  | {
      kind: 'missing_session_identity';
      authority?: never;
    }
  | {
      kind: 'authority_not_ecdsa_signing_session';
      authority?: never;
    };

/** Canonical counterpart of the record-backed resolver: the Email OTP authority
 * comes from the sealed runtime's auth binding, and the signing-session lane is
 * completed by the independently-resolved reusable Wallet Session. Material
 * identity plays no part here -- it is proven separately by the manifest.  */
export function resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime(args: {
  runtime: ExactEcdsaSealedRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): EmailOtpEcdsaSigningSessionAuthorityResolution {
  const authBinding = args.runtime.authBinding;
  if (authBinding.kind !== 'email_otp') {
    // A passkey-bound runtime is not an Email OTP signing session; report the
    // missing lane rather than inventing a store source for it.
    return { kind: 'record_missing' };
  }
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ecdsa');
  if (!walletSessionToken) {
    return { kind: 'wallet_session_auth_unavailable', reason: 'missing_wallet_session_token' };
  }
  const authority = buildEmailOtpEcdsaSigningSessionAuthority({
    authority: authBinding.emailOtpAuthority,
    authLane: {
      kind: 'signing_session',
      walletSessionToken,
      thresholdSessionId: args.runtime.sealedRecord.thresholdSessionId,
      curve: 'ecdsa',
      chainTarget: args.runtime.chainTarget,
    },
  });
  if (!authority) return { kind: 'authority_not_ecdsa_signing_session' };
  return { kind: 'ready', authority };
}

/**
 * Registration establishes the canonical capability and a reusable Wallet
 * Session before any Email OTP sealed session exists. The Wallet Session token
 * carries the threshold-session identity needed by the signing-session route;
 * the capability carries the Email OTP authority. Keep this path separate from
 * sealed-runtime resolution so a missing sealed record cannot hide a usable
 * post-registration lane.
 */
export function resolveEmailOtpEcdsaSigningSessionAuthorityFromCapability(args: {
  capability: CanonicalEvmFamilyEcdsaSigningCapability;
  authorization: ActiveWalletSessionAuthorizationProjection;
  chainTarget: ThresholdEcdsaChainTarget;
}): EmailOtpEcdsaSigningSessionAuthorityResolution {
  const capabilityAuthority = args.capability.authority;
  if (!isEmailOtpWalletAuthAuthority(capabilityAuthority)) {
    return { kind: 'record_missing' };
  }
  const signer = args.capability.manifest.signer;
  if (
    signer.walletId !== args.authorization.walletId ||
    signer.authority.authorityDigest !== args.authorization.authority.authorityDigest ||
    !signer.scope.targetMemberships.some((target) =>
      thresholdEcdsaChainTargetsEqual(target, args.chainTarget),
    ) ||
    args.capability.material.publicFacts.walletId !== signer.walletId
  ) {
    return { kind: 'record_missing' };
  }
  const walletSessionToken = walletSessionTokenForCurve(args.authorization, 'ecdsa');
  if (!walletSessionToken) {
    return { kind: 'wallet_session_auth_unavailable', reason: 'missing_wallet_session_token' };
  }
  const thresholdSessionId = walletSessionThresholdSessionIdForCurve(
    args.authorization,
    'ecdsa',
  );
  if (!thresholdSessionId) return { kind: 'missing_session_identity' };
  const authority = buildEmailOtpEcdsaSigningSessionAuthority({
    authority: capabilityAuthority,
    authLane: {
      kind: 'signing_session',
      walletSessionToken,
      thresholdSessionId,
      curve: 'ecdsa',
      chainTarget: args.chainTarget,
    },
  });
  return authority
    ? { kind: 'ready', authority }
    : { kind: 'authority_not_ecdsa_signing_session' };
}
