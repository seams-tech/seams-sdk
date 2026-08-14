import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { VerifiedOwnerProof } from '../../../../authorization/factorEvidence';
import type { RouterAbEd25519WalletSessionClaims } from '../../../../core/ThresholdService/validation';
import type { WebAuthnAuthenticationCredential } from '../../../../core/types';
import type {
  RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
  RouterAbEd25519YaoOperationStepUpGrantCommandV1,
} from './routerAbEd25519YaoWalletSession';

declare const passkeyAuthority: PasskeyWalletAuthAuthority;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const currentSession: RouterAbEd25519WalletSessionClaims;
declare const authorityRef: WalletAuthAuthorityRef;
declare const runtimePolicyScope: RuntimePolicyScope;
declare const ownerProof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
declare const webauthnAuthentication: WebAuthnAuthenticationCredential;

function acceptBudgetRefreshAuthorization(
  authorization: RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
): void {
  void authorization;
}

function acceptOperationStepUpProof(
  proof: RouterAbEd25519YaoOperationStepUpGrantCommandV1['proof'],
): void {
  void proof;
}

acceptOperationStepUpProof({
  kind: 'passkey',
  authority: passkeyAuthority,
  webauthnAuthentication,
});

acceptOperationStepUpProof({
  kind: 'email_otp',
  authorityRef,
  providerSubjectId: 'provider-user-id',
  challengeId: 'challenge-id',
  otpCode: '123456',
});

// @ts-expect-error Passkey proof cannot carry Email OTP fields.
acceptOperationStepUpProof({
  kind: 'passkey',
  authority: passkeyAuthority,
  webauthnAuthentication,
  challengeId: 'challenge-id',
});

// @ts-expect-error Email OTP proof requires its challenge and code.
acceptOperationStepUpProof({
  kind: 'email_otp',
  authorityRef,
  providerSubjectId: 'provider-user-id',
});

// @ts-expect-error Email OTP proof cannot carry WebAuthn material.
acceptOperationStepUpProof({
  kind: 'email_otp',
  authorityRef,
  providerSubjectId: 'provider-user-id',
  challengeId: 'challenge-id',
  otpCode: '123456',
  webauthnAuthentication,
});

acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  proof: ownerProof,
  verifiedChallengeId: 'challenge-id',
});

acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: emailOtpAuthority,
  proof: ownerProof,
  currentSession,
  signerSlot: 1,
  verifiedChallengeId: 'challenge-id',
  verifiedProviderUserId: 'provider-user-id',
  verifiedOrgId: 'org-id',
});

// @ts-expect-error Passkey verification cannot carry Email OTP signer selection.
acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  proof: ownerProof,
  verifiedChallengeId: 'challenge-id',
  signerSlot: 1,
});

// @ts-expect-error Passkey refresh authorization is the fresh WebAuthn proof, not an old session.
acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  proof: ownerProof,
  verifiedChallengeId: 'challenge-id',
  currentSession,
});

// @ts-expect-error Email OTP verification requires exact signer and proof identity.
acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: emailOtpAuthority,
  proof: ownerProof,
  currentSession,
});

// @ts-expect-error Email OTP verification cannot carry passkey authority.
acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  proof: ownerProof,
  currentSession,
  signerSlot: 1,
  verifiedChallengeId: 'challenge-id',
  verifiedProviderUserId: 'provider-user-id',
  verifiedOrgId: 'org-id',
});
