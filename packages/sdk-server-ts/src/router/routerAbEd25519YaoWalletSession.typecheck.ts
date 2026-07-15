import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { RouterAbEd25519WalletSessionClaims } from '../core/ThresholdService/validation';
import type { RouterAbEd25519YaoBudgetRefreshAuthorizationV1 } from './routerAbEd25519YaoWalletSession';

declare const passkeyAuthority: PasskeyWalletAuthAuthority;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const currentSession: RouterAbEd25519WalletSessionClaims;

function acceptBudgetRefreshAuthorization(
  authorization: RouterAbEd25519YaoBudgetRefreshAuthorizationV1,
): void {
  void authorization;
}

acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
});

acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: emailOtpAuthority,
  currentSession,
  signerSlot: 1,
  verifiedChallengeId: 'challenge-id',
  verifiedProviderUserId: 'provider-user-id',
  verifiedOrgId: 'org-id',
});

// @ts-expect-error Passkey verification cannot carry Email OTP signer selection.
acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  signerSlot: 1,
});

// @ts-expect-error Passkey refresh authorization is the fresh WebAuthn proof, not an old session.
acceptBudgetRefreshAuthorization({
  kind: 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  currentSession,
});

// @ts-expect-error Email OTP verification requires exact signer and proof identity.
acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: emailOtpAuthority,
  currentSession,
});

// @ts-expect-error Email OTP verification cannot carry passkey authority.
acceptBudgetRefreshAuthorization({
  kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1',
  authority: passkeyAuthority,
  currentSession,
  signerSlot: 1,
  verifiedChallengeId: 'challenge-id',
  verifiedProviderUserId: 'provider-user-id',
  verifiedOrgId: 'org-id',
});
