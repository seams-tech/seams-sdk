import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WebAuthnAuthenticationCredential } from '../core/types';
import type { RouterAbEd25519WalletSessionClaims } from '../core/ThresholdService/validation';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../core/ThresholdService/validation';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../core/registrationContracts';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from './routerAbEd25519YaoRecovery';

export type RouterAbEd25519YaoSessionPolicyV1 = {
  readonly version: 'threshold_session_v1';
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly relayerKeyId: string;
  readonly thresholdSessionId: string;
  readonly signingGrantId: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  readonly participantIds: readonly [number, number];
  readonly ttlMs: number;
  readonly remainingUses: number;
};

export type RouterAbEd25519YaoSessionRouteCommandV1 = {
  readonly relayerKeyId: string;
  readonly sessionPolicy: RouterAbEd25519YaoSessionPolicyV1;
  readonly projectEnvironmentId?: string;
  readonly routeAuth:
    | {
        readonly kind: 'passkey';
        readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
      }
    | {
        readonly kind: 'signed_session';
        readonly webauthnAuthentication?: never;
      };
  readonly sessionKind: 'jwt';
};

export type RouterAbEd25519YaoBudgetRefreshAuthorizationV1 =
  | {
      readonly kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1';
      readonly authority: PasskeyWalletAuthAuthority;
      readonly authorityRef?: never;
      readonly runtimePolicyScope?: never;
      readonly currentSession?: never;
      readonly signerSlot?: never;
      readonly verifiedChallengeId?: never;
      readonly verifiedProviderUserId?: never;
      readonly verifiedOrgId?: never;
    }
  | {
      readonly kind: 'verified_passkey_app_session_router_ab_ed25519_yao_budget_refresh_v1';
      readonly authority: PasskeyWalletAuthAuthority;
      readonly authorityRef: WalletAuthAuthorityRef;
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly currentSession?: never;
      readonly signerSlot?: never;
      readonly verifiedChallengeId?: never;
      readonly verifiedProviderUserId?: never;
      readonly verifiedOrgId?: never;
    }
  | {
      readonly kind: 'verified_email_otp_router_ab_ed25519_yao_budget_refresh_v1';
      readonly authority: EmailOtpWalletAuthAuthority;
      readonly currentSession: RouterAbEd25519WalletSessionClaims;
      readonly signerSlot: number;
      readonly verifiedChallengeId: string;
      readonly verifiedProviderUserId: string;
      readonly verifiedOrgId: string;
    };

export type RouterAbEd25519YaoBudgetRefreshRequestV1 = {
  readonly kind: 'router_ab_ed25519_yao_budget_refresh_v1';
  readonly sessionPolicy: RouterAbEd25519YaoSessionPolicyV1;
  readonly authorization: RouterAbEd25519YaoBudgetRefreshAuthorizationV1;
};

export type RouterAbEd25519YaoBudgetRefreshResponseV1 =
  | {
      readonly ok: true;
      readonly walletId: string;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly authorityScope: ReturnType<
        typeof thresholdEd25519AuthorityScopeFromWalletAuthAuthority
      >;
      readonly thresholdSessionId: string;
      readonly signingGrantId: string;
      readonly expiresAtMs: number;
      readonly expiresAt: string;
      readonly participantIds: readonly [number, number];
      readonly remainingUses: number;
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
      readonly jwt: string;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

type RouterAbEd25519YaoEmailOtpSessionRequestBaseV1 = {
  readonly walletId: string;
  readonly orgId: string;
  readonly signerSlot: number;
  readonly remainingUses: number;
  readonly verifiedChallengeId: string;
  readonly verifiedProviderUserId: string;
};

export type RouterAbEd25519YaoEmailOtpLocalSessionRequestV1 =
  RouterAbEd25519YaoEmailOtpSessionRequestBaseV1 & {
    readonly kind: 'router_ab_ed25519_yao_email_otp_local_session_v1';
  };

export type RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1 =
  RouterAbEd25519YaoEmailOtpSessionRequestBaseV1 & {
    readonly kind: 'router_ab_ed25519_yao_email_otp_recovery_session_v1';
  };

export type RouterAbEd25519YaoEmailOtpSessionRequestV1 =
  | RouterAbEd25519YaoEmailOtpLocalSessionRequestV1
  | RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1;

export type RouterAbEd25519YaoEmailOtpSessionResponseV1 =
  | {
      readonly ok: true;
      readonly session: WalletRegistrationEd25519YaoBootstrapSession;
      readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
    }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type RouterAbEd25519YaoEmailOtpLocalSessionResponseV1 =
  RouterAbEd25519YaoEmailOtpSessionResponseV1;

export type RouterAbEd25519YaoEmailOtpRecoverySessionResponseV1 =
  RouterAbEd25519YaoEmailOtpSessionResponseV1;
