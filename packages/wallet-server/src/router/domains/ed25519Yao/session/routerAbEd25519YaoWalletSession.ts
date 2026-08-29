import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  PasskeyWalletAuthAuthority,
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WebAuthnAuthenticationCredential } from '../../../../core/types';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../../core/ThresholdService/validation';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../../../core/registrationContracts';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../recovery/routerAbEd25519YaoRecovery';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionMintId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking';
import type {
  ThresholdEd25519SessionId,
  WalletAuthMethodId,
  WalletAuthorityId,
  WalletId,
} from '@shared/utils/domainIds';
import type { VerifiedOwnerProof } from '../../../../authorization/factorEvidence';

export type RouterAbEd25519YaoSessionPolicyV1 = {
  readonly version: 'threshold_session_v1';
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly relayerKeyId: string;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
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
  readonly routeAuth: {
    readonly kind: 'passkey';
    readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
  };
  readonly walletSessionTarget:
    | { readonly kind: 'new_wallet_session' }
    | { readonly kind: 'reuse_ecdsa_wallet_session' };
  readonly sessionKind: 'opaque';
};

export type RouterAbEd25519YaoOperationStepUpMaterialRecoveryRequest =
  | {
      readonly kind: 'not_requested';
    }
  | {
      readonly kind: 'email_otp_factor_release_v1';
      readonly workerEphemeralPublicKey65B64u: string;
    };

export type RouterAbEd25519YaoOperationStepUpMaterialRecoveryResponse =
  | {
      readonly kind: 'not_requested';
    }
  | {
      readonly kind: 'email_otp_factor_release_v1';
      readonly challengeId: string;
      readonly enrollmentId: string;
      readonly enrollmentSealKeyVersion: string;
      readonly serverEphemeralPublicKey65B64u: string;
      readonly nonce12B64u: string;
      readonly ciphertextB64u: string;
    };

type RouterAbEd25519YaoOperationStepUpGrantCommandBase = {
  readonly kind: 'router_ab_ed25519_yao_operation_step_up_grant_v1';
  readonly normalSigningRequest: Record<string, unknown>;
  readonly displayDigest: string;
};

export type RouterAbEd25519YaoOperationStepUpGrantCommandV1 =
  RouterAbEd25519YaoOperationStepUpGrantCommandBase &
    (
      | {
          readonly proof: {
            readonly kind: 'passkey';
            readonly authority: PasskeyWalletAuthAuthority;
            readonly webauthnAuthentication: WebAuthnAuthenticationCredential;
            readonly challengeId?: never;
            readonly otpCode?: never;
          };
          readonly materialRecovery: Extract<
            RouterAbEd25519YaoOperationStepUpMaterialRecoveryRequest,
            { kind: 'not_requested' }
          >;
        }
      | {
          readonly proof: {
            readonly kind: 'email_otp';
            readonly authorityRef: WalletAuthAuthorityRef;
            readonly providerSubjectId: string;
            readonly challengeId: string;
            readonly otpCode: string;
            readonly webauthnAuthentication?: never;
            readonly authority?: never;
          };
          readonly materialRecovery: RouterAbEd25519YaoOperationStepUpMaterialRecoveryRequest;
        }
    );

export type RouterAbEd25519YaoBudgetRefreshAuthorizationV1 = {
  readonly kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1';
  readonly authority: PasskeyWalletAuthAuthority;
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly verifiedChallengeId: string;
};

export type RouterAbEd25519YaoBudgetRefreshRequestV1 =
  | {
      readonly kind: 'router_ab_ed25519_yao_budget_refresh_v1';
      readonly sessionPolicy: RouterAbEd25519YaoSessionPolicyV1;
      readonly authorization: RouterAbEd25519YaoBudgetRefreshAuthorizationV1;
      readonly existingWalletSession?: never;
    }
  | {
      readonly kind: 'router_ab_ed25519_yao_same_wallet_session_curve_mint_v1';
      readonly sessionPolicy: RouterAbEd25519YaoSessionPolicyV1;
      readonly authorization: RouterAbEd25519YaoBudgetRefreshAuthorizationV1;
      readonly existingWalletSession: {
        readonly authorizationId: WalletSessionAuthorizationId;
        readonly walletSessionId: WalletSessionId;
        readonly quotaId: MpcWalletSigningQuotaId;
        readonly expiresAtMs: number;
        readonly remainingUses: number;
      };
    };

/**
 * The committed identity of one Wallet Session issuance attempt whose
 * credential is unreachable. It is credential-free by construction: a replay
 * reads a committed digest, and no digest reproduces plaintext.
 */
export type RouterAbEd25519YaoCommittedWalletSessionV1 = {
  readonly kind: 'already_committed_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly mintId: WalletSessionMintId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type RouterAbEd25519YaoAlreadyCommittedResponseV1 = {
  readonly ok: false;
  readonly code: 'already_committed';
  readonly message: string;
  readonly next: 'unlock_exact_method';
  readonly committed: RouterAbEd25519YaoCommittedWalletSessionV1;
};

export type RouterAbEd25519YaoWalletSessionRejectionV1 = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
  readonly next?: never;
  readonly committed?: never;
};

type RouterAbEd25519YaoBudgetRefreshSessionV1 = {
  readonly ok: true;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authorityScope: ReturnType<typeof thresholdEd25519AuthorityScopeFromWalletAuthAuthority>;
  readonly thresholdSessionId: string;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly expiresAt: string;
  readonly participantIds: readonly [number, number];
  readonly remainingUses: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RouterAbEd25519YaoBudgetRefreshResponseV1 =
  | (RouterAbEd25519YaoBudgetRefreshSessionV1 & {
      readonly sessionKind: 'issued_exact_wallet_session';
      readonly operationCredential: WalletSessionOperationCredentialV1;
    })
  | (RouterAbEd25519YaoBudgetRefreshSessionV1 & {
      readonly sessionKind: 'already_committed_exact_wallet_session';
      readonly operationCredential?: never;
    })
  | RouterAbEd25519YaoAlreadyCommittedResponseV1
  | RouterAbEd25519YaoWalletSessionRejectionV1;

type RouterAbEd25519YaoVerifiedWalletUnlockRequestBaseV1 = {
  readonly walletId: string;
  readonly signerSlot: number;
  readonly remainingUses: number;
  readonly verifiedChallengeId: string;
  readonly authority: WalletAuthAuthority;
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
};

export type RouterAbEd25519YaoWalletSessionIdentityV1 =
  | { readonly kind: 'issue_wallet_session_v1' }
  | {
      readonly kind: 'reuse_wallet_session_v2';
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly expiresAtMs: number;
      readonly remainingUses: number;
    };

export type RouterAbEd25519YaoVerifiedWalletUnlockRequestV1 =
  RouterAbEd25519YaoVerifiedWalletUnlockRequestBaseV1 & {
    readonly walletSessionIdentity: RouterAbEd25519YaoWalletSessionIdentityV1;
  };

export type RouterAbEd25519YaoVerifiedWalletUnlockResponseV1 =
  | {
      readonly ok: true;
      readonly session: WalletRegistrationEd25519YaoBootstrapSession;
      readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
    }
  | RouterAbEd25519YaoAlreadyCommittedResponseV1
  | RouterAbEd25519YaoWalletSessionRejectionV1;
