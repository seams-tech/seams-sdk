import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import type { WalletId } from './domainIds';
import type {
  ThresholdEcdsaSessionId,
  ThresholdEd25519SessionId,
} from './domainIds';
import type { ThresholdEcdsaKeyHandle } from './thresholdEcdsaKeyHandle';
import type { NearAccountId } from './near';
import type { NearEd25519SigningKeyId } from './registrationIntent';
import type { RuntimePolicyScope } from '../threshold/signingRootScope';
import type { RouterAbEd25519NormalSigningState } from './signingSessionSeal';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from './routerAbEcdsaDerivation';

/**
 * Registration establishes one reusable authorization identity. Each curve
 * receives its own opaque bearer token and server-validated material binding.
 */
export type RegistrationEstablishedEcdsaSession = {
  readonly sessionKind: 'opaque';
  readonly walletSessionToken: string;
  readonly thresholdSessionId: ThresholdEcdsaSessionId;
  readonly keyHandle: ThresholdEcdsaKeyHandle;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

export type RegistrationEstablishedEd25519Session = {
  readonly sessionKind: 'opaque';
  readonly walletSessionToken: string;
  readonly thresholdSessionId: ThresholdEd25519SessionId;
  readonly nearAccountId: NearAccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type RegistrationEstablishedSessionTokens =
  | {
      readonly kind: 'evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSession;
      readonly ed25519?: never;
    }
  | {
      readonly kind: 'near_ed25519';
      readonly ed25519: RegistrationEstablishedEd25519Session;
      readonly ecdsa?: never;
    }
  | {
      readonly kind: 'near_ed25519_and_evm_family_ecdsa';
      readonly ecdsa: RegistrationEstablishedEcdsaSession;
      readonly ed25519: RegistrationEstablishedEd25519Session;
    };

export type RegistrationEstablishedSession = {
  readonly kind: 'registration_established_wallet_session_v1';
  readonly walletId: WalletId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly tokens: RegistrationEstablishedSessionTokens;
};
