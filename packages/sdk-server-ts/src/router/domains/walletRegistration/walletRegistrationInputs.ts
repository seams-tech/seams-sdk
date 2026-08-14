import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type {
  RegisterWalletInput,
  RegistrationAuthMethodInput,
  RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import type {
  RouterAbEcdsaRegistrationRequestV1,
  RouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletRegistrationAuthorityInput } from '../../../core/registrationContracts';
import type { ThresholdRuntimePolicyScope } from '../../../core/types';
import type {
  WalletRegistrationSetupMinter,
  WalletRegistrationSetupVerifier,
} from './walletRegistrationSetupPayload';

export type WalletRegistrationSetupRequest = {
  readonly wallet?: RegisterWalletInput;
  readonly signerSelection: RegistrationSignerSetSelection;
  readonly authMethod: RegistrationAuthMethodInput;
};

export type WalletRegistrationSetupInput = {
  readonly request: WalletRegistrationSetupRequest;
  readonly orgId: string;
  readonly expectedOrigin: string;
  /* The Gateway session signer, supplied at the route boundary where the
     other wallet-session minting already happens. Gateway is the sole
     minting authority (94C checkpoint decision 4). */
  readonly signer: WalletRegistrationSetupMinter;
  readonly runtimePolicyScope?: ThresholdRuntimePolicyScope;
  readonly signingRootId?: string;
  readonly signingRootVersion?: string;
};

export type WalletRegistrationRespondInput = {
  readonly registrationCeremonyId: string;
  readonly signedSetup: unknown;
  readonly authority: WalletRegistrationAuthorityInput;
  /** Checked against the plan the ceremony recorded before anything runs. */
  readonly planKind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa' | 'near_ed25519';
  /** Absent exactly when the plan is Ed25519-only. */
  readonly ecdsa?: {
    readonly kind: 'router_ab_ecdsa_registration_v1';
    readonly strictRegistration: RouterAbEcdsaRegistrationRequestV1;
    readonly requestDigestB64u: string;
  };
  /** Verifies the opaque setup token before authority-bound work begins. */
  readonly verifier: WalletRegistrationSetupVerifier;
  readonly userAgent?: string;
};

export type WalletRegistrationActivateInput = {
  readonly registrationCeremonyId: string;
  readonly signedSetup: unknown;
  readonly idempotencyKey: string;
  /**
   * No `expectedKeyHandles`. That field was the client's cross-check between
   * two separate requests: activate returned the key handle, and the client
   * echoed it to finalize so a mismatched pair could be caught. With both
   * legs in one call the handle is produced and consumed inside the same
   * request, so the client has nothing to cross-check against and asking it
   * to supply one would be theatre.
   */
  readonly planKind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa' | 'near_ed25519';
  /** Absent exactly when the plan is Ed25519-only. */
  readonly ecdsa?: {
    readonly activationCorrelationId: CorrelationId;
    readonly activationRequestDigestB64u: string;
    readonly clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  };
  readonly emailOtpEnrollment?: unknown;
  /** The custody ceremony's sealed output; the admission gate owns validation. */
  readonly walletCustodyCommit?: unknown;
  readonly verifier: WalletRegistrationSetupVerifier;
};

export type WalletRegistrationNearProvisioningInput = {
  readonly registrationCeremonyId: string;
  readonly signedSetup: unknown;
  readonly idempotencyKey: string;
  readonly ed25519: unknown;
  readonly emailOtpEnrollment?: unknown;
  /**
   * The custody ceremony's sealed output. An Ed25519-only wallet establishes
   * its custody *here* rather than at activate: activate returns
   * `near_pending` with no Yao result yet, so this deferred leg is the first
   * point at which that wallet has a key set to seal against.
   */
  readonly walletCustodyCommit?: unknown;
  readonly verifier: WalletRegistrationSetupVerifier;
};
