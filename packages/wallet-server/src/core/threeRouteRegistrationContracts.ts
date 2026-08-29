import type {
  RegisterWalletInput,
  RegistrationAuthMethodInput,
  RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type { RouterAbEcdsaVerifiedClientActivationFactsV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationStartRequest,
  WalletRegistrationAuthorityInput,
  WalletRegistrationStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationFinalizeRouteSuccess,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaWalletKey,
  WalletRegistrationEd25519YaoPublicResult,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationRouteDiagnostics,
} from './registrationContracts';
import type {
  RegistrationEstablishedSessionProjectionV2,
  RegistrationEstablishedSessionResultV2,
} from '@shared/utils/registrationEstablishedSession';
import type { WalletSessionClientCapabilityV1 } from '@shared/authorization/capabilityKinds';
import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';
import type { ReusableWalletSessionMintId } from '@shared/authorization/capabilityKinds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type {
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
  WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import type { WalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { WalletCustodyRegistrationOutcome } from '@shared/passkey-custody';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  ThresholdEd25519AuthorityScope,
  EcdsaDerivationServerBootstrapResponse,
} from './types';

/**
 * Refactor 94C: the three-route registration wire contract, frozen at the
 * 2026-07-28 checkpoint (docs/refactor-94C-product-contract.md §2).
 *
 * Everything here derives from the existing contracts by indexed access, so a
 * change to an underlying payload surfaces as a compile error in this file
 * rather than silent drift. The routes:
 *
 *   1. POST /wallets/register/setup      — replaces grant + intent + start
 *   2. POST /wallets/register/respond    — replaces derivation/respond
 *   3. POST /wallets/register/activate   — replaces derivation/activate + finalize
 *
 * Design rules encoded in the shapes:
 * - The client carries exactly one opaque signed payload (`signedSetup`) and
 *   never parses it. Policy does not cross the public wire: the Gateway mints
 *   an internal Router-policy JWT per concrete Router call.
 * - Each route binds its own canonical `PublicDigest32` over that route's
 *   canonical encoded bytes; no signed payload satisfies a route it was not
 *   minted for.
 * - Route 3's completion row stores the credential-free committed projection
 *   and request fingerprint. A direct-capability first response carries the
 *   ephemeral primary credential after the receipt CAS; exact retry returns
 *   `already_committed` with the stable projection and no credential. The
 *   receipt projection retains the parent session expiry. A conflicting
 *   fingerprint returns the typed conflict.
 * - The V2 wire contract has no legacy fields or dual-write.
 */

declare const signedSetupPayloadBrand: unique symbol;
/** Compact Ed25519 JWS, opaque to the client; verified with pinned keys. */
export type SignedSetupPayloadB64u = string & { readonly [signedSetupPayloadBrand]: true };

/* Reused pieces, named once so route shapes below stay readable. Indexed
   access keeps them bound to the canonical definitions. */
type SetupEd25519Work =
  Extract<WalletRegistrationStartResponse, { kind: 'near_ed25519' }> extends {
    ed25519: infer T;
  }
    ? T
    : never;
type ActivateIdempotencyKey = WalletRegistrationFinalizeRequest['idempotencyKey'];
type FinalizeRequestBase = WalletRegistrationFinalizeRequest;
type EcdsaFinalizeSuccess = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'evm_family_ecdsa' }
>;
type EcdsaActivationSuccess = Extract<WalletRegistrationEcdsaActivationResponse, { ok: true }>;

type WalletRegistrationSessionCommitReceiptMetadataV2 = {
  readonly kind: 'wallet_registration_session_commit_receipt_v2';
  readonly operation: 'registration_activate' | 'near_provisioning';
  readonly operationFingerprint: string;
  readonly registrationCeremonyId: string;
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authority: WalletAuthAuthority;
  readonly authMethod: WalletRegistrationFinalizeAuthMethod;
  readonly expectedOrigin: string;
  readonly registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
};

type WalletRegistrationSessionCommitReadyBaseV2 =
  WalletRegistrationSessionCommitReceiptMetadataV2 & {
    readonly foundingAuthority: ActiveWalletAuthorityV1;
    readonly foundingAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
    readonly mintId: ReusableWalletSessionMintId;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly custodyKeyManifestDigestB64u: DigestB64u;
    readonly walletCustody?: WalletCustodyRegistrationOutcome;
  };

export type WalletRegistrationSessionCommitReceiptV2 =
  | {
      readonly kind: 'wallet_registration_session_commit_receipt_v2';
      readonly operation: 'registration_activate' | 'near_provisioning';
      readonly operationFingerprint: string;
      readonly registrationCeremonyId: string;
      readonly committed: {
        readonly kind: 'error';
        readonly error: WalletRegistrationRouteErrorV2;
      };
    }
  | (WalletRegistrationSessionCommitReceiptMetadataV2 & {
      readonly committed: {
        readonly kind: 'near_pending';
        readonly nearProvisioning: { readonly status: 'near_pending' };
      };
    })
  | (WalletRegistrationSessionCommitReadyBaseV2 & {
      readonly committed: {
        readonly kind: 'ecdsa_ready';
        readonly ecdsa: {
          readonly walletKeys: readonly WalletRegistrationEcdsaWalletKey[];
          readonly activation: EcdsaActivationSuccess['ecdsa']['activation'];
          readonly bootstrap: EcdsaDerivationServerBootstrapResponse;
        };
        readonly session: RegistrationEstablishedSessionProjectionV2;
        readonly nearProvisioning?: { readonly status: 'near_pending' };
      };
    })
  | (WalletRegistrationSessionCommitReadyBaseV2 & {
      readonly committed: {
        readonly kind: 'near_ready';
        readonly authorityScope: ThresholdEd25519AuthorityScope;
        readonly accountProvisioning: RegistrationNearAccountProvisioning;
        readonly resolvedAccount: ResolvedRegistrationNearAccount;
        readonly ed25519: WalletRegistrationEd25519YaoPublicResult;
        readonly session: RegistrationEstablishedSessionProjectionV2;
        readonly nearProvisioning: { readonly status: 'near_ready' };
      };
    });

export type WalletRegistrationRouteErrorV2 = {
  ok: false;
  code: string;
  message: string;
  retryAfterMs?: number;
};

/** Route 1 — one Gateway request replacing grant, intent, and start. */
export type WalletRegistrationSetupRequestV2 = {
  /** Omitted means server-allocated, matching the intent route it replaces. */
  wallet?: RegisterWalletInput;
  signerSelection: RegistrationSignerSetSelection;
  /**
   * The requested method, not a proof. Setup issues the challenge that the
   * client's WebAuthn create must sign, so no proof can exist yet; it arrives
   * on respond.
   */
  authMethod: RegistrationAuthMethodInput;
};

/**
 * Setup is ECDSA-only, uniformly, for both authentication methods.
 *
 * Yao admission binds the Ed25519 authority scope, and that scope is only
 * sound once the proof is verified. Preparing it at setup would have been
 * possible for a passkey and not for Email OTP — which would have meant two
 * different setup protocols depending on auth method. One protocol that always
 * defers is simpler and strictly safer, so Ed25519 work does not appear in the
 * setup request or response at all. Respond derives it, authority-bound, for
 * both methods.
 */
type WalletRegistrationSetupSuccessBase = {
  ok: true;
  registrationCeremonyId: string;
  walletId: string;
  walletAuthMethodId: WalletAuthMethodId;
  /** The WebAuthn create challenge; the client signs exactly this. */
  registrationIntentDigestB64u: string;
  intent: WalletRegistrationStartRequest['intent'];
  /** Opaque; echoed verbatim on routes 2 and 3. */
  signedSetup: SignedSetupPayloadB64u;
};

/**
 * Setup's shape follows the signer plan, exhaustively.
 *
 * An Ed25519-only wallet has no ECDSA branch to prepare, so `ecdsa` is not an
 * optional field that happens to be absent — the arm types it `never`, and a
 * caller that reads it fails to compile. Yao work is still absent from both
 * arms: it binds the authority scope, which no proof has established yet.
 */
export type WalletRegistrationSetupResponseV2 =
  | (WalletRegistrationSetupSuccessBase & {
      kind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa';
      ecdsa: WalletRegistrationEcdsaPreparePayload;
    })
  | (WalletRegistrationSetupSuccessBase & {
      /* Nothing to prepare before the proof: the ceremony and its challenge
         are the whole of setup's work for this plan. */
      kind: 'near_ed25519';
      ecdsa?: never;
    })
  | WalletRegistrationRouteErrorV2;

/**
 * Route 2 — authenticated respond.
 *
 * The request discriminates on the signer plan, exhaustively, because an
 * Ed25519-only ceremony has no ECDSA registration to send. A single object
 * type with a required `ecdsa` made that request impossible to construct.
 * The parser validates this discriminant against the plan the signed setup
 * and ceremony actually recorded, so a caller cannot pick an arm the ceremony
 * was not created for.
 */
type WalletRegistrationRespondRequestBaseV2 = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
};

type WalletRegistrationRespondAuthorityProofV2 =
  | {
      webauthn_registration: Extract<
        WalletRegistrationAuthorityInput,
        { kind: 'passkey' }
      >['webauthnRegistration'];
      emailOtpRegistrationProof?: never;
    }
  | {
      emailOtpRegistrationProof: Extract<
        WalletRegistrationAuthorityInput,
        { kind: 'email_otp' }
      >['emailOtpRegistrationProof'];
      webauthn_registration?: never;
    };

export type RespondEcdsaRegistrationWorkV2 = {
  kind: 'router_ab_ecdsa_registration_v1';
  strictRegistration: unknown; // RouterAbEcdsaRegistrationRequestV1; bound at the parser
  /** Canonical Router request digest produced by the client ceremony WASM. */
  requestDigestB64u: string;
};

export type WalletRegistrationRespondRequestV2 = WalletRegistrationRespondAuthorityProofV2 &
  (
    | (WalletRegistrationRespondRequestBaseV2 & {
        kind: 'evm_family_ecdsa';
        ecdsa: RespondEcdsaRegistrationWorkV2;
      })
    | (WalletRegistrationRespondRequestBaseV2 & {
        kind: 'near_ed25519_and_evm_family_ecdsa';
        ecdsa: RespondEcdsaRegistrationWorkV2;
      })
    | (WalletRegistrationRespondRequestBaseV2 & {
        kind: 'near_ed25519';
        ecdsa?: never;
      })
  );

/**
 * What respond returns for the ceremony's signer plan.
 *
 * Respond verifies the authority first, then derives the authority-bound Yao
 * admission — for both authentication methods, since by this point the proof
 * exists either way. The plan's shape is exhaustive rather than an optional
 * `ed25519` field: a mixed plan always carries its deferred NEAR work, and an
 * ECDSA-only plan has no arm to omit.
 *
 * The NEAR work is deferred, not pending-in-progress. The client starts it
 * asynchronously and must not await it: the wallet is usable on ECDSA alone,
 * and blocking registration on Yao is the coupling this refactor removes.
 */
export type WalletRegistrationRespondSignerPlanV2 =
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: RespondEcdsaProofBundles;
      ed25519?: never;
    }
  | {
      kind: 'near_ed25519_and_evm_family_ecdsa';
      ecdsa: RespondEcdsaProofBundles;
      /** Authority-bound admission, derived here because the proof now exists. */
      ed25519: RespondEd25519DeferredWorkV2;
    }
  | {
      /**
       * Ed25519-only: no ECDSA leg ran, so there is no proof bundle — `ecdsa`
       * is `never`, not an empty object.
       *
       * The admission is deferred, exactly as on a mixed plan. Yao being the
       * wallet's sole signer is not a reason to block on it: the client starts
       * the computation and calls activate without awaiting it, and the wallet
       * exists in `near_pending` until Yao produces its signer. There is
       * deliberately no second, blocking Yao lifecycle.
       */
      kind: 'near_ed25519';
      ecdsa?: never;
      ed25519: RespondEd25519DeferredWorkV2;
    };

/** Exact A/B role bundles, unchanged from the derivation respond leg. */
export type RespondEcdsaProofBundles = {
  kind: 'router_ab_ecdsa_registration_forwarded_v1';
  strictResult: unknown; // RouterAbEcdsaStrictForwardedRegistrationResponseV1; bound at the parser
};

export type RespondEd25519DeferredWorkV2 = {
  status: 'deferred';
  admissionRequest: SetupEd25519Work extends { admissionRequest: infer T } ? T : never;
  admissionReceipt: SetupEd25519Work extends { admissionReceipt: infer T } ? T : never;
};

export type WalletRegistrationRespondResponseV2 =
  | ({ ok: true; registrationCeremonyId: string } & WalletRegistrationRespondSignerPlanV2)
  | WalletRegistrationRouteErrorV2;

/**
 * Route 3 — activate-and-finalize; the operation row is the replay record.
 *
 * Two independent discriminants, because they vary independently: the signer
 * plan decides whether there is ECDSA activation to send, and the auth method
 * decides whether Email OTP enrollment is required. Enrollment is *not* an
 * ECDSA concern — an Ed25519-only wallet registered with Email OTP still
 * enrolls — so deriving those fields from the ECDSA work, as this type
 * previously did, mismodelled them.
 *
 * Passkey activation carrying enrollment fields fails to compile, and Email
 * OTP activation missing them fails to compile. Neither is optional, because
 * neither is genuinely optional at runtime.
 */
type WalletRegistrationActivateAuthWorkV2 =
  | {
      authMethod: 'passkey';
      emailOtpEnrollment?: never;
    }
  | {
      authMethod: 'email_otp';
      emailOtpEnrollment: NonNullable<FinalizeRequestBase['emailOtpEnrollment']>;
    };

type WalletRegistrationActivateRequestBaseV2 = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  idempotencyKey: ActivateIdempotencyKey;
  walletSessionClientCapability: WalletSessionClientCapabilityV1;
};

export type ActivateEcdsaWorkV2 = {
  activationCorrelationId: CorrelationId;
  clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
};

export type WalletRegistrationActivateRequestV2 = WalletRegistrationActivateRequestBaseV2 &
  WalletRegistrationActivateAuthWorkV2 &
  (
    | { kind: 'evm_family_ecdsa'; ecdsa: ActivateEcdsaWorkV2 }
    | { kind: 'near_ed25519_and_evm_family_ecdsa'; ecdsa: ActivateEcdsaWorkV2 }
    | {
        /**
         * Ed25519-only activate persists the pending wallet and nothing else.
         * It sends no ECDSA activation and — deliberately — no Ed25519
         * activation reference either: Yao has not resolved yet, and its
         * result arrives later at `/wallets/register/near-provisioning`.
         */
        kind: 'near_ed25519';
        ecdsa?: never;
      }
  );

/**
 * Activate's terminal response is both legs merged.
 *
 * The commit half supplies the wallet keys; the activation half supplies the
 * receipt and the derivation bootstrap the client needs to bring the wallet
 * online. Separate requests used to return these separately — folding the
 * legs without merging the payloads would leave the client unable to finish,
 * so `ecdsa` carries all three.
 */
type ActivateEcdsaTerminalPayload = EcdsaFinalizeSuccess['ecdsa'] & {
  activation: EcdsaActivationSuccess['ecdsa']['activation'];
  bootstrap: EcdsaActivationSuccess['ecdsa']['bootstrap'];
};

type Ed25519FinalizeSuccess = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'near_ed25519' }
>;

type DistributiveOmit<T, K extends keyof any> = T extends unknown ? Omit<T, K> : never;

/**
 * Activate's Ed25519-only terminal result: a wallet that exists and cannot
 * yet sign.
 *
 * Activate does not wait for Yao. It persists the wallet, profile, and
 * authentication state plus the `near_pending` provisioning record, and that
 * pending response is the committed terminal projection, and a retry
 * reconstructs that projection from the receipt. Every field that only
 * completed Yao can produce is `never`, so a caller cannot read a signer, a
 * resolved account, or a key identity that does not exist yet. The wallet
 * becomes signable when deferred Yao reaches `near_ready`.
 */
export type WalletRegistrationActivateEd25519PendingV2 = DistributiveOmit<
  Ed25519FinalizeSuccess,
  | 'ed25519'
  | 'resolvedAccount'
  | 'accountProvisioning'
  | 'authorityScope'
  | 'foundingAuthority'
  | 'foundingAuthMethod'
  // The activate leg precedes the key set, so there is no manifest to name yet.
  | 'custodyKeyManifestDigestB64u'
> & {
  nearProvisioning: { status: 'near_pending' };
  ed25519?: never;
  resolvedAccount?: never;
  accountProvisioning?: never;
  authorityScope?: never;
  ecdsa?: never;
};

export type WalletRegistrationActivateResponseV2 =
  | (DistributiveOmit<EcdsaFinalizeSuccess, 'ecdsa'> & {
      ecdsa: ActivateEcdsaTerminalPayload;
      registrationEstablishedSession: RegistrationEstablishedSessionResultV2;
      /** Mixed plans: deferred NEAR snapshot; never identifiers before readiness. */
      nearProvisioning?: { status: 'near_pending' };
    })
  | WalletRegistrationActivateEd25519PendingV2
  | WalletRegistrationRouteErrorV2;

type ActivateSuccessV2 = Exclude<
  WalletRegistrationActivateResponseV2,
  WalletRegistrationRouteErrorV2
>;

export type WalletRegistrationActivateRouteResponseV2 =
  | ActivateSuccessV2
  | WalletRegistrationRouteErrorV2;

/**
 * Deferred NEAR provisioning — `POST /wallets/register/near-provisioning`.
 *
 * Not one of the three routes: it is the non-blocking completion the client
 * calls *after* activate has returned, with the Yao activation the already
 * running computation produced. It installs the wallet's Ed25519 signer,
 * derives the implicit-account projection, and moves provisioning to ready.
 *
 * Implicit-account registration is keypair derivation only — no NEAR RPC and
 * no on-chain transaction, so nothing here spends gas or creates irreversible
 * chain state.
 *
 * Both plans use it. On a mixed plan the wallet was already signable on ECDSA;
 * on an Ed25519-only plan this call is what makes the wallet signable at all.
 */
export type WalletRegistrationNearProvisioningRequestV2 = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  /** Its own key: this commit is a separate effect from activate's. */
  idempotencyKey: ActivateIdempotencyKey;
  ed25519: Extract<WalletRegistrationFinalizeRequest, { kind: 'near_ed25519' }>['ed25519'];
  emailOtpEnrollment?: NonNullable<WalletRegistrationFinalizeRequest['emailOtpEnrollment']>;
  walletSessionClientCapability: WalletSessionClientCapabilityV1;
};

type WalletRegistrationNearProvisioningSuccessV2 = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'near_ed25519' }
> & {
  registrationEstablishedSession: RegistrationEstablishedSessionResultV2;
  nearProvisioning: { status: 'near_ready' };
};

export type WalletRegistrationNearProvisioningResponseV2 =
  | WalletRegistrationNearProvisioningSuccessV2
  | (WalletRegistrationRouteErrorV2 & {
      /**
       * A retryable failure leaves the pending wallet intact and the call
       * repeatable — the wallet must never be destroyed because its signer
       * ceremony needs another attempt.
       */
      nearProvisioning?: { status: 'near_failed_retryable' };
    });

/** Public route response after the Gateway mints the Email OTP authentication session. */
