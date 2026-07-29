import type {
  RegisterWalletInput,
  RegistrationAuthMethodInput,
  RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import type {
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationEcdsaActivationResponse,
} from './registrationContracts';

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
 * - Route 3's terminal response bytes are the replay record. Exact retry with
 *   the same idempotency key and fingerprint returns them byte-identically;
 *   a conflicting fingerprint returns the typed conflict.
 * - No compatibility route, legacy field, or dual-write path.
 */

declare const signedSetupPayloadBrand: unique symbol;
/** Compact Ed25519 JWS, opaque to the client; verified with pinned keys. */
export type SignedSetupPayloadB64u = string & { readonly [signedSetupPayloadBrand]: true };

/* Reused pieces, named once so route shapes below stay readable. Indexed
   access keeps them bound to the canonical definitions. */
type SetupAuthorityProof = WalletRegistrationStartRequest['authority'];
type SetupEd25519Work = Extract<WalletRegistrationStartResponse, { kind: 'near_ed25519' }> extends {
  ed25519: infer T;
}
  ? T
  : never;
type ActivateIdempotencyKey = WalletRegistrationFinalizeRequest['idempotencyKey'];
type EcdsaFinalizeWork = Extract<WalletRegistrationFinalizeRequest, { kind: 'evm_family_ecdsa' }>;
type EcdsaFinalizeSuccess = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'evm_family_ecdsa' }
>;
type EcdsaActivationSuccess = Extract<WalletRegistrationEcdsaActivationResponse, { ok: true }>;

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
export type WalletRegistrationSetupResponseV2 =
  | {
      ok: true;
      registrationCeremonyId: string;
      walletId: string;
      /** The WebAuthn create challenge; the client signs exactly this. */
      registrationIntentDigestB64u: string;
      intent: WalletRegistrationStartRequest['intent'];
      /** Opaque; echoed verbatim on routes 2 and 3. */
      signedSetup: SignedSetupPayloadB64u;
      ecdsa: WalletRegistrationEcdsaPreparePayload;
    }
  | WalletRegistrationRouteErrorV2;

/** Route 2 — authenticated respond; wire-stable while Gateway bookkeeping is removed. */
export type WalletRegistrationRespondRequestV2 = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  authority: SetupAuthorityProof;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: unknown; // RouterAbEcdsaRegistrationRequestV1; bound at the parser
  };
};

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

/** Route 3 — activate-and-finalize; the operation row is the replay record. */
export type WalletRegistrationActivateRequestV2 = {
  registrationCeremonyId: string;
  signedSetup: SignedSetupPayloadB64u;
  idempotencyKey: ActivateIdempotencyKey;
  ecdsa: EcdsaFinalizeWork['ecdsa'] & {
    clientActivation: unknown; // RouterAbEcdsaVerifiedClientActivationFactsV1; bound at the parser
  };
  emailOtpEnrollment?: EcdsaFinalizeWork extends { emailOtpEnrollment?: infer T } ? T : never;
  emailOtpBackupAck?: EcdsaFinalizeWork extends { emailOtpBackupAck?: infer T } ? T : never;
};

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

export type WalletRegistrationActivateResponseV2 =
  | (Omit<EcdsaFinalizeSuccess, 'ecdsa'> & {
      ecdsa: ActivateEcdsaTerminalPayload;
      /** Mixed plans: deferred NEAR snapshot; never identifiers before readiness. */
      nearProvisioning?: { status: 'pending' };
    })
  | WalletRegistrationRouteErrorV2;
