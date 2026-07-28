import type {
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
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

export type WalletRegistrationRouteErrorV2 = {
  ok: false;
  code: string;
  message: string;
  retryAfterMs?: number;
};

/** Route 1 — one Gateway request replacing grant, intent, and start. */
export type WalletRegistrationSetupRequestV2 = {
  wallet: WalletRegistrationStartRequest['intent']['walletId'] extends never
    ? never
    : { kind: 'provided'; walletId: string } | { kind: 'server_allocated' };
  intent: WalletRegistrationStartRequest['intent'];
};

export type WalletRegistrationSetupResponseV2 =
  | {
      ok: true;
      registrationCeremonyId: string;
      walletId: string;
      /** Opaque; echoed verbatim on routes 2 and 3. */
      signedSetup: SignedSetupPayloadB64u;
      ecdsa: WalletRegistrationEcdsaPreparePayload;
      /** Mixed plans only; unchanged Yao admission shapes. */
      ed25519?: SetupEd25519Work;
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

export type WalletRegistrationActivateResponseV2 =
  | (EcdsaFinalizeSuccess & {
      /** Mixed plans: deferred NEAR snapshot; never identifiers before readiness. */
      nearProvisioning?: { status: 'pending' };
    })
  | WalletRegistrationRouteErrorV2;
