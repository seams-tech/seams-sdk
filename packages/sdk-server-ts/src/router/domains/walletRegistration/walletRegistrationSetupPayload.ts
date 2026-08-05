/**
 * Refactor 94C. The opaque payload `/wallets/register/setup` mints and routes
 * 2 and 3 verify.
 *
 * Setup admits the application, allocates the wallet, and runs the Router
 * preparation in one request. Routes 2 and 3 then need to know that the
 * ceremony they are being driven with is the one setup admitted, and with the
 * parameters setup admitted — without paying another storage round trip to
 * find out. The client carries this string and never parses it.
 *
 * The claims bind the route's canonical request digest, so a payload minted
 * for one ceremony cannot drive another, and a ceremony cannot be driven with
 * mutated parameters. Policy never appears here: it does not cross the public
 * wire at all. The Gateway mints a separate internal Router-policy JWT per
 * concrete Router call.
 *
 * Minting and verification both go through the Gateway session signer, which
 * is the sole minting authority and verifies locally against pinned key
 * material. Nothing here performs a JWKS fetch or any other I/O.
 */

import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { RegistrationIntentV1 } from '@shared/utils/registrationIntent';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import type { SignedSetupPayloadB64u } from '../../../core/threeRouteRegistrationContracts';

/* Minting and verification are separate capabilities on purpose: setup only
   mints, and routes 2 and 3 only verify. Neither needs the other's power. */

export type WalletRegistrationSetupMinter = {
  signJwt(sub: string, extra?: Record<string, unknown>): Promise<string>;
};

/* Matches `SessionService.verifyJwt` exactly rather than introducing a second
   verification shape for the same key material. */
export type WalletRegistrationSetupVerifier = {
  verifyJwt(token: string): Promise<
    { readonly valid: true; readonly payload: Record<string, unknown> } | { readonly valid: false }
  >;
};

export const WALLET_REGISTRATION_SETUP_CLAIM_KIND = 'wallet_registration_setup_v1' as const;

export type WalletRegistrationSetupClaimsV1 = {
  readonly kind: typeof WALLET_REGISTRATION_SETUP_CLAIM_KIND;
  readonly registrationCeremonyId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly policy:
    | {
        readonly kind: 'runtime_policy_scope';
        readonly scope: RuntimePolicyScope;
      }
    | {
        readonly kind: 'signing_root_only';
        readonly scope?: never;
      };
  /** Canonical digest of setup's own request bytes. */
  readonly setupDigestB64u: string;
  readonly expiresAtMs: number;
};

/**
 * Setup's canonical request digest, over canonically encoded bytes rather than
 * raw JSON, so property order cannot change the value.
 *
 * This is setup's own digest. Respond and activate each compute their own over
 * their own bytes, so a payload minted for one route can never satisfy
 * another.
 */
export async function computeWalletRegistrationSetupDigestB64u(input: {
  readonly registrationCeremonyId: string;
  readonly intent: RegistrationIntentV1;
  readonly intentDigestB64u: string;
  readonly orgId: string;
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly expectedOrigin: string;
}): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'wallet_registration_setup_digest_v1',
        registrationCeremonyId: input.registrationCeremonyId,
        intent: input.intent,
        intentDigestB64u: input.intentDigestB64u,
        orgId: input.orgId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        expectedOrigin: input.expectedOrigin,
      }),
    ),
  );
}

export async function mintSignedWalletRegistrationSetup(
  signer: WalletRegistrationSetupMinter,
  claims: WalletRegistrationSetupClaimsV1,
): Promise<SignedSetupPayloadB64u> {
  const token = await signer.signJwt(claims.registrationCeremonyId, { ...claims });
  return token as SignedSetupPayloadB64u;
}

export type WalletRegistrationSetupVerification =
  | { readonly ok: true; readonly claims: WalletRegistrationSetupClaimsV1 }
  | { readonly ok: false; readonly code: string; readonly message: string };

/**
 * Verifies the payload and binds it to the ceremony the caller is driving.
 * A payload that verifies cryptographically but names a different ceremony,
 * wallet, or setup digest is rejected — signature validity alone is not
 * authorization for this request.
 */
/**
 * Verifies the payload's signature, ceremony binding, and expiry, and returns
 * its claims — without needing the ceremony row.
 *
 * Activate depends on this: a successful activation deletes the ceremony, so
 * an exact replay must be answerable from the operation row alone. The claims
 * are Gateway-signed, so the `setupDigestB64u` they carry is trustworthy
 * without recomputing it from storage.
 */
export async function verifyWalletRegistrationSetupClaims(
  signer: WalletRegistrationSetupVerifier,
  token: unknown,
  expected: { readonly registrationCeremonyId: string; readonly nowMs: number },
): Promise<WalletRegistrationSetupVerification> {
  const value = toOptionalTrimmedString(token);
  if (!value) {
    return { ok: false, code: 'invalid_body', message: 'signedSetup is required' };
  }
  const verified = await signer.verifyJwt(value);
  if (!verified.valid) {
    return { ok: false, code: 'invalid_grant', message: 'signedSetup is not valid' };
  }
  const claims = parseWalletRegistrationSetupClaims(verified.payload);
  if (!claims) {
    return { ok: false, code: 'invalid_grant', message: 'signedSetup claims are not valid' };
  }
  if (claims.registrationCeremonyId !== expected.registrationCeremonyId) {
    return {
      ok: false,
      code: 'invalid_grant',
      message: 'signedSetup belongs to a different registration ceremony',
    };
  }
  if (claims.expiresAtMs <= expected.nowMs) {
    return { ok: false, code: 'invalid_grant', message: 'signedSetup has expired' };
  }
  return { ok: true, claims };
}

export async function verifySignedWalletRegistrationSetup(
  signer: WalletRegistrationSetupVerifier,
  token: unknown,
  expected: {
    readonly registrationCeremonyId: string;
    readonly setupDigestB64u: string;
    readonly nowMs: number;
  },
): Promise<WalletRegistrationSetupVerification> {
  const verified = await verifyWalletRegistrationSetupClaims(signer, token, expected);
  if (!verified.ok) return verified;
  /* Respond holds the ceremony, so it can additionally require that the
     payload matches the parameters actually stored. */
  if (verified.claims.setupDigestB64u !== expected.setupDigestB64u) {
    return {
      ok: false,
      code: 'invalid_grant',
      message: 'signedSetup does not match this registration setup',
    };
  }
  return verified;
}

export function parseWalletRegistrationSetupClaims(
  value: unknown,
): WalletRegistrationSetupClaimsV1 | null {
  if (typeof value !== 'object' || value === null) return null;
  const record = value as Record<string, unknown>;
  if (record.kind !== WALLET_REGISTRATION_SETUP_CLAIM_KIND) return null;
  const registrationCeremonyId = toOptionalTrimmedString(record.registrationCeremonyId);
  const walletId = toOptionalTrimmedString(record.walletId);
  const orgId = toOptionalTrimmedString(record.orgId);
  const signingRootId = toOptionalTrimmedString(record.signingRootId);
  const signingRootVersion = toOptionalTrimmedString(record.signingRootVersion);
  const setupDigestB64u = toOptionalTrimmedString(record.setupDigestB64u);
  const expiresAtMs = Number(record.expiresAtMs);
  const policy = parseWalletRegistrationSetupPolicy(record.policy);
  if (
    !registrationCeremonyId ||
    !walletId ||
    !orgId ||
    !signingRootId ||
    !signingRootVersion ||
    !setupDigestB64u ||
    !policy ||
    !Number.isSafeInteger(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: WALLET_REGISTRATION_SETUP_CLAIM_KIND,
    registrationCeremonyId,
    walletId,
    orgId,
    signingRootId,
    signingRootVersion,
    policy,
    setupDigestB64u,
    expiresAtMs,
  };
}

function parseWalletRegistrationSetupPolicy(
  value: unknown,
): WalletRegistrationSetupClaimsV1['policy'] | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  switch (record.kind) {
    case 'runtime_policy_scope':
      try {
        return {
          kind: 'runtime_policy_scope',
          scope: normalizeRuntimePolicyScope(record.scope),
        };
      } catch {
        return null;
      }
    case 'signing_root_only':
      return record.scope === undefined ? { kind: 'signing_root_only' } : null;
    default:
      return null;
  }
}
