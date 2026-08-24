/**
 * Refactor 109C — the internal contract for same-device auth-method addition.
 *
 * One product action ("Add authentication method") has exactly two branches:
 * a Passkey-only authority adds Email OTP, or an Email-OTP-only authority adds
 * a Passkey. Both fill the missing factor family on an authority that already
 * exists; neither creates an authority, signer activation, share, public key,
 * export root, or key manifest.
 *
 * Same-family addition is not expressible here. There is no branch for it, so
 * an attempt to add a family the authority already has is resolved as
 * `already_configured` at admission — before any target verification or local
 * write — rather than travelling through the operation as a rejected case.
 *
 * Every identity a branch depends on is required and branded. The raw wire and
 * storage values are parsed once by {@link parseAddWalletAuthMethodSourceV1}
 * and {@link parseAddWalletAuthMethodIntentIdentityV1} at their boundary; core
 * code below them receives branded identities and one verified branch, and
 * never compares raw identity strings.
 */

import { parseDeviceId, parseWalletSessionId } from '../authorization/capabilityKinds';
import type { DeviceId, WalletSessionId } from '../authorization/capabilityKinds';
import { parseDigestB64u } from './canonicalPrimitives';
import type { DigestB64u } from './canonicalPrimitives';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from './domainIds';
import type {
  EmailOtpWalletAuthMethodDraftV1,
  PasskeyWalletAuthMethodDraftV1,
  WalletAuthMethodRecordV2,
} from './registrationIntent';

/**
 * The factor family a method belongs to.
 *
 * Derived from the canonical record rather than written out as its own literal
 * union: a hand-written `'passkey' | 'email_otp'` is a second, unversioned
 * declaration of the same domain fact, and the auth-method domain guard fails
 * on one for exactly that reason.
 */
export type WalletAuthMethodFamilyV1 = WalletAuthMethodRecordV2['kind'];

/**
 * The two exhaustive branches. The name reads source-to-target, which is the
 * order every stage of the operation uses: resolve the source, then verify the
 * target.
 */
export type AddWalletAuthMethodBranchV1 = 'passkey_to_email_otp' | 'email_otp_to_passkey';

/**
 * A validated authority generation. Branding it stops a revocation epoch from
 * being read as any other integer on the authority — a signer slot, a counter,
 * a timestamp — at the boundaries where all of them arrive as bare numbers.
 */
export type WalletAuthorityRevocationEpochV1 = number & {
  readonly __walletAuthorityRevocationEpochBrand: 'WalletAuthorityRevocationEpochV1';
};

/**
 * One server-allocated addition ceremony. The server mints it, binds the
 * target method ID to it, and a client request can neither nominate nor
 * substitute one.
 */
export type AddWalletAuthMethodCeremonyIdV1 = string & {
  readonly __addWalletAuthMethodCeremonyIdBrand: 'AddWalletAuthMethodCeremonyIdV1';
};

/**
 * Everything the active Wallet Session names about the source.
 *
 * The caller supplies none of it: the selected session names the exact source
 * method, and the server resolves the wallet, authority, device, digest, and
 * epoch from that method. Each field is required, so a branch cannot be built
 * from a partially resolved session.
 */
export type AddWalletAuthMethodSourceV1 = {
  readonly walletId: WalletId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly sourceWalletAuthMethodId: WalletAuthMethodId;
  readonly sourceWalletSessionId: WalletSessionId;
  readonly deviceId: DeviceId;
  readonly authorityDigestB64u: DigestB64u;
  readonly revocationEpoch: WalletAuthorityRevocationEpochV1;
};

/**
 * The intent identity every stage revalidates against.
 *
 * `targetWalletAuthMethodId` is allocated by the server during preparation and
 * bound into the Passkey creation options or the Email OTP grant, so a retry
 * that reuses this intent converges on the same target method instead of
 * creating a second one.
 */
export type AddWalletAuthMethodIntentIdentityV1 = {
  readonly addAuthMethodCeremonyId: AddWalletAuthMethodCeremonyIdV1;
  readonly intentDigestB64u: DigestB64u;
  readonly targetWalletAuthMethodId: WalletAuthMethodId;
  readonly expiresAtMs: number;
};

/**
 * Fresh source authorization for this exact intent.
 *
 * Both variants carry the digest they were collected against, which is what
 * binds the proof to one wallet, authority, source method, source session,
 * target method ID, and authority state rather than to the operation kind.
 */
export type VerifiedAddWalletAuthMethodSourceProofV1 =
  | {
      readonly kind: 'verified_passkey_source_proof_v1';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly boundIntentDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'verified_email_otp_source_proof_v1';
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly boundIntentDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    };

/**
 * The independently verified target factor plus its exact draft.
 *
 * A source proof can never appear here: the target is verified on its own
 * evidence — a created credential, or a consumed one-use Email OTP grant — and
 * the two are separate fields on the branch so neither can stand in for the
 * other.
 */
export type VerifiedAddWalletAuthMethodTargetV1 =
  | {
      readonly kind: 'verified_passkey_target_v1';
      readonly authMethod: PasskeyWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    }
  | {
      readonly kind: 'verified_email_otp_target_v1';
      readonly authMethod: EmailOtpWalletAuthMethodDraftV1;
      readonly verificationDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
    };

type VerifiedPasskeySourceProofV1 = Extract<
  VerifiedAddWalletAuthMethodSourceProofV1,
  { readonly kind: 'verified_passkey_source_proof_v1' }
>;
type VerifiedEmailOtpSourceProofV1 = Extract<
  VerifiedAddWalletAuthMethodSourceProofV1,
  { readonly kind: 'verified_email_otp_source_proof_v1' }
>;
type VerifiedPasskeyTargetV1 = Extract<
  VerifiedAddWalletAuthMethodTargetV1,
  { readonly kind: 'verified_passkey_target_v1' }
>;
type VerifiedEmailOtpTargetV1 = Extract<
  VerifiedAddWalletAuthMethodTargetV1,
  { readonly kind: 'verified_email_otp_target_v1' }
>;

type AddWalletAuthMethodInputCommonV1 = {
  readonly source: AddWalletAuthMethodSourceV1;
  readonly intent: AddWalletAuthMethodIntentIdentityV1;
};

/**
 * What core code accepts after verification, and the only shape the activation
 * stage reads. The proof/target pairing is fixed per branch, so a verified
 * Passkey source cannot arrive alongside a verified Passkey target.
 */
export type VerifiedAddWalletAuthMethodInputV1 =
  | (AddWalletAuthMethodInputCommonV1 & {
      readonly branch: 'passkey_to_email_otp';
      readonly sourceProof: VerifiedPasskeySourceProofV1;
      readonly target: VerifiedEmailOtpTargetV1;
    })
  | (AddWalletAuthMethodInputCommonV1 & {
      readonly branch: 'email_otp_to_passkey';
      readonly sourceProof: VerifiedEmailOtpSourceProofV1;
      readonly target: VerifiedPasskeyTargetV1;
    });

export type AddWalletAuthMethodFailureReasonV1 =
  | 'source_session_not_selected'
  | 'source_method_not_active'
  | 'source_authority_not_active'
  | 'source_authority_not_full_owner'
  | 'source_authority_changed'
  | 'local_installation_incomplete'
  | 'source_proof_rejected'
  | 'target_factor_rejected'
  | 'target_family_present'
  | 'intent_expired'
  | 'intent_digest_mismatch'
  | 'identity_mismatch'
  | 'custody_reseal_failed'
  | 'local_persistence_failed'
  | 'activation_conflict';

/**
 * The one result union both SDK entry points return. UI control flow switches
 * on `kind`; `reason` and `message` are display and diagnostic data and never
 * select a code path.
 */
export type AddWalletAuthMethodResultV1 =
  | {
      readonly kind: 'active';
      readonly branch: AddWalletAuthMethodBranchV1;
      readonly walletId: WalletId;
      readonly walletAuthorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly family: WalletAuthMethodFamilyV1;
      readonly sourceWalletAuthMethodId: WalletAuthMethodId;
      readonly sourceWalletSessionId: WalletSessionId;
    }
  | {
      readonly kind: 'already_configured';
      readonly walletId: WalletId;
      readonly walletAuthorityId: WalletAuthorityId;
      readonly family: WalletAuthMethodFamilyV1;
      readonly existingWalletAuthMethodId: WalletAuthMethodId;
    }
  | { readonly kind: 'cancelled'; readonly branch: AddWalletAuthMethodBranchV1 }
  | { readonly kind: 'expired'; readonly branch: AddWalletAuthMethodBranchV1 }
  | {
      readonly kind: 'unauthorized';
      readonly branch: AddWalletAuthMethodBranchV1;
      readonly reason: AddWalletAuthMethodFailureReasonV1;
      readonly message: string;
    }
  | {
      readonly kind: 'target_verification_failed';
      readonly branch: AddWalletAuthMethodBranchV1;
      readonly reason: AddWalletAuthMethodFailureReasonV1;
      readonly message: string;
    }
  | {
      readonly kind: 'integrity_error';
      readonly branch: AddWalletAuthMethodBranchV1;
      readonly reason: AddWalletAuthMethodFailureReasonV1;
      readonly message: string;
    };

/**
 * Admission: what the operation does before it verifies anything.
 *
 * `already_configured` is a first-class outcome rather than a failure, because
 * a user whose wallet already has both families asked for a state that already
 * holds. Resolving it here is what keeps the promise that a present family
 * never reaches target verification or a local write.
 */
export type AddWalletAuthMethodAdmissionV1 =
  | { readonly kind: 'proceed'; readonly branch: AddWalletAuthMethodBranchV1 }
  | {
      readonly kind: 'already_configured';
      readonly family: WalletAuthMethodFamilyV1;
      readonly existingWalletAuthMethodId: WalletAuthMethodId;
    };

export function unreachableAddWalletAuthMethodBranch(value: never): never {
  throw new Error(`Unhandled add-auth-method branch: ${String(value)}`);
}

function unreachableAuthMethodFamily(value: never): never {
  throw new Error(`Unhandled wallet auth-method family: ${String(value)}`);
}

/** The family a branch fills in. */
export function addWalletAuthMethodTargetFamily(
  branch: AddWalletAuthMethodBranchV1,
): WalletAuthMethodFamilyV1 {
  switch (branch) {
    case 'passkey_to_email_otp':
      return 'email_otp';
    case 'email_otp_to_passkey':
      return 'passkey';
    default:
      return unreachableAddWalletAuthMethodBranch(branch);
  }
}

/** The family the branch authorizes from. */
export function addWalletAuthMethodSourceFamily(
  branch: AddWalletAuthMethodBranchV1,
): WalletAuthMethodFamilyV1 {
  switch (branch) {
    case 'passkey_to_email_otp':
      return 'passkey';
    case 'email_otp_to_passkey':
      return 'email_otp';
    default:
      return unreachableAddWalletAuthMethodBranch(branch);
  }
}

/**
 * Resolves the branch from the exact active inventory of one authority.
 *
 * The selected session's method decides the source, and the requested target
 * family decides the rest. Both same-family cases — the target family is the
 * source's own, or a sibling already holds it — land on `already_configured`,
 * which is why the operation needs no same-family rejection of its own.
 */
export function admitAddWalletAuthMethod(input: {
  readonly sourceMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  readonly targetFamily: WalletAuthMethodFamilyV1;
  readonly activeMethodsOnAuthority: readonly Extract<
    WalletAuthMethodRecordV2,
    { readonly status: 'active' }
  >[];
}): AddWalletAuthMethodAdmissionV1 {
  const present = input.activeMethodsOnAuthority.find(
    (method) => method.kind === input.targetFamily,
  );
  if (present) {
    return {
      kind: 'already_configured',
      family: input.targetFamily,
      existingWalletAuthMethodId: present.walletAuthMethodId,
    };
  }
  switch (input.sourceMethod.kind) {
    case 'passkey':
      return { kind: 'proceed', branch: 'passkey_to_email_otp' };
    case 'email_otp':
      return { kind: 'proceed', branch: 'email_otp_to_passkey' };
    default:
      return unreachableAuthMethodFamily(input.sourceMethod);
  }
}

function requireSafeNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return value;
}

export function parseWalletAuthorityRevocationEpochV1(
  value: unknown,
): WalletAuthorityRevocationEpochV1 {
  return requireSafeNonNegativeInteger(
    value,
    'revocationEpoch',
  ) as WalletAuthorityRevocationEpochV1;
}

export function parseAddWalletAuthMethodCeremonyIdV1(
  value: unknown,
): AddWalletAuthMethodCeremonyIdV1 {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error('addAuthMethodCeremonyId must be a non-empty canonical string');
  }
  return value as AddWalletAuthMethodCeremonyIdV1;
}

function requireBrandedId<T>(
  parsed: { ok: true; value: T } | { ok: false; error: { message: string } },
  label: string,
): T {
  if (!parsed.ok) throw new Error(`${label} is invalid: ${parsed.error.message}`);
  return parsed.value;
}

/**
 * The one place raw source identity becomes branded. Every field is read from
 * the resolved session and authority, so a caller cannot widen the source by
 * supplying an extra one.
 */
export function parseAddWalletAuthMethodSourceV1(raw: {
  readonly walletId: unknown;
  readonly walletAuthorityId: unknown;
  readonly sourceWalletAuthMethodId: unknown;
  readonly sourceWalletSessionId: unknown;
  readonly deviceId: unknown;
  readonly authorityDigestB64u: unknown;
  readonly revocationEpoch: unknown;
}): AddWalletAuthMethodSourceV1 {
  return {
    walletId: requireBrandedId(parseWalletId(raw.walletId), 'walletId'),
    walletAuthorityId: requireBrandedId(
      parseWalletAuthorityId(raw.walletAuthorityId),
      'walletAuthorityId',
    ),
    sourceWalletAuthMethodId: requireBrandedId(
      parseWalletAuthMethodId(raw.sourceWalletAuthMethodId),
      'sourceWalletAuthMethodId',
    ),
    sourceWalletSessionId: requireBrandedId(
      parseWalletSessionId(raw.sourceWalletSessionId),
      'sourceWalletSessionId',
    ),
    deviceId: requireBrandedId(parseDeviceId(raw.deviceId), 'deviceId'),
    authorityDigestB64u: parseDigestB64u(raw.authorityDigestB64u),
    revocationEpoch: parseWalletAuthorityRevocationEpochV1(raw.revocationEpoch),
  };
}

export function parseAddWalletAuthMethodIntentIdentityV1(raw: {
  readonly addAuthMethodCeremonyId: unknown;
  readonly intentDigestB64u: unknown;
  readonly targetWalletAuthMethodId: unknown;
  readonly expiresAtMs: unknown;
}): AddWalletAuthMethodIntentIdentityV1 {
  const expiresAtMs = requireSafeNonNegativeInteger(raw.expiresAtMs, 'expiresAtMs');
  if (expiresAtMs === 0) throw new Error('expiresAtMs must be a positive safe integer');
  return {
    addAuthMethodCeremonyId: parseAddWalletAuthMethodCeremonyIdV1(raw.addAuthMethodCeremonyId),
    intentDigestB64u: parseDigestB64u(raw.intentDigestB64u),
    targetWalletAuthMethodId: requireBrandedId(
      parseWalletAuthMethodId(raw.targetWalletAuthMethodId),
      'targetWalletAuthMethodId',
    ),
    expiresAtMs,
  };
}

function assertBranchIdentitiesAgree(input: {
  readonly source: AddWalletAuthMethodSourceV1;
  readonly intent: AddWalletAuthMethodIntentIdentityV1;
  readonly sourceProof: VerifiedAddWalletAuthMethodSourceProofV1;
  readonly target: VerifiedAddWalletAuthMethodTargetV1;
}): void {
  if (input.sourceProof.walletAuthMethodId !== input.source.sourceWalletAuthMethodId) {
    throw new Error('add-auth-method source proof names another auth method');
  }
  if (input.sourceProof.boundIntentDigestB64u !== input.intent.intentDigestB64u) {
    throw new Error('add-auth-method source proof is bound to another intent');
  }
  if (input.target.authMethod.walletId !== input.source.walletId) {
    throw new Error('add-auth-method target draft names another wallet');
  }
  if (input.target.authMethod.walletAuthMethodId !== input.intent.targetWalletAuthMethodId) {
    throw new Error('add-auth-method target draft names another auth method');
  }
}

/**
 * Branch-specific builders rather than one constructor with a `branch`
 * parameter: each accepts only the proof and target its branch can hold, so a
 * mismatched pair is a compile error at the call site instead of a runtime
 * check inside the operation.
 */
export function buildPasskeyToEmailOtpAdditionV1(input: {
  readonly source: AddWalletAuthMethodSourceV1;
  readonly intent: AddWalletAuthMethodIntentIdentityV1;
  readonly sourceProof: VerifiedPasskeySourceProofV1;
  readonly target: VerifiedEmailOtpTargetV1;
}): Extract<VerifiedAddWalletAuthMethodInputV1, { readonly branch: 'passkey_to_email_otp' }> {
  assertBranchIdentitiesAgree(input);
  return {
    branch: 'passkey_to_email_otp',
    source: input.source,
    intent: input.intent,
    sourceProof: input.sourceProof,
    target: input.target,
  };
}

export function buildEmailOtpToPasskeyAdditionV1(input: {
  readonly source: AddWalletAuthMethodSourceV1;
  readonly intent: AddWalletAuthMethodIntentIdentityV1;
  readonly sourceProof: VerifiedEmailOtpSourceProofV1;
  readonly target: VerifiedPasskeyTargetV1;
}): Extract<VerifiedAddWalletAuthMethodInputV1, { readonly branch: 'email_otp_to_passkey' }> {
  assertBranchIdentitiesAgree(input);
  return {
    branch: 'email_otp_to_passkey',
    source: input.source,
    intent: input.intent,
    sourceProof: input.sourceProof,
    target: input.target,
  };
}

/**
 * The exact active record the activation stage inserts.
 *
 * It reuses the source authority and the server-allocated target method ID,
 * and it is built from the verified target draft alone — no field is carried
 * across from the source method, which is what keeps addition from copying
 * permissions, activations, or credential identity onto the new method.
 */
export function buildAddedWalletAuthMethodRecordV2Input(input: {
  readonly verified: VerifiedAddWalletAuthMethodInputV1;
  readonly nowMs: number;
}): WalletAuthMethodRecordV2 {
  const activatedAtMs = requireSafeNonNegativeInteger(input.nowMs, 'nowMs');
  const common = {
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: input.verified.intent.targetWalletAuthMethodId,
    walletId: input.verified.source.walletId,
    walletAuthorityId: input.verified.source.walletAuthorityId,
    status: 'active',
    createdAtMs: input.verified.target.authMethod.createdAtMs,
    updatedAtMs: activatedAtMs,
    activatedAtMs,
  } as const;
  switch (input.verified.branch) {
    case 'passkey_to_email_otp':
      return {
        ...common,
        kind: 'email_otp',
        emailHashHex: input.verified.target.authMethod.emailHashHex,
        registrationAuthorityId: input.verified.target.authMethod.registrationAuthorityId,
      };
    case 'email_otp_to_passkey':
      return {
        ...common,
        kind: 'passkey',
        rpId: input.verified.target.authMethod.rpId,
        credentialIdB64u: input.verified.target.authMethod.credentialIdB64u,
        credentialPublicKeyB64u: input.verified.target.authMethod.credentialPublicKeyB64u,
        counter: input.verified.target.authMethod.counter,
      };
    default:
      return unreachableAddWalletAuthMethodBranch(input.verified);
  }
}
