/**
 * R103F: the one exact Wallet Session credential a signing-session operation is
 * allowed to act on.
 *
 * The wallet-wide active projection cannot answer this question. It selects a
 * session by wallet alone, so a sibling auth method's session satisfies it, and
 * its curve token bundle names threshold runtime identities that the exact
 * model resolves from authority material instead. Every read here starts at the
 * selected wallet authority and auth method, ends at one exact record with its
 * primary operation credential, and proves that record names the session the
 * caller already holds and carries the capability subject the operation needs.
 *
 * Expiry is a precondition when the credential authorizes a request and the
 * trigger — not a precondition — when the caller is invalidating a session the
 * server already reported as expired, so it is an explicit requirement rather
 * than a fixed rule.
 */

import {
  type ActiveWalletSessionV1,
  type WalletSessionAuthorizationRepository,
  type WalletSessionOperationCredentialV1,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { ResolveSelectedWalletAuthorityResultV1 } from '@/core/indexedDB/seamsWalletDB/repositories';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { SignerAuthMethod } from '@shared/utils/signerDomain';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  isExactEcdsaSigningLaneIdentity,
  type ExactSigningLaneIdentity,
} from './exactSigningLaneIdentity';
import type { ActiveWalletAuthMethodV2 } from './ownerLaneScope';

/** The signer material one operation needs the exact session to authorize. */
export type RequiredExactWalletSessionSigningSubject =
  | { readonly keyFamily: 'ed25519'; readonly materialActivation?: never }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    };

export type ExactWalletSessionExpiryRequirement =
  | { readonly kind: 'unexpired'; readonly nowMs: number }
  | { readonly kind: 'expired'; readonly nowMs: number };

export type ExactWalletSessionCredentialUnavailableReason =
  | 'selected_authority_missing'
  | 'selected_authority_invalid'
  | 'wallet_locked'
  | 'auth_method_inactive'
  | 'auth_method_mismatch'
  | 'authority_inactive'
  | 'authority_identity_mismatch'
  | 'signer_material_missing'
  | 'signer_material_mismatch'
  | 'wallet_session_missing'
  | 'wallet_session_upgrade_required'
  | 'wallet_session_identity_mismatch'
  | 'wallet_session_expired'
  | 'wallet_session_not_expired'
  | 'wallet_session_capability_mismatch'
  | 'persistence_unavailable';

export type ResolvedExactWalletSessionCredential = {
  readonly walletId: WalletId;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly session: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly walletSessionId: WalletSessionId;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type ExactWalletSessionCredentialResolution =
  | {
      readonly kind: 'resolved';
      readonly resolved: ResolvedExactWalletSessionCredential;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason: ExactWalletSessionCredentialUnavailableReason;
      readonly resolved?: never;
    };

export type ResolveExactWalletSessionCredentialInput = {
  readonly walletId: WalletId;
  readonly authMethod: SignerAuthMethod;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly requiredSigningSubject: RequiredExactWalletSessionSigningSubject;
  readonly expiry: ExactWalletSessionExpiryRequirement;
};

export type ExactWalletSessionReadPorts = {
  readonly resolveSelectedWalletAuthority: (
    walletId: string,
  ) => Promise<ResolveSelectedWalletAuthorityResultV1>;
  readonly readExactWithOperationCredential: WalletSessionAuthorizationRepository['readExactWithOperationCredential'];
};

type SelectedExactWalletAuthority = {
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: ActiveWalletAuthMethodV2;
};

function unavailable(
  reason: ExactWalletSessionCredentialUnavailableReason,
): ExactWalletSessionCredentialResolution {
  return { kind: 'unavailable', reason };
}

function selectedExactWalletAuthority(args: {
  readonly selected: ResolveSelectedWalletAuthorityResultV1;
  readonly walletId: WalletId;
  readonly authMethod: SignerAuthMethod;
}): SelectedExactWalletAuthority | ExactWalletSessionCredentialResolution {
  const selected = args.selected;
  if (selected.kind !== 'resolved') {
    switch (selected.kind) {
      case 'missing_selection':
        return unavailable('selected_authority_missing');
      case 'missing_auth_method':
      case 'missing_authority':
      case 'integrity_error':
        return unavailable('selected_authority_invalid');
      default: {
        const exhaustive: never = selected;
        return exhaustive;
      }
    }
  }
  if (
    selected.selection.walletId !== args.walletId ||
    selected.authMethod.walletId !== args.walletId ||
    selected.authority.walletId !== args.walletId ||
    selected.selection.walletAuthMethodId !== selected.authMethod.walletAuthMethodId ||
    selected.authMethod.walletAuthorityId !== selected.authority.authorityId
  ) {
    return unavailable('authority_identity_mismatch');
  }
  if (selected.selection.lockState !== 'unlocked') return unavailable('wallet_locked');
  if (selected.authMethod.status !== 'active') return unavailable('auth_method_inactive');
  if (selected.authority.state !== 'active') return unavailable('authority_inactive');
  if (selected.authMethod.kind !== args.authMethod) return unavailable('auth_method_mismatch');
  return { authority: selected.authority, authMethod: selected.authMethod };
}

function authorityMaterialActivation(args: {
  readonly authority: ActiveWalletAuthorityV1;
  readonly keyFamily: RequiredExactWalletSessionSigningSubject['keyFamily'];
}): MpcMaterialActivationRef | null {
  const activations = args.authority.signerActivations;
  if (args.keyFamily === 'ed25519') {
    return activations.ed25519?.materialActivation ?? null;
  }
  return activations.ecdsa?.materialActivation ?? null;
}

function sessionAuthorizesSigningSubject(args: {
  readonly session: ActiveWalletSessionV1;
  readonly keyFamily: RequiredExactWalletSessionSigningSubject['keyFamily'];
  readonly materialActivation: MpcMaterialActivationRef;
}): boolean {
  const subjects = args.session.capabilitySubjects.filter(
    (subject) =>
      subject.kind === 'sign' &&
      subject.keyFamily === args.keyFamily &&
      mpcMaterialActivationRefsEqual(subject.materialActivation, args.materialActivation),
  );
  return subjects.length === 1;
}

/** The signing subject an operation on this lane must find in the session. */
export function requiredSigningSubjectForExactSigningLane(
  identity: ExactSigningLaneIdentity,
): RequiredExactWalletSessionSigningSubject {
  if (isExactEcdsaSigningLaneIdentity(identity)) {
    return {
      keyFamily: 'ecdsa_secp256k1',
      materialActivation: identity.signer.materialActivation,
    };
  }
  return { keyFamily: 'ed25519' };
}

export async function resolveExactWalletSessionOperationCredential(args: {
  readonly input: ResolveExactWalletSessionCredentialInput;
  readonly ports: ExactWalletSessionReadPorts;
}): Promise<ExactWalletSessionCredentialResolution> {
  const { input, ports } = args;
  let selectedResult: ResolveSelectedWalletAuthorityResultV1;
  try {
    selectedResult = await ports.resolveSelectedWalletAuthority(String(input.walletId));
  } catch {
    return unavailable('persistence_unavailable');
  }
  const selected = selectedExactWalletAuthority({
    selected: selectedResult,
    walletId: input.walletId,
    authMethod: input.authMethod,
  });
  if ('kind' in selected) return selected;

  const materialActivation = authorityMaterialActivation({
    authority: selected.authority,
    keyFamily: input.requiredSigningSubject.keyFamily,
  });
  if (!materialActivation) return unavailable('signer_material_missing');
  if (
    input.requiredSigningSubject.keyFamily === 'ecdsa_secp256k1' &&
    !mpcMaterialActivationRefsEqual(
      input.requiredSigningSubject.materialActivation,
      materialActivation,
    )
  ) {
    return unavailable('signer_material_mismatch');
  }

  let read: Awaited<ReturnType<ExactWalletSessionReadPorts['readExactWithOperationCredential']>>;
  try {
    read = await ports.readExactWithOperationCredential({
      walletId: input.walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch {
    // A corrupt or duplicated exact row throws. Fail closed as unavailable so
    // the caller reauthorizes instead of acting on unverified state.
    return unavailable('persistence_unavailable');
  }
  switch (read.kind) {
    case 'found':
      break;
    case 'missing':
      return unavailable('wallet_session_missing');
    case 'upgrade_required':
      return unavailable('wallet_session_upgrade_required');
  }

  const session = read.record;
  const operationCredential = read.operationCredential;
  if (
    session.walletId !== input.walletId ||
    session.authorityId !== selected.authority.authorityId ||
    session.authMethodId !== selected.authMethod.walletAuthMethodId ||
    session.authorityDigestB64u !== selected.authority.authorityDigestB64u ||
    session.authorityRevocationEpoch !== selected.authority.revocationEpoch ||
    session.quotaId !== input.quotaId ||
    operationCredential.walletSessionId !== input.walletSessionId ||
    operationCredential.token.trim().length === 0
  ) {
    return unavailable('wallet_session_identity_mismatch');
  }
  if (input.expiry.kind === 'unexpired' && session.expiresAtMs <= input.expiry.nowMs) {
    return unavailable('wallet_session_expired');
  }
  if (input.expiry.kind === 'expired' && session.expiresAtMs > input.expiry.nowMs) {
    return unavailable('wallet_session_not_expired');
  }
  if (
    !sessionAuthorizesSigningSubject({
      session,
      keyFamily: input.requiredSigningSubject.keyFamily,
      materialActivation,
    })
  ) {
    return unavailable('wallet_session_capability_mismatch');
  }
  return {
    kind: 'resolved',
    resolved: {
      walletId: input.walletId,
      authority: selected.authority,
      authMethod: selected.authMethod,
      session,
      operationCredential,
      walletSessionId: operationCredential.walletSessionId,
      materialActivation,
    },
  };
}
