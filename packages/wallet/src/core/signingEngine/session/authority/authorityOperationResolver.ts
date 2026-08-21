import {
  computeWalletAuthorityDigestB64u,
  computeWalletSignerActivationSetDigestB64u,
  type WalletAuthorityV1,
  type WalletEcdsaSignerActivationV1,
  type WalletEd25519SignerActivationV1,
  type WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type {
  MpcMaterialActivationRef,
  WalletAuthMethodId,
  WalletAuthorityId,
  WalletId,
  WalletKeyId,
} from '@shared/utils/domainIds';

export type WalletAuthorityOperationV1 =
  | {
      readonly kind: 'near_sign';
      readonly operation: 'sign';
      readonly keyFamily: 'ed25519';
    }
  | {
      readonly kind: 'near_export';
      readonly operation: 'export_keys';
      readonly keyFamily: 'ed25519';
    }
  | {
      readonly kind: 'evm_sign';
      readonly operation: 'sign';
      readonly keyFamily: 'ecdsa_secp256k1';
    }
  | {
      readonly kind: 'evm_export';
      readonly operation: 'export_keys';
      readonly keyFamily: 'ecdsa_secp256k1';
    };

export type SelectedWalletAuthorityV1 = {
  readonly authMethod: WalletAuthMethodRecordV2;
  readonly authority: WalletAuthorityV1;
};

export type ResolveWalletAuthorityOperationInputV1 = {
  readonly selected: SelectedWalletAuthorityV1;
  readonly operation: WalletAuthorityOperationV1;
};

type ResolvedWalletAuthorityOperationCommonV1 = {
  readonly kind: 'resolved';
  readonly operation: WalletAuthorityOperationV1['operation'];
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly authMethodId: WalletAuthMethodId;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type ResolvedWalletAuthorityOperationV1 =
  | (ResolvedWalletAuthorityOperationCommonV1 & {
      readonly keyFamily: 'ed25519';
      readonly walletKeyId: WalletKeyId;
      readonly registeredPublicKeyB64u: string;
      readonly thresholdPublicKey33B64u?: never;
      readonly evmAddress?: never;
    })
  | (ResolvedWalletAuthorityOperationCommonV1 & {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly walletKeyId: WalletKeyId;
      readonly thresholdPublicKey33B64u: string;
      readonly evmAddress: string;
      readonly registeredPublicKeyB64u?: never;
    });

export type WalletAuthorityOperationResolutionFailureV1 =
  | {
      readonly kind: 'wallet_id_mismatch';
      readonly authorityWalletId: WalletId;
      readonly authMethodWalletId: WalletId;
    }
  | {
      readonly kind: 'authority_id_mismatch';
      readonly authorityId: WalletAuthorityId;
      readonly authMethodAuthorityId: WalletAuthorityId;
    }
  | { readonly kind: 'authority_not_active'; readonly authorityId: WalletAuthorityId }
  | { readonly kind: 'auth_method_not_active'; readonly authMethodId: WalletAuthMethodId }
  | {
      readonly kind: 'authority_activation_set_digest_mismatch';
      readonly authorityId: WalletAuthorityId;
      readonly expected: DigestB64u;
      readonly actual: DigestB64u;
    }
  | {
      readonly kind: 'authority_digest_mismatch';
      readonly authorityId: WalletAuthorityId;
      readonly expected: DigestB64u;
      readonly actual: DigestB64u;
    }
  | {
      readonly kind: 'permission_missing';
      readonly authorityId: WalletAuthorityId;
      readonly requiredPermission: 'sign' | 'export_keys';
      readonly operation: WalletAuthorityOperationV1['operation'];
    }
  | {
      readonly kind: 'signer_family_unavailable';
      readonly authorityId: WalletAuthorityId;
      readonly keyFamily: WalletAuthorityOperationV1['keyFamily'];
    }
  | {
      readonly kind: 'signer_wallet_id_mismatch';
      readonly authorityId: WalletAuthorityId;
      readonly signerWalletId: WalletId;
    };

export type ResolveWalletAuthorityOperationResultV1 =
  | { readonly kind: 'resolved'; readonly value: ResolvedWalletAuthorityOperationV1 }
  | { readonly kind: 'rejected'; readonly reason: WalletAuthorityOperationResolutionFailureV1 };

export async function resolveWalletAuthorityOperation(
  input: ResolveWalletAuthorityOperationInputV1,
): Promise<ResolveWalletAuthorityOperationResultV1> {
  const { authMethod, authority } = input.selected;
  if (authority.state !== 'active') {
    return {
      kind: 'rejected',
      reason: { kind: 'authority_not_active', authorityId: authority.authorityId },
    };
  }
  if (authMethod.status !== 'active') {
    return {
      kind: 'rejected',
      reason: { kind: 'auth_method_not_active', authMethodId: authMethod.walletAuthMethodId },
    };
  }
  if (authority.walletId !== authMethod.walletId) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'wallet_id_mismatch',
        authorityWalletId: authority.walletId,
        authMethodWalletId: authMethod.walletId,
      },
    };
  }
  if (authority.authorityId !== authMethod.walletAuthorityId) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'authority_id_mismatch',
        authorityId: authority.authorityId,
        authMethodAuthorityId: authMethod.walletAuthorityId,
      },
    };
  }

  const activationDigest = await computeWalletSignerActivationSetDigestB64u(
    authority.signerActivations,
  );
  if (activationDigest !== authority.signerActivationSetDigestB64u) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'authority_activation_set_digest_mismatch',
        authorityId: authority.authorityId,
        expected: authority.signerActivationSetDigestB64u,
        actual: activationDigest,
      },
    };
  }
  const authorityDigest = await computeWalletAuthorityDigestB64u(authority);
  if (authorityDigest !== authority.authorityDigestB64u) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'authority_digest_mismatch',
        authorityId: authority.authorityId,
        expected: authority.authorityDigestB64u,
        actual: authorityDigest,
      },
    };
  }

  const requiredPermission = requiredPermissionForOperation(input.operation);
  if (!authority.permissions.includes(requiredPermission)) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'permission_missing',
        authorityId: authority.authorityId,
        requiredPermission,
        operation: input.operation.operation,
      },
    };
  }

  switch (input.operation.kind) {
    case 'near_sign':
    case 'near_export':
      return resolveEd25519Operation(input.operation, authority, authMethod);
    case 'evm_sign':
    case 'evm_export':
      return resolveEcdsaOperation(input.operation, authority, authMethod);
    default:
      return assertNeverOperation(input.operation);
  }
}

function requiredPermissionForOperation(
  operation: WalletAuthorityOperationV1,
): 'sign' | 'export_keys' {
  switch (operation.kind) {
    case 'near_sign':
    case 'evm_sign':
      return 'sign';
    case 'near_export':
    case 'evm_export':
      return 'export_keys';
    default:
      return assertNeverOperation(operation);
  }
}

function resolveEd25519Operation(
  operation: Extract<WalletAuthorityOperationV1, { readonly keyFamily: 'ed25519' }>,
  authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>,
  authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
): ResolveWalletAuthorityOperationResultV1 {
  const activation = ed25519Activation(authority.signerActivations);
  if (activation === null) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'signer_family_unavailable',
        authorityId: authority.authorityId,
        keyFamily: operation.keyFamily,
      },
    };
  }
  if (activation.signer.walletId !== authority.walletId) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'signer_wallet_id_mismatch',
        authorityId: authority.authorityId,
        signerWalletId: activation.signer.walletId,
      },
    };
  }
  return {
    kind: 'resolved',
    value: {
      kind: 'resolved',
      operation: operation.operation,
      keyFamily: 'ed25519',
      walletId: authority.walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
      materialActivation: activation.materialActivation,
      walletKeyId: activation.signer.walletKeyId,
      registeredPublicKeyB64u: activation.signer.registeredPublicKeyB64u,
    },
  };
}

function resolveEcdsaOperation(
  operation: Extract<WalletAuthorityOperationV1, { readonly keyFamily: 'ecdsa_secp256k1' }>,
  authority: Extract<WalletAuthorityV1, { readonly state: 'active' }>,
  authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>,
): ResolveWalletAuthorityOperationResultV1 {
  const activation = ecdsaActivation(authority.signerActivations);
  if (activation === null) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'signer_family_unavailable',
        authorityId: authority.authorityId,
        keyFamily: operation.keyFamily,
      },
    };
  }
  if (activation.signer.walletId !== authority.walletId) {
    return {
      kind: 'rejected',
      reason: {
        kind: 'signer_wallet_id_mismatch',
        authorityId: authority.authorityId,
        signerWalletId: activation.signer.walletId,
      },
    };
  }
  return {
    kind: 'resolved',
    value: {
      kind: 'resolved',
      operation: operation.operation,
      keyFamily: 'ecdsa_secp256k1',
      walletId: authority.walletId,
      authorityId: authority.authorityId,
      authMethodId: authMethod.walletAuthMethodId,
      materialActivation: activation.materialActivation,
      walletKeyId: activation.signer.walletKeyId,
      thresholdPublicKey33B64u: activation.signer.thresholdPublicKey33B64u,
      evmAddress: activation.signer.evmAddress,
    },
  };
}

function ed25519Activation(
  activations: WalletSignerActivationSetV1,
): WalletEd25519SignerActivationV1 | null {
  if (activations.keyFamilies[0] !== 'ed25519') return null;
  if (activations.ed25519 === undefined) return null;
  return activations.ed25519;
}

function ecdsaActivation(
  activations: WalletSignerActivationSetV1,
): WalletEcdsaSignerActivationV1 | null {
  if (activations.keyFamilies[0] !== 'ecdsa_secp256k1' && activations.keyFamilies.length !== 2) {
    return null;
  }
  if (activations.ecdsa === undefined) return null;
  return activations.ecdsa;
}

function assertNeverOperation(value: never): never {
  throw new Error(`unsupported wallet authority operation: ${String(value)}`);
}
