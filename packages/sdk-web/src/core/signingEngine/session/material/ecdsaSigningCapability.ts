import type { ActiveEcdsaCapabilityManifest } from './ecdsaCapabilityManifest';
import type { PersistedEcdsaRoleLocalMaterial } from './ecdsaRoleLocalMaterialResolver';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type { ReusableWalletSessionStatus } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import {
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

export type ActiveEvmFamilyWalletSessionAuthorization = {
  readonly kind: 'active_reusable_wallet_session_authorization';
  readonly projection: ActiveWalletSessionAuthorizationProjection;
  readonly status: Extract<ReusableWalletSessionStatus, { readonly status: 'active' }>;
};

export type CanonicalEvmFamilyEcdsaSigningCapability = {
  readonly kind: 'canonical_evm_family_ecdsa_signing_capability';
  readonly authority: WalletAuthAuthority;
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly material: PersistedEcdsaRoleLocalMaterial;
};

// The canonical capability is durable state: it must resolve from persistence
// alone so hydration can rebind exact material while no reusable Wallet Session
// is active. Authorization is the independent second proof, paired with the
// capability only on the signing path.
export type AuthorizedEvmFamilyEcdsaSigningCapability = {
  readonly kind: 'authorized_evm_family_ecdsa_signing_capability';
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly authorization: ActiveEvmFamilyWalletSessionAuthorization;
};

export type EvmFamilyEcdsaSigningCapabilityAvailability =
  | AuthorizedEvmFamilyEcdsaSigningCapability
  | {
      readonly kind: 'authorization_required';
      readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
      readonly authorization?: never;
    };

export function authorizeEvmFamilyEcdsaSigningCapability(input: {
  readonly capability: CanonicalEvmFamilyEcdsaSigningCapability;
  readonly authorization: ActiveEvmFamilyWalletSessionAuthorization;
}): AuthorizedEvmFamilyEcdsaSigningCapability {
  const signer = input.capability.manifest.signer;
  const projection = input.authorization.projection;
  if (
    projection.walletId !== signer.walletId ||
    projection.authority.authorityDigest !== signer.authority.authorityDigest
  ) {
    throw new Error(
      'Reusable Wallet Session authorization does not bind the ECDSA signing capability',
    );
  }
  return {
    kind: 'authorized_evm_family_ecdsa_signing_capability',
    capability: input.capability,
    authorization: input.authorization,
  };
}

export async function buildCanonicalEvmFamilyEcdsaSigningCapability(input: {
  readonly authority: WalletAuthAuthority;
  readonly manifest: ActiveEcdsaCapabilityManifest;
  readonly material: PersistedEcdsaRoleLocalMaterial;
}): Promise<CanonicalEvmFamilyEcdsaSigningCapability> {
  const signer = input.manifest.signer;
  const registeredPublicFacts = signer.registeredPublicFacts;
  const materialPublicFacts = input.material.publicFacts;
  const authorityRef = await walletAuthAuthorityRef({ authority: input.authority });
  if (
    authorityRef.authorityDigest !== signer.authority.authorityDigest ||
    authorityRef.walletId !== signer.walletId ||
    input.material.authority.walletId !== signer.walletId ||
    input.material.authority.authorityDigest !== signer.authority.authorityDigest ||
    !mpcMaterialActivationRefsEqual(
      input.material.materialActivation,
      input.manifest.activation.materialActivation,
    ) ||
    materialPublicFacts.walletId !== signer.walletId ||
    materialPublicFacts.keyHandle !== registeredPublicFacts.keyHandle ||
    String(materialPublicFacts.groupPublicKey33B64u) !==
      String(registeredPublicFacts.publicKeyB64u) ||
    materialPublicFacts.ethereumAddress !== registeredPublicFacts.thresholdOwnerAddress ||
    materialPublicFacts.participantIds.length !== registeredPublicFacts.participantIds.length ||
    materialPublicFacts.participantIds.some(
      (participantId, index) => participantId !== registeredPublicFacts.participantIds[index],
    )
  ) {
    throw new Error('Canonical EVM-family ECDSA signing capability identity is inconsistent');
  }
  return {
    kind: 'canonical_evm_family_ecdsa_signing_capability',
    authority: input.authority,
    manifest: input.manifest,
    material: input.material,
  };
}
