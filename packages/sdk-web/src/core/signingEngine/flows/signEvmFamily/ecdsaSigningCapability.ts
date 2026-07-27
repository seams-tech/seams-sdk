import type {
  ActiveEcdsaCapabilityManifest,
} from '../../session/material/ecdsaCapabilityManifest';
import type {
  PersistedEcdsaRoleLocalMaterial,
} from '../../session/material/ecdsaRoleLocalMaterialResolver';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type {
  ReusableWalletSessionStatus,
} from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import type {
  ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
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
