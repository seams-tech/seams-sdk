import {
  nearEd25519YaoRuntimeRef,
  type NearEd25519YaoCapabilityHydrationInputV1,
} from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import {
  buildMpcCapabilityPublicReauthAnchor,
} from '@/core/signingEngine/session/material/mpcCapabilityHydration';
import { buildRestorableMpcMaterialRefInternal } from '@/core/signingEngine/session/material/restorableMpcMaterialRef.internal';
import {
  parseMpcReauthorizationPolicyRef,
  parseMpcRegisteredPublicKeyBindingRef,
  parseWalletAuthMethodId,
  type DomainIdParseResult,
} from '@shared/utils/domainIds';
import { buildMpcMaterialActivationRefFixture } from './ecdsaMaterialRef.fixtures';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';

function unwrap<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function authorityFixture(): WalletAuthAuthorityRef {
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: 'wallet-near-hydration',
    authorityDigest: 'authority-near-hydration',
    walletAuthMethodId: unwrap(parseWalletAuthMethodId('wallet-auth-method:near-hydration')),
  });
  if (!authority) throw new Error('Near hydration authority fixture is invalid');
  return authority;
}

type NearEd25519YaoCapabilityHydrationFixture = {
  authority: WalletAuthAuthorityRef;
  materialActivation: Extract<
    NearEd25519YaoCapabilityHydrationInputV1['publicLocator'],
    { kind: 'available' }
  >['materialActivation'];
  publicLocator: Extract<
    NearEd25519YaoCapabilityHydrationInputV1['publicLocator'],
    { kind: 'available' }
  >;
  sealed: Extract<NearEd25519YaoCapabilityHydrationInputV1['sealed'], { kind: 'available' }>;
  runtime: Extract<NearEd25519YaoCapabilityHydrationInputV1['runtime'], { kind: 'live' }>;
  publicReauthAnchor: Extract<
    NearEd25519YaoCapabilityHydrationInputV1['publicLocator'],
    { kind: 'retired' }
  >['publicReauthAnchor'];
};

export function nearEd25519YaoCapabilityHydrationFixture(): NearEd25519YaoCapabilityHydrationFixture {
  const authority = authorityFixture();
  const materialActivation = buildMpcMaterialActivationRefFixture(
    'near-hydration',
    'wallet-near-hydration',
  );
  const publicLocator = {
    kind: 'available' as const,
    walletId: 'wallet-near-hydration',
    nearAccountId: 'wallet-near-hydration.testnet',
    signerSlot: 1,
    materialActivation,
    authority,
  };
  const sealed = {
    kind: 'available' as const,
    authority,
    materialActivation,
    sealedMaterial: buildRestorableMpcMaterialRefInternal('sealed-near-active-client'),
  };
  return {
    authority,
    materialActivation,
    publicLocator,
    sealed,
    runtime: {
      kind: 'live' as const,
      runtime: nearEd25519YaoRuntimeRef(materialActivation),
      materialActivation,
    },
    publicReauthAnchor: buildMpcCapabilityPublicReauthAnchor({
      capability: materialActivation.capability,
      materialOwner: materialActivation.materialOwner,
      authority,
      keyBinding: materialActivation.keyBinding,
      lifecycleBinding: materialActivation.lifecycleBinding,
      reauthorizationPolicy: unwrap(
        parseMpcReauthorizationPolicyRef('near-ed25519-yao-reauthorization'),
      ),
      registeredPublicKeyBinding: unwrap(
        parseMpcRegisteredPublicKeyBindingRef('near-ed25519-yao-public-key'),
      ),
    }),
  };
}
