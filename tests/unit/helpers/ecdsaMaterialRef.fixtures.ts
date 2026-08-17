import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
} from '@/core/signingEngine/session/keyMaterialBrands';
import {
  buildMpcMaterialActivationRef,
  parseCapabilityInstanceRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityBindingDigest,
  type DomainIdParseResult,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  canonicalWalletAuthorityBindingDigestInput,
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256 } from '@noble/hashes/sha2.js';

function unwrapDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function buildWalletAuthAuthorityRefFixture(args: {
  walletId: string;
  label?: string;
}): WalletAuthAuthorityRef {
  const authority = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: args.walletId,
    authorityDigest: unwrapDomainId(
      parseWalletAuthorityBindingDigest(`authority:${args.label ?? args.walletId}`),
    ),
    // R103B: the ref names the auth method it was minted for.
    walletAuthMethodId: unwrapDomainId(
      parseWalletAuthMethodId(`auth-method:${args.label ?? args.walletId}`),
    ),
  });
  if (!authority) throw new Error('invalid wallet authority fixture');
  return authority;
}

export function buildWalletAuthAuthorityRefForAuthorityFixture(
  authority: WalletAuthAuthority,
): WalletAuthAuthorityRef {
  const authorityDigest = base64UrlEncode(
    sha256(
      new TextEncoder().encode(
        canonicalWalletAuthorityBindingDigestInput({
          authority,
        }),
      ),
    ),
  );
  const ref = parseWalletAuthAuthorityRef({
    kind: 'wallet_auth_authority_ref',
    walletId: authority.walletId,
    authorityDigest,
    walletAuthMethodId: authority.bindingId,
  });
  if (!ref) throw new Error('invalid wallet authority fixture ref');
  return ref;
}

export function buildEcdsaRoleLocalPersistedMaterialRefFixture(args: {
  durableMaterialRef: string;
  bindingDigest: string;
  label?: string;
  materialOwner?: string;
}): EcdsaRoleLocalPersistedMaterialRef {
  const label = args.label ?? args.durableMaterialRef;
  return parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(args.durableMaterialRef),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(args.bindingDigest),
    materialActivation: buildMpcMaterialActivationRefFixture(label, args.materialOwner),
  });
}

export function buildMpcMaterialActivationRefFixture(
  label: string,
  materialOwner?: string,
  signingWorker?: string,
  keyBinding?: string,
): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRef({
    activationId: unwrapDomainId(parseMpcMaterialActivationId(`activation:${label}`)),
    capability: unwrapDomainId(parseCapabilityInstanceRef(`capability:${label}`)),
    materialOwner: unwrapDomainId(parseMpcMaterialOwnerRef(materialOwner ?? `owner:${label}`)),
    keyBinding: unwrapDomainId(parseMpcKeyBindingRef(keyBinding ?? `key:${label}`)),
    lifecycleBinding: unwrapDomainId(parseMpcLifecycleBindingRef(`lifecycle:${label}`)),
    signingWorker: unwrapDomainId(parseMpcSigningWorkerRef(signingWorker ?? `worker:${label}`)),
  });
}
