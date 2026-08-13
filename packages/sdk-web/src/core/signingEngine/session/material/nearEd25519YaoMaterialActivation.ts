import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcCapabilityRuntimeRef,
  type CapabilityInstanceRef,
  type DomainIdParseResult,
  type MpcCapabilityRuntimeRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildReauthorizePublicAnchorHydrationPlan,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationPlan,
  type MpcCapabilityPublicReauthAnchor,
  type RestorableMpcMaterialRef,
} from './mpcCapabilityHydration';

function requireParsedDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function nearEd25519YaoMaterialActivationFromMetadata(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): MpcMaterialActivationRef {
  return metadata.materialActivation;
}

export type NearEd25519YaoPublicLocatorObservationV1 =
  | {
      readonly kind: 'available';
      readonly walletId: string;
      readonly nearAccountId: string;
      readonly signerSlot: number;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly authority: WalletAuthAuthorityRef;
    }
  | {
      readonly kind: 'missing';
    }
  | {
      readonly kind: 'retired';
      readonly retirement: 'expired' | 'exhausted';
      readonly publicReauthAnchor: MpcCapabilityPublicReauthAnchor;
    }
  | {
      readonly kind: 'conflict';
    }
  | {
      readonly kind: 'corrupt';
    }
  | {
      readonly kind: 'unavailable';
      readonly capability: CapabilityInstanceRef;
    };

export type NearEd25519YaoSealedMaterialObservationV1 =
  | {
      readonly kind: 'available';
      readonly authority: WalletAuthAuthorityRef;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly sealedMaterial: RestorableMpcMaterialRef;
    }
  | {
      readonly kind: 'missing';
    }
  | {
      readonly kind: 'corrupt';
    };

export type NearEd25519YaoRuntimeObservationV1 =
  | {
      readonly kind: 'live';
      readonly runtime: MpcCapabilityRuntimeRef;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'absent';
    };

export type NearEd25519YaoUnlockSourceObservationV1 =
  | {
      readonly kind: 'available';
      readonly authority: WalletAuthAuthorityRef;
    }
  | {
      readonly kind: 'unavailable';
    };

export type NearEd25519YaoCapabilityHydrationInputV1 = {
  readonly publicLocator: NearEd25519YaoPublicLocatorObservationV1;
  readonly sealed: NearEd25519YaoSealedMaterialObservationV1;
  readonly runtime: NearEd25519YaoRuntimeObservationV1;
  readonly unlockSource: NearEd25519YaoUnlockSourceObservationV1;
  readonly entryPoint?: never;
  readonly provenance?: never;
};

export function nearEd25519YaoRuntimeRef(
  materialActivation: MpcMaterialActivationRef,
): MpcCapabilityRuntimeRef {
  return requireParsedDomainId(
    parseMpcCapabilityRuntimeRef(`near-ed25519-yao:${materialActivation.activationId}`),
  );
}

function blockedNearHydration(
  input: {
    readonly publicLocator: NearEd25519YaoPublicLocatorObservationV1;
    readonly sealed: NearEd25519YaoSealedMaterialObservationV1;
    readonly runtime: NearEd25519YaoRuntimeObservationV1;
  },
  reason: 'missing_material' | 'binding_mismatch' | 'exact_record_conflict' | 'corrupt',
): MpcCapabilityHydrationPlan {
  const capability =
    input.sealed.kind === 'available'
      ? input.sealed.materialActivation.capability
      : input.runtime.kind === 'live'
        ? input.runtime.materialActivation.capability
        : input.publicLocator.kind === 'available'
          ? input.publicLocator.materialActivation.capability
          : null;
  return capability
    ? buildBlockedMpcCapabilityHydrationPlan({ capability, reason })
    : buildBlockedMpcCapabilityHydrationPlan({
        capability: null,
        reason: 'missing_capability',
      });
}

export function resolveNearEd25519YaoCapabilityHydrationV1(
  input: NearEd25519YaoCapabilityHydrationInputV1,
): MpcCapabilityHydrationPlan {
  switch (input.publicLocator.kind) {
    case 'missing':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: null,
        reason: 'missing_capability',
      });
    case 'retired':
      return buildReauthorizePublicAnchorHydrationPlan({
        retirement: input.publicLocator.retirement,
        publicReauthAnchor: input.publicLocator.publicReauthAnchor,
      });
    case 'conflict':
      return blockedNearHydration(input, 'exact_record_conflict');
    case 'corrupt':
      return blockedNearHydration(input, 'corrupt');
    case 'unavailable':
      return buildBlockedMpcCapabilityHydrationPlan({
        capability: input.publicLocator.capability,
        reason: 'persistence_unavailable',
      });
    case 'available':
      break;
    default:
      input.publicLocator satisfies never;
  }
  const publicMaterialActivation = input.publicLocator.materialActivation;
  if (String(publicMaterialActivation.materialOwner) !== input.publicLocator.walletId) {
    return blockedNearHydration(input, 'binding_mismatch');
  }
  switch (input.runtime.kind) {
    case 'live':
      if (
        !mpcMaterialActivationRefsEqual(publicMaterialActivation, input.runtime.materialActivation)
      ) {
        return blockedNearHydration(input, 'binding_mismatch');
      }
      return buildUseLiveRuntimeHydrationPlan({
        authority: input.publicLocator.authority,
        runtime: input.runtime.runtime,
        materialActivation: publicMaterialActivation,
      });
    case 'absent':
      break;
    default:
      input.runtime satisfies never;
  }
  switch (input.sealed.kind) {
    case 'missing':
      return blockedNearHydration(input, 'missing_material');
    case 'corrupt':
      return blockedNearHydration(input, 'corrupt');
    case 'available':
      break;
    default:
      input.sealed satisfies never;
  }
  const sealed = input.sealed;
  if (
    String(sealed.authority.walletId) !== input.publicLocator.walletId ||
    String(sealed.authority.authorityDigest) !==
      String(input.publicLocator.authority.authorityDigest) ||
    String(sealed.materialActivation.materialOwner) !== input.publicLocator.walletId ||
    !mpcMaterialActivationRefsEqual(
      sealed.materialActivation,
      input.publicLocator.materialActivation,
    )
  ) {
    return blockedNearHydration(input, 'binding_mismatch');
  }
  switch (input.unlockSource.kind) {
    case 'unavailable':
      return blockedNearHydration(input, 'missing_material');
    case 'available':
      if (
        String(input.unlockSource.authority.walletId) !== String(sealed.authority.walletId) ||
        String(input.unlockSource.authority.authorityDigest) !==
          String(sealed.authority.authorityDigest)
      ) {
        return blockedNearHydration(input, 'binding_mismatch');
      }
      return buildRehydrateMaterialActivationHydrationPlan({
        authority: sealed.authority,
        materialActivation: sealed.materialActivation,
        sealedMaterial: sealed.sealedMaterial,
      });
    default:
      input.unlockSource satisfies never;
  }
  throw new Error('Unsupported Near Ed25519 unlock-source observation');
}
