import type { RouterAbEd25519YaoActiveClientMetadataV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { base64UrlEncode } from '@shared/utils/base64';
import {
  buildMpcMaterialActivationRef,
  mpcMaterialActivationRefsEqual,
  parseCapabilityInstanceRef,
  parseMpcCapabilityRuntimeRef,
  parseMpcKeyBindingRef,
  parseMpcLifecycleBindingRef,
  parseMpcMaterialActivationId,
  parseMpcMaterialOwnerRef,
  parseMpcSigningWorkerRef,
  type DomainIdParseResult,
  type MpcCapabilityRuntimeRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import {
  buildBlockedMpcCapabilityHydrationPlan,
  buildRehydrateMaterialActivationHydrationPlan,
  buildUseLiveRuntimeHydrationPlan,
  type MpcCapabilityHydrationPlan,
  type RestorableMpcMaterialRef,
} from './mpcCapabilityHydration';

function requireParsedDomainId<T>(result: DomainIdParseResult<T>): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

export function nearEd25519YaoMaterialActivationFromMetadata(
  metadata: RouterAbEd25519YaoActiveClientMetadataV1,
): MpcMaterialActivationRef {
  const sealedMaterialActivationId = metadata.scope.wallet_session_id;
  return nearEd25519YaoMaterialActivationFromPublicFacts({
    activationId: sealedMaterialActivationId,
    activeCapabilityBinding: metadata.activeCapabilityBinding,
    walletId: metadata.applicationBinding.wallet_id,
    registeredPublicKey: metadata.registeredPublicKey,
    lifecycleId: metadata.scope.lifecycle_id,
    signingWorkerId: metadata.scope.signing_worker_id,
  });
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
      readonly kind: 'conflict';
    }
  | {
      readonly kind: 'corrupt';
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
    case 'conflict':
      return blockedNearHydration(input, 'exact_record_conflict');
    case 'corrupt':
      return blockedNearHydration(input, 'corrupt');
    case 'available':
      break;
    default:
      input.publicLocator satisfies never;
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
  switch (input.runtime.kind) {
    case 'live':
      if (
        !mpcMaterialActivationRefsEqual(sealed.materialActivation, input.runtime.materialActivation)
      ) {
        return blockedNearHydration(input, 'binding_mismatch');
      }
      return buildUseLiveRuntimeHydrationPlan({
        authority: sealed.authority,
        runtime: input.runtime.runtime,
        materialActivation: sealed.materialActivation,
      });
    case 'absent':
      break;
    default:
      input.runtime satisfies never;
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

export function nearEd25519YaoMaterialActivationFromPublicFacts(input: {
  activationId: string;
  activeCapabilityBinding: ArrayLike<number>;
  walletId: string;
  registeredPublicKey: Uint8Array | readonly number[];
  lifecycleId: string;
  signingWorkerId: string;
}): MpcMaterialActivationRef {
  return buildMpcMaterialActivationRef({
    activationId: requireParsedDomainId(parseMpcMaterialActivationId(input.activationId)),
    capability: requireParsedDomainId(
      parseCapabilityInstanceRef(base64UrlEncode(Uint8Array.from(input.activeCapabilityBinding))),
    ),
    materialOwner: requireParsedDomainId(parseMpcMaterialOwnerRef(input.walletId)),
    keyBinding: requireParsedDomainId(
      parseMpcKeyBindingRef(base64UrlEncode(Uint8Array.from(input.registeredPublicKey))),
    ),
    lifecycleBinding: requireParsedDomainId(parseMpcLifecycleBindingRef(input.lifecycleId)),
    signingWorker: requireParsedDomainId(parseMpcSigningWorkerRef(input.signingWorkerId)),
  });
}
