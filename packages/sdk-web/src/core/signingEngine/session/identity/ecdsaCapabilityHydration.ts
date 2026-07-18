import {
  activeMpcMaterialSessionRef,
  buildBlockedMpcCapabilityHydrationPlan,
  buildMpcCapabilityHydrationResolution,
  buildMpcCapabilityPublicReauthAnchor,
  buildReauthorizeMpcCapabilityPublicAnchorPlan,
  buildRehydrateActiveMpcMaterialSessionPlan,
  buildUseLiveMpcCapabilityRuntimePlan,
  capabilityInstanceRef,
  mpcCapabilityRuntimeRef,
  mpcKeyBindingRef,
  mpcLifecycleBindingRef,
  mpcMaterialOwnerRef,
  mpcPolicyBindingRef,
  mpcRegisteredPublicKeyBindingRef,
  restorableMpcMaterialRef,
  walletAuthAuthorityRef,
  type MpcCapabilityHydrationEntryPoint,
  type MpcCapabilityHydrationResolution,
} from '../../capability/mpcCapabilityHydration';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';

function ecdsaWalletAuthorityRef(record: ThresholdEcdsaSessionRecord): string {
  return `wallet-auth:${record.source}:${record.walletId}`;
}

function ecdsaCapabilityRef(record: ThresholdEcdsaSessionRecord): string {
  return `ecdsa:${record.walletId}:${record.evmFamilySigningKeySlotId}`;
}

function ecdsaMaterialOwnerRef(record: ThresholdEcdsaSessionRecord): string {
  return `ecdsa-derivation-worker:${record.walletId}:${record.evmFamilySigningKeySlotId}`;
}

function ecdsaPublicReauthAnchor(record: ThresholdEcdsaSessionRecord) {
  return buildMpcCapabilityPublicReauthAnchor({
    capability: capabilityInstanceRef(ecdsaCapabilityRef(record)),
    materialOwner: mpcMaterialOwnerRef(ecdsaMaterialOwnerRef(record)),
    authority: walletAuthAuthorityRef(ecdsaWalletAuthorityRef(record)),
    keyBinding: mpcKeyBindingRef(record.keyHandle),
    lifecycleBinding: mpcLifecycleBindingRef(record.thresholdSessionId),
    policyBinding: mpcPolicyBindingRef(record.signingGrantId),
    registeredPublicKeyBinding: mpcRegisteredPublicKeyBindingRef(
      record.thresholdEcdsaPublicKeyB64u,
    ),
  });
}

export function resolveEcdsaCapabilityHydration(args: {
  record: ThresholdEcdsaSessionRecord;
  entryPoint: MpcCapabilityHydrationEntryPoint;
  nowMs: number;
}): MpcCapabilityHydrationResolution {
  const record = args.record;
  const capability = capabilityInstanceRef(ecdsaCapabilityRef(record));
  const materialOwner = mpcMaterialOwnerRef(ecdsaMaterialOwnerRef(record));
  const authority = walletAuthAuthorityRef(ecdsaWalletAuthorityRef(record));
  const entryPoint = args.entryPoint;
  if (record.remainingUses <= 0) {
    return buildMpcCapabilityHydrationResolution({
      entryPoint,
      plan: buildReauthorizeMpcCapabilityPublicAnchorPlan({
        retirement: 'exhausted',
        publicReauthAnchor: ecdsaPublicReauthAnchor(record),
      }),
    });
  }
  if (record.expiresAtMs <= args.nowMs) {
    return buildMpcCapabilityHydrationResolution({
      entryPoint,
      plan: buildReauthorizeMpcCapabilityPublicAnchorPlan({
        retirement: 'expired',
        publicReauthAnchor: ecdsaPublicReauthAnchor(record),
      }),
    });
  }
  if (record.roleLocalMaterialHandle) {
    return buildMpcCapabilityHydrationResolution({
      entryPoint,
      plan: buildUseLiveMpcCapabilityRuntimePlan({
        capability,
        materialOwner,
        authority,
        runtime: mpcCapabilityRuntimeRef(
          record.roleLocalMaterialHandle.materialHandle,
        ),
        activeMaterialSession: activeMpcMaterialSessionRef(
          record.thresholdSessionId,
        ),
      }),
    });
  }
  if (record.roleLocalDurableMaterialRef) {
    return buildMpcCapabilityHydrationResolution({
      entryPoint,
      plan: buildRehydrateActiveMpcMaterialSessionPlan({
        capability,
        materialOwner,
        authority,
        activeMaterialSession: activeMpcMaterialSessionRef(
          record.thresholdSessionId,
        ),
        sealedMaterial: restorableMpcMaterialRef(
          record.roleLocalDurableMaterialRef,
        ),
      }),
    });
  }
  return buildMpcCapabilityHydrationResolution({
    entryPoint,
    plan: buildBlockedMpcCapabilityHydrationPlan({
      capability,
      reason: 'missing_material',
    }),
  });
}
