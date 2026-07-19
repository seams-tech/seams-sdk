import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import { buildRouterAbEcdsaDerivationActiveStateIdV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type { EcdsaActiveStateId } from '@shared/utils/domainIds';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  rehydrateEcdsaRoleLocalSigningMaterialWasm,
  type RehydrateEcdsaRoleLocalSigningMaterialWasmResult,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import {
  parseEcdsaRoleLocalBindingDigest,
  parseEcdsaRoleLocalDurableMaterialRef,
  parseEcdsaRoleLocalPersistedMaterialRef,
  parseEcdsaRoleLocalWorkerHandle,
  type EcdsaRoleLocalDurableMaterialRef,
  type EcdsaRoleLocalPersistedMaterialRef,
  type EcdsaRoleLocalWorkerHandle,
} from '../keyMaterialBrands';

const persistedMaterialBrand: unique symbol = Symbol('persisted-ecdsa-role-local-material');

export type PersistedEcdsaRoleLocalMaterial = {
  readonly [persistedMaterialBrand]: true;
  readonly kind: 'persisted_ecdsa_role_local_material_v1';
  readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
  readonly liveHandle?: never;
};

export type EcdsaRoleLocalMaterialResolutionPurpose =
  | 'registration_activation'
  | 'wallet_unlock'
  | 'transaction_signing'
  | 'explicit_key_export';

export type EcdsaRoleLocalMaterialSource =
  | {
      readonly kind: 'persisted';
      readonly material: PersistedEcdsaRoleLocalMaterial;
      readonly reason?: never;
    }
  | {
      readonly kind: 'unavailable';
      readonly reason: 'missing_local_material';
      readonly material?: never;
    };

type EcdsaRoleLocalMaterialResolved = {
  readonly purpose: EcdsaRoleLocalMaterialResolutionPurpose;
  readonly liveHandle: EcdsaRoleLocalWorkerHandle;
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly reason?: never;
  readonly message?: never;
};

export type EcdsaRoleLocalMaterialResolution =
  | (EcdsaRoleLocalMaterialResolved & {
      readonly kind: 'live';
    })
  | (EcdsaRoleLocalMaterialResolved & {
      readonly kind: 'rehydrated';
    })
  | {
      readonly kind: 'device_link_required';
      readonly purpose: EcdsaRoleLocalMaterialResolutionPurpose;
      readonly reason: 'missing_local_material';
      readonly liveHandle?: never;
      readonly persistedMaterial?: never;
      readonly message?: never;
    }
  | {
      readonly kind: 'corrupt';
      readonly purpose: EcdsaRoleLocalMaterialResolutionPurpose;
      readonly reason:
        | 'expired'
        | 'binding_mismatch'
        | 'corrupt_persistence'
        | 'persistence_unavailable'
        | 'worker_identity_mismatch';
      readonly message: string;
      readonly liveHandle?: never;
      readonly persistedMaterial?: never;
    };

const liveHandlesByDurableMaterialRef = new Map<
  EcdsaRoleLocalDurableMaterialRef,
  EcdsaRoleLocalWorkerHandle
>();
const runtimeValidatedMaterialKeys = new Set<string>();

export function ecdsaRoleLocalActiveStateId(
  publicFacts: EcdsaRoleLocalPublicFacts,
): EcdsaActiveStateId {
  return buildRouterAbEcdsaDerivationActiveStateIdV1({
    ecdsaThresholdKeyId: String(publicFacts.ecdsaThresholdKeyId),
    signingRootId: String(publicFacts.signingRootId),
    signingRootVersion: String(publicFacts.signingRootVersion),
    activationEpoch: publicFacts.publicCapability.activation_epoch,
  });
}

function materialRefMatchesPublicFacts(
  materialRef: EcdsaRoleLocalPersistedMaterialRef,
  publicFacts: EcdsaRoleLocalPublicFacts,
): boolean {
  return materialRef.bindingDigest === publicFacts.contextBinding32B64u;
}

function liveHandleMatchesPersistedMaterial(
  liveHandle: EcdsaRoleLocalWorkerHandle,
  persistedMaterial: PersistedEcdsaRoleLocalMaterial,
): boolean {
  return (
    liveHandle.durableMaterialRef === persistedMaterial.materialRef.durableMaterialRef &&
    liveHandle.bindingDigest === persistedMaterial.materialRef.bindingDigest
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function corruptResolution(args: {
  purpose: EcdsaRoleLocalMaterialResolutionPurpose;
  reason: Extract<EcdsaRoleLocalMaterialResolution, { kind: 'corrupt' }>['reason'];
  message: string;
}): Extract<EcdsaRoleLocalMaterialResolution, { kind: 'corrupt' }> {
  return {
    kind: 'corrupt',
    purpose: args.purpose,
    reason: args.reason,
    message: args.message,
  };
}

function resolutionFromRehydrationFailure(args: {
  purpose: EcdsaRoleLocalMaterialResolutionPurpose;
  failure: Extract<RehydrateEcdsaRoleLocalSigningMaterialWasmResult, { ok: false }>;
}): Extract<EcdsaRoleLocalMaterialResolution, { kind: 'device_link_required' | 'corrupt' }> {
  switch (args.failure.reason) {
    case 'missing':
      return {
        kind: 'device_link_required',
        purpose: args.purpose,
        reason: 'missing_local_material',
      };
    case 'expired':
      return corruptResolution({
        purpose: args.purpose,
        reason: 'expired',
        message: 'ECDSA role-local persisted material has expired',
      });
    case 'binding_mismatch':
      return corruptResolution({
        purpose: args.purpose,
        reason: 'binding_mismatch',
        message: 'ECDSA role-local persisted material binding does not match its public facts',
      });
    case 'corrupt':
      return corruptResolution({
        purpose: args.purpose,
        reason: 'corrupt_persistence',
        message: 'ECDSA role-local persisted material is corrupt',
      });
    default: {
      const exhaustive: never = args.failure.reason;
      throw new Error(`Unsupported ECDSA role-local restoration failure: ${String(exhaustive)}`);
    }
  }
}

export function buildPersistedEcdsaRoleLocalMaterial(input: {
  readonly durableMaterialRef: EcdsaRoleLocalDurableMaterialRef;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
}): PersistedEcdsaRoleLocalMaterial {
  const materialRef = parseEcdsaRoleLocalPersistedMaterialRef({
    kind: 'ecdsa_role_local_persisted_material_ref_v1',
    durableMaterialRef: parseEcdsaRoleLocalDurableMaterialRef(input.durableMaterialRef),
    bindingDigest: parseEcdsaRoleLocalBindingDigest(input.publicFacts.contextBinding32B64u),
  });
  if (!materialRefMatchesPublicFacts(materialRef, input.publicFacts)) {
    throw new Error('ECDSA role-local persisted material does not match its public facts');
  }
  return {
    [persistedMaterialBrand]: true,
    kind: 'persisted_ecdsa_role_local_material_v1',
    materialRef,
    publicFacts: input.publicFacts,
  };
}

export function persistedEcdsaRoleLocalMaterialSource(
  material: PersistedEcdsaRoleLocalMaterial,
): EcdsaRoleLocalMaterialSource {
  return {
    kind: 'persisted',
    material,
  };
}

export function unavailableEcdsaRoleLocalMaterialSource(): EcdsaRoleLocalMaterialSource {
  return {
    kind: 'unavailable',
    reason: 'missing_local_material',
  };
}

export function bindLiveEcdsaRoleLocalMaterial(input: {
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly liveHandle: EcdsaRoleLocalWorkerHandle;
}): EcdsaRoleLocalWorkerHandle {
  const liveHandle = requireMatchingLiveEcdsaRoleLocalMaterial(input);
  liveHandlesByDurableMaterialRef.set(
    input.persistedMaterial.materialRef.durableMaterialRef,
    liveHandle,
  );
  return liveHandle;
}

export function requireMatchingLiveEcdsaRoleLocalMaterial(input: {
  readonly persistedMaterial: PersistedEcdsaRoleLocalMaterial;
  readonly liveHandle: EcdsaRoleLocalWorkerHandle;
}): EcdsaRoleLocalWorkerHandle {
  const liveHandle = parseEcdsaRoleLocalWorkerHandle(input.liveHandle);
  if (!liveHandleMatchesPersistedMaterial(liveHandle, input.persistedMaterial)) {
    throw new Error(
      '[SigningEngine] ECDSA role-local live worker handle does not match persisted material',
    );
  }
  return liveHandle;
}

export function getLiveEcdsaRoleLocalMaterial(
  persistedMaterial: PersistedEcdsaRoleLocalMaterial,
): EcdsaRoleLocalWorkerHandle | null {
  const liveHandle = liveHandlesByDurableMaterialRef.get(
    persistedMaterial.materialRef.durableMaterialRef,
  );
  if (!liveHandle || !liveHandleMatchesPersistedMaterial(liveHandle, persistedMaterial)) {
    return null;
  }
  return liveHandle;
}

export function forgetLiveEcdsaRoleLocalMaterial(
  durableMaterialRef: EcdsaRoleLocalDurableMaterialRef,
): void {
  liveHandlesByDurableMaterialRef.delete(durableMaterialRef);
}

export function markEcdsaRoleLocalRuntimeValidationKey(key: string): void {
  runtimeValidatedMaterialKeys.add(key);
}

export function hasEcdsaRoleLocalRuntimeValidationKey(key: string): boolean {
  return runtimeValidatedMaterialKeys.has(key);
}

export function clearEcdsaRoleLocalWorkerRuntimeState(): void {
  liveHandlesByDurableMaterialRef.clear();
  runtimeValidatedMaterialKeys.clear();
}

export async function resolveEcdsaRoleLocalMaterial(input: {
  readonly purpose: EcdsaRoleLocalMaterialResolutionPurpose;
  readonly source: EcdsaRoleLocalMaterialSource;
  readonly workerCtx: WorkerOperationContext;
}): Promise<EcdsaRoleLocalMaterialResolution> {
  switch (input.source.kind) {
    case 'unavailable':
      return {
        kind: 'device_link_required',
        purpose: input.purpose,
        reason: input.source.reason,
      };
    case 'persisted': {
      const persistedMaterial = input.source.material;
      const liveHandle = getLiveEcdsaRoleLocalMaterial(persistedMaterial);
      if (liveHandle) {
        return {
          kind: 'live',
          purpose: input.purpose,
          liveHandle,
          persistedMaterial,
        };
      }
      try {
        const rehydrated = await rehydrateEcdsaRoleLocalSigningMaterialWasm({
          materialRef: persistedMaterial.materialRef,
          workerCtx: input.workerCtx,
        });
        if (!rehydrated.ok) {
          return resolutionFromRehydrationFailure({
            purpose: input.purpose,
            failure: rehydrated,
          });
        }
        if (!liveHandleMatchesPersistedMaterial(rehydrated.liveHandle, persistedMaterial)) {
          return corruptResolution({
            purpose: input.purpose,
            reason: 'worker_identity_mismatch',
            message: 'ECDSA role-local worker restored a different material identity',
          });
        }
        const boundHandle = bindLiveEcdsaRoleLocalMaterial({
          persistedMaterial,
          liveHandle: rehydrated.liveHandle,
        });
        return {
          kind: 'rehydrated',
          purpose: input.purpose,
          liveHandle: boundHandle,
          persistedMaterial,
        };
      } catch (error: unknown) {
        return corruptResolution({
          purpose: input.purpose,
          reason: 'persistence_unavailable',
          message: errorMessage(error),
        });
      }
    }
    default: {
      const exhaustive: never = input.source;
      throw new Error(`Unsupported ECDSA role-local material source: ${String(exhaustive)}`);
    }
  }
}
