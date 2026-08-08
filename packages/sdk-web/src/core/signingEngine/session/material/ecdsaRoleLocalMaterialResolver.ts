import type { EcdsaRoleLocalPublicFacts } from '@/core/platform';
import {
  mpcMaterialActivationRefsEqual,
  parseMpcMaterialActivationRef,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  parseWalletAuthAuthorityRef,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import {
  openEcdsaRoleLocalSigningMaterialWasm,
  type OpenEcdsaRoleLocalSigningMaterialWasmResult,
} from '../../threshold/crypto/ecdsaDerivationClientWasm';
import type {
  EcdsaRoleLocalPersistedMaterialRef,
  EcdsaRoleLocalWorkerHandle,
} from '../keyMaterialBrands';

const persistedMaterialBrand: unique symbol = Symbol('persisted-ecdsa-role-local-material');

export type PersistedEcdsaRoleLocalMaterial = {
  readonly [persistedMaterialBrand]: true;
  readonly kind: 'persisted_ecdsa_role_local_material_v1';
  readonly authority: WalletAuthAuthorityRef;
  readonly materialActivation: MpcMaterialActivationRef;
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
      readonly authority: WalletAuthAuthorityRef;
      readonly materialActivation: MpcMaterialActivationRef;
      readonly publicFacts: EcdsaRoleLocalPublicFacts;
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
  readonly materialRef: EcdsaRoleLocalPersistedMaterialRef;
  readonly reason?: never;
  readonly message?: never;
};

export type ResolvedEcdsaRoleLocalSigningMaterial = EcdsaRoleLocalMaterialResolved & {
  readonly kind: 'rehydrated';
};

export type EcdsaRoleLocalMaterialResolution =
  | ResolvedEcdsaRoleLocalSigningMaterial
  | {
      readonly kind: 'device_link_required';
      readonly purpose: EcdsaRoleLocalMaterialResolutionPurpose;
      readonly reason: 'missing_local_material';
      readonly liveHandle?: never;
      readonly materialRef?: never;
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
      readonly materialRef?: never;
    };

function materialRefMatchesPublicFacts(
  materialRef: EcdsaRoleLocalPersistedMaterialRef,
  publicFacts: EcdsaRoleLocalPublicFacts,
): boolean {
  return materialRef.bindingDigest === publicFacts.contextBinding32B64u;
}

function liveHandleMatchesMaterialRef(
  liveHandle: EcdsaRoleLocalWorkerHandle,
  materialRef: EcdsaRoleLocalPersistedMaterialRef,
): boolean {
  return (
    liveHandle.durableMaterialRef === materialRef.durableMaterialRef &&
    liveHandle.bindingDigest === materialRef.bindingDigest
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
  failure: Extract<OpenEcdsaRoleLocalSigningMaterialWasmResult, { ok: false }>;
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
  readonly authority: WalletAuthAuthorityRef;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly publicFacts: EcdsaRoleLocalPublicFacts;
}): PersistedEcdsaRoleLocalMaterial {
  const authority = parseWalletAuthAuthorityRef(input.authority);
  if (!authority) {
    throw new Error('ECDSA role-local persisted material authority is invalid');
  }
  const materialActivationResult = parseMpcMaterialActivationRef(input.materialActivation);
  if (!materialActivationResult.ok) {
    throw new Error(materialActivationResult.error.message);
  }
  if (authority.walletId !== input.publicFacts.walletId) {
    throw new Error('ECDSA role-local persisted material authority does not match its wallet');
  }
  return {
    [persistedMaterialBrand]: true,
    kind: 'persisted_ecdsa_role_local_material_v1',
    authority,
    materialActivation: materialActivationResult.value,
    publicFacts: input.publicFacts,
  };
}

export function ecdsaRoleLocalPersistedMaterialSource(
  persistedMaterial: Pick<
    PersistedEcdsaRoleLocalMaterial,
    'authority' | 'materialActivation' | 'publicFacts'
  >,
): EcdsaRoleLocalMaterialSource {
  return {
    kind: 'persisted',
    authority: persistedMaterial.authority,
    materialActivation: persistedMaterial.materialActivation,
    publicFacts: persistedMaterial.publicFacts,
  };
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
      try {
        const rehydrated = await openEcdsaRoleLocalSigningMaterialWasm({
          authority: input.source.authority,
          materialActivation: input.source.materialActivation,
          workerCtx: input.workerCtx,
        });
        if (!rehydrated.ok) {
          return resolutionFromRehydrationFailure({
            purpose: input.purpose,
            failure: rehydrated,
          });
        }
        if (
          !mpcMaterialActivationRefsEqual(
            rehydrated.materialRef.materialActivation,
            input.source.materialActivation,
          ) ||
          !materialRefMatchesPublicFacts(rehydrated.materialRef, input.source.publicFacts)
        ) {
          return corruptResolution({
            purpose: input.purpose,
            reason: 'worker_identity_mismatch',
            message: 'ECDSA role-local worker restored a different material identity',
          });
        }
        if (!liveHandleMatchesMaterialRef(rehydrated.liveHandle, rehydrated.materialRef)) {
          return corruptResolution({
            purpose: input.purpose,
            reason: 'worker_identity_mismatch',
            message: 'ECDSA role-local worker restored a different durable material',
          });
        }
        return {
          kind: 'rehydrated',
          purpose: input.purpose,
          liveHandle: rehydrated.liveHandle,
          materialRef: rehydrated.materialRef,
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
