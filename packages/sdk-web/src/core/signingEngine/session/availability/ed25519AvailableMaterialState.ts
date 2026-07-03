import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import {
  classifyRouterAbEd25519PersistedSigningRecord,
  routerAbEd25519WorkerMaterialIdentityFromPersistedState,
  type RouterAbEd25519PersistedSigningRecordState,
} from '../routerAbSigningWalletSession';
import type { Ed25519AvailableWorkerMaterialState } from './availableSigningLanes';

export function ed25519AvailableMaterialStateFromRouterAbPersistedState(
  state: RouterAbEd25519PersistedSigningRecordState,
): Ed25519AvailableWorkerMaterialState | null {
  switch (state.kind) {
    case 'runtime_validated': {
      const identity = routerAbEd25519WorkerMaterialIdentityFromPersistedState(state);
      if (!identity) return null;
      return {
        kind: 'loaded_worker_material',
        identity,
      };
    }
    case 'restore_available':
      return {
        kind: 'sealed_worker_material',
        identity: state.restorableMaterial.identity,
      };
    case 'auth_ready_material_pending':
      return { kind: 'material_pending' };
    case 'material_hint_unvalidated':
    case 'non_signing':
    case 'invalid':
      return null;
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}

export function ed25519AvailableMaterialStateFromSessionRecord(
  record: ThresholdEd25519SessionRecord,
): Ed25519AvailableWorkerMaterialState | null {
  return ed25519AvailableMaterialStateFromRouterAbPersistedState(
    classifyRouterAbEd25519PersistedSigningRecord(record),
  );
}
