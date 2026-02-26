export {
  buildNearAccountProjection,
  buildNearProfileId,
  getNearChainCandidates,
  inferNearChainIdKey,
  mapProfileAuthenticatorToClient,
  parseLastProfileState,
  upsertNearAccountProjectionRecords,
} from './accountProjection';

export {
  getNearLocalKeyMaterial,
  getNearThresholdKeyMaterial,
  storeNearKeyMaterial,
  storeNearLocalKeyMaterial,
  storeNearThresholdKeyMaterial,
} from './keyMaterial';

export type {
  NearKeyMaterialDeps,
  StoreNearKeyMaterialInput,
  StoreNearLocalKeyMaterialInput,
  StoreNearThresholdKeyMaterialInput,
} from './keyMaterial';

export type { UpsertNearProjectionOperations } from './accountProjection';
