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
  getNearThresholdKeyMaterial,
  storeNearKeyMaterial,
  storeNearThresholdKeyMaterial,
} from './keyMaterial';

export type {
  NearKeyMaterialDeps,
  StoreNearKeyMaterialInput,
  StoreNearThresholdKeyMaterialInput,
} from './keyMaterial';

export type { UpsertNearProjectionOperations } from './accountProjection';
