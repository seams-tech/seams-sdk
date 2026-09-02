import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type { RestorePersistedSessionPurpose } from '../sealedRecovery/sealedRecovery.types';
import type { RawSigningSessionSealedStoreRecord } from '../sealedRecovery/recoveryRecord';
import { restorePasskeyEcdsaSealedRecordForWallet } from './ecdsaRecovery';
import type { ActiveEcdsaCapabilityRuntimeResolver } from '../material/activeEcdsaCapabilityRuntime';

declare const rawRecord: RawSigningSessionSealedStoreRecord;
declare const purpose: RestorePersistedSessionPurpose & { authMethod: 'passkey' };
declare const transport: WarmSessionSealTransportInput;
declare const status: WarmSessionStatusResult;
declare const resolveActiveEcdsaCapabilityRuntime: ActiveEcdsaCapabilityRuntimeResolver;

void restorePasskeyEcdsaSealedRecordForWallet({
  // @ts-expect-error raw sealed store records must be normalized before passkey ECDSA recovery
  record: rawRecord,
  purpose,
  transport,
  groupId: 'prime',
  rehydrateWarmSessionMaterial: async () => status,
  deletePersistedRecord: async () => undefined,
  recordSessionMaterialRestored: async () => undefined,
  readWarmSessionStatusFromWorker: async () => status,
  resolveCurrentEcdsaCapabilityRuntime: resolveActiveEcdsaCapabilityRuntime,
  loadEcdsaRoleLocalReadyRecord: async () => ({ ok: true, value: { kind: 'not_found' } }),
  updatePersistedPolicy: async () => undefined,
});

export {};
