import type { WarmSessionSealTransportInput } from '@/core/types/secure-confirm-worker';
import type { WarmSessionStatusResult } from '@/core/signingEngine/uiConfirm/types';
import type { RestorePersistedEcdsaSessionPurpose } from '../sealedRecovery/types';
import type { RawSigningSessionSealedStoreRecord } from '../sealedRecovery/recoveryRecord';
import { restorePasskeyEcdsaSealedRecordForWallet } from './ecdsaRecovery';

declare const rawRecord: RawSigningSessionSealedStoreRecord;
declare const purpose: RestorePersistedEcdsaSessionPurpose & { authMethod: 'passkey' };
declare const transport: WarmSessionSealTransportInput;
declare const status: WarmSessionStatusResult;

void restorePasskeyEcdsaSealedRecordForWallet({
  walletId: 'wallet.testnet',
  // @ts-expect-error raw sealed store records must be normalized before passkey ECDSA recovery
  record: rawRecord,
  purpose,
  transport,
  shamirPrimeB64u: 'prime',
  rehydrateWarmSessionMaterial: async () => status,
  deletePersistedRecord: async () => undefined,
  recordSessionMaterialRestored: async () => undefined,
  readWarmSessionStatusFromWorker: async () => status,
  updatePersistedPolicy: async () => undefined,
});

export {};
