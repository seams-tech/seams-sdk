import {
  createIndexedDBNonceLaneCoordinationStore,
  type UnifiedIndexedDBManager,
} from '@/core/indexedDB';
import type { ManagerAssemblyStores } from '@/core/signingEngine/assembly/createManagers';
import type { SigningEngineStorePorts } from '@/core/signingEngine/assembly/ports/shared';
import type { EmailOtpSealedSessionStorePorts } from '@/core/signingEngine/session/emailOtp/EmailOtpWalletSessionCoordinator';
import {
  acquireSigningSessionRestoreLease,
  deleteDurableSealedSessionRecord,
  listExactSealedSessionsForWallet,
  releaseSigningSessionRestoreLease,
  readExactSealedSession,
  updateExactSealedSessionPolicy,
  writeExactSealedSession,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  IndexedDbEd25519YaoPublicCapabilityReferenceStore,
  type Ed25519YaoPublicCapabilityReferenceStorePort,
} from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';

export type BrowserSigningStorePorts = {
  managerStores: ManagerAssemblyStores;
  signingEngineStores: SigningEngineStorePorts;
  sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
  ed25519YaoPublicCapabilityReferences: Ed25519YaoPublicCapabilityReferenceStorePort;
};

export function createBrowserSigningStores(
  indexedDB: UnifiedIndexedDBManager,
): BrowserSigningStorePorts {
  return {
    managerStores: {
      userPreferencesStore: indexedDB,
      nonceLaneCoordinationStore: createIndexedDBNonceLaneCoordinationStore({ indexedDB }),
      webauthnCredentialStore: indexedDB,
      passkeyAuthenticatorStore: indexedDB,
      nearKeyMaterialStore: indexedDB,
    },
    signingEngineStores: {
      walletProfileAndSignerRecords: {
        accountStore: indexedDB,
        walletSignerStore: indexedDB,
        passkeyAuthenticatorStore: indexedDB,
        ecdsaBootstrapStore: indexedDB,
      },
      recoveryAndDeviceLinking: {
        credentialStore: indexedDB,
        keyMaterialStore: indexedDB,
      },
      warmup: {
        store: indexedDB,
      },
    },
    sealedSigningSessionStore: {
      writeExactSealedSession,
      readExactSealedSession,
      listExactSealedSessionsForWallet,
      acquireSigningSessionRestoreLease,
      releaseSigningSessionRestoreLease,
      deleteDurableSealedSessionRecord,
      updateExactSealedSessionPolicy,
    },
    ed25519YaoPublicCapabilityReferences:
      new IndexedDbEd25519YaoPublicCapabilityReferenceStore(indexedDB),
  };
}
