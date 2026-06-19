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

export type BrowserSigningStorePorts = {
  managerStores: ManagerAssemblyStores;
  signingEngineStores: SigningEngineStorePorts;
  sealedSigningSessionStore: EmailOtpSealedSessionStorePorts;
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
        ed25519MetadataStore: indexedDB,
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
  };
}
