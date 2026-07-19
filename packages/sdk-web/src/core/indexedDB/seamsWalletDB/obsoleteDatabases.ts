const OBSOLETE_STANDALONE_WALLET_DATABASES = [
  'seams_router_ab_ecdsa_role_local_session_v1',
  'seams_router_ab_ecdsa_presign_material_v2',
] as const;

let cleanupPromise: Promise<void> | null = null;

function deleteObsoleteDatabase(dbName: string): Promise<void> {
  return new Promise((resolve) => {
    const request = indexedDB.deleteDatabase(dbName);
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
}

async function runObsoleteDatabaseCleanup(): Promise<void> {
  await Promise.all(OBSOLETE_STANDALONE_WALLET_DATABASES.map(deleteObsoleteDatabase));
}

export function deleteObsoleteStandaloneWalletDatabases(): Promise<void> {
  cleanupPromise ??= runObsoleteDatabaseCleanup();
  return cleanupPromise;
}
