import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

const LINKED_WALLET_DISCOVERY_KEY = 'seams.linked-wallet-discovery.v1';

function readLinkedWalletDiscoveryStorage(): Storage | null {
  try {
    return globalThis.localStorage;
  } catch {
    return null;
  }
}

export function readLinkedWalletDiscoveryIds(): readonly WalletId[] {
  const storage = readLinkedWalletDiscoveryStorage();
  if (!storage) return [];
  try {
    const value: unknown = JSON.parse(storage.getItem(LINKED_WALLET_DISCOVERY_KEY) || '[]');
    if (!Array.isArray(value)) return [];
    const walletIds = value.flatMap((candidate) => {
      const parsed = parseWalletId(candidate);
      return parsed.ok ? [parsed.value] : [];
    });
    return [...new Set(walletIds)];
  } catch {
    return [];
  }
}

export function rememberLinkedWalletDiscoveryId(walletId: WalletId): void {
  const storage = readLinkedWalletDiscoveryStorage();
  if (!storage) return;
  const walletIds = [...new Set([...readLinkedWalletDiscoveryIds(), walletId])];
  storage.setItem(LINKED_WALLET_DISCOVERY_KEY, JSON.stringify(walletIds));
}
