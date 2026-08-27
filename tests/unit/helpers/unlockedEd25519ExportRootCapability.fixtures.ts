import type { UnlockedWalletEd25519ExportRootCapabilityV1 } from '@/core/signingEngine/workerManager/workerTypes';

export function buildUnlockedWalletEd25519ExportRootCapabilityFixture(args: {
  readonly walletId: string;
  readonly walletAuthMethodId?: string;
  readonly walletSessionId?: string;
  readonly capabilityHandleId?: string;
  readonly expiresAtMs?: number;
}): UnlockedWalletEd25519ExportRootCapabilityV1 {
  return {
    kind: 'unlocked_wallet_ed25519_export_root_capability_v1',
    capabilityHandleId: args.capabilityHandleId ?? 'unlocked-ed25519-export-root-fixture',
    walletId: args.walletId,
    walletAuthMethodId: args.walletAuthMethodId ?? 'wallet-auth-method:fixture',
    walletSessionId: args.walletSessionId ?? 'wallet-session:fixture',
    expiresAtMs: args.expiresAtMs ?? Date.now() + 60_000,
  };
}
