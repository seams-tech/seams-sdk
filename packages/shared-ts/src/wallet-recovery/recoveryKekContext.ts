import type { WalletId } from '../utils/domainIds';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import type {
  WalletRecoveryEnvelopeEntry,
  WalletRecoveryManifestKekWrap,
} from './walletRecoveryEnvelopeSet';

/**
 * Frozen two-level recovery wrap:
 *
 *   recovery code --HKDF--> code KEK --opens--> manifest KEK
 *   manifest KEK --HKDF--> entry KEK --opens--> one custody secret
 *
 * A recovery code never wraps a custody entry directly, so rotating codes
 * rewraps only the 32-byte manifest KEK and never re-opens plaintext roots.
 */

/** KEK inputs for one recovery code's wrap of the manifest KEK. */
export type WalletRecoveryCodeKekDerivationContext = {
  kind: 'wallet_recovery_code_kek_derivation_context_v1';
  walletId: WalletId;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  purpose: 'wallet_recovery_manifest_kek';
};

/**
 * KEK inputs for the seed entry's wrap under the manifest KEK.
 *
 * A recovery set carries one entry — the wallet custody seed — so the purpose
 * is fixed. It is still encoded rather than assumed, so adding a second entry
 * kind later cannot silently reuse this context.
 */
export type WalletRecoveryEntryKekDerivationContext = {
  kind: 'wallet_recovery_entry_kek_derivation_context_v1';
  walletId: WalletId;
  purpose: 'wallet_custody_seed_v1';
};

/** Derives the entry-level KEK context from a parsed set entry. */
export function buildWalletRecoveryEntryKekDerivationContext(args: {
  walletId: WalletId;
  entry: WalletRecoveryEnvelopeEntry;
}): WalletRecoveryEntryKekDerivationContext {
  return {
    kind: 'wallet_recovery_entry_kek_derivation_context_v1',
    walletId: args.walletId,
    purpose: args.entry.custodySecretKind,
  };
}
