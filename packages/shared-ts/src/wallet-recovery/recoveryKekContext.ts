import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { WalletId } from '../utils/domainIds';
import type { PasskeyCustodySecretKind } from '../passkey-custody';
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
 * KEK inputs for one entry's wrap under the manifest KEK. The purpose is the
 * custody-secret kind, so an entry KEK that opens the Ed25519 root cannot open
 * the ECDSA entry by substitution — per-entry AAD survives the manifest KEK.
 */
export type WalletRecoveryEntryKekDerivationContext = {
  kind: 'wallet_recovery_entry_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  purpose: PasskeyCustodySecretKind;
};

/**
 * Derives the code-level KEK context from a parsed manifest-KEK wrap, so a
 * caller cannot assemble a context that disagrees with the wrap it opens.
 */
export function buildWalletRecoveryCodeKekDerivationContext(args: {
  walletId: WalletId;
  wrap: WalletRecoveryManifestKekWrap;
}): WalletRecoveryCodeKekDerivationContext {
  return {
    kind: 'wallet_recovery_code_kek_derivation_context_v1',
    walletId: args.walletId,
    recoveryKeyId: args.wrap.recoveryKeyId,
    purpose: 'wallet_recovery_manifest_kek',
  };
}

/** Derives the entry-level KEK context from a parsed set entry. */
export function buildWalletRecoveryEntryKekDerivationContext(args: {
  walletId: WalletId;
  entry: WalletRecoveryEnvelopeEntry;
}): WalletRecoveryEntryKekDerivationContext {
  return {
    kind: 'wallet_recovery_entry_kek_derivation_context_v1',
    walletId: args.walletId,
    walletKeyId: args.entry.walletKeyId,
    laneId: args.entry.laneId,
    laneShareEpoch: args.entry.laneShareEpoch,
    purpose: args.entry.custodySecretKind,
  };
}
