import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { WalletId } from '../utils/domainIds';
import type { PasskeyCustodySecretKind } from '../passkey-custody';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';
import type { WalletRecoveryEnvelopeEntry } from './walletRecoveryEnvelopeSet';

/**
 * KEK inputs for one entry in a wallet-scoped recovery envelope set.
 *
 * The recovery code protects the whole wallet key set, but each entry is
 * wrapped under its own KEK so per-entry AAD stays intact: a code that opens
 * the Ed25519 root entry cannot open the ECDSA entry by substitution. The
 * purpose is the custody-secret kind, matching the passkey KEK context.
 */
export type WalletRecoveryKekDerivationContext = {
  kind: 'wallet_recovery_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  purpose: PasskeyCustodySecretKind;
};

/**
 * Derives the recovery KEK context from a parsed set entry, so a caller cannot
 * assemble a context that disagrees with the ciphertext it is about to open.
 */
export function buildWalletRecoveryKekDerivationContext(args: {
  walletId: WalletId;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  entry: WalletRecoveryEnvelopeEntry;
}): WalletRecoveryKekDerivationContext {
  return {
    kind: 'wallet_recovery_kek_derivation_context_v1',
    walletId: args.walletId,
    walletKeyId: args.entry.walletKeyId,
    laneId: args.entry.laneId,
    laneShareEpoch: args.entry.laneShareEpoch,
    recoveryKeyId: args.recoveryKeyId,
    purpose: args.entry.custodySecretKind,
  };
}
