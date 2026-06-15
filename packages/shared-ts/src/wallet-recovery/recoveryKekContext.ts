import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '../signing-lanes/ids';
import type { WalletId } from '../utils/domainIds';
import type { DerivedWalletRecoveryKeyId } from './recoveryCodes';

export type WalletRecoveryKekDerivationContext = {
  kind: 'wallet_recovery_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  recoveryKeyId: DerivedWalletRecoveryKeyId;
  recoveryEnvelopeVersion: string;
  purpose: 'holder_share_recovery_envelope';
};

export function buildWalletRecoveryKekDerivationContext(
  args: WalletRecoveryKekDerivationContext,
): WalletRecoveryKekDerivationContext {
  return {
    kind: 'wallet_recovery_kek_derivation_context_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
    recoveryKeyId: args.recoveryKeyId,
    recoveryEnvelopeVersion: args.recoveryEnvelopeVersion,
    purpose: 'holder_share_recovery_envelope',
  };
}
