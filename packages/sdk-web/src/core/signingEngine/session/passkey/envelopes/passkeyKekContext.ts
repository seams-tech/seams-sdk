import type { LaneShareEpoch, SigningLaneId, WalletKeyId } from '@shared/signing-lanes';
import type { WalletId } from '@shared/utils/domainIds';

export type PasskeyKekDerivationContext = {
  kind: 'passkey_kek_derivation_context_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  rpId: string;
  credentialIdB64u: string;
  passkeyKekVersion: string;
  purpose: 'holder_share_envelope';
};

export function buildPasskeyKekDerivationContext(
  args: PasskeyKekDerivationContext,
): PasskeyKekDerivationContext {
  return {
    kind: 'passkey_kek_derivation_context_v1',
    walletId: args.walletId,
    walletKeyId: args.walletKeyId,
    laneId: args.laneId,
    laneShareEpoch: args.laneShareEpoch,
    rpId: args.rpId,
    credentialIdB64u: args.credentialIdB64u,
    passkeyKekVersion: args.passkeyKekVersion,
    purpose: 'holder_share_envelope',
  };
}
