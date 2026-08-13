import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type LoginWithEmailOtpWalletCustodyEd25519Args = {
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  remainingUses: number;
  appSessionJwt: string;
  emailHashHex: string;
};
