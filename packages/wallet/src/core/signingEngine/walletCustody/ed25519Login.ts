import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

export type LoginWithEmailOtpWalletCustodyEd25519Args = {
  walletSession: WalletSessionRef;
  /**
   * Email OTP provider subject id (e.g. `google:<sub>`). Carried as its own
   * field so it is never conflated with the wallet-scoped
   * `walletSession.walletSessionUserId`.
   */
  providerSubjectId: string;
  challengeId: string;
  otpCode: string;
  remainingUses: number;
  emailOtpAuthorityEmail: string;
  emailHashHex: string;
};
