export type SignNEP413MessageParams = {
  message: string;
  recipient: string;
  state?: string;
};

export type SignNEP413MessageResult =
  | {
      success: true;
      accountId: string;
      publicKey: string;
      signature: string;
      nonce: string;
      state?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      accountId?: never;
      publicKey?: never;
      signature?: never;
      nonce?: never;
      state?: never;
    };

export type SyncAccountResult =
  | {
      success: true;
      accountId: string;
      walletId: string;
      nearAccountId: string;
      nearEd25519SigningKeyId: string;
      publicKey: string;
      message: string;
      loginState: {
        isLoggedIn: boolean;
      };
      error?: never;
    }
  | {
      success: false;
      accountId: string;
      publicKey: '';
      message: string;
      error: string;
      loginState: {
        isLoggedIn: false;
      };
      walletId?: never;
      nearAccountId?: never;
      nearEd25519SigningKeyId?: never;
    };
