export type SignNEP413MessageParams = {
  message: string;
  recipient: string;
  state?: string;
};

export type SignNEP413MessageResult = {
  success: boolean;
  accountId?: string;
  publicKey?: string;
  signature?: string;
  nonce?: string;
  state?: string;
  error?: string;
};

export type SyncAccountResult =
  | {
      success: true;
      accountId: string;
      walletId: string;
      nearAccountId: string;
      ed25519KeyScopeId: string;
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
      ed25519KeyScopeId?: never;
    };
