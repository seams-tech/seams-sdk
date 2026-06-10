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

export type SyncAccountResult = {
  success: boolean;
  accountId: string;
  publicKey: string;
  message: string;
  error?: string;
  loginState?: {
    isLoggedIn: boolean;
  };
};
