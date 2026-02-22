/**
 * UserConfirm worker types
 *
 * The UserConfirm worker now hosts:
 * - the UserConfirm bridge (`awaitUserConfirmationV2`) used by confirmTxFlow, and
 * - a small PRF.first cache for threshold warm sessions.
 */

export interface TouchConfirmManagerConfig {
  workerUrl?: string;
  workerTimeout?: number;
  debug?: boolean;
}

export type UserConfirmWorkerMessageType =
  | 'PING'
  | 'SECURE_CONFIRM_REQUEST'
  | 'EXPORT_PRIVATE_KEYS_WITH_UI'
  | 'THRESHOLD_PRF_FIRST_CACHE_PUT'
  | 'THRESHOLD_PRF_FIRST_CACHE_PEEK'
  | 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE'
  | 'THRESHOLD_PRF_FIRST_CACHE_CLEAR';

export type ExportPrivateKeyScheme = 'ed25519' | 'secp256k1';
export type ExportKeypairChain = 'near' | 'evm' | 'tempo';

export type ExportLocalKeyMaterialSnapshot = {
  publicKey?: string;
  encryptedSk: string;
  chacha20NonceB64u: string;
  wrapKeySalt: string;
};

export interface ExportPrivateKeysWithUiWorkerPayload {
  nearAccountId: string;
  deviceNumber: number;
  chain: ExportKeypairChain;
  publicKeyHint?: string;
  hasThresholdKeyMaterial: boolean;
  localKeyMaterial?: ExportLocalKeyMaterialSnapshot;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
}

export interface ExportPrivateKeysWithUiWorkerResult {
  ok: boolean;
  cancelled?: boolean;
  accountId: string;
  exportedSchemes: ExportPrivateKeyScheme[];
  error?: string;
}

export interface UserConfirmWorkerMessage<TPayload = unknown> {
  type: UserConfirmWorkerMessageType;
  id?: string;
  payload?: TPayload;
}

export interface UserConfirmWorkerResponse<TData = unknown> {
  id?: string;
  success: boolean;
  data?: TData;
  error?: string;
}
