import type { ClientAuthenticatorData } from '@/core/indexedDB';
import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import type { AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';

export type NearSigningKeyOps = {
  deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: AccountId;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
      persistToDb?: boolean;
    };
    sessionId: string;
  }): Promise<{
    success: boolean;
    nearAccountId: AccountId;
    publicKey: string;
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
    encryptedSk?: string;
  }>;
  deriveThresholdEd25519ClientVerifyingShare(args: {
    sessionId: string;
    nearAccountId: AccountId;
    prfFirstB64u: string;
    wrapKeySalt: string;
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    clientVerifyingShareB64u: string;
    error?: string;
  }>;
  decryptPrivateKeyWithPrf(args: {
    nearAccountId: AccountId;
    authenticators: ClientAuthenticatorData[];
    sessionId: string;
    prfFirstB64u?: string;
    wrapKeySalt?: string;
    encryptedPrivateKeyData?: string;
    encryptedPrivateKeyChacha20NonceB64u?: string;
    deviceNumber?: number;
  }): Promise<{
    decryptedPrivateKey: string;
    nearAccountId: AccountId;
  }>;
  recoverKeypairFromPasskey(args: {
    credential: WebAuthnAuthenticationCredential;
    accountIdHint?: string;
    sessionId: string;
  }): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    chacha20NonceB64u: string;
    accountIdHint?: string;
    wrapKeySalt: string;
  }>;
  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
  signTransactionWithKeyPair(args: {
    nearPrivateKey: string;
    signerAccountId: string;
    receiverId: string;
    nonce: string;
    blockHash: string;
    actions: ActionArgsWasm[];
  }): Promise<{
    signedTransaction: SignedTransaction;
    logs?: string[];
  }>;
  generateEphemeralNearKeypair(): Promise<{
    publicKey: string;
    privateKey: string;
  }>;
};
