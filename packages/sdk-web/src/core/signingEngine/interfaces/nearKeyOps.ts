import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import type { AccountId } from '@/core/types/accountIds';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';

export type NearSigningKeyOps = {
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
  deriveThresholdEd25519HssClientInputs(args: {
    sessionId: string;
    applicationBindingDigestB64u: string;
    participantIds: number[];
    prfFirstB64u: string;
  }): Promise<{
    success: boolean;
    applicationBindingDigestB64u: string;
    participantIds: number[];
    contextBindingB64u: string;
    yClientB64u: string;
    tauClientB64u: string;
    error?: string;
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
