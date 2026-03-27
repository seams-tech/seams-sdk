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
  deriveThresholdEd25519BootstrapPackage(args: {
    sessionId: string;
    nearAccountId: AccountId;
    rpId?: string;
    keyVersion: string;
    prfFirstB64u: string;
    recoveryServerShareB64u?: string;
  }): Promise<
    | {
        success: true;
        nearAccountId: string;
        keyVersion: string;
        recoveryExportCapable: true;
        clientParticipantId: number;
        relayerParticipantId: number;
        publicKey: string;
        recoveryPublicKey: string;
        clientVerifyingShareB64u: string;
        relayerSigningShareB64u: string;
        relayerVerifyingShareB64u: string;
      }
    | {
        success: false;
        nearAccountId: string;
        keyVersion: string;
        error?: string;
      }
  >;
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
