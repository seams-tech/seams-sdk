import type { SignedTransaction } from '@/core/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { ActionArgsWasm } from '@/core/types/actions';
import type { AuthenticatorOptions } from '@/core/types/authenticatorOptions';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types';
import type { RegistrationCredentialConfirmationPayload } from '../../workers/signerWorkerManager/internal/validation';
import type { WebAuthnAllowCredential } from '../../webauthn/credentials';
import {
  deriveNearKeypairAndEncryptFromSerialized as deriveNearKeypairAndEncryptFromSerializedValue,
  deriveNearKeypairFromCredentialViaWorker as deriveNearKeypairFromCredentialViaWorkerValue,
  type NearKeyDerivationDeps,
} from '../recovery/nearKeyDerivation';
import {
  exportPrivateKeysWithUI as exportPrivateKeysWithUIValue,
  type PrivateKeyExportRecoveryDeps,
} from '../recovery/privateKeyExportRecovery';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
  type RegistrationSessionDeps,
} from '../registration/registrationSession';
import {
  extractCosePublicKey as extractCosePublicKeyValue,
  generateEphemeralNearKeypair as generateEphemeralNearKeypairValue,
  signTransactionWithKeyPair as signTransactionWithKeyPairValue,
  type SignerWorkerBridgeDeps,
} from '../signing/signerWorkerBridge';

export type CredentialRecoverySurfaceDeps = {
  registrationSessionDeps: RegistrationSessionDeps;
  nearKeyDerivationDeps: NearKeyDerivationDeps;
  privateKeyExportRecoveryDeps: PrivateKeyExportRecoveryDeps;
  signerWorkerBridgeDeps: SignerWorkerBridgeDeps;
};

export type CredentialRecoverySurface = {
  requestRegistrationCredentialConfirmation(params: {
    nearAccountId: string;
    deviceNumber: number;
    confirmerText?: { title?: string; body?: string };
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
  }): Promise<RegistrationCredentialConfirmationPayload>;
  getAuthenticationCredentialsSerialized(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }): Promise<WebAuthnAuthenticationCredential>;
  deriveNearKeypairAndEncryptFromSerialized(args: {
    credential: WebAuthnRegistrationCredential;
    nearAccountId: string;
    options?: {
      authenticatorOptions?: AuthenticatorOptions;
      deviceNumber?: number;
      persistToDb?: boolean;
    };
  }): Promise<{
    success: boolean;
    nearAccountId: string;
    publicKey: string;
    chacha20NonceB64u?: string;
    wrapKeySalt?: string;
    encryptedSk?: string;
    error?: string;
  }>;
  deriveNearKeypairFromCredentialViaWorker(args: {
    credential: WebAuthnRegistrationCredential | WebAuthnAuthenticationCredential;
    nearAccountId: AccountId;
  }): Promise<{ publicKey: string; privateKey: string }>;
  extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array>;
  exportPrivateKeysWithUI(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
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

export function createCredentialRecoverySurface(
  deps: CredentialRecoverySurfaceDeps,
): CredentialRecoverySurface {
  return {
    requestRegistrationCredentialConfirmation(
      params,
    ): Promise<RegistrationCredentialConfirmationPayload> {
      return requestRegistrationCredentialConfirmationValue(
        deps.registrationSessionDeps,
        params,
      );
    },
    getAuthenticationCredentialsSerialized(
      args,
    ): Promise<WebAuthnAuthenticationCredential> {
      return getAuthenticationCredentialsSerializedValue(
        deps.registrationSessionDeps,
        args,
      );
    },
    deriveNearKeypairAndEncryptFromSerialized(args): Promise<{
      success: boolean;
      nearAccountId: string;
      publicKey: string;
      chacha20NonceB64u?: string;
      wrapKeySalt?: string;
      encryptedSk?: string;
      error?: string;
    }> {
      return deriveNearKeypairAndEncryptFromSerializedValue(
        deps.nearKeyDerivationDeps,
        args,
      );
    },
    deriveNearKeypairFromCredentialViaWorker(args): Promise<{
      publicKey: string;
      privateKey: string;
    }> {
      return deriveNearKeypairFromCredentialViaWorkerValue(
        deps.nearKeyDerivationDeps,
        args,
      );
    },
    extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
      return extractCosePublicKeyValue(deps.signerWorkerBridgeDeps, attestationObjectBase64url);
    },
    exportPrivateKeysWithUI(
      nearAccountId: AccountId,
      options?: {
        schemes?: Array<'ed25519' | 'secp256k1'>;
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
      },
    ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
      return exportPrivateKeysWithUIValue(deps.privateKeyExportRecoveryDeps, {
        nearAccountId,
        options,
      });
    },
    signTransactionWithKeyPair(args): Promise<{
      signedTransaction: SignedTransaction;
      logs?: string[];
    }> {
      return signTransactionWithKeyPairValue(deps.signerWorkerBridgeDeps, args);
    },
    generateEphemeralNearKeypair(): Promise<{
      publicKey: string;
      privateKey: string;
    }> {
      return generateEphemeralNearKeypairValue(deps.signerWorkerBridgeDeps);
    },
  };
}
