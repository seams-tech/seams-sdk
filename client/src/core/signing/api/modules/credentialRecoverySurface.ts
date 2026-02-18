import type { SignedTransaction } from '../../../near/NearClient';
import type { AccountId } from '../../../types/accountIds';
import type { ActionArgsWasm } from '../../../types/actions';
import type { AuthenticatorOptions } from '../../../types/authenticatorOptions';
import type { ConfirmationConfig } from '../../../types/signer-worker';
import type {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '../../../types';
import type { RegistrationCredentialConfirmationPayload } from '../../workers/signerWorkerManager/internal/validation';
import type { WebAuthnAllowCredential } from '../../webauthn/credentials';
import {
  deriveNearKeypairAndEncryptFromSerialized as deriveNearKeypairAndEncryptFromSerializedValue,
  deriveNearKeypairFromCredentialViaWorker as deriveNearKeypairFromCredentialViaWorkerValue,
  type NearKeyDerivationDeps,
} from '../nearKeyDerivation';
import {
  exportNearKeypairWithUI as exportNearKeypairWithUIValue,
  exportNearKeypairWithUIWorkerDriven as exportNearKeypairWithUIWorkerDrivenValue,
  exportPrivateKeysWithUI as exportPrivateKeysWithUIValue,
  exportPrivateKeysWithUIWorkerDriven as exportPrivateKeysWithUIWorkerDrivenValue,
  recoverKeypairFromPasskey as recoverKeypairFromPasskeyValue,
  type PrivateKeyExportRecoveryDeps,
} from '../privateKeyExportRecovery';
import {
  getAuthenticationCredentialsSerialized as getAuthenticationCredentialsSerializedValue,
  getAuthenticationCredentialsSerializedDualPrf as getAuthenticationCredentialsSerializedDualPrfValue,
  requestRegistrationCredentialConfirmation as requestRegistrationCredentialConfirmationValue,
  type RegistrationSessionDeps,
} from '../registrationSession';
import {
  extractCosePublicKey as extractCosePublicKeyValue,
  signTransactionWithKeyPair as signTransactionWithKeyPairValue,
  type SignerWorkerBridgeDeps,
} from '../signerWorkerBridge';

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
  exportNearKeypairWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
  ): Promise<void>;
  exportNearKeypairWithUI(
    nearAccountId: AccountId,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
  ): Promise<{ accountId: string; publicKey: string; privateKey: string }>;
  exportPrivateKeysWithUIWorkerDriven(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void>;
  exportPrivateKeysWithUI(
    nearAccountId: AccountId,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }>;
  recoverKeypairFromPasskey(
    authenticationCredential: WebAuthnAuthenticationCredential,
    accountIdHint?: string,
  ): Promise<{
    publicKey: string;
    encryptedPrivateKey: string;
    chacha20NonceB64u: string;
    accountIdHint?: string;
    wrapKeySalt: string;
    stored?: boolean;
  }>;
  getAuthenticationCredentialsSerializedDualPrf(args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    credentialIds: string[];
  }): Promise<WebAuthnAuthenticationCredential>;
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
};

export function createCredentialRecoverySurface(
  deps: CredentialRecoverySurfaceDeps,
): CredentialRecoverySurface {
  return {
    async requestRegistrationCredentialConfirmation(params): Promise<RegistrationCredentialConfirmationPayload> {
      return await requestRegistrationCredentialConfirmationValue(
        deps.registrationSessionDeps,
        params,
      );
    },
    async getAuthenticationCredentialsSerialized(args): Promise<WebAuthnAuthenticationCredential> {
      return await getAuthenticationCredentialsSerializedValue(
        deps.registrationSessionDeps,
        args,
      );
    },
    async deriveNearKeypairAndEncryptFromSerialized(args): Promise<{
      success: boolean;
      nearAccountId: string;
      publicKey: string;
      chacha20NonceB64u?: string;
      wrapKeySalt?: string;
      encryptedSk?: string;
      error?: string;
    }> {
      return await deriveNearKeypairAndEncryptFromSerializedValue(
        deps.nearKeyDerivationDeps,
        args,
      );
    },
    async deriveNearKeypairFromCredentialViaWorker(args): Promise<{
      publicKey: string;
      privateKey: string;
    }> {
      return await deriveNearKeypairFromCredentialViaWorkerValue(
        deps.nearKeyDerivationDeps,
        args,
      );
    },
    async extractCosePublicKey(attestationObjectBase64url: string): Promise<Uint8Array> {
      return await extractCosePublicKeyValue(deps.signerWorkerBridgeDeps, attestationObjectBase64url);
    },
    async exportNearKeypairWithUIWorkerDriven(
      nearAccountId: AccountId,
      options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
    ): Promise<void> {
      await exportNearKeypairWithUIWorkerDrivenValue(deps.privateKeyExportRecoveryDeps, {
        nearAccountId,
        options,
      });
    },
    async exportNearKeypairWithUI(
      nearAccountId: AccountId,
      options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
    ): Promise<{ accountId: string; publicKey: string; privateKey: string }> {
      return await exportNearKeypairWithUIValue(deps.privateKeyExportRecoveryDeps, {
        nearAccountId,
        options,
      });
    },
    async exportPrivateKeysWithUIWorkerDriven(
      nearAccountId: AccountId,
      options?: {
        schemes?: Array<'ed25519' | 'secp256k1'>;
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
      },
    ): Promise<void> {
      await exportPrivateKeysWithUIWorkerDrivenValue(deps.privateKeyExportRecoveryDeps, {
        nearAccountId,
        options,
      });
    },
    async exportPrivateKeysWithUI(
      nearAccountId: AccountId,
      options?: {
        schemes?: Array<'ed25519' | 'secp256k1'>;
        variant?: 'drawer' | 'modal';
        theme?: 'dark' | 'light';
      },
    ): Promise<{ accountId: string; exportedSchemes: Array<'ed25519' | 'secp256k1'> }> {
      return await exportPrivateKeysWithUIValue(deps.privateKeyExportRecoveryDeps, {
        nearAccountId,
        options,
      });
    },
    async recoverKeypairFromPasskey(
      authenticationCredential: WebAuthnAuthenticationCredential,
      accountIdHint?: string,
    ): Promise<{
      publicKey: string;
      encryptedPrivateKey: string;
      chacha20NonceB64u: string;
      accountIdHint?: string;
      wrapKeySalt: string;
      stored?: boolean;
    }> {
      return await recoverKeypairFromPasskeyValue(deps.privateKeyExportRecoveryDeps, {
        authenticationCredential,
        accountIdHint,
      });
    },
    async getAuthenticationCredentialsSerializedDualPrf(args): Promise<WebAuthnAuthenticationCredential> {
      return await getAuthenticationCredentialsSerializedDualPrfValue(
        deps.registrationSessionDeps,
        args,
      );
    },
    async signTransactionWithKeyPair(args): Promise<{
      signedTransaction: SignedTransaction;
      logs?: string[];
    }> {
      return await signTransactionWithKeyPairValue(deps.signerWorkerBridgeDeps, args);
    },
  };
}
