import type { AccountId } from '../../types/accountIds';
import type { ThresholdEd25519ParticipantV1 } from '@shared/threshold/participants';
import type {
  PasskeyCredentialRecord,
  UserPreferences,
} from '../../indexedDB/passkeyClientDB.types';
import type { WalletAuthMethod } from '@shared/utils/signerDomain';

export interface ClientUserData {
  walletId: string;
  nearAccountId: AccountId;
  loginDisplayName: string;
  signerSlot: number;
  version?: number;
  registeredAt?: number;
  lastLogin?: number;
  lastUpdated?: number;
  operationalPublicKey: string;
  passkeyCredential: PasskeyCredentialRecord;
  authMethod?: WalletAuthMethod | null;
  preferences?: UserPreferences;
}

export type StoreUserDataInput = Omit<
  ClientUserData,
  'walletId' | 'loginDisplayName' | 'signerSlot' | 'lastLogin' | 'registeredAt'
> & {
  walletId: string;
  loginDisplayName?: string;
  signerSlot?: number;
  version?: number;
};

export interface ClientAuthenticatorData {
  credentialId: string;
  credentialPublicKey: Uint8Array;
  transports?: string[];
  name?: string;
  nearAccountId: AccountId;
  signerSlot: number;
  registered: string;
  syncedAt: string;
}

export interface RecoveryEmailRecord {
  nearAccountId: AccountId;
  hashHex: string;
  email: string;
  addedAt: number;
}

export interface ThresholdEd25519KeyMaterial {
  nearAccountId: AccountId;
  signerSlot: number;
  kind: 'threshold_ed25519_v1';
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participants: ThresholdEd25519ParticipantV1[];
  timestamp: number;
}
