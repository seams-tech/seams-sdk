import {
  nearEd25519SigningKeyIdFromString,
  implicitNearAccountProvisioning,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { parseImplicitNearAccountId } from '@shared/utils/near';
import type {
  ActionResult,
  AddedEvmFamilyEcdsaSignerCapability,
  AddedNearEd25519SignerCapability,
  LoginResult,
  RegisteredEvmFamilyEcdsaCapability,
  RegisteredNearEd25519Capability,
  RegistrationResult,
} from './seams';
import type { SignNEP413MessageResult, SyncAccountResult } from './sdkPublicResults';

const walletId = walletIdFromString('frost-vermillion-k7p9m2');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('ed25519ks_example');
const implicitNearAccountIdParse = parseImplicitNearAccountId('a'.repeat(64));
if (!implicitNearAccountIdParse.ok) {
  throw new Error('test fixture implicit account id must parse');
}
const implicitNearAccountId = implicitNearAccountIdParse.value;

const loginSuccess: LoginResult = {
  success: true,
  kind: 'near_wallet_unlocked',
  walletId,
  loggedInNearAccountId: 'alice.testnet',
  operationalPublicKey: 'ed25519:public-key',
  nearAccountId: 'alice.testnet',
};
void loginSuccess;

const ecdsaLoginSuccess: LoginResult = {
  success: true,
  kind: 'ecdsa_wallet_unlocked',
  walletId,
};
void ecdsaLoginSuccess;

const loginFailure: LoginResult = {
  success: false,
  error: 'Login failed',
};
void loginFailure;

// @ts-expect-error login success requires the public account payload.
const invalidLoginSuccess: LoginResult = {
  success: true,
  kind: 'near_wallet_unlocked',
  walletId,
  nearAccountId: 'alice.testnet',
};
void invalidLoginSuccess;

// @ts-expect-error ECDSA-only login cannot fabricate NEAR account identity.
const invalidEcdsaLoginSuccess: LoginResult = {
  success: true,
  kind: 'ecdsa_wallet_unlocked',
  walletId,
  nearAccountId: 'alice.testnet',
};
void invalidEcdsaLoginSuccess;

const actionSuccess: ActionResult = {
  success: true,
  transactionId: 'txid',
};
void actionSuccess;

const actionFailure: ActionResult = {
  success: false,
  error: 'Action failed',
};
void actionFailure;

// @ts-expect-error action failure cannot carry a transaction id.
const invalidActionFailure: ActionResult = {
  success: false,
  error: 'Action failed',
  transactionId: 'txid',
};
void invalidActionFailure;

const nep413Success: SignNEP413MessageResult = {
  success: true,
  accountId: 'alice.testnet',
  publicKey: 'ed25519:public-key',
  signature: 'signature',
  nonce: 'nonce',
};
void nep413Success;

const nep413Failure: SignNEP413MessageResult = {
  success: false,
  error: 'NEP-413 failed',
};
void nep413Failure;

// @ts-expect-error NEP-413 success requires signature payload.
const invalidNep413Success: SignNEP413MessageResult = {
  success: true,
  accountId: 'alice.testnet',
  publicKey: 'ed25519:public-key',
  nonce: 'nonce',
};
void invalidNep413Success;

// @ts-expect-error NEP-413 failure cannot carry signature payload.
const invalidNep413Failure: SignNEP413MessageResult = {
  success: false,
  error: 'NEP-413 failed',
  signature: 'signature',
};
void invalidNep413Failure;

const syncAccountSuccess: SyncAccountResult = {
  success: true,
  accountId: String(walletId),
  walletId: String(walletId),
  nearAccountId: String(implicitNearAccountId),
  nearEd25519SigningKeyId: String(nearEd25519SigningKeyId),
  publicKey: 'ed25519:public-key',
  message: 'Account synced successfully',
  loginState: { isLoggedIn: true },
};
void syncAccountSuccess;

const syncAccountFailure: SyncAccountResult = {
  success: false,
  error: 'Sync failed',
};
void syncAccountFailure;

// @ts-expect-error sync-account failure cannot carry success-only account data.
const invalidSyncAccountFailureWithAccount: SyncAccountResult = {
  success: false,
  error: 'Sync failed',
  accountId: String(walletId),
};
void invalidSyncAccountFailureWithAccount;

// @ts-expect-error sync-account failure cannot carry a placeholder public key.
const invalidSyncAccountFailureWithPublicKey: SyncAccountResult = {
  success: false,
  error: 'Sync failed',
  publicKey: '',
};
void invalidSyncAccountFailureWithPublicKey;

const registeredNearCapability: RegisteredNearEd25519Capability = {
  kind: 'near_ed25519',
  accountProvisioning: implicitNearAccountProvisioning(),
  resolvedAccount: {
    kind: 'implicit_account',
    nearAccountId: implicitNearAccountId,
    nearEd25519SigningKeyId,
  },
  nearEd25519SigningKeyId,
  operationalPublicKey: 'ed25519:public-key',
  nearAccountId: implicitNearAccountId,
  transactionId: null,
};

const registeredEcdsaCapability: RegisteredEvmFamilyEcdsaCapability = {
  kind: 'evm_family_ecdsa',
  thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
  thresholdEcdsaPublicKeyB64u: 'public-key',
};

const nearRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_registered',
  walletId,
  capabilities: [registeredNearCapability],
};
void nearRegistrationSuccess;

const ecdsaRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_registered',
  walletId,
  capabilities: [registeredEcdsaCapability],
};
void ecdsaRegistrationSuccess;

/* Refactor 94 Phase 7. A mixed plan resolves ECDSA-ready with NEAR still
   settling; there is no synchronous mixed result to model any more. */
const mixedRegistrationPendingSuccess: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [registeredEcdsaCapability],
  nearProvisioning: { status: 'pending' },
};
void mixedRegistrationPendingSuccess;

const nearOnlyRegistrationPendingSuccess: RegistrationResult = {
  success: true,
  kind: 'near_wallet_registered_pending',
  walletId,
  nearProvisioning: { status: 'pending' },
};
void nearOnlyRegistrationPendingSuccess;

const invalidNearOnlyPendingWithSigningKey: RegistrationResult = {
  success: true,
  kind: 'near_wallet_registered_pending',
  walletId,
  nearProvisioning: { status: 'pending' },
  // @ts-expect-error an Ed25519-only pending wallet has no signing key before Yao completes.
  nearEd25519SigningKeyId,
};
void invalidNearOnlyPendingWithSigningKey;

const invalidPendingRegistrationWithSigningKeyId: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [registeredEcdsaCapability],
  nearProvisioning: { status: 'pending' },
  // @ts-expect-error a pending NEAR branch has no Ed25519 signing key yet.
  nearEd25519SigningKeyId,
};
void invalidPendingRegistrationWithSigningKeyId;

const invalidPendingRegistrationWithOperationalKey: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [registeredEcdsaCapability],
  nearProvisioning: { status: 'pending' },
  // @ts-expect-error a pending NEAR branch has no operational public key yet.
  operationalPublicKey: 'ed25519:public-key',
};
void invalidPendingRegistrationWithOperationalKey;

const invalidPendingRegistrationWithNearAccountId: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [registeredEcdsaCapability],
  nearProvisioning: { status: 'pending' },
  // @ts-expect-error the NEAR account does not exist until provisioning is ready.
  nearAccountId: implicitNearAccountId,
};
void invalidPendingRegistrationWithNearAccountId;

const invalidNearRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_registered',
  walletId,
  // @ts-expect-error NEAR registration success requires the complete capability result.
  capabilities: [{ kind: 'near_ed25519', nearAccountId: 'a'.repeat(64) }],
};
void invalidNearRegistrationSuccess;

const invalidEcdsaRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_registered',
  walletId,
  capabilities: [
    {
      kind: 'evm_family_ecdsa',
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
      thresholdEcdsaPublicKeyB64u: 'public-key',
      // @ts-expect-error ECDSA capability results cannot carry NEAR provisioning.
      accountProvisioning: implicitNearAccountProvisioning(),
    },
  ],
};
void invalidEcdsaRegistrationSuccess;

const invalidMixedRegistrationWithoutPublicKey: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [
    // @ts-expect-error Mixed registration requires a complete ECDSA capability result.
    {
      kind: 'evm_family_ecdsa',
      thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
    },
  ],
  nearProvisioning: { status: 'pending' },
};
void invalidMixedRegistrationWithoutPublicKey;

const invalidRegistrationWithDuplicateNearCapabilities: RegistrationResult = {
  success: true,
  kind: 'wallet_registered',
  walletId,
  // @ts-expect-error Registration cannot duplicate a capability branch.
  capabilities: [registeredNearCapability, registeredNearCapability],
};
void invalidRegistrationWithDuplicateNearCapabilities;

// @ts-expect-error the pending result must state where NEAR provisioning got to.
const invalidPendingRegistrationWithoutProvisioning: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered_near_pending',
  walletId,
  capabilities: [registeredEcdsaCapability],
};
void invalidPendingRegistrationWithoutProvisioning;

const addedNearCapability: AddedNearEd25519SignerCapability = {
  kind: 'near_ed25519',
  nearEd25519SigningKeyId,
  operationalPublicKey: 'ed25519:public-key',
  nearAccountId: implicitNearAccountId,
};

const addedEcdsaCapability: AddedEvmFamilyEcdsaSignerCapability = {
  kind: 'evm_family_ecdsa',
  thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
  thresholdEcdsaPublicKeyB64u: 'public-key',
};
const nearSignerAddedSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_signer_added',
  walletId,
  capabilities: [addedNearCapability],
};
void nearSignerAddedSuccess;

const ecdsaSignerAddedSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_signer_added',
  walletId,
  capabilities: [addedEcdsaCapability],
};
void ecdsaSignerAddedSuccess;

const invalidCombinedSignerAddedSuccess: RegistrationResult = {
  success: true,
  kind: 'wallet_signer_added',
  walletId,
  // @ts-expect-error A single add-signer operation returns exactly one capability.
  capabilities: [addedNearCapability, addedEcdsaCapability],
};
void invalidCombinedSignerAddedSuccess;
