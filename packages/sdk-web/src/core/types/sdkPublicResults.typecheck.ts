import {
  nearEd25519SigningKeyIdFromString,
  implicitNearAccountProvisioning,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { parseImplicitNearAccountId } from '@shared/utils/near';
import type { ActionResult, LoginResult, RegistrationResult } from './seams';
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
  loggedInNearAccountId: 'alice.testnet',
  operationalPublicKey: 'ed25519:public-key',
  nearAccountId: 'alice.testnet',
};
void loginSuccess;

const loginFailure: LoginResult = {
  success: false,
  error: 'Login failed',
};
void loginFailure;

// @ts-expect-error login success requires the public account payload.
const invalidLoginSuccess: LoginResult = {
  success: true,
  nearAccountId: 'alice.testnet',
};
void invalidLoginSuccess;

// @ts-expect-error login failure cannot carry a success-only JWT.
const invalidLoginFailure: LoginResult = {
  success: false,
  error: 'Login failed',
  jwt: 'jwt',
};
void invalidLoginFailure;

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

const nearRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'near_wallet_registered',
  walletId,
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
void nearRegistrationSuccess;

const ecdsaRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered',
  walletId,
  thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
  thresholdEcdsaPublicKeyB64u: 'public-key',
};
void ecdsaRegistrationSuccess;

// @ts-expect-error NEAR registration success requires resolved provisioning and account data.
const invalidNearRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'near_wallet_registered',
  walletId,
  nearAccountId: 'a'.repeat(64),
};
void invalidNearRegistrationSuccess;

// @ts-expect-error ECDSA-only registration cannot carry NEAR account provisioning.
const invalidEcdsaRegistrationSuccess: RegistrationResult = {
  success: true,
  kind: 'ecdsa_wallet_registered',
  walletId,
  thresholdEcdsaEthereumAddress: '0x1111111111111111111111111111111111111111',
  thresholdEcdsaPublicKeyB64u: 'public-key',
  accountProvisioning: implicitNearAccountProvisioning(),
};
void invalidEcdsaRegistrationSuccess;
