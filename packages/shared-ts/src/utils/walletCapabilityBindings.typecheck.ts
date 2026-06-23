import type { WalletId } from './domainIds';
import type { NamedNearAccountId } from './near';
import type { Ed25519KeyScopeId } from './registrationIntent';
import type {
  CurrentWalletAuthMethod,
  NearAccountBinding,
  NearEd25519SignerBinding,
  PasskeyAuthScope,
  WalletAuthMethodBinding,
  WalletIdentity,
} from './walletCapabilityBindings';

declare const wallet: WalletIdentity;
declare const walletId: WalletId;
declare const rpId: PasskeyAuthScope['rpId'];
declare const credentialIdB64u: string;
declare const emailHashHex: string;
declare const registrationAuthorityId: string;
declare const namedNearAccountId: NamedNearAccountId;
declare const ed25519KeyScopeId: Ed25519KeyScopeId;

const validPasskeyBinding = {
  kind: 'passkey',
  scope: {
    wallet,
    rpId,
  },
  credentialIdB64u,
} satisfies WalletAuthMethodBinding;
void validPasskeyBinding;

const validEmailOtpBinding = {
  kind: 'email_otp',
  wallet,
  emailHashHex,
  registrationAuthorityId,
} satisfies WalletAuthMethodBinding;
void validEmailOtpBinding;

const validCurrentAuthMethod = {
  kind: 'selected',
  binding: validEmailOtpBinding,
} satisfies CurrentWalletAuthMethod;
void validCurrentAuthMethod;

const invalidCurrentAuthMethodEnum = {
  // @ts-expect-error current auth method must be none or selected binding.
  kind: 'passkey',
} satisfies CurrentWalletAuthMethod;
void invalidCurrentAuthMethodEnum;

const invalidEmailOtpWithRpId = {
  kind: 'email_otp',
  wallet,
  emailHashHex,
  registrationAuthorityId,
  // @ts-expect-error Email OTP auth-method binding must not carry passkey RP scope.
  rpId,
} satisfies WalletAuthMethodBinding;
void invalidEmailOtpWithRpId;

const invalidPasskeyWithoutRpId = {
  kind: 'passkey',
  // @ts-expect-error passkey scope requires rpId.
  scope: {
    wallet,
  },
  credentialIdB64u,
} satisfies WalletAuthMethodBinding;
void invalidPasskeyWithoutRpId;

const invalidNearAccountWithoutWallet = {
  kind: 'named_near_account',
  nearAccountId: namedNearAccountId,
  // @ts-expect-error NEAR account binding requires owning wallet identity.
} satisfies NearAccountBinding;
void invalidNearAccountWithoutWallet;

const validNearAccount = {
  kind: 'named_near_account',
  wallet,
  nearAccountId: namedNearAccountId,
} satisfies NearAccountBinding;

const invalidSignerWithFlatWalletId = {
  account: validNearAccount,
  ed25519KeyScopeId,
  signerSlot: 0,
  // @ts-expect-error signer binding must read wallet identity through account binding.
  walletId,
} satisfies NearEd25519SignerBinding;
void invalidSignerWithFlatWalletId;

const invalidSignerWithoutKeyScope = {
  account: validNearAccount,
  signerSlot: 0,
  // @ts-expect-error Ed25519 signer binding requires ed25519KeyScopeId.
} satisfies NearEd25519SignerBinding;
void invalidSignerWithoutKeyScope;
