import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
} from '../../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../../packages/shared-ts/src/utils/domainIds';

type ActivePasskeyWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'passkey'; readonly status: 'active' }
>;

type ActiveEmailOtpWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly kind: 'email_otp'; readonly status: 'active' }
>;

export function activeRecoveryPasskeyMethodFixture(input: {
  readonly walletAuthMethodId: string;
  readonly credentialIdB64u: string;
  readonly rpId: string;
  readonly createdAtMs: number;
}): ActivePasskeyWalletAuthMethodRecordV2 {
  const walletAuthMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(input.credentialIdB64u);
  const rpId = parseWebAuthnRpId(input.rpId);
  const walletId = parseWalletId('alice.testnet');
  const walletAuthorityId = parseWalletAuthorityId('wallet-authority:recovery-source');
  if (
    !walletAuthMethodId.ok ||
    !credentialIdB64u.ok ||
    !rpId.ok ||
    !walletId.ok ||
    !walletAuthorityId.ok
  ) {
    throw new Error('active recovery Passkey fixture identities are invalid');
  }
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: walletId.value,
    walletAuthorityId: walletAuthorityId.value,
    kind: 'passkey',
    status: 'active',
    rpId: rpId.value,
    credentialIdB64u: credentialIdB64u.value,
    credentialPublicKeyB64u: `public-key:${input.credentialIdB64u}`,
    counter: 0,
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.createdAtMs,
    activatedAtMs: input.createdAtMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('active recovery Passkey fixture changed branch');
  }
  return record;
}

export function activeRecoveryEmailOtpMethodFixture(input: {
  readonly walletAuthMethodId: string;
  readonly createdAtMs: number;
}): ActiveEmailOtpWalletAuthMethodRecordV2 {
  const walletAuthMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
  const walletId = parseWalletId('alice.testnet');
  const walletAuthorityId = parseWalletAuthorityId('wallet-authority:recovery-email-sibling');
  if (!walletAuthMethodId.ok || !walletId.ok || !walletAuthorityId.ok) {
    throw new Error('active recovery Email OTP fixture identities are invalid');
  }
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: walletId.value,
    walletAuthorityId: walletAuthorityId.value,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'a'.repeat(64),
    registrationAuthorityId: 'email-authority:recovery-sibling',
    createdAtMs: input.createdAtMs,
    updatedAtMs: input.createdAtMs,
    activatedAtMs: input.createdAtMs,
  });
  if (record.kind !== 'email_otp' || record.status !== 'active') {
    throw new Error('active recovery Email OTP fixture changed branch');
  }
  return record;
}
