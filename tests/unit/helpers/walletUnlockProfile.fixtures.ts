import type {
  LocalWalletAuthMethodRecord,
  ProfileAuthenticatorRecord,
  ProfileRecord,
} from '@/core/indexedDB/passkeyClientDB.types';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { buildEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

function walletUnlockFixtureRpId() {
  const parsed = parseWebAuthnRpId('localhost');
  if (!parsed.ok) throw new Error('wallet unlock fixture rpId must parse');
  return parsed.value;
}

export function walletUnlockProfileFixture(args: {
  walletId: string;
  signerSlot: number;
}): ProfileRecord {
  const nowMs = Date.now();
  return {
    profileId: args.walletId,
    defaultSignerSlot: args.signerSlot,
    createdAt: nowMs,
    updatedAt: nowMs,
  };
}

export function walletUnlockPasskeyAuthenticatorFixture(args: {
  walletId: string;
  signerSlot: number;
  credentialId: string;
}): ProfileAuthenticatorRecord {
  const nowIso = new Date().toISOString();
  return {
    profileId: args.walletId,
    signerSlot: args.signerSlot,
    credentialId: args.credentialId,
    credentialPublicKey: new Uint8Array([1, 2, 3]),
    transports: ['internal'],
    registered: nowIso,
    syncedAt: nowIso,
  };
}

export function walletUnlockPasskeyAuthMethodFixture(args: {
  walletId: string;
  credentialId: string;
}): LocalWalletAuthMethodRecord {
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: walletIdFromString(args.walletId),
    rpId: walletUnlockFixtureRpId(),
    credentialIdB64u: args.credentialId,
    credentialPublicKeyB64u: 'AQID',
    counter: 0,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

export function walletUnlockEmailOtpAuthMethodFixture(args: {
  walletId: string;
  providerSubjectId: string;
  emailHashHex: string;
}): LocalWalletAuthMethodRecord {
  const nowMs = Date.now();
  const walletId = walletIdFromString(args.walletId);
  return {
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    localStatus: 'synced',
    walletId,
    emailHashHex: args.emailHashHex,
    registrationAuthorityId: 'registration-authority',
    authority: buildEmailOtpWalletAuthAuthority({
      walletId,
      provider: 'google',
      providerUserId: args.providerSubjectId,
      emailHashHex: args.emailHashHex,
    }),
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}
