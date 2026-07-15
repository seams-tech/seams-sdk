import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ClientUserData } from '@/core/accountData/near/nearAccountData.types';
import type { Ed25519YaoActiveClientIdentityV1 } from '../../threshold/ed25519/yaoActiveClientRegistry';

export type LoginWithEmailOtpEd25519YaoCapabilityInternalArgs = {
  walletSession: WalletSessionRef;
  challengeId: string;
  otpCode: string;
  remainingUses: number;
  appSessionJwt: string;
  emailHashHex: string;
};

export type ResolvedEmailOtpEd25519YaoColdRecoveryV1 = {
  identity: Ed25519YaoActiveClientIdentityV1;
  user: ClientUserData;
  providerSubject: string;
};

export type ResolveEmailOtpEd25519YaoColdRecoveryDeps = {
  listPublicCapabilityReferences(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]>;
  listUsers(): Promise<readonly ClientUserData[]>;
};

function requireNonEmpty(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`Email OTP Ed25519 Yao login requires ${field}`);
  return normalized;
}

export async function resolveEmailOtpEd25519YaoColdRecoveryV1(
  deps: ResolveEmailOtpEd25519YaoColdRecoveryDeps,
  walletSession: WalletSessionRef,
): Promise<ResolvedEmailOtpEd25519YaoColdRecoveryV1 | null> {
  const walletId = String(walletSession.walletId);
  const providerSubject = requireNonEmpty(
    String(walletSession.walletSessionUserId),
    'providerSubject',
  );
  const users: ClientUserData[] = [];
  for (const user of await deps.listUsers()) {
    if (String(user.walletId) === walletId && user.authMethod === 'email_otp') {
      users.push(user);
    }
  }
  if (users.length === 0) return null;
  if (users.length !== 1) {
    throw new Error('Email OTP Ed25519 Yao login requires one exact persisted signer projection');
  }
  const user = users[0];
  if (!user) {
    throw new Error('Email OTP Ed25519 Yao signer projection is unavailable');
  }
  const references: Ed25519YaoActiveClientIdentityV1[] = [];
  for (const identity of await deps.listPublicCapabilityReferences()) {
    if (
      String(identity.walletId) === walletId &&
      String(identity.nearAccountId) === String(user.nearAccountId)
    ) {
      references.push(identity);
    }
  }
  if (references.length !== 1) {
    throw new Error(
      'Email OTP Ed25519 Yao login requires one exact durable public capability reference',
    );
  }
  const identity = references[0];
  if (!identity) {
    throw new Error('Email OTP Ed25519 Yao public capability reference is unavailable');
  }
  return { identity, user, providerSubject };
}
