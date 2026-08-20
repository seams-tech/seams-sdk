import type { ClientUserData } from '@/core/accountData/near/nearAccountData.types';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { Ed25519YaoPublicCapabilityReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';

export type WalletCustodyEd25519Projection = {
  identity: Ed25519YaoPublicCapabilityReferenceV1;
  user: ClientUserData;
  providerSubject: string;
};

function requireNonEmpty(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`Wallet custody Ed25519 projection requires ${field}`);
  return normalized;
}

/**
 * `providerSubject` is the Email OTP provider's subject id (e.g. `google:<sub>`)
 * and is passed as its own argument. It must never be read off
 * `walletSession.walletSessionUserId`: that field is a wallet-scoped identity,
 * and conflating the two caused the Email OTP bootstrap regression recorded in
 * docs/refactor-36-narrow-lifecycle-types.md.
 */
export async function resolveWalletCustodyEd25519ProjectionV1(
  deps: {
    listPublicCapabilityReferences(): Promise<readonly Ed25519YaoPublicCapabilityReferenceV1[]>;
    listUsers(): Promise<readonly ClientUserData[]>;
  },
  walletSession: WalletSessionRef,
  providerSubjectId: string,
): Promise<WalletCustodyEd25519Projection | null> {
  const walletId = String(walletSession.walletId);
  const providerSubject = requireNonEmpty(String(providerSubjectId), 'providerSubject');
  const users = (await deps.listUsers()).filter(
    (user) => String(user.walletId) === walletId && user.authMethod === 'email_otp',
  );
  if (users.length === 0) return null;
  if (users.length !== 1 || !users[0]) {
    throw new Error('Wallet custody Ed25519 requires one exact persisted signer projection');
  }
  const user = users[0];
  const references = (await deps.listPublicCapabilityReferences()).filter(
    (identity) =>
      String(identity.walletId) === walletId &&
      String(identity.nearAccountId) === String(user.nearAccountId),
  );
  if (references.length !== 1 || !references[0]) {
    throw new Error('Wallet custody Ed25519 requires one exact public capability reference');
  }
  return { identity: references[0], user, providerSubject };
}
