import type { ClientUserData } from '@/core/accountData/near/nearAccountData.types';
import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { Ed25519YaoPublicCapabilityReferenceV1 } from '@/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';

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
  /**
   * The Ed25519 activation of the authority being unlocked.
   *
   * This is the key, and it has to be: a wallet can hold a founding authority
   * and linked ones, each with its own Ed25519 signer. Selecting "the wallet's
   * one signer record" would resolve whichever happened to be unique and quietly
   * pick the wrong authority as soon as a second exists. Selecting the reference
   * that carries this exact activation names one authority's signer and nothing
   * else, and the persisted record follows from the reference rather than being
   * matched independently.
   */
  expectedMaterialActivation: MpcMaterialActivationRef,
): Promise<WalletCustodyEd25519Projection | null> {
  const walletId = String(walletSession.walletId);
  const providerSubject = requireNonEmpty(String(providerSubjectId), 'providerSubject');
  const references = (await deps.listPublicCapabilityReferences()).filter(
    (identity) =>
      String(identity.walletId) === walletId &&
      mpcMaterialActivationRefsEqual(identity.materialActivation, expectedMaterialActivation),
  );
  if (references.length === 0) return null;
  if (references.length !== 1 || !references[0]) {
    throw new Error('Wallet custody Ed25519 requires one exact public capability reference');
  }
  const identity = references[0];
  const users = (await deps.listUsers()).filter(
    (user) =>
      String(user.walletId) === walletId &&
      String(user.nearAccountId) === String(identity.nearAccountId),
  );
  if (users.length !== 1 || !users[0]) {
    throw new Error('Wallet custody Ed25519 requires one exact persisted signer projection');
  }
  return { identity, user: users[0], providerSubject };
}
