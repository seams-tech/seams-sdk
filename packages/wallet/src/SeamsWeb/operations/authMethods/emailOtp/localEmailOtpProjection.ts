/**
 * The local projection of an Email OTP factor the server has already accepted.
 *
 * A cache of the server's record, written after the finalize that produced it
 * rather than inside it. A finalize that succeeded but whose local write did
 * not is recoverable: replaying it returns the same response, and the
 * projection can be written again.
 *
 * Both shapes are written, and they are not redundant. The V1 record is what
 * the local unlock path reads to know this wallet can be opened with an email
 * code at all; the V2 record is what names the method and the authority it
 * belongs to, which is what makes two active methods on one authority
 * distinguishable.
 */
import {
  isEmailOtpWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import { buildWalletAuthMethodRecordV2, type WalletId } from '@shared/utils/registrationIntent';
import { IndexedDBManager } from '@/core/indexedDB';

export type FinalizedEmailOtpAuthMethodV1 = {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId | string;
  readonly walletAuthorityId: WalletAuthorityId | string;
  readonly emailAddress: string;
  readonly authority: WalletAuthAuthority;
};

/** Writes the projection for a factor the server has already accepted. */
export async function persistFinalizedEmailOtpAuthMethodV1(
  args: FinalizedEmailOtpAuthMethodV1,
): Promise<void> {
  if (!isEmailOtpWalletAuthAuthority(args.authority)) {
    throw new Error('Wallet add-email-code finalize returned a non-Email authority');
  }
  const walletAuthMethodId = parseWalletAuthMethodId(args.walletAuthMethodId);
  if (!walletAuthMethodId.ok) throw new Error(walletAuthMethodId.error.message);
  const walletAuthorityId = parseWalletAuthorityId(args.walletAuthorityId);
  if (!walletAuthorityId.ok) throw new Error(walletAuthorityId.error.message);
  const emailHashHex = String(args.authority.verifier.emailHashHex || '').trim();
  if (!emailHashHex) {
    throw new Error('Wallet add-email-code finalize returned no verified email digest');
  }
  /* The provider identity the enrollment was filed under. It is what a later
     unlock looks the authority up by, so it comes from the authority the server
     returned rather than from anything reconstructed here. */
  const registrationAuthorityId = String(args.authority.factor.providerUserId || '').trim();
  if (!registrationAuthorityId) {
    throw new Error('Wallet add-email-code finalize returned no provider identity');
  }
  const nowMs = Date.now();
  await IndexedDBManager.upsertWalletAuthMethod({
    version: 'wallet_auth_method_v1',
    kind: 'email_otp',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    emailHashHex,
    registrationAuthorityId,
    authority: args.authority,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  });
  await IndexedDBManager.upsertWalletAuthMethodV2(
    buildWalletAuthMethodRecordV2({
      version: 'wallet_auth_method_v2',
      walletAuthMethodId: walletAuthMethodId.value,
      walletId: args.walletId,
      walletAuthorityId: walletAuthorityId.value,
      kind: 'email_otp',
      status: 'active',
      emailHashHex,
      registrationAuthorityId,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      activatedAtMs: nowMs,
    }),
  );
}
