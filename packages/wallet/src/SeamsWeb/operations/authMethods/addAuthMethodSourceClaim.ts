/**
 * Refactor 109C: the source claim a same-device addition puts in its intent.
 *
 * The intent digest is what the fresh source proof signs, so every identity the
 * proof is meant to bind has to be inside it. The server resolves the true
 * source from the presented credential and refuses the ceremony when the two
 * disagree, which is what makes this a claim rather than an authority: a client
 * that lies here fails closed at `start` instead of authorizing anything.
 *
 * The authority digest is read from the persisted `WalletAuthorityV1`, not from
 * the Wallet Session's `authorityDigest`. Those are different values under
 * different brands, and only the authority record's is what the server
 * revalidates against.
 */

import { IndexedDBManager } from '@/core/indexedDB';
import { walletSessionAuthorizations } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';
import type { AddAuthMethodIntentSourceV1 } from '@shared/utils/registrationIntent';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';

export type AddAuthMethodSourceClaimResultV1 =
  | {
      readonly kind: 'resolved';
      readonly source: AddAuthMethodIntentSourceV1;
      /* Kept alongside the hashed claim so the proof uses the exact method
         named by that claim. */
      readonly sourceAuthMethod: Extract<
        WalletAuthMethodRecordV2,
        { readonly status: 'active' }
      >;
    }
  | { readonly kind: 'unavailable'; readonly reason: string };

export async function resolveAddAuthMethodSourceClaimV1(
  walletId: WalletId,
): Promise<AddAuthMethodSourceClaimResultV1> {
  const selected = await IndexedDBManager.resolveSelectedWalletAuthority(String(walletId));
  if (selected.kind !== 'resolved') {
    return {
      kind: 'unavailable',
      reason: `selected wallet authority is ${selected.kind}`,
    };
  }
  if (selected.authMethod.status !== 'active') {
    return { kind: 'unavailable', reason: 'selected auth method is not active' };
  }
  if (selected.authority.state !== 'active') {
    return { kind: 'unavailable', reason: 'selected wallet authority is not active' };
  }
  const session = await walletSessionAuthorizations.readActiveForWallet(walletId);
  if (session.kind !== 'found') {
    return { kind: 'unavailable', reason: `active Wallet Session is ${session.kind}` };
  }
  /* The session has to belong to the method being used as the source. A
     session minted by a sibling method would name a different authorization
     than the proof, and the server's own check would reject it later — failing
     here keeps the refusal where the mismatch is visible. */
  if (session.projection.authority.walletAuthMethodId !== selected.authMethod.walletAuthMethodId) {
    return {
      kind: 'unavailable',
      reason: 'active Wallet Session was issued through a different auth method',
    };
  }
  return {
    kind: 'resolved',
    sourceAuthMethod: selected.authMethod,
    source: {
      walletAuthorityId: selected.authMethod.walletAuthorityId,
      walletAuthMethodId: selected.authMethod.walletAuthMethodId,
      walletSessionId: String(session.projection.walletSessionId),
      authorityDigestB64u: String(selected.authority.authorityDigestB64u),
      revocationEpoch: selected.authority.revocationEpoch,
    },
  };
}
