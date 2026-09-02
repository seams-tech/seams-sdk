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
      readonly sourceAuthMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
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
  if (
    selected.selection.lockState !== 'unlocked' ||
    selected.selection.walletId !== walletId ||
    selected.selection.walletAuthMethodId !== selected.authMethod.walletAuthMethodId ||
    selected.authMethod.walletId !== walletId ||
    selected.authMethod.walletAuthorityId !== selected.authority.authorityId ||
    selected.authority.walletId !== walletId
  ) {
    return { kind: 'unavailable', reason: 'selected wallet authority identity is invalid' };
  }

  let session: Awaited<
    ReturnType<typeof walletSessionAuthorizations.readExactWithOperationCredential>
  >;
  try {
    session = await walletSessionAuthorizations.readExactWithOperationCredential({
      walletId,
      authorityId: selected.authority.authorityId,
      authMethodId: selected.authMethod.walletAuthMethodId,
    });
  } catch {
    return { kind: 'unavailable', reason: 'exact Wallet Session state is corrupt' };
  }
  if (session.kind !== 'found') {
    return {
      kind: 'unavailable',
      reason: `exact Wallet Session is ${session.kind}`,
    };
  }
  if (
    session.record.walletId !== walletId ||
    session.record.authorityId !== selected.authority.authorityId ||
    session.record.authMethodId !== selected.authMethod.walletAuthMethodId ||
    session.record.authorityDigestB64u !== selected.authority.authorityDigestB64u ||
    session.record.authorityRevocationEpoch !== selected.authority.revocationEpoch ||
    session.record.expiresAtMs <= Date.now()
  ) {
    return { kind: 'unavailable', reason: 'exact Wallet Session identity is invalid or expired' };
  }
  return {
    kind: 'resolved',
    sourceAuthMethod: selected.authMethod,
    source: {
      walletAuthorityId: selected.authMethod.walletAuthorityId,
      walletAuthMethodId: selected.authMethod.walletAuthMethodId,
      walletSessionId: String(session.operationCredential.walletSessionId),
      authorityDigestB64u: String(selected.authority.authorityDigestB64u),
      revocationEpoch: selected.authority.revocationEpoch,
    },
  };
}
