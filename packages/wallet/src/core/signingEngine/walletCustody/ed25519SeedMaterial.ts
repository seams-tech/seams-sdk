import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import {
  getAccountKeyMaterial,
  resolveAccountKeyMaterialTarget,
  type AccountKeyMaterialDeps,
} from '@/core/indexedDB/accountKeyMaterial';
import {
  assertWalletCustodyEd25519MaterialBindingV1,
  buildWalletCustodyEd25519MaterialRecordV1,
  WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM,
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
  type WalletCustodyEd25519MaterialTargetV1,
  type WalletCustodySealedEd25519MaterialV1,
} from '@/core/indexedDB/walletCustodyEd25519MaterialRecord';

export {
  buildWalletCustodyEd25519MaterialRecordV1,
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  type WalletCustodyEd25519MaterialBindingV1,
  type WalletCustodyEd25519MaterialTargetV1,
  type WalletCustodySealedEd25519MaterialV1,
};

/**
 * The wallet's Ed25519 same-device continuity cache, as persisted.
 *
 * **One record per wallet, not one per factor.** The two records this replaces
 * were sealed under `PRF.first` and the Email OTP enrollment secret
 * respectively, and were read through two parallel paths — which existed only
 * because there were two wrapping factors. The ceremony now seals under a key
 * derived from the wallet custody seed, so every factor that opens the wallet's
 * envelope reaches the same record and there is one path to read it.
 *
 * It is a cache and never a source of truth (Constraint 13): losing it costs a
 * Router round, not the wallet.
 *
 * This module never seals. The ceremony sealed inside its own wasm module,
 * where the seed lives and never leaves; anything here that could seal would
 * need the seed on this side of the boundary, which is the property the whole
 * module exists to keep.
 */

export type PersistWalletCustodyEd25519MaterialInputV1 = {
  readonly store: AccountKeyMaterialDeps['clientDB'] & AccountKeyMaterialDeps['keyMaterialStore'];
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
};

export type WalletCustodyEd25519MaterialStorePort = AccountKeyMaterialDeps['clientDB'] &
  AccountKeyMaterialDeps['keyMaterialStore'] & {
    deleteKeyMaterial(
      profileId: string,
      signerSlot: number,
      chainIdKey: string,
      keyKind: typeof WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    ): Promise<void>;
  };

export async function persistWalletCustodyEd25519MaterialV1(
  input: PersistWalletCustodyEd25519MaterialInputV1,
): Promise<void> {
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(input.binding.nearAccountId),
  });
  if (!target) {
    throw new Error('Wallet custody Ed25519 material requires a persisted wallet profile');
  }
  await input.store.storeKeyMaterial(
    buildWalletCustodyEd25519MaterialRecordV1({ target, ...input }),
  );
}

export async function deleteWalletCustodyEd25519MaterialV1(input: {
  readonly store: WalletCustodyEd25519MaterialStorePort;
  readonly nearAccountId: string;
  readonly signerSlot: number;
}): Promise<void> {
  const target = await resolveAccountKeyMaterialTarget(input.store, {
    accountRefs: buildNearAccountRefs(input.nearAccountId),
  });
  if (!target) return;
  await input.store.deleteKeyMaterial(
    target.profileId,
    input.signerSlot,
    target.chainIdKey,
    WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  );
}

export type LoadedWalletCustodyEd25519MaterialV1 = {
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
};

export type LoadWalletCustodyEd25519MaterialResultV1 =
  | { readonly kind: 'found'; readonly material: LoadedWalletCustodyEd25519MaterialV1 }
  /** No cached row. Expected on a new device — not a failure. */
  | { readonly kind: 'absent' }
  /**
   * A row exists and cannot be used. Distinct from absent on purpose: absent
   * means fetch the envelope, unusable means the cache is wrong about this
   * wallet and should be discarded rather than repaired.
   */
  | { readonly kind: 'unusable'; readonly reason: string };

/**
 * Reads the cache the ceremony wrote.
 *
 * The counterpart to `persistWalletCustodyEd25519MaterialV1`, which shipped
 * without one — the row was written at registration and never read, so every
 * unlock paid for a Router round the cache existed to avoid.
 *
 * Returns the sealed halves rather than opening them. Opening needs the cache
 * key derived from the wallet custody seed, which lives behind the ceremony's
 * wasm boundary; a loader that could open would need the seed on this side,
 * and that is the property this module exists to keep.
 *
 * The caller states which key set it expects. A row that names a different
 * registered public key is reported unusable rather than returned: it is a
 * cache entry for a key set this unlock is not performing, and importing it
 * would install material for the wrong key.
 */
export async function loadWalletCustodyEd25519MaterialV1(input: {
  readonly store: AccountKeyMaterialDeps['clientDB'] & AccountKeyMaterialDeps['keyMaterialStore'];
  readonly nearAccountId: string;
  readonly signerSlot: number;
  /** Absent means "whatever is cached"; present pins the key set. */
  readonly expectedRegisteredPublicKeyB64u?: string;
}): Promise<LoadWalletCustodyEd25519MaterialResultV1> {
  const record = await getAccountKeyMaterial({
    deps: { clientDB: input.store, keyMaterialStore: input.store },
    accountRefs: buildNearAccountRefs(input.nearAccountId),
    signerSlot: input.signerSlot,
    keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
  });
  if (!record) return { kind: 'absent' };

  const envelope = record.payloadEnvelope;
  if (!envelope?.ciphertext || !envelope.nonce) {
    return { kind: 'unusable', reason: 'cached custody material has no sealed payload' };
  }
  /* The algorithm names the seed domain. A row sealed under one of the
     retired per-factor keys would decrypt to nothing with the seed-derived
     cache key, and reporting that as a signing failure would send someone
     looking at the ceremony instead of at a stale row. */
  if (envelope.alg !== WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM) {
    return { kind: 'unusable', reason: 'cached custody material was sealed under another key' };
  }

  const binding = (record.payload as { binding?: unknown } | undefined)?.binding;
  if (!binding || typeof binding !== 'object') {
    return { kind: 'unusable', reason: 'cached custody material has no binding' };
  }
  const candidate = binding as WalletCustodyEd25519MaterialBindingV1;
  if (candidate.kind !== WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND) {
    return { kind: 'unusable', reason: 'cached custody material is not a wallet custody record' };
  }
  try {
    assertWalletCustodyEd25519MaterialBindingV1(candidate);
  } catch (error: unknown) {
    return {
      kind: 'unusable',
      reason: error instanceof Error ? error.message : 'cached custody binding is incomplete',
    };
  }

  const expected = String(input.expectedRegisteredPublicKeyB64u || '').trim();
  if (expected && expected !== String(candidate.registeredPublicKeyB64u || '').trim()) {
    return { kind: 'unusable', reason: 'cached custody material is for another key set' };
  }

  return {
    kind: 'found',
    material: {
      binding: candidate,
      sealed: { ciphertextB64u: envelope.ciphertext, nonceB64u: envelope.nonce },
    },
  };
}
