import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from '@/core/indexedDB/keyMaterialEnvelope';
import type { KeyMaterialRecord } from '@/core/indexedDB/keyMaterial.types';
import {
  resolveAccountKeyMaterialTarget,
  type AccountKeyMaterialDeps,
} from '@/core/indexedDB/accountKeyMaterial';
import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';

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

export const WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND =
  'wallet_custody_ed25519_active_client_v1' as const;

/**
 * Names the seed domain, so a reader cannot mistake this row for one of the
 * per-factor records and try to open it with a factor secret.
 */
const WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM =
  'chacha20poly1305-hkdf-sha256-wallet-custody-seed-v1';
/** Starts at 1: this row is new, not a migration of the per-factor records. */
const WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION = 1;

/**
 * What a reader needs to rebuild the seal binding and identify the key.
 *
 * Carries no `rpId` and no `credentialIdB64u`. That absence is the point: the
 * record belongs to the wallet, and naming the credential that happened to run
 * the ceremony would reintroduce exactly the coupling the seed-sealed cache
 * removes. The first four fields are the ones the ceremony hashed into the
 * seal binding, so a reader reproduces it from the record alone.
 */
export type WalletCustodyEd25519MaterialBindingV1 = {
  readonly kind: typeof WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND;
  readonly applicationBindingDigestB64u: string;
  readonly registeredPublicKeyB64u: string;
  readonly participantIds: readonly [number, number];
  readonly stateEpoch: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly signingWorkerId: string;
  readonly signingWorkerVerifyingShareB64u: string;
};

/** The ceremony's sealed output, verbatim. */
export type WalletCustodySealedEd25519MaterialV1 = {
  readonly ciphertextB64u: string;
  readonly nonceB64u: string;
};

export type PersistWalletCustodyEd25519MaterialInputV1 = {
  readonly store: AccountKeyMaterialDeps['clientDB'] & AccountKeyMaterialDeps['keyMaterialStore'];
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
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

export type WalletCustodyEd25519MaterialTargetV1 = {
  readonly profileId: string;
  readonly chainIdKey: string;
  readonly accountAddress: string;
};

/**
 * Assembles the stored row from material the ceremony already sealed.
 *
 * Takes ciphertext rather than a live client precisely so this cannot seal:
 * the wrapping key derives from the seed, and the seed never crosses the
 * ceremony's wasm boundary.
 */
export function buildWalletCustodyEd25519MaterialRecordV1(input: {
  readonly target: WalletCustodyEd25519MaterialTargetV1;
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
}): KeyMaterialRecord {
  const { binding, sealed, target } = input;
  requireBindingIdentity(binding);
  const registeredPublicKey = base64UrlDecode(binding.registeredPublicKeyB64u);
  if (registeredPublicKey.length !== 32) {
    throw new Error('Wallet custody Ed25519 material requires a 32-byte registered public key');
  }
  if (!sealed.ciphertextB64u || !sealed.nonceB64u) {
    throw new Error('Wallet custody Ed25519 material requires its sealed ciphertext and nonce');
  }

  return {
    profileId: target.profileId,
    signerSlot: binding.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: `ed25519:${base58Encode(registeredPublicKey)}`,
    signerId: binding.nearEd25519SigningKeyId,
    payload: { binding },
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM,
      nonce: sealed.nonceB64u,
      ciphertext: sealed.ciphertextB64u,
      aad: buildEnvelopeAAD({
        profileId: target.profileId,
        signerSlot: binding.signerSlot,
        chainIdKey: target.chainIdKey,
        accountAddress: target.accountAddress,
        keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        schemaVersion: WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION,
        signerId: binding.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION,
  };
}

/**
 * Rejects a record that cannot be looked up or re-opened.
 *
 * These are all identity, not secrets: a row missing one is a row a later
 * unlock finds and then cannot use, which is worse than one that was never
 * written — the wallet looks cached and fails at signing time.
 */
function requireBindingIdentity(binding: WalletCustodyEd25519MaterialBindingV1): void {
  for (const [label, value] of [
    ['walletId', binding.walletId],
    ['nearAccountId', binding.nearAccountId],
    ['nearEd25519SigningKeyId', binding.nearEd25519SigningKeyId],
    ['signingWorkerId', binding.signingWorkerId],
    ['applicationBindingDigestB64u', binding.applicationBindingDigestB64u],
    ['signingWorkerVerifyingShareB64u', binding.signingWorkerVerifyingShareB64u],
    ['stateEpoch', binding.stateEpoch],
  ] as const) {
    if (!String(value || '').trim()) {
      throw new Error(`Wallet custody Ed25519 material binding requires ${label}`);
    }
  }
  if (binding.participantIds.length !== 2) {
    throw new Error('Wallet custody Ed25519 material binding requires exactly two participants');
  }
}
