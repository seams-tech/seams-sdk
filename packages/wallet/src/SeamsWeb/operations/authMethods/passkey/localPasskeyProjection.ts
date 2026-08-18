/**
 * The local projection of a passkey factor the server has already accepted.
 *
 * Adding a factor on the wallet's own device and adding one from a linked
 * device end at the same place: a canonical owner credential the server has
 * verified and persisted. The local record is the same either way, so it is
 * built here rather than twice.
 *
 * Persisting is deliberately separate from the finalize that produced it. The
 * server's record is the authority; this is a cache. A finalize that succeeded
 * but whose local write did not is recoverable — replaying the finalize returns
 * the same response and the projection can be written again.
 */
import { base64UrlDecode } from '@shared/utils/base64';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import type { WalletId } from '@shared/utils/registrationIntent';
import { IndexedDBManager, type LocalWalletAuthMethodRecord } from '@/core/indexedDB';
import type { LinkedDeviceLocalAccountProjectionV1 } from '@shared/device-linking';

/** The finalize fields this projection is built from, whichever route returned them. */
export type FinalizedPasskeyAuthMethodV1 = {
  readonly walletId: WalletId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
};

export function localPasskeyAuthMethodFromFinalizeV1(
  args: FinalizedPasskeyAuthMethodV1,
): LocalWalletAuthMethodRecord & { kind: 'passkey' } {
  const parsedRpId = parseWebAuthnRpId(args.rpId);
  if (!parsedRpId.ok) throw new Error(parsedRpId.error.message);
  const parsedCredentialId = parseWebAuthnCredentialIdB64u(args.credentialIdB64u);
  if (!parsedCredentialId.ok) throw new Error(parsedCredentialId.error.message);
  const credentialPublicKeyB64u = String(args.credentialPublicKeyB64u || '').trim();
  if (!credentialPublicKeyB64u) {
    throw new Error('Wallet add-passkey finalize omitted credential public key');
  }
  if (base64UrlDecode(credentialPublicKeyB64u).byteLength === 0) {
    throw new Error('Wallet add-passkey finalize returned an empty credential public key');
  }
  if (!Number.isSafeInteger(args.counter) || args.counter < 0) {
    throw new Error('Wallet add-passkey finalize returned an invalid credential counter');
  }
  const nowMs = Date.now();
  return {
    version: 'wallet_auth_method_v1',
    kind: 'passkey',
    status: 'active',
    localStatus: 'synced',
    walletId: args.walletId,
    rpId: parsedRpId.value,
    credentialIdB64u: parsedCredentialId.value,
    credentialPublicKeyB64u,
    counter: args.counter,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  };
}

/** Writes the projection for a factor the server has already accepted. */
export async function persistFinalizedPasskeyAuthMethodV1(
  args: FinalizedPasskeyAuthMethodV1,
): Promise<void> {
  await IndexedDBManager.upsertWalletAuthMethod(localPasskeyAuthMethodFromFinalizeV1(args));
}

/**
 * Everything a device that has never registered locally needs to unlock.
 *
 * A device reaching this through linking has the finalized credential but none
 * of the wallet identity around it, and canonical unlock is fail-closed on three
 * separate local records: a wallet profile carrying the signer slot, a profile
 * authenticator naming the credential, and an active auth method binding the
 * two. Missing any one of them, unlock refuses before it ever consults the
 * server's credential allow-list — so the server's list cannot stand in for
 * them, and they cannot be discovered by attempting to unlock.
 *
 * The slot is the wallet's own, carried from the server rather than defaulted.
 * `upsertProfile` falls back to slot 1 when none is given, which for a wallet
 * whose key was created in another slot produces a profile that unlocks nothing
 * and fails far from the cause.
 *
 * Writes are ordered so the binding lands last: an auth method referencing an
 * authenticator that is not there yet reads as "no active passkey binding",
 * which is indistinguishable from a genuinely revoked device.
 */
export async function persistFinalizedLinkedOwnerPasskeyV1(args: {
  readonly credential: FinalizedPasskeyAuthMethodV1;
  readonly localAccount: LinkedDeviceLocalAccountProjectionV1;
}): Promise<void> {
  const { credential, localAccount } = args;
  if (String(credential.walletId) !== String(localAccount.walletId)) {
    throw new Error('linked owner projection credential and account name different wallets');
  }
  const authMethod = localPasskeyAuthMethodFromFinalizeV1(credential);
  await IndexedDBManager.upsertProfile({
    profileId: String(localAccount.walletId),
    defaultSignerSlot: localAccount.signerSlot,
    // Already provisioned: this device is joining a wallet whose NEAR account
    // exists, so its provisioning is observed rather than pending.
    nearProvisioning: {
      status: 'near_ready',
      updatedAtMs: authMethod.updatedAtMs,
      nearAccountId: localAccount.nearAccountId,
    },
  });
  await IndexedDBManager.upsertProfileAuthenticator({
    profileId: String(localAccount.walletId),
    signerSlot: localAccount.signerSlot,
    credentialId: authMethod.credentialIdB64u,
    credentialPublicKey: base64UrlDecode(authMethod.credentialPublicKeyB64u),
    transports: [],
    name: `${localAccount.nearAccountId} (linked device)`,
    registered: new Date(authMethod.createdAtMs).toISOString(),
    syncedAt: new Date(authMethod.updatedAtMs).toISOString(),
  });
  await IndexedDBManager.upsertWalletAuthMethod(authMethod);
}
