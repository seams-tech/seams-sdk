/**
 * The local projection of a passkey factor the server has already accepted.
 *
 * The local record mirrors a canonical owner credential the server has
 * verified and persisted.
 *
 * Persisting is deliberately separate from the finalize that produced it. The
 * server's record is the authority; this is a cache. A finalize that succeeded
 * but whose local write did not is recoverable — replaying the finalize returns
 * the same response and the projection can be written again.
 */
import { base64UrlDecode } from '@shared/utils/base64';
import {
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import {
  buildWalletAuthMethodRecordV2,
  type WalletAuthMethodRecordV2,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { IndexedDBManager, type LocalWalletAuthMethodRecord } from '@/core/indexedDB';

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

export type SyncedPasskeyAuthMethodV2 = {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
};

export function localPasskeyAuthMethodFromSyncV2(
  args: SyncedPasskeyAuthMethodV2,
): Extract<WalletAuthMethodRecordV2, { kind: 'passkey'; status: 'active' }> {
  const rpId = parseWebAuthnRpId(args.rpId);
  const credentialIdB64u = parseWebAuthnCredentialIdB64u(args.credentialIdB64u);
  const walletAuthMethodId = parseWalletAuthMethodId(args.walletAuthMethodId);
  const walletAuthorityId = parseWalletAuthorityId(args.walletAuthorityId);
  const credentialPublicKeyB64u = String(args.credentialPublicKeyB64u || '').trim();
  if (!rpId.ok || !credentialIdB64u.ok || !walletAuthMethodId.ok || !walletAuthorityId.ok) {
    throw new Error('Synced passkey auth-method identity is invalid');
  }
  if (!credentialPublicKeyB64u || base64UrlDecode(credentialPublicKeyB64u).byteLength === 0) {
    throw new Error('Synced passkey auth method omitted credential public key');
  }
  if (!Number.isSafeInteger(args.counter) || args.counter < 0) {
    throw new Error('Synced passkey auth method returned an invalid credential counter');
  }
  const nowMs = Date.now();
  const record = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId: args.walletId,
    walletAuthorityId: walletAuthorityId.value,
    kind: 'passkey',
    status: 'active',
    rpId: rpId.value,
    credentialIdB64u: credentialIdB64u.value,
    credentialPublicKeyB64u,
    counter: args.counter,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
    activatedAtMs: nowMs,
  });
  if (record.kind !== 'passkey' || record.status !== 'active') {
    throw new Error('Synced passkey auth method branch is invalid');
  }
  return record;
}

export async function persistSyncedPasskeyAuthMethodV2(
  args: SyncedPasskeyAuthMethodV2,
): Promise<void> {
  await IndexedDBManager.upsertWalletAuthMethodV2(localPasskeyAuthMethodFromSyncV2(args));
}

type RecoveredPasskeyLocalProjection = {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly credential: {
    readonly id: string;
    readonly rawId: string;
  };
} & (
  | {
      readonly kind: 'near';
      readonly signerSlot?: never;
    }
  | {
      readonly kind: 'wallet_only';
      readonly signerSlot: number;
    }
);

async function retireOtherLocalPasskeys(
  walletId: WalletId,
  rpId: string,
  replacementCredentialIdB64u: string,
): Promise<void> {
  const methods = await IndexedDBManager.listWalletAuthMethodsForWallet(String(walletId));
  const nowMs = Date.now();
  for (const method of methods) {
    if (
      method.kind !== 'passkey' ||
      method.status !== 'active' ||
      method.rpId !== rpId ||
      method.credentialIdB64u === replacementCredentialIdB64u
    ) {
      continue;
    }
    await IndexedDBManager.upsertWalletAuthMethod({
      ...method,
      status: 'revoked',
      updatedAtMs: nowMs,
    });
  }
}

/** Rebuilds the local identity required by exact-wallet login after recovery. */
export async function persistRecoveredPasskeyAuthMethodProjectionV1(
  input: RecoveredPasskeyLocalProjection,
): Promise<void> {
  const authMethod = localPasskeyAuthMethodFromFinalizeV1(input);
  const passkeyCredential = {
    id: input.credential.id,
    rawId: input.credential.rawId,
  };
  if (input.kind === 'wallet_only') {
    await IndexedDBManager.upsertProfile({
      profileId: String(input.walletId),
      defaultSignerSlot: input.signerSlot,
      passkeyCredential,
    });
  }

  await retireOtherLocalPasskeys(input.walletId, authMethod.rpId, authMethod.credentialIdB64u);
  await IndexedDBManager.upsertWalletAuthMethod(authMethod);
  await persistSyncedPasskeyAuthMethodV2({
    walletId: input.walletId,
    walletAuthMethodId: input.walletAuthMethodId,
    walletAuthorityId: input.walletAuthorityId,
    rpId: authMethod.rpId,
    credentialIdB64u: authMethod.credentialIdB64u,
    credentialPublicKeyB64u: authMethod.credentialPublicKeyB64u,
    counter: authMethod.counter,
  });
}
