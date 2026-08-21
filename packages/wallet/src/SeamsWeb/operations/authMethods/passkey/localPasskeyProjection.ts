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
import { SIGNER_KINDS } from '@shared/utils/signerDomain';
import { IndexedDBManager, type LocalWalletAuthMethodRecord } from '@/core/indexedDB';
import type { AccountId } from '@/core/types/accountIds';
import { upsertNearAccountProjectionRecords } from '@/core/accountData/near/accountProjection';
import type { ClientUserData } from '@/core/accountData/near/nearAccountData.types';
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

type RecoveredPasskeyLocalProjection = {
  readonly walletId: WalletId;
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
      readonly nearAccountId: AccountId;
      readonly signerSlot: number;
      readonly nearEd25519SigningKeyId: string;
      readonly operationalPublicKey: string;
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
export async function persistRecoveredPasskeyLocalProjectionV1(
  input: RecoveredPasskeyLocalProjection,
): Promise<void> {
  const authMethod = localPasskeyAuthMethodFromFinalizeV1(input);
  const passkeyCredential = {
    id: input.credential.id,
    rawId: input.credential.rawId,
  };
  await IndexedDBManager.upsertProfile({
    profileId: String(input.walletId),
    defaultSignerSlot: input.signerSlot,
    passkeyCredential,
    ...(input.kind === 'near'
      ? {
          nearProvisioning: {
            status: 'near_ready' as const,
            updatedAtMs: authMethod.updatedAtMs,
            nearAccountId: input.nearAccountId,
          },
        }
      : {}),
  });

  if (input.kind === 'near') {
    const nearUserData: ClientUserData = {
      walletId: String(input.walletId),
      nearAccountId: input.nearAccountId,
      loginDisplayName: String(input.walletId),
      signerSlot: input.signerSlot,
      version: 2,
      registeredAt: authMethod.createdAtMs,
      lastLogin: authMethod.updatedAtMs,
      lastUpdated: authMethod.updatedAtMs,
      operationalPublicKey: input.operationalPublicKey,
      nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
      passkeyCredential,
    };
    const activation = await upsertNearAccountProjectionRecords({
      userData: nearUserData,
      ops: {
        upsertProfile: (record) => IndexedDBManager.upsertProfile(record),
        getAccountSigner: (args) => IndexedDBManager.getAccountSigner(args),
        activateAccountSigner: (record) => IndexedDBManager.activateAccountSigner(record),
      },
      activationPolicy: {
        mode: 'replace_slot',
        signerSlot: input.signerSlot,
        replacedSignerKind: SIGNER_KINDS.thresholdEd25519,
        revocationReason: 'wallet_recovery_replacement',
      },
    });
    const walletProfileId = String(input.walletId);
    await IndexedDBManager.setLastProfileStateForProfile(walletProfileId, activation.signerSlot);
  }

  await retireOtherLocalPasskeys(input.walletId, authMethod.rpId, authMethod.credentialIdB64u);
  await IndexedDBManager.upsertWalletAuthMethod(authMethod);
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
 * Writes are ordered so the binding lands after the profile and authenticator.
 * The last-profile pointer lands last so Lock returns to the wallet that was
 * just linked instead of a wallet previously used by this browser.
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
  await IndexedDBManager.setLastProfileStateForProfile(
    String(localAccount.walletId),
    localAccount.signerSlot,
  );
}
