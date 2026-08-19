import {
  buildEmailOtpWalletAuthAuthority,
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
  type WalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletAuthMethodRecordId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { toRpId } from './evmFamilyEcdsaIdentity';
import type { OwnerLaneScope } from './signingLaneAuthBinding';

export type OwnerLaneScopeStores = {
  listWalletAuthMethodsForWallet(walletId: string): Promise<readonly LocalWalletAuthMethodRecord[]>;
  getWalletPasskeyAuthenticator(args: {
    walletId: string;
    credentialId: string;
  }): Promise<{ readonly credentialId: string; readonly signerSlot: number } | null>;
};

export class OwnerLaneScopeIntegrityError extends Error {
  constructor(message: string) {
    super(`[OwnerLaneScope] ${message}`);
    this.name = 'OwnerLaneScopeIntegrityError';
  }
}

/**
 * The active authority names a credential this device holds no active
 * canonical wallet auth method for: a pre-Phase-8 enrollment (or a device
 * whose canonical state was removed). It cannot act as a human owner until it
 * links again. Distinct from OwnerLaneScopeIntegrityError so request
 * boundaries and the UI can surface "link this device again" instead of a
 * generic integrity failure.
 */
export class OwnerRelinkRequiredError extends Error {
  readonly code = 'relink_required' as const;
  readonly reason = 'missing_canonical_owner_binding' as const;

  constructor(walletAuthMethodId: string) {
    super(
      `[OwnerLaneScope] relink_required: no active canonical wallet auth method (${walletAuthMethodId})`,
    );
    this.name = 'OwnerRelinkRequiredError';
  }
}

export function isOwnerRelinkRequiredError(error: unknown): error is OwnerRelinkRequiredError {
  return (
    error instanceof OwnerRelinkRequiredError &&
    error.name === 'OwnerRelinkRequiredError' &&
    error.code === 'relink_required'
  );
}

function walletAuthAuthorityFromLocalRecord(
  record: LocalWalletAuthMethodRecord,
): WalletAuthAuthority {
  switch (record.kind) {
    case 'passkey':
      return buildPasskeyWalletAuthAuthority({
        walletId: record.walletId,
        rpId: record.rpId,
        credentialIdB64u: record.credentialIdB64u,
      });
    case 'email_otp':
      return buildEmailOtpWalletAuthAuthority({
        walletId: record.walletId,
        provider: record.authority.factor.provider,
        providerUserId: record.authority.factor.providerUserId,
        emailHashHex: record.authority.verifier.emailHashHex,
      });
  }
}

/**
 * R103C owner derivation chain: active Wallet Session authority -> one active
 * wallet auth method -> exact credential -> exact local authenticator and
 * signer slot (Passkey only). Every value comes from the previous link, and
 * the resolved method must reproduce the authority digest the active session
 * carries. Missing or duplicate records are integrity failures — timestamps,
 * labels, and slot searches never select another owner.
 */
export async function resolveOwnerLaneScope(args: {
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly stores: OwnerLaneScopeStores;
}): Promise<OwnerLaneScope> {
  const walletId = String(args.authorityRef.walletId);
  const expectedAuthMethodId = String(args.authorityRef.walletAuthMethodId);
  const authMethods = await args.stores.listWalletAuthMethodsForWallet(walletId);
  const matches = authMethods.filter(
    (record) =>
      record.status === 'active' &&
      String(record.walletId) === walletId &&
      String(walletAuthMethodRecordId(record)) === expectedAuthMethodId,
  );
  const [authMethod] = matches;
  if (!authMethod) {
    throw new OwnerRelinkRequiredError(expectedAuthMethodId);
  }
  if (matches.length > 1) {
    throw new OwnerLaneScopeIntegrityError(
      `active authority resolves ${matches.length} wallet auth methods (${expectedAuthMethodId})`,
    );
  }
  // The method id alone under-discriminates (an Email OTP id omits the
  // provider subject); the recomputed authority must reproduce the digest the
  // active session was issued for.
  const resolvedAuthority = walletAuthAuthorityFromLocalRecord(authMethod);
  const resolvedRef = await walletAuthAuthorityRef({ authority: resolvedAuthority });
  if (
    resolvedRef.kind !== args.authorityRef.kind ||
    String(resolvedRef.walletId) !== walletId ||
    resolvedRef.walletAuthMethodId !== args.authorityRef.walletAuthMethodId ||
    resolvedRef.authorityDigest !== args.authorityRef.authorityDigest
  ) {
    throw new OwnerLaneScopeIntegrityError(
      `resolved wallet auth method does not reproduce the active authority digest (${expectedAuthMethodId})`,
    );
  }
  if (authMethod.kind === 'email_otp') {
    return {
      auth: {
        kind: 'email_otp',
        providerSubjectId: String(authMethod.authority.factor.providerUserId),
      },
    };
  }
  const authenticator = await args.stores.getWalletPasskeyAuthenticator({
    walletId,
    credentialId: authMethod.credentialIdB64u,
  });
  if (!authenticator || authenticator.credentialId !== authMethod.credentialIdB64u) {
    throw new OwnerLaneScopeIntegrityError(
      'active Passkey auth method has no exact local authenticator',
    );
  }
  const signerSlot = parseSignerSlot(authenticator.signerSlot, { min: 1 });
  if (signerSlot === null) {
    throw new OwnerLaneScopeIntegrityError('local authenticator signer slot is invalid');
  }
  return {
    auth: {
      kind: 'passkey',
      rpId: toRpId(authMethod.rpId),
      credentialIdB64u: authMethod.credentialIdB64u,
    },
    signerSlot,
  };
}
