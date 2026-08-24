import {
  parseEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import { parseSignerSlot, type SignerSlot } from '@shared/utils/signerSlot';
import type { LocalWalletAuthMethodRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { toRpId } from './evmFamilyEcdsaIdentity';
import type { OwnerLaneScope } from './signingLaneAuthBinding';

export type OwnerLaneScopeStores = {
  getWalletAuthMethodV2(walletAuthMethodId: string): Promise<WalletAuthMethodRecordV2 | null>;
  listWalletAuthMethodsForWallet(walletId: string): Promise<readonly LocalWalletAuthMethodRecord[]>;
  getWalletPasskeyAuthenticator(args: {
    walletId: string;
    credentialId: string;
  }): Promise<{ readonly credentialId: string; readonly signerSlot: number } | null>;
};

export type ActiveWalletAuthMethodV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

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

function passkeyWalletAuthAuthorityFromV2Record(
  record: Extract<WalletAuthMethodRecordV2, { kind: 'passkey' }>,
): PasskeyWalletAuthAuthority {
  return {
    walletId: record.walletId,
    factor: {
      kind: 'passkey',
      credentialIdB64u: record.credentialIdB64u,
    },
    verifier: {
      kind: 'webauthn',
      rpId: record.rpId,
    },
    bindingId: record.walletAuthMethodId,
  };
}

function emailOtpWalletAuthAuthorityFromLocalFactor(args: {
  readonly authMethod: Extract<WalletAuthMethodRecordV2, { kind: 'email_otp' }>;
  readonly localMethods: readonly LocalWalletAuthMethodRecord[];
}): EmailOtpWalletAuthAuthority {
  const matches = args.localMethods.filter(
    (record): record is Extract<LocalWalletAuthMethodRecord, { kind: 'email_otp' }> =>
      record.kind === 'email_otp' &&
      record.status === 'active' &&
      record.walletId === args.authMethod.walletId &&
      record.emailHashHex === args.authMethod.emailHashHex,
  );
  const localMethod = matches[0];
  const authority = localMethod ? parseEmailOtpWalletAuthAuthority(localMethod.authority) : null;
  if (
    matches.length !== 1 ||
    !authority ||
    authority.walletId !== args.authMethod.walletId ||
    authority.bindingId !== args.authMethod.walletAuthMethodId ||
    authority.verifier.emailHashHex !== args.authMethod.emailHashHex
  ) {
    throw new OwnerLaneScopeIntegrityError('active Email OTP method has no exact local factor');
  }
  return authority;
}

function assertExactFactorAuthorityBinding(args: {
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly authority: WalletAuthAuthority;
}): WalletAuthAuthority {
  if (
    args.authority.walletId !== args.authMethod.walletId ||
    args.authority.bindingId !== args.authMethod.walletAuthMethodId
  ) {
    throw new OwnerLaneScopeIntegrityError(
      'active wallet auth method does not have an exact factor authority binding',
    );
  }
  return args.authority;
}

export async function resolveExactWalletAuthAuthority(args: {
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly stores: OwnerLaneScopeStores;
}): Promise<WalletAuthAuthority> {
  if (args.authMethod.kind === 'passkey') {
    return assertExactFactorAuthorityBinding({
      authMethod: args.authMethod,
      authority: passkeyWalletAuthAuthorityFromV2Record(args.authMethod),
    });
  }
  return assertExactFactorAuthorityBinding({
    authMethod: args.authMethod,
    authority: emailOtpWalletAuthAuthorityFromLocalFactor({
      authMethod: args.authMethod,
      localMethods: await args.stores.listWalletAuthMethodsForWallet(
        String(args.authMethod.walletId),
      ),
    }),
  });
}

async function assertOwnerAuthorityRefMatches(args: {
  readonly expected: WalletAuthAuthorityRef;
  readonly authority: PasskeyWalletAuthAuthority | EmailOtpWalletAuthAuthority;
}): Promise<void> {
  const resolvedRef = await walletAuthAuthorityRef({ authority: args.authority });
  if (
    resolvedRef.kind !== args.expected.kind ||
    resolvedRef.walletId !== args.expected.walletId ||
    resolvedRef.walletAuthMethodId !== args.expected.walletAuthMethodId ||
    resolvedRef.authorityDigest !== args.expected.authorityDigest
  ) {
    throw new OwnerLaneScopeIntegrityError(
      `resolved wallet auth method does not reproduce the active authority digest (${String(
        args.expected.walletAuthMethodId,
      )})`,
    );
  }
}

export function buildExactPasskeyOwnerLaneScope(args: {
  readonly authMethod: Extract<ActiveWalletAuthMethodV2, { readonly kind: 'passkey' }>;
  readonly signerSlot: SignerSlot;
}): Extract<OwnerLaneScope, { readonly auth: { readonly kind: 'passkey' } }> {
  return {
    auth: {
      kind: 'passkey',
      rpId: toRpId(args.authMethod.rpId),
      credentialIdB64u: args.authMethod.credentialIdB64u,
    },
    signerSlot: args.signerSlot,
  };
}

async function passkeyOwnerLaneScope(args: {
  readonly authMethod: Extract<ActiveWalletAuthMethodV2, { readonly kind: 'passkey' }>;
  readonly stores: OwnerLaneScopeStores;
}): Promise<Extract<OwnerLaneScope, { readonly auth: { readonly kind: 'passkey' } }>> {
  const authenticator = await args.stores.getWalletPasskeyAuthenticator({
    walletId: String(args.authMethod.walletId),
    credentialId: args.authMethod.credentialIdB64u,
  });
  if (!authenticator || authenticator.credentialId !== args.authMethod.credentialIdB64u) {
    throw new OwnerLaneScopeIntegrityError(
      'active Passkey auth method has no exact local authenticator',
    );
  }
  const signerSlot = parseSignerSlot(authenticator.signerSlot, { min: 1 });
  if (signerSlot === null) {
    throw new OwnerLaneScopeIntegrityError('local authenticator signer slot is invalid');
  }
  return buildExactPasskeyOwnerLaneScope({ authMethod: args.authMethod, signerSlot });
}

export async function resolveExactOwnerLaneScope(args: {
  readonly authMethod: ActiveWalletAuthMethodV2;
  readonly stores: OwnerLaneScopeStores;
}): Promise<OwnerLaneScope> {
  if (args.authMethod.kind === 'passkey') {
    return await passkeyOwnerLaneScope({ authMethod: args.authMethod, stores: args.stores });
  }
  const authority = emailOtpWalletAuthAuthorityFromLocalFactor({
    authMethod: args.authMethod,
    localMethods: await args.stores.listWalletAuthMethodsForWallet(
      String(args.authMethod.walletId),
    ),
  });
  const authorityRef = await walletAuthAuthorityRef({ authority });
  return {
    auth: {
      kind: 'email_otp',
      providerSubjectId: String(authority.factor.providerUserId),
    },
    ownerAuthority: {
      walletAuthMethodId: authorityRef.walletAuthMethodId,
      authorityDigest: authorityRef.authorityDigest,
    },
  };
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
  const authMethod = await args.stores.getWalletAuthMethodV2(expectedAuthMethodId);
  if (!authMethod || authMethod.status !== 'active' || String(authMethod.walletId) !== walletId) {
    throw new OwnerRelinkRequiredError(expectedAuthMethodId);
  }
  if (authMethod.kind === 'email_otp') {
    const authority = emailOtpWalletAuthAuthorityFromLocalFactor({
      authMethod,
      localMethods: await args.stores.listWalletAuthMethodsForWallet(walletId),
    });
    await assertOwnerAuthorityRefMatches({ expected: args.authorityRef, authority });
    return {
      auth: {
        kind: 'email_otp',
        providerSubjectId: String(authority.factor.providerUserId),
      },
      ownerAuthority: {
        walletAuthMethodId: args.authorityRef.walletAuthMethodId,
        authorityDigest: args.authorityRef.authorityDigest,
      },
    };
  }
  const resolvedAuthority = passkeyWalletAuthAuthorityFromV2Record(authMethod);
  await assertOwnerAuthorityRefMatches({
    expected: args.authorityRef,
    authority: resolvedAuthority,
  });
  return await passkeyOwnerLaneScope({ authMethod, stores: args.stores });
}
