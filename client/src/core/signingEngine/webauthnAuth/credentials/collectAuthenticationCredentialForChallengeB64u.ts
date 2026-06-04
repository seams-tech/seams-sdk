import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { AccountSignerStatus, ProfileAuthenticatorRecord } from '@/core/indexedDB';
import { buildNearAccountRefs } from '@/core/accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '@/core/indexedDB/profileAccountProjection';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';

export type WebAuthnAllowCredential = {
  id: string;
  type: string;
  transports: AuthenticatorTransport[];
};

export type WebAuthnAuthenticatorRecord = Pick<
  ProfileAuthenticatorRecord,
  'credentialId' | 'transports'
>;

export type WebAuthnCredentialStorePort<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
> = {
  resolveProfileAccountContext: (args: {
    chainIdKey: string;
    accountAddress: string;
  }) => Promise<{ profileId: string; accountRef: { chainIdKey: string; accountAddress: string } } | null>;
  listProfileAuthenticators: (profileId: string) => Promise<TAuth[]>;
  listAccountSigners: (args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerStatus;
  }) => Promise<Array<{ metadata?: Record<string, unknown>; signerAuthMethod?: string }>>;
  selectProfileAuthenticatorsForPrompt: (args: {
    profileId: string;
    authenticators: TAuth[];
    selectedCredentialRawId?: string;
    accountLabel?: string;
  }) => Promise<{
    authenticatorsForPrompt: TAuth[];
    wrongPasskeyError?: string;
  }>;
};

export type WebAuthnPromptPort = {
  getRpId: () => string;
  getAuthenticationCredentialsSerializedForChallengeB64u: (args: {
    nearAccountId: AccountId;
    challengeB64u: string;
    allowCredentials?: WebAuthnAllowCredential[];
    includeSecondPrfOutput?: boolean;
  }) => Promise<WebAuthnAuthenticationCredential>;
};

export function authenticatorsToAllowCredentials<TAuth extends WebAuthnAuthenticatorRecord>(
  authenticators: TAuth[],
): WebAuthnAllowCredential[] {
  return authenticators.map((auth) => ({
    id: String(auth.credentialId || ''),
    type: 'public-key',
    transports: Array.isArray(auth.transports) ? (auth.transports as AuthenticatorTransport[]) : [],
  }));
}

function canonicalWalletIdFromPasskeySigner(
  signer: { metadata?: Record<string, unknown>; signerAuthMethod?: string },
): string {
  if (String(signer.signerAuthMethod || '') !== 'passkey') return '';
  const walletId = String(signer.metadata?.walletId || '').trim();
  const credentialId = String(signer.metadata?.passkeyCredentialRawId || '').trim();
  return walletId && credentialId ? walletId : '';
}

async function resolveCanonicalWalletPasskeyContext<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
>(args: {
  credentialStore: WebAuthnCredentialStorePort<TAuth>;
  chainIdKey: string;
  accountAddress: string;
  accountLabel: string;
}): Promise<{ walletId: string; authenticators: TAuth[] }> {
  const signers = await args.credentialStore
    .listAccountSigners({
      chainIdKey: args.chainIdKey,
      accountAddress: args.accountAddress,
      status: 'active',
    });
  const walletIds = Array.from(
    new Set(signers.map(canonicalWalletIdFromPasskeySigner).filter(Boolean)),
  );
  if (walletIds.length === 0) {
    throw new Error(`[multichain] no passkey signer found for account ${args.accountLabel}`);
  }
  if (walletIds.length > 1) {
    throw new Error(`[multichain] multiple wallet identities found for account ${args.accountLabel}`);
  }
  const walletId = walletIds[0];
  const authenticators = await args.credentialStore.listProfileAuthenticators(walletId);
  return { walletId, authenticators };
}

async function collectFromAuthenticators<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
>(args: {
  credentialStore: WebAuthnCredentialStorePort<TAuth>;
  touchIdPrompt: Pick<WebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  profileId: string;
  accountLabel: AccountId | string;
  challengeB64u: string;
  authenticators: TAuth[];
  onBeforePrompt?: (info: {
    authenticators: TAuth[];
    authenticatorsForPrompt: TAuth[];
    challengeB64u: string;
  }) => void;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  if (args.authenticators.length === 0) {
    throw new Error(`[multichain] no passkeys found for account ${String(args.accountLabel)}`);
  }

  const ensured = await args.credentialStore.selectProfileAuthenticatorsForPrompt({
    profileId: args.profileId,
    authenticators: args.authenticators,
    accountLabel: String(args.accountLabel),
  });
  const authenticatorsForPrompt = ensured.authenticatorsForPrompt;
  if (authenticatorsForPrompt.length === 0) {
    throw new Error(`[multichain] no passkey credential selected for account ${String(args.accountLabel)}`);
  }

  args.onBeforePrompt?.({
    authenticators: args.authenticators,
    authenticatorsForPrompt,
    challengeB64u: args.challengeB64u,
  });

  const allowCredentials = authenticatorsToAllowCredentials(authenticatorsForPrompt);
  const serialized =
    await args.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
      nearAccountId: String(args.accountLabel) as AccountId,
      challengeB64u: args.challengeB64u,
      allowCredentials,
      includeSecondPrfOutput: args.includeSecondPrfOutput,
    });

  const selected = await args.credentialStore.selectProfileAuthenticatorsForPrompt({
    profileId: args.profileId,
    authenticators: args.authenticators,
    selectedCredentialRawId: serialized.rawId,
    accountLabel: String(args.accountLabel),
  });
  if (selected?.wrongPasskeyError) {
    throw new Error(String(selected.wrongPasskeyError));
  }

  return serialized;
}

export async function collectAuthenticationCredentialForChallengeB64u<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
>(args: {
  credentialStore: WebAuthnCredentialStorePort<TAuth>;
  touchIdPrompt: Pick<WebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  nearAccountId: AccountId | string;
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: TAuth[];
    authenticatorsForPrompt: TAuth[];
    challengeB64u: string;
  }) => void;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  const nearAccountId = toAccountId(args.nearAccountId);
  const context = await resolveProfileAccountContextFromCandidates(
    args.credentialStore,
    buildNearAccountRefs(nearAccountId),
  );
  if (!context?.profileId) {
    throw new Error(`[multichain] no profile/account mapping found for account ${nearAccountId}`);
  }

  const passkeyContext = await resolveCanonicalWalletPasskeyContext({
    credentialStore: args.credentialStore,
    chainIdKey: context.accountRef.chainIdKey,
    accountAddress: context.accountRef.accountAddress,
    accountLabel: nearAccountId,
  });
  return await collectFromAuthenticators({
    credentialStore: args.credentialStore,
    touchIdPrompt: args.touchIdPrompt,
    profileId: passkeyContext.walletId,
    accountLabel: nearAccountId,
    authenticators: passkeyContext.authenticators,
    challengeB64u: args.challengeB64u,
    ...(args.onBeforePrompt ? { onBeforePrompt: args.onBeforePrompt } : {}),
    ...(typeof args.includeSecondPrfOutput === 'boolean'
      ? { includeSecondPrfOutput: args.includeSecondPrfOutput }
      : {}),
  });
}

export async function collectAuthenticationCredentialForWalletChallengeB64u<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
>(args: {
  credentialStore: WebAuthnCredentialStorePort<TAuth>;
  touchIdPrompt: Pick<WebAuthnPromptPort, 'getAuthenticationCredentialsSerializedForChallengeB64u'>;
  walletId: AccountId | string;
  challengeB64u: string;
  onBeforePrompt?: (info: {
    authenticators: TAuth[];
    authenticatorsForPrompt: TAuth[];
    challengeB64u: string;
  }) => void;
  includeSecondPrfOutput?: boolean;
}): Promise<WebAuthnAuthenticationCredential> {
  const walletId = String(args.walletId || '').trim();
  const authenticators = await args.credentialStore.listProfileAuthenticators(walletId);
  return await collectFromAuthenticators({
    credentialStore: args.credentialStore,
    touchIdPrompt: args.touchIdPrompt,
    profileId: walletId,
    accountLabel: walletId,
    authenticators,
    challengeB64u: args.challengeB64u,
    ...(args.onBeforePrompt ? { onBeforePrompt: args.onBeforePrompt } : {}),
    ...(typeof args.includeSecondPrfOutput === 'boolean'
      ? { includeSecondPrfOutput: args.includeSecondPrfOutput }
      : {}),
  });
}
