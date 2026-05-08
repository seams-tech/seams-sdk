import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { ProfileAuthenticatorRecord } from '@/core/indexedDB';
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

export type WebAuthnIndexedDbClientPort<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
> = {
  resolveProfileAccountContext: (args: {
    chainIdKey: string;
    accountAddress: string;
  }) => Promise<{ profileId: string; accountRef: { chainIdKey: string; accountAddress: string } } | null>;
  listProfileAuthenticators: (profileId: string) => Promise<TAuth[]>;
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

export type WebAuthnIndexedDbPort<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
> = {
  clientDB: WebAuthnIndexedDbClientPort<TAuth>;
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

export async function collectAuthenticationCredentialForChallengeB64u<
  TAuth extends WebAuthnAuthenticatorRecord = ProfileAuthenticatorRecord,
>(args: {
  indexedDB: WebAuthnIndexedDbPort<TAuth>;
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
    args.indexedDB.clientDB as any,
    buildNearAccountRefs(nearAccountId),
  );
  if (!context?.profileId) {
    throw new Error(`[multichain] no profile/account mapping found for account ${nearAccountId}`);
  }

  const authenticators = await args.indexedDB.clientDB.listProfileAuthenticators(context.profileId);
  let authenticatorsForPrompt = authenticators;
  if (authenticators.length > 0) {
    const ensured = await args.indexedDB.clientDB.selectProfileAuthenticatorsForPrompt({
      profileId: context.profileId,
      authenticators,
      accountLabel: nearAccountId,
    });
    authenticatorsForPrompt = ensured.authenticatorsForPrompt;
  }

  args.onBeforePrompt?.({
    authenticators,
    authenticatorsForPrompt,
    challengeB64u: args.challengeB64u,
  });

  const allowCredentials = authenticatorsToAllowCredentials(authenticatorsForPrompt);
  const serialized =
    await args.touchIdPrompt.getAuthenticationCredentialsSerializedForChallengeB64u({
      nearAccountId,
      challengeB64u: args.challengeB64u,
      allowCredentials,
      includeSecondPrfOutput: args.includeSecondPrfOutput,
    });

  if (authenticators.length > 0) {
    const ensured = await args.indexedDB.clientDB.selectProfileAuthenticatorsForPrompt({
      profileId: context.profileId,
      authenticators,
      selectedCredentialRawId: serialized.rawId,
      accountLabel: nearAccountId,
    });
    if (ensured?.wrongPasskeyError) {
      throw new Error(String(ensured.wrongPasskeyError));
    }
  }

  return serialized;
}
