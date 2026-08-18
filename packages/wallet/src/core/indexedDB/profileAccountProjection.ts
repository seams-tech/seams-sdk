import type {
  AccountRef,
  AccountSignerRecord,
  ChainAccountRecord,
  LastProfileState,
  ProfileRecord,
} from './passkeyClientDB.types';

export type ResolvedProfileAccountContext = {
  profileId: string;
  accountRef: AccountRef;
};

export type ProfileAccountContextPort = {
  resolveProfileAccountContext: (
    accountRef: AccountRef,
  ) => Promise<ResolvedProfileAccountContext | null>;
};

export type ProfileAccountProjectionPort = ProfileAccountContextPort & {
  getProfile: (profileId: string) => Promise<ProfileRecord | null>;
  listAccountSigners: (args: {
    chainIdKey: string;
    accountAddress: string;
    status?: AccountSignerRecord['status'];
  }) => Promise<AccountSignerRecord[]>;
};

export type ProfileLastSelectionPort = {
  getLastProfileState: () => Promise<LastProfileState | null>;
  listChainAccountsByProfile: (profileId: string) => Promise<ChainAccountRecord[]>;
};

export function selectPrimaryChainAccount(
  chainAccounts: ChainAccountRecord[],
): ChainAccountRecord | null {
  if (!Array.isArray(chainAccounts) || chainAccounts.length === 0) return null;
  return chainAccounts.find((row) => !!row.isPrimary) || chainAccounts[0] || null;
}

export function selectAccountSigner(args: {
  profile: ProfileRecord;
  activeSigners: AccountSignerRecord[];
  signerSlot?: number;
}): AccountSignerRecord | null {
  if (typeof args.signerSlot === 'number') {
    return args.activeSigners.find((row) => row.signerSlot === args.signerSlot) || null;
  }
  const preferredSlot = Number.isSafeInteger(args.profile.defaultSignerSlot)
    ? args.profile.defaultSignerSlot
    : 1;
  return (
    args.activeSigners.find((row) => row.signerSlot === preferredSlot) ||
    args.activeSigners.slice().sort((a, b) => a.signerSlot - b.signerSlot)[0] ||
    null
  );
}

export async function resolveProfileAccountContextFromCandidates(
  clientDB: ProfileAccountContextPort,
  accountRefs: AccountRef[],
): Promise<ResolvedProfileAccountContext | null> {
  for (const accountRef of accountRefs) {
    const context = await clientDB.resolveProfileAccountContext(accountRef).catch(() => null);
    if (!context?.profileId) continue;
    return {
      profileId: context.profileId,
      accountRef: context.accountRef,
    };
  }
  return null;
}

export type ResolvedProfileAccountProjection = {
  context: ResolvedProfileAccountContext;
  profile: ProfileRecord;
  activeSigners: AccountSignerRecord[];
  selectedSigner: AccountSignerRecord;
};

export async function resolveProfileAccountProjection(
  clientDB: ProfileAccountProjectionPort,
  args: {
    accountRefs: AccountRef[];
    signerSlot?: number;
  },
): Promise<ResolvedProfileAccountProjection | null> {
  const context = await resolveProfileAccountContextFromCandidates(clientDB, args.accountRefs);
  if (!context?.profileId) return null;

  const [profile, activeSigners] = await Promise.all([
    clientDB.getProfile(context.profileId),
    clientDB.listAccountSigners({
      chainIdKey: context.accountRef.chainIdKey,
      accountAddress: context.accountRef.accountAddress,
      status: 'active',
    }),
  ]);
  if (!profile || !activeSigners.length) return null;

  const selectedSigner = selectAccountSigner({
    profile,
    activeSigners,
    signerSlot: args.signerSlot,
  });
  if (!selectedSigner) return null;

  return {
    context,
    profile,
    activeSigners,
    selectedSigner,
  };
}

export async function getPrimaryProfileAccountByChain(
  clientDB: {
    listChainAccountsByProfile: (profileId: string) => Promise<ChainAccountRecord[]>;
  },
  args: {
    profileId: string;
    chainIdKeys: string[];
  },
): Promise<ChainAccountRecord | null> {
  const rows = await clientDB.listChainAccountsByProfile(args.profileId).catch(() => []);
  if (!rows.length) return null;

  for (const chainIdKey of args.chainIdKeys) {
    const matches = rows.filter((row) => row.chainIdKey === chainIdKey);
    const selected = selectPrimaryChainAccount(matches);
    if (selected) return selected;
  }

  return null;
}

export async function getLastSelectedProfileAccountByChain(
  clientDB: ProfileLastSelectionPort,
  args: {
    chainIdKeys: string[];
  },
): Promise<{
  profileId: string;
  signerSlot: number;
  chainAccount: ChainAccountRecord;
} | null> {
  const lastProfileState = await clientDB.getLastProfileState().catch(() => null);
  if (!lastProfileState?.profileId) return null;

  const chainAccount = await getPrimaryProfileAccountByChain(clientDB, {
    profileId: lastProfileState.profileId,
    chainIdKeys: args.chainIdKeys,
  });
  if (!chainAccount) return null;

  return {
    profileId: lastProfileState.profileId,
    signerSlot: lastProfileState.activeSignerSlot,
    chainAccount,
  };
}
