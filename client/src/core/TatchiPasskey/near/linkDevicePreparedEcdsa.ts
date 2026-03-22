import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import type { PasskeyManagerContext } from '../interfaces';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import { toAccountId } from '../../types/accountIds';

type PreparedLinkDeviceThresholdEcdsa = {
  relayerKeyId: string;
  groupPublicKeyB64u: string;
  ethereumAddress: string;
  participantIds?: number[];
};

type PreparedLinkDeviceLinkedAccount = {
  chainIdKey: string;
  chain: 'evm' | 'tempo';
  chainId: number;
  accountAddress: string;
  accountModel: 'erc4337' | 'tempo-native';
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
};

type PreparedLinkDeviceSessionPayload = {
  preparedThresholdEcdsa?: PreparedLinkDeviceThresholdEcdsa;
  preparedLinkedAccounts?: PreparedLinkDeviceLinkedAccount[];
};

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseParticipantIds(raw: unknown): number[] | undefined {
  if (!Array.isArray(raw)) return undefined;
  const out = raw
    .map((value) => Math.floor(Number(value)))
    .filter((value) => Number.isFinite(value) && value > 0);
  return out.length > 0 ? out : undefined;
}

function parsePreparedThresholdEcdsa(raw: unknown): PreparedLinkDeviceThresholdEcdsa | null {
  if (!isObject(raw)) return null;
  const relayerKeyId = String(raw.relayerKeyId || '').trim();
  const groupPublicKeyB64u = String(raw.groupPublicKeyB64u || '').trim();
  const ethereumAddress = String(raw.ethereumAddress || '').trim();
  if (!relayerKeyId || !groupPublicKeyB64u || !ethereumAddress) return null;
  return {
    relayerKeyId,
    groupPublicKeyB64u,
    ethereumAddress,
    ...(parseParticipantIds(raw.participantIds)
      ? { participantIds: parseParticipantIds(raw.participantIds) }
      : {}),
  };
}

function parsePreparedLinkedAccounts(raw: unknown): PreparedLinkDeviceLinkedAccount[] {
  if (!Array.isArray(raw)) return [];
  const out: PreparedLinkDeviceLinkedAccount[] = [];
  const seen = new Set<string>();
  for (const value of raw) {
    if (!isObject(value)) continue;
    const chainIdKey = String(value.chainIdKey || '').trim().toLowerCase();
    const chain = String(value.chain || '').trim().toLowerCase();
    const chainId = Math.floor(Number(value.chainId));
    const accountAddress = String(value.accountAddress || '').trim();
    const accountModel = String(value.accountModel || '').trim();
    if (!chainIdKey || !accountAddress) continue;
    if (chain !== 'evm' && chain !== 'tempo') continue;
    if (!Number.isFinite(chainId) || chainId <= 0) continue;
    if (accountModel !== 'erc4337' && accountModel !== 'tempo-native') continue;
    const key = `${chainIdKey}::${accountAddress}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      chainIdKey,
      chain,
      chainId,
      accountAddress,
      accountModel,
      ...(typeof value.factory === 'string' && value.factory.trim()
        ? { factory: value.factory.trim() }
        : {}),
      ...(typeof value.entryPoint === 'string' && value.entryPoint.trim()
        ? { entryPoint: value.entryPoint.trim() }
        : {}),
      ...(typeof value.salt === 'string' && value.salt.trim() ? { salt: value.salt.trim() } : {}),
      ...(typeof value.counterfactualAddress === 'string' && value.counterfactualAddress.trim()
        ? { counterfactualAddress: value.counterfactualAddress.trim() }
        : {}),
    });
  }
  return out;
}

async function fetchPreparedLinkDeviceSession(input: {
  relayerUrl: string;
  sessionId: string;
}): Promise<PreparedLinkDeviceSessionPayload | null> {
  const url = joinNormalizedUrl(
    input.relayerUrl,
    `/link-device/session/${encodeURIComponent(input.sessionId)}`,
  );
  const response = await fetch(url, { method: 'GET' });
  if (!response.ok) return null;
  const body: unknown = await response.json().catch(() => ({}));
  if (!isObject(body) || body.ok !== true || !isObject(body.session)) return null;
  const preparedThresholdEcdsa = parsePreparedThresholdEcdsa(body.session.preparedThresholdEcdsa);
  const preparedLinkedAccounts = parsePreparedLinkedAccounts(body.session.preparedLinkedAccounts);
  if (!preparedThresholdEcdsa || preparedLinkedAccounts.length === 0) return null;
  return { preparedThresholdEcdsa, preparedLinkedAccounts };
}

async function upsertPreparedLinkedAccounts(input: {
  indexedDB: UnifiedIndexedDBManager;
  profileId: string;
  linkedAccounts: PreparedLinkDeviceLinkedAccount[];
}): Promise<void> {
  for (const account of input.linkedAccounts) {
    await input.indexedDB.upsertChainAccount({
      profileId: input.profileId,
      chainIdKey: account.chainIdKey,
      accountAddress: account.accountAddress,
      accountModel: account.accountModel,
      isPrimary: true,
      ...(account.factory ? { factory: account.factory } : {}),
      ...(account.entryPoint ? { entryPoint: account.entryPoint } : {}),
      ...(account.salt ? { salt: account.salt } : {}),
      ...(account.counterfactualAddress ? { counterfactualAddress: account.counterfactualAddress } : {}),
    });
  }
}

export async function persistPreparedLinkDeviceSmartAccountSigners(args: {
  context: PasskeyManagerContext;
  indexedDB: UnifiedIndexedDBManager;
  accountId: string;
  sessionId: string;
  deviceNumber: number;
  relayerUrl?: string;
  pollIntervalMs?: number;
  maxWaitMs?: number;
}): Promise<{ seededSignerCount: number }> {
  const relayerUrl =
    stripTrailingSlashes(String(args.relayerUrl || args.context?.configs?.network.relayer?.url || '').trim());
  if (!relayerUrl) {
    throw new Error('Missing relayer url for link-device prepared signer sync');
  }
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('Missing link-device sessionId for prepared signer sync');
  }

  const nearContext = await args.indexedDB.clientDB.resolveNearAccountContext(
    toAccountId(String(args.accountId)),
  );
  if (!nearContext?.profileId) {
    throw new Error(`Missing profile/account mapping for ${String(args.accountId)}`);
  }

  const pollIntervalMs = Math.max(25, Math.floor(Number(args.pollIntervalMs) || 250));
  const maxWaitMs = Math.max(pollIntervalMs, Math.floor(Number(args.maxWaitMs) || 10_000));
  const deadline = Date.now() + maxWaitMs;
  let prepared: PreparedLinkDeviceSessionPayload | null = null;
  while (!prepared && Date.now() <= deadline) {
    prepared = await fetchPreparedLinkDeviceSession({ relayerUrl, sessionId });
    if (prepared) break;
    await sleep(pollIntervalMs);
  }
  if (!prepared?.preparedThresholdEcdsa || !prepared.preparedLinkedAccounts?.length) {
    throw new Error('Timed out waiting for prepared link-device threshold-ECDSA session payload');
  }

  await upsertPreparedLinkedAccounts({
    indexedDB: args.indexedDB,
    profileId: nearContext.profileId,
    linkedAccounts: prepared.preparedLinkedAccounts,
  });

  let seededSignerCount = 0;
  for (const account of prepared.preparedLinkedAccounts) {
    await args.indexedDB.upsertAccountSigner({
      profileId: nearContext.profileId,
      chainIdKey: account.chainIdKey,
      accountAddress: account.accountAddress,
      signerId: prepared.preparedThresholdEcdsa.ethereumAddress,
      signerSlot: Math.max(1, Math.floor(Number(args.deviceNumber) || 1)),
      signerType: 'threshold',
      status: 'pending',
      metadata: {
        accountModel: account.accountModel,
        ownerAddress: prepared.preparedThresholdEcdsa.ethereumAddress,
        relayerKeyId: prepared.preparedThresholdEcdsa.relayerKeyId,
        groupPublicKeyB64u: prepared.preparedThresholdEcdsa.groupPublicKeyB64u,
        deviceNumber: Math.max(1, Math.floor(Number(args.deviceNumber) || 1)),
        chain: account.chain,
        chainId: account.chainId,
        ...(Array.isArray(prepared.preparedThresholdEcdsa.participantIds)
          ? { participantIds: [...prepared.preparedThresholdEcdsa.participantIds] }
          : {}),
        ...(account.factory ? { factory: account.factory } : {}),
        ...(account.entryPoint ? { entryPoint: account.entryPoint } : {}),
        ...(account.salt ? { salt: account.salt } : {}),
        ...(account.counterfactualAddress
          ? { counterfactualAddress: account.counterfactualAddress }
          : {}),
      },
    });
    seededSignerCount += 1;
  }

  return { seededSignerCount };
}
