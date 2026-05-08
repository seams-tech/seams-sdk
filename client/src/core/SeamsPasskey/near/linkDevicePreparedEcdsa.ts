import { joinNormalizedUrl, stripTrailingSlashes } from '@shared/utils/normalize';
import { SIGNER_AUTH_METHODS, SIGNER_KINDS, SIGNER_SOURCES } from '@shared/utils/signerDomain';
import { isPlainObject } from '@shared/utils/validation';
import type { PasskeyManagerContext } from '../interfaces';
import type { UnifiedIndexedDBManager } from '../../indexedDB';
import { buildNearAccountRefs } from '../../accountData/near/accountRefs';
import { resolveProfileAccountContextFromCandidates } from '../../indexedDB/profileAccountProjection';
import { toAccountId } from '../../types/accountIds';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

type PreparedLinkDeviceThresholdEcdsa = {
  clientAdditiveShare32B64u: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  participantIds?: number[];
};

type PreparedLinkDeviceLinkedAccount = {
  chainIdKey: string;
  chainTarget: ThresholdEcdsaChainTarget;
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
  if (!isPlainObject(raw)) return null;
  const clientAdditiveShare32B64u = String(raw.clientAdditiveShare32B64u || '').trim();
  const relayerKeyId = String(raw.relayerKeyId || '').trim();
  const thresholdEcdsaPublicKeyB64u = String(raw.thresholdEcdsaPublicKeyB64u || '').trim();
  const ethereumAddress = String(raw.ethereumAddress || '').trim();
  if (
    !clientAdditiveShare32B64u ||
    !relayerKeyId ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    clientAdditiveShare32B64u,
    relayerKeyId,
    thresholdEcdsaPublicKeyB64u,
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
    if (!isPlainObject(value)) continue;
    const chainIdKey = String(value.chainIdKey || '')
      .trim()
      .toLowerCase();
    const accountAddress = String(value.accountAddress || '').trim();
    const accountModel = String(value.accountModel || '').trim();
    let chainTarget: ThresholdEcdsaChainTarget;
    try {
      chainTarget = thresholdEcdsaChainTargetFromRequest(
        isPlainObject(value.chainTarget)
          ? (value.chainTarget as Record<string, unknown>)
          : {
              chain: value.chain,
              chainId: value.chainId,
            },
      );
    } catch {
      continue;
    }
    if (!chainIdKey || !accountAddress) continue;
    if (accountModel !== 'erc4337' && accountModel !== 'tempo-native') continue;
    const key = `${chainIdKey}::${thresholdEcdsaChainTargetKey(chainTarget)}::${accountAddress}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      chainIdKey,
      chainTarget,
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
  if (!isPlainObject(body) || body.ok !== true || !isPlainObject(body.session)) return null;
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
      ...(account.counterfactualAddress
        ? { counterfactualAddress: account.counterfactualAddress }
        : {}),
    });
  }
}

export async function persistPreparedLinkDeviceSmartAccountSigners(args: {
  context: PasskeyManagerContext;
  indexedDB: UnifiedIndexedDBManager;
  accountId: string;
  sessionId: string;
  signerSlot: number;
  relayerUrl?: string;
  pollIntervalMs?: number;
  maxWaitMs?: number;
}): Promise<{ seededSignerCount: number }> {
  const relayerUrl = stripTrailingSlashes(
    String(args.relayerUrl || args.context?.configs?.network.relayer?.url || '').trim(),
  );
  if (!relayerUrl) {
    throw new Error('Missing relayer url for link-device prepared signer sync');
  }
  const sessionId = String(args.sessionId || '').trim();
  if (!sessionId) {
    throw new Error('Missing link-device sessionId for prepared signer sync');
  }

  const nearContext = await resolveProfileAccountContextFromCandidates(
    args.indexedDB.clientDB,
    buildNearAccountRefs(toAccountId(String(args.accountId))),
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
    const signerSlot = Math.max(1, Math.floor(Number(args.signerSlot) || 1));
    await args.indexedDB.stageAccountSigner({
      account: {
        profileId: nearContext.profileId,
        chainIdKey: account.chainIdKey,
        accountAddress: account.accountAddress,
        accountModel: account.accountModel,
      },
      signer: {
        signerId: prepared.preparedThresholdEcdsa.ethereumAddress,
        signerSlot,
        signerType: 'threshold',
        signerKind: SIGNER_KINDS.thresholdEcdsa,
        signerAuthMethod: SIGNER_AUTH_METHODS.passkey,
        signerSource: SIGNER_SOURCES.passkeyRegistration,
        metadata: {
          accountModel: account.accountModel,
          ownerAddress: prepared.preparedThresholdEcdsa.ethereumAddress,
          relayerKeyId: prepared.preparedThresholdEcdsa.relayerKeyId,
          thresholdEcdsaPublicKeyB64u: prepared.preparedThresholdEcdsa.thresholdEcdsaPublicKeyB64u,
          signerSlot,
          chainTarget: account.chainTarget,
          chainId: account.chainTarget.chainId,
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
      },
      mutation: { routeThroughOutbox: false },
    });
    seededSignerCount += 1;
  }

  return { seededSignerCount };
}
