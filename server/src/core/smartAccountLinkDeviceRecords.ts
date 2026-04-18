import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AccountSignerRecord } from './AccountSignerStore';
import type { SmartAccountRecoverySubjectRecord } from './SmartAccountRecoverySubjectStore';
import { normalizeSmartAccountHexLike } from './smartAccountRegistrationRecords';

export type LinkedSmartAccountRecord = {
  chainIdKey: string;
  chain: 'evm' | 'tempo';
  chainId: number;
  accountAddress: string;
  accountModel: 'erc4337' | 'tempo-native';
  deployed: boolean;
  factory?: string;
  entryPoint?: string;
  salt?: string;
  counterfactualAddress?: string;
};

function coerceChain(value: unknown): 'evm' | 'tempo' | null {
  const normalized = toOptionalTrimmedString(value)?.toLowerCase() || '';
  if (normalized === 'evm' || normalized === 'tempo') return normalized;
  return null;
}

function coerceChainId(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return parsed;
}

function inferAccountModel(chain: 'evm' | 'tempo', value: unknown): 'erc4337' | 'tempo-native' {
  const normalized = toOptionalTrimmedString(value);
  if (normalized === 'erc4337' || normalized === 'tempo-native') return normalized;
  return chain === 'evm' ? 'erc4337' : 'tempo-native';
}

function toLinkedSmartAccountRecord(
  record: SmartAccountRecoverySubjectRecord,
): LinkedSmartAccountRecord | null {
  const chainIdKey = toOptionalTrimmedString(record.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeSmartAccountHexLike(record.accountAddress);
  const metadata = record.metadata || {};
  const chain = coerceChain(metadata.chain);
  const chainId = coerceChainId(metadata.chainId);
  if (!chainIdKey || !accountAddress || !chain || !chainId) return null;

  return {
    chainIdKey,
    chain,
    chainId,
    accountAddress,
    accountModel: inferAccountModel(chain, metadata.accountModel),
    deployed: metadata.deployed === true,
    ...(normalizeSmartAccountHexLike(metadata.factory)
      ? { factory: normalizeSmartAccountHexLike(metadata.factory) }
      : {}),
    ...(normalizeSmartAccountHexLike(metadata.entryPoint)
      ? { entryPoint: normalizeSmartAccountHexLike(metadata.entryPoint) }
      : {}),
    ...(toOptionalTrimmedString(metadata.salt) ? { salt: toOptionalTrimmedString(metadata.salt)! } : {}),
    ...(normalizeSmartAccountHexLike(metadata.counterfactualAddress)
      ? { counterfactualAddress: normalizeSmartAccountHexLike(metadata.counterfactualAddress) }
      : {}),
  };
}

export function buildLinkDeviceSmartAccountRecords(input: {
  userId: string;
  signerSlot: number;
  credentialIdB64u: string;
  rpId: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  participantIds?: number[];
  recoverySubjects?: SmartAccountRecoverySubjectRecord[];
  nowMs?: number;
}): {
  accountSigners: AccountSignerRecord[];
  linkedAccounts: LinkedSmartAccountRecord[];
} {
  const userId = toOptionalTrimmedString(input.userId);
  const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
  const rpId = toOptionalTrimmedString(input.rpId);
  const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(input.thresholdEcdsaPublicKeyB64u);
  const thresholdOwnerAddress = normalizeSmartAccountHexLike(input.thresholdOwnerAddress);
  const nowMs = Number.isFinite(Number(input.nowMs)) ? Math.floor(Number(input.nowMs)) : Date.now();
  if (!userId || !credentialIdB64u || !rpId) return { accountSigners: [], linkedAccounts: [] };
  if (!relayerKeyId || !thresholdEcdsaPublicKeyB64u || !thresholdOwnerAddress) {
    return { accountSigners: [], linkedAccounts: [] };
  }

  const accountSigners: AccountSignerRecord[] = [];
  const linkedAccounts: LinkedSmartAccountRecord[] = [];
  const seenAccountKeys = new Set<string>();

  for (const subject of input.recoverySubjects || []) {
    const linked = toLinkedSmartAccountRecord(subject);
    if (!linked) continue;
    const linkedAccountKey = `${linked.chainIdKey}::${linked.accountAddress}`;
    if (seenAccountKeys.has(linkedAccountKey)) continue;
    seenAccountKeys.add(linkedAccountKey);
    linkedAccounts.push(linked);
    accountSigners.push({
      version: 'account_signer_v1',
      userId,
      chainIdKey: linked.chainIdKey,
      accountAddress: linked.accountAddress,
      signerType: 'threshold',
      signerId: thresholdOwnerAddress,
      status: 'pending',
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      metadata: {
        accountModel: linked.accountModel,
        ownerAddress: thresholdOwnerAddress,
        relayerKeyId,
        thresholdEcdsaPublicKeyB64u,
        signerSlot: input.signerSlot,
        credentialIdB64u,
        rpId,
        chain: linked.chain,
        chainId: linked.chainId,
        ...(Array.isArray(input.participantIds) && input.participantIds.length > 0
          ? { participantIds: [...input.participantIds] }
          : {}),
        ...(linked.factory ? { factory: linked.factory } : {}),
        ...(linked.entryPoint ? { entryPoint: linked.entryPoint } : {}),
        ...(linked.salt ? { salt: linked.salt } : {}),
        ...(linked.counterfactualAddress
          ? { counterfactualAddress: linked.counterfactualAddress }
          : {}),
      },
    });
  }

  return { accountSigners, linkedAccounts };
}
