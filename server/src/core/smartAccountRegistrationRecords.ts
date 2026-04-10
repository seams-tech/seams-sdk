import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { AccountSignerRecord } from './AccountSignerStore';
import type { SmartAccountRecoverySubjectRecord } from './SmartAccountRecoverySubjectStore';
import type { CreateAccountAndRegisterSmartAccountTarget } from './types';

type SmartAccountChain = CreateAccountAndRegisterSmartAccountTarget['chain'];

type RegistrationSmartAccountTarget = {
  chain: SmartAccountChain;
  chainId: number;
  factory?: string;
  entryPoint?: string;
  recoveryAuthority?: string;
  salt?: string;
  counterfactualAddress?: string;
};

export function normalizeSmartAccountHexLike(value: unknown): string {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) return '';
  return normalized.startsWith('0x') ? normalized.toLowerCase() : normalized;
}

function normalizeTarget(
  target: CreateAccountAndRegisterSmartAccountTarget,
): RegistrationSmartAccountTarget | null {
  const chain = String(target?.chain || '')
    .trim()
    .toLowerCase();
  if (chain !== 'evm' && chain !== 'tempo') return null;
  const chainId = Math.floor(Number(target?.chain_id));
  if (!Number.isFinite(chainId) || chainId <= 0) return null;
  return {
    chain,
    chainId,
    ...(normalizeSmartAccountHexLike(target?.factory)
      ? { factory: normalizeSmartAccountHexLike(target.factory) }
      : {}),
    ...(normalizeSmartAccountHexLike(target?.entry_point)
      ? { entryPoint: normalizeSmartAccountHexLike(target.entry_point) }
      : {}),
    ...(normalizeSmartAccountHexLike(target?.recovery_authority)
      ? { recoveryAuthority: normalizeSmartAccountHexLike(target.recovery_authority) }
      : {}),
    ...(toOptionalTrimmedString(target?.salt) ? { salt: toOptionalTrimmedString(target.salt)! } : {}),
    ...(normalizeSmartAccountHexLike(target?.counterfactual_address)
      ? { counterfactualAddress: normalizeSmartAccountHexLike(target.counterfactual_address) }
      : {}),
  };
}

function toChainIdKey(chain: SmartAccountChain, chainId: number): string {
  return `${chain}:${Math.floor(chainId)}`;
}

function toAccountModel(chain: SmartAccountChain): 'erc4337' | 'tempo-native' {
  return chain === 'evm' ? 'erc4337' : 'tempo-native';
}

export function buildRegistrationSmartAccountRecords(input: {
  userId: string;
  nearAccountId: string;
  deviceNumber: number;
  credentialIdB64u: string;
  rpId: string;
  ecdsaThresholdKeyId?: string;
  relayerKeyId: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  participantIds?: number[];
  smartAccountTargets?: CreateAccountAndRegisterSmartAccountTarget[];
  nowMs?: number;
}): {
  accountSigners: AccountSignerRecord[];
  recoverySubjects: SmartAccountRecoverySubjectRecord[];
} {
  const userId = toOptionalTrimmedString(input.userId);
  const nearAccountId = toOptionalTrimmedString(input.nearAccountId);
  const credentialIdB64u = toOptionalTrimmedString(input.credentialIdB64u);
  const rpId = toOptionalTrimmedString(input.rpId);
  const ecdsaThresholdKeyId = toOptionalTrimmedString(input.ecdsaThresholdKeyId);
  const relayerKeyId = toOptionalTrimmedString(input.relayerKeyId);
  const thresholdEcdsaPublicKeyB64u = toOptionalTrimmedString(input.thresholdEcdsaPublicKeyB64u);
  const thresholdOwnerAddress = normalizeSmartAccountHexLike(input.thresholdOwnerAddress);
  const nowMs = Number.isFinite(Number(input.nowMs)) ? Math.floor(Number(input.nowMs)) : Date.now();
  if (!userId || !nearAccountId || !credentialIdB64u || !rpId) {
    return { accountSigners: [], recoverySubjects: [] };
  }
  if (!thresholdOwnerAddress || !relayerKeyId || !thresholdEcdsaPublicKeyB64u) {
    return { accountSigners: [], recoverySubjects: [] };
  }

  const accountSigners: AccountSignerRecord[] = [];
  const recoverySubjects: SmartAccountRecoverySubjectRecord[] = [];
  const seenSignerKeys = new Set<string>();
  const seenSubjectKeys = new Set<string>();

  for (const rawTarget of input.smartAccountTargets || []) {
    const target = normalizeTarget(rawTarget);
    if (!target) continue;

    const chainIdKey = toChainIdKey(target.chain, target.chainId);
    const accountAddress = target.counterfactualAddress || thresholdOwnerAddress;
    if (!accountAddress) continue;

    const accountModel = toAccountModel(target.chain);
    const signerKey = `${userId}::${chainIdKey}::${accountAddress}::${thresholdOwnerAddress}`;
    if (!seenSignerKeys.has(signerKey)) {
      seenSignerKeys.add(signerKey);
      accountSigners.push({
        version: 'account_signer_v1',
        userId,
        chainIdKey,
        accountAddress,
        signerType: 'threshold',
        signerId: thresholdOwnerAddress,
        status: 'active',
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        metadata: {
          accountModel,
          ownerAddress: thresholdOwnerAddress,
          ...(ecdsaThresholdKeyId ? { ecdsaThresholdKeyId } : {}),
          relayerKeyId,
          thresholdEcdsaPublicKeyB64u,
          deviceNumber: input.deviceNumber,
          credentialIdB64u,
          rpId,
          chain: target.chain,
          chainId: target.chainId,
          ...(Array.isArray(input.participantIds) && input.participantIds.length > 0
            ? { participantIds: [...input.participantIds] }
            : {}),
          ...(target.factory ? { factory: target.factory } : {}),
          ...(target.entryPoint ? { entryPoint: target.entryPoint } : {}),
          ...(target.salt ? { salt: target.salt } : {}),
          ...(target.counterfactualAddress
            ? { counterfactualAddress: target.counterfactualAddress }
            : {}),
        },
      });
    }

    const subjectKey = `${chainIdKey}::${accountAddress}`;
    if (!seenSubjectKeys.has(subjectKey)) {
      seenSubjectKeys.add(subjectKey);
      recoverySubjects.push({
        version: 'smart_account_recovery_subject_v1',
        userId,
        nearAccountId,
        chainIdKey,
        accountAddress,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        metadata: {
          accountModel,
          chain: target.chain,
          chainId: target.chainId,
          deployed: false,
          ...(target.factory ? { factory: target.factory } : {}),
          ...(target.entryPoint ? { entryPoint: target.entryPoint } : {}),
          ...(target.recoveryAuthority ? { recoveryAuthority: target.recoveryAuthority } : {}),
          ...(target.salt ? { salt: target.salt } : {}),
          ...(target.counterfactualAddress
            ? { counterfactualAddress: target.counterfactualAddress }
            : {}),
        },
      });
    }
  }

  return { accountSigners, recoverySubjects };
}
