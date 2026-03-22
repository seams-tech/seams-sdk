import type { AccountId } from '../../types/accountIds';
import {
  buildThresholdEd25519Participants2pV1,
  parseThresholdEd25519ParticipantsV1,
} from '@shared/threshold/participants';
import { toTrimmedString } from '@shared/utils/validation';
import type { PasskeyClientDBManager } from '../passkeyClientDB/manager';
import type { PasskeyNearKeysDBManager } from '../passkeyNearKeysDB/manager';
import type {
  ClientShareDerivation,
  PasskeyChainIdKeyAlgorithm,
  PasskeyChainIdKeyKind,
  PasskeyChainIdKeyMaterial,
  ThresholdEd25519_2p_V1Material,
} from '../passkeyNearKeysDB.types';
import { getNearChainCandidates } from './accountProjection';

export interface NearKeyMaterialDeps {
  clientDB: Pick<PasskeyClientDBManager, 'getProfileByAccount'>;
  nearKeysDB: Pick<PasskeyNearKeysDBManager, 'getKeyMaterial' | 'storeKeyMaterial'>;
}

export interface StoreNearKeyMaterialInput {
  nearAccountId: AccountId;
  deviceNumber: number;
  keyKind: PasskeyChainIdKeyKind;
  algorithm?: PasskeyChainIdKeyAlgorithm;
  publicKey: string;
  signerId?: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  timestamp?: number;
  schemaVersion?: number;
  profileId?: string;
  chainIdKey?: string;
}

export interface StoreNearThresholdKeyMaterialInput {
  nearAccountId: AccountId;
  deviceNumber: number;
  publicKey: string;
  relayerKeyId: string;
  clientShareDerivation: ClientShareDerivation;
  participants?: ThresholdEd25519_2p_V1Material['participants'];
  wrapKeySalt?: string;
  signerId?: string;
  timestamp?: number;
  schemaVersion?: number;
  profileId?: string;
  chainIdKey?: string;
}

function mapThresholdNearKey(
  nearAccountId: AccountId,
  deviceNumber: number,
  rec: PasskeyChainIdKeyMaterial | null,
): ThresholdEd25519_2p_V1Material | null {
  if (!rec) return null;
  const payload = (rec.payload || {}) as Record<string, unknown>;
  const relayerKeyId = toTrimmedString(payload.relayerKeyId || '');
  const clientShareDerivation = toTrimmedString(payload.clientShareDerivation || '') as
    | ClientShareDerivation
    | '';
  if (!relayerKeyId || !clientShareDerivation) return null;
  const participants =
    parseThresholdEd25519ParticipantsV1(payload.participants) ||
    buildThresholdEd25519Participants2pV1({
      relayerKeyId,
      clientShareDerivation,
    });
  return {
    nearAccountId,
    deviceNumber,
    kind: 'threshold_ed25519_2p_v1',
    publicKey: rec.publicKey,
    ...(rec.wrapKeySalt ? { wrapKeySalt: rec.wrapKeySalt } : {}),
    relayerKeyId,
    clientShareDerivation,
    participants,
    timestamp: rec.timestamp,
  };
}

async function resolveNearProfileByAccount(
  deps: NearKeyMaterialDeps,
  nearAccountId: AccountId,
): Promise<{ profileId: string; chainIdKey: string } | null> {
  const accountAddress = toTrimmedString(nearAccountId || '').toLowerCase();
  if (!accountAddress) return null;

  for (const chainIdKey of getNearChainCandidates(accountAddress as AccountId)) {
    const profile = await deps.clientDB
      .getProfileByAccount(chainIdKey, accountAddress)
      .catch(() => null);
    if (profile?.profileId) {
      return {
        profileId: String(profile.profileId).trim(),
        chainIdKey,
      };
    }
  }
  return null;
}

export async function getNearThresholdKeyMaterial(
  deps: NearKeyMaterialDeps,
  nearAccountId: AccountId,
  deviceNumber: number,
): Promise<ThresholdEd25519_2p_V1Material | null> {
  const resolved = await resolveNearProfileByAccount(deps, nearAccountId);
  if (!resolved?.profileId || !resolved.chainIdKey) return null;
  const keyRecord = await deps.nearKeysDB.getKeyMaterial(
    resolved.profileId,
    deviceNumber,
    resolved.chainIdKey,
    'threshold_share_v1',
  );
  return mapThresholdNearKey(nearAccountId, deviceNumber, keyRecord);
}

export async function storeNearKeyMaterial(
  deps: NearKeyMaterialDeps,
  input: StoreNearKeyMaterialInput,
): Promise<void> {
  const accountAddress = toTrimmedString(input.nearAccountId || '').toLowerCase();
  if (!accountAddress) {
    throw new Error('IndexedDBManager: Missing nearAccountId for key write');
  }
  if (!Number.isSafeInteger(input.deviceNumber) || input.deviceNumber < 1) {
    throw new Error('IndexedDBManager: Invalid deviceNumber for key write');
  }
  const keyKind = toTrimmedString(input.keyKind || '');
  if (!keyKind) {
    throw new Error('IndexedDBManager: Missing keyKind for key write');
  }
  if (keyKind !== 'threshold_share_v1') {
    throw new Error(`IndexedDBManager: Unsupported NEAR keyKind for key write: ${keyKind}`);
  }
  const algorithm = String(input.algorithm || 'ed25519')
    .trim()
    .toLowerCase();
  if (algorithm !== 'ed25519') {
    throw new Error(`IndexedDBManager: Unsupported NEAR key algorithm for key write: ${algorithm}`);
  }
  const publicKey = toTrimmedString(input.publicKey || '');
  if (!publicKey) {
    throw new Error('IndexedDBManager: Missing publicKey for key write');
  }

  const explicitProfileId = toTrimmedString(input.profileId || '');
  const explicitChainIdKey = toTrimmedString(input.chainIdKey || '').toLowerCase();
  const hasExplicitProfileId = explicitProfileId.length > 0;
  const hasExplicitChainIdKey = explicitChainIdKey.length > 0;
  if (hasExplicitProfileId !== hasExplicitChainIdKey) {
    throw new Error(
      'IndexedDBManager: profileId and chainIdKey must be provided together for explicit key target writes',
    );
  }

  const resolved =
    hasExplicitProfileId && hasExplicitChainIdKey
      ? null
      : await resolveNearProfileByAccount(deps, accountAddress as AccountId);
  const profileId = hasExplicitProfileId
    ? explicitProfileId
    : toTrimmedString(resolved?.profileId || '');
  const chainIdKey = hasExplicitChainIdKey
    ? explicitChainIdKey
    : toTrimmedString(resolved?.chainIdKey || '').toLowerCase();
  if (!profileId || !chainIdKey) {
    throw new Error(
      `IndexedDBManager: Missing profile/account mapping for NEAR account "${accountAddress}". ` +
        'Persist profile/account first or pass explicit profileId + chainIdKey.',
    );
  }
  if (!chainIdKey.startsWith('near:')) {
    throw new Error(
      `IndexedDBManager: NEAR key writes require near:* chainIdKey, received "${chainIdKey}"`,
    );
  }

  if (hasExplicitProfileId && hasExplicitChainIdKey) {
    const mapped = await deps.clientDB
      .getProfileByAccount(chainIdKey, accountAddress)
      .catch(() => null);
    if (mapped?.profileId && String(mapped.profileId).trim() !== profileId) {
      throw new Error(
        `IndexedDBManager: Explicit key target (${profileId}, ${chainIdKey}, ${accountAddress}) mismatches mapped profile ${String(mapped.profileId).trim()}`,
      );
    }
  }

  const schemaVersion =
    Number.isSafeInteger(input.schemaVersion) &&
    typeof input.schemaVersion === 'number' &&
    input.schemaVersion >= 1
      ? input.schemaVersion
      : 1;

  await deps.nearKeysDB.storeKeyMaterial({
    profileId,
    deviceNumber: input.deviceNumber,
    chainIdKey,
    keyKind,
    algorithm,
    publicKey,
    ...(input.signerId ? { signerId: String(input.signerId).trim() } : {}),
    ...(input.wrapKeySalt ? { wrapKeySalt: String(input.wrapKeySalt).trim() } : {}),
    ...(input.payload ? { payload: input.payload } : {}),
    timestamp: typeof input.timestamp === 'number' ? input.timestamp : Date.now(),
    schemaVersion,
  });
}

export async function storeNearThresholdKeyMaterial(
  deps: NearKeyMaterialDeps,
  input: StoreNearThresholdKeyMaterialInput,
): Promise<void> {
  const relayerKeyId = toTrimmedString(input.relayerKeyId || '');
  const clientShareDerivation = toTrimmedString(
    input.clientShareDerivation || '',
  ) as ClientShareDerivation;
  if (!relayerKeyId || !clientShareDerivation) {
    throw new Error('IndexedDBManager: Missing threshold NEAR key fields for key write');
  }
  const participants =
    parseThresholdEd25519ParticipantsV1(input.participants) ||
    buildThresholdEd25519Participants2pV1({
      relayerKeyId,
      clientShareDerivation,
    });

  await storeNearKeyMaterial(deps, {
    nearAccountId: input.nearAccountId,
    deviceNumber: input.deviceNumber,
    keyKind: 'threshold_share_v1',
    publicKey: input.publicKey,
    signerId: input.signerId,
    ...(input.wrapKeySalt ? { wrapKeySalt: String(input.wrapKeySalt).trim() } : {}),
    payload: {
      relayerKeyId,
      clientShareDerivation,
      participants,
    },
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    profileId: input.profileId,
    chainIdKey: input.chainIdKey,
  });
}
