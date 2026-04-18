import type { AccountId } from '../../types/accountIds';
import {
  buildThresholdEd25519Participants2pV1,
  parseThresholdEd25519ParticipantsV1,
} from '@shared/threshold/participants';
import { toTrimmedString } from '@shared/utils/validation';
import type { PasskeyClientDBManager } from '../../indexedDB/passkeyClientDB/manager';
import type { AccountKeyMaterialDBManager } from '../../indexedDB/accountKeyMaterialDB/manager';
import type { ThresholdEd25519KeyMaterial } from './types';
import type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialRecord,
} from '../../indexedDB/accountKeyMaterialDB.types';
import { getAccountKeyMaterial, storeAccountKeyMaterial } from '../../indexedDB/accountKeyMaterial';
import { buildNearAccountRefs } from './accountRefs';

export interface NearKeyMaterialDeps {
  clientDB: Pick<PasskeyClientDBManager, 'resolveProfileAccountContext'>;
  accountKeyMaterialDB: Pick<AccountKeyMaterialDBManager, 'getKeyMaterial' | 'storeKeyMaterial'>;
}

export interface StoreNearKeyMaterialInput {
  nearAccountId: AccountId;
  signerSlot: number;
  keyKind: KeyMaterialKind;
  algorithm?: KeyMaterialAlgorithm;
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
  signerSlot: number;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participants?: ThresholdEd25519KeyMaterial['participants'];
  signerId?: string;
  timestamp?: number;
  schemaVersion?: number;
  profileId?: string;
  chainIdKey?: string;
}

function mapThresholdNearKey(
  nearAccountId: AccountId,
  signerSlot: number,
  rec: KeyMaterialRecord | null,
): ThresholdEd25519KeyMaterial | null {
  if (!rec) return null;
  const payload = (rec.payload || {}) as Record<string, unknown>;
  const relayerKeyId = toTrimmedString(payload.relayerKeyId || '');
  const keyVersion = toTrimmedString(payload.keyVersion || '');
  if (!relayerKeyId || !keyVersion) {
    return null;
  }
  const participants =
    parseThresholdEd25519ParticipantsV1(payload.participants) ||
    buildThresholdEd25519Participants2pV1({
      relayerKeyId,
      clientShareDerivation: 'prf_first_v1',
    });
  return {
    nearAccountId,
    signerSlot,
    kind: 'threshold_ed25519_v1',
    publicKey: rec.publicKey,
    relayerKeyId,
    keyVersion,
    participants,
    timestamp: rec.timestamp,
  };
}

export async function getNearThresholdKeyMaterial(
  deps: NearKeyMaterialDeps,
  nearAccountId: AccountId,
  signerSlot: number,
): Promise<ThresholdEd25519KeyMaterial | null> {
  const keyRecord = await getAccountKeyMaterial({
    deps,
    accountRefs: buildNearAccountRefs(nearAccountId),
    signerSlot,
    keyKind: 'threshold_share_v1',
  });
  return mapThresholdNearKey(nearAccountId, signerSlot, keyRecord);
}

export async function storeNearKeyMaterial(
  deps: NearKeyMaterialDeps,
  input: StoreNearKeyMaterialInput,
): Promise<void> {
  const accountAddress = toTrimmedString(input.nearAccountId || '').toLowerCase();
  if (!accountAddress) {
    throw new Error('IndexedDBManager: Missing nearAccountId for key write');
  }
  if (!Number.isSafeInteger(input.signerSlot) || input.signerSlot < 1) {
    throw new Error('IndexedDBManager: Invalid signerSlot for key write');
  }
  const keyKind = toTrimmedString(input.keyKind || '');
  if (!keyKind) {
    throw new Error('IndexedDBManager: Missing keyKind for key write');
  }
  const algorithm = String(input.algorithm || 'ed25519')
    .trim()
    .toLowerCase();
  const publicKey = toTrimmedString(input.publicKey || '');
  if (!publicKey) {
    throw new Error('IndexedDBManager: Missing publicKey for key write');
  }

  const explicitChainIdKey = toTrimmedString(input.chainIdKey || '').toLowerCase();

  await storeAccountKeyMaterial(deps, {
    accountRefs: buildNearAccountRefs(accountAddress as AccountId),
    signerSlot: input.signerSlot,
    keyKind,
    algorithm,
    publicKey,
    ...(input.signerId ? { signerId: input.signerId } : {}),
    ...(input.wrapKeySalt ? { wrapKeySalt: input.wrapKeySalt } : {}),
    ...(input.payload ? { payload: input.payload } : {}),
    ...(typeof input.timestamp === 'number' ? { timestamp: input.timestamp } : {}),
    ...(typeof input.schemaVersion === 'number' ? { schemaVersion: input.schemaVersion } : {}),
    ...(input.profileId ? { explicitProfileId: input.profileId } : {}),
    ...(explicitChainIdKey ? { explicitChainIdKey } : {}),
  });
}

export async function storeNearThresholdKeyMaterial(
  deps: NearKeyMaterialDeps,
  input: StoreNearThresholdKeyMaterialInput,
): Promise<void> {
  const relayerKeyId = toTrimmedString(input.relayerKeyId || '');
  const keyVersion = toTrimmedString(input.keyVersion || '');
  const participants =
    parseThresholdEd25519ParticipantsV1(input.participants) ||
    buildThresholdEd25519Participants2pV1({
      relayerKeyId,
      clientShareDerivation: 'prf_first_v1',
    });

  await storeNearKeyMaterial(deps, {
    nearAccountId: input.nearAccountId,
    signerSlot: input.signerSlot,
    keyKind: 'threshold_share_v1',
    publicKey: input.publicKey,
    signerId: input.signerId,
    payload: {
      relayerKeyId,
      keyVersion,
      participants,
    },
    timestamp: input.timestamp,
    schemaVersion: input.schemaVersion,
    profileId: input.profileId,
    chainIdKey: input.chainIdKey,
  });
}
