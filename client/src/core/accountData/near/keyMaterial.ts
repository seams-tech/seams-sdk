import type { AccountId } from '../../types/accountIds';
import {
  buildThresholdEd25519Participants2pV1,
  parseThresholdEd25519ParticipantsV1,
} from '@shared/threshold/participants';
import { toTrimmedString } from '@shared/utils/validation';
import type { ThresholdEd25519KeyMaterial } from './types';
import type {
  KeyMaterialAlgorithm,
  KeyMaterialKind,
  KeyMaterialRecord,
} from '../../indexedDB/keyMaterial.types';
import {
  getAccountKeyMaterial,
  storeAccountKeyMaterial,
  type AccountKeyMaterialStorePort,
  type StoreAccountKeyMaterialInput,
} from '../../indexedDB/accountKeyMaterial';
import type { ProfileAccountContextPort } from '../../indexedDB/profileAccountProjection';
import { buildNearAccountRefs } from './accountRefs';

export interface NearKeyMaterialDeps {
  clientDB: ProfileAccountContextPort;
  keyMaterialStore: AccountKeyMaterialStorePort;
}

type StoreNearKeyMaterialTarget =
  | {
      profileId?: never;
      chainIdKey?: never;
    }
  | {
      profileId: string;
      chainIdKey: string;
    };

type StoreNearKeyMaterialInputBase = {
  nearAccountId: AccountId;
  signerSlot: number;
  keyKind: KeyMaterialKind;
  algorithm?: KeyMaterialAlgorithm;
  publicKey: string;
  signerId: string;
  wrapKeySalt?: string;
  payload?: Record<string, unknown>;
  timestamp?: number;
  schemaVersion?: number;
};

export type StoreNearKeyMaterialInput = StoreNearKeyMaterialInputBase & StoreNearKeyMaterialTarget;

type StoreNearThresholdKeyMaterialInputBase = {
  nearAccountId: AccountId;
  signerSlot: number;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  participants?: ThresholdEd25519KeyMaterial['participants'];
  signerId: string;
  timestamp?: number;
  schemaVersion?: number;
};

export type StoreNearThresholdKeyMaterialInput = StoreNearThresholdKeyMaterialInputBase &
  StoreNearKeyMaterialTarget;

function applyOptionalNearKeyMaterialFields(
  target: StoreAccountKeyMaterialInput,
  input: StoreNearKeyMaterialInput,
): void {
  if (input.wrapKeySalt) {
    target.wrapKeySalt = input.wrapKeySalt;
  }
  if (input.payload) {
    target.payload = input.payload;
  }
  if (typeof input.timestamp === 'number') {
    target.timestamp = input.timestamp;
  }
  if (typeof input.schemaVersion === 'number') {
    target.schemaVersion = input.schemaVersion;
  }
}

function applyOptionalNearThresholdFields(
  target: StoreNearKeyMaterialInput,
  input: StoreNearThresholdKeyMaterialInput,
): void {
  if (typeof input.timestamp === 'number') {
    target.timestamp = input.timestamp;
  }
  if (typeof input.schemaVersion === 'number') {
    target.schemaVersion = input.schemaVersion;
  }
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
  const signerId = toTrimmedString(input.signerId || '');
  if (!signerId) {
    throw new Error('IndexedDBManager: Missing signerId for key write');
  }

  const explicitChainIdKey = toTrimmedString(input.chainIdKey || '').toLowerCase();
  const explicitProfileId = toTrimmedString(input.profileId || '');
  const accountRefs = buildNearAccountRefs(accountAddress as AccountId);

  if (explicitProfileId || explicitChainIdKey) {
    if (!explicitProfileId || !explicitChainIdKey) {
      throw new Error(
        'IndexedDBManager: profileId and chainIdKey are required together for explicit NEAR key material writes',
      );
    }
    const explicitInput: StoreAccountKeyMaterialInput = {
      accountRefs,
      signerSlot: input.signerSlot,
      keyKind,
      algorithm,
      publicKey,
      signerId,
      explicitProfileId,
      explicitChainIdKey,
      explicitAccountAddress: accountAddress,
    };
    applyOptionalNearKeyMaterialFields(explicitInput, input);
    await storeAccountKeyMaterial(deps, explicitInput);
    return;
  }

  const mappedInput: StoreAccountKeyMaterialInput = {
    accountRefs,
    signerSlot: input.signerSlot,
    keyKind,
    algorithm,
    publicKey,
    signerId,
  };
  applyOptionalNearKeyMaterialFields(mappedInput, input);
  await storeAccountKeyMaterial(deps, mappedInput);
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

  const payload = {
    relayerKeyId,
    keyVersion,
    participants,
  };
  const profileId = toTrimmedString(input.profileId || '');
  const chainIdKey = toTrimmedString(input.chainIdKey || '').toLowerCase();
  if (profileId || chainIdKey) {
    if (!profileId || !chainIdKey) {
      throw new Error(
        'IndexedDBManager: profileId and chainIdKey are required together for explicit NEAR threshold key writes',
      );
    }
    const explicitInput: StoreNearKeyMaterialInput = {
      nearAccountId: input.nearAccountId,
      signerSlot: input.signerSlot,
      keyKind: 'threshold_share_v1',
      publicKey: input.publicKey,
      signerId: input.signerId,
      payload,
      profileId,
      chainIdKey,
    };
    applyOptionalNearThresholdFields(explicitInput, input);
    await storeNearKeyMaterial(deps, explicitInput);
    return;
  }
  const mappedInput: StoreNearKeyMaterialInput = {
    nearAccountId: input.nearAccountId,
    signerSlot: input.signerSlot,
    keyKind: 'threshold_share_v1',
    publicKey: input.publicKey,
    signerId: input.signerId,
    payload,
  };
  applyOptionalNearThresholdFields(mappedInput, input);
  await storeNearKeyMaterial(deps, mappedInput);
}
