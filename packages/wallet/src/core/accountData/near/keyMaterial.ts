import type { AccountId } from '../../types/accountIds';
import {
  buildThresholdEd25519Participants2pV1,
  parseThresholdEd25519ParticipantsV1,
  type ThresholdEd25519ParticipantV1,
} from '@shared/threshold/participants';
import { ensureEd25519Prefix, toTrimmedString } from '@shared/utils/validation';
import type { ThresholdEd25519KeyMaterial } from './nearAccountData.types';
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

function normalizeThresholdEd25519PublicKey(value: unknown): string {
  const publicKey = ensureEd25519Prefix(toTrimmedString(value || ''));
  return publicKey.startsWith('ed25519:') ? publicKey : '';
}

function canonicalThresholdEd25519RelayerKeyId(input: {
  publicKey: unknown;
  relayerKeyId: unknown;
}): string {
  const publicKey = normalizeThresholdEd25519PublicKey(input.publicKey);
  if (publicKey) {
    return publicKey;
  }
  const relayerKeyId = ensureEd25519Prefix(toTrimmedString(input.relayerKeyId || ''));
  return relayerKeyId.startsWith('ed25519:') ? relayerKeyId : '';
}

function canonicalThresholdEd25519RelayerParticipant(
  participant: ThresholdEd25519ParticipantV1,
  relayerKeyId: string,
): ThresholdEd25519ParticipantV1 {
  if (participant.role !== 'relayer') {
    return participant;
  }
  const canonical: ThresholdEd25519ParticipantV1 = {
    id: participant.id,
    role: 'relayer',
    relayerKeyId,
  };
  if (participant.relayerUrl) {
    canonical.relayerUrl = participant.relayerUrl;
  }
  if (participant.shareDerivation) {
    canonical.shareDerivation = participant.shareDerivation;
  }
  return canonical;
}

function buildCanonicalThresholdEd25519Participants(input: {
  participants: unknown;
  relayerKeyId: string;
}): ThresholdEd25519KeyMaterial['participants'] {
  const parsed = parseThresholdEd25519ParticipantsV1(input.participants);
  const hasRelayer = parsed?.some((participant) => participant.role === 'relayer') === true;
  if (!parsed || !hasRelayer) {
    return buildThresholdEd25519Participants2pV1({
      relayerKeyId: input.relayerKeyId,
      clientShareDerivation: 'prf_first_v1',
    });
  }
  return parsed.map((participant) =>
    canonicalThresholdEd25519RelayerParticipant(participant, input.relayerKeyId),
  );
}

function mapThresholdNearKey(
  nearAccountId: AccountId,
  signerSlot: number,
  rec: KeyMaterialRecord | null,
): ThresholdEd25519KeyMaterial | null {
  if (!rec) return null;
  const payload = (rec.payload || {}) as Record<string, unknown>;
  const publicKey = normalizeThresholdEd25519PublicKey(rec.publicKey);
  const relayerKeyId = canonicalThresholdEd25519RelayerKeyId({
    publicKey,
    relayerKeyId: payload.relayerKeyId,
  });
  const keyVersion = toTrimmedString(payload.keyVersion || '');
  if (!publicKey || !relayerKeyId || !keyVersion) {
    return null;
  }
  const participants = buildCanonicalThresholdEd25519Participants({
    participants: payload.participants,
    relayerKeyId,
  });
  return {
    nearAccountId,
    signerSlot,
    kind: 'threshold_ed25519_v1',
    publicKey,
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
  const publicKey = normalizeThresholdEd25519PublicKey(input.publicKey);
  if (!publicKey) {
    throw new Error('IndexedDBManager: Missing Ed25519 publicKey for threshold key write');
  }
  const relayerKeyId = canonicalThresholdEd25519RelayerKeyId({
    publicKey,
    relayerKeyId: input.relayerKeyId,
  });
  const keyVersion = toTrimmedString(input.keyVersion || '');
  if (!relayerKeyId || !keyVersion) {
    throw new Error('IndexedDBManager: Missing threshold Ed25519 relayer metadata for key write');
  }
  const participants = buildCanonicalThresholdEd25519Participants({
    participants: input.participants,
    relayerKeyId,
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
      publicKey,
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
    publicKey,
    signerId: input.signerId,
    payload,
  };
  applyOptionalNearThresholdFields(mappedInput, input);
  await storeNearKeyMaterial(deps, mappedInput);
}
