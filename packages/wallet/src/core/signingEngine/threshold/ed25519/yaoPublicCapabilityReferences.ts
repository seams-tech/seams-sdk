import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  parseMpcMaterialActivationRef,
  parseThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type { Ed25519YaoActiveClientIdentityV1 } from './yaoActiveClientRegistry';
import type { ThresholdEd25519SessionId } from '../../session/operationState/types';
import { normalizeThresholdRuntimePolicyScope } from '../sessionPolicy';
import type { ThresholdRuntimePolicyScope } from '../sessionPolicy';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { SigningLaneAuthBinding } from '../../session/identity/signingLaneAuthBinding';

export const ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1 =
  'ed25519_yao_public_capability_references_v1' as const;
export const ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1 =
  'ed25519_yao_public_capability_lanes_v1' as const;

const ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY =
  'ed25519YaoPublicCapabilityReferencesV1';
const ED25519_YAO_PUBLIC_CAPABILITY_LANES_APP_STATE_KEY =
  'ed25519YaoPublicCapabilityLanesV1';
const MAX_PUBLIC_CAPABILITY_REFERENCES = 64;
const MAX_PUBLIC_CAPABILITY_LANES = 64;

export type Ed25519YaoPublicCapabilityReferenceV1 = Ed25519YaoActiveClientIdentityV1 & {
  thresholdSessionId: ThresholdEd25519SessionId;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

type Ed25519YaoPublicCapabilityLaneReferenceBaseV1 = Ed25519YaoPublicCapabilityReferenceV1 & {
  nearEd25519SigningKeyId: ReturnType<typeof nearEd25519SigningKeyIdFromString>;
  signerSlot: number;
};

export type Ed25519YaoPublicCapabilityLaneReferenceV1 =
  Ed25519YaoPublicCapabilityLaneReferenceBaseV1 &
    (
      | {
          auth: Extract<SigningLaneAuthBinding, { kind: 'email_otp' }>;
          remainingUses: number;
          expiresAtMs: number;
        }
      | {
          auth: Extract<SigningLaneAuthBinding, { kind: 'passkey' }>;
          remainingUses?: never;
          expiresAtMs?: never;
        }
    );

export type Ed25519YaoPublicCapabilityReferencesV1 = {
  kind: typeof ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1;
  identities: readonly Ed25519YaoPublicCapabilityReferenceV1[];
};

export type Ed25519YaoPublicCapabilityLanesV1 = {
  kind: typeof ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1;
  lanes: readonly Ed25519YaoPublicCapabilityLaneReferenceV1[];
};

export type Ed25519YaoPublicCapabilityReferenceStorePort = {
  upsert(reference: Ed25519YaoPublicCapabilityReferenceV1): Promise<void>;
  remove(identity: Ed25519YaoActiveClientIdentityV1): Promise<void>;
  list(): Promise<readonly Ed25519YaoPublicCapabilityReferenceV1[]>;
  upsertLane(reference: Ed25519YaoPublicCapabilityLaneReferenceV1): Promise<void>;
  removeLane(identity: Ed25519YaoActiveClientIdentityV1): Promise<void>;
  listLanes(): Promise<readonly Ed25519YaoPublicCapabilityLaneReferenceV1[]>;
};

export type Ed25519YaoPublicCapabilityLaneReferenceStorePort = Pick<
  Ed25519YaoPublicCapabilityReferenceStorePort,
  'upsertLane' | 'removeLane' | 'listLanes'
>;

/**
 * Publish the durable identity and its auth lane from one canonical material
 * reference. Cold recovery reads the identity projection, while warm signing
 * reads the lane projection; both must describe the same activation.
 */
export async function publishEd25519YaoPublicCapabilityReferenceAndLane(
  store: Ed25519YaoPublicCapabilityReferenceStorePort,
  reference: Ed25519YaoPublicCapabilityLaneReferenceV1,
): Promise<void> {
  const identity: Ed25519YaoPublicCapabilityReferenceV1 = {
    walletId: reference.walletId,
    nearAccountId: reference.nearAccountId,
    thresholdSessionId: reference.thresholdSessionId,
    runtimePolicyScope: reference.runtimePolicyScope,
    materialActivation: reference.materialActivation,
  };
  await store.upsert(identity);
  await store.upsertLane(reference);
}

type AppStatePort = {
  isDisabled(): boolean;
  getAppState<T = unknown>(key: string): Promise<T | undefined>;
  setAppState<T = unknown>(key: string, value: T): Promise<void>;
};

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(
  record: Record<string, unknown>,
  expectedKeys: readonly string[],
  label: string,
): void {
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains unexpected fields`);
  }
}

function requireNonEmptyString(value: unknown, label: string): string {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} must be a non-empty normalized string`);
  }
  return value;
}

function requireNonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}

function requirePositiveInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function parseSigningLaneAuth(value: unknown, label: string): SigningLaneAuthBinding {
  const record = requireRecord(value, label);
  const kind = requireNonEmptyString(record.kind, `${label}.kind`);
  switch (kind) {
    case 'passkey': {
      requireExactKeys(record, ['kind', 'rpId', 'credentialIdB64u'], label);
      const rpId = toRpId(requireNonEmptyString(record.rpId, `${label}.rpId`));
      const credentialIdB64u = requireNonEmptyString(
        record.credentialIdB64u,
        `${label}.credentialIdB64u`,
      );
      return { kind, rpId, credentialIdB64u };
    }
    case 'email_otp': {
      requireExactKeys(record, ['kind', 'providerSubjectId'], label);
      return {
        kind,
        providerSubjectId: requireNonEmptyString(
          record.providerSubjectId,
          `${label}.providerSubjectId`,
        ),
      };
    }
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

function parsePublicCapabilityIdentity(
  value: unknown,
  label: string,
): Ed25519YaoPublicCapabilityReferenceV1 {
  const record = requireRecord(value, label);
  requireExactKeys(
    record,
    ['walletId', 'nearAccountId', 'thresholdSessionId', 'runtimePolicyScope', 'materialActivation'],
    label,
  );
  const materialActivation = parseMpcMaterialActivationRef(record.materialActivation);
  if (!materialActivation.ok) {
    throw new Error(`${label}.materialActivation is invalid: ${materialActivation.error.message}`);
  }
  const thresholdSessionId = parseThresholdEd25519SessionId(record.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error(`${label}.thresholdSessionId is invalid`);
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(record.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${label}.runtimePolicyScope is invalid`);
  }
  return {
    walletId: toWalletId(requireNonEmptyString(record.walletId, `${label}.walletId`)),
    nearAccountId: toAccountId(
      requireNonEmptyString(record.nearAccountId, `${label}.nearAccountId`),
    ),
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope,
    materialActivation: materialActivation.value,
  };
}

function parsePublicCapabilityLane(
  value: unknown,
  label: string,
): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  const record = requireRecord(value, label);
  const auth = parseSigningLaneAuth(record.auth, `${label}.auth`);
  requireExactKeys(
    record,
    [
      'walletId',
      'nearAccountId',
      'thresholdSessionId',
      'runtimePolicyScope',
      'materialActivation',
      'auth',
      'nearEd25519SigningKeyId',
      'signerSlot',
      ...(auth.kind === 'email_otp' ? ['remainingUses', 'expiresAtMs'] : []),
    ],
    label,
  );
  const base = parsePublicCapabilityIdentity(
    {
      walletId: record.walletId,
      nearAccountId: record.nearAccountId,
      thresholdSessionId: record.thresholdSessionId,
      runtimePolicyScope: record.runtimePolicyScope,
      materialActivation: record.materialActivation,
    },
    label,
  );
  const signerSlot = parseSignerSlot(record.signerSlot);
  if (signerSlot === null) {
    throw new Error(`${label}.signerSlot is invalid`);
  }
  const common = {
    ...base,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      requireNonEmptyString(record.nearEd25519SigningKeyId, `${label}.nearEd25519SigningKeyId`),
    ),
    signerSlot,
  };
  switch (auth.kind) {
    case 'email_otp':
      return {
        ...common,
        auth,
        remainingUses: requireNonNegativeInteger(record.remainingUses, `${label}.remainingUses`),
        expiresAtMs: requirePositiveInteger(record.expiresAtMs, `${label}.expiresAtMs`),
      };
    case 'passkey':
      return { ...common, auth };
    default:
      auth satisfies never;
      throw new Error(`${label}.auth is invalid`);
  }
}

export function parseEd25519YaoPublicCapabilityReferencesV1(
  value: unknown,
): Ed25519YaoPublicCapabilityReferencesV1 {
  const record = requireRecord(value, 'Ed25519 Yao public capability references');
  requireExactKeys(record, ['kind', 'identities'], 'Ed25519 Yao public capability references');
  if (record.kind !== ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1) {
    throw new Error('Ed25519 Yao public capability references kind is invalid');
  }
  if (!Array.isArray(record.identities)) {
    throw new Error('Ed25519 Yao public capability identities must be an array');
  }
  if (record.identities.length > MAX_PUBLIC_CAPABILITY_REFERENCES) {
    throw new Error('Ed25519 Yao public capability reference capacity is exceeded');
  }
  const identities = record.identities.map((identity, index) =>
    parsePublicCapabilityIdentity(identity, `Ed25519 Yao public capability identity ${index}`),
  );
  const uniqueKeys = new Set(identities.map(publicCapabilityIdentityKey));
  if (uniqueKeys.size !== identities.length) {
    throw new Error('Ed25519 Yao public capability references contain duplicate identities');
  }
  return {
    kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
    identities,
  };
}

export function parseEd25519YaoPublicCapabilityLanesV1(
  value: unknown,
): Ed25519YaoPublicCapabilityLanesV1 {
  const record = requireRecord(value, 'Ed25519 Yao public capability lanes');
  requireExactKeys(record, ['kind', 'lanes'], 'Ed25519 Yao public capability lanes');
  if (record.kind !== ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1) {
    throw new Error('Ed25519 Yao public capability lanes kind is invalid');
  }
  if (!Array.isArray(record.lanes)) {
    throw new Error('Ed25519 Yao public capability lanes must be an array');
  }
  if (record.lanes.length > MAX_PUBLIC_CAPABILITY_LANES) {
    throw new Error('Ed25519 Yao public capability lane capacity is exceeded');
  }
  const lanes = record.lanes.map((lane, index) =>
    parsePublicCapabilityLane(lane, `Ed25519 Yao public capability lane ${index}`),
  );
  const uniqueKeys = new Set(lanes.map(publicCapabilityIdentityKey));
  if (uniqueKeys.size !== lanes.length) {
    throw new Error('Ed25519 Yao public capability lanes contain duplicate identities');
  }
  return { kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1, lanes };
}

function emptyPublicCapabilityReferences(): Ed25519YaoPublicCapabilityReferencesV1 {
  return {
    kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
    identities: [],
  };
}

function emptyPublicCapabilityLanes(): Ed25519YaoPublicCapabilityLanesV1 {
  return {
    kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
    lanes: [],
  };
}

function publicCapabilityIdentityKey(identity: Ed25519YaoActiveClientIdentityV1): string {
  const activation = identity.materialActivation;
  return JSON.stringify([
    String(identity.walletId),
    String(identity.nearAccountId),
    activation.activationId,
    activation.capability,
    activation.materialOwner,
    activation.keyBinding,
    activation.lifecycleBinding,
    activation.signingWorker,
  ]);
}

function clonePublicCapabilityIdentity(
  identity: Ed25519YaoPublicCapabilityReferenceV1,
): Ed25519YaoPublicCapabilityReferenceV1 {
  return parsePublicCapabilityIdentity(identity, 'Ed25519 Yao public capability identity');
}

function clonePublicCapabilityLane(
  lane: Ed25519YaoPublicCapabilityLaneReferenceV1,
): Ed25519YaoPublicCapabilityLaneReferenceV1 {
  return parsePublicCapabilityLane(lane, 'Ed25519 Yao public capability lane');
}

export class IndexedDbEd25519YaoPublicCapabilityReferenceStore implements Ed25519YaoPublicCapabilityReferenceStorePort {
  constructor(private readonly appState: AppStatePort) {}

  private async readProjection(): Promise<Ed25519YaoPublicCapabilityReferencesV1> {
    if (this.appState.isDisabled()) return emptyPublicCapabilityReferences();
    const raw = await this.appState.getAppState<unknown>(
      ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY,
    );
    if (raw === undefined || raw === null) return emptyPublicCapabilityReferences();
    return parseEd25519YaoPublicCapabilityReferencesV1(raw);
  }

  private async writeProjection(projection: Ed25519YaoPublicCapabilityReferencesV1): Promise<void> {
    if (this.appState.isDisabled()) return;
    await this.appState.setAppState(
      ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY,
      parseEd25519YaoPublicCapabilityReferencesV1(projection),
    );
  }

  private async readLaneProjection(): Promise<Ed25519YaoPublicCapabilityLanesV1> {
    if (this.appState.isDisabled()) return emptyPublicCapabilityLanes();
    const raw = await this.appState.getAppState<unknown>(
      ED25519_YAO_PUBLIC_CAPABILITY_LANES_APP_STATE_KEY,
    );
    if (raw === undefined || raw === null) return emptyPublicCapabilityLanes();
    return parseEd25519YaoPublicCapabilityLanesV1(raw);
  }

  private async writeLaneProjection(
    projection: Ed25519YaoPublicCapabilityLanesV1,
  ): Promise<void> {
    if (this.appState.isDisabled()) return;
    await this.appState.setAppState(
      ED25519_YAO_PUBLIC_CAPABILITY_LANES_APP_STATE_KEY,
      parseEd25519YaoPublicCapabilityLanesV1(projection),
    );
  }

  async upsert(identity: Ed25519YaoPublicCapabilityReferenceV1): Promise<void> {
    const normalized = clonePublicCapabilityIdentity(identity);
    const current = await this.readProjection();
    const identities = current.identities.filter(
      (candidate) =>
        String(candidate.walletId) !== String(normalized.walletId) ||
        String(candidate.nearAccountId) !== String(normalized.nearAccountId),
    );
    if (identities.length >= MAX_PUBLIC_CAPABILITY_REFERENCES) {
      throw new Error('Ed25519 Yao public capability reference capacity is exhausted');
    }
    await this.writeProjection({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
      identities: [...identities, normalized],
    });
  }

  async remove(identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {
    const key = publicCapabilityIdentityKey(identity);
    const current = await this.readProjection();
    await this.writeProjection({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
      identities: current.identities.filter(
        (candidate) => publicCapabilityIdentityKey(candidate) !== key,
      ),
    });
  }

  async list(): Promise<readonly Ed25519YaoPublicCapabilityReferenceV1[]> {
    const current = await this.readProjection();
    return current.identities.map(clonePublicCapabilityIdentity);
  }

  async upsertLane(reference: Ed25519YaoPublicCapabilityLaneReferenceV1): Promise<void> {
    const normalized = clonePublicCapabilityLane(reference);
    const current = await this.readLaneProjection();
    const lanes = current.lanes.filter(
      (candidate) =>
        String(candidate.walletId) !== String(normalized.walletId) ||
        String(candidate.nearAccountId) !== String(normalized.nearAccountId),
    );
    if (lanes.length >= MAX_PUBLIC_CAPABILITY_LANES) {
      throw new Error('Ed25519 Yao public capability lane capacity is exhausted');
    }
    await this.writeLaneProjection({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
      lanes: [...lanes, normalized],
    });
  }

  async removeLane(identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {
    const key = publicCapabilityIdentityKey(identity);
    const current = await this.readLaneProjection();
    await this.writeLaneProjection({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_LANES_KIND_V1,
      lanes: current.lanes.filter(
        (candidate) => publicCapabilityIdentityKey(candidate) !== key,
      ),
    });
  }

  async listLanes(): Promise<readonly Ed25519YaoPublicCapabilityLaneReferenceV1[]> {
    const current = await this.readLaneProjection();
    return current.lanes.map(clonePublicCapabilityLane);
  }
}

/**
 * The verified Email OTP provider subject this installation persisted on its
 * own Ed25519 lanes. A linked installation holds no local factor record to
 * carry that subject — the record belongs to registration — so the owner lane
 * scope reads it here. Exactly one subject may answer for a wallet: two would
 * mean two provider identities on one installation, which is an integrity
 * failure rather than a value to choose between.
 */
export async function readEmailOtpProviderSubjectForWalletV1(
  appState: AppStatePort,
  walletIdInput: string,
): Promise<string | null> {
  const walletId = String(walletIdInput || '').trim();
  if (!walletId) return null;
  const subjects = new Set<string>();
  for (const lane of await new IndexedDbEd25519YaoPublicCapabilityReferenceStore(
    appState,
  ).listLanes()) {
    if (lane.auth.kind !== 'email_otp') continue;
    if (String(lane.walletId) !== walletId) continue;
    const providerSubjectId = String(lane.auth.providerSubjectId || '').trim();
    if (providerSubjectId) subjects.add(providerSubjectId);
  }
  if (subjects.size !== 1) return null;
  return [...subjects][0] ?? null;
}
