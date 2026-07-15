import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { UnifiedIndexedDBManager } from '@/core/indexedDB/unifiedIndexedDBManager';
import type { Ed25519YaoActiveClientIdentityV1 } from './yaoActiveClientRegistry';

export const ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1 =
  'ed25519_yao_public_capability_references_v1' as const;

const ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY =
  'ed25519YaoPublicCapabilityReferencesV1';
const MAX_PUBLIC_CAPABILITY_REFERENCES = 64;

export type Ed25519YaoPublicCapabilityReferencesV1 = {
  kind: typeof ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1;
  identities: readonly Ed25519YaoActiveClientIdentityV1[];
};

export type Ed25519YaoPublicCapabilityReferenceStorePort = {
  upsert(identity: Ed25519YaoActiveClientIdentityV1): Promise<void>;
  remove(identity: Ed25519YaoActiveClientIdentityV1): Promise<void>;
  list(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]>;
};

type AppStatePort = Pick<
  UnifiedIndexedDBManager,
  'getAppState' | 'setAppState' | 'isDisabled'
>;

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

function parsePublicCapabilityIdentity(
  value: unknown,
  label: string,
): Ed25519YaoActiveClientIdentityV1 {
  const record = requireRecord(value, label);
  requireExactKeys(record, ['walletId', 'nearAccountId', 'thresholdSessionId'], label);
  return {
    walletId: toWalletId(requireNonEmptyString(record.walletId, `${label}.walletId`)),
    nearAccountId: toAccountId(
      requireNonEmptyString(record.nearAccountId, `${label}.nearAccountId`),
    ),
    thresholdSessionId: requireNonEmptyString(
      record.thresholdSessionId,
      `${label}.thresholdSessionId`,
    ),
  };
}

export function parseEd25519YaoPublicCapabilityReferencesV1(
  value: unknown,
): Ed25519YaoPublicCapabilityReferencesV1 {
  const record = requireRecord(value, 'Ed25519 Yao public capability references');
  requireExactKeys(
    record,
    ['kind', 'identities'],
    'Ed25519 Yao public capability references',
  );
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

function emptyPublicCapabilityReferences(): Ed25519YaoPublicCapabilityReferencesV1 {
  return {
    kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
    identities: [],
  };
}

function publicCapabilityIdentityKey(identity: Ed25519YaoActiveClientIdentityV1): string {
  return JSON.stringify([
    String(identity.walletId),
    String(identity.nearAccountId),
    identity.thresholdSessionId,
  ]);
}

function clonePublicCapabilityIdentity(
  identity: Ed25519YaoActiveClientIdentityV1,
): Ed25519YaoActiveClientIdentityV1 {
  return parsePublicCapabilityIdentity(identity, 'Ed25519 Yao public capability identity');
}

export class IndexedDbEd25519YaoPublicCapabilityReferenceStore
  implements Ed25519YaoPublicCapabilityReferenceStorePort
{
  constructor(private readonly appState: AppStatePort) {}

  private async readProjection(): Promise<Ed25519YaoPublicCapabilityReferencesV1> {
    if (this.appState.isDisabled()) return emptyPublicCapabilityReferences();
    const raw = await this.appState.getAppState<unknown>(
      ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY,
    );
    if (raw === undefined || raw === null) return emptyPublicCapabilityReferences();
    return parseEd25519YaoPublicCapabilityReferencesV1(raw);
  }

  private async writeProjection(
    projection: Ed25519YaoPublicCapabilityReferencesV1,
  ): Promise<void> {
    if (this.appState.isDisabled()) return;
    await this.appState.setAppState(
      ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_APP_STATE_KEY,
      parseEd25519YaoPublicCapabilityReferencesV1(projection),
    );
  }

  async upsert(identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {
    const normalized = clonePublicCapabilityIdentity(identity);
    const current = await this.readProjection();
    const key = publicCapabilityIdentityKey(normalized);
    const identities = current.identities.filter(
      (candidate) => publicCapabilityIdentityKey(candidate) !== key,
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
    const key = publicCapabilityIdentityKey(clonePublicCapabilityIdentity(identity));
    const current = await this.readProjection();
    await this.writeProjection({
      kind: ED25519_YAO_PUBLIC_CAPABILITY_REFERENCES_KIND_V1,
      identities: current.identities.filter(
        (candidate) => publicCapabilityIdentityKey(candidate) !== key,
      ),
    });
  }

  async list(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]> {
    const current = await this.readProjection();
    return current.identities.map(clonePublicCapabilityIdentity);
  }
}
