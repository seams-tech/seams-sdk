import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoOperationMaterial } from '@/core/signingEngine/interfaces/near';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '@shared/threshold/participants';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import {
  routerAbMpcMaterialActivationRefToWire,
  sameRouterAbMpcMaterialActivationRef,
} from '@shared/utils/routerAbNormalSigningIdentity';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../session/material/nearEd25519YaoMaterialActivation';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from './yaoPublicCapabilityReferences';

const MAX_ACTIVE_ED25519_YAO_CLIENTS = 64;

export type Ed25519YaoActiveClientIdentityV1 = {
  walletId: WalletId;
  nearAccountId: AccountId;
  materialActivation: MpcMaterialActivationRef;
};

export type Ed25519YaoActiveClientLookupScopeV1 = {
  walletId: WalletId;
  nearAccountId: AccountId;
};

export type Ed25519YaoActiveClientRegistryPort = {
  activate(material: NearEd25519YaoOperationMaterial): Promise<Ed25519YaoActiveClientIdentityV1>;
  resolve(identity: Ed25519YaoActiveClientIdentityV1): NearEd25519YaoOperationMaterial | null;
  resolveExact(
    identity: Ed25519YaoActiveClientIdentityV1,
  ): NearEd25519YaoOperationMaterial | null;
  resolveForWalletAccount(
    scope: Ed25519YaoActiveClientLookupScopeV1,
  ): NearEd25519YaoOperationMaterial | null;
  rollbackActivation(identity: Ed25519YaoActiveClientIdentityV1): Promise<boolean>;
  disposeWallet(walletId: WalletId): number;
  dispose(): void;
};

type ActiveClientEntryV1 = {
  identity: Ed25519YaoActiveClientIdentityV1;
  material: NearEd25519YaoOperationMaterial;
};

class VolatileOnlyPublicCapabilityReferenceStore implements Ed25519YaoPublicCapabilityReferenceStorePort {
  async upsert(
    _reference: Parameters<Ed25519YaoPublicCapabilityReferenceStorePort['upsert']>[0],
  ): Promise<void> {}

  async remove(_identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {}

  async list(): ReturnType<Ed25519YaoPublicCapabilityReferenceStorePort['list']> {
    return [];
  }

  async upsertLane(
    _reference: Parameters<Ed25519YaoPublicCapabilityReferenceStorePort['upsertLane']>[0],
  ): Promise<void> {}

  async removeLane(_identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {}

  async listLanes(): ReturnType<Ed25519YaoPublicCapabilityReferenceStorePort['listLanes']> {
    return [];
  }
}

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value ?? '').trim();
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function identityKey(identity: Ed25519YaoActiveClientIdentityV1): string {
  const activation = identity.materialActivation;
  return JSON.stringify([
    requireNonEmpty(identity.walletId, 'walletId'),
    requireNonEmpty(identity.nearAccountId, 'nearAccountId'),
    requireNonEmpty(activation.activationId, 'materialActivation.activationId'),
    requireNonEmpty(activation.capability, 'materialActivation.capability'),
    requireNonEmpty(activation.materialOwner, 'materialActivation.materialOwner'),
    requireNonEmpty(activation.keyBinding, 'materialActivation.keyBinding'),
    requireNonEmpty(activation.lifecycleBinding, 'materialActivation.lifecycleBinding'),
    requireNonEmpty(activation.signingWorker, 'materialActivation.signingWorker'),
  ]);
}

function materialIdentity(
  material: NearEd25519YaoOperationMaterial,
): Ed25519YaoActiveClientIdentityV1 {
  if (material.activeClient.status().kind !== 'active') {
    throw new Error('Ed25519 Yao active Client registry rejects disposed state');
  }
  const metadata = material.activeClient.metadata();
  const facts = material.facts;
  const signer = facts.signer;
  const walletId = signer.account.wallet.walletId;
  const nearAccountId = signer.account.nearAccountId;
  const thresholdSessionId = requireNonEmpty(
    facts.thresholdSessionId,
    'material.facts.thresholdSessionId',
  );
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  if (
    metadata.scope.threshold_session_id !== thresholdSessionId ||
    !sameRouterAbMpcMaterialActivationRef(
      metadata.scope.material_activation,
      routerAbMpcMaterialActivationRefToWire(materialActivation),
    ) ||
    metadata.scope.account_id !== String(walletId) ||
    metadata.applicationBinding.wallet_id !== String(walletId) ||
    metadata.applicationBinding.near_ed25519_signing_key_id !==
      String(signer.nearEd25519SigningKeyId) ||
    metadata.applicationBinding.signing_root_id !== facts.signingRootId ||
    metadata.scope.root_share_epoch !== facts.signingRootVersion ||
    metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot ||
    metadata.scope.signing_worker_id !== facts.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 Yao active Client registry subject identity mismatch');
  }
  if (
    metadata.participantIds[0] !== THRESHOLD_ED25519_2P_PARTICIPANT_IDS[0] ||
    metadata.participantIds[1] !== THRESHOLD_ED25519_2P_PARTICIPANT_IDS[1]
  ) {
    throw new Error('Ed25519 Yao active Client registry participant identity mismatch');
  }
  return {
    walletId,
    nearAccountId,
    materialActivation,
  };
}

function sameIdentity(
  left: Ed25519YaoActiveClientIdentityV1,
  right: Ed25519YaoActiveClientIdentityV1,
): boolean {
  return (
    String(left.walletId) === String(right.walletId) &&
    String(left.nearAccountId) === String(right.nearAccountId) &&
    mpcMaterialActivationRefsEqual(left.materialActivation, right.materialActivation)
  );
}

export class Ed25519YaoActiveClientRegistry implements Ed25519YaoActiveClientRegistryPort {
  private readonly entries = new Map<string, ActiveClientEntryV1>();
  private lifecycleGeneration = 0;

  constructor(
    private readonly publicReferences: Ed25519YaoPublicCapabilityReferenceStorePort = new VolatileOnlyPublicCapabilityReferenceStore(),
  ) {}

  async activate(
    material: NearEd25519YaoOperationMaterial,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    const identity = materialIdentity(material);
    const key = identityKey(identity);
    const lifecycleGeneration = this.lifecycleGeneration;
    for (const entry of this.entries.values()) {
      if (
        entry.material.activeClient === material.activeClient &&
        !sameIdentity(entry.identity, identity)
      ) {
        throw new Error('Ed25519 Yao active Client state is already bound to another identity');
      }
    }
    const current = this.entries.get(key);
    if (!current && this.entries.size >= MAX_ACTIVE_ED25519_YAO_CLIENTS) {
      throw new Error('Ed25519 Yao active Client registry capacity is exhausted');
    }
    await this.publicReferences.upsert({
      walletId: identity.walletId,
      nearAccountId: identity.nearAccountId,
      thresholdSessionId: material.facts.thresholdSessionId,
      runtimePolicyScope: material.facts.runtimePolicyScope,
      materialActivation: identity.materialActivation,
    });
    if (
      lifecycleGeneration !== this.lifecycleGeneration ||
      material.activeClient.status().kind !== 'active'
    ) {
      material.activeClient.dispose();
      await this.publicReferences.remove(identity);
      await this.publicReferences.removeLane(identity);
      throw new Error('Ed25519 Yao active Client activation was interrupted');
    }
    if (current && current.material.activeClient !== material.activeClient) {
      current.material.activeClient.dispose();
    }
    this.entries.set(key, { identity, material });
    return identity;
  }

  resolve(identity: Ed25519YaoActiveClientIdentityV1): NearEd25519YaoOperationMaterial | null {
    const key = identityKey(identity);
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.material.activeClient.status().kind === 'disposed') {
      this.entries.delete(key);
      return null;
    }
    return entry.material;
  }

  resolveExact(
    identity: Ed25519YaoActiveClientIdentityV1,
  ): NearEd25519YaoOperationMaterial | null {
    return this.resolve(identity);
  }

  resolveForWalletAccount(
    scope: Ed25519YaoActiveClientLookupScopeV1,
  ): NearEd25519YaoOperationMaterial | null {
    let match: NearEd25519YaoOperationMaterial | null = null;
    for (const entry of this.entries.values()) {
      if (
        String(entry.identity.walletId) !== String(scope.walletId) ||
        String(entry.identity.nearAccountId) !== String(scope.nearAccountId)
      ) {
        continue;
      }
      if (entry.material.activeClient.status().kind === 'disposed') continue;
      if (match) throw new Error('Ed25519 Yao active Client lookup scope is ambiguous');
      match = entry.material;
    }
    return match;
  }

  async rollbackActivation(identity: Ed25519YaoActiveClientIdentityV1): Promise<boolean> {
    this.lifecycleGeneration += 1;
    const key = identityKey(identity);
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      entry.material.activeClient.dispose();
    }
    await this.publicReferences.remove(identity);
    await this.publicReferences.removeLane(identity);
    return entry !== undefined;
  }

  disposeWallet(walletId: WalletId): number {
    this.lifecycleGeneration += 1;
    const expectedWalletId = requireNonEmpty(walletId, 'walletId');
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (String(entry.identity.walletId) !== expectedWalletId) continue;
      this.entries.delete(key);
      entry.material.activeClient.dispose();
      removed += 1;
    }
    return removed;
  }

  dispose(): void {
    this.lifecycleGeneration += 1;
    for (const entry of this.entries.values()) entry.material.activeClient.dispose();
    this.entries.clear();
  }
}
