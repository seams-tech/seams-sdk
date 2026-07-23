import type { AccountId } from '@/core/types/accountIds';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { exactSigningLaneIdentityKey } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { THRESHOLD_ED25519_2P_PARTICIPANT_IDS } from '@shared/threshold/participants';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from './yaoPublicCapabilityReferences';

const MAX_ACTIVE_ED25519_YAO_CLIENTS = 64;

export type Ed25519YaoActiveClientIdentityV1 = {
  walletId: WalletId;
  nearAccountId: AccountId;
  thresholdSessionId: string;
};

export type Ed25519YaoActiveClientRegistryPort = {
  activate(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1>;
  resolve(identity: Ed25519YaoActiveClientIdentityV1): NearEd25519YaoSigningCapability | null;
  refreshWalletSession(
    input: Ed25519YaoSameIdentityWalletSessionRefreshV1,
  ): Ed25519YaoSameIdentityWalletSessionRefreshResultV1;
  rollbackActivation(identity: Ed25519YaoActiveClientIdentityV1): Promise<boolean>;
  disposeWallet(walletId: WalletId): number;
  dispose(): void;
};

export type Ed25519YaoSameIdentityWalletSessionRefreshV1 = {
  kind: 'same_identity_wallet_session_refresh_v1';
  identity: Ed25519YaoActiveClientIdentityV1;
  signingGrantId: string;
  nextWalletSessionState: NearEd25519YaoSigningCapability['walletSessionState'];
};

export type Ed25519YaoSameIdentityWalletSessionRefreshResultV1 =
  | {
      ok: true;
      identity: Ed25519YaoActiveClientIdentityV1;
      capability: NearEd25519YaoSigningCapability;
    }
  | {
      ok: false;
      code: 'source_missing' | 'source_disposed' | 'stable_binding_mismatch';
      message: string;
    };

type ActiveClientEntryV1 = {
  identity: Ed25519YaoActiveClientIdentityV1;
  capability: NearEd25519YaoSigningCapability;
};

class VolatileOnlyPublicCapabilityReferenceStore
  implements Ed25519YaoPublicCapabilityReferenceStorePort
{
  async upsert(_identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {}

  async remove(_identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {}

  async list(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]> {
    return [];
  }
}

function requireNonEmpty(value: unknown, label: string): string {
  const parsed = String(value ?? '').trim();
  if (!parsed) throw new Error(`${label} is required`);
  return parsed;
}

function identityKey(identity: Ed25519YaoActiveClientIdentityV1): string {
  return JSON.stringify([
    requireNonEmpty(identity.walletId, 'walletId'),
    requireNonEmpty(identity.nearAccountId, 'nearAccountId'),
    requireNonEmpty(identity.thresholdSessionId, 'thresholdSessionId'),
  ]);
}

function capabilityIdentity(
  capability: NearEd25519YaoSigningCapability,
): Ed25519YaoActiveClientIdentityV1 {
  if (capability.activeClient.status().kind !== 'active') {
    throw new Error('Ed25519 Yao active Client registry rejects disposed state');
  }
  const metadata = capability.activeClient.metadata();
  const sessionState = capability.walletSessionState;
  const signingLane = sessionState.signingLane;
  const signer = signingLane.identity.signer;
  const walletId = signingLane.identity.signer.account.wallet.walletId;
  const nearAccountId = signingLane.identity.signer.account.nearAccountId;
  const thresholdSessionId = requireNonEmpty(
    sessionState.thresholdSessionId,
    'walletSessionState.thresholdSessionId',
  );
  if (
    String(signingLane.thresholdSessionId) !== thresholdSessionId ||
    String(signingLane.identity.thresholdSessionId) !== thresholdSessionId
  ) {
    throw new Error('Ed25519 Yao active Client registry session identity mismatch');
  }
  if (
    // Router ceremony scope binds the wallet subject; the signing lane binds its NEAR account.
    metadata.scope.account_id !== String(walletId) ||
    metadata.applicationBinding.wallet_id !== String(walletId) ||
    metadata.applicationBinding.near_ed25519_signing_key_id !==
      String(signer.nearEd25519SigningKeyId) ||
    metadata.applicationBinding.signing_root_id !== sessionState.signingRootId ||
    metadata.scope.root_share_epoch !== sessionState.signingRootVersion ||
    metadata.applicationBinding.key_creation_signer_slot !== signer.signerSlot ||
    metadata.scope.signing_worker_id !== sessionState.routerAbNormalSigning.signingWorkerId
  ) {
    throw new Error('Ed25519 Yao active Client registry subject identity mismatch');
  }
  if (
    metadata.participantIds[0] !== THRESHOLD_ED25519_2P_PARTICIPANT_IDS[0] ||
    metadata.participantIds[1] !== THRESHOLD_ED25519_2P_PARTICIPANT_IDS[1]
  ) {
    throw new Error('Ed25519 Yao active Client registry participant identity mismatch');
  }
  return { walletId, nearAccountId, thresholdSessionId };
}

function sameIdentity(
  left: Ed25519YaoActiveClientIdentityV1,
  right: Ed25519YaoActiveClientIdentityV1,
): boolean {
  return identityKey(left) === identityKey(right);
}

function sameRuntimePolicyScope(
  left: NearEd25519YaoSigningCapability['walletSessionState']['runtimePolicyScope'],
  right: NearEd25519YaoSigningCapability['walletSessionState']['runtimePolicyScope'],
): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function sameStableWalletSessionBinding(args: {
  current: NearEd25519YaoSigningCapability['walletSessionState'];
  next: NearEd25519YaoSigningCapability['walletSessionState'];
  signingGrantId: string;
}): boolean {
  const signingGrantId = requireNonEmpty(args.signingGrantId, 'signingGrantId');
  return (
    String(args.current.signingGrantId) === signingGrantId &&
    String(args.next.signingGrantId) === signingGrantId &&
    exactSigningLaneIdentityKey(args.current.signingLane.identity) ===
      exactSigningLaneIdentityKey(args.next.signingLane.identity) &&
    args.current.signingRootId === args.next.signingRootId &&
    args.current.signingRootVersion === args.next.signingRootVersion &&
    args.current.relayerUrl === args.next.relayerUrl &&
    args.current.routerAbNormalSigning.kind === args.next.routerAbNormalSigning.kind &&
    args.current.routerAbNormalSigning.signingWorkerId ===
      args.next.routerAbNormalSigning.signingWorkerId &&
    sameRuntimePolicyScope(args.current.runtimePolicyScope, args.next.runtimePolicyScope)
  );
}

export class Ed25519YaoActiveClientRegistry implements Ed25519YaoActiveClientRegistryPort {
  private readonly entries = new Map<string, ActiveClientEntryV1>();
  private lifecycleGeneration = 0;

  constructor(
    private readonly publicReferences: Ed25519YaoPublicCapabilityReferenceStorePort =
      new VolatileOnlyPublicCapabilityReferenceStore(),
  ) {}

  async activate(
    capability: NearEd25519YaoSigningCapability,
  ): Promise<Ed25519YaoActiveClientIdentityV1> {
    const identity = capabilityIdentity(capability);
    const key = identityKey(identity);
    const lifecycleGeneration = this.lifecycleGeneration;
    for (const entry of this.entries.values()) {
      if (
        entry.capability.activeClient === capability.activeClient &&
        !sameIdentity(entry.identity, identity)
      ) {
        throw new Error('Ed25519 Yao active Client state is already bound to another identity');
      }
    }
    const current = this.entries.get(key);
    if (!current && this.entries.size >= MAX_ACTIVE_ED25519_YAO_CLIENTS) {
      throw new Error('Ed25519 Yao active Client registry capacity is exhausted');
    }
    await this.publicReferences.upsert(identity);
    if (
      lifecycleGeneration !== this.lifecycleGeneration ||
      capability.activeClient.status().kind !== 'active'
    ) {
      capability.activeClient.dispose();
      await this.publicReferences.remove(identity);
      throw new Error('Ed25519 Yao active Client activation was interrupted');
    }
    if (current && current.capability.activeClient !== capability.activeClient) {
      current.capability.activeClient.dispose();
    }
    this.entries.set(key, { identity, capability });
    return identity;
  }

  resolve(identity: Ed25519YaoActiveClientIdentityV1): NearEd25519YaoSigningCapability | null {
    const key = identityKey(identity);
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.capability.activeClient.status().kind === 'disposed') {
      this.entries.delete(key);
      return null;
    }
    return entry.capability;
  }

  refreshWalletSession(
    input: Ed25519YaoSameIdentityWalletSessionRefreshV1,
  ): Ed25519YaoSameIdentityWalletSessionRefreshResultV1 {
    const key = identityKey(input.identity);
    const current = this.entries.get(key);
    if (!current) {
      return {
        ok: false,
        code: 'source_missing',
        message: 'Ed25519 Yao Wallet Session refresh requires an active source capability',
      };
    }
    if (current.capability.activeClient.status().kind !== 'active') {
      return {
        ok: false,
        code: 'source_disposed',
        message: 'Ed25519 Yao Wallet Session refresh rejects disposed Client state',
      };
    }

    const capability: NearEd25519YaoSigningCapability = {
      activeClient: current.capability.activeClient,
      walletSessionState: input.nextWalletSessionState,
    };
    try {
      const nextIdentity = capabilityIdentity(capability);
      if (
        !sameIdentity(current.identity, input.identity) ||
        !sameIdentity(nextIdentity, input.identity) ||
        !sameStableWalletSessionBinding({
          current: current.capability.walletSessionState,
          next: input.nextWalletSessionState,
          signingGrantId: input.signingGrantId,
        })
      ) {
        return {
          ok: false,
          code: 'stable_binding_mismatch',
          message: 'Ed25519 Yao Wallet Session refresh changed a stable public binding',
        };
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'stable_binding_mismatch',
        message:
          error instanceof Error
            ? error.message
            : 'Ed25519 Yao Wallet Session refresh is invalid',
      };
    }

    this.entries.set(key, { identity: current.identity, capability });
    return { ok: true, identity: current.identity, capability };
  }

  async rollbackActivation(identity: Ed25519YaoActiveClientIdentityV1): Promise<boolean> {
    this.lifecycleGeneration += 1;
    const key = identityKey(identity);
    const entry = this.entries.get(key);
    if (entry) {
      this.entries.delete(key);
      entry.capability.activeClient.dispose();
    }
    await this.publicReferences.remove(identity);
    return entry !== undefined;
  }

  disposeWallet(walletId: WalletId): number {
    this.lifecycleGeneration += 1;
    const expectedWalletId = requireNonEmpty(walletId, 'walletId');
    let removed = 0;
    for (const [key, entry] of this.entries) {
      if (String(entry.identity.walletId) !== expectedWalletId) continue;
      this.entries.delete(key);
      entry.capability.activeClient.dispose();
      removed += 1;
    }
    return removed;
  }

  dispose(): void {
    this.lifecycleGeneration += 1;
    for (const entry of this.entries.values()) {
      entry.capability.activeClient.dispose();
    }
    this.entries.clear();
  }
}
