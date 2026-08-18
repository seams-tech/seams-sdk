import type { WalletEd25519YaoActiveCapabilityRecord } from '../../../packages/wallet-server/src/core/WalletStore';
import { D1WalletStore } from '../../../packages/wallet-server/src/core/d1WalletStore';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoWalletSigner';
import { createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1 } from '../../../packages/wallet-server/src/router/cloudflare/d1/ed25519Yao/d1Ed25519YaoProductRegistrationPartitionedStateStore';
import { createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1 } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistrationRequestScopedRuntime';
import type { RouterAbEd25519YaoActiveCapabilityLookupV1 } from '../../../packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';
import { parseWalletId } from '../../../packages/shared-ts/src/utils/domainIds';
import {
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  type TemporaryD1Database,
} from '../../helpers/sqliteD1';
import { applySignerMigrations } from './cloudflareD1RouterApiAuthService.fixtures';
import {
  UnavailableRouterAbEd25519YaoRegistrationBackend,
  UnusedSessionAdapter,
} from './routerAbEd25519YaoRegistrationBridge.fixtures';

export type RouterAbEd25519YaoExistingWalletD1Fixture = {
  readonly database: TemporaryD1Database['database'];
  readonly walletStore: D1WalletStore;
  readonly store: ReturnType<
    typeof createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1
  >;
  readonly runtime: ReturnType<
    typeof createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1
  >;
  readonly persistedCapabilityLoadCount: () => number;
  readonly cleanup: () => void;
};

type ExistingWalletD1FixtureInput = {
  readonly namespace: string;
  readonly capability: WalletEd25519YaoActiveCapabilityRecord;
};

export function routerAbEd25519YaoCapabilityLookupFixture(
  capability: WalletEd25519YaoActiveCapabilityRecord,
): RouterAbEd25519YaoActiveCapabilityLookupV1 {
  const application = capability.admissionRequest.application_binding;
  return {
    kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
    walletId: application.wallet_id,
    nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
    signerSlot: application.key_creation_signer_slot,
    signingWorkerId: capability.admissionRequest.scope.signing_worker_id,
    participantIds: capability.admissionRequest.participant_ids,
  };
}

class PersistedCapabilityLoader {
  calls = 0;

  constructor(private readonly walletStore: D1WalletStore) {}

  async load(
    lookup: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): Promise<WalletEd25519YaoActiveCapabilityRecord | null> {
    this.calls += 1;
    const walletId = parseWalletId(lookup.walletId);
    if (!walletId.ok) return null;
    const signer = await this.walletStore.getEd25519SignerBySlot({
      walletId: walletId.value,
      signerSlot: lookup.signerSlot,
    });
    return signer?.activeYaoCapability || null;
  }
}

export async function createRouterAbEd25519YaoExistingWalletD1Fixture(
  input: ExistingWalletD1FixtureInput,
): Promise<RouterAbEd25519YaoExistingWalletD1Fixture> {
  const temporary = createTemporaryD1Database();
  try {
    await applySignerMigrations(temporary.database);
    const application = input.capability.admissionRequest.application_binding;
    const scope = {
      namespace: input.namespace,
      orgId: input.capability.runtimePolicyScope.orgId,
      projectId: input.capability.runtimePolicyScope.projectId,
      envId: input.capability.runtimePolicyScope.envId,
    } as const;
    const walletId = parseWalletId(application.wallet_id);
    if (!walletId.ok) throw new Error(walletId.error.message);
    const walletStore = new D1WalletStore({
      database: temporary.database,
      ...scope,
      ensureSchema: false,
    });
    await walletStore.putSigner(
      buildYaoEd25519WalletSignerRecord({
        walletId: walletId.value,
        nearAccountId: input.capability.nearAccountId,
        nearEd25519SigningKeyId: application.near_ed25519_signing_key_id,
        thresholdSessionId: input.capability.admissionRequest.scope.threshold_session_id,
        signerSlot: application.key_creation_signer_slot,
        publicKey: ed25519NearPublicKeyFromBytes(
          input.capability.activationResult.public_receipt.registered_public_key,
        ),
        signingWorkerId: input.capability.admissionRequest.scope.signing_worker_id,
        keyVersion: 'router-ab-ed25519-yao-v1',
        participantIds: input.capability.admissionRequest.participant_ids,
        signingRootId: application.signing_root_id,
        signingRootVersion: input.capability.admissionRequest.scope.root_share_epoch,
        runtimePolicyScope: input.capability.runtimePolicyScope,
        activeYaoCapability: input.capability,
        custodyKeyManifestDigestB64u: Buffer.alloc(32, 21).toString('base64url'),
        now: 1_900_000_000_000,
      }),
    );
    const store = createRouterAbEd25519YaoProductRegistrationPartitionedStateStoreFromD1V1({
      database: temporary.database,
      scope,
    });
    const loader = new PersistedCapabilityLoader(walletStore);
    const runtime = createRouterAbEd25519YaoProductRegistrationRequestScopedRuntimeV1({
      signingWorkerId: input.capability.admissionRequest.scope.signing_worker_id,
      session: new UnusedSessionAdapter(),
      store,
      registrationBackend: new UnavailableRouterAbEd25519YaoRegistrationBackend(),
      loadPersistedActiveCapability: loader.load.bind(loader),
    });
    return {
      database: temporary.database,
      walletStore,
      store,
      runtime,
      persistedCapabilityLoadCount: loaderCallCount.bind(undefined, loader),
      cleanup: cleanupTemporaryD1Database.bind(undefined, temporary.tempDir),
    };
  } catch (error: unknown) {
    cleanupTemporaryD1Database(temporary.tempDir);
    throw error;
  }
}

function loaderCallCount(loader: PersistedCapabilityLoader): number {
  return loader.calls;
}
