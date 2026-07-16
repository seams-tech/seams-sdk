import { expect, test } from '@playwright/test';
import type { WebAuthnAuthenticationCredential } from '../../packages/sdk-web/src/core/types/webauthn';
import type { NearEd25519YaoSigningCapability } from '../../packages/sdk-web/src/core/signingEngine/interfaces/near';
import type {
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  type ThresholdEd25519SessionRecord,
  upsertThresholdEd25519SessionFact,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  buildExactPasskeyEd25519RefreshLaneIdentity,
  refreshPasskeyEd25519CapabilityForSigning,
} from '../../packages/sdk-web/src/core/signingEngine/session/passkey/ed25519BudgetRefresh';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '../../packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildThresholdEd25519WebAuthnPrfSecretSource } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession';
import {
  Ed25519YaoActiveClientRegistry,
  type Ed25519YaoActiveClientIdentityV1,
} from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoActiveClientRegistry';
import type { Ed25519YaoPublicCapabilityReferenceStorePort } from '../../packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoPublicCapabilityReferences';

const ACCOUNT_ID = 'ed25519-budget-refresh.testnet';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'ed25519:relayer-key';
const PARTICIPANT_IDS = [1, 2] as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-ed25519-budget-refresh',
  projectId: 'project-ed25519-budget-refresh',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: 'local-signing-worker',
} as const;
const TEST_WEBAUTHN_CREDENTIAL: WebAuthnAuthenticationCredential = {
  id: 'credential-id',
  rawId: 'credential-id',
  type: 'public-key',
  authenticatorAttachment: 'platform',
  response: {
    clientDataJSON: 'client-data',
    authenticatorData: 'authenticator-data',
    signature: 'signature',
    userHandle: undefined,
  },
  clientExtensionResults: {
    prf: {
      results: {
        first: Buffer.alloc(32, 7).toString('base64url'),
        second: undefined,
      },
    },
  },
};

function base64UrlEncodeJsonFixture(value: unknown): string {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function buildWalletSessionJwt(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  version: string;
}): string {
  const header = base64UrlEncodeJsonFixture({ alg: 'none', typ: 'JWT' });
  const payload = base64UrlEncodeJsonFixture({
    kind: 'router_ab_ed25519_wallet_session_v1',
    sub: ACCOUNT_ID,
    walletId: ACCOUNT_ID,
    nearAccountId: ACCOUNT_ID,
    nearEd25519SigningKeyId: ACCOUNT_ID,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    relayerKeyId: RELAYER_KEY_ID,
    rpId: RP_ID,
    participantIds: [...PARTICIPANT_IDS],
    version: args.version,
  });
  return `${header}.${payload}.fixture`;
}

function writeEd25519Record(args: {
  thresholdSessionId: string;
  signingGrantId: string;
  remainingUses?: number;
  updatedAtMs: number;
  version?: string;
  runtimePolicyScope?: {
    orgId: string;
    projectId: string;
    envId: string;
    signingRootVersion: string;
  };
  includeRuntimePolicyScope?: boolean;
}): ThresholdEd25519SessionRecord {
  const record = upsertThresholdEd25519SessionFact({
    walletId: ACCOUNT_ID,
    nearAccountId: ACCOUNT_ID,
    nearEd25519SigningKeyId: ACCOUNT_ID,
    rpId: RP_ID,
    passkeyCredentialIdB64u: 'credential-id-b64u',
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: [...PARTICIPANT_IDS],
    ...(args.includeRuntimePolicyScope === false
      ? {}
      : { runtimePolicyScope: args.runtimePolicyScope || RUNTIME_POLICY_SCOPE }),
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    signerSlot: 1,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: buildWalletSessionJwt({
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
      version: args.version || 'initial',
    }),
    expiresAtMs: Date.now() + 60_000,
    remainingUses: args.remainingUses ?? 1,
    updatedAtMs: args.updatedAtMs,
    source: 'login',
  });
  if (!record) throw new Error('expected Ed25519 test record');
  return record;
}

class ActiveYaoClientFixture implements RouterAbEd25519YaoActiveClientV1 {
  private disposed = false;
  private disposeCalls = 0;
  private readonly record: ThresholdEd25519SessionRecord;

  constructor(record: ThresholdEd25519SessionRecord) {
    this.record = record;
  }

  status(): { kind: 'active' } | { kind: 'disposed' } {
    return this.disposed ? { kind: 'disposed' } : { kind: 'active' };
  }

  async createSigningShare(
    _input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1> {
    throw new Error('budget refresh fixture does not create signing shares');
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    return {
      kind: 'router_ab_ed25519_yao_active_client_v1',
      scope: {
        lifecycle_id: 'registration-lifecycle-1',
        root_share_epoch: this.record.runtimePolicyScope?.signingRootVersion || 'default',
        account_id: String(this.record.walletId),
        wallet_session_id: String(this.record.thresholdSessionId),
        signer_set_id: 'near-primary',
        signing_worker_id: this.record.routerAbNormalSigning.signingWorkerId,
      },
      applicationBinding: {
        wallet_id: String(this.record.walletId),
        near_ed25519_signing_key_id: String(this.record.nearEd25519SigningKeyId),
        signing_root_id: `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`,
        key_creation_signer_slot: this.record.signerSlot,
      },
      participantIds: PARTICIPANT_IDS,
      registeredPublicKey: new Uint8Array(32),
      signingWorkerVerifyingShare: new Uint8Array(32),
      stateEpoch: 1n,
      transcript: new Uint8Array(32),
      activeCapabilityBinding: new Array<number>(32).fill(1),
    };
  }

  dispose(): void {
    this.disposeCalls += 1;
    this.disposed = true;
  }

  disposeCallCount(): number {
    return this.disposeCalls;
  }

  asActiveClient(): NearEd25519YaoSigningCapability['activeClient'] {
    return this;
  }
}

class PublicCapabilityReferenceStoreFixture implements Ed25519YaoPublicCapabilityReferenceStorePort {
  private identities: Ed25519YaoActiveClientIdentityV1[] = [];

  async upsert(identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {
    this.identities = [identity];
  }

  async remove(identity: Ed25519YaoActiveClientIdentityV1): Promise<void> {
    this.identities = this.identities.filter(
      (candidate) => candidate.thresholdSessionId !== identity.thresholdSessionId,
    );
  }

  async list(): Promise<readonly Ed25519YaoActiveClientIdentityV1[]> {
    return [...this.identities];
  }
}

function yaoCapabilityFixture(
  record: ThresholdEd25519SessionRecord,
  activeClient: NearEd25519YaoSigningCapability['activeClient'],
): NearEd25519YaoSigningCapability {
  const walletSessionState = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!walletSessionState) throw new Error('expected signable Yao Wallet Session state');
  return { activeClient, walletSessionState };
}

function policySecretSourceFixture() {
  return buildThresholdEd25519WebAuthnPrfSecretSource({
    credential: TEST_WEBAUTHN_CREDENTIAL,
    rpId: RP_ID,
  });
}

function refreshLaneIdentityFixture(record: ThresholdEd25519SessionRecord) {
  return buildExactPasskeyEd25519RefreshLaneIdentity({
    nearAccountId: ACCOUNT_ID,
    record,
    signerSlot: record.signerSlot,
    sessionId: record.thresholdSessionId,
    signingGrantId: record.signingGrantId || '',
  });
}

test.describe('passkey Ed25519 Yao same-identity budget refresh', () => {
  test.beforeEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test.afterEach(() => {
    clearAllStoredThresholdEd25519SessionRecords();
  });

  test('reuses the active Client while replacing public Wallet Session budget state', async () => {
    const sessionId = 'tsess-ed25519-stable';
    const signingGrantId = 'wsess-ed25519-stable';
    const initialRecord = writeEd25519Record({
      thresholdSessionId: sessionId,
      signingGrantId,
      remainingUses: 1,
      updatedAtMs: 1,
      version: 'initial',
    });
    const activeClientFixture = new ActiveYaoClientFixture(initialRecord);
    const activeClient = activeClientFixture.asActiveClient();
    const initialCapability = yaoCapabilityFixture(initialRecord, activeClient);
    const registry = new Ed25519YaoActiveClientRegistry();
    const identity = await registry.activate(initialCapability);
    const exhaustedRecord = writeEd25519Record({
      thresholdSessionId: sessionId,
      signingGrantId,
      remainingUses: 0,
      updatedAtMs: 2,
      version: 'exhausted',
    });

    const result = await refreshPasskeyEd25519CapabilityForSigning({
      record: exhaustedRecord,
      laneIdentity: refreshLaneIdentityFixture(exhaustedRecord),
      policySecretSource: policySecretSourceFixture(),
      operationUsesNeeded: 1,
      runtimeScopeBootstrap: {
        projectEnvironmentId: 'env-refresh',
        publishableKey: 'pk_test_refresh',
      },
      provisionThresholdEd25519Session: async (request) => {
        expect(request.kind).toBe('exact_ed25519_provisioning');
        if (!request.laneIdentity) {
          throw new Error('expected exact Ed25519 provisioning lane identity');
        }
        expect(String(request.laneIdentity.thresholdSessionId)).toBe(sessionId);
        expect(String(request.laneIdentity.signingGrantId)).toBe(signingGrantId);
        expect(request.auth?.kind).toBe('router_ab_ed25519_yao_budget_refresh_v1');
        if (request.auth?.kind !== 'router_ab_ed25519_yao_budget_refresh_v1') {
          throw new Error('expected Yao budget refresh authorization');
        }
        expect(request.runtimeScopeBootstrap).toEqual({
          projectEnvironmentId: 'env-refresh',
          publishableKey: 'pk_test_refresh',
        });
        const refreshedRecord = writeEd25519Record({
          thresholdSessionId: sessionId,
          signingGrantId,
          remainingUses: 1,
          updatedAtMs: 3,
          version: 'refreshed',
        });
        return {
          ok: true,
          sessionId,
          signingGrantId,
          expiresAtMs: refreshedRecord.expiresAtMs,
          remainingUses: refreshedRecord.remainingUses,
          jwt: refreshedRecord.walletSessionJwt || '',
        };
      },
      resolveActiveEd25519YaoSigningCapability: (requestedIdentity) =>
        registry.resolve(requestedIdentity),
      recoverPasskeyEd25519YaoCapabilityForSigning: async () => {
        throw new Error('active-client refresh must not enter cold recovery');
      },
      refreshActiveEd25519YaoWalletSession: (refresh) =>
        registry.refreshWalletSession({
          kind: 'same_identity_wallet_session_refresh_v1',
          identity: refresh.identity,
          signingGrantId: refresh.signingGrantId,
          nextWalletSessionState: refresh.nextWalletSessionState,
        }),
    });

    expect(result.sessionId).toBe(sessionId);
    expect(result.record.thresholdSessionId).toBe(sessionId);
    expect(result.record.signingGrantId).toBe(signingGrantId);
    expect(result.walletSessionState.remainingUses).toBe(1);
    expect(result.walletSessionState.walletSessionAuth.walletSessionJwt).toBe(
      result.record.walletSessionJwt,
    );
    expect(result.activeClient).toBe(activeClient);
    expect(registry.resolve(identity)?.activeClient).toBe(activeClient);
    expect(registry.resolve(identity)?.walletSessionState.remainingUses).toBe(1);
    expect(activeClientFixture.disposeCallCount()).toBe(0);
  });

  test('mints and recovers the exact Client when page refresh cleared live state', async () => {
    const oldRecord = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-inactive',
      signingGrantId: 'wsess-ed25519-inactive',
      remainingUses: 0,
      updatedAtMs: 1,
    });
    let provisionCalls = 0;
    let recoveredRecord: ThresholdEd25519SessionRecord | null = null;
    const recoveredClient = new ActiveYaoClientFixture(oldRecord).asActiveClient();

    const result = await refreshPasskeyEd25519CapabilityForSigning({
      record: oldRecord,
      laneIdentity: refreshLaneIdentityFixture(oldRecord),
      policySecretSource: policySecretSourceFixture(),
      operationUsesNeeded: 1,
      provisionThresholdEd25519Session: async () => {
        provisionCalls += 1;
        recoveredRecord = writeEd25519Record({
          thresholdSessionId: oldRecord.thresholdSessionId,
          signingGrantId: oldRecord.signingGrantId || '',
          remainingUses: 1,
          updatedAtMs: 2,
          version: 'cold-recovered',
        });
        return {
          ok: true,
          sessionId: oldRecord.thresholdSessionId,
          signingGrantId: oldRecord.signingGrantId || '',
          expiresAtMs: recoveredRecord.expiresAtMs,
          remainingUses: recoveredRecord.remainingUses,
          jwt: recoveredRecord.walletSessionJwt || '',
        };
      },
      resolveActiveEd25519YaoSigningCapability: () => null,
      recoverPasskeyEd25519YaoCapabilityForSigning: async (identity) => {
        expect(identity).toEqual({
          walletId: oldRecord.walletId,
          nearAccountId: ACCOUNT_ID,
          signerSlot: oldRecord.signerSlot,
          thresholdSessionId: oldRecord.thresholdSessionId,
        });
        if (!recoveredRecord) throw new Error('expected refreshed record before recovery');
        return yaoCapabilityFixture(recoveredRecord, recoveredClient);
      },
      refreshActiveEd25519YaoWalletSession: () => {
        throw new Error('cold recovery must not refresh a missing live Client');
      },
    });
    expect(provisionCalls).toBe(1);
    expect(result.activeClient).toBe(recoveredClient);
    expect(result.walletSessionState.remainingUses).toBe(1);
  });

  test('fails before mint when persisted runtime policy scope is unavailable', async () => {
    const record = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-missing-scope',
      signingGrantId: 'wsess-ed25519-missing-scope',
      remainingUses: 0,
      updatedAtMs: 1,
      includeRuntimePolicyScope: false,
    });
    let provisionCalls = 0;

    await expect(
      refreshPasskeyEd25519CapabilityForSigning({
        record,
        laneIdentity: refreshLaneIdentityFixture(record),
        policySecretSource: policySecretSourceFixture(),
        operationUsesNeeded: 1,
        provisionThresholdEd25519Session: async () => {
          provisionCalls += 1;
          throw new Error('provision must not run');
        },
        resolveActiveEd25519YaoSigningCapability: () => null,
        recoverPasskeyEd25519YaoCapabilityForSigning: async () => {
          throw new Error('recovery must not run');
        },
        refreshActiveEd25519YaoWalletSession: () => {
          throw new Error('refresh must not run');
        },
      }),
    ).rejects.toThrow('budget refresh requires runtime policy scope');
    expect(provisionCalls).toBe(0);
  });

  test('rejects stable-binding drift without replacing or disposing the Client', async () => {
    const sessionId = 'tsess-ed25519-binding';
    const signingGrantId = 'wsess-ed25519-binding';
    const initialRecord = writeEd25519Record({
      thresholdSessionId: sessionId,
      signingGrantId,
      updatedAtMs: 1,
    });
    const activeClientFixture = new ActiveYaoClientFixture(initialRecord);
    const activeClient = activeClientFixture.asActiveClient();
    const initialCapability = yaoCapabilityFixture(initialRecord, activeClient);
    const registry = new Ed25519YaoActiveClientRegistry();
    const identity = await registry.activate(initialCapability);
    const changedScope = {
      ...RUNTIME_POLICY_SCOPE,
      signingRootVersion: 'rotated',
    };
    const changedRecord = writeEd25519Record({
      thresholdSessionId: sessionId,
      signingGrantId,
      updatedAtMs: 2,
      runtimePolicyScope: changedScope,
    });
    const changedState = resolveRouterAbEd25519WalletSessionStateFromRecord(changedRecord);
    if (!changedState) throw new Error('expected changed Wallet Session state');

    const refreshed = registry.refreshWalletSession({
      kind: 'same_identity_wallet_session_refresh_v1',
      identity,
      signingGrantId,
      nextWalletSessionState: changedState,
    });

    expect(refreshed).toMatchObject({ ok: false, code: 'stable_binding_mismatch' });
    expect(registry.resolve(identity)).toBe(initialCapability);
    expect(activeClientFixture.disposeCallCount()).toBe(0);
  });

  test('page/runtime disposal destroys the live Client while retaining its public reference', async () => {
    const record = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-page-dispose',
      signingGrantId: 'wsess-ed25519-page-dispose',
      updatedAtMs: 1,
    });
    const activeClientFixture = new ActiveYaoClientFixture(record);
    const publicReferences = new PublicCapabilityReferenceStoreFixture();
    const registry = new Ed25519YaoActiveClientRegistry(publicReferences);
    const identity = await registry.activate(
      yaoCapabilityFixture(record, activeClientFixture.asActiveClient()),
    );

    registry.dispose();

    expect(activeClientFixture.disposeCallCount()).toBe(1);
    expect(registry.resolve(identity)).toBeNull();
    expect(await publicReferences.list()).toEqual([identity]);
  });

  test('wallet-scoped volatile disposal retains the public reference required by cold recovery', async () => {
    const record = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-explicit-clear',
      signingGrantId: 'wsess-ed25519-explicit-clear',
      updatedAtMs: 1,
    });
    const activeClientFixture = new ActiveYaoClientFixture(record);
    const publicReferences = new PublicCapabilityReferenceStoreFixture();
    const registry = new Ed25519YaoActiveClientRegistry(publicReferences);
    const identity = await registry.activate(
      yaoCapabilityFixture(record, activeClientFixture.asActiveClient()),
    );

    expect(registry.disposeWallet(record.walletId)).toBe(1);

    expect(activeClientFixture.disposeCallCount()).toBe(1);
    expect(registry.resolve(identity)).toBeNull();
    expect(await publicReferences.list()).toEqual([identity]);
  });

  test('rejected activation rollback deletes its public reference', async () => {
    const record = writeEd25519Record({
      thresholdSessionId: 'tsess-ed25519-rejected-activation',
      signingGrantId: 'wsess-ed25519-rejected-activation',
      updatedAtMs: 1,
    });
    const activeClientFixture = new ActiveYaoClientFixture(record);
    const publicReferences = new PublicCapabilityReferenceStoreFixture();
    const registry = new Ed25519YaoActiveClientRegistry(publicReferences);
    const identity = await registry.activate(
      yaoCapabilityFixture(record, activeClientFixture.asActiveClient()),
    );

    await expect(registry.rollbackActivation(identity)).resolves.toBe(true);

    expect(activeClientFixture.disposeCallCount()).toBe(1);
    expect(registry.resolve(identity)).toBeNull();
    expect(await publicReferences.list()).toEqual([]);
  });
});
