import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  exportEd25519YaoKeyWithFreshPasskey,
  type Ed25519YaoExportFlowDeps,
} from '@/core/signingEngine/flows/recovery/ed25519YaoExportFlow';
import type { NearEd25519YaoSigningCapability } from '@/core/signingEngine/interfaces/near';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  clearAllStoredThresholdEd25519SessionRecords,
  upsertThresholdEd25519SessionFact,
} from '@/core/signingEngine/session/persistence/records';
import { resolveRouterAbEd25519WalletSessionStateFromRecord } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import type {
  RouterAbEd25519YaoActiveClientMetadataV1,
  RouterAbEd25519YaoActiveClientV1,
  RouterAbEd25519YaoClientSigningInputV1,
  RouterAbEd25519YaoClientSigningShareV1,
} from '@/core/signingEngine/threshold/ed25519/yaoClient';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { RouterAbEd25519YaoExportWorkerPayloadV1 } from '@/core/types/secure-confirm-worker';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

const WALLET_ID = toWalletId('passkey-export-refresh-wallet');
const NEAR_ACCOUNT_ID = toAccountId('passkey-export-refresh.testnet');
const NEAR_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString('passkey-export-refresh-key');
const THRESHOLD_SESSION_ID = 'threshold-passkey-export-refresh';
const STALE_SIGNING_GRANT_ID = 'grant-before-cold-recovery';
const CURRENT_SIGNING_GRANT_ID = 'grant-after-cold-recovery';
const CREDENTIAL_ID = 'passkey-export-refresh-credential';
const RP_ID = 'localhost';
const RELAYER_URL = 'https://relay.example.test';
const RELAYER_KEY_ID = 'passkey-export-refresh-worker';
const PARTICIPANT_IDS = [1, 2] as const;
const RUNTIME_POLICY_SCOPE = {
  orgId: 'org-passkey-export-refresh',
  projectId: 'project-passkey-export-refresh',
  envId: 'test',
  signingRootVersion: 'root-v1',
} as const;
const ROUTER_AB_NORMAL_SIGNING = {
  kind: 'router_ab_ed25519_normal_signing_v1',
  signingWorkerId: RELAYER_KEY_ID,
} as const;

function fixtureJwt(signingGrantId: string): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      kind: 'router_ab_ed25519_wallet_session_v1',
      sub: String(WALLET_ID),
      walletId: String(WALLET_ID),
      nearAccountId: String(NEAR_ACCOUNT_ID),
      nearEd25519SigningKeyId: String(NEAR_SIGNING_KEY_ID),
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signingGrantId,
      relayerKeyId: RELAYER_KEY_ID,
      rpId: RP_ID,
      participantIds: [...PARTICIPANT_IDS],
      version: 'current',
    }),
  ).toString('base64url');
  return `${header}.${payload}.fixture`;
}

function passkeyLaneIdentity(signingGrantId: string): ExactEd25519SigningLaneIdentity {
  return exactEd25519SigningLaneIdentity({
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      signerSlot: 1,
    }),
    auth: {
      kind: 'passkey',
      rpId: toRpId(RP_ID),
      credentialIdB64u: CREDENTIAL_ID,
    },
    signingGrantId,
    thresholdSessionId: THRESHOLD_SESSION_ID,
  });
}

function currentWalletSessionState(credentialIdB64u: string) {
  const record = upsertThresholdEd25519SessionFact({
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    rpId: RP_ID,
    passkeyCredentialIdB64u: credentialIdB64u,
    relayerUrl: RELAYER_URL,
    relayerKeyId: RELAYER_KEY_ID,
    participantIds: [...PARTICIPANT_IDS],
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
    signerSlot: 1,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: THRESHOLD_SESSION_ID,
    signingGrantId: CURRENT_SIGNING_GRANT_ID,
    walletSessionJwt: fixtureJwt(CURRENT_SIGNING_GRANT_ID),
    expiresAtMs: Date.now() + 60_000,
    remainingUses: 3,
    updatedAtMs: Date.now(),
    source: 'login',
  });
  if (!record) throw new Error('expected current Ed25519 export session record');
  const state = resolveRouterAbEd25519WalletSessionStateFromRecord(record);
  if (!state) throw new Error('expected current Ed25519 export Wallet Session state');
  return state;
}

class ActiveYaoClientFixture implements RouterAbEd25519YaoActiveClientV1 {
  status(): { kind: 'active' } {
    return { kind: 'active' };
  }

  async createSigningShare(
    _input: RouterAbEd25519YaoClientSigningInputV1,
  ): Promise<RouterAbEd25519YaoClientSigningShareV1> {
    throw new Error('passkey export refresh fixture does not sign');
  }

  metadata(): RouterAbEd25519YaoActiveClientMetadataV1 {
    return {
      kind: 'router_ab_ed25519_yao_active_client_v1',
      scope: {
        lifecycle_id: 'lifecycle-passkey-export-refresh',
        root_share_epoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
        account_id: String(WALLET_ID),
        wallet_session_id: THRESHOLD_SESSION_ID,
        signer_set_id: 'near-primary',
        signing_worker_id: RELAYER_KEY_ID,
      },
      applicationBinding: {
        wallet_id: String(WALLET_ID),
        near_ed25519_signing_key_id: String(NEAR_SIGNING_KEY_ID),
        signing_root_id: `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`,
        key_creation_signer_slot: 1,
      },
      participantIds: PARTICIPANT_IDS,
      registeredPublicKey: new Uint8Array(32),
      signingWorkerVerifyingShare: new Uint8Array(32),
      stateEpoch: 1n,
      transcript: new Uint8Array(32),
      activeCapabilityBinding: new Array<number>(32).fill(1),
    };
  }

  dispose(): void {}
}

class PasskeyEd25519ExportRefreshHarness {
  readonly capability: NearEd25519YaoSigningCapability;
  recoveredLane: ExactEd25519SigningLaneIdentity | null = null;
  workerPayload: RouterAbEd25519YaoExportWorkerPayloadV1 | null = null;

  constructor(credentialIdB64u: string) {
    this.capability = {
      activeClient: new ActiveYaoClientFixture(),
      walletSessionState: currentWalletSessionState(credentialIdB64u),
    };
  }

  resolveActiveCapability(): null {
    return null;
  }

  async recoverPasskeyCapability(
    laneIdentity: ExactEd25519SigningLaneIdentity,
  ): Promise<NearEd25519YaoSigningCapability> {
    this.recoveredLane = laneIdentity;
    return this.capability;
  }

  async resolvePasskeyExportContext(): ReturnType<
    Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']
  > {
    return {
      kind: 'capability_recovery_required',
      reason: 'sealed_session_missing',
    };
  }

  async exportPrivateKeysWithUi(
    payload: RouterAbEd25519YaoExportWorkerPayloadV1,
  ): Promise<{ ok: true; exportedSchemes: ['ed25519'] }> {
    this.workerPayload = payload;
    return { ok: true, exportedSchemes: ['ed25519'] };
  }

  async initialize(): Promise<void> {}

  async unexpectedConfirmation(): Promise<never> {
    throw new Error('passkey export fixture does not request Email OTP confirmation');
  }

  async unexpectedEmailOtpOperation(): Promise<never> {
    throw new Error('passkey export fixture does not enter Email OTP export');
  }

  deps(): Ed25519YaoExportFlowDeps {
    return {
      touchConfirm: {
        exportPrivateKeysWithUi: this.exportPrivateKeysWithUi.bind(this),
        initialize: this.initialize.bind(this),
        requestUserConfirmation: this.unexpectedConfirmation.bind(this),
      },
      resolveActiveCapability: this.resolveActiveCapability.bind(this),
      recoverPasskeyCapability: this.recoverPasskeyCapability.bind(this),
      resolvePasskeyExportContext: this.resolvePasskeyExportContext.bind(this),
      emailOtp: {
        requestExportChallenge: this.unexpectedEmailOtpOperation.bind(this),
        resolveExportContext: this.unexpectedEmailOtpOperation.bind(this),
        exportSeedWithFreshAuthorization: this.unexpectedEmailOtpOperation.bind(this),
      },
    };
  }
}

class DurablePasskeyEd25519ExportRefreshHarness extends PasskeyEd25519ExportRefreshHarness {
  recoveryCalls = 0;

  async recoverPasskeyCapability(): Promise<never> {
    this.recoveryCalls += 1;
    throw new Error('durable passkey export context must bypass signing-capability recovery');
  }

  async resolvePasskeyExportContext(): ReturnType<
    Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']
  > {
    return {
      kind: 'ready',
      context: {
        kind: 'passkey_ed25519_yao_export_context_v1',
        relayerUrl: RELAYER_URL,
        rpId: RP_ID,
        descriptor: {
          walletId: WALLET_ID,
          nearAccountId: NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: String(NEAR_SIGNING_KEY_ID),
          signerSlot: 1,
          operationalPublicKey: 'ed25519:durable-export-context',
          relayerKeyId: RELAYER_KEY_ID,
          credentialIdB64u: CREDENTIAL_ID,
          session: {
            walletSessionJwt: fixtureJwt(CURRENT_SIGNING_GRANT_ID),
            thresholdSessionId: THRESHOLD_SESSION_ID,
            signingGrantId: CURRENT_SIGNING_GRANT_ID,
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 3,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            participantIds: PARTICIPANT_IDS,
            routerAbNormalSigning: ROUTER_AB_NORMAL_SIGNING,
          },
          capability: {
            activeCapabilityBinding: new Array<number>(32).fill(1),
            registeredPublicKey: new Array<number>(32).fill(0),
            nearAccountId: NEAR_ACCOUNT_ID,
            applicationBinding: {
              wallet_id: String(WALLET_ID),
              near_ed25519_signing_key_id: String(NEAR_SIGNING_KEY_ID),
              signing_root_id: `${RUNTIME_POLICY_SCOPE.projectId}:${RUNTIME_POLICY_SCOPE.envId}`,
              key_creation_signer_slot: 1,
            },
            participantIds: PARTICIPANT_IDS,
            runtimePolicyScope: RUNTIME_POLICY_SCOPE,
            lifecycle: {
              lifecycleId: 'lifecycle-passkey-export-refresh',
              rootShareEpoch: RUNTIME_POLICY_SCOPE.signingRootVersion,
              accountId: String(WALLET_ID),
              walletSessionId: THRESHOLD_SESSION_ID,
              signerSetId: 'near-primary',
              signingWorkerId: RELAYER_KEY_ID,
            },
            stateEpoch: 1,
          },
        },
      },
    };
  }
}

test('page-refresh passkey export prompts from durable context without activating a signing client', async () => {
  clearAllStoredThresholdEd25519SessionRecords();
  try {
    const harness = new DurablePasskeyEd25519ExportRefreshHarness(CREDENTIAL_ID);
    const result = await exportEd25519YaoKeyWithFreshPasskey(harness.deps(), {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      laneIdentity: passkeyLaneIdentity(STALE_SIGNING_GRANT_ID),
      options: {},
      flowId: 'flow-passkey-export-durable-context',
    });

    expect(result).toEqual({
      accountId: String(NEAR_ACCOUNT_ID),
      exportedSchemes: ['ed25519'],
    });
    expect(harness.recoveryCalls).toBe(0);
    expect(harness.workerPayload?.exactLane.signingGrantId).toBe(CURRENT_SIGNING_GRANT_ID);
    expect(harness.workerPayload?.walletSessionJwt).toBe(fixtureJwt(CURRENT_SIGNING_GRANT_ID));
  } finally {
    clearAllStoredThresholdEd25519SessionRecords();
  }
});

test('page-refresh passkey export uses the Wallet Session issued by cold Yao recovery', async () => {
  clearAllStoredThresholdEd25519SessionRecords();
  try {
    const harness = new PasskeyEd25519ExportRefreshHarness(CREDENTIAL_ID);
    const selectedLane = passkeyLaneIdentity(STALE_SIGNING_GRANT_ID);
    const result = await exportEd25519YaoKeyWithFreshPasskey(harness.deps(), {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      laneIdentity: selectedLane,
      options: {},
      flowId: 'flow-passkey-export-refresh',
    });

    expect(result).toEqual({
      accountId: String(NEAR_ACCOUNT_ID),
      exportedSchemes: ['ed25519'],
    });
    expect(harness.recoveredLane).toEqual(selectedLane);
    expect(harness.workerPayload?.exactLane).toMatchObject({
      signingGrantId: CURRENT_SIGNING_GRANT_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      credentialIdB64u: CREDENTIAL_ID,
    });
    expect(harness.workerPayload?.walletSessionJwt).toBe(fixtureJwt(CURRENT_SIGNING_GRANT_ID));
  } finally {
    clearAllStoredThresholdEd25519SessionRecords();
  }
});

test('page-refresh passkey export rejects recovered authenticator drift', async () => {
  clearAllStoredThresholdEd25519SessionRecords();
  try {
    const harness = new PasskeyEd25519ExportRefreshHarness('different-passkey-credential');
    await expect(
      exportEd25519YaoKeyWithFreshPasskey(harness.deps(), {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        laneIdentity: passkeyLaneIdentity(STALE_SIGNING_GRANT_ID),
        options: {},
        flowId: 'flow-passkey-export-refresh-authenticator-drift',
      }),
    ).rejects.toThrow('Yao capability stable identity mismatch');
    expect(harness.workerPayload).toBeNull();
  } finally {
    clearAllStoredThresholdEd25519SessionRecords();
  }
});
