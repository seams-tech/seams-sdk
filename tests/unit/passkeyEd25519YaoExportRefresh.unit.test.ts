import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  exportEd25519YaoKeyWithFreshAuthorization,
  type Ed25519YaoExportFlowDeps,
} from '@/core/signingEngine/flows/recovery/ed25519YaoExportFlow';
import {
  exactEd25519SigningLaneIdentity,
  nearEd25519SignerBindingFromBoundaryFields,
  type ExactEd25519SigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { RouterAbEd25519YaoExportWorkerPayloadV1 } from '@/core/types/secure-confirm-worker';
import type { PasskeyEd25519YaoExportContextV1 } from '@/core/signingEngine/session/passkey/ed25519YaoWarmRecovery';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';
import { availableLaneEd25519Authorization } from './helpers/availableSigningLanes.fixtures';

const WALLET_ID = toWalletId('passkey-export-refresh-wallet');
const NEAR_ACCOUNT_ID = toAccountId('passkey-export-refresh.testnet');
const NEAR_SIGNING_KEY_ID = nearEd25519SigningKeyIdFromString('passkey-export-refresh-key');
const THRESHOLD_SESSION_ID = 'threshold-passkey-export-refresh';
const RETIRED_THRESHOLD_SESSION_ID = 'threshold-passkey-export-refresh-retired';
const WALLET_SESSION_ID = 'wallet-session-passkey-export-refresh';
const QUOTA_ID = 'quota-passkey-export-refresh';
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
const MATERIAL_ACTIVATION = buildMpcMaterialActivationRefFixture(
  'passkey-export-refresh',
  String(WALLET_ID),
);
const DURABLE_EXPORT_AUTHORIZATION = availableLaneEd25519Authorization({
  walletId: String(WALLET_ID),
  identitySeed: 'passkey-export-refresh',
  authMethod: 'passkey',
});

function passkeyLaneIdentity(
  walletSessionId: string,
  quotaId: string = QUOTA_ID,
  thresholdSessionId: string = THRESHOLD_SESSION_ID,
): ExactEd25519SigningLaneIdentity {
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
    walletSessionId,
    quotaId,
    thresholdSessionId,
  });
}

class PasskeyEd25519ExportRefreshHarness {
  resolvedLane: ExactEd25519SigningLaneIdentity | null = null;
  workerPayload: RouterAbEd25519YaoExportWorkerPayloadV1 | null = null;

  constructor(private readonly contextCredentialIdB64u: string) {}

  async resolvePasskeyExportContext(
    args: Parameters<Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']>[0],
  ): ReturnType<Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']> {
    this.resolvedLane = args.laneIdentity;
    return { kind: 'ready', context: this.buildDurableContext() };
  }

  buildDurableContext(): PasskeyEd25519YaoExportContextV1 {
    return {
      kind: 'passkey_ed25519_yao_export_context_v1',
      selectedLaneMaterialActivation: MATERIAL_ACTIVATION,
      relayerUrl: RELAYER_URL,
      rpId: RP_ID,
      authorization: DURABLE_EXPORT_AUTHORIZATION,
      material: {
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: String(NEAR_SIGNING_KEY_ID),
        signerSlot: 1,
        operationalPublicKey: 'ed25519:durable-export-context',
        relayerKeyId: RELAYER_KEY_ID,
        credentialIdB64u: this.contextCredentialIdB64u,
        capability: {
          materialActivation: MATERIAL_ACTIVATION,
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
            thresholdSessionId: THRESHOLD_SESSION_ID,
            signerSetId: 'near-primary',
            signingWorkerId: RELAYER_KEY_ID,
          },
          stateEpoch: 1,
        },
      },
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

  async withThresholdEd25519CommitQueue<T>(
    args: Parameters<Ed25519YaoExportFlowDeps['withThresholdEd25519CommitQueue']>[0],
  ): Promise<T> {
    return await args.task();
  }

  deps(): Ed25519YaoExportFlowDeps {
    return {
      touchConfirm: {
        initialize: this.initialize.bind(this),
        requestUserConfirmation: this.unexpectedConfirmation.bind(this),
      },
      passkeyMpcExport: {
        exportPrivateKeysWithUi: this.exportPrivateKeysWithUi.bind(this),
      },
      resolvePasskeyExportContext: this.resolvePasskeyExportContext.bind(this),
      withThresholdEd25519CommitQueue: this.withThresholdEd25519CommitQueue.bind(this),
      emailOtp: {
        requestExportChallenge: this.unexpectedEmailOtpOperation.bind(this),
        resolveExportContext: this.unexpectedEmailOtpOperation.bind(this),
        exportSeedWithFreshAuthorization: this.unexpectedEmailOtpOperation.bind(this),
      },
    };
  }
}

class DurablePasskeyEd25519ExportRefreshHarness extends PasskeyEd25519ExportRefreshHarness {
  async resolvePasskeyExportContext(): ReturnType<
    Ed25519YaoExportFlowDeps['resolvePasskeyExportContext']
  > {
    return {
      kind: 'ready',
      context: {
        kind: 'passkey_ed25519_yao_export_context_v1',
        selectedLaneMaterialActivation: MATERIAL_ACTIVATION,
        relayerUrl: RELAYER_URL,
        rpId: RP_ID,
        authorization: DURABLE_EXPORT_AUTHORIZATION,
        material: {
          walletId: WALLET_ID,
          nearAccountId: NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: String(NEAR_SIGNING_KEY_ID),
          signerSlot: 1,
          operationalPublicKey: 'ed25519:durable-export-context',
          relayerKeyId: RELAYER_KEY_ID,
          credentialIdB64u: CREDENTIAL_ID,
          capability: {
            materialActivation: MATERIAL_ACTIVATION,
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
              thresholdSessionId: THRESHOLD_SESSION_ID,
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
  const harness = new DurablePasskeyEd25519ExportRefreshHarness(CREDENTIAL_ID);
  const result = await exportEd25519YaoKeyWithFreshAuthorization(harness.deps(), {
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    laneIdentity: passkeyLaneIdentity(WALLET_SESSION_ID, QUOTA_ID, RETIRED_THRESHOLD_SESSION_ID),
    materialActivation: MATERIAL_ACTIVATION,
    options: {},
    flowId: 'flow-passkey-export-durable-context',
  });

  expect(result).toEqual({
    accountId: String(NEAR_ACCOUNT_ID),
    exportedSchemes: ['ed25519'],
  });
  expect(harness.workerPayload?.exactLane.materialActivation).toEqual(MATERIAL_ACTIVATION);
  expect(harness.workerPayload?.authorization.walletSessionJwt).toBe(
    DURABLE_EXPORT_AUTHORIZATION.walletSessionJwt,
  );
});

test('page-refresh passkey export uses the exact durable context returned after recovery', async () => {
  const harness = new PasskeyEd25519ExportRefreshHarness(CREDENTIAL_ID);
  const selectedLane = passkeyLaneIdentity(WALLET_SESSION_ID);
  const result = await exportEd25519YaoKeyWithFreshAuthorization(harness.deps(), {
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    laneIdentity: selectedLane,
    materialActivation: MATERIAL_ACTIVATION,
    options: {},
    flowId: 'flow-passkey-export-refresh',
  });

  expect(result).toEqual({
    accountId: String(NEAR_ACCOUNT_ID),
    exportedSchemes: ['ed25519'],
  });
  expect(harness.resolvedLane).toEqual(selectedLane);
  expect(harness.workerPayload?.exactLane).toMatchObject({
    credentialIdB64u: CREDENTIAL_ID,
    materialActivation: MATERIAL_ACTIVATION,
  });
  expect(harness.workerPayload?.authorization.walletSessionJwt).toBe(
    DURABLE_EXPORT_AUTHORIZATION.walletSessionJwt,
  );
});

test('page-refresh passkey export rejects durable-context authenticator drift', async () => {
  const harness = new PasskeyEd25519ExportRefreshHarness('different-passkey-credential');
  await expect(
    exportEd25519YaoKeyWithFreshAuthorization(harness.deps(), {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      laneIdentity: passkeyLaneIdentity(WALLET_SESSION_ID),
      materialActivation: MATERIAL_ACTIVATION,
      options: {},
      flowId: 'flow-passkey-export-refresh-authenticator-drift',
    }),
  ).rejects.toThrow('durable Yao context identity mismatch');
  expect(harness.workerPayload).toBeNull();
});
