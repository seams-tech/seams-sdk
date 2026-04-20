import { buildCanonicalSmartAccountDeploymentManifest } from '../../server/src/core/smartAccountDeploymentManifest.ts';
import { syncCanonicalSmartAccountDeploymentManifest } from '../../server/src/router/smartAccountDeploymentManifest.ts';
import { buildThresholdEcdsaBootstrapUndeployedSignerSet } from '../../client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence.ts';

const accountAddress = `0x${'11'.repeat(20)}`;

const manifest = buildCanonicalSmartAccountDeploymentManifest({
  recoverySubject: {
    version: 'smart_account_recovery_subject_v1',
    userId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    chainIdKey: 'evm:11155111',
    accountAddress,
    createdAtMs: 1,
    updatedAtMs: 1,
    metadata: {
      chain: 'evm',
      chainId: 11155111,
      accountModel: 'erc4337',
      deployed: false,
      counterfactualAddress: accountAddress,
    },
  },
  signers: [
    {
      version: 'account_signer_v1',
      userId: 'alice.testnet',
      chainIdKey: 'evm:11155111',
      accountAddress,
      signerType: 'threshold',
      signerId: accountAddress,
      status: 'active',
      createdAtMs: 1,
      updatedAtMs: 1,
      metadata: {
        relayerKeyId: 'rk-1',
        thresholdEcdsaPublicKeyB64u: 'group-key',
        participantIds: [1, 2],
      },
    },
  ],
  materializedAtMs: 1234,
});

const clientUndeployedSignerSet = buildThresholdEcdsaBootstrapUndeployedSignerSet({
  accountAddress,
  bootstrap: {
    thresholdEcdsaKeyRef: {
      type: 'threshold-ecdsa-secp256k1',
      userId: 'alice.testnet',
      relayerUrl: 'https://relayer.example',
      ecdsaThresholdKeyId: 'ehss-1',
      signingRootId: 'proj_local:dev',
      backendBinding: {
        relayerKeyId: 'rk-1',
        clientVerifyingShareB64u: 'client-share',
      },
      participantIds: [1, 2],
    },
    keygen: {
      ok: true,
      relayerKeyId: 'rk-1',
      thresholdEcdsaPublicKeyB64u: 'group-key',
      ethereumAddress: accountAddress,
      participantIds: [1, 2],
      clientVerifyingShareB64u: 'client-share',
    },
    session: {
      ok: true,
      sessionId: 'session-1',
      expiresAtMs: 1,
      remainingUses: 1,
      clientVerifyingShareB64u: 'client-share',
    },
  },
});

const syncedWrites: Array<Record<string, unknown>> = [];

await syncCanonicalSmartAccountDeploymentManifest({
  authService: {
    async getSmartAccountRecoverySubjectByAccount() {
      return {
        ok: true,
        record: {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress,
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'evm',
            chainId: 11155111,
            accountModel: 'erc4337',
            deployed: false,
            counterfactualAddress: accountAddress,
          },
        },
      };
    },
    async listAccountSignersByAccount() {
      return {
        ok: true,
        records: [
          {
            version: 'account_signer_v1',
            userId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress,
            signerType: 'threshold',
            signerId: accountAddress,
            status: 'active',
            createdAtMs: 1,
            updatedAtMs: 1,
            metadata: {
              relayerKeyId: 'rk-1',
              thresholdEcdsaPublicKeyB64u: 'group-key',
              participantIds: [1, 2],
            },
          },
        ],
      };
    },
    async putSmartAccountRecoverySubject(record: Record<string, unknown>) {
      syncedWrites.push(record);
      return { ok: true, record };
    },
  } as never,
  chainIdKey: 'evm:11155111',
  accountAddress,
  materializedAtMs: 4321,
});

console.log(
  'RESULT:' +
    JSON.stringify({
      manifestUndeployedSignerSet: manifest?.undeployedSignerSet || null,
      clientUndeployedSignerSet,
      syncedMetadataUndeployedSignerSet:
        (syncedWrites[0]?.metadata as any)?.deploymentManifest?.[
          'undeployedSignerSet'
        ] || null,
    }),
);
