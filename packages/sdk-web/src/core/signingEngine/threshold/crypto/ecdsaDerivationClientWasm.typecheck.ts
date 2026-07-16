import {
  buildEcdsaRoleLocalExportArtifactCommandWasm,
  finalizeEcdsaClientBootstrapCommandWasm,
  parseServerPlannedEcdsaDerivationContext,
  prepareEcdsaClientBootstrapCommandWasm,
  type ServerPlannedEcdsaDerivationContext,
  type ThresholdEcdsaDerivationRoleLocalClientContext,
  type ThresholdEcdsaDerivationStableKeyContext,
} from './ecdsaDerivationClientWasm';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand,
  FinalizeEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapCommand,
} from '@/core/platform/generated/signerCoreCommands';
import {
  toEcdsaDerivationSigningRootId,
  toEcdsaDerivationSigningRootVersion,
  toEcdsaDerivationThresholdKeyId,
} from '../../session/identity/emailOtpEcdsaDerivationIdentity';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
const serverPlannedContext = parseServerPlannedEcdsaDerivationContext({
  walletId: 'wallet-user',
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: 'wallet-user',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
  }),
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
  ecdsaThresholdKeyId: 'ederivation-stable',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
});
void (serverPlannedContext satisfies ServerPlannedEcdsaDerivationContext);

const locallyConstructedStableContext: ThresholdEcdsaDerivationStableKeyContext = {
  walletId: toWalletId('wallet-user'),
  ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId('ederivation-stable'),
  signingRootId: toEcdsaDerivationSigningRootId('project:dev'),
  signingRootVersion: toEcdsaDerivationSigningRootVersion('default'),
};

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context requires branded wallet ids.
  walletId: 'wallet-user',
} satisfies ThresholdEcdsaDerivationStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context requires branded ECDSA key ids.
  ecdsaThresholdKeyId: 'ederivation-stable',
} satisfies ThresholdEcdsaDerivationStableKeyContext);

const stableContextWithSigningGrantId: ThresholdEcdsaDerivationStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects volatile wallet session ids.
  signingGrantId: 'wsess-1',
};
void stableContextWithSigningGrantId;

const stableContextWithThresholdSessionId: ThresholdEcdsaDerivationStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects volatile threshold session ids.
  thresholdSessionId: 'tsess-1',
};
void stableContextWithThresholdSessionId;

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects SDK wallet key aliases.
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId: 'wallet-user',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
  }),
} satisfies ThresholdEcdsaDerivationStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects chain targets.
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
} satisfies ThresholdEcdsaDerivationStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects caller-provided key purpose.
  keyPurpose: 'evm-signing',
} satisfies ThresholdEcdsaDerivationStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA DERIVATION key context rejects protocol key version labels.
  keyVersion: 'v1',
} satisfies ThresholdEcdsaDerivationStableKeyContext);

const roleLocalClientContext: ThresholdEcdsaDerivationRoleLocalClientContext = {
  walletId: toWalletId('wallet-user'),
  ecdsaThresholdKeyId: toEcdsaDerivationThresholdKeyId('ederivation-stable'),
  signingRootId: toEcdsaDerivationSigningRootId('project:dev'),
  signingRootVersion: toEcdsaDerivationSigningRootVersion('default'),
};
const passkeyRpId = toRpId('wallet.example.test');

void ({
  ...roleLocalClientContext,
  // @ts-expect-error role-local client context excludes chain-specific DERIVATION derivation fields.
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
} satisfies ThresholdEcdsaDerivationRoleLocalClientContext);

declare const workerCtx: WorkerOperationContext;

async function assertRoleLocalBootstrapShape(): Promise<void> {
  const prepared = await prepareEcdsaClientBootstrapCommandWasm({
    command: {
      kind: 'prepare_ecdsa_client_bootstrap_v1',
      algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
      context: {
        applicationBindingDigestB64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
      },
      participants: {
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
      },
      secretSource: {
        kind: 'webauthn_prf_first',
        prfFirstB64u: 'prf-first',
        rpId: passkeyRpId,
        credentialIdB64u: 'credential-id',
      },
    } satisfies PrepareEcdsaClientBootstrapCommand,
    workerCtx,
  });
  void (prepared.pendingStateBlob.kind satisfies 'ecdsa_role_local_pending_state_blob_v1');
  void (prepared.clientBootstrap.derivationClientSharePublicKey33B64u satisfies string);
}

async function assertRoleLocalFinalizeShape(): Promise<void> {
  const finalized = await finalizeEcdsaClientBootstrapCommandWasm({
    command: {
      kind: 'finalize_ecdsa_client_bootstrap_v1',
      pendingStateBlob: {
        kind: 'ecdsa_role_local_pending_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'pending-state',
      },
      relayerPublicIdentity: {
        relayerKeyId: 'relayer-key',
        relayerPublicKey33B64u: 'relayer-public',
        groupPublicKey33B64u: 'group-public',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
      },
    } satisfies FinalizeEcdsaClientBootstrapCommand,
    workerCtx,
  });
  void (finalized.stateBlob.kind satisfies 'ecdsa_role_local_state_blob_v1');
  void (finalized.publicFacts.groupPublicKey33B64u satisfies string);
}

async function assertRoleLocalExportShape(): Promise<void> {
  const artifact = await buildEcdsaRoleLocalExportArtifactCommandWasm({
    command: {
      kind: 'build_ecdsa_role_local_export_artifact_v1',
      algorithm: 'router_ab_ecdsa_derivation_secp256k1_role_local_v1',
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'ready-state',
      },
      publicFacts: {
        applicationBindingDigestB64u: 'BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc',
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        contextBinding32B64u: 'context-binding',
        derivationClientSharePublicKey33B64u: 'client-public',
        relayerPublicKey33B64u: 'relayer-public',
        groupPublicKey33B64u: 'group-public',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
      },
      serverExportShare32B64u: 'server-export-share',
    } satisfies BuildEcdsaRoleLocalExportArtifactCommand,
    workerCtx,
  });
  void (artifact.privateKeyHex satisfies string);
}

void assertRoleLocalBootstrapShape;
void assertRoleLocalFinalizeShape;
void assertRoleLocalExportShape;
