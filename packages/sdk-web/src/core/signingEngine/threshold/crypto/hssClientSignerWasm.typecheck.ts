import {
  buildEcdsaRoleLocalExportArtifactCommandWasm,
  createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm,
  finalizeEcdsaClientBootstrapCommandWasm,
  parseServerPlannedEcdsaHssContext,
  prepareEcdsaClientBootstrapCommandWasm,
  type ServerPlannedEcdsaHssContext,
  type ThresholdEcdsaHssRoleLocalClientContext,
  type ThresholdEcdsaHssStableKeyContext,
} from './hssClientSignerWasm';
import type {
  BuildEcdsaRoleLocalExportArtifactCommand,
  FinalizeEcdsaClientBootstrapCommand,
  PrepareEcdsaClientBootstrapCommand,
} from '@/core/platform/generated/signerCoreCommands';
import {
  toEcdsaHssSigningRootId,
  toEcdsaHssSigningRootVersion,
  toEcdsaHssThresholdKeyId,
} from '../../session/identity/emailOtpHssIdentity';
import { toWalletId } from '../../interfaces/ecdsaChainTarget';
import { toRpId } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { WorkerOperationContext } from '../../workerManager/executeWorkerOperation';
import type {
  WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest,
  WasmDeriveThresholdEd25519HssClientOutputMaskRequest,
  WasmOpenThresholdEd25519HssClientOutputRequest,
  WasmPrepareThresholdEd25519HssClientRequestRequest,
} from '../../../types/signer-worker';

const serverPlannedContext = parseServerPlannedEcdsaHssContext({
  walletId: 'wallet-user',
  rpId: 'wallet.example.test',
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
  ecdsaThresholdKeyId: 'ehss-stable',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
});
void (serverPlannedContext satisfies ServerPlannedEcdsaHssContext);

const locallyConstructedStableContext: ThresholdEcdsaHssStableKeyContext = {
  walletId: toWalletId('wallet-user'),
  rpId: toRpId('wallet.example.test'),
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-stable'),
  signingRootId: toEcdsaHssSigningRootId('project:dev'),
  signingRootVersion: toEcdsaHssSigningRootVersion('default'),
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
};

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context requires branded wallet ids.
  walletId: 'wallet-user',
} satisfies ThresholdEcdsaHssStableKeyContext);

void ({
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context requires branded ECDSA key ids.
  ecdsaThresholdKeyId: 'ehss-stable',
} satisfies ThresholdEcdsaHssStableKeyContext);

const stableContextWithSigningGrantId: ThresholdEcdsaHssStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile wallet session ids.
  signingGrantId: 'wsess-1',
};
void stableContextWithSigningGrantId;

const stableContextWithThresholdSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile threshold session ids.
  thresholdSessionId: 'tsess-1',
};
void stableContextWithThresholdSessionId;

const roleLocalClientContext: ThresholdEcdsaHssRoleLocalClientContext = {
  walletId: toWalletId('wallet-user'),
  rpId: toRpId('wallet.example.test'),
  ecdsaThresholdKeyId: toEcdsaHssThresholdKeyId('ehss-stable'),
  signingRootId: toEcdsaHssSigningRootId('project:dev'),
  signingRootVersion: toEcdsaHssSigningRootVersion('default'),
  keyPurpose: 'evm-signing',
  keyVersion: 'v1',
};

void ({
  ...roleLocalClientContext,
  // @ts-expect-error role-local client context excludes chain-specific HSS derivation fields.
  chainTarget: {
    kind: 'evm',
    namespace: 'eip155',
    chainId: 11155111,
    networkSlug: 'ethereum-sepolia',
  },
} satisfies ThresholdEcdsaHssRoleLocalClientContext);

declare const workerCtx: WorkerOperationContext;

async function assertRoleLocalBootstrapShape(): Promise<void> {
  const prepared = await prepareEcdsaClientBootstrapCommandWasm({
    command: {
      kind: 'prepare_ecdsa_client_bootstrap_v1',
      algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
      context: {
        walletId: roleLocalClientContext.walletId,
        rpId: roleLocalClientContext.rpId,
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 11155111,
          networkSlug: 'ethereum-sepolia',
        },
        ecdsaThresholdKeyId: roleLocalClientContext.ecdsaThresholdKeyId,
        signingRootId: roleLocalClientContext.signingRootId,
        signingRootVersion: roleLocalClientContext.signingRootVersion,
        keyPurpose: 'evm-signing',
        keyVersion: 'v1',
      },
      participants: {
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
      },
      secretSource: {
        kind: 'webauthn_prf_first',
        prfFirstB64u: 'prf-first',
        rpId: roleLocalClientContext.rpId,
        credentialIdB64u: 'credential-id',
      },
    } satisfies PrepareEcdsaClientBootstrapCommand,
    workerCtx,
  });
  void (prepared.pendingStateBlob.kind satisfies 'ecdsa_role_local_pending_state_blob_v1');
  void (prepared.clientBootstrap.hssClientSharePublicKey33B64u satisfies string);
}

async function assertEd25519RoleSeparatedNormalSigningClientShareShape(): Promise<void> {
  const share = await createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm({
    xClientBaseB64u: 'x-client-base',
    groupPublicKeyB64u: 'group-public-key',
    serverVerifyingShareB64u: 'server-verifying-share',
    serverCommitments: {
      hidingB64u: 'server-hiding',
      bindingB64u: 'server-binding',
    },
    signingPayloadB64u: 'signing-payload',
    workerCtx,
  });
  void (share.clientCommitments.hidingB64u satisfies string);
  void (share.clientCommitments.bindingB64u satisfies string);
  void (share.clientVerifyingShareB64u satisfies string);
  void (share.clientSignatureShareB64u satisfies string);

  // @ts-expect-error role-separated normal signing requires explicit server commitments.
  void createThresholdEd25519RoleSeparatedNormalSigningClientShareWasm({
    xClientBaseB64u: 'x-client-base',
    groupPublicKeyB64u: 'group-public-key',
    serverVerifyingShareB64u: 'server-verifying-share',
    signingPayloadB64u: 'signing-payload',
    workerCtx,
  });
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
      algorithm: 'ecdsa_hss_secp256k1_role_local_v1',
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: 'ready-state',
      },
      publicFacts: {
        walletId: roleLocalClientContext.walletId,
        rpId: roleLocalClientContext.rpId,
        chainTarget: {
          kind: 'evm',
          namespace: 'eip155',
          chainId: 11155111,
          networkSlug: 'ethereum-sepolia',
        },
        keyHandle: 'credential-id',
        ecdsaThresholdKeyId: roleLocalClientContext.ecdsaThresholdKeyId,
        signingRootId: roleLocalClientContext.signingRootId,
        signingRootVersion: roleLocalClientContext.signingRootVersion,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds: [1, 2],
        contextBinding32B64u: 'context-binding',
        hssClientSharePublicKey33B64u: 'client-public',
        relayerPublicKey33B64u: 'relayer-public',
        groupPublicKey33B64u: 'group-public',
        ethereumAddress: '0x1111111111111111111111111111111111111111',
      },
      authorization: {
        kind: 'passkey_export_authorized',
        walletId: roleLocalClientContext.walletId,
        rpId: roleLocalClientContext.rpId,
        credentialIdB64u: 'credential-id',
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

const serializedPrepareClientRequest = {
  sessionSource: 'serialized_state',
  evaluatorDriverStateB64u: 'evaluator-state',
  clientOtOfferMessageB64u: 'client-ot-offer',
  yClientB64u: 'y-client',
  tauClientB64u: 'tau-client',
} satisfies WasmPrepareThresholdEd25519HssClientRequestRequest;
void serializedPrepareClientRequest;

const workerHandlePrepareClientRequest: WasmPrepareThresholdEd25519HssClientRequestRequest = {
  // @ts-expect-error prepare_client_request creates the worker handle from
  // serialized state; caller-provided handles are only valid for staged build.
  sessionSource: 'worker_handle',
  // @ts-expect-error caller-provided handles are only valid for staged build.
  workerSessionHandle: 'ed25519-hss-client-session-1',
  clientOtOfferMessageB64u: 'client-ot-offer',
  yClientB64u: 'y-client',
  tauClientB64u: 'tau-client',
};
void workerHandlePrepareClientRequest;

const maskedStagedArtifactRequest = {
  sessionSource: 'serialized_state',
  evaluatorDriverStateB64u: 'evaluator-state',
  clientRequestMessageB64u: 'client-request',
  evaluatorOtStateB64u: 'evaluator-ot-state',
  serverInputDeliveryB64u: 'server-input-delivery',
  clientOutputMaskB64u: 'client-mask',
} satisfies WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest;
void maskedStagedArtifactRequest;

const workerHandleStagedArtifactRequest = {
  sessionSource: 'worker_handle',
  workerSessionHandle: 'ed25519-hss-client-session-1',
  clientRequestMessageB64u: 'client-request',
  evaluatorOtStateB64u: 'evaluator-ot-state',
  serverInputDeliveryB64u: 'server-input-delivery',
  clientOutputMaskB64u: 'client-mask',
} satisfies WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest;
void workerHandleStagedArtifactRequest;

// @ts-expect-error client-owned HSS artifact construction requires a client output mask.
const missingStagedArtifactMask: WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest =
  {
    sessionSource: 'serialized_state',
    evaluatorDriverStateB64u: 'evaluator-state',
    clientRequestMessageB64u: 'client-request',
    evaluatorOtStateB64u: 'evaluator-ot-state',
    serverInputDeliveryB64u: 'server-input-delivery',
  };
void missingStagedArtifactMask;

const clientOutputMaskDerivationRequest = {
  signingRootId: 'root',
  nearAccountId: 'alice.testnet',
  keyPurpose: 'near-ed25519-signing',
  keyVersion: 'v1',
  participantIds: [1, 2],
  derivationVersion: 1,
  contextBindingB64u: 'context-binding',
  operation: 'tx_signing',
  relayerKeyId: 'relayer-key',
  clientRecoverableSecretB64u: 'client-secret',
} satisfies WasmDeriveThresholdEd25519HssClientOutputMaskRequest;
void clientOutputMaskDerivationRequest;

// @ts-expect-error client output mask derivation requires recoverable client secret material.
const missingClientOutputMaskDerivationSecret: WasmDeriveThresholdEd25519HssClientOutputMaskRequest =
  {
    signingRootId: 'root',
    nearAccountId: 'alice.testnet',
    keyPurpose: 'near-ed25519-signing',
    keyVersion: 'v1',
    participantIds: [1, 2],
    derivationVersion: 1,
    contextBindingB64u: 'context-binding',
    operation: 'tx_signing',
    relayerKeyId: 'relayer-key',
  };
void missingClientOutputMaskDerivationSecret;

const maskedClientOutputOpenRequest = {
  sessionSource: 'serialized_state',
  evaluatorDriverStateB64u: 'evaluator-state',
  clientOutputMessageB64u: 'client-output',
  clientOutputMaskB64u: 'client-mask',
} satisfies WasmOpenThresholdEd25519HssClientOutputRequest;
void maskedClientOutputOpenRequest;

const workerHandleClientOutputOpenRequest: WasmOpenThresholdEd25519HssClientOutputRequest = {
  // @ts-expect-error client output opening stays on serialized state until
  // handle lifecycle is explicitly extended to the open phase.
  sessionSource: 'worker_handle',
  // @ts-expect-error caller-provided handles are only valid for staged build.
  workerSessionHandle: 'ed25519-hss-client-session-1',
  clientOutputMessageB64u: 'client-output',
  clientOutputMaskB64u: 'client-mask',
};
void workerHandleClientOutputOpenRequest;

// @ts-expect-error client output opening requires the client output mask.
const missingOpenClientOutputMask: WasmOpenThresholdEd25519HssClientOutputRequest = {
  sessionSource: 'serialized_state',
  evaluatorDriverStateB64u: 'evaluator-state',
  clientOutputMessageB64u: 'client-output',
};
void missingOpenClientOutputMask;
