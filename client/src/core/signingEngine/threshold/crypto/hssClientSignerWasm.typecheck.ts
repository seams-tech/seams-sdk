import {
  buildThresholdEcdsaHssRoleLocalClientBootstrapWasm,
  parseServerPlannedEcdsaHssContext,
  type ServerPlannedEcdsaHssContext,
  type ThresholdEcdsaHssRoleLocalClientContext,
  type ThresholdEcdsaHssStableKeyContext,
} from './hssClientSignerWasm';
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

const stableContextWithWalletSigningSessionId: ThresholdEcdsaHssStableKeyContext = {
  ...locallyConstructedStableContext,
  // @ts-expect-error stable ECDSA HSS key context rejects volatile wallet session ids.
  walletSigningSessionId: 'wsess-1',
};
void stableContextWithWalletSigningSessionId;

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
  const bootstrap = await buildThresholdEcdsaHssRoleLocalClientBootstrapWasm({
    context: roleLocalClientContext,
    clientRootShare32B64u: 'client-root-share',
    workerCtx,
  });
  void (bootstrap.clientCaitSithInput satisfies {
    participantId: 1;
    mappedPrivateShare32B64u: string;
    verifyingShare33B64u: string;
  });
}

void assertRoleLocalBootstrapShape;

const maskedStagedArtifactRequest = {
  evaluatorDriverStateB64u: 'evaluator-state',
  clientRequestMessageB64u: 'client-request',
  evaluatorOtStateB64u: 'evaluator-ot-state',
  serverInputDeliveryB64u: 'server-input-delivery',
  clientOutputMaskB64u: 'client-mask',
} satisfies WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest;
void maskedStagedArtifactRequest;

// @ts-expect-error client-owned HSS artifact construction requires a client output mask.
const missingStagedArtifactMask: WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest =
  {
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
  evaluatorDriverStateB64u: 'evaluator-state',
  clientOutputMessageB64u: 'client-output',
  clientOutputMaskB64u: 'client-mask',
} satisfies WasmOpenThresholdEd25519HssClientOutputRequest;
void maskedClientOutputOpenRequest;

// @ts-expect-error client output opening requires the client output mask.
const missingOpenClientOutputMask: WasmOpenThresholdEd25519HssClientOutputRequest = {
  evaluatorDriverStateB64u: 'evaluator-state',
  clientOutputMessageB64u: 'client-output',
};
void missingOpenClientOutputMask;
