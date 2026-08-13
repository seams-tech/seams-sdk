import { resolveNearNetwork } from '@/core/config/chains';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import {
  WorkerRequestType,
  WorkerResponseType,
  type DelegatePayload,
  type TransactionPayload,
  type WasmSignedDelegate,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import {
  buildThresholdEd25519DelegateSigningPayloadWasm,
  buildThresholdEd25519NearTxUnsignedBorshWasm,
  decodeThresholdEd25519SignedNearTxBorshWasm,
  finalizeThresholdEd25519NearTxFromSignatureWasm,
  finalizeThresholdEd25519DelegateFromSignatureWasm,
} from '@/core/signingEngine/chains/near/nearSignerWasm';
import type { RouterAbEd25519YaoActiveClientV1 } from '@/core/signingEngine/threshold/ed25519/yaoClient';
import type { TransactionContext } from '@/core/types/rpc';
import { ActionType, fromActionArgsWasm, type ActionArgsWasm } from '@/core/types/actions';
import type { NearSigningRuntimeDeps } from '@/core/signingEngine/interfaces/runtime';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildRouterAbEd25519DelegateActionPrepareRequestV2,
  buildRouterAbEd25519NearTransactionPrepareRequestV2,
  buildRouterAbEd25519Nep413PrepareRequestV2,
  buildRouterAbEd25519NormalSigningFinalizeRequestV2,
  finalizeRouterAbNormalSigningV2,
  prepareRouterAbNormalSigningV2,
  routerAbCanonicalWireBytesToB64u,
  routerAbNormalSigningActionFingerprint,
  type RouterAbNormalSigningPrepareRequestV2BuildResult,
  type RouterAbNormalSigningScopeV2Wire,
  type RouterAbEd25519NormalSigningCredential,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  requireRouterAbEd25519NormalSigningReadyState,
} from '../../../session/warmCapabilities/routerAbWalletSessionCredential';
import type {
  AuthorizedRouterAbEd25519WalletSessionState,
  ResolvedRouterAbEd25519WalletSessionState,
} from '../../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { base58Decode } from '@shared/utils/base58';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionOperationFingerprint,
  type ThresholdEd25519NearAction,
} from '@shared/threshold/ed25519OperationFingerprint';
import { nearEd25519YaoMaterialActivationFromMetadata } from '@/core/signingEngine/session/material/nearEd25519YaoMaterialActivation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import {
  buildCapabilityOperationEnvelope,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import {
  parseCapabilityId,
  parseCapabilityOperationId,
  parsePrincipalId,
  parseTenantId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseSigningOperationFingerprintDigest } from '../../../session/planning/operationFingerprint';
import {
  requireNearOperationStepUpMaterialActivation,
  type PreparedNearOperationStepUp,
} from './operationStepUpPreparation';
import {
  issueEd25519OperationStepUpAuthorization,
  type Ed25519OperationStepUpCredential,
  type Ed25519OperationStepUpProof,
} from '@/core/signingEngine/threshold/ed25519/walletSession';
import type { NearEd25519YaoSigningPreparation } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import type { SelectedEd25519Lane } from '@/core/signingEngine/session/identity/laneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import type {
  NearEd25519StepUpAuthorization,
  NearEd25519OperationStepUpAuthorization,
  NearEd25519YaoOperationMaterialFacts,
} from '@/core/signingEngine/interfaces/near';

const ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS = 120_000;

async function nearOperationStepUpCredential(args: {
  ctx: NearSigningRuntimeDeps;
  walletId: WalletId;
  relayerUrl: string;
  proof: Ed25519OperationStepUpProof;
}): Promise<Ed25519OperationStepUpCredential> {
  const credential = await args.ctx.resolveOperationStepUpCredential({
    walletId: args.walletId,
    relayerUrl: args.relayerUrl,
    proof: args.proof,
  });
  if (credential.kind === 'wallet_session_jwt') {
    throw new Error(
      '[SigningEngine][near] operation step-up requires an app-session credential',
    );
  }
  return credential;
}

export function requireIssuedNearEd25519OperationStepUpAuthorization(args: {
  prepared: Extract<
    PreparedNearOperationStepUp,
    { kind: 'near_signature_only' | 'near_transaction' }
  >;
  issuedAuthorization: NearEd25519OperationStepUpAuthorization;
}): void {
  const authorization = args.prepared.prepare.request.scope.authorization;
  if (authorization.kind !== 'operation_step_up') {
    throw new Error('[SigningEngine][near] operation step-up authorization scope is missing');
  }
  if (args.issuedAuthorization.kind !== 'verified_step_up') {
    throw new Error('[SigningEngine][near] operation step-up authorization is invalid');
  }
}

export type RouterAbEd25519SignatureOnlyIntentWire =
  | {
      kind: 'nep413_message_v1';
      message: string;
      recipient: string;
      nonce: string;
      state?: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      delegate: {
        senderId: string;
        receiverId: string;
        actions: readonly ThresholdEd25519NearAction[];
        nonce: string;
        maxBlockHeight: string;
        publicKey: string;
      };
    };

export type RouterAbEd25519NearTransactionNormalSigningResult =
  | {
      kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1';
      authorization: 'operation_step_up';
      issuedAuthorization: NearEd25519OperationStepUpAuthorization;
      okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
      transactionHash: string;
    }
  | {
      kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1';
      authorization: 'reusable_wallet_session';
      issuedAuthorization?: never;
      okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
      transactionHash: string;
    };

export type RouterAbEd25519SignatureOnlyNormalSigningResult =
  | {
      kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1';
      authorization: 'operation_step_up';
      operationId: string;
      signatureB64u: string;
      signerPublicKey: string;
      issuedAuthorization: NearEd25519OperationStepUpAuthorization;
    }
  | {
      kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1';
      authorization: 'reusable_wallet_session';
      operationId: string;
      signatureB64u: string;
      signerPublicKey: string;
    };

type RouterAbEd25519NormalSigningFinalized = {
  signatureB64u: string;
  signerPublicKey: string;
};

function requireParticipantId(args: {
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  role: 'client' | 'relayer';
}): number {
  const participantId = args.thresholdKeyMaterial.participants.find(
    (participant) => participant.role === args.role,
  )?.id;
  if (!participantId) {
    throw new Error(`threshold-ed25519 signing requires ${args.role} participant id`);
  }
  return participantId;
}

function digestB64uToHex(signingDigestB64u: string): string {
  return [...base64UrlDecode(signingDigestB64u)]
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

function normalizeNearNetworkId(ctx: NearSigningRuntimeDeps): 'testnet' | 'mainnet' {
  return resolveNearNetwork(ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains);
}

function createRouterAbNormalSigningRequestId(operationId: SigningOperationId): string {
  const cryptoApi = globalThis.crypto;
  if (cryptoApi && typeof cryptoApi.randomUUID === 'function') {
    return `router-ab-normal-signing/${operationId}/${cryptoApi.randomUUID()}`;
  }
  if (cryptoApi && typeof cryptoApi.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    cryptoApi.getRandomValues(bytes);
    return `router-ab-normal-signing/${operationId}/${base64UrlEncode(bytes)}`;
  }
  throw new Error('secure randomness is unavailable for Router A/B normal-signing request id');
}

function requireAuthorizationParse<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (!result.ok) throw new Error(result.error.message);
  return result.value;
}

function routerAbNormalSigningExpiresAtMs(args: {
  walletSessionExpiresAtMs: number;
  requestedTtlMs: number;
}): number {
  const walletSessionExpiresAtMs = Math.floor(Number(args.walletSessionExpiresAtMs));
  const requestedTtlMs = Math.floor(Number(args.requestedTtlMs));
  if (!Number.isFinite(walletSessionExpiresAtMs) || walletSessionExpiresAtMs <= Date.now()) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 Wallet Session is expired');
  }
  if (!Number.isFinite(requestedTtlMs) || requestedTtlMs <= 0) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 request TTL is invalid');
  }
  return Math.min(walletSessionExpiresAtMs, Date.now() + requestedTtlMs);
}

function buildRouterAbNormalSigningScope(args: {
  thresholdSessionId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: AuthorizedRouterAbEd25519WalletSessionState;
  walletId: WalletId;
  operationId: SigningOperationId;
}): RouterAbNormalSigningScopeV2Wire | null {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing wallet id');
  }
  const metadata = args.activeClient.metadata();
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  return {
    request_id: createRouterAbNormalSigningRequestId(args.operationId),
    account_id: walletId,
    authorization: {
      kind: 'reusable_wallet_session',
      wallet_session_id: args.walletSessionState.walletSessionId,
    },
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: materialActivation.activationId,
      capability: materialActivation.capability,
      material_owner: materialActivation.materialOwner,
      key_binding: materialActivation.keyBinding,
      lifecycle_binding: materialActivation.lifecycleBinding,
      signing_worker: materialActivation.signingWorker,
    },
    signing_worker_id: routerAbState.signingWorkerId,
  };
}

function buildRouterAbOperationStepUpScope(args: {
  materialActivation: MpcMaterialActivationRef;
  materialFacts: NearEd25519YaoOperationMaterialFacts;
  walletId: WalletId;
  operationId: SigningOperationId;
}): RouterAbNormalSigningScopeV2Wire {
  const routerAbState = args.materialFacts.routerAbNormalSigning;
  if (!routerAbState) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing');
  }
  return {
    request_id: createRouterAbNormalSigningRequestId(args.operationId),
    account_id: String(args.walletId),
    authorization: {
      kind: 'operation_step_up',
    },
    material_activation: {
      kind: 'mpc_material_activation_ref',
      activation_id: args.materialActivation.activationId,
      capability: args.materialActivation.capability,
      material_owner: args.materialActivation.materialOwner,
      key_binding: args.materialActivation.keyBinding,
      lifecycle_binding: args.materialActivation.lifecycleBinding,
      signing_worker: args.materialActivation.signingWorker,
    },
    signing_worker_id: routerAbState.signingWorkerId,
  };
}

function routerAbDelegateActionsForWasm(
  actions: readonly ThresholdEd25519NearAction[],
): ActionArgsWasm[] {
  return actions.map((action): ActionArgsWasm => {
    switch (action.action_type) {
      case 'CreateAccount':
        return { action_type: ActionType.CreateAccount };
      case 'DeployContract':
        return { action_type: ActionType.DeployContract, code: [...action.code] };
      case 'FunctionCall':
        return {
          action_type: ActionType.FunctionCall,
          method_name: action.method_name,
          args: action.args,
          gas: action.gas,
          deposit: action.deposit,
        };
      case 'Transfer':
        return { action_type: ActionType.Transfer, deposit: action.deposit };
      case 'Stake':
        return {
          action_type: ActionType.Stake,
          stake: action.stake,
          public_key: action.public_key,
        };
      case 'AddKey':
        return {
          action_type: ActionType.AddKey,
          public_key: action.public_key,
          access_key: action.access_key,
        };
      case 'DeleteKey':
        return { action_type: ActionType.DeleteKey, public_key: action.public_key };
      case 'DeleteAccount':
        return {
          action_type: ActionType.DeleteAccount,
          beneficiary_id: action.beneficiary_id,
        };
      case 'SignedDelegate': {
        const delegateActions = routerAbDelegateActionsForWasm(action.delegate_action.actions).map(
          fromActionArgsWasm,
        );
        return {
          action_type: ActionType.SignedDelegate,
          delegate_action: {
            senderId: action.delegate_action.senderId,
            receiverId: action.delegate_action.receiverId,
            actions: delegateActions,
            nonce: action.delegate_action.nonce,
            maxBlockHeight: action.delegate_action.maxBlockHeight,
            publicKey: {
              keyType: action.delegate_action.publicKey.keyType,
              keyData: [...action.delegate_action.publicKey.keyData],
            },
          },
          signature: {
            keyType: action.signature.keyType,
            signatureData: [...action.signature.signatureData],
          },
        };
      }
      case 'DeployGlobalContract':
        return {
          action_type: ActionType.DeployGlobalContract,
          code: [...action.code],
          deploy_mode: action.deploy_mode,
        };
      case 'UseGlobalContract':
        return 'account_id' in action
          ? { action_type: ActionType.UseGlobalContract, account_id: action.account_id }
          : { action_type: ActionType.UseGlobalContract, code_hash: action.code_hash };
    }
  });
}

export async function finalizeThresholdEd25519DelegateSignatureResult(args: {
  ctx: NearSigningRuntimeDeps;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  signatureB64u: string;
}): Promise<{ signedDelegate: WasmSignedDelegate; hash: string }> {
  const signedDelegate = await finalizeThresholdEd25519DelegateFromSignatureWasm({
    delegate: args.delegate,
    signingDigestB64u: args.signingDigestB64u,
    signatureB64u: args.signatureB64u,
    workerCtx: args.ctx,
  });
  return {
    signedDelegate,
    hash: digestB64uToHex(args.signingDigestB64u),
  };
}

function requireMatchingRouterAbEd25519Identity(
  actual: string | number,
  expected: string | number,
  label: string,
): void {
  if (String(actual) !== String(expected)) {
    throw new Error(`Router A/B Ed25519 active Client ${label} mismatch`);
  }
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function requireWireBytes32(value: readonly number[], label: string): Uint8Array {
  if (
    value.length !== 32 ||
    value.some((byte) => !Number.isInteger(byte) || byte < 0 || byte > 255)
  ) {
    throw new Error(`Router A/B normal-signing ${label} must contain 32 bytes`);
  }
  return Uint8Array.from(value);
}

function decodeThresholdEd25519PublicKey(publicKey: string): Uint8Array {
  const normalized = ensureEd25519Prefix(publicKey);
  if (!normalized.startsWith('ed25519:')) {
    throw new Error('Router A/B Ed25519 signer public key must use ed25519');
  }
  const decoded = base58Decode(normalized.slice('ed25519:'.length));
  if (decoded.length !== 32) {
    throw new Error('Router A/B Ed25519 signer public key must decode to 32 bytes');
  }
  return decoded;
}

function requireActiveClientMatchesNormalSigningOperation(args: {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  authorization:
    | { kind: 'reusable_wallet_session'; walletSessionId: string }
    | { kind: 'operation_step_up' };
  materialFacts: NearEd25519YaoOperationMaterialFacts;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  signingWorkerId: string;
  signingWorkerVerifyingShare: Uint8Array;
}): void {
  const metadata = args.activeClient.metadata();
  const materialActivation = nearEd25519YaoMaterialActivationFromMetadata(metadata);
  const signer = args.materialFacts.signer;
  const clientParticipantId = requireParticipantId({
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    role: 'client',
  });
  const relayerParticipantId = requireParticipantId({
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    role: 'relayer',
  });
  if (args.thresholdKeyMaterial.participants.length !== 2) {
    throw new Error('Router A/B Ed25519 active Client requires exactly two participants');
  }

  requireMatchingRouterAbEd25519Identity(
    metadata.scope.account_id,
    args.prepare.request.scope.account_id,
    'scope account',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.scope.threshold_session_id,
    args.materialFacts.thresholdSessionId,
    'threshold session',
  );
  requireMatchingRouterAbEd25519Identity(metadata.scope.account_id, args.walletId, 'scope wallet');
  requireMatchingRouterAbEd25519Identity(
    materialActivation.activationId,
    args.prepare.request.scope.material_activation.activation_id,
    'material activation',
  );
  requireMatchingRouterAbEd25519Identity(
    materialActivation.capability,
    args.prepare.request.scope.material_activation.capability,
    'material capability',
  );
  requireMatchingRouterAbEd25519Identity(
    materialActivation.materialOwner,
    args.prepare.request.scope.material_activation.material_owner,
    'material owner',
  );
  requireMatchingRouterAbEd25519Identity(
    materialActivation.keyBinding,
    args.prepare.request.scope.material_activation.key_binding,
    'material key binding',
  );
  requireMatchingRouterAbEd25519Identity(
    materialActivation.lifecycleBinding,
    args.prepare.request.scope.material_activation.lifecycle_binding,
    'material lifecycle',
  );
  requireMatchingRouterAbEd25519Identity(
    materialActivation.signingWorker,
    args.prepare.request.scope.material_activation.signing_worker,
    'material SigningWorker',
  );
  const authorization = args.prepare.request.scope.authorization;
  if (authorization.kind !== args.authorization.kind) {
    throw new Error('Router A/B Ed25519 authorization kind mismatch');
  }
  switch (args.authorization.kind) {
    case 'reusable_wallet_session':
      if (authorization.kind !== 'reusable_wallet_session') {
        throw new Error('Router A/B Ed25519 reusable authorization is missing');
      }
      requireMatchingRouterAbEd25519Identity(
        authorization.wallet_session_id,
        args.authorization.walletSessionId,
        'authorization session',
      );
      break;
    case 'operation_step_up':
      if (authorization.kind !== 'operation_step_up') {
        throw new Error('Router A/B Ed25519 operation step-up authorization is missing');
      }
      break;
    default:
      args.authorization satisfies never;
  }
  requireMatchingRouterAbEd25519Identity(
    metadata.scope.signing_worker_id,
    args.prepare.request.scope.signing_worker_id,
    'scope SigningWorker',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.scope.signing_worker_id,
    args.signingWorkerId,
    'prepare SigningWorker',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.wallet_id,
    args.walletId,
    'application wallet',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.wallet_id,
    signer.account.wallet.walletId,
    'lane wallet',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.near_ed25519_signing_key_id,
    signer.nearEd25519SigningKeyId,
    'signing key',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.signing_root_id,
    args.materialFacts.signingRootId,
    'signing root',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.key_creation_signer_slot,
    signer.signerSlot,
    'signer slot',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.applicationBinding.key_creation_signer_slot,
    args.thresholdKeyMaterial.signerSlot,
    'key-material signer slot',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.participantIds[0],
    clientParticipantId,
    'Client participant',
  );
  requireMatchingRouterAbEd25519Identity(
    metadata.participantIds[1],
    relayerParticipantId,
    'SigningWorker participant',
  );

  const registeredPublicKey = decodeThresholdEd25519PublicKey(args.thresholdKeyMaterial.publicKey);
  if (!sameBytes(metadata.registeredPublicKey, registeredPublicKey)) {
    throw new Error('Router A/B Ed25519 active Client registered public key mismatch');
  }
  if (!sameBytes(metadata.signingWorkerVerifyingShare, args.signingWorkerVerifyingShare)) {
    throw new Error('Router A/B Ed25519 active Client SigningWorker verifying share mismatch');
  }
}

type RouterAbEd25519NormalSigningSignatureBase = {
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  signingDigestB64u: string;
  signingPayloadLabel: string;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  credential: RouterAbEd25519NormalSigningCredential;
};

type RouterAbEd25519NormalSigningSignatureArgs =
  RouterAbEd25519NormalSigningSignatureBase &
    (
      | {
          authorization: 'reusable_wallet_session';
          walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
          materialFacts?: never;
        }
      | {
          authorization: 'operation_step_up';
          materialFacts: NearEd25519YaoOperationMaterialFacts;
          walletSessionState?: never;
        }
    );

async function tryFinalizeRouterAbEd25519NormalSigningSignature(
  args: RouterAbEd25519NormalSigningSignatureArgs,
): Promise<RouterAbEd25519NormalSigningFinalized> {
  const signingPayload = base64UrlDecode(args.signingDigestB64u);
  if (signingPayload.length !== 32) {
    throw new Error(`Router A/B normal-signing ${args.signingPayloadLabel} must be 32 bytes`);
  }
  const admittedDigest = requireWireBytes32(
    args.prepare.admissionMaterial.admittedSigningDigest.bytes,
    'admitted digest',
  );
  if (!sameBytes(signingPayload, admittedDigest)) {
    throw new Error('Router A/B normal-signing admitted digest mismatch');
  }

  if (args.authorization === 'reusable_wallet_session') {
    requireRouterAbEd25519NormalSigningReadyState({
      state: args.walletSessionState,
      thresholdSessionId: args.thresholdSessionId,
      nearAccountId: args.nearAccountId,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
    });
  }
  const materialFacts =
    args.authorization === 'reusable_wallet_session'
      ? {
          thresholdSessionId: args.walletSessionState.thresholdSessionId,
          signer: args.walletSessionState.signingLane.identity.signer,
          signingRootId: args.walletSessionState.signingRootId,
          signingRootVersion: args.walletSessionState.signingRootVersion,
          routerAbNormalSigning: args.walletSessionState.routerAbNormalSigning,
          runtimePolicyScope: args.walletSessionState.runtimePolicyScope,
          relayerUrl: args.walletSessionState.relayerUrl,
        }
      : args.materialFacts;
  const prepareResponse = await prepareRouterAbNormalSigningV2({
    relayServerUrl: materialFacts.relayerUrl,
    credential: args.credential,
    request: args.prepare.request,
  });
  requireRouterAbNormalSigningPrepareMatchesRequest({
    request: args.prepare.request,
    signingPayloadDigest: args.prepare.admissionMaterial.signingPayloadDigest,
    response: prepareResponse,
  });

  const signingWorkerVerifyingShare = base64UrlDecode(prepareResponse.server_verifying_share_b64u);
  if (signingWorkerVerifyingShare.length !== 32) {
    throw new Error('Router A/B normal-signing SigningWorker verifying share must be 32 bytes');
  }
  requireActiveClientMatchesNormalSigningOperation({
    activeClient: args.activeClient,
    authorization:
      args.authorization === 'reusable_wallet_session'
        ? {
            kind: 'reusable_wallet_session',
            walletSessionId: args.walletSessionState.signingWalletSession.walletSessionId,
          }
        : { kind: 'operation_step_up' },
    materialFacts,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    walletId: args.walletId,
    prepare: args.prepare,
    signingWorkerId: prepareResponse.signing_worker.server_id,
    signingWorkerVerifyingShare,
  });
  const clientShare = await args.activeClient.createSigningShare({
    admittedDigest,
    signingWorkerCommitments: prepareResponse.server_commitments,
    signingWorkerVerifyingShare,
  });
  if (clientShare.clientVerifyingShare.length !== 32) {
    throw new Error('Router A/B normal-signing Client verifying share must be 32 bytes');
  }

  const signingResponse = await finalizeRouterAbNormalSigningV2({
    relayServerUrl: materialFacts.relayerUrl,
    credential: args.credential,
    request: buildRouterAbEd25519NormalSigningFinalizeRequestV2({
      scope: args.prepare.request.scope,
      expiresAtMs: args.prepare.request.expires_at_ms,
      prepareResponse,
      admissionMaterial: args.prepare.admissionMaterial,
      clientCommitments: clientShare.clientCommitments,
      clientVerifyingShareB64u: base64UrlEncode(clientShare.clientVerifyingShare),
      clientSignatureShareB64u: clientShare.clientSignatureShareB64u,
    }),
  });
  requireRouterAbNormalSigningResponseMatchesRequest({
    request: args.prepare.request,
    signingPayloadDigest: args.prepare.admissionMaterial.signingPayloadDigest,
    response: signingResponse,
  });
  return {
    signatureB64u: routerAbCanonicalWireBytesToB64u(
      signingResponse.signature,
      'Router A/B normal-signing signature',
    ),
    signerPublicKey: args.thresholdKeyMaterial.publicKey,
  };
}

type RouterAbEd25519SignatureOnlyNormalSigningBase = {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  displayDigest: string;
  signingDigestB64u: string;
  intent: RouterAbEd25519SignatureOnlyIntentWire;
};

type RouterAbEd25519SignatureOnlyNormalSigningArgs =
  RouterAbEd25519SignatureOnlyNormalSigningBase &
    (
      | {
          walletSessionState: AuthorizedRouterAbEd25519WalletSessionState;
          authorization: { kind: 'reusable_wallet_session' };
        }
      | {
          materialFacts: NearEd25519YaoOperationMaterialFacts;
          walletSessionState?: never;
          authorization: {
            kind: 'operation_step_up';
            prepared: Extract<PreparedNearOperationStepUp, { kind: 'near_signature_only' }>;
            proof: Ed25519OperationStepUpProof;
            issuedAuthorization: NearEd25519OperationStepUpAuthorization | null;
          };
        }
    );

async function buildRouterAbEd25519SignatureOnlyPrepareRequest(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  scope: RouterAbNormalSigningScopeV2Wire;
  expiresAtMs: number;
  nearAccountId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  displayDigest: string;
  signingDigestB64u: string;
  intent: RouterAbEd25519SignatureOnlyIntentWire;
}): Promise<RouterAbNormalSigningPrepareRequestV2BuildResult> {
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  return (
    args.intent.kind === 'nep413_message_v1'
      ? await buildRouterAbEd25519Nep413PrepareRequestV2({
          scope: args.scope,
          expiresAtMs: args.expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
          displayDigestB64u: args.displayDigest,
          nearAccountId: args.nearAccountId,
          nearNetworkId,
          message: args.intent.message,
          recipient: args.intent.recipient,
          nonce: args.intent.nonce,
          ...(args.intent.state ? { callbackUrl: args.intent.state } : {}),
          expectedSigningDigestB64u: args.signingDigestB64u,
        })
      : await buildRouterAbEd25519DelegateActionPrepareRequestV2({
          scope: args.scope,
          expiresAtMs: args.expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
          displayDigestB64u: args.displayDigest,
          nearAccountId: args.nearAccountId,
          nearNetworkId,
          delegate: {
            senderId: args.intent.delegate.senderId,
            receiverId: args.intent.delegate.receiverId,
            publicKey: args.intent.delegate.publicKey,
            nonce: args.intent.delegate.nonce,
            maxBlockHeight: args.intent.delegate.maxBlockHeight,
            actionFingerprint: await routerAbNormalSigningActionFingerprint(
              args.intent.delegate.actions,
            ),
            canonicalDelegateBorshB64u: (
              await buildThresholdEd25519DelegateSigningPayloadWasm({
                delegate: {
                  senderId: args.intent.delegate.senderId,
                  receiverId: args.intent.delegate.receiverId,
                  actions: routerAbDelegateActionsForWasm(args.intent.delegate.actions),
                  nonce: args.intent.delegate.nonce,
                  maxBlockHeight: args.intent.delegate.maxBlockHeight,
                  publicKey: args.intent.delegate.publicKey,
                },
                workerCtx: args.ctx,
              })
            ).canonicalDelegateBorshB64u,
          },
          expectedSigningDigestB64u: args.signingDigestB64u,
        })
  );
}

export async function prepareRouterAbEd25519SignatureOnlyOperationStepUp(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  materialFacts: NearEd25519YaoOperationMaterialFacts;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  materialActivation: MpcMaterialActivationRef;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  displayDigest: string;
  signingDigestB64u: string;
  intent: RouterAbEd25519SignatureOnlyIntentWire;
}): Promise<{
  operation: Extract<PreparedNearOperationStepUp, { kind: 'near_signature_only' }>;
  envelope: CapabilityOperationEnvelope;
}> {
  const scope = buildRouterAbOperationStepUpScope({
    materialActivation: args.materialActivation,
    materialFacts: args.materialFacts,
    walletId: args.walletId,
    operationId: args.operationId,
  });
  const prepare = await buildRouterAbEd25519SignatureOnlyPrepareRequest({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    scope,
    expiresAtMs: Date.now() + ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    displayDigest: args.displayDigest,
    signingDigestB64u: args.signingDigestB64u,
    intent: args.intent,
  });
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: requireAuthorizationParse(
      parseTenantId(args.materialFacts.runtimePolicyScope.orgId),
    ),
    principalId: requireAuthorizationParse(parsePrincipalId(String(args.walletId))),
    capabilityId: requireAuthorizationParse(parseCapabilityId(args.materialActivation.capability)),
    operationId: requireAuthorizationParse(parseCapabilityOperationId(String(args.operationId))),
    operation: {
      capabilityKind: 'near_ed25519_mpc_signing',
      operationKind:
        args.intent.kind === 'nep413_message_v1'
          ? 'near.sign_nep413_message'
          : 'near.sign_delegate_action',
    },
    digests: {
      laneDigest: parseSigningOperationFingerprintDigest(args.operationFingerprint),
      intentDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(prepare.admissionMaterial.intentDigest.bytes)),
      ),
      displayDigest: parseDigestB64u(args.displayDigest),
    },
  });
  return {
    operation: {
      kind: 'near_signature_only',
      prepare,
      signingDigestB64u: args.signingDigestB64u,
      materialActivation: args.materialActivation,
    },
    envelope,
  };
}

export function buildNearEmailOtpEd25519OperationStepUpProof(args: {
  preparation: NearEd25519YaoSigningPreparation;
  auth: SigningLaneAuthBinding;
  walletId: string;
  challengeId: string;
  otpCode: string;
}): Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }> {
  if (args.auth.kind !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP step-up requires an Email OTP auth binding');
  }
  const authorityRef = args.preparation.hydration.authority;
  if (
    !authorityRef ||
    String(authorityRef.walletId) !== String(args.walletId)
  ) {
    throw new Error('[SigningEngine][near] Email OTP material authority changed');
  }
  return {
    kind: 'email_otp',
    authorityRef,
    providerSubjectId: args.auth.providerSubjectId,
    challengeId: args.challengeId,
    otpCode: args.otpCode,
  };
}

export function buildNearEd25519OperationStepUpProof(args: {
  authorization: Exclude<NearEd25519StepUpAuthorization, { kind: 'warm_session' }>;
  preparation: NearEd25519YaoSigningPreparation;
  auth: SigningLaneAuthBinding;
  walletId: string;
}): Ed25519OperationStepUpProof {
  switch (args.authorization.kind) {
    case 'passkey':
      return {
        kind: 'passkey',
        authority: args.authorization.plannedPasskeyOperationStepUp.authority,
        credential: args.authorization.credential,
      };
    case 'email_otp':
      return buildNearEmailOtpEd25519OperationStepUpProof({
        preparation: args.preparation,
        auth: requireEmailOtpAuth(args.auth),
        walletId: args.walletId,
        challengeId: args.authorization.challengeId,
        otpCode: args.authorization.otpCode,
      });
    default:
      args.authorization satisfies never;
      throw new Error('[SigningEngine][near] unsupported operation step-up authorization');
  }
}

function requireEmailOtpAuth(
  auth: SigningLaneAuthBinding,
): Extract<SigningLaneAuthBinding, { kind: 'email_otp' }> {
  if (auth.kind !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP step-up requires an Email OTP auth binding');
  }
  return auth;
}

export function requireNearEd25519OperationStepUpProof(
  proof: Ed25519OperationStepUpProof | null,
): Ed25519OperationStepUpProof {
  if (!proof) {
    throw new Error('[SigningEngine][near] operation step-up proof is missing');
  }
  return proof;
}

function isRouterAbEd25519SignatureOnlyOperationStepUp(
  args: RouterAbEd25519SignatureOnlyNormalSigningArgs,
): args is Extract<
  RouterAbEd25519SignatureOnlyNormalSigningArgs,
  { authorization: { kind: 'operation_step_up' } }
> {
  return args.authorization.kind === 'operation_step_up';
}

async function resolveIssuedEd25519OperationStepUpAuthorization(args: {
  issuedAuthorization: NearEd25519OperationStepUpAuthorization | null;
  relayerUrl: string;
  normalSigningRequest: RouterAbNormalSigningPrepareRequestV2BuildResult['request'];
  displayDigest: string;
  proof: Ed25519OperationStepUpProof;
  credential: Ed25519OperationStepUpCredential;
}): Promise<NearEd25519OperationStepUpAuthorization> {
  if (args.issuedAuthorization) return args.issuedAuthorization;
  switch (args.proof.kind) {
    case 'passkey':
      return await issueEd25519OperationStepUpAuthorization({
        relayerUrl: args.relayerUrl,
        normalSigningRequest: args.normalSigningRequest,
        displayDigest: args.displayDigest,
        proof: args.proof,
        credential: args.credential,
        materialRecovery: { kind: 'not_requested' },
      });
    case 'email_otp':
      return await issueEd25519OperationStepUpAuthorization({
        relayerUrl: args.relayerUrl,
        normalSigningRequest: args.normalSigningRequest,
        displayDigest: args.displayDigest,
        proof: args.proof,
        credential: args.credential,
        materialRecovery: { kind: 'not_requested' },
      });
    default:
      args.proof satisfies never;
      throw new Error('[SigningEngine][near] unsupported operation step-up proof');
  }
}

export async function tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning(
  args: RouterAbEd25519SignatureOnlyNormalSigningArgs,
): Promise<RouterAbEd25519SignatureOnlyNormalSigningResult | null> {
  if (isRouterAbEd25519SignatureOnlyOperationStepUp(args)) {
    const actualMaterialActivation = nearEd25519YaoMaterialActivationFromMetadata(
      args.activeClient.metadata(),
    );
    requireNearOperationStepUpMaterialActivation({
      expected: args.authorization.prepared.materialActivation,
      actual: actualMaterialActivation,
    });
    if (args.authorization.prepared.signingDigestB64u !== args.signingDigestB64u) {
      throw new Error('[SigningEngine][near] signature-only operation digest changed');
    }
    const prepare = args.authorization.prepared.prepare;
    const credential = await nearOperationStepUpCredential({
      ctx: args.ctx,
      walletId: args.walletId,
      relayerUrl: args.materialFacts.relayerUrl,
      proof: args.authorization.proof,
    });
    const issued = await resolveIssuedEd25519OperationStepUpAuthorization({
      issuedAuthorization: args.authorization.issuedAuthorization,
      relayerUrl: args.materialFacts.relayerUrl,
      normalSigningRequest: prepare.request,
      displayDigest: args.displayDigest,
      proof: args.authorization.proof,
      credential,
    });
    if (
      prepare.request.scope.authorization.kind !== 'operation_step_up' ||
      issued.kind !== 'verified_step_up'
    ) {
      throw new Error('[SigningEngine][near] issued operation step-up evidence changed identity');
    }
    const finalized = await tryFinalizeRouterAbEd25519NormalSigningSignature({
      thresholdSessionId: args.thresholdSessionId,
      materialFacts: args.materialFacts,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      activeClient: args.activeClient,
      signingDigestB64u: args.signingDigestB64u,
      signingPayloadLabel: 'signature-only payload digest',
      prepare,
      credential,
      authorization: 'operation_step_up',
    });
    return {
      kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1',
      authorization: 'operation_step_up',
      operationId: args.operationId,
      issuedAuthorization: issued,
      ...finalized,
    };
  }
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    activeClient: args.activeClient,
    walletSessionState: args.walletSessionState,
    walletId: args.walletId,
    operationId: args.operationId,
  });
  if (!scope) return null;
  const prepare = await buildRouterAbEd25519SignatureOnlyPrepareRequest({
    ctx: args.ctx,
    thresholdSessionId: args.thresholdSessionId,
    scope,
    expiresAtMs: routerAbNormalSigningExpiresAtMs({
      walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
      requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
    }),
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
    displayDigest: args.displayDigest,
    signingDigestB64u: args.signingDigestB64u,
    intent: args.intent,
  });
  const finalized = await tryFinalizeRouterAbEd25519NormalSigningSignature({
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    activeClient: args.activeClient,
    signingDigestB64u: args.signingDigestB64u,
    signingPayloadLabel: 'signature-only payload digest',
    prepare,
    credential: requireRouterAbEd25519NormalSigningReadyState({
      state: args.walletSessionState,
      thresholdSessionId: args.thresholdSessionId,
      nearAccountId: args.nearAccountId,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
    }).credential,
    authorization: args.authorization.kind,
  });
  return {
    kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1',
    authorization: 'reusable_wallet_session',
    operationId: args.operationId,
    ...finalized,
  };
}

export async function prepareRouterAbEd25519NearTransactionOperationStepUp(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  materialFacts: NearEd25519YaoOperationMaterialFacts;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  materialActivation: MpcMaterialActivationRef;
  operationId: SigningOperationId;
  txSigningRequest: TransactionPayload;
  transactionContext: TransactionContext;
  displayDigest: string;
}): Promise<{
  operation: PreparedNearOperationStepUp;
  envelope: CapabilityOperationEnvelope;
}> {
  const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
    txSigningRequest: args.txSigningRequest,
    transactionContext: args.transactionContext,
    workerCtx: args.ctx,
  });
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const parsedTransaction = parseThresholdEd25519NearTransaction(
    args.txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionOperationFingerprint({
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: [parsedTransaction],
      unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
      signingDigestB64u: unsigned.signingDigestB64u,
    }),
  );
  const scope = buildRouterAbOperationStepUpScope({
    materialActivation: args.materialActivation,
    materialFacts: args.materialFacts,
    walletId: args.walletId,
    operationId: args.operationId,
  });
  const prepare = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
    scope,
    expiresAtMs: Date.now() + ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
    operationId: args.operationId,
    operationFingerprint,
    displayDigestB64u: args.displayDigest,
    nearAccountId: args.nearAccountId,
    nearNetworkId,
    transactions: [
      {
        receiverId: parsedTransaction.receiverId,
        actionFingerprint: await routerAbNormalSigningActionFingerprint(parsedTransaction.actions),
      },
    ],
    unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
    expectedSigningDigestB64u: unsigned.signingDigestB64u,
  });
  const envelope = buildCapabilityOperationEnvelope({
    tenantId: requireAuthorizationParse(
      parseTenantId(args.materialFacts.runtimePolicyScope.orgId),
    ),
    principalId: requireAuthorizationParse(parsePrincipalId(String(args.walletId))),
    capabilityId: requireAuthorizationParse(parseCapabilityId(args.materialActivation.capability)),
    operationId: requireAuthorizationParse(parseCapabilityOperationId(String(args.operationId))),
    operation: {
      capabilityKind: 'near_ed25519_mpc_signing',
      operationKind: 'near.sign_transaction',
    },
    digests: {
      laneDigest: parseSigningOperationFingerprintDigest(operationFingerprint),
      intentDigest: parseDigestB64u(
        base64UrlEncode(Uint8Array.from(prepare.admissionMaterial.intentDigest.bytes)),
      ),
      displayDigest: parseDigestB64u(args.displayDigest),
    },
  });
  return {
    operation: {
      kind: 'near_transaction',
      prepare,
      unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
      signingDigestB64u: unsigned.signingDigestB64u,
      materialActivation: args.materialActivation,
    },
    envelope,
  };
}

type RouterAbEd25519NearTransactionNormalSigningBase = {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  displayDigest: string;
  txSigningRequest: TransactionPayload;
  transactionContext: TransactionContext | undefined;
};

type RouterAbEd25519NearTransactionNormalSigningArgs =
  RouterAbEd25519NearTransactionNormalSigningBase &
    (
      | {
          walletSessionState: AuthorizedRouterAbEd25519WalletSessionState;
          authorization: { kind: 'reusable_wallet_session' };
        }
      | {
          materialFacts: NearEd25519YaoOperationMaterialFacts;
          walletSessionState?: never;
          authorization: {
            kind: 'operation_step_up';
            prepared: Extract<PreparedNearOperationStepUp, { kind: 'near_transaction' }>;
            displayDigest: string;
            proof: Ed25519OperationStepUpProof;
            issuedAuthorization: NearEd25519OperationStepUpAuthorization | null;
          };
        }
    );

function isRouterAbEd25519OperationStepUpSigning(
  args: RouterAbEd25519NearTransactionNormalSigningArgs,
): args is Extract<
  RouterAbEd25519NearTransactionNormalSigningArgs,
  { authorization: { kind: 'operation_step_up' } }
> {
  return args.authorization.kind === 'operation_step_up';
}

function routerAbEd25519NormalSigningMaterialFacts(
  args: RouterAbEd25519NearTransactionNormalSigningArgs,
): NearEd25519YaoOperationMaterialFacts {
  if (isRouterAbEd25519OperationStepUpSigning(args)) return args.materialFacts;
  return {
    thresholdSessionId: args.walletSessionState.thresholdSessionId,
    signer: args.walletSessionState.signingLane.identity.signer,
    signingRootId: args.walletSessionState.signingRootId,
    signingRootVersion: args.walletSessionState.signingRootVersion,
    routerAbNormalSigning: args.walletSessionState.routerAbNormalSigning,
    runtimePolicyScope: args.walletSessionState.runtimePolicyScope,
    relayerUrl: args.walletSessionState.relayerUrl,
  };
}

export async function tryFinalizeRouterAbEd25519NearTransactionNormalSigning(
  args: RouterAbEd25519NearTransactionNormalSigningArgs,
): Promise<RouterAbEd25519NearTransactionNormalSigningResult | null> {
  const materialFacts = routerAbEd25519NormalSigningMaterialFacts(args);
  const routerAbState = materialFacts.routerAbNormalSigning;
  if (!routerAbState) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 normal-signing state is missing');
  }
  if (!args.transactionContext) {
    throw new Error(
      '[SigningEngine][near] Router A/B Ed25519 transaction signing is missing transaction context from confirmation',
    );
  }

  const operationStepUp = isRouterAbEd25519OperationStepUpSigning(args);
  const unsigned =
    operationStepUp
      ? {
          unsignedTransactionBorshB64u: args.authorization.prepared.unsignedTransactionBorshB64u,
          signingDigestB64u: args.authorization.prepared.signingDigestB64u,
        }
      : await buildThresholdEd25519NearTxUnsignedBorshWasm({
          txSigningRequest: args.txSigningRequest,
          transactionContext: args.transactionContext,
          workerCtx: args.ctx,
        });
  const signingPayload = base64UrlDecode(unsigned.signingDigestB64u);
  if (signingPayload.length !== 32) {
    throw new Error('Router A/B normal-signing NEAR payload digest must be 32 bytes');
  }

  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const parsedTransaction = parseThresholdEd25519NearTransaction(
    args.txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionOperationFingerprint({
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      relayerKeyId: args.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: args.thresholdKeyMaterial.publicKey,
      transactions: [parsedTransaction],
      unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
      signingDigestB64u: unsigned.signingDigestB64u,
    }),
  );
  let prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  let credential: RouterAbEd25519NormalSigningCredential;
  let issuedAuthorization: NearEd25519OperationStepUpAuthorization | undefined;
  if (operationStepUp) {
    prepare = args.authorization.prepared.prepare;
    credential = await nearOperationStepUpCredential({
      ctx: args.ctx,
      walletId: args.walletId,
      relayerUrl: materialFacts.relayerUrl,
      proof: args.authorization.proof,
    });
    const issued = await resolveIssuedEd25519OperationStepUpAuthorization({
      issuedAuthorization: args.authorization.issuedAuthorization,
      relayerUrl: materialFacts.relayerUrl,
      normalSigningRequest: prepare.request,
      displayDigest: args.authorization.displayDigest,
      proof: args.authorization.proof,
      credential,
    });
    if (
      prepare.request.scope.authorization.kind !== 'operation_step_up' ||
      issued.kind !== 'verified_step_up'
    ) {
      throw new Error('[SigningEngine][near] issued operation step-up evidence changed identity');
    }
    issuedAuthorization = issued;
  } else {
    const scope = buildRouterAbNormalSigningScope({
      thresholdSessionId: args.thresholdSessionId,
      activeClient: args.activeClient,
      walletSessionState: args.walletSessionState,
      walletId: args.walletId,
      operationId: args.operationId,
    });
    if (!scope) {
      throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing');
    }
    prepare = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
      scope,
      expiresAtMs: routerAbNormalSigningExpiresAtMs({
        walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
        requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
      }),
      operationId: args.operationId,
      operationFingerprint,
      displayDigestB64u: args.displayDigest,
      nearAccountId: args.nearAccountId,
      nearNetworkId,
      transactions: [
        {
          receiverId: parsedTransaction.receiverId,
          actionFingerprint: await routerAbNormalSigningActionFingerprint(
            parsedTransaction.actions,
          ),
        },
      ],
      unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
      expectedSigningDigestB64u: unsigned.signingDigestB64u,
    });
    credential = requireRouterAbEd25519NormalSigningReadyState({
      state: args.walletSessionState,
      thresholdSessionId: args.thresholdSessionId,
      nearAccountId: args.nearAccountId,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
    }).credential;
  }
  const signatureResult = isRouterAbEd25519OperationStepUpSigning(args)
    ? await tryFinalizeRouterAbEd25519NormalSigningSignature({
        thresholdSessionId: args.thresholdSessionId,
        materialFacts,
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        activeClient: args.activeClient,
        signingDigestB64u: unsigned.signingDigestB64u,
        signingPayloadLabel: 'NEAR payload digest',
        prepare,
        credential,
        authorization: 'operation_step_up',
      })
    : await tryFinalizeRouterAbEd25519NormalSigningSignature({
        thresholdSessionId: args.thresholdSessionId,
        walletSessionState: args.walletSessionState,
        thresholdKeyMaterial: args.thresholdKeyMaterial,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        activeClient: args.activeClient,
        signingDigestB64u: unsigned.signingDigestB64u,
        signingPayloadLabel: 'NEAR payload digest',
        prepare,
        credential,
        authorization: 'reusable_wallet_session',
      });
  const finalized = await finalizeThresholdEd25519NearTxFromSignatureWasm({
    unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
    signingDigestB64u: unsigned.signingDigestB64u,
    signatureB64u: signatureResult.signatureB64u,
    expectedNearAccountId: args.nearAccountId,
    expectedSignerPublicKey: args.thresholdKeyMaterial.publicKey,
    workerCtx: args.ctx,
  });
  const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
    signedTransactionBorshB64u: finalized.signedTransactionBorshB64u,
    workerCtx: args.ctx,
  });
  const transactionHash = finalized.transactionHash || decoded.transactionHash;
  const okResponse = {
    type: WorkerResponseType.SignTransactionsWithActionsSuccess,
    payload: {
      free: () => undefined,
      success: true,
      transactionHashes: [transactionHash],
      signedTransactions: [decoded.signedTransaction],
      logs: ['NEAR transaction signed through Router A/B normal signing'],
      error: undefined,
    },
  } satisfies WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  if (operationStepUp) {
    if (!issuedAuthorization) {
      throw new Error('[SigningEngine][near] operation step-up authorization was not issued');
    }
    return {
      kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1',
      authorization: 'operation_step_up',
      issuedAuthorization,
      transactionHash,
      okResponse,
    };
  }
  return {
    kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1',
    authorization: 'reusable_wallet_session',
    transactionHash,
    okResponse,
  };
}
