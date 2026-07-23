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
import type { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import type {
  BudgetFinalizationSpend,
  SigningBudgetFinalizationResult,
  SigningSessionBudgetStatusAuth,
  SigningSessionPreparedBudgetIdentity,
} from '@/core/signingEngine/session/budget/budget';
import { isSigningSessionBudgetReservation } from '@/core/signingEngine/session/budget/budget';
import {
  createSigningSessionBudgetFinalizer,
  type SigningSessionBudgetFinalizer,
} from '@/core/signingEngine/session/budget/budgetFinalizer';
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
  type RouterAbNormalSigningScopeV1Wire,
} from '@/core/rpcClients/relayer/routerAbNormalSigning';
import {
  requireRouterAbNormalSigningPrepareMatchesRequest,
  requireRouterAbNormalSigningResponseMatchesRequest,
} from '@/core/rpcClients/relayer/routerAbNormalSigningValidation';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '@/core/signingEngine/session/operationState/types';
import {
  requireRouterAbEd25519NormalSigningReadyState,
  type RouterAbEd25519NormalSigningReadyState,
} from '../../../session/warmCapabilities/routerAbWalletSessionCredential';
import type { ResolvedRouterAbEd25519WalletSessionState } from '../../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import { base58Decode } from '@shared/utils/base58';
import { ensureEd25519Prefix } from '@shared/utils/validation';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionOperationFingerprint,
  type ThresholdEd25519NearAction,
} from '@shared/threshold/ed25519OperationFingerprint';

const ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS = 120_000;

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

export type RouterAbEd25519NearTransactionNormalSigningResult = {
  kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1';
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  transactionHash: string;
};

export type RouterAbEd25519SignatureOnlyNormalSigningResult = {
  kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1';
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
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  walletId: WalletId;
  operationId: SigningOperationId;
}): RouterAbNormalSigningScopeV1Wire | null {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) return null;
  const walletId = String(args.walletId || '').trim();
  if (!walletId) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing scope is missing wallet id');
  }
  const activeStateSessionId = String(
    args.activeClient.metadata().scope.wallet_session_id,
  ).trim();
  if (!activeStateSessionId) {
    throw new Error(
      '[SigningEngine][near] Router A/B Ed25519 signing scope is missing active material session id',
    );
  }
  return {
    request_id: createRouterAbNormalSigningRequestId(args.operationId),
    account_id: walletId,
    session_id: args.thresholdSessionId,
    active_state_session_id: activeStateSessionId,
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
  thresholdSessionId: string;
  delegate: DelegatePayload;
  signingDigestB64u: string;
  signatureB64u: string;
}): Promise<{ signedDelegate: WasmSignedDelegate; hash: string }> {
  const signedDelegate = await finalizeThresholdEd25519DelegateFromSignatureWasm({
    sessionId: args.thresholdSessionId,
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
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
  signingWorkerId: string;
  signingWorkerVerifyingShare: Uint8Array;
}): void {
  const metadata = args.activeClient.metadata();
  const signer = args.walletSessionState.signingLane.identity.signer;
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
  requireMatchingRouterAbEd25519Identity(metadata.scope.account_id, args.walletId, 'scope wallet');
  requireMatchingRouterAbEd25519Identity(
    metadata.scope.wallet_session_id,
    args.prepare.request.scope.active_state_session_id,
    'active material session',
  );
  requireMatchingRouterAbEd25519Identity(
    args.prepare.request.scope.session_id,
    args.thresholdSessionId,
    'authorization session',
  );
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
    args.walletSessionState.signingRootId,
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

async function tryFinalizeRouterAbEd25519NormalSigningSignature(args: {
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  signingDigestB64u: string;
  signingPayloadLabel: string;
  prepare: RouterAbNormalSigningPrepareRequestV2BuildResult;
}): Promise<RouterAbEd25519NormalSigningFinalized> {
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

  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const prepareResponse = await prepareRouterAbNormalSigningV2({
    relayServerUrl: args.walletSessionState.relayerUrl,
    credential: routerAbReadyState.credential,
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
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
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
    relayServerUrl: args.walletSessionState.relayerUrl,
    credential: routerAbReadyState.credential,
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

export async function tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  signingSessionCoordinator: SigningSessionCoordinator;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  signingDigestB64u: string;
  intent: RouterAbEd25519SignatureOnlyIntentWire;
}): Promise<RouterAbEd25519SignatureOnlyNormalSigningResult | null> {
  const scope = buildRouterAbNormalSigningScope({
    thresholdSessionId: args.thresholdSessionId,
    activeClient: args.activeClient,
    walletSessionState: args.walletSessionState,
    walletId: args.walletId,
    operationId: args.operationId,
  });
  if (!scope) return null;
  const nearNetworkId = normalizeNearNetworkId(args.ctx);
  const expiresAtMs = routerAbNormalSigningExpiresAtMs({
    walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
    requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
  });
  const prepare =
    args.intent.kind === 'nep413_message_v1'
      ? await buildRouterAbEd25519Nep413PrepareRequestV2({
          scope,
          expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
          nearAccountId: args.nearAccountId,
          nearNetworkId,
          message: args.intent.message,
          recipient: args.intent.recipient,
          nonce: args.intent.nonce,
          ...(args.intent.state ? { callbackUrl: args.intent.state } : {}),
          expectedSigningDigestB64u: args.signingDigestB64u,
        })
      : await buildRouterAbEd25519DelegateActionPrepareRequestV2({
          scope,
          expiresAtMs,
          operationId: args.operationId,
          operationFingerprint: args.operationFingerprint,
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
                sessionId: args.thresholdSessionId,
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
        });
  const budgetFinalizer = await prepareRouterAbEd25519SignatureOnlyBudgetFinalizer({
    signingSessionCoordinator: args.signingSessionCoordinator,
    walletSessionState: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    operationId: args.operationId,
    operationFingerprint: args.operationFingerprint,
  });
  const reservation = await budgetFinalizer.reserve();
  if (reservation && !isSigningSessionBudgetReservation(reservation)) {
    throw new Error('[SigningEngine][near] signature-only budget reservation identity mismatch');
  }

  let finalized: RouterAbEd25519NormalSigningFinalized;
  try {
    finalized = await tryFinalizeRouterAbEd25519NormalSigningSignature({
      thresholdSessionId: args.thresholdSessionId,
      walletSessionState: args.walletSessionState,
      thresholdKeyMaterial: args.thresholdKeyMaterial,
      walletId: args.walletId,
      nearAccountId: args.nearAccountId,
      activeClient: args.activeClient,
      signingDigestB64u: args.signingDigestB64u,
      signingPayloadLabel: 'signature-only payload digest',
      prepare,
    });
  } catch (error) {
    budgetFinalizer.recordZeroSpend(error);
    throw error;
  }
  requireSignatureOnlyBudgetFinalizationResult(await budgetFinalizer.recordSuccess());
  return {
    kind: 'router_ab_ed25519_signature_only_normal_signing_result_v1',
    operationId: args.operationId,
    ...finalized,
  };
}

function requireSignatureOnlyBudgetFinalizationResult(
  result: SigningBudgetFinalizationResult | null,
): void {
  if (!result || result.kind === 'finalized' || result.kind === 'already_finalized') return;
  switch (result.kind) {
    case 'projection_mismatch':
      throw new Error(
        `[SigningEngine][near] signature-only budget finalization projection mismatch: expected ${result.expectedProjectionVersion}, got ${result.actualProjectionVersion}`,
      );
    case 'missing_reservation':
      throw new Error(
        '[SigningEngine][near] signature-only budget finalization missing reservation',
      );
    case 'reservation_identity_mismatch':
      throw new Error(
        '[SigningEngine][near] signature-only budget finalization reservation identity mismatch',
      );
    case 'budget_status_unavailable':
      throw new Error(
        `[SigningEngine][near] signature-only budget finalization status unavailable: ${result.status}`,
      );
    default:
      assertNever(result satisfies never);
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected signature-only budget finalization result: ${String(value)}`);
}

async function prepareRouterAbEd25519SignatureOnlyBudgetFinalizer(args: {
  signingSessionCoordinator: SigningSessionCoordinator;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdSessionId: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
}): Promise<SigningSessionBudgetFinalizer> {
  const routerAbReadyState = requireRouterAbEd25519NormalSigningReadyState({
    state: args.walletSessionState,
    thresholdSessionId: args.thresholdSessionId,
    nearAccountId: args.nearAccountId,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
  });
  const trustedStatusAuth = budgetStatusAuthFromRouterAbReadyState(routerAbReadyState);
  const budgetIdentity = await args.signingSessionCoordinator.prepareBudgetIdentity({
    lane: args.walletSessionState.signingLane,
    trustedStatusAuth,
    operationUsesNeeded: 1,
  });
  return createRouterAbEd25519SignatureOnlyBudgetFinalizer({
    signingSessionCoordinator: args.signingSessionCoordinator,
    budgetIdentity,
    finalization: {
      kind: 'externally_consumed_success',
      spend: {
        operationId: args.operationId,
        operationFingerprint: args.operationFingerprint,
        lane: args.walletSessionState.signingLane,
        backingMaterialSessionIds: [],
        uses: 1,
        reason: SigningOperationIntent.TransactionSign,
      },
      trustedStatusAuth,
      alreadyConsumedThresholdSessionIds: [args.walletSessionState.signingLane.thresholdSessionId],
    },
    nearAccountId: args.nearAccountId,
    signingGrantId: args.walletSessionState.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
  });
}

function budgetStatusAuthFromRouterAbReadyState(
  state: RouterAbEd25519NormalSigningReadyState,
): SigningSessionBudgetStatusAuth {
  const thresholdSessionId = String(state.thresholdSessionId || '').trim();
  const relayerUrl = String(state.relayerUrl || '').trim();
  const walletSessionJwt = String(state.credential.walletSessionJwt || '').trim();
  if (!thresholdSessionId || !relayerUrl || !walletSessionJwt) {
    throw new Error('[SigningEngine][near] signature-only budget auth is incomplete');
  }
  return {
    thresholdSessionId,
    relayerUrl,
    walletSessionJwt,
  };
}

function createRouterAbEd25519SignatureOnlyBudgetFinalizer(args: {
  signingSessionCoordinator: SigningSessionCoordinator;
  budgetIdentity: SigningSessionPreparedBudgetIdentity;
  finalization: BudgetFinalizationSpend;
  nearAccountId: string;
  signingGrantId: string;
  thresholdSessionId: string;
}): SigningSessionBudgetFinalizer {
  return createSigningSessionBudgetFinalizer({
    budgetMode: 'with_budget',
    signingSessionBudget: args.signingSessionCoordinator,
    budgetIdentity: args.budgetIdentity,
    finalization: args.finalization,
    onRecordSuccessError: (error) => {
      console.warn('[SigningEngine][near] failed to update signature-only signing grant budget', {
        nearAccountId: args.nearAccountId,
        signingGrantId: args.signingGrantId,
        thresholdSessionId: args.thresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
    },
    onRecordZeroSpendError: (error) => {
      console.warn('[SigningEngine][near] failed to record signature-only zero spend', {
        nearAccountId: args.nearAccountId,
        thresholdSessionId: args.thresholdSessionId,
        error: error instanceof Error ? error.message : String(error || 'unknown error'),
      });
    },
  });
}

export async function tryFinalizeRouterAbEd25519NearTransactionNormalSigning(args: {
  ctx: NearSigningRuntimeDeps;
  thresholdSessionId: string;
  walletSessionState: ResolvedRouterAbEd25519WalletSessionState;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  walletId: WalletId;
  nearAccountId: string;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  operationId: SigningOperationId;
  operationFingerprint: SigningOperationFingerprint;
  txSigningRequest: TransactionPayload;
  transactionContext: TransactionContext | undefined;
}): Promise<RouterAbEd25519NearTransactionNormalSigningResult | null> {
  const routerAbState = args.walletSessionState.routerAbNormalSigning;
  if (!routerAbState) {
    throw new Error('[SigningEngine][near] Router A/B Ed25519 normal-signing state is missing');
  }
  if (!args.transactionContext) {
    throw new Error(
      '[SigningEngine][near] Router A/B Ed25519 transaction signing is missing transaction context from confirmation',
    );
  }

  const unsigned = await buildThresholdEd25519NearTxUnsignedBorshWasm({
    sessionId: args.thresholdSessionId,
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
  const prepare = await buildRouterAbEd25519NearTransactionPrepareRequestV2({
    scope,
    expiresAtMs: routerAbNormalSigningExpiresAtMs({
      walletSessionExpiresAtMs: args.walletSessionState.signingWalletSession.expiresAtMs,
      requestedTtlMs: ROUTER_AB_NORMAL_SIGNING_REQUEST_TTL_MS,
    }),
    operationId: args.operationId,
    operationFingerprint,
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
  const signatureResult = await tryFinalizeRouterAbEd25519NormalSigningSignature({
    thresholdSessionId: args.thresholdSessionId,
    walletSessionState: args.walletSessionState,
    thresholdKeyMaterial: args.thresholdKeyMaterial,
    walletId: args.walletId,
    nearAccountId: args.nearAccountId,
    activeClient: args.activeClient,
    signingDigestB64u: unsigned.signingDigestB64u,
    signingPayloadLabel: 'NEAR payload digest',
    prepare,
  });
  const finalized = await finalizeThresholdEd25519NearTxFromSignatureWasm({
    sessionId: args.thresholdSessionId,
    unsignedTransactionBorshB64u: unsigned.unsignedTransactionBorshB64u,
    signingDigestB64u: unsigned.signingDigestB64u,
    signatureB64u: signatureResult.signatureB64u,
    expectedNearAccountId: args.nearAccountId,
    expectedSignerPublicKey: args.thresholdKeyMaterial.publicKey,
    workerCtx: args.ctx,
  });
  const decoded = await decodeThresholdEd25519SignedNearTxBorshWasm({
    sessionId: args.thresholdSessionId,
    signedTransactionBorshB64u: finalized.signedTransactionBorshB64u,
    workerCtx: args.ctx,
  });
  const transactionHash = finalized.transactionHash || decoded.transactionHash;
  return {
    kind: 'router_ab_ed25519_near_transaction_normal_signing_result_v1',
    transactionHash,
    okResponse: {
      type: WorkerResponseType.SignTransactionsWithActionsSuccess,
      payload: {
        free: () => undefined,
        success: true,
        transactionHashes: [transactionHash],
        signedTransactions: [decoded.signedTransaction],
        logs: ['NEAR transaction signed through Router A/B normal signing'],
        error: undefined,
      },
    },
  };
}
