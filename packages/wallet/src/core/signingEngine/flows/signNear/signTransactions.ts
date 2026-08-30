import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { TransactionInputWasm } from '@/core/types/actions';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  WorkerRequestType,
  type ConfirmationConfig,
  type RpcCallPayload,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { AccountId, toAccountId } from '@/core/types/accountIds';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import type {
  NearEd25519YaoMaterialExecutor,
  NearEd25519YaoOperationMaterial,
  NearEmailOtpEd25519StepUpHook,
  NearEd25519StepUpAuthorization,
  NearEd25519TransactionSigningBoundary,
  NearPasskeyEd25519OperationStepUpHook,
  NearTransactionWithActionsPayload,
} from '../../interfaces/near';
import type { NearEd25519YaoSigningPreparation } from '../../session/material/nearEd25519YaoSigningPreparation';
import {
  isWarmSessionSigningAuthPlan,
  type SigningAuthPlan,
  type UserConfirmProgressEvent,
} from '@/core/signingEngine/stepUpConfirmation/types';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork, resolvePrimaryNearRpcUrl } from '@/core/config/chains';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import {
  resolveActiveAuthorizedRouterAbEd25519WalletSessionState,
  type AuthorizedRouterAbEd25519WalletSessionState,
  type ResolvedRouterAbEd25519WalletSessionState,
} from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import { buildNearTransactionSigningPayload } from '../../chains/near/payloads';
import { SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR } from './shared/signingSessionAuthMode';
import type { SelectedEd25519Lane } from '../../session/identity/laneIdentity';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
import {
  SigningOperationIntent,
  SigningSessionIds,
  SigningSessionPlanKind,
  type DeferredEd25519MaterialIdentity,
  type SigningSessionPlan,
  type SigningOperationId,
} from '../../session/operationState/types';
import { nearEd25519SignerBindingFromBoundaryFields } from '../../session/identity/exactSigningLaneIdentity';
import type { NearTransactionSigningLane } from '../../session/operationState/lanes';
import { type PreparedTransactionOperation } from '../../session/operationState/transactionState';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/operationState/trace';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  parseThresholdEd25519NearTransaction,
  thresholdEd25519NearTransactionPlanningOperationFingerprint,
} from '@shared/threshold/ed25519OperationFingerprint';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import {
  requireNearStepUpAuth,
  signingAuthPlanForNearMaterialRequirement,
} from './requireNearStepUpAuth';
import {
  buildSigningConfirmationAuthParams,
  confirmationConfigForSigningAuthPlan,
  mapSigningConfirmationProgress,
  resolveSigningConfirmationAuthMethod,
  runSigningConfirmationCommand,
  type ConfirmTransactionSigningOperationResult,
} from '../shared/signingConfirmation';
import { buildNearEd25519StepUpAuthorization } from './stepUpAuthorization';
import type { NearAccountRef, NearCommandSubject } from '../../interfaces/ecdsaChainTarget';
import { requiredNearTransactionSignatureUses } from './signatureUses';
import {
  buildNearEd25519OperationStepUpProof,
  buildNearEmailOtpEd25519OperationStepUpProof,
  prepareRouterAbEd25519NearTransactionOperationStepUp,
  requireNearEd25519OperationStepUpProof,
  requireIssuedNearEd25519OperationStepUpAuthorization,
  tryFinalizeRouterAbEd25519NearTransactionNormalSigning,
} from './shared/ed25519YaoNormalSigning';
import {
  fundNearImplicitAccountForOperationStepUp,
  resolveConfirmedNearTransactionContext,
} from './implicitAccountFunding';
import {
  clearNearImplicitAccountFunder,
  registerNearImplicitAccountFunder,
} from './shared/implicitAccountFundingPort';
import {
  nearOperationStepUpMaterialFacts,
  prepareNearOperationStepUpMaterial,
  resolveNearOperationStepUpMaterial,
  resolvePreparedNearEd25519YaoMaterial,
  type NearOperationStepUpMaterial,
  type ResolvedNearOperationStepUpMaterial,
} from './shared/ed25519YaoCapabilityResolution';
import {
  clearNearOperationStepUpBuilder,
  consumePreparedNearOperationStepUp,
  registerNearOperationStepUpBuilder,
  requireNearOperationStepUpMaterialActivation,
  type PreparedNearOperationStepUp,
} from './shared/operationStepUpPreparation';
import type { NearOperationStepUpPreparationRef } from '../../interfaces/operationStepUpPreparation';
import { nearEd25519YaoMaterialActivationFromMetadata } from '../../session/material/nearEd25519YaoMaterialActivation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import { parseSigningOperationFingerprintDigest } from '../../session/planning/operationFingerprint';

function requireNearOperationStepUpPreparation(
  value: NearOperationStepUpPreparationRef | undefined,
): NearOperationStepUpPreparationRef {
  if (!value) {
    throw new Error('[SigningEngine][near] confirmed operation step-up is missing preparation');
  }
  return value;
}

function requirePreparedNearOperationStepUp(
  value: PreparedNearOperationStepUp | null,
): Extract<PreparedNearOperationStepUp, { kind: 'near_transaction' }> {
  if (!value) {
    throw new Error('[SigningEngine][near] prepared operation step-up is missing');
  }
  if (value.kind !== 'near_transaction') {
    throw new Error('[SigningEngine][near] prepared operation step-up is not a transaction');
  }
  return value;
}

function requireNearTransactionOperationStepUpMaterial(
  value: NearOperationStepUpMaterial | null,
): NearOperationStepUpMaterial {
  if (!value) {
    throw new Error('[SigningEngine][near] transaction operation material is unavailable');
  }
  return value;
}

function disposeOwnedNearOperationStepUpMaterial(args: {
  resolved: ResolvedNearOperationStepUpMaterial | null;
  owned: boolean;
}): void {
  if (args.owned) args.resolved?.material.activeClient.dispose();
}

function disposeOwnedNearOperationStepUpMaterialAndRethrow(
  args: {
    resolved: ResolvedNearOperationStepUpMaterial | null;
    owned: boolean;
  },
  error: unknown,
): never {
  disposeOwnedNearOperationStepUpMaterial(args);
  throw error;
}

async function resolveNearTransactionOperationStepUpMaterial(args: {
  material: NearOperationStepUpMaterial;
  prepared: Extract<PreparedNearOperationStepUp, { kind: 'near_transaction' }>;
  displayDigest: string;
  authorization: Exclude<NearEd25519StepUpAuthorization, { kind: 'warm_session' }>;
  proof: ReturnType<typeof buildNearEd25519OperationStepUpProof>;
}): Promise<ResolvedNearOperationStepUpMaterial> {
  if (args.authorization.kind === 'passkey') {
    if (args.material.kind !== 'passkey_live' && args.material.kind !== 'passkey_sealed') {
      throw new Error('[SigningEngine][near] passkey transaction material changed factor');
    }
    return await resolveNearOperationStepUpMaterial({
      kind: 'passkey',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
      credential: args.authorization.credential,
    });
  }
  if (args.material.kind !== 'email_otp_live' && args.material.kind !== 'email_otp_sealed') {
    throw new Error('[SigningEngine][near] Email OTP transaction material changed factor');
  }
  if (args.proof.kind !== 'email_otp') {
    throw new Error('[SigningEngine][near] Email OTP transaction proof is missing');
  }
  if (args.material.kind === 'email_otp_live') {
    return await resolveNearOperationStepUpMaterial({
      kind: 'email_otp_live',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
    });
  }
  return await resolveNearOperationStepUpMaterial({
    kind: 'email_otp_sealed',
    material: args.material,
    expectedActivation: args.prepared.materialActivation,
    normalSigningRequest: args.prepared.prepare.request,
    displayDigest: args.displayDigest,
    proof: args.proof,
  });
}

function emitNearSigningEvent(
  onEvent: ((event: SigningFlowEvent) => void) | undefined,
  accountId: AccountId | string,
  event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: `signing:near:${String(accountId)}:${event.phase}`,
        accountId: String(accountId),
      }),
    );
  } catch {}
}

export function emitNearSigningConfirmationProgress(
  args: {
    onEvent: ((event: SigningFlowEvent) => void) | undefined;
    nearAccountId: AccountId | string;
    signingAuthPlan: SigningAuthPlan;
  },
  progress: UserConfirmProgressEvent,
): void {
  if (
    progress.phase !== 'auth.passkey.prompt.started' &&
    progress.phase !== 'auth.passkey.prompt.succeeded'
  ) {
    return;
  }
  const authMethod = resolveSigningConfirmationAuthMethod(args.signingAuthPlan);
  if (authMethod !== 'passkey') return;
  const event = mapSigningConfirmationProgress(progress, authMethod);
  if (!event) return;
  emitNearSigningEvent(args.onEvent, args.nearAccountId, { ...event, authMethod });
}

async function requireActiveAuthorizedWalletSessionState(
  state: ResolvedRouterAbEd25519WalletSessionState | null,
) {
  if (!state) {
    throw new Error('[SigningEngine][near] reusable Wallet Session state is unavailable');
  }
  const authorized = await resolveActiveAuthorizedRouterAbEd25519WalletSessionState({
    state,
    nowMs: Date.now(),
  });
  if (!authorized) {
    throw new Error('[SigningEngine][near] reusable Wallet Session authorization is unavailable');
  }
  return authorized;
}

function createNearTransactionSigningOperationId(): SigningOperationId {
  const randomId = secureRandomBase64Url(32, 'NEAR transaction signing operation IDs');
  return SigningSessionIds.signingOperation(`near-transaction-sign:${randomId}`);
}

/**
 * Sign one NEAR transaction. A transaction may contain multiple actions.
 */

function isNearAuthorizationRequiredTransactionPayload(
  payload: NearTransactionWithActionsPayload,
): payload is Extract<
  NearTransactionWithActionsPayload,
  { selection: { kind: 'authorization_required' } }
> {
  return payload.selection.kind === 'authorization_required';
}

export async function runNearTransactionWithActionsSigning(
  payload: NearTransactionWithActionsPayload,
): Promise<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  if (isNearAuthorizationRequiredTransactionPayload(payload)) {
    return await runNearAuthorizationRequiredTransactionSigning(payload);
  }
  return await runAuthorizedNearTransactionWithActionsSigning(payload);
}

async function runNearAuthorizationRequiredTransactionSigning(
  payload: Extract<
    NearTransactionWithActionsPayload,
    { selection: { kind: 'authorization_required' } }
  >,
): Promise<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  const {
    ctx,
    commandSubject,
    nearAccount,
    transaction,
    rpcCall,
    onEvent,
    confirmationConfigOverride,
    title,
    body,
    signerSlot,
    signingOperationId: providedOperationId,
    signingSessionCoordinator: sessionCoordinator,
    selection,
    yaoSigningPreparation,
    yaoMaterialExecutor,
    passkeyEd25519OperationStepUp,
    emailOtpEd25519StepUp,
  } = payload;
  const candidate = selection.candidate;
  const nearAccountId = toAccountId(nearAccount.accountId);
  const operationId =
    providedOperationId ||
    SigningSessionIds.signingOperation(
      `near-transaction-sign:${secureRandomBase64Url(32, 'NEAR operation')}`,
    );
  const warnings: string[] = [];
  if (!ctx.touchConfirm) throw new Error('UiConfirm bridge not available for signing');
  if (!sessionCoordinator) {
    throw new Error('[SigningEngine][near] production signing session coordinator is required');
  }
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    materialExecutor: yaoMaterialExecutor,
    nearAccount,
    signerSlot: candidate.signerSlot,
    requestedSignerSlot: signerSlot,
    operationLabel: 'signing',
    warnings,
  });
  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    relayerUrl: ctx.relayerUrl,
    thresholdKeyMaterial,
  });
  const resolvedRpcCall = {
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
    nearAccountId,
  } as RpcCallPayload;
  const { txSigningRequest, confirmationTransaction } = buildNearTransactionSigningPayload({
    nearAccountId: String(nearAccountId),
    transaction,
  });
  const parsedTransaction = parseThresholdEd25519NearTransaction(
    txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionPlanningOperationFingerprint({
      nearAccountId,
      nearNetworkId: resolveNearNetwork(
        ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
      ),
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
      transactions: [parsedTransaction],
    }),
  );
  const operationFingerprintDigest = parseSigningOperationFingerprintDigest(operationFingerprint);
  const deferredIdentity: DeferredEd25519MaterialIdentity = {
    kind: 'deferred_ed25519_material_identity',
    signer: nearEd25519SignerBindingFromBoundaryFields({
      walletId: candidate.walletId,
      nearAccountId: candidate.nearAccountId,
      nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
      signerSlot: candidate.signerSlot,
    }),
    materialActivation: candidate.materialActivation,
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(candidate.thresholdSessionId),
  };
  const signingSessionPlan: SigningSessionPlan = {
    kind: SigningSessionPlanKind.OperationStepUp,
    lane: {
      identity: deferredIdentity,
      auth: candidate.auth,
      curve: 'ed25519',
      keyKind: 'threshold_ed25519',
      chainFamily: 'near',
      sessionOrigin: 'per_operation',
      storageSource: 'sealed_restore',
      retention: 'single_use',
      materialActivation: deferredIdentity.materialActivation,
      thresholdSessionId: deferredIdentity.thresholdSessionId,
    },
  };
  const signingAuthPlan = signingAuthPlanForNearMaterialRequirement(candidate.auth);
  const signingOperation = {
    operationId,
    operationFingerprint,
    intent: SigningOperationIntent.TransactionSign,
  };
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan,
    signingLaneAuth: candidate.auth,
    requiredSignatureUses: requiredNearTransactionSignatureUses(transaction),
    operationFingerprintDigest,
    ...(passkeyEd25519OperationStepUp ? { passkeyEd25519OperationStepUp } : {}),
    ...(emailOtpEd25519StepUp ? { emailOtpEd25519StepUp } : {}),
  });
  if (preparedStepUp.kind === 'warm_session') {
    throw new Error('[SigningEngine][near] deferred Ed25519 transaction cannot use warm session');
  }
  const operationStepUpMaterial = await prepareNearOperationStepUpMaterial({
    method: preparedStepUp.kind,
    preparation: yaoSigningPreparation,
    executor: yaoMaterialExecutor,
  });
  const materialFacts = nearOperationStepUpMaterialFacts(operationStepUpMaterial);
  const signingOperationUses = requiredNearTransactionSignatureUses(transaction);
  registerNearOperationStepUpBuilder({
    requestId: String(operationId),
    build: async (preparation) => {
      if (preparation.kind !== 'near_transaction') {
        throw new Error('[SigningEngine][near] transaction step-up preparation kind changed');
      }
      return await prepareRouterAbEd25519NearTransactionOperationStepUp({
        ctx,
        thresholdSessionId: materialFacts.thresholdSessionId,
        materialFacts,
        thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
        walletId: commandSubject.walletSession.walletId,
        nearAccountId,
        materialActivation: operationStepUpMaterial.materialActivation,
        operationId,
        operationFingerprint,
        txSigningRequest,
        transactionContext: preparation.transactionContext,
        displayDigest: preparation.displayDigest,
      });
    },
  });
  // The confirmation flow funds an unfunded implicit account through this
  // narrow port before it prepares the step-up (the assertion signs the
  // prepared operation's digest, so funding must precede preparation). The
  // funder lives here because this side holds the Wallet Session and the
  // request-integrity checks.
  registerNearImplicitAccountFunder({
    requestId: String(operationId),
    fund: async (fundingRequest) =>
      await fundNearImplicitAccountForOperationStepUp({
        request: fundingRequest,
        ctx,
        nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
        fundingSession: await yaoMaterialExecutor.resolveFundingSession(),
        method: preparedStepUp.kind,
        signingOperation,
        signatureUses: signingOperationUses,
      }),
  });
  let confirmation: ConfirmTransactionSigningOperationResult;
  try {
    confirmation = await runSigningConfirmationCommand({
      signingSessionPlan,
      signingOperation,
      runtime: ctx.touchConfirm,
      request: {
        ctx: { touchConfirm: ctx.touchConfirm },
        sessionId: String(operationId),
        chain: 'near',
        kind: 'transaction' as const,
        ...buildSigningConfirmationAuthParams({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
        }),
        walletId: candidate.walletId,
        txSigningRequests: [confirmationTransaction],
        rpcCall: resolvedRpcCall,
        nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
        nearFundingRequest: {
          subject: {
            walletId: candidate.walletId,
            nearAccountId,
            nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
          },
          operation: { ...signingOperation, accountId: String(nearAccountId) },
          signatureUses: signingOperationUses,
        },
        confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
          override: confirmationConfigOverride,
        }),
        title,
        body,
        onProgress: emitNearSigningConfirmationProgress.bind(undefined, {
          onEvent,
          nearAccountId,
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
        }),
      },
    });
  } finally {
    clearNearOperationStepUpBuilder(String(operationId));
    clearNearImplicitAccountFunder(String(operationId));
  }
  const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
    prepared: preparedStepUp,
    confirmation,
  });
  if (stepUpAuthorization.kind === 'warm_session') {
    throw new Error('[SigningEngine][near] deferred transaction requires operation step-up');
  }
  const operationStepUpProof = buildNearEd25519OperationStepUpProof({
    authorization: stepUpAuthorization,
    preparation: yaoSigningPreparation,
    auth: candidate.auth,
    walletId: commandSubject.walletSession.walletId,
  });
  const preparedOperationStepUp = consumePreparedNearOperationStepUp({
    requestId: String(operationId),
    ref: requireNearOperationStepUpPreparation(confirmation.operationStepUpPreparation),
  });
  const preparedTransactionStepUp = requirePreparedNearOperationStepUp(preparedOperationStepUp);
  const resolvedOperationStepUpMaterial = await resolveNearTransactionOperationStepUpMaterial({
    material: operationStepUpMaterial,
    prepared: preparedTransactionStepUp,
    displayDigest: confirmation.intentDigest,
    authorization: stepUpAuthorization,
    proof: requireNearEd25519OperationStepUpProof(operationStepUpProof),
  });
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
    status: 'succeeded',
    interaction: { kind: 'none', overlay: 'none' },
    authMethod: resolveSigningConfirmationAuthMethod(
      preparedStepUp.confirmationAuthPayload.signingAuthPlan,
    ),
  });
  try {
    await ctx.nonceCoordinator.recoverDurableLeases({ walletId: String(candidate.walletId) });
    if (confirmation.readiness.kind !== 'context_ready') {
      throw new Error(
        '[SigningEngine][near] implicit-account funding requires transaction context',
      );
    }
    const result = await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
      ctx,
      thresholdSessionId: materialFacts.thresholdSessionId,
      activeClient: resolvedOperationStepUpMaterial.material.activeClient,
      materialFacts,
      thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
      walletId: commandSubject.walletSession.walletId,
      nearAccountId,
      operationId,
      operationFingerprint,
      displayDigest: confirmation.intentDigest,
      txSigningRequest,
      transactionContext: confirmation.readiness.transactionContext,
      authorization: {
        kind: 'operation_step_up',
        prepared: preparedTransactionStepUp,
        displayDigest: confirmation.intentDigest,
        proof: requireNearEd25519OperationStepUpProof(operationStepUpProof),
        issuedAuthorization: resolvedOperationStepUpMaterial.issuedAuthorization,
      },
    });
    if (!result || result.authorization !== 'operation_step_up') {
      throw new Error('[SigningEngine][near] operation step-up transaction signing is unavailable');
    }
    requireIssuedNearEd25519OperationStepUpAuthorization({
      prepared: preparedTransactionStepUp,
      issuedAuthorization: result.issuedAuthorization,
    });
    const signed = toSignedTransactionResult({
      okResponse: result.okResponse,
      nearAccountId,
      warnings,
      nonceLeases: confirmation.readiness.nonceLeases,
    });
    await markNearNonceLeasesSigned(ctx, confirmation.readiness.nonceLeases);
    return signed;
  } finally {
    resolvedOperationStepUpMaterial.material.activeClient.dispose();
  }
}

async function runAuthorizedNearTransactionWithActionsSigning({
  ctx,
  commandSubject,
  nearAccount,
  transaction,
  rpcCall,
  onEvent,
  confirmationConfigOverride,
  title,
  body,
  signerSlot,
  signingOperationId: providedSigningOperationId,
  signingSessionCoordinator: sessionCoordinator,
  transactionOperation,
  ed25519SigningBoundary,
  passkeyEd25519OperationStepUp,
  emailOtpEd25519StepUp,
  yaoSigningPreparation,
  yaoMaterialExecutor,
}: Extract<NearTransactionWithActionsPayload, { selection: { kind: 'authorized' } }>): Promise<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}> {
  let signingOperationId = providedSigningOperationId;
  const callerProvidedSigningOperationId = Boolean(providedSigningOperationId);
  const ensureSigningOperationId = (): SigningOperationId => {
    signingOperationId = signingOperationId || createNearTransactionSigningOperationId();
    return signingOperationId;
  };
  const nearAccountId = toAccountId(nearAccount.accountId);
  const relayerUrl = ctx.relayerUrl;
  const warnings: string[] = [];
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_02_REQUEST_PREPARED,
    status: 'running',
    message: 'Loading threshold signing state',
    interaction: { kind: 'none', overlay: 'none' },
  });
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    materialExecutor: yaoMaterialExecutor,
    nearAccount,
    signerSlot: ed25519SigningBoundary.signingLane.identity.signer.signerSlot,
    requestedSignerSlot: signerSlot,
    operationLabel: 'signing',
    warnings,
  });
  const signingContext = validateAndPrepareSigningContext({
    nearAccountId,
    relayerUrl,
    thresholdKeyMaterial,
  });

  // Normalize rpcCall to ensure required fields are present.
  const resolvedRpcCall = {
    nearRpcUrl:
      rpcCall.nearRpcUrl ||
      resolvePrimaryNearRpcUrl(PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains),
    nearAccountId,
  } as RpcCallPayload;
  const { txSigningRequest, confirmationTransaction } = buildNearTransactionSigningPayload({
    nearAccountId: String(resolvedRpcCall.nearAccountId),
    transaction,
  });
  const presignFingerprintTransaction = parseThresholdEd25519NearTransaction(
    txSigningRequest,
    'txSigningRequest',
  );
  const operationFingerprint = SigningSessionIds.signingOperationFingerprint(
    await thresholdEd25519NearTransactionPlanningOperationFingerprint({
      nearAccountId,
      nearNetworkId: resolveNearNetwork(
        ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
      ),
      relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
      signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
      transactions: [presignFingerprintTransaction],
    }),
  );
  const operationFingerprintDigest = parseSigningOperationFingerprintDigest(operationFingerprint);

  // UserConfirm before sending anything to the signer worker.
  // WebAuthn uses the typed threshold session policy challenge when passkey reauth is required.
  if (!ctx.touchConfirm) {
    throw new Error('UiConfirm bridge not available for signing');
  }
  const touchConfirm = ctx.touchConfirm;
  if (!sessionCoordinator) {
    throw new Error('[SigningEngine][near] production signing session coordinator is required');
  }
  if (callerProvidedSigningOperationId) {
    sessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
      operationId: ensureSigningOperationId(),
      operationFingerprint,
    });
  }
  const requiredSignatureUses = requiredNearTransactionSignatureUses(transaction);
  const confirmationOperationId = ensureSigningOperationId();
  const signingOperation = {
    operationId: confirmationOperationId,
    operationFingerprint,
    intent: SigningOperationIntent.TransactionSign,
  };
  const runSharedNearTransactionCommand = async <T>(args: {
    commandKind: SigningOperationCommand['kind'];
    execute: () => Promise<T>;
  }): Promise<T> =>
    await runSigningOperationCommand({
      signingSessionPlan: ed25519SigningBoundary.signingSessionPlan,
      signingOperation,
      commandKind: args.commandKind,
      execute: args.execute,
    });
  const providedThresholdSessionId = ed25519SigningBoundary.thresholdSessionId;
  const thresholdSessionId = String(providedThresholdSessionId || '').trim();
  const providedSigningAuthPlan = ed25519SigningBoundary.signingAuthPlan;
  const signingLane = ed25519SigningBoundary.signingLane;
  if (!transactionOperation) {
    throw new Error(
      '[SigningEngine][near] threshold transaction signing requires prepared transaction operation',
    );
  }
  if (
    isWarmSessionSigningAuthPlan(providedSigningAuthPlan) &&
    providedSigningAuthPlan.thresholdSessionId !== providedThresholdSessionId
  ) {
    throw new Error(
      '[SigningEngine][near] warm-session auth plan must match prepared session identity',
    );
  }
  const signingSessionAuthPlan = {
    thresholdSessionId: isWarmSessionSigningAuthPlan(providedSigningAuthPlan)
      ? providedSigningAuthPlan.thresholdSessionId
      : providedThresholdSessionId,
    lane: signingLane,
    signingAuthPlan: providedSigningAuthPlan,
    confirmationAuthPayload: { signingAuthPlan: providedSigningAuthPlan },
    warmSessionReady: isWarmSessionSigningAuthPlan(providedSigningAuthPlan),
  };
  const activeSigningLane = signingLane;
  type NearAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';
  const authSideEffectsStarted = new Set<NearAuthSideEffect>();
  const emitConfirmedAuthSideEffectStarted = (sideEffect: NearAuthSideEffect): void => {
    if (authSideEffectsStarted.has(sideEffect)) return;
    authSideEffectsStarted.add(sideEffect);
    emitSigningBoundaryTrace(
      'near',
      createSigningBoundaryTraceEvent({
        event: 'auth_side_effect_started',
        lane: activeSigningLane,
        sideEffect,
        phase: 'confirmed',
      }),
    );
  };
  const emitUiConfirmProgress = (progress: UserConfirmProgressEvent): void => {
    if (progress.phase === 'auth.passkey.prompt.started') {
      emitConfirmedAuthSideEffectStarted('passkey_reauth');
    }
    emitNearSigningConfirmationProgress(
      {
        onEvent,
        nearAccountId,
        signingAuthPlan: signingSessionAuthPlan.confirmationAuthPayload.signingAuthPlan,
      },
      progress,
    );
  };
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan: providedSigningAuthPlan,
    signingLaneAuth: signingLane.auth,
    requiredSignatureUses,
    operationFingerprintDigest,
    ...(passkeyEd25519OperationStepUp ? { passkeyEd25519OperationStepUp } : {}),
    ...(emailOtpEd25519StepUp ? { emailOtpEd25519StepUp } : {}),
  });
  const confirmationAuthPayload = preparedStepUp.confirmationAuthPayload;
  if (isWarmSessionSigningAuthPlan(confirmationAuthPayload.signingAuthPlan)) {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: {
        thresholdSessionId: confirmationAuthPayload.signingAuthPlan.thresholdSessionId,
        expiresAtMs: confirmationAuthPayload.signingAuthPlan.expiresAtMs,
        remainingUses: confirmationAuthPayload.signingAuthPlan.remainingUses,
      },
    });
  }
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
    status: 'waiting_for_user',
    message: 'Opening confirmation prompt',
    interaction: { kind: 'transaction_confirmation', overlay: 'show' },
  });
  let operationStepUpMaterial: NearOperationStepUpMaterial | null = null;
  if (preparedStepUp.kind !== 'warm_session') {
    operationStepUpMaterial = await prepareNearOperationStepUpMaterial({
      method: preparedStepUp.kind,
      preparation: yaoSigningPreparation,
      executor: yaoMaterialExecutor,
    });
    const material = operationStepUpMaterial;
    const materialFacts = nearOperationStepUpMaterialFacts(material);
    registerNearOperationStepUpBuilder({
      requestId: thresholdSessionId,
      build: async (preparation) => {
        if (preparation.kind !== 'near_transaction') {
          throw new Error('[SigningEngine][near] transaction step-up preparation kind changed');
        }
        if (preparation.operationId !== String(signingOperation.operationId)) {
          throw new Error('[SigningEngine][near] operation step-up operation identity changed');
        }
        return await prepareRouterAbEd25519NearTransactionOperationStepUp({
          ctx,
          thresholdSessionId: materialFacts.thresholdSessionId,
          materialFacts,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          materialActivation: material.materialActivation,
          operationId: signingOperation.operationId,
          operationFingerprint,
          txSigningRequest,
          transactionContext: preparation.transactionContext,
          displayDigest: preparation.displayDigest,
        });
      },
    });
    // The confirmation flow funds an unfunded implicit account through this
    // narrow port before it prepares the step-up (the assertion signs the
    // prepared operation's digest, so funding must precede preparation). The
    // funder lives here because this side holds the Wallet Session and the
    // request-integrity checks. Warm sessions skip it — their authorization is
    // not context-bound, so funding stays deferred to after the confirmation.
    const stepUpFundingMethod = preparedStepUp.kind;
    registerNearImplicitAccountFunder({
      requestId: thresholdSessionId,
      fund: async (fundingRequest) =>
        await fundNearImplicitAccountForOperationStepUp({
          request: fundingRequest,
          ctx,
          nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
          fundingSession: await yaoMaterialExecutor.resolveFundingSession(),
          method: stepUpFundingMethod,
          signingOperation,
          signatureUses: requiredSignatureUses,
        }),
    });
  }
  let confirmation: ConfirmTransactionSigningOperationResult;
  try {
    confirmation = await runSigningConfirmationCommand({
      signingSessionPlan: ed25519SigningBoundary.signingSessionPlan,
      signingOperation,
      runtime: touchConfirm,
      request: {
        ctx: { touchConfirm },
        sessionId: thresholdSessionId,
        chain: 'near',
        kind: 'transaction',
        ...buildSigningConfirmationAuthParams({
          signingAuthPlan: confirmationAuthPayload.signingAuthPlan,
        }),
        walletId: String(signingLane.identity.signer.account.wallet.walletId),
        txSigningRequests: [confirmationTransaction],
        rpcCall: resolvedRpcCall,
        nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
        nearFundingRequest: {
          subject: {
            walletId: signingLane.identity.signer.account.wallet.walletId,
            nearAccountId,
            nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
          },
          operation: {
            ...signingOperation,
            accountId: String(nearAccountId),
          },
          signatureUses: requiredSignatureUses,
        },
        confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
          signingAuthPlan: confirmationAuthPayload.signingAuthPlan,
          override: confirmationConfigOverride,
        }),
        title,
        body,
        onProgress: emitUiConfirmProgress,
      },
    });
  } finally {
    clearNearOperationStepUpBuilder(thresholdSessionId);
    clearNearImplicitAccountFunder(thresholdSessionId);
  }
  emitNearSigningEvent(onEvent, nearAccountId, {
    phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
    status: 'succeeded',
    interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
  });
  const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
    prepared: preparedStepUp,
    confirmation,
  });
  const operationStepUpProof =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : buildNearEd25519OperationStepUpProof({
          authorization: stepUpAuthorization,
          preparation: yaoSigningPreparation,
          auth: transactionOperation.lane.auth,
          walletId: commandSubject.walletSession.walletId,
        });
  const preparedOperationStepUp =
    stepUpAuthorization.kind !== 'warm_session'
      ? consumePreparedNearOperationStepUp({
          requestId: thresholdSessionId,
          ref: requireNearOperationStepUpPreparation(confirmation.operationStepUpPreparation),
        })
      : null;
  const resolvedOperationStepUpMaterial =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : await resolveNearTransactionOperationStepUpMaterial({
          material: requireNearTransactionOperationStepUpMaterial(operationStepUpMaterial),
          prepared: requirePreparedNearOperationStepUp(preparedOperationStepUp),
          displayDigest: confirmation.intentDigest,
          authorization: stepUpAuthorization,
          proof: requireNearEd25519OperationStepUpProof(operationStepUpProof),
        });
  const ownsResolvedOperationStepUpMaterial =
    operationStepUpMaterial?.kind === 'passkey_sealed' ||
    operationStepUpMaterial?.kind === 'email_otp_sealed';
  try {
    await ctx.nonceCoordinator.recoverDurableLeases({
      walletId: String(signingLane.identity.signer.account.wallet.walletId),
    });
  } catch (error) {
    disposeOwnedNearOperationStepUpMaterial({
      resolved: resolvedOperationStepUpMaterial,
      owned: ownsResolvedOperationStepUpMaterial,
    });
    throw error;
  }

  let thresholdSignatureCreated = false;
  const preparedPayload = await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED,
        status: 'running',
        message: 'Preparing NEAR signer',
        interaction: { kind: 'none', overlay: 'none' },
      });
      const resolvedMaterial =
        stepUpAuthorization.kind === 'warm_session'
          ? {
              kind: 'warm_session' as const,
              material: await resolvePreparedNearEd25519YaoMaterial(
                yaoSigningPreparation,
                yaoMaterialExecutor,
              ),
            }
          : {
              kind: 'operation_step_up' as const,
              resolved: resolvedOperationStepUpMaterial!,
            };
      const canonicalThresholdSessionId =
        resolvedMaterial.kind === 'warm_session'
          ? resolvedMaterial.material.facts.thresholdSessionId
          : resolvedMaterial.resolved.material.facts.thresholdSessionId;
      const activeYaoClient =
        resolvedMaterial.kind === 'warm_session'
          ? resolvedMaterial.material.activeClient
          : resolvedMaterial.resolved.material.activeClient;
      const activeWalletSessionState =
        resolvedMaterial.kind === 'warm_session'
          ? await yaoMaterialExecutor.resolveWalletSessionState()
          : null;
      const confirmedNearContext =
        resolvedMaterial.kind === 'warm_session'
          ? await resolveConfirmedNearTransactionContext({
              confirmation,
              ctx,
              nearPublicKeyStr: signingContext.signingNearPublicKeyStr,
              walletSessionState: activeWalletSessionState!,
              authorization: stepUpAuthorization,
              signingOperation,
              signatureUses: requiredSignatureUses,
            })
          : // A step-up funds an unfunded implicit account during the
            // confirmation (see the funder registered above), so it arrives
            // here already context_ready.
            confirmation.readiness.kind === 'context_ready'
            ? confirmation.readiness
            : (() => {
                throw new Error(
                  '[SigningEngine][near] operation step-up confirmation did not resolve a transaction context',
                );
              })();
      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        authMethod: signingSessionAuthPlan.warmSessionReady
          ? 'warm_session'
          : signingSessionAuthPlan.signingAuthPlan.method,
      });

      emitNearSigningEvent(onEvent, nearAccountId, {
        phase: SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED,
        status: 'succeeded',
        message: 'NEAR signer ready',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          signer: 'threshold-ed25519',
          thresholdSessionId: canonicalThresholdSessionId,
          clientBaseSource: 'yao_active_client',
        },
      });
      return {
        canonicalThresholdSessionId,
        activeClient: activeYaoClient,
        walletSessionState: activeWalletSessionState,
        operationMaterialFacts:
          resolvedMaterial.kind === 'operation_step_up'
            ? resolvedMaterial.resolved.material.facts
            : null,
        issuedAuthorization:
          resolvedMaterial.kind === 'operation_step_up'
            ? resolvedMaterial.resolved.issuedAuthorization
            : null,
        transactionContext: confirmedNearContext.transactionContext,
        nonceLeaseRefs: confirmedNearContext.nonceLeases,
      };
    },
  }).catch(
    disposeOwnedNearOperationStepUpMaterialAndRethrow.bind(undefined, {
      resolved: resolvedOperationStepUpMaterial,
      owned: ownsResolvedOperationStepUpMaterial,
    }),
  );
  const {
    canonicalThresholdSessionId,
    activeClient: preparedActiveClient,
    walletSessionState,
    operationMaterialFacts,
    issuedAuthorization,
    transactionContext,
    nonceLeaseRefs,
  } = preparedPayload;
  const releaseUnsignedNonceLeases = async (error: unknown): Promise<void> => {
    if (thresholdSignatureCreated || !nonceLeaseRefs.length) return;
    await releaseNearNonceLeases(ctx, nonceLeaseRefs, 'signing_failed').catch((releaseError) => {
      console.warn('[SigningEngine][near][transaction] failed to release nonce leases', {
        originalError: error instanceof Error ? error.message : String(error || ''),
        releaseError:
          releaseError instanceof Error ? releaseError.message : String(releaseError || ''),
      });
    });
  };
  const executeSignRequest = async (yaoClient: NearEd25519YaoOperationMaterial['activeClient']) => {
    emitNearSigningEvent(onEvent, nearAccountId, {
      phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
      status: 'running',
      interaction: { kind: 'none', overlay: 'none' },
    });
    const routerAbNormalSigningResult =
      stepUpAuthorization.kind !== 'warm_session'
        ? await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: yaoClient,
            materialFacts: operationMaterialFacts!,
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            walletId: commandSubject.walletSession.walletId,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint,
            displayDigest: confirmation.intentDigest,
            txSigningRequest,
            transactionContext,
            authorization: {
              kind: 'operation_step_up',
              prepared: requirePreparedNearOperationStepUp(preparedOperationStepUp),
              displayDigest: confirmation.intentDigest,
              proof:
                stepUpAuthorization.kind === 'passkey'
                  ? {
                      kind: 'passkey',
                      authority: stepUpAuthorization.plannedPasskeyOperationStepUp.authority,
                      credential: stepUpAuthorization.credential,
                    }
                  : {
                      ...buildNearEmailOtpEd25519OperationStepUpProof({
                        preparation: yaoSigningPreparation,
                        auth: transactionOperation.lane.auth,
                        walletId: commandSubject.walletSession.walletId,
                        challengeId: stepUpAuthorization.challengeId,
                        otpCode: stepUpAuthorization.otpCode,
                      }),
                    },
              issuedAuthorization,
            },
          })
        : await tryFinalizeRouterAbEd25519NearTransactionNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: yaoClient,
            walletSessionState: await requireActiveAuthorizedWalletSessionState(walletSessionState),
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            walletId: commandSubject.walletSession.walletId,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint,
            displayDigest: confirmation.intentDigest,
            txSigningRequest,
            transactionContext,
            authorization: { kind: 'reusable_wallet_session' },
          });
    if (routerAbNormalSigningResult) {
      return routerAbNormalSigningResult.okResponse;
    }
    throw new Error('[SigningEngine][near] Router A/B Ed25519 signing is unavailable');
  };

  return await runSharedNearTransactionCommand({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        const okResponse = await executeSignRequest(preparedActiveClient);
        thresholdSignatureCreated = true;
        await markNearNonceLeasesSigned(ctx, nonceLeaseRefs);
        const signedResult = toSignedTransactionResult({
          okResponse,
          nearAccountId,
          warnings,
          nonceLeases: nonceLeaseRefs,
        });
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
          status: 'succeeded',
          interaction: { kind: 'none', overlay: 'hide' },
        });
        emitNearSigningEvent(onEvent, nearAccountId, {
          phase: SigningEventPhase.STEP_15_COMPLETED,
          status: 'succeeded',
          interaction: { kind: 'none', overlay: 'none' },
          data: { operation: 'sign' },
        });
        return signedResult;
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        await releaseUnsignedNonceLeases(err);
        disposeOwnedNearOperationStepUpMaterial({
          resolved: resolvedOperationStepUpMaterial,
          owned: ownsResolvedOperationStepUpMaterial,
        });
        throw err;
      }
    },
  });
}

async function releaseNearNonceLeases(
  ctx: NearSigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
  reason: 'cancelled' | 'auth_failed' | 'signing_failed' | 'nonce_failed',
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.release({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
        reason,
      }),
    ),
  );
}

async function markNearNonceLeasesSigned(
  ctx: NearSigningRuntimeDeps,
  nonceLeases: readonly NonceLeaseRef[],
): Promise<void> {
  if (!nonceLeases.length) return;
  await Promise.all(
    nonceLeases.map((nonceLease) =>
      ctx.nonceCoordinator.markSigned({
        leaseId: nonceLease.leaseId,
        operationId: nonceLease.operationId,
        operationFingerprint: nonceLease.operationFingerprint,
      }),
    ),
  );
}

function toSignedTransactionResult(args: {
  okResponse: WorkerSuccessResponse<typeof WorkerRequestType.SignTransactionsWithActions>;
  nearAccountId: string;
  warnings: string[];
  nonceLeases?: readonly NonceLeaseRef[];
}): {
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
  nonceLease?: NonceLeaseRef;
} {
  const signedTransactions = args.okResponse.payload.signedTransactions || [];
  if (signedTransactions.length !== 1) {
    throw new Error(`Expected one signed transaction but received ${signedTransactions.length}`);
  }

  const signedTx = signedTransactions[0];
  if (!signedTx || !signedTx.transaction || !signedTx.signature) {
    throw new Error('Incomplete signed transaction data received');
  }
  const nonceLease = args.nonceLeases?.[0];
  const serverDispatch = (signedTx as { serverDispatch?: SignedTransaction['serverDispatch'] })
    .serverDispatch;
  const signedTransaction = new SignedTransaction({
    transaction: signedTx.transaction,
    signature: signedTx.signature,
    borsh_bytes: Array.from(signedTx.borshBytes || []),
    ...(nonceLease ? { nonceLease } : {}),
    ...(serverDispatch ? { serverDispatch } : {}),
  });
  return {
    signedTransaction,
    nearAccountId: toAccountId(args.nearAccountId),
    logs: [...(args.okResponse.payload.logs || []), ...args.warnings],
    ...(nonceLease ? { nonceLease } : {}),
  };
}

type ThresholdSigningContext = {
  signingNearPublicKeyStr: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  };
};

function validateAndPrepareSigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
}): ThresholdSigningContext {
  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = String(thresholdKeyMaterial.publicKey || '').trim();
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  return {
    signingNearPublicKeyStr: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
    },
  };
}
