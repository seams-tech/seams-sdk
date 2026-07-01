import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  UiConfirmSigningPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmContext,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import type {
  KeyRef,
  SignRequest,
  Signer,
  SigningIntent,
  SignatureBytes,
} from '@/core/signingEngine/interfaces/signing';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';
import {
  isWarmSessionSigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { toManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
import { base64UrlEncode } from '@shared/utils/base64';
import { bytesToHex } from '@/core/signingEngine/chains/evm/bytes';
import type { WorkerOperationContext } from '@/core/signingEngine/workerManager/executeWorkerOperation';
import { normalizeAuthenticationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import type { ReadyEcdsaSignerSession } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  createSigningFlowEvent,
  SigningEventPhase,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
} from '@/core/signingEngine/stepUpConfirmation/intentDigestPreparation';
import {
  isSigningSessionBudgetReservation,
  type SigningSessionBudgetReservation,
  type SigningSessionBudgetReserveResult,
} from '../../session/budget/budget';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { BudgetAdmittedOperation } from '../../session/operationState/transactionState';
import type { SigningOperationContext, SigningSessionPlan } from '../../session/operationState/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  SigningOperationCommandKind,
  buildSigningOperationCommandSteps,
  createSigningOperationPlan,
  runSigningOperationCommandSteps,
  runUnplannedSigningOperationCommandSequence,
  type SigningOperationCommand,
  type SigningOperationCommandExecutor,
  type SigningOperationTransitionObserver,
} from '../shared/signingStateMachine';
import type {
  EvmFamilyThresholdEcdsaAdmissionConfirmation,
  EvmFamilyThresholdEcdsaAdmissionMode,
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import {
  completeEvmFamilyThresholdEcdsaAdmissionAfterConfirmation,
} from './thresholdAdmission';
import {
  type ConfirmIntentDigestSigningOperationRequest,
  type ConfirmIntentDigestSigningOperationResult,
  createSigningConfirmationCommandHandler,
  inferDigest32FromSignRequest,
  makeRequestId,
  mapSigningConfirmationProgress,
  resolveSigningConfirmationAuth,
  resolveSigningConfirmationAuthMethod,
} from '../shared/signingConfirmation';
import {
  requireEvmFamilyStepUpAuth,
  signingAuthPlanFromThresholdEcdsaStepUp,
  type EvmFamilyPreparedStepUpAuth,
  type EvmFamilyThresholdEcdsaStepUp,
  type EvmFamilyThresholdEcdsaStepUpRuntime,
} from './requireEvmFamilyStepUpAuth';
import { buildEvmFamilyEcdsaStepUpAuthorization } from './stepUpAuthorization';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import { requiredEvmFamilySignatureUses } from './signatureUses';
import type {
  ReadySecp256k1Signer,
  ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';
import { buildReadySecp256k1SigningMaterial } from './signers/secp256k1';

type EvmFamilySigningWebAuthnMode<TRequest> =
  | {
      kind: 'not_supported';
    }
  | {
      kind: 'supported';
      requestNeedsWebAuthn: (request: TRequest) => boolean;
      validateIntent: (intent: SigningIntent<unknown, unknown>) => void;
      resolveKeyRef: (args: {
        ctx: UiConfirmContext;
        walletId: string;
        workerCtx: WorkerOperationContext;
        signReq: Extract<SignRequest, { kind: 'webauthn' }>;
        credential: WebAuthnAuthenticationCredential;
      }) => Promise<{
        signReq: SignRequest;
        keyRef: KeyRef;
      }>;
    };

type EvmFamilySigningEngines = {
  secp256k1?: ReadySecp256k1Signer;
  webauthnP256?: Signer<SignRequest, KeyRef, SignatureBytes>;
};

export type ReadyEcdsaSigningMaterialSource =
  | {
      kind: 'material_from_step_up';
      material: ReadySecp256k1SigningMaterial;
    }
  | {
      kind: 'material_from_runtime_validated_record';
      material: ReadySecp256k1SigningMaterial;
    };

export type EcdsaSigningMaterialPlan =
  | ReadyEcdsaSigningMaterialSource
  | {
      kind: 'reconnect_required';
      runtime: NonNullable<EvmFamilyThresholdEcdsaStepUpRuntime['thresholdReconnect']>;
    }
  | {
      kind: 'unavailable';
      reason:
        | 'missing_record'
        | 'not_runtime_validated'
        | 'rp_id_mismatch'
        | 'chain_mismatch'
        | 'single_use_email_otp_consumed';
    };

export type ResolveEcdsaSigningMaterialPlan = (args: {
  requestLabel: unknown;
}) => Promise<EcdsaSigningMaterialPlan>;

function isReadySecp256k1Signer(engine: unknown): engine is ReadySecp256k1Signer {
  return typeof (engine as { signReady?: unknown } | null)?.signReady === 'function';
}

export type EvmFamilyUiConfirmFlowConfig<TRequest, TResult extends object> = {
  targetKind: ThresholdEcdsaChainTarget['kind'];
  flowName: 'evm' | 'tempo';
  explicitAuthErrorLabel: 'EVM' | 'Tempo';
  nonceErrorLabel: 'EVM' | 'Tempo';
  title: string;
  body: string;
  buildIntent: (args: {
    workerCtx: WorkerOperationContext;
    request: TRequest;
  }) => Promise<SigningIntent<unknown, TResult>>;
  buildDisplayModel: (args: {
    request: TRequest;
    intentDigest?: string;
    signerAccount: string;
    title: string;
    subtitle: string;
  }) => TxDisplayModel;
  webauthn: EvmFamilySigningWebAuthnMode<TRequest>;
};

export type SignEvmFamilyWithUiConfirmArgs<TRequest> = {
  ctx: UiConfirmContext;
  touchConfirm: UiConfirmSigningPort &
    UiConfirmSecureConfirmationPort &
    WarmSessionStatusReader;
  walletId: string;
  request: TRequest & { senderSignatureAlgorithm: string };
  engines: EvmFamilySigningEngines;
  onEvent?: (event: SigningFlowEvent) => void;
  signingSessionPlan?: SigningSessionPlan;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  resolveEcdsaSigningMaterialPlan?: ResolveEcdsaSigningMaterialPlan;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: TRequest & { senderSignatureAlgorithm: string };
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void | Promise<void>;
  onConfirmationDisplayed?: () => void;
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  reserveSigningGrantBudget?: (
    input: EvmFamilySigningGrantBudgetReservationInput,
  ) => Promise<SigningSessionBudgetReserveResult>;
};

export type EvmFamilySigningGrantBudgetReservationInput = {
  operation: BudgetAdmittedOperation<SelectedEcdsaLane>;
  signerSession: ReadyEcdsaSignerSession;
};

export async function signEvmFamilyWithUiConfirm<TRequest, TResult extends object>(args: {
  config: EvmFamilyUiConfirmFlowConfig<TRequest & { senderSignatureAlgorithm: string }, TResult>;
  input: SignEvmFamilyWithUiConfirmArgs<TRequest>;
}): Promise<TResult> {
  const { config, input } = args;
  const sessionId = makeRequestId('intent');
  const flowId = `signing:${config.flowName}:${input.walletId}:${sessionId}`;
  const hasThresholdEcdsaRequest = input.request.senderSignatureAlgorithm === 'secp256k1';
  const thresholdEcdsaStepUp = input.thresholdEcdsaStepUp;
  const thresholdEcdsaStepUpRuntime =
    thresholdEcdsaStepUp.kind === 'not_required' ? undefined : thresholdEcdsaStepUp.runtime;
  const signingAuthPlan = signingAuthPlanFromThresholdEcdsaStepUp(thresholdEcdsaStepUp);
  if (hasThresholdEcdsaRequest && !signingAuthPlan) {
    throw new Error(
      '[chains] threshold ECDSA transaction signing requires an explicit auth plan',
    );
  }
  const authMethod = resolveSigningConfirmationAuthMethod(
    signingAuthPlan,
    Boolean(thresholdEcdsaStepUpRuntime?.emailOtpSigning),
  );
  const emitProgress = (
    event: Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId' | 'authMethod'>,
  ) => {
    try {
      input.onEvent?.(
        createSigningFlowEvent({
          ...event,
          flowId,
          accountId: input.walletId,
          authMethod,
        }),
      );
    } catch {}
  };
  const authSideEffectsStarted = new Set<EvmFamilySigningAuthSideEffect>();
  const notifyAuthSideEffectStarted = (sideEffect: EvmFamilySigningAuthSideEffect): void => {
    if (authSideEffectsStarted.has(sideEffect)) return;
    authSideEffectsStarted.add(sideEffect);
    try {
      thresholdEcdsaStepUpRuntime?.onAuthSideEffectStarted?.(sideEffect);
    } catch {}
  };
  const emitUiConfirmProgress = (progress: {
    phase: string;
    status: 'running' | 'succeeded' | 'failed';
    message?: string;
    data?: unknown;
  }) => {
    if (progress.phase === 'auth.passkey.prompt.started') {
      notifyAuthSideEffectStarted('passkey_reauth');
    }
    const mapped = mapSigningConfirmationProgress(progress, authMethod);
    if (mapped) emitProgress(mapped);
  };
  const runSharedSigningCommandSequence = async (
    commands: readonly SigningOperationCommand['kind'][],
    handlers: Partial<Record<SigningOperationCommand['kind'], () => Promise<void>>>,
  ): Promise<void> => {
    const executeCommand = async (kind: SigningOperationCommand['kind']): Promise<void> => {
      await handlers[kind]?.();
    };
    if (!input.signingSessionPlan) {
      await runUnplannedSigningOperationCommandSequence({
        commands,
        execute: executeCommand,
      });
      return;
    }
    const operationPlan = createSigningOperationPlan({
      sessionPlan: input.signingSessionPlan,
      operation: input.signingOperation || null,
      commands,
    });
    const executor: SigningOperationCommandExecutor = {
      execute: async (command) => {
        await executeCommand(command.kind);
      },
    };
    const result = await runSigningOperationCommandSteps({
      steps: buildSigningOperationCommandSteps(operationPlan),
      executor,
      onTransition: input.onSigningOperationTransition,
    });
    if (!result.ok) throw result.error;
    if (result.finalState.kind === 'failed') {
      throw new Error(result.finalState.reason);
    }
  };

  let eagerDisplayModel: TxDisplayModel | undefined;
  try {
    eagerDisplayModel = config.buildDisplayModel({
      request: input.request,
      signerAccount: input.walletId,
      title: config.title,
      subtitle: config.body,
    });
  } catch {}
  const needsWebAuthn =
    config.webauthn.kind === 'supported' &&
    config.webauthn.requestNeedsWebAuthn(input.request);
  let preparedRequest = input.request;
  let nonceReservation: ManagedNonceReservation | null = null;
  let reservationReleased = false;
  let thresholdSignatureCreated = false;
  let walletBudgetReservation: SigningSessionBudgetReservation | null = null;
  let walletBudgetReservationAttempted = false;
  let activeThresholdEcdsaOperation: EvmFamilyThresholdEcdsaOperation | null =
    thresholdEcdsaStepUp.kind === 'required_admitted' ? thresholdEcdsaStepUp.operation : null;
  const getBudgetAdmittedThresholdEcdsaOperation =
    async (): Promise<EvmFamilyThresholdEcdsaOperation> => {
      if (activeThresholdEcdsaOperation) return activeThresholdEcdsaOperation;
      throw new Error(
        '[chains] threshold ECDSA transaction signing requires budget-admitted state before signing',
      );
    };
  const reserveWalletSigningBudgetOnce = async (): Promise<void> => {
    if (walletBudgetReservationAttempted) return;
    walletBudgetReservationAttempted = true;
    const thresholdEcdsaOperation = await getBudgetAdmittedThresholdEcdsaOperation();
    if (!input.reserveSigningGrantBudget) return;
    const signerSession = thresholdEcdsaSignerSession;
    if (!signerSession) {
      throw new Error(
        '[SigningSessionBudget] ECDSA budget reservation requires a ready signer session',
      );
    }
    const reservationResult = await input.reserveSigningGrantBudget({
      operation: thresholdEcdsaOperation,
      signerSession,
    });
    if (reservationResult?.kind === 'reservation_identity_mismatch') {
      throw new Error('[SigningSessionBudget] signing grant reservation identity mismatch');
    }
    walletBudgetReservation = isSigningSessionBudgetReservation(reservationResult)
      ? reservationResult
      : null;
  };
  const releaseWalletBudgetReservation = (): void => {
    if (!walletBudgetReservation) return;
    walletBudgetReservation.release();
    walletBudgetReservation = null;
  };
  const releaseNonceReservation = async (): Promise<void> => {
    if (reservationReleased || !nonceReservation || !input.releaseNonceReservation) return;
    reservationReleased = true;
    try {
      await input.releaseNonceReservation(nonceReservation);
    } catch {}
  };
  const markNonceReservationSigned = async (): Promise<void> => {
    if (!nonceReservation) return;
    const leaseId = String(nonceReservation.leaseId || '').trim();
    const operationId = String(nonceReservation.operationId || '').trim();
    const operationFingerprint = String(nonceReservation.operationFingerprint || '').trim();
    if (!leaseId || !operationId || !operationFingerprint) {
      throw new Error(
        `[chains] managed ${config.nonceErrorLabel} nonce reservation is missing lease metadata`,
      );
    }
    await input.ctx.nonceCoordinator.markSigned({
      leaseId,
      operationId,
      operationFingerprint,
    });
  };

  const intentPreparationTask = (async () => {
    if (input.prepareRequestWithManagedNonce) {
      const prepared = await input.prepareRequestWithManagedNonce();
      preparedRequest = prepared.request;
      nonceReservation = prepared.reservation;
    }

    const intent = await config.buildIntent({
      workerCtx: input.workerCtx,
      request: preparedRequest,
    });
    if (config.webauthn.kind === 'supported') {
      config.webauthn.validateIntent(intent);
    }
    const firstSignRequest = intent.signRequests[0];
    if (!firstSignRequest) {
      throw new Error('[chains] signing intent has no sign requests');
    }
    const firstDigest = inferDigest32FromSignRequest(firstSignRequest);
    const challengeB64u = base64UrlEncode(firstDigest);
    const intentDigestHex = bytesToHex(firstDigest);
    const displayModel = config.buildDisplayModel({
      request: preparedRequest,
      intentDigest: intentDigestHex,
      signerAccount: input.walletId,
      title: config.title,
      subtitle: config.body,
    });
    return {
      intent,
      challengeB64u,
      intentDigestHex,
      displayModel,
    };
  })();
  registerIntentDigestPreparation({
    requestId: sessionId,
    preparation: intentPreparationTask.then((prepared) => ({
      intentDigest: prepared.intentDigestHex,
      challengeB64u: prepared.challengeB64u,
      displayModel: prepared.displayModel,
      title: config.title,
      body: config.body,
    })),
  });

  type ConfirmationAuthPayload = Awaited<
    ReturnType<typeof resolveSigningConfirmationAuth>
  >['confirmationAuthPayload'];
  type PreparedIntent = Awaited<typeof intentPreparationTask>;

  let preparedStepUpAuth: EvmFamilyPreparedStepUpAuth | null = null;
  let stepUpAuthorization: ReturnType<typeof buildEvmFamilyEcdsaStepUpAuthorization> | null = null;
  let confirmation: ConfirmIntentDigestSigningOperationResult | null = null;
  let intentPrepared: PreparedIntent | null = null;
  let intentHasSecp256k1Request = false;
  let signedResult: TResult | null = null;
  let recordBackedReadySecp256k1MaterialSource: ReadyEcdsaSigningMaterialSource | null = null;
  let ensureReadySecp256k1SigningMaterialTask:
    | Promise<ReadySecp256k1SigningMaterial>
    | null = null;
  let thresholdEcdsaSignerSession: ReadyEcdsaSignerSession | null =
    thresholdEcdsaStepUp.kind === 'required_admitted'
      ? thresholdEcdsaStepUp.signerSession
      : null;
  let thresholdEcdsaSingleUseEmailOtpSession =
    thresholdEcdsaStepUp.kind === 'required_admitted'
      ? thresholdEcdsaStepUp.singleUseEmailOtpSession
      : false;

  const buildCurrentReadySecp256k1SigningMaterialSource = ():
    | ReadyEcdsaSigningMaterialSource
    | null => {
    const signerSession = thresholdEcdsaSignerSession;
    if (!signerSession) return null;
    return {
      kind: 'material_from_step_up',
      material: buildReadySecp256k1SigningMaterial({
        walletId: input.walletId,
        signerSession,
        singleUseEmailOtpSession: thresholdEcdsaSingleUseEmailOtpSession,
      }),
    };
  };

  const ensureReadySecp256k1SigningMaterial = async (
    signReq: SignRequest,
  ): Promise<ReadyEcdsaSigningMaterialSource> => {
    const currentReadyMaterial = buildCurrentReadySecp256k1SigningMaterialSource();
    if (currentReadyMaterial) return currentReadyMaterial;
    if (recordBackedReadySecp256k1MaterialSource) {
      return recordBackedReadySecp256k1MaterialSource;
    }
    if (ensureReadySecp256k1SigningMaterialTask) {
      return {
        kind: 'material_from_step_up',
        material: await ensureReadySecp256k1SigningMaterialTask,
      };
    }
    if (thresholdEcdsaStepUpRuntime?.thresholdReconnect) {
      if (!stepUpAuthorization || stepUpAuthorization.kind !== 'warm_session') {
        throw new Error(
          '[chains] threshold ECDSA reconnect requires warm-session step-up authorization',
        );
      }
      notifyAuthSideEffectStarted('threshold_reconnect');
      ensureReadySecp256k1SigningMaterialTask = (async () => {
        const thresholdReconnect = thresholdEcdsaStepUpRuntime.thresholdReconnect!;
        const ensured = await thresholdReconnect.ensureThresholdEcdsaReadyMaterial({
          authorization: stepUpAuthorization,
          usesNeeded: intentPrepared
            ? requiredEvmFamilySignatureUses(intentPrepared.intent)
            : 1,
        });
        thresholdEcdsaSignerSession = ensured.signerSession;
        thresholdEcdsaSingleUseEmailOtpSession = false;
        activeThresholdEcdsaOperation = ensured.operation;
        const readyMaterial = buildCurrentReadySecp256k1SigningMaterialSource();
        if (!readyMaterial) {
          throw new Error('[chains] threshold ECDSA reconnect did not return ready material');
        }
        return readyMaterial.material;
      })();
      try {
        return {
          kind: 'material_from_step_up',
          material: await ensureReadySecp256k1SigningMaterialTask,
        };
      } finally {
        ensureReadySecp256k1SigningMaterialTask = null;
      }
    }
    if (input.resolveEcdsaSigningMaterialPlan) {
      const plan = await input.resolveEcdsaSigningMaterialPlan({
        requestLabel: signReq.label,
      });
      switch (plan.kind) {
        case 'material_from_step_up':
        case 'material_from_runtime_validated_record':
          recordBackedReadySecp256k1MaterialSource = plan;
          return plan;
        case 'reconnect_required':
          throw new Error('[chains] threshold ECDSA reconnect is required before signing');
        case 'unavailable':
          throw new Error(`[chains] threshold ECDSA material is unavailable: ${plan.reason}`);
      }
    }
    throw new Error('[chains] missing ready threshold ECDSA material for secp256k1 signing');
  };

  const runShowConfirmationCommand = async (): Promise<void> => {
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    input.onConfirmationDisplayed?.();
    const preparedIntentForBudget = await intentPreparationTask;
    const stepUp = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest,
      needsWebAuthn,
      requiredSignatureUses: requiredEvmFamilySignatureUses(preparedIntentForBudget.intent),
      explicitAuthErrorLabel: config.explicitAuthErrorLabel,
    });
    preparedStepUpAuth = stepUp;
    const confirmationAuthPayload = stepUp.confirmationAuthPayload;
    if (isWarmSessionSigningAuthPlan(confirmationAuthPayload.signingAuthPlan)) {
      if (activeThresholdEcdsaOperation) {
        await reserveWalletSigningBudgetOnce();
      }
      emitProgress({
        phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          sessionId: confirmationAuthPayload.signingAuthPlan.sessionId,
          expiresAtMs: confirmationAuthPayload.signingAuthPlan.expiresAtMs,
          remainingUses: confirmationAuthPayload.signingAuthPlan.remainingUses,
        },
      });
    }
    const confirmationRequestBase = {
      ctx: { touchConfirm: input.touchConfirm },
      sessionId,
      chain: config.targetKind,
      kind: 'intentDigest' as const,
      signingSubject: {
        kind: 'evm_wallet' as const,
        walletId: input.walletId,
      },
      challengeB64u: PENDING_CHALLENGE_B64U,
      intentDigest: PENDING_INTENT_DIGEST,
      ...(eagerDisplayModel ? { displayModel: eagerDisplayModel } : {}),
      title: config.title,
      body: config.body,
      onProgress: emitUiConfirmProgress,
      confirmationConfigOverride: input.confirmationConfigOverride,
    };
    const confirmationRequest: ConfirmIntentDigestSigningOperationRequest =
      stepUp.kind === 'passkey'
        ? {
            ...confirmationRequestBase,
            ...stepUp.confirmationAuthPayload,
            webauthnChallenge: stepUp.plannedPasskeyReconnect.webauthnChallenge,
          }
        : stepUp.kind === 'email_otp'
          ? {
              ...confirmationRequestBase,
              ...stepUp.confirmationAuthPayload,
              emailOtpPrompt: stepUp.emailOtpPrompt,
            }
          : {
              ...confirmationRequestBase,
              ...stepUp.confirmationAuthPayload,
            };
    const runConfirmation = createSigningConfirmationCommandHandler({
      runtime: input.touchConfirm,
      request: confirmationRequest,
    });
    confirmation = await runConfirmation();
    notifyAuthSideEffectStarted('auth_confirmed');
    stepUpAuthorization = buildEvmFamilyEcdsaStepUpAuthorization({
      prepared: stepUp,
      confirmation,
    });
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
      status: 'succeeded',
      interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
    });
  };

  const runPreparePayloadCommand = async (): Promise<void> => {
    intentPrepared = await intentPreparationTask;
    intentHasSecp256k1Request = intentPrepared.intent.signRequests.some(
      (signReq) => signReq.algorithm === 'secp256k1',
    );
    const requiredSignatureUses = requiredEvmFamilySignatureUses(intentPrepared.intent);
    if (!confirmation) {
      throw new Error('[chains] signing confirmation is required before threshold admission');
    }
    if (!preparedStepUpAuth) {
      throw new Error('[chains] signing auth payload is required before threshold admission');
    }
    if (!stepUpAuthorization) {
      throw new Error('[chains] signing step-up authorization is required before threshold admission');
    }
    const admissionMode: EvmFamilyThresholdEcdsaAdmissionMode = (() => {
      if (!intentHasSecp256k1Request) return { kind: 'not_required' };
      if (activeThresholdEcdsaOperation && thresholdEcdsaSignerSession) {
        return { kind: 'already_admitted' };
      }
      if (thresholdEcdsaStepUpRuntime?.emailOtpSigning) {
        return {
          kind: 'email_otp',
          emailOtpSigning: thresholdEcdsaStepUpRuntime.emailOtpSigning,
        };
      }
      if (stepUpAuthorization.kind === 'passkey' && thresholdEcdsaStepUpRuntime?.passkeyReconnect) {
        return {
          kind: 'passkey_reconnect',
          passkeyEcdsaReconnect: thresholdEcdsaStepUpRuntime.passkeyReconnect,
          onThresholdReconnectStarted: () => notifyAuthSideEffectStarted('threshold_reconnect'),
        };
      }
      if (thresholdEcdsaStepUpRuntime?.thresholdReconnect) {
        return {
          kind: 'threshold_reconnect',
          ensureThresholdEcdsaReadyMaterial:
            thresholdEcdsaStepUpRuntime.thresholdReconnect.ensureThresholdEcdsaReadyMaterial,
          onThresholdReconnectStarted: () => notifyAuthSideEffectStarted('threshold_reconnect'),
        };
      }
      return { kind: 'already_admitted' };
    })();
    const admissionConfirmation: EvmFamilyThresholdEcdsaAdmissionConfirmation =
      admissionMode.kind === 'threshold_reconnect'
        ? stepUpAuthorization.kind === 'warm_session'
          ? {
              kind: 'warm_session',
              authorization: stepUpAuthorization,
            }
          : { kind: 'none' }
        : admissionMode.kind === 'email_otp'
          ? stepUpAuthorization.kind === 'email_otp'
            ? {
                kind: 'email_otp',
                authorization: stepUpAuthorization,
              }
            : { kind: 'none' }
          : admissionMode.kind === 'passkey_reconnect'
            ? stepUpAuthorization.kind === 'passkey'
              ? {
                  kind: 'passkey',
                  authorization: stepUpAuthorization,
                }
              : { kind: 'none' }
            : { kind: 'none' };
    const admissionCompletion = await completeEvmFamilyThresholdEcdsaAdmissionAfterConfirmation({
      mode: admissionMode,
      confirmation: admissionConfirmation,
      usesNeeded: requiredSignatureUses,
    });
    if (admissionCompletion) {
      recordBackedReadySecp256k1MaterialSource = null;
      thresholdEcdsaSignerSession = admissionCompletion.result.signerSession;
      thresholdEcdsaSingleUseEmailOtpSession = admissionCompletion.source === 'email_otp';
      activeThresholdEcdsaOperation = admissionCompletion.result.operation;
    }
  };

  const runReserveBudgetCommand = async (): Promise<void> => {
    if (intentHasSecp256k1Request) {
      await reserveWalletSigningBudgetOnce();
    }
  };

  const runSignCommand = async (): Promise<void> => {
    if (!intentPrepared) {
      throw new Error('[chains] signing intent must be prepared before signing');
    }
    if (!confirmation) {
      throw new Error('[chains] signing confirmation must complete before signing');
    }
    const intent = intentPrepared.intent;
    if (intentHasSecp256k1Request) {
      emitProgress({
        phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
        status: 'running',
        interaction: { kind: 'none', overlay: 'none' },
      });
    }
    const signatures: SignatureBytes[] = [];
    for (const signReq of intent.signRequests) {
      let keyRef: KeyRef;
      if (signReq.kind === 'webauthn') {
        if (config.webauthn.kind !== 'supported') {
          throw new Error('[chains] WebAuthn signing is not supported for this chain');
        }
        if (!confirmation.credential) {
          throw new Error('[chains] missing WebAuthn credential from touchConfirm');
        }
        keyRef = (
          await config.webauthn.resolveKeyRef({
            ctx: input.ctx,
            walletId: input.walletId,
            workerCtx: input.workerCtx,
            signReq,
            credential: normalizeAuthenticationCredential(confirmation.credential),
          })
        ).keyRef;
      } else if (signReq.algorithm === 'secp256k1') {
        const engine = input.engines.secp256k1;
        if (!engine) {
          throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
        }
        if (!isReadySecp256k1Signer(engine)) {
          throw new Error('[chains] secp256k1 signing engine requires ready material support');
        }
        await getBudgetAdmittedThresholdEcdsaOperation();
        const readyMaterialSource = await ensureReadySecp256k1SigningMaterial(signReq);
        signatures.push(await engine.signReady(signReq, readyMaterialSource.material));
        continue;
      } else {
        throw new Error(
          `[chains] unsupported ${config.explicitAuthErrorLabel} signing algorithm: ${signReq.algorithm}`,
        );
      }

      const engine = input.engines.webauthnP256;
      if (!engine) {
        throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
      }
      signatures.push(await engine.sign(signReq, keyRef));
    }
    signedResult = await intent.finalize(signatures);
    thresholdSignatureCreated = true;
    await markNonceReservationSigned();
    emitProgress({
      phase: SigningEventPhase.STEP_11_TRANSACTION_SIGNED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'hide' },
    });
    emitProgress({
      phase: SigningEventPhase.STEP_15_COMPLETED,
      status: 'succeeded',
      interaction: { kind: 'none', overlay: 'none' },
      data: { operation: 'sign' },
    });
  };

  try {
    await runSharedSigningCommandSequence(
      [
        SigningOperationCommandKind.ShowConfirmation,
        SigningOperationCommandKind.PreparePayload,
        SigningOperationCommandKind.ReserveBudget,
        SigningOperationCommandKind.Sign,
      ],
      {
        [SigningOperationCommandKind.ShowConfirmation]: runShowConfirmationCommand,
        [SigningOperationCommandKind.PreparePayload]: runPreparePayloadCommand,
        [SigningOperationCommandKind.ReserveBudget]: runReserveBudgetCommand,
        [SigningOperationCommandKind.Sign]: runSignCommand,
      },
    );
    if (!signedResult) {
      throw new Error('[chains] signing operation completed without a signed result');
    }
    const result = signedResult as TResult;
    if (!nonceReservation) return result;
    return {
      ...result,
      managedNonce: toManagedNonceReservationSnapshot(nonceReservation),
    };
  } catch (error: unknown) {
    if (!thresholdSignatureCreated) {
      releaseWalletBudgetReservation();
      if (nonceReservation) {
        await releaseNonceReservation();
      } else if (input.releaseNonceReservation) {
        await intentPreparationTask
          .then(async () => {
            await releaseNonceReservation();
          })
          .catch(() => undefined);
      }
    }
    throw error;
  }
}
