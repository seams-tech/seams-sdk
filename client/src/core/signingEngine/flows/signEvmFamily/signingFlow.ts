import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  UiConfirmSigningPort,
  UiConfirmSecureConfirmationPort,
  UiConfirmContext,
  WarmSessionStatusReader,
} from '@/core/signingEngine/uiConfirm/types';
import type {
  KeyRef,
  SignRequest,
  SignerMap,
  SigningIntent,
  SignatureBytes,
} from '@/core/signingEngine/interfaces/signing';
import type { ThresholdEcdsaSecp256k1KeyRef } from '@/core/signingEngine/interfaces/signing';
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
import type { SigningSessionBudgetReservation } from '../../session/budget/budget';
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
} from './requireEvmFamilyStepUpAuth';
import { buildEvmFamilyEcdsaStepUpAuthorization } from './stepUpAuthorization';

export type EvmFamilySigningAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';

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
  engines: SignerMap<SignRequest, KeyRef, SignatureBytes>;
  onEvent?: (event: SigningFlowEvent) => void;
  signingSessionPlan?: SigningSessionPlan;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: TRequest & { senderSignatureAlgorithm: string };
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void | Promise<void>;
  onConfirmationDisplayed?: () => void;
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  reserveWalletSigningSessionBudget?: (
    operation: BudgetAdmittedOperation<SelectedEcdsaLane>,
  ) => Promise<SigningSessionBudgetReservation | null>;
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
      preparedOperation: null,
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
  let thresholdEcdsaKeyRef = input.thresholdEcdsaKeyRef || null;
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
    if (!input.reserveWalletSigningSessionBudget) return;
    walletBudgetReservation =
      (await input.reserveWalletSigningSessionBudget(thresholdEcdsaOperation)) || null;
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
    if (!leaseId || !operationId) {
      throw new Error(
        `[chains] managed ${config.nonceErrorLabel} nonce reservation is missing lease metadata`,
      );
    }
    await input.ctx.nonceCoordinator.markSigned({
      leaseId,
      operationId,
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
  let ensuredThresholdKeyRef: ThresholdEcdsaSecp256k1KeyRef | null = null;
  let ensureThresholdKeyRefTask: Promise<ThresholdEcdsaSecp256k1KeyRef> | null = null;

  const ensureThresholdKeyRef = async (): Promise<ThresholdEcdsaSecp256k1KeyRef> => {
    if (ensuredThresholdKeyRef) return ensuredThresholdKeyRef;
    if (ensureThresholdKeyRefTask) return await ensureThresholdKeyRefTask;
    if (thresholdEcdsaStepUpRuntime?.thresholdReconnect) {
      if (!stepUpAuthorization || stepUpAuthorization.kind !== 'warm_session') {
        throw new Error(
          '[chains] threshold ECDSA reconnect requires warm-session step-up authorization',
        );
      }
      notifyAuthSideEffectStarted('threshold_reconnect');
      ensureThresholdKeyRefTask = (async () => {
        const thresholdReconnect = thresholdEcdsaStepUpRuntime.thresholdReconnect!;
        const ensured = await thresholdReconnect.ensureThresholdEcdsaKeyRefReady({
          authorization: stepUpAuthorization,
          usesNeeded: 1,
        });
        thresholdEcdsaKeyRef = ensured.keyRef;
        ensuredThresholdKeyRef = ensured.keyRef;
        activeThresholdEcdsaOperation = ensured.operation;
        return ensured.keyRef;
      })();
      try {
        return await ensureThresholdKeyRefTask;
      } finally {
        ensureThresholdKeyRefTask = null;
      }
    }
    if (thresholdEcdsaKeyRef) {
      ensuredThresholdKeyRef = thresholdEcdsaKeyRef;
      return thresholdEcdsaKeyRef;
    }
    throw new Error('[chains] missing threshold ECDSA keyRef for secp256k1 signing');
  };

  const runShowConfirmationCommand = async (): Promise<void> => {
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    input.onConfirmationDisplayed?.();
    const stepUp = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest,
      needsWebAuthn,
      explicitAuthErrorLabel: config.explicitAuthErrorLabel,
    });
    preparedStepUpAuth = stepUp;
    const confirmationAuthPayload = stepUp.confirmationAuthPayload;
    if (isWarmSessionSigningAuthPlan(confirmationAuthPayload.signingAuthPlan)) {
      await reserveWalletSigningBudgetOnce();
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
    const runConfirmation = createSigningConfirmationCommandHandler({
      runtime: input.touchConfirm,
      request: {
        ctx: { touchConfirm: input.touchConfirm },
        sessionId,
        chain: config.targetKind,
        kind: 'intentDigest',
        signerAccountId: input.walletId,
        challengeB64u: PENDING_CHALLENGE_B64U,
        intentDigest: PENDING_INTENT_DIGEST,
        ...(eagerDisplayModel ? { displayModel: eagerDisplayModel } : {}),
        title: config.title,
        body: config.body,
        ...confirmationAuthPayload,
        ...(stepUp.kind === 'email_otp' ? { emailOtpPrompt: stepUp.emailOtpPrompt } : {}),
        ...(stepUp.kind === 'passkey' && stepUp.plannedPasskeyReconnect?.sessionPolicyDigest32
          ? { sessionPolicyDigest32: stepUp.plannedPasskeyReconnect.sessionPolicyDigest32 }
          : {}),
        onProgress: emitUiConfirmProgress,
        confirmationConfigOverride: input.confirmationConfigOverride,
      },
    });
    confirmation = await runConfirmation();
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
          ensureThresholdEcdsaKeyRefReady:
            thresholdEcdsaStepUpRuntime.thresholdReconnect.ensureThresholdEcdsaKeyRefReady,
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
      usesNeeded: 1,
    });
    if (admissionCompletion) {
      thresholdEcdsaKeyRef = admissionCompletion.result.keyRef;
      ensuredThresholdKeyRef = admissionCompletion.result.keyRef;
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
        keyRef = await ensureThresholdKeyRef();
      } else {
        throw new Error(
          `[chains] unsupported ${config.explicitAuthErrorLabel} signing algorithm: ${signReq.algorithm}`,
        );
      }

      const engine = input.engines[signReq.algorithm];
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
