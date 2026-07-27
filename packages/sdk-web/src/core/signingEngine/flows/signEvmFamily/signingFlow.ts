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
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import type { OperationDigestSet } from '@shared/authorization/operationFingerprint';
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
import type { EvmFamilyThresholdEcdsaOperation } from './thresholdAdmission';
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
import type {
  ReadySecp256k1Signer,
  ReadySecp256k1SigningMaterial,
} from './signers/secp256k1';

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
      kind: 'material_from_canonical_capability';
      material: ReadySecp256k1SigningMaterial;
    };

export type EcdsaSigningMaterialPlan =
  | ReadyEcdsaSigningMaterialSource
  | {
      kind: 'unavailable';
      reason:
        | 'material_activation_mismatch'
        | 'chain_mismatch'
        | 'authorization_unavailable';
    };

export type ResolveEcdsaSigningMaterialPlan = (args: {
  requestLabel: unknown;
}) => Promise<EcdsaSigningMaterialPlan>;

function isReadySecp256k1Signer(engine: unknown): engine is ReadySecp256k1Signer {
  return typeof (engine as { signReady?: unknown } | null)?.signReady === 'function';
}

async function buildEvmFamilyOperationDigests(input: {
  operationFingerprint: unknown;
  signingDigest32: Uint8Array;
  displayModel: TxDisplayModel;
}): Promise<OperationDigestSet> {
  const operationFingerprint = String(input.operationFingerprint || '').trim();
  const laneDigest = operationFingerprint.startsWith('sha256:')
    ? operationFingerprint.slice('sha256:'.length)
    : '';
  if (!laneDigest) {
    throw new Error('[chains] exact EVM signing operation fingerprint digest is required');
  }
  return {
    laneDigest: parseDigestB64u(laneDigest),
    intentDigest: parseDigestB64u(base64UrlEncode(input.signingDigest32)),
    displayDigest: parseDigestB64u(
      base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input.displayModel))),
    ),
  };
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
  /* Sizes step-up auth from the raw request so showing the confirmation UI
     never has to wait for the prepared intent (nonce reservation + worker
     intent build). Threshold admission re-derives the exact count from the
     prepared intent after the user confirms. */
  requiredSignatureUsesForRequest: (request: TRequest) => number;
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
          walletId: input.walletId,
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
  let activeThresholdEcdsaOperation: EvmFamilyThresholdEcdsaOperation | null =
    thresholdEcdsaStepUp.kind === 'required' ? thresholdEcdsaStepUp.operation : null;
  const getThresholdEcdsaOperation =
    async (): Promise<EvmFamilyThresholdEcdsaOperation> => {
      if (activeThresholdEcdsaOperation) return activeThresholdEcdsaOperation;
      throw new Error('[chains] threshold ECDSA transaction signing requires an operation');
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

  const ensureReadySecp256k1SigningMaterial = async (
    signReq: SignRequest,
    operation: EvmFamilyThresholdEcdsaOperation,
    operationDigests: OperationDigestSet,
  ): Promise<ReadyEcdsaSigningMaterialSource> => {
    if (!recordBackedReadySecp256k1MaterialSource && input.resolveEcdsaSigningMaterialPlan) {
      const plan = await input.resolveEcdsaSigningMaterialPlan({
        requestLabel: signReq.label,
      });
      switch (plan.kind) {
        case 'material_from_step_up':
        case 'material_from_canonical_capability':
          recordBackedReadySecp256k1MaterialSource = plan;
          break;
        case 'unavailable':
          throw new Error(`[chains] threshold ECDSA material is unavailable: ${plan.reason}`);
      }
    }
    const source = recordBackedReadySecp256k1MaterialSource;
    if (!source) {
      throw new Error('[chains] missing ready threshold ECDSA material for secp256k1 signing');
    }
    if (!stepUpAuthorization || stepUpAuthorization.kind === 'warm_session') return source;
    if (!thresholdEcdsaStepUpRuntime) {
      throw new Error('[chains] ECDSA operation step-up runtime is unavailable');
    }
    // NOTE: preparation runs here, after confirmation, which preserves the
    // pre-cutover ordering but leaves the passkey challenge bound to the
    // placeholder digest rather than this prepared operation. Correcting that
    // ordering is the operation-step-up challenge-binding fix, tracked
    // separately -- it is deliberately not attempted here.
    const prepared = await thresholdEcdsaStepUpRuntime.operationStepUp.prepare({
      operation,
      operationDigests,
      material: source.material,
    });
    return {
      kind: 'material_from_step_up',
      material: await thresholdEcdsaStepUpRuntime.operationStepUp.authorize({
        authorization: stepUpAuthorization,
        prepared,
        material: source.material,
      }),
    };
  };

  const runShowConfirmationCommand = async (): Promise<void> => {
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    input.onConfirmationDisplayed?.();
    /* Deliberately NOT awaiting intentPreparationTask here: the confirmation
       UI mounts with the PENDING placeholders in a loading state, and the
       registered intent preparation streams the real digest/display model in
       (see handleIntentDigestSigningFlow). Blocking here would gate the modal
       on the nonce-reservation RPC and the intent-build worker round-trip. */
    const stepUp = await requireEvmFamilyStepUpAuth({
      thresholdEcdsaStepUp,
      hasThresholdEcdsaRequest,
      needsWebAuthn,
      requiredSignatureUses: config.requiredSignatureUsesForRequest(input.request),
      explicitAuthErrorLabel: config.explicitAuthErrorLabel,
    });
    preparedStepUpAuth = stepUp;
    const confirmationAuthPayload = stepUp.confirmationAuthPayload;
    if (isWarmSessionSigningAuthPlan(confirmationAuthPayload.signingAuthPlan)) {
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
            webauthnChallenge: {
              kind: 'intent_digest' as const,
              challengeB64u: PENDING_CHALLENGE_B64U,
            },
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
    if (!confirmation) {
      throw new Error('[chains] signing confirmation is required before threshold admission');
    }
    if (!preparedStepUpAuth) {
      throw new Error('[chains] signing auth payload is required before threshold admission');
    }
    if (!stepUpAuthorization) {
      throw new Error('[chains] signing step-up authorization is required before threshold admission');
    }
    if (intentHasSecp256k1Request && !activeThresholdEcdsaOperation) {
      throw new Error('[chains] threshold ECDSA operation must be prepared before signing');
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
        const thresholdEcdsaOperation = await getThresholdEcdsaOperation();
        const operationDigests = await buildEvmFamilyOperationDigests({
          operationFingerprint: input.signingOperation?.operationFingerprint,
          signingDigest32: signReq.digest32,
          displayModel: intentPrepared.displayModel,
        });
        const readyMaterialSource = await ensureReadySecp256k1SigningMaterial(
          signReq,
          thresholdEcdsaOperation,
          operationDigests,
        );
        signatures.push(
          await engine.signReady(
            signReq,
            readyMaterialSource.material,
            thresholdEcdsaOperation,
            operationDigests,
          ),
        );
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
        SigningOperationCommandKind.Sign,
      ],
      {
        [SigningOperationCommandKind.ShowConfirmation]: runShowConfirmationCommand,
        [SigningOperationCommandKind.PreparePayload]: runPreparePayloadCommand,
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
