import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type {
  UiConfirmSigningPort,
  UiConfirmRequestConfirmationPort,
  UiConfirmContext,
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
  type SigningAuthPlan,
} from '@/core/signingEngine/stepUpConfirmation/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { toManagedNonceReservationSnapshot } from '@/core/rpcClients/evm/nonceBackend';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
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
import type {
  SigningOperationContext,
  SigningSessionPlan,
} from '../../session/operationState/types';
import { SigningSessionIds } from '../../session/operationState/types';
import { parseSigningOperationFingerprintDigest } from '../../session/planning/operationFingerprint';
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
import type { PreparedEcdsaOperationStepUp } from '../../threshold/ecdsa/operationStepUp';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import type { ReadySecp256k1Signer, ReadySecp256k1SigningMaterial } from './signers/secp256k1';
import type {
  HydratedSecp256k1SigningMaterialResolution,
  ReadySecp256k1SigningMaterialResolution,
} from './readySecp256k1Material';
import type { CapabilityPreparationResult } from '../../session/material/capabilityPreparationResult';
import type { HydratedEcdsaSignerMaterial } from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  PENDING_CHALLENGE_B64U,
  PENDING_INTENT_DIGEST,
  registerIntentDigestPreparation,
  type IntentDigestPreparationResult,
} from '../../stepUpConfirmation/intentDigestPreparation';

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

export type EcdsaSigningMaterialSource =
  | ReadyEcdsaSigningMaterialSource
  | {
      kind: 'material_for_step_up';
      material: HydratedEcdsaSignerMaterial;
    };

/** The material this operation was prepared against is no longer the one the
 * wallet's active manifest names. R90-INV-010: supersession invalidates the
 * preparation -- the caller discards the prepared lane and resolves current
 * canonical state again. It is a retry condition, not a failure, and it is
 * distinct from an activation mismatch caused by asking for the wrong material. */
export type SupersededEcdsaSigningMaterial = {
  kind: 'superseded';
  supersessionKind:
    | 'material_activation_replaced'
    | 'capability_authority_replaced'
    | 'reusable_authorization_replaced';
  preparedMaterialActivation: MpcMaterialActivationRef;
  currentMaterialActivation: MpcMaterialActivationRef;
  material?: never;
  reason?: never;
};

/** Thrown so a superseded preparation unwinds to the retry boundary rather than
 * surfacing as a signing failure. `signEvmFamily` catches it and re-prepares
 * once against current canonical state. */
export class EvmFamilyEcdsaMaterialSupersededError extends Error {
  readonly superseded: SupersededEcdsaSigningMaterial;

  constructor(superseded: SupersededEcdsaSigningMaterial) {
    super(
      `[chains] threshold ECDSA material was superseded (${superseded.supersessionKind}): prepared ${String(
        superseded.preparedMaterialActivation.activationId,
      )}, current ${String(superseded.currentMaterialActivation.activationId)}`,
    );
    this.name = 'EvmFamilyEcdsaMaterialSupersededError';
    this.superseded = superseded;
  }
}

export function isEvmFamilyEcdsaMaterialSupersededError(
  error: unknown,
): error is EvmFamilyEcdsaMaterialSupersededError {
  return error instanceof EvmFamilyEcdsaMaterialSupersededError;
}

type EcdsaSigningMaterialFailure =
  | Extract<ReadySecp256k1SigningMaterialResolution, { kind: 'unavailable' }>
  | Extract<HydratedSecp256k1SigningMaterialResolution, { kind: 'unavailable' }>;

/** Signing preparation has no resumable intermediate state. The generic
 * capability result retains `pending` for operations that genuinely persist a
 * resume token; this specialization exposes only outcomes this boundary can
 * produce. */
export type EcdsaSigningMaterialPlan = Exclude<
  CapabilityPreparationResult<
    ReadyEcdsaSigningMaterialSource,
    never,
    Extract<EcdsaSigningMaterialSource, { kind: 'material_for_step_up' }>,
    SupersededEcdsaSigningMaterial,
    EcdsaSigningMaterialFailure
  >,
  { kind: 'pending' }
>;

export type ResolveEcdsaSigningMaterialPlan = () => Promise<EcdsaSigningMaterialPlan>;

export type RunEcdsaMaterialUse = <T>(task: () => Promise<T>) => Promise<T>;

function hydratedMaterialFromSource(
  source: EcdsaSigningMaterialSource,
): HydratedEcdsaSignerMaterial {
  switch (source.kind) {
    case 'material_for_step_up':
      return source.material;
    case 'material_from_canonical_capability':
    case 'material_from_step_up':
      return source.material.signerSession;
  }
}

function isReadySecp256k1Signer(engine: unknown): engine is ReadySecp256k1Signer {
  return typeof (engine as { signReady?: unknown } | null)?.signReady === 'function';
}

async function buildEvmFamilyOperationDigests(input: {
  operationFingerprint: unknown;
  signingDigest32: Uint8Array;
  displayModel: TxDisplayModel;
}): Promise<OperationDigestSet> {
  const operationFingerprint = String(input.operationFingerprint || '').trim();
  if (!operationFingerprint) {
    throw new Error('[chains] exact EVM signing operation fingerprint digest is required');
  }
  return {
    laneDigest: parseSigningOperationFingerprintDigest(
      SigningSessionIds.signingOperationFingerprint(operationFingerprint),
    ),
    intentDigest: parseDigestB64u(base64UrlEncode(input.signingDigest32)),
    displayDigest: parseDigestB64u(
      base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(input.displayModel))),
    ),
  };
}

function intentDigestPreparationFromEvmIntent(args: {
  intentDigestHex: string;
  challengeB64u: string;
  displayModel: TxDisplayModel;
}): IntentDigestPreparationResult {
  return {
    intentDigest: args.intentDigestHex,
    challengeB64u: args.challengeB64u,
    displayModel: args.displayModel,
  };
}

function digestsEqual(left: OperationDigestSet, right: OperationDigestSet): boolean {
  return (
    String(left.laneDigest) === String(right.laneDigest) &&
    String(left.intentDigest) === String(right.intentDigest) &&
    String(left.displayDigest) === String(right.displayDigest)
  );
}

// The confirmation signed one exact prepared operation. Signing anything whose
// operation identity or digest set differs from it fails closed rather than
// silently authorizing a different operation than the user approved.
function assertPreparedEcdsaOperationStepUpMatches(args: {
  prepared: {
    readonly prepared: PreparedEcdsaOperationStepUp;
    readonly operation: EvmFamilyThresholdEcdsaOperation;
    readonly operationDigests: OperationDigestSet;
  };
  operation: EvmFamilyThresholdEcdsaOperation;
  operationDigests: OperationDigestSet;
}): void {
  if (args.prepared.operation !== args.operation) {
    throw new Error(
      '[chains] prepared ECDSA operation step-up does not match the operation being signed',
    );
  }
  if (!digestsEqual(args.prepared.operationDigests, args.operationDigests)) {
    throw new Error('[chains] prepared ECDSA operation step-up digest drift');
  }
}

// Passkey step-up cannot proceed on an unprepared operation: the WebAuthn
// challenge must be the canonical digest of the exact preparation the grant
// will later be issued against.
function requirePreparedEcdsaStepUpChallenge(args: {
  prepared: {
    readonly prepared: PreparedEcdsaOperationStepUp;
    readonly operation: EvmFamilyThresholdEcdsaOperation;
    readonly operationDigests: OperationDigestSet;
  } | null;
  challengeB64u: string;
}): string {
  if (!args.prepared) {
    throw new Error(
      '[chains] passkey ECDSA step-up requires an operation prepared before confirmation',
    );
  }
  const challengeB64u = String(args.prepared.prepared.challengeB64u || '').trim();
  if (!challengeB64u || challengeB64u !== String(args.challengeB64u || '').trim()) {
    throw new Error(
      '[chains] passkey ECDSA step-up challenge does not match the prepared operation',
    );
  }
  return challengeB64u;
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

export type OwnerEvmFamilySigningAuthorization = {
  readonly kind: 'owner';
};

export type LinkedDeviceEvmFamilySigningAuthorization = {
  readonly kind: 'linked_device';
  readonly confirmationAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
  readonly sign: (input: {
    readonly requestId: string;
    readonly operationId: string;
    readonly operationDigests: OperationDigestSet;
    readonly signingDigest32: Uint8Array;
  }) => Promise<Uint8Array>;
};

export type EvmFamilySigningAuthorization =
  | OwnerEvmFamilySigningAuthorization
  | LinkedDeviceEvmFamilySigningAuthorization;

export type SignEvmFamilyWithUiConfirmArgs<TRequest> = {
  ctx: UiConfirmContext;
  touchConfirm: UiConfirmSigningPort & UiConfirmRequestConfirmationPort;
  walletId: string;
  request: TRequest & { senderSignatureAlgorithm: string };
  engines: EvmFamilySigningEngines;
  onEvent?: (event: SigningFlowEvent) => void;
  signingSessionPlan?: SigningSessionPlan;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  resolveEcdsaSigningMaterialPlan?: ResolveEcdsaSigningMaterialPlan;
  runEcdsaMaterialUse?: RunEcdsaMaterialUse;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  workerCtx: WorkerOperationContext;
  prepareRequestWithManagedNonce?: () => Promise<{
    request: TRequest & { senderSignatureAlgorithm: string };
    reservation: ManagedNonceReservation;
  }>;
  releaseNonceReservation?: (reservation: ManagedNonceReservation) => void | Promise<void>;
  onConfirmationDisplayed?: () => void;
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  authorization: EvmFamilySigningAuthorization;
};

function assertNeverEvmFamilySigningAuthorization(value: never): never {
  throw new Error(`[chains] unsupported EVM-family signing authorization: ${String(value)}`);
}

async function resolvePreparedEvmFamilyAuthorization(input: {
  readonly authorization: EvmFamilySigningAuthorization;
  readonly thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  readonly hasThresholdEcdsaRequest: boolean;
  readonly needsWebAuthn: boolean;
  readonly requiredSignatureUses: number;
  readonly explicitAuthErrorLabel: 'EVM' | 'Tempo';
}): Promise<EvmFamilyPreparedStepUpAuth> {
  switch (input.authorization.kind) {
    case 'linked_device':
      return {
        kind: 'warm_session',
        confirmationAuthPayload: {
          signingAuthPlan: input.authorization.confirmationAuthPlan,
        },
      };
    case 'owner':
      return await requireEvmFamilyStepUpAuth({
        thresholdEcdsaStepUp: input.thresholdEcdsaStepUp,
        hasThresholdEcdsaRequest: input.hasThresholdEcdsaRequest,
        needsWebAuthn: input.needsWebAuthn,
        requiredSignatureUses: input.requiredSignatureUses,
        explicitAuthErrorLabel: input.explicitAuthErrorLabel,
      });
    default:
      return assertNeverEvmFamilySigningAuthorization(input.authorization);
  }
}

function buildPendingLinkedDeviceConfirmationRequest<
  TRequest,
  TResult extends object,
>(args: {
  config: EvmFamilyUiConfirmFlowConfig<
    TRequest & { senderSignatureAlgorithm: string },
    TResult
  >;
  input: SignEvmFamilyWithUiConfirmArgs<TRequest>;
  sessionId: string;
}): ConfirmIntentDigestSigningOperationRequest {
  if (args.input.authorization.kind !== 'linked_device') {
    throw new Error('[chains] pending linked-device confirmation requires linked authorization');
  }
  return {
    ctx: { touchConfirm: args.input.touchConfirm },
    sessionId: args.sessionId,
    chain: args.config.targetKind,
    kind: 'intentDigest',
    signingSubject: {
      kind: 'evm_wallet',
      walletId: args.input.walletId,
    },
    signingAuthPlan: args.input.authorization.confirmationAuthPlan,
    challengeB64u: PENDING_CHALLENGE_B64U,
    intentDigest: PENDING_INTENT_DIGEST,
    displayModel: args.config.buildDisplayModel({
      request: args.input.request,
      signerAccount: args.input.walletId,
      title: args.config.title,
      subtitle: args.config.body,
    }),
    title: args.config.title,
    body: args.config.body,
    confirmationConfigOverride: args.input.confirmationConfigOverride,
  };
}

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
    switch (input.authorization.kind) {
      case 'owner':
        throw new Error(
          '[chains] threshold ECDSA transaction signing requires an explicit auth plan',
        );
      case 'linked_device':
        break;
      default:
        assertNeverEvmFamilySigningAuthorization(input.authorization);
    }
  }
  const authMethod = signingAuthPlan
    ? resolveSigningConfirmationAuthMethod(signingAuthPlan)
    : 'passkey';
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

  const needsWebAuthn =
    config.webauthn.kind === 'supported' && config.webauthn.requestNeedsWebAuthn(input.request);
  let preparedRequest = input.request;
  let nonceReservation: ManagedNonceReservation | null = null;
  let reservationReleased = false;
  let thresholdSignatureCreated = false;
  const activeThresholdEcdsaOperation: EvmFamilyThresholdEcdsaOperation | null =
    thresholdEcdsaStepUp.kind === 'required' ? thresholdEcdsaStepUp.operation : null;
  const getThresholdEcdsaOperation = async (): Promise<EvmFamilyThresholdEcdsaOperation> => {
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
    const intentDigestHex = bytesToHex(firstDigest);
    const displayModel = config.buildDisplayModel({
      request: preparedRequest,
      intentDigest: intentDigestHex,
      signerAccount: input.walletId,
      title: config.title,
      subtitle: config.body,
    });
    // Operation step-up preparation runs here, ahead of confirmation, so the
    // Passkey challenge can bind the exact prepared operation instead of the
    // raw transaction digest. Email OTP shares this prepared operation; only
    // its OTP challenge stays factor-specific.
    let challengeB64u = base64UrlEncode(firstDigest);
    if (
      firstSignRequest.algorithm === 'secp256k1' &&
      thresholdEcdsaStepUpRuntime &&
      activeThresholdEcdsaOperation &&
      input.resolveEcdsaSigningMaterialPlan
    ) {
      const operationDigests = await buildEvmFamilyOperationDigests({
        operationFingerprint: input.signingOperation?.operationFingerprint,
        signingDigest32: inferDigest32FromSignRequest(firstSignRequest),
        displayModel,
      });
      const plan = await input.resolveEcdsaSigningMaterialPlan();
      switch (plan.kind) {
        case 'ready':
          ecdsaSigningMaterialSource = plan.value;
          break;
        case 'authorization_required':
          ecdsaSigningMaterialSource = plan.requirement;
          break;
        case 'superseded':
          throw new EvmFamilyEcdsaMaterialSupersededError(plan.replacement);
        case 'failed':
          throw new Error(
            `[chains] threshold ECDSA material is unavailable: ${plan.failure.reason}`,
          );
      }
      const preparationMaterialSource = ecdsaSigningMaterialSource;
      if (!preparationMaterialSource) {
        throw new Error('[chains] ECDSA preparation did not produce signing material');
      }
      const prepared = await thresholdEcdsaStepUpRuntime.operationStepUp.prepare({
        operation: activeThresholdEcdsaOperation,
        operationDigests,
        material: hydratedMaterialFromSource(preparationMaterialSource),
      });
      preparedEcdsaOperationStepUp = {
        prepared,
        operation: activeThresholdEcdsaOperation,
        operationDigests,
      };
      challengeB64u = prepared.challengeB64u;
    }
    return {
      intent,
      challengeB64u,
      intentDigestHex,
      displayModel,
    };
  })();
  if (input.authorization.kind === 'linked_device') {
    registerIntentDigestPreparation({
      requestId: sessionId,
      preparation: intentPreparationTask.then(intentDigestPreparationFromEvmIntent),
    });
  }
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
  let ecdsaSigningMaterialSource: EcdsaSigningMaterialSource | null = null;
  // The exact operation step-up prepared BEFORE confirmation. Its canonical
  // digest is what the Passkey challenge signs and what the server recomputes
  // from the parsed preparation, so the object is built once and threaded
  // through confirmation and grant issuance unchanged.
  let preparedEcdsaOperationStepUp: {
    readonly prepared: PreparedEcdsaOperationStepUp;
    readonly operation: EvmFamilyThresholdEcdsaOperation;
    readonly operationDigests: OperationDigestSet;
  } | null = null;

  const ensureReadySecp256k1SigningMaterial = async (
    signReq: SignRequest,
    operation: EvmFamilyThresholdEcdsaOperation,
    operationDigests: OperationDigestSet,
  ): Promise<ReadyEcdsaSigningMaterialSource> => {
    // Re-resolve inside the exact-material queue after confirmation. The user
    // may spend an arbitrary amount of time in the prompt, so the material and
    // capability authority prepared above cannot be treated as current here.
    if (input.resolveEcdsaSigningMaterialPlan) {
      const plan = await input.resolveEcdsaSigningMaterialPlan();
      switch (plan.kind) {
        case 'ready':
          ecdsaSigningMaterialSource = plan.value;
          break;
        case 'authorization_required':
          ecdsaSigningMaterialSource = plan.requirement;
          break;
        case 'superseded':
          throw new EvmFamilyEcdsaMaterialSupersededError(plan.replacement);
        case 'failed':
          throw new Error(
            `[chains] threshold ECDSA material is unavailable: ${plan.failure.reason}`,
          );
      }
    }
    const source = ecdsaSigningMaterialSource;
    if (!source) {
      throw new Error('[chains] missing ready threshold ECDSA material for secp256k1 signing');
    }
    if (!stepUpAuthorization || stepUpAuthorization.kind === 'warm_session') {
      if (source.kind === 'material_for_step_up') {
        // Unreachable: an auth-neutral candidate escalates to a same-method
        // step-up when the runtime reports no active reusable Wallet Session,
        // so a warm-session authorization cannot be paired with one here.
        throw new Error(
          '[chains] auth-neutral ECDSA material reached signing without a same-method step-up',
        );
      }
      return source;
    }
    if (!thresholdEcdsaStepUpRuntime) {
      throw new Error('[chains] ECDSA operation step-up runtime is unavailable');
    }
    // The prepared operation is the one the user's confirmation actually
    // signed over. It is never rebuilt here; any drift between it and the
    // operation now being signed fails closed.
    const preparedStepUp = preparedEcdsaOperationStepUp;
    if (!preparedStepUp) {
      throw new Error(
        '[chains] ECDSA step-up signing requires an operation prepared before confirmation',
      );
    }
    assertPreparedEcdsaOperationStepUpMatches({
      prepared: preparedStepUp,
      operation,
      operationDigests,
    });
    return {
      kind: 'material_from_step_up',
      material: await thresholdEcdsaStepUpRuntime.operationStepUp.authorize({
        authorization: stepUpAuthorization,
        prepared: preparedStepUp.prepared,
        material: hydratedMaterialFromSource(source),
      }),
    };
  };

  const runShowConfirmationCommand = async (): Promise<void> => {
    if (input.authorization.kind === 'linked_device') {
      emitProgress({
        phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
        status: 'waiting_for_user',
        interaction: { kind: 'transaction_confirmation', overlay: 'show' },
      });
      input.onConfirmationDisplayed?.();
      const pendingConfirmationRequest = buildPendingLinkedDeviceConfirmationRequest({
        config,
        input,
        sessionId,
      });
      const runConfirmation = createSigningConfirmationCommandHandler({
        runtime: input.touchConfirm,
        request: pendingConfirmationRequest,
      });
      confirmation = await runConfirmation();
      // A confirmed request has already awaited the exact preparation through
      // the intent-digest readiness registry. A cancelled request returns
      // immediately and leaves preparation to unwind through the outer catch.
      intentPrepared = await intentPreparationTask;
      intentHasSecp256k1Request = intentPrepared.intent.signRequests.some(
        (signReq) => signReq.algorithm === 'secp256k1',
      );
      const stepUp = await resolvePreparedEvmFamilyAuthorization({
        authorization: input.authorization,
        thresholdEcdsaStepUp,
        hasThresholdEcdsaRequest,
        needsWebAuthn,
        requiredSignatureUses: config.requiredSignatureUsesForRequest(input.request),
        explicitAuthErrorLabel: config.explicitAuthErrorLabel,
      });
      if (!isWarmSessionSigningAuthPlan(stepUp.confirmationAuthPayload.signingAuthPlan)) {
        throw new Error('[chains] linked-device signing requires a warm-session auth plan');
      }
      preparedStepUpAuth = stepUp;
      emitProgress({
        phase: SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED,
        status: 'succeeded',
        interaction: { kind: 'none', overlay: 'none' },
        data: {
          thresholdSessionId: stepUp.confirmationAuthPayload.signingAuthPlan.thresholdSessionId,
          expiresAtMs: stepUp.confirmationAuthPayload.signingAuthPlan.expiresAtMs,
          remainingUses: stepUp.confirmationAuthPayload.signingAuthPlan.remainingUses,
        },
      });
      notifyAuthSideEffectStarted('auth_confirmed');
      emitProgress({
        phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
        status: 'succeeded',
        interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
      });
      return;
    }

    // Resolve the exact operation, canonical material, and operation-step-up
    // preparation before any factor-specific side effect begins. In particular,
    // an Email OTP challenge must never be issued for material that this
    // preparation then discovers is superseded or unavailable.
    intentPrepared = await intentPreparationTask;
    intentHasSecp256k1Request = intentPrepared.intent.signRequests.some(
      (signReq) => signReq.algorithm === 'secp256k1',
    );
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED,
      status: 'waiting_for_user',
      interaction: { kind: 'transaction_confirmation', overlay: 'show' },
    });
    input.onConfirmationDisplayed?.();
    const stepUp = await resolvePreparedEvmFamilyAuthorization({
      authorization: input.authorization,
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
          thresholdSessionId: confirmationAuthPayload.signingAuthPlan.thresholdSessionId,
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
      challengeB64u: intentPrepared.challengeB64u,
      intentDigest: intentPrepared.intentDigestHex,
      displayModel: intentPrepared.displayModel,
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
              challengeB64u: requirePreparedEcdsaStepUpChallenge({
                prepared: preparedEcdsaOperationStepUp,
                challengeB64u: intentPrepared.challengeB64u,
              }),
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
    const confirmed = confirmation;
    if (!confirmed) {
      throw new Error('[chains] signing confirmation did not produce a decision');
    }
    notifyAuthSideEffectStarted('auth_confirmed');
    switch (input.authorization.kind) {
      case 'owner':
        stepUpAuthorization = buildEvmFamilyEcdsaStepUpAuthorization({
          prepared: stepUp,
          confirmation: confirmed,
        });
        break;
      default:
        assertNeverEvmFamilySigningAuthorization(input.authorization);
    }
    emitProgress({
      phase: SigningEventPhase.STEP_05_CONFIRMATION_APPROVED,
      status: 'succeeded',
      interaction: { kind: 'transaction_confirmation', overlay: 'hide' },
    });
  };

  const runPreparePayloadCommand = async (): Promise<void> => {
    if (!intentPrepared) {
      throw new Error('[chains] signing intent must be prepared before threshold admission');
    }
    if (!confirmation) {
      throw new Error('[chains] signing confirmation is required before threshold admission');
    }
    if (!preparedStepUpAuth) {
      throw new Error('[chains] signing auth payload is required before threshold admission');
    }
    switch (input.authorization.kind) {
      case 'owner':
        if (!stepUpAuthorization) {
          throw new Error(
            '[chains] signing step-up authorization is required before threshold admission',
          );
        }
        if (intentHasSecp256k1Request && !activeThresholdEcdsaOperation) {
          throw new Error('[chains] threshold ECDSA operation must be prepared before signing');
        }
        break;
      case 'linked_device':
        break;
      default:
        assertNeverEvmFamilySigningAuthorization(input.authorization);
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
        const operationDigests = await buildEvmFamilyOperationDigests({
          operationFingerprint: input.signingOperation?.operationFingerprint,
          signingDigest32: signReq.digest32,
          displayModel: intentPrepared.displayModel,
        });
        switch (input.authorization.kind) {
          case 'linked_device': {
            const operationId = input.signingOperation?.operationId;
            if (!operationId) {
              throw new Error('[chains] linked-device ECDSA signing requires an operation id');
            }
            signatures.push(
              await input.authorization.sign({
                requestId: sessionId,
                operationId: String(operationId),
                operationDigests,
                signingDigest32: signReq.digest32,
              }),
            );
            continue;
          }
          case 'owner':
            break;
          default:
            assertNeverEvmFamilySigningAuthorization(input.authorization);
        }
        const thresholdEcdsaOperation = await getThresholdEcdsaOperation();
        const engine = input.engines.secp256k1;
        if (!engine) {
          throw new Error(`[chains] missing engine for algorithm: ${signReq.algorithm}`);
        }
        if (!isReadySecp256k1Signer(engine)) {
          throw new Error('[chains] secp256k1 signing engine requires ready material support');
        }
        if (!input.runEcdsaMaterialUse) {
          throw new Error('[chains] secp256k1 signing requires exact material serialization');
        }
        signatures.push(
          await input.runEcdsaMaterialUse(async () => {
            const readyMaterialSource = await ensureReadySecp256k1SigningMaterial(
              signReq,
              thresholdEcdsaOperation,
              operationDigests,
            );
            return await engine.signReady(
              signReq,
              readyMaterialSource.material,
              thresholdEcdsaOperation,
              operationDigests,
            );
          }),
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
