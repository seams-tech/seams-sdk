import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { SigningAuthPlan } from '@/core/signingEngine/touchConfirm/shared/confirmTypes';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { assertThresholdSigningSessionReady } from '../../orchestration/shared/thresholdSigningSessionReadiness';
import type { SigningLaneContext, SigningSessionPlan } from '../../session/signingSessionTypes';
import {
  createSigningExecutionCommandTraceEvent,
  type SigningExecutionCommand,
} from '../../session/SigningExecutionMachine';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
} from '../../session/SigningSessionTrace';
import type { EvmFamilySigningDeps } from '../evmSigning';
import { resolveThresholdEcdsaCommitQueueKey } from '../thresholdLifecycle/thresholdEcdsaCommitQueue';
import {
  emitEvmFamilySigningEvent,
  emitEvmFamilySigningExecutionTrace,
} from './events';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type {
  EvmFamilyLifecycleEventCallback,
  EvmFamilySenderSignatureAlgorithm,
} from './types';
import {
  loadSecp256k1EngineCtor,
  loadWebAuthnP256EngineCtor,
} from './signerLoader';
import { createEvmFamilySigningSessionCoordinator } from './signingSessionCoordinator';
import { ensureSmartAccountDeploymentReady } from './smartAccount';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from './ecdsaReadiness';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';

type ThresholdEcdsaPresignRefillEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: {
    scheduled: boolean;
    reason?: string;
    [key: string]: unknown;
  };
};

type ThresholdEcdsaCommitQueueArgs = {
  nearAccountId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<unknown>;
};

type EvmFamilyAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';

type EvmFamilyRuntimeCommandKind = Extract<
  SigningExecutionCommand['kind'],
  'requestOtp' | 'reconnectThreshold'
>;

type EvmFamilyEmailOtpSigningForFlow = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (otpCode: string, challengeId?: string) => Promise<ThresholdEcdsaSecp256k1KeyRef>;
};

function executionCommandTraceForPlan(args: {
  signingSessionPlan?: SigningSessionPlan;
  commandKind: EvmFamilyRuntimeCommandKind;
}) {
  const plan = args.signingSessionPlan;
  if (!plan || plan.kind === 'not_ready') return null;
  return createSigningExecutionCommandTraceEvent({
    plan,
    commandKind: args.commandKind,
  });
}

async function executeEvmFamilyRuntimeCommand<T>(args: {
  signingSessionPlan?: SigningSessionPlan;
  commandKind: EvmFamilyRuntimeCommandKind;
  execute: () => Promise<T>;
}): Promise<T> {
  const result = await args.execute();
  const traceEvent = executionCommandTraceForPlan({
    signingSessionPlan: args.signingSessionPlan,
    commandKind: args.commandKind,
  });
  if (traceEvent) {
    emitEvmFamilySigningExecutionTrace(traceEvent);
  }
  return result;
}

function wrapEmailOtpSigningWithRuntimeCommands(args: {
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigning?: EvmFamilyEmailOtpSigningForFlow;
}): EvmFamilyEmailOtpSigningForFlow | undefined {
  const emailOtpSigning = args.emailOtpSigning;
  if (!emailOtpSigning) return undefined;
  return {
    ...emailOtpSigning,
    prepare: async () =>
      await executeEvmFamilyRuntimeCommand({
        signingSessionPlan: args.signingSessionPlan,
        commandKind: 'requestOtp',
        execute: emailOtpSigning.prepare,
      }),
    ...(emailOtpSigning.resend
      ? {
          resend: async () =>
            await executeEvmFamilyRuntimeCommand({
              signingSessionPlan: args.signingSessionPlan,
              commandKind: 'requestOtp',
              execute: emailOtpSigning.resend!,
            }),
        }
      : {}),
  };
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingAuthPlan?: SigningAuthPlan;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyEmailOtpSigningForFlow;
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  getThresholdEcdsaKeyRef: () => ThresholdEcdsaSecp256k1KeyRef | undefined;
  setThresholdEcdsaKeyRef: (keyRef: ThresholdEcdsaSecp256k1KeyRef) => void;
  getEcdsaSigningLane: () => SigningLaneContext | undefined;
}) {
  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);
  const signerWorkerCtx = args.deps.getSignerWorkerContext();
  const ctx = args.deps.touchConfirm.getContext();
  const signingSessionCoordinator = createEvmFamilySigningSessionCoordinator(args.deps, args.onEvent);
  const emailOtpSigningForFlow = wrapEmailOtpSigningWithRuntimeCommands({
    signingSessionPlan: args.signingSessionPlan,
    emailOtpSigning: args.emailOtpSigningForFlow,
  });
  const emitConfirmedAuthSideEffectStarted = (sideEffect: EvmFamilyAuthSideEffect): void => {
    let lane: SigningLaneContext | undefined;
    try {
      lane = args.getEcdsaSigningLane();
    } catch {
      lane = undefined;
    }
    emitSigningBoundaryTrace(
      'evm-family',
      createSigningBoundaryTraceEvent({
        event: 'auth_side_effect_started',
        lane,
        sideEffect,
        phase: 'confirmed',
      }),
    );
  };
  const flowArgs = {
    ctx,
    touchConfirm: args.deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    nearAccountId: args.nearAccountId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        shouldAbort: args.shouldAbort,
        thresholdEcdsaPresignPoolPolicy:
          args.deps.tatchiPasskeyConfigs.signing.thresholdEcdsa.presignPool,
        onThresholdEcdsaPresignRefillScheduled: ({
          trigger,
          result,
        }: ThresholdEcdsaPresignRefillEvent) => {
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_08_PRESIGN_REFILL_SCHEDULED,
              status: 'running',
              accountId: args.nearAccountId,
              message: result.scheduled
                ? `Scheduled threshold presign refill (${trigger})`
                : `Skipped threshold presign refill (${trigger}): ${result.reason}`,
              interaction: { kind: 'none', overlay: 'none' },
              data: { trigger, ...result },
            });
          } catch {}
        },
        enqueueThresholdEcdsaCommit: async (queueArgs: ThresholdEcdsaCommitQueueArgs) => {
          const thresholdSessionId = String(queueArgs.thresholdSessionId || '').trim();
          const queueKey = resolveThresholdEcdsaCommitQueueKey({
            chain: args.request.chain,
            thresholdSessionId,
          });
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_10_COMMIT_QUEUED,
              status: 'running',
              accountId: args.nearAccountId,
              interaction: { kind: 'none', overlay: 'none' },
              data: { queueKey, chain: args.request.chain },
            });
          } catch {}
          return await args.deps.withThresholdEcdsaCommitQueue({
            queueKey,
            nearAccountId: queueArgs.nearAccountId,
            enabled: true,
            shouldAbort: queueArgs.shouldAbort,
            task: async () => {
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              await assertThresholdSigningSessionReady({
                signingSessionCoordinator,
                nearAccountId: String(queueArgs.nearAccountId),
                chain: args.request.chain,
                sessionId: thresholdSessionId,
                usesNeeded: 1,
              });
              try {
                emitEvmFamilySigningEvent(args.onEvent, {
                  phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
                  status: 'running',
                  accountId: args.nearAccountId,
                  interaction: { kind: 'none', overlay: 'none' },
                  data: { queueKey, chain: args.request.chain },
                });
              } catch {}
              await ensureSmartAccountDeploymentReady({
                deps: args.deps,
                nearAccountId: args.nearAccountId,
                request: args.request,
                onEvent: args.onEvent,
                ...(args.getThresholdEcdsaKeyRef()
                  ? { thresholdEcdsaKeyRef: args.getThresholdEcdsaKeyRef() }
                  : {}),
              });
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              return await queueArgs.task();
            },
          });
        },
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(args.getThresholdEcdsaKeyRef()
      ? { keyRefsByAlgorithm: { secp256k1: args.getThresholdEcdsaKeyRef() } }
      : {}),
    ...(emailOtpSigningForFlow ? { emailOtpSigning: emailOtpSigningForFlow } : {}),
    signingAuthPlan: args.signingAuthPlan,
    confirmationConfigOverride: args.confirmationConfigOverride,
    ...(args.senderSignatureAlgorithm === 'secp256k1'
      ? {
          onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted,
          ensureThresholdEcdsaKeyRefReady: async () => {
            const readyKeyRef = await executeEvmFamilyRuntimeCommand({
              signingSessionPlan: args.signingSessionPlan,
              commandKind: 'reconnectThreshold',
              execute: async () =>
                await ensureEvmFamilyThresholdEcdsaKeyRefReady({
                  deps: args.deps,
                  lane: args.getEcdsaSigningLane()!,
                  keyRef: args.getThresholdEcdsaKeyRef(),
                  shouldAbort: args.shouldAbort,
                  onEvent: args.onEvent,
                }),
            });
            args.setThresholdEcdsaKeyRef(readyKeyRef);
            return readyKeyRef;
          },
        }
      : {}),
  };

  return { flowArgs, signingSessionCoordinator };
}
