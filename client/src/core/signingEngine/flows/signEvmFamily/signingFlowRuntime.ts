import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { assertThresholdSigningSessionReady } from '../../session/warmCapabilities/thresholdSigningSessionReadiness';
import type { SigningOperationContext, SigningSessionPlan } from '../../session/operationState/types';
import {
  SigningOperationCommandKind,
  runSigningOperationCommandTrace,
  type SigningOperationTransitionObserver,
} from '../shared/signingStateMachine';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningSessionFlowTrace,
} from '../../session/operationState/trace';
import type { EvmFamilySigningDeps } from '../../interfaces/operationDeps';
import { resolveThresholdEcdsaCommitQueueKey } from '../../threshold/ecdsa/commitQueue';
import { emitEvmFamilySigningEvent, emitEvmFamilySigningOperationTrace } from './events';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { EvmFamilyLifecycleEventCallback, EvmFamilySenderSignatureAlgorithm } from './types';
import {
  loadSecp256k1EngineCtor,
  loadWebAuthnP256EngineCtor,
} from './signerLoader';
import { createEvmFamilyWarmSessionServices } from './warmSessionServices';
import { ensureSmartAccountDeploymentReady } from './smartAccount';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from './ecdsaReadiness';
import {
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import { buildEcdsaSessionPolicy } from '../../threshold/sessionPolicy';
import {
  buildEcdsaSessionIdentity,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyPasskeyEcdsaProvisionPlan,
  buildEvmFamilyWarmSessionReconnectPlan,
} from './provisionPlan';

function resolveTransactionStepUpSessionUses(operationUsesNeeded?: number): number {
  const normalized = Math.floor(Number(operationUsesNeeded) || 0);
  return normalized > 0 ? normalized : 1;
}

type ThresholdEcdsaPresignRefillEvent = {
  trigger: 'commit_start' | 'post_sign_success';
  result: {
    scheduled: boolean;
    reason?: string;
    [key: string]: unknown;
  };
};

type ThresholdEcdsaCommitQueueArgs = {
  walletId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<unknown>;
};

type EvmFamilyThresholdEcdsaKeyRefUpdate = {
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
  signingSessionIdentity: {
    thresholdSessionId: string;
    walletSigningSessionId: string;
  };
};

function requirePlannedReconnectSessionIdentity(args: {
  sessionId: string;
  walletSigningSessionId: string;
}): {
  thresholdSessionId: string;
  walletSigningSessionId: string;
} {
  return buildEcdsaSessionIdentity({
    thresholdSessionId: args.sessionId,
    walletSigningSessionId: args.walletSigningSessionId,
  });
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyThresholdEcdsaStepUpRuntime['emailOtpSigning'];
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  getThresholdEcdsaKeyRef: () => ThresholdEcdsaSecp256k1KeyRef | undefined;
  setThresholdEcdsaKeyRef: (
    update: EvmFamilyThresholdEcdsaKeyRefUpdate,
  ) => Promise<EvmFamilyThresholdEcdsaOperation> | EvmFamilyThresholdEcdsaOperation;
  getResolvedEcdsaSigningLane: () => ResolvedEvmFamilyEcdsaSigningLane;
}) {
  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);
  const signerWorkerCtx = args.deps.getSignerWorkerContext();
  const ctx = args.deps.touchConfirm.getContext();
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const walletId = String(args.walletSession.walletId);
  const requestChainId = args.chainTarget.chainId;
  const requestChainTarget = args.chainTarget;
  const runRuntimeCommand = async <T>(
    commandKind:
      | typeof SigningOperationCommandKind.RequestOtp
      | typeof SigningOperationCommandKind.ConnectThreshold,
    execute: () => Promise<T>,
  ): Promise<T> =>
    await runSigningOperationCommandTrace({
      signingSessionPlan: args.signingSessionPlan,
      commandKind,
      ...(args.signingOperation ? { operation: args.signingOperation } : {}),
      onTransition: args.onSigningOperationTransition || emitEvmFamilySigningOperationTrace,
      execute,
    });
  const emailOtpSigningForFlow = args.emailOtpSigningForFlow
    ? {
        ...args.emailOtpSigningForFlow,
        prepare: async () =>
          await runRuntimeCommand(
            SigningOperationCommandKind.RequestOtp,
            args.emailOtpSigningForFlow!.prepare,
          ),
        ...(args.emailOtpSigningForFlow.resend
          ? {
              resend: async () =>
                await runRuntimeCommand(
                  SigningOperationCommandKind.RequestOtp,
                  args.emailOtpSigningForFlow!.resend!,
                ),
            }
          : {}),
      }
    : undefined;
  const buildPasskeyEcdsaReconnect = () => {
    if (args.senderSignatureAlgorithm !== 'secp256k1') return undefined;
    return {
      prepare: async ({ usesNeeded }: { usesNeeded: number }) => {
        const lane = args.getResolvedEcdsaSigningLane();
        const keyRef =
          args.getThresholdEcdsaKeyRef() ||
          readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane });
        const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        if (!rpId) {
          throw new Error('[SigningEngine] missing rpId for passkey ECDSA reconnect');
        }
        const relayerKeyId = String(
          record?.relayerKeyId || keyRef?.backendBinding?.relayerKeyId || '',
        ).trim();
        if (!relayerKeyId) {
          throw new Error('[SigningEngine] missing relayerKeyId for passkey ECDSA reconnect');
        }
        // Passkey step-up mints a fresh wallet signing session. The planned
        // policy digest must be the confirmation challenge so the reconnect
        // can consume that same WebAuthn assertion.
        const remainingUses = resolveTransactionStepUpSessionUses(usesNeeded);
        const ecdsaThresholdKeyId = String(
          record?.ecdsaThresholdKeyId || keyRef?.ecdsaThresholdKeyId || '',
        ).trim();
        if (!ecdsaThresholdKeyId) {
          throw new Error(
            '[SigningEngine] passkey ECDSA reconnect requires threshold key identity',
          );
        }
	        const { policy, sessionPolicyDigest32 } = await buildEcdsaSessionPolicy({
	          walletSessionUserId: walletId,
	          subjectId: lane.subjectId,
	          rpId,
	          relayerKeyId,
          chainTarget: lane.chainTarget,
          ecdsaThresholdKeyId,
          ...(record?.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
          ...(record?.participantIds?.length
            ? { participantIds: record.participantIds }
            : keyRef?.participantIds?.length
              ? { participantIds: keyRef.participantIds }
              : {}),
          remainingUses,
        });
        return {
          sessionId: policy.sessionId,
          walletSigningSessionId: policy.walletSigningSessionId,
          sessionPolicyDigest32,
        };
      },
      reconnect: async ({
        authorization,
        usesNeeded,
      }: {
        authorization: Parameters<
          NonNullable<EvmFamilyThresholdEcdsaStepUpRuntime['passkeyReconnect']>['reconnect']
        >[0]['authorization'];
        usesNeeded: number;
      }) => {
        const lane = args.getResolvedEcdsaSigningLane();
        const keyRef =
          args.getThresholdEcdsaKeyRef() ||
          readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane });
        const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
        const reconnectPlan = buildEvmFamilyPasskeyEcdsaProvisionPlan({
          authorization,
          lane,
          keyRef,
          record: record || null,
          sessionBudgetUses: resolveTransactionStepUpSessionUses(usesNeeded),
        });
        const reconnectSessionIdentity = requirePlannedReconnectSessionIdentity({
          sessionId: reconnectPlan.newSessionIdentity.thresholdSessionId,
          walletSigningSessionId: reconnectPlan.newSessionIdentity.walletSigningSessionId,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_start',
          accountId: walletId,
          chain: args.request.chain,
          chainId: requestChainId,
          lane: {
            authMethod: lane.authMethod,
            walletSigningSessionId: String(lane.walletSigningSessionId),
            thresholdSessionId: String(lane.thresholdSessionId),
          },
          reconnectSessionIdentity,
          usesNeeded,
        });
        const readyKeyRef = await runRuntimeCommand(
          SigningOperationCommandKind.ConnectThreshold,
          async () =>
                  await ensureEvmFamilyThresholdEcdsaKeyRefReady({
                    mode: 'planned_reconnect',
                    deps: args.deps,
                    lane,
                    chainId: requestChainId,
                    keyRef: args.getThresholdEcdsaKeyRef(),
                    reconnectSessionIdentity,
              reconnectPlan,
              operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
              sessionBudgetUses: resolveTransactionStepUpSessionUses(usesNeeded),
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            }),
        );
        const operation = await args.setThresholdEcdsaKeyRef({
          keyRef: readyKeyRef,
          signingSessionIdentity: reconnectSessionIdentity,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_admitted',
          accountId: walletId,
          chain: args.request.chain,
          chainId: requestChainId,
          keyRef: {
            walletSigningSessionId: readyKeyRef.walletSigningSessionId,
            thresholdSessionId: readyKeyRef.thresholdSessionId,
            hasThresholdSessionAuthToken: Boolean(readyKeyRef.thresholdSessionAuthToken),
          },
          budgetKind: operation.budgetAdmission ? 'admitted' : 'missing',
        });
        return { keyRef: readyKeyRef, operation };
      },
    };
  };
  const emitConfirmedAuthSideEffectStarted = (
    sideEffect: 'passkey_reauth' | 'threshold_reconnect',
  ): void => {
    let lane: ResolvedEvmFamilyEcdsaSigningLane | undefined;
    try {
      lane = args.getResolvedEcdsaSigningLane();
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
  const passkeyEcdsaReconnect = buildPasskeyEcdsaReconnect();
  const thresholdEcdsaStepUpRuntime: EvmFamilyThresholdEcdsaStepUpRuntime | undefined =
    args.senderSignatureAlgorithm === 'secp256k1'
      ? {
          ...(emailOtpSigningForFlow ? { emailOtpSigning: emailOtpSigningForFlow } : {}),
          ...(passkeyEcdsaReconnect ? { passkeyReconnect: passkeyEcdsaReconnect } : {}),
          thresholdReconnect: {
            ensureThresholdEcdsaKeyRefReady: async ({ authorization, usesNeeded }) => {
              const lane = args.getResolvedEcdsaSigningLane();
              const keyRef =
                args.getThresholdEcdsaKeyRef() ||
                readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane });
              const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
              const reconnectPlan = buildEvmFamilyWarmSessionReconnectPlan({
                authorization,
                lane,
                keyRef,
                record: record || null,
                sessionBudgetUses: resolveTransactionStepUpSessionUses(usesNeeded),
              });
              const readyKeyRef = await runRuntimeCommand(
                SigningOperationCommandKind.ConnectThreshold,
                async () =>
                  await ensureEvmFamilyThresholdEcdsaKeyRefReady({
                    mode: 'planned_reconnect',
                    deps: args.deps,
                    lane,
                    chainId: requestChainId,
                    keyRef,
                    reconnectSessionIdentity: buildEcdsaSessionIdentity({
                      thresholdSessionId: lane.thresholdSessionId,
                      walletSigningSessionId: lane.walletSigningSessionId,
                    }),
                    reconnectPlan,
                    operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
                    sessionBudgetUses: resolveTransactionStepUpSessionUses(usesNeeded),
                    shouldAbort: args.shouldAbort,
                    onEvent: args.onEvent,
                  }),
              );
              const operation = await args.setThresholdEcdsaKeyRef({
                keyRef: readyKeyRef,
                signingSessionIdentity: {
                  thresholdSessionId: String(lane.thresholdSessionId),
                  walletSigningSessionId: String(lane.walletSigningSessionId),
                },
              });
              return { keyRef: readyKeyRef, operation };
            },
          },
          onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted,
        }
      : undefined;
  const flowArgs = {
    ctx,
    touchConfirm: args.deps.touchConfirm,
    workerCtx: signerWorkerCtx,
    walletId,
    onEvent: args.onEvent,
    engines: {
      secp256k1: new Secp256k1Engine({
        getRpId: () => ctx.touchIdPrompt.getRpId(),
        workerCtx: signerWorkerCtx,
        shouldAbort: args.shouldAbort,
        thresholdEcdsaPresignPoolPolicy:
          args.deps.seamsPasskeyConfigs.signing.thresholdEcdsa.presignPool,
        onThresholdEcdsaPresignRefillScheduled: ({
          trigger,
          result,
        }: ThresholdEcdsaPresignRefillEvent) => {
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_08_PRESIGN_REFILL_SCHEDULED,
              status: 'running',
              accountId: walletId,
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
            chainTarget: requestChainTarget,
            thresholdSessionId,
          });
          try {
            emitEvmFamilySigningEvent(args.onEvent, {
              phase: SigningEventPhase.STEP_10_COMMIT_QUEUED,
              status: 'running',
              accountId: walletId,
              interaction: { kind: 'none', overlay: 'none' },
              data: { queueKey, chain: args.request.chain },
            });
          } catch {}
          return await args.deps.withThresholdEcdsaCommitQueue({
            queueKey,
            walletId: queueArgs.walletId,
            enabled: true,
            shouldAbort: queueArgs.shouldAbort,
            task: async () => {
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              await assertThresholdSigningSessionReady({
                signingSessionCoordinator: warmSessionServices,
                walletId: String(queueArgs.walletId),
                chainTarget: requestChainTarget,
                sessionId: thresholdSessionId,
                usesNeeded: 1,
              });
              try {
                emitEvmFamilySigningEvent(args.onEvent, {
                  phase: SigningEventPhase.STEP_10_COMMIT_STARTED,
                  status: 'running',
                  accountId: walletId,
                  interaction: { kind: 'none', overlay: 'none' },
                  data: { queueKey, chain: args.request.chain },
                });
              } catch {}
              await ensureSmartAccountDeploymentReady({
                deps: args.deps,
                walletId,
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
      ? { thresholdEcdsaKeyRef: args.getThresholdEcdsaKeyRef() }
      : {}),
    ...(args.signingSessionPlan ? { signingSessionPlan: args.signingSessionPlan } : {}),
    ...(args.signingOperation ? { signingOperation: args.signingOperation } : {}),
    onSigningOperationTransition:
      args.onSigningOperationTransition || emitEvmFamilySigningOperationTrace,
    ...(thresholdEcdsaStepUpRuntime ? { thresholdEcdsaStepUpRuntime } : {}),
    confirmationConfigOverride: args.confirmationConfigOverride,
  };

  return { flowArgs, warmSessionServices };
}
