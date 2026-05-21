import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { assertThresholdSigningSessionReady } from '../../session/warmCapabilities/thresholdSigningSessionReadiness';
import { SigningSessionIds } from '../../session/operationState/types';
import type {
  SigningOperationContext,
  SigningOperationId,
  SigningSessionPlan,
} from '../../session/operationState/types';
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
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { loadSecp256k1EngineCtor, loadWebAuthnP256EngineCtor } from './signerLoader';
import { createEvmFamilyWarmSessionServices } from './warmSessionServices';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from './ecdsaReadiness';
import {
  findSharedEvmFamilyEcdsaKeyRefForLane,
  findSharedEvmFamilyEcdsaSessionRecordForLane,
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { thresholdEcdsaRecordRpId } from '../../session/persistence/records';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import { buildEcdsaSessionPolicy } from '../../threshold/sessionPolicy';
import { buildEcdsaSessionIdentity } from '../../session/warmCapabilities/ecdsaProvisionPlan';
import {
  buildEvmFamilyThresholdEcdsaReauthResult,
  type EvmFamilyThresholdEcdsaReauthResult,
} from './thresholdAdmission';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import { buildReadySecp256k1SigningMaterialFromKeyRef } from './signers/secp256k1';
import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  configuredThresholdEcdsaChainTargets,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildEvmFamilyPasskeyEcdsaProvisionPlan,
  buildEvmFamilyWarmSessionReconnectPlan,
} from './provisionPlan';
import {
  deriveBaseEcdsaSubjectIdFromKey,
  resolveReadyEvmFamilyEcdsaMaterial,
  type ReadyEvmFamilyEcdsaMaterial,
} from '../../session/identity/evmFamilyEcdsaIdentity';
import {
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
  type SigningBudgetAllowance,
} from '../../session/budget/policy';
import {
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

function resolveEvmFamilyStepUpOperationId(
  operation: SigningOperationContext | undefined,
): SigningOperationId {
  return normalizeStepUpOperationId(
    operation?.operationId ||
      SigningSessionIds.signingOperation('evm-family-post-exhaustion-step-up'),
  );
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
  walletId: WalletId;
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

type EvmFamilyThresholdEcdsaKeyRefUpdateResult = Pick<
  EvmFamilyThresholdEcdsaReauthResult,
  'operation' | 'readyMaterial'
>;

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

function requireReadyEvmFamilyEcdsaMaterial(args: {
  lane: ResolvedEvmFamilyEcdsaSigningLane;
  record: ReadyEvmFamilyEcdsaMaterial['record'];
  keyRef: ReadyEvmFamilyEcdsaMaterial['keyRef'];
  context: string;
}): ReadyEvmFamilyEcdsaMaterial {
  const resolution = resolveReadyEvmFamilyEcdsaMaterial({
    record: args.record,
    keyRef: args.keyRef,
    rpId: thresholdEcdsaRecordRpId(args.record),
    expected: {
      walletId: args.record.walletId,
      chainTarget: args.lane.chainTarget,
      authMethod: args.lane.authMethod,
      source: args.record.source,
      thresholdSessionId: args.lane.thresholdSessionId,
      walletSigningSessionId: args.lane.walletSigningSessionId,
    },
  });
  if (resolution.kind !== 'ready') {
    throw new Error(
      `[SigningEngine][ecdsa] ${args.context} requires ready ECDSA material: ${resolution.kind}`,
    );
  }
  return resolution.material;
}

function generateEvmFamilyEcdsaBootstrapRequestId(): string {
  const id =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `tecdsa-keygen-${id}`;
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  walletSession: WalletSessionRef;
  request: TempoSigningRequest | EvmSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyThresholdEcdsaStepUpRuntime['emailOtpSigning'];
  warmBudgetRefreshAllowance?: SigningBudgetAllowance;
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  getThresholdEcdsaKeyRef: () => ThresholdEcdsaSecp256k1KeyRef | undefined;
  setThresholdEcdsaKeyRef: (
    update: EvmFamilyThresholdEcdsaKeyRefUpdate,
  ) =>
    | Promise<EvmFamilyThresholdEcdsaKeyRefUpdateResult>
    | EvmFamilyThresholdEcdsaKeyRefUpdateResult;
  getResolvedEcdsaSigningLane: () => ResolvedEvmFamilyEcdsaSigningLane;
}) {
  const [Secp256k1Engine, WebAuthnP256Engine] = await Promise.all([
    loadSecp256k1EngineCtor(),
    loadWebAuthnP256EngineCtor(),
  ]);
  const signerWorkerCtx = args.deps.getSignerWorkerContext();
  const ctx = args.deps.touchConfirm.getContext();
  const warmSessionServices = createEvmFamilyWarmSessionServices(args.deps);
  const walletId = toWalletId(args.walletSession.walletId);
  const requestChainId = args.chainTarget.chainId;
  const requestChainTarget = args.chainTarget;
  const configuredEcdsaChainTargets = configuredThresholdEcdsaChainTargets(
    args.deps.seamsPasskeyConfigs.network.chains,
  );
  const postExhaustionStepUpBudgetPolicy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: resolveEvmFamilyStepUpOperationId(args.signingOperation),
    ...(args.warmBudgetRefreshAllowance
      ? { warmBudgetRefreshAllowance: args.warmBudgetRefreshAllowance }
      : {}),
  });
  const postExhaustionStepUpSessionBudgetUses = resolveSigningBudgetPolicyRemainingUses(
    postExhaustionStepUpBudgetPolicy,
  );
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
        void usesNeeded;
        const lane = args.getResolvedEcdsaSigningLane();
        const exactRecord = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
        const record =
          exactRecord ||
          findSharedEvmFamilyEcdsaSessionRecordForLane({
            deps: args.deps,
            lane,
            chainTargets: configuredEcdsaChainTargets,
          });
        const keyRef =
          args.getThresholdEcdsaKeyRef() ||
          readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane }) ||
          findSharedEvmFamilyEcdsaKeyRefForLane({
            deps: args.deps,
            lane,
            chainTargets: configuredEcdsaChainTargets,
            ...(record ? { record } : {}),
          });
        if (!record || !keyRef) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact record and keyRef material',
          );
        }
        const material = requireReadyEvmFamilyEcdsaMaterial({
          lane,
          record,
          keyRef,
          context: 'passkey reconnect preparation',
        });
        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        if (!rpId) {
          throw new Error('[SigningEngine] missing rpId for passkey ECDSA reconnect');
        }
        const materialRelayerKeyId = String(
          material.record.relayerKeyId || material.keyRef.backendBinding?.relayerKeyId || '',
        ).trim();
        if (!materialRelayerKeyId) {
          throw new Error('[SigningEngine] missing relayerKeyId for passkey ECDSA reconnect');
        }
        const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
          walletSessionUserId: walletId,
          rpId,
        });
        if (materialRelayerKeyId !== relayerKeyId) {
          throw new Error('[SigningEngine] passkey ECDSA reconnect relayer key mismatch');
        }
        const requestId = generateEvmFamilyEcdsaBootstrapRequestId();
        const remainingUses = postExhaustionStepUpSessionBudgetUses;
        const ecdsaThresholdKeyId = String(material.signingKeyContext.ecdsaThresholdKeyId).trim();
        if (!ecdsaThresholdKeyId) {
          throw new Error(
            '[SigningEngine] passkey ECDSA reconnect requires threshold key identity',
          );
        }
        const participantIds = material.signingKeyContext.participantIds.map((participantId) =>
          Number(participantId),
        );
        const { policy } = await buildEcdsaSessionPolicy({
          walletSessionUserId: walletId,
          subjectId: deriveBaseEcdsaSubjectIdFromKey(lane.key),
          rpId,
          relayerKeyId,
          chainTarget: lane.chainTarget,
          ecdsaThresholdKeyId,
          ...(material.record.runtimePolicyScope
            ? { runtimePolicyScope: material.record.runtimePolicyScope }
            : {}),
          ...(participantIds?.length ? { participantIds } : {}),
          remainingUses,
        });
        const passkeyBootstrapDigest32B64u =
          await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
            walletSessionUserId: policy.walletSessionUserId,
            rpId: policy.rpId,
            subjectId: policy.subjectId,
            ecdsaThresholdKeyId: policy.ecdsaThresholdKeyId,
            signingRootId: material.signingKeyContext.signingRootId,
            signingRootVersion: material.signingKeyContext.signingRootVersion || 'default',
            keyScope: 'evm-family',
            relayerKeyId,
            requestId,
            sessionId: policy.sessionId,
            walletSigningSessionId: policy.walletSigningSessionId,
            ttlMs: policy.ttlMs,
            remainingUses: policy.remainingUses,
            participantIds: policy.participantIds || participantIds,
        });
        return {
          webauthnChallenge: {
            kind: 'ecdsa_role_local_bootstrap' as const,
            digest32B64u: passkeyBootstrapDigest32B64u,
            requestId,
            thresholdSessionId: policy.sessionId,
            walletSigningSessionId: policy.walletSigningSessionId,
          },
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
        const exactRecord = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
        const record =
          exactRecord ||
          findSharedEvmFamilyEcdsaSessionRecordForLane({
            deps: args.deps,
            lane,
            chainTargets: configuredEcdsaChainTargets,
          });
        const keyRef =
          args.getThresholdEcdsaKeyRef() ||
          readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane }) ||
          findSharedEvmFamilyEcdsaKeyRefForLane({
            deps: args.deps,
            lane,
            chainTargets: configuredEcdsaChainTargets,
            ...(record ? { record } : {}),
          });
        if (!record || !keyRef) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact record and keyRef material',
          );
        }
        const material = requireReadyEvmFamilyEcdsaMaterial({
          lane,
          record,
          keyRef,
          context: 'passkey reconnect',
        });
        const reconnectPlan = buildEvmFamilyPasskeyEcdsaProvisionPlan({
          authorization,
          material,
          sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
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
              deps: args.deps,
              lane,
              chainId: requestChainId,
              keyRef: material.keyRef,
              reconnectSessionIdentity,
              reconnectPlan,
              operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
              sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            }),
        );
        const updated = await args.setThresholdEcdsaKeyRef({
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
          budgetKind: updated.operation.budgetAdmission ? 'admitted' : 'missing',
        });
        return await buildEvmFamilyThresholdEcdsaReauthResult({
          readyMaterial: updated.readyMaterial,
          operation: updated.operation,
        });
      },
    };
  };
  const emitConfirmedAuthSideEffectStarted = (sideEffect: EvmFamilySigningAuthSideEffect): void => {
    let lane: ResolvedEvmFamilyEcdsaSigningLane | undefined;
    try {
      args.onAuthSideEffectStarted?.(sideEffect);
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
            ensureThresholdEcdsaReadyMaterial: async ({ authorization, usesNeeded }) => {
              const lane = args.getResolvedEcdsaSigningLane();
              const keyRef =
                args.getThresholdEcdsaKeyRef() ||
                readSelectedEcdsaKeyRefForLane({ deps: args.deps, lane });
              const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
              if (!keyRef || !record) {
                throw new Error(
                  '[SigningEngine][ecdsa] warm-session reconnect requires exact record and keyRef material',
                );
              }
              const material = requireReadyEvmFamilyEcdsaMaterial({
                lane,
                record,
                keyRef,
                context: 'warm-session reconnect',
              });
              const reconnectPlan = buildEvmFamilyWarmSessionReconnectPlan({
                authorization,
                material,
                sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
              });
              const readyKeyRef = await runRuntimeCommand(
                SigningOperationCommandKind.ConnectThreshold,
                async () =>
                  await ensureEvmFamilyThresholdEcdsaKeyRefReady({
                    deps: args.deps,
                    lane,
                    chainId: requestChainId,
                    keyRef: material.keyRef,
                    reconnectSessionIdentity: buildEcdsaSessionIdentity({
                      thresholdSessionId: lane.thresholdSessionId,
                      walletSigningSessionId: lane.walletSigningSessionId,
                    }),
                    reconnectPlan,
                    operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
                    sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
                    shouldAbort: args.shouldAbort,
                    onEvent: args.onEvent,
                  }),
              );
              const updated = await args.setThresholdEcdsaKeyRef({
                keyRef: readyKeyRef,
                signingSessionIdentity: {
                  thresholdSessionId: String(lane.thresholdSessionId),
                  walletSigningSessionId: String(lane.walletSigningSessionId),
                },
              });
              return await buildEvmFamilyThresholdEcdsaReauthResult({
                readyMaterial: updated.readyMaterial,
                operation: updated.operation,
              });
            },
          },
          onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted,
        }
      : undefined;
  const fallbackThresholdEcdsaKeyRef = args.getThresholdEcdsaKeyRef();
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
                walletId: toWalletId(queueArgs.walletId),
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
              throwIfEvmFamilySigningCancelled(queueArgs.shouldAbort);
              return await queueArgs.task();
            },
          });
        },
      }),
      webauthnP256: new WebAuthnP256Engine(signerWorkerCtx),
    },
    ...(fallbackThresholdEcdsaKeyRef
      ? {
          buildFallbackReadySecp256k1SigningMaterial: async ({
            requestLabel,
          }: {
            requestLabel: unknown;
          }) =>
            await buildReadySecp256k1SigningMaterialFromKeyRef({
              keyRef: fallbackThresholdEcdsaKeyRef,
              requestLabel,
              rpId: ctx.touchIdPrompt.getRpId?.(),
            }),
        }
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
