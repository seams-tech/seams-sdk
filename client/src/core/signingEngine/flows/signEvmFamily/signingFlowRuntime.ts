import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { secureRandomId } from '@shared/utils/secureRandomId';
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
import { ensureEvmFamilyThresholdEcdsaRecordReady } from './ecdsaReadiness';
import {
  findSharedEvmFamilyEcdsaSessionRecordForLane,
  readSelectedEcdsaRecordForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { type ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import { buildEcdsaSessionPolicy } from '../../threshold/sessionPolicy';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import type { EvmFamilyThresholdEcdsaReauthResult } from './thresholdAdmission';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import { buildReadySecp256k1SigningMaterialFromRecord } from './signers/secp256k1';
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
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
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

type EvmFamilyThresholdEcdsaRecordUpdate = {
  record: ThresholdEcdsaSessionRecord;
};

type EvmFamilyThresholdEcdsaRecordUpdateResult = EvmFamilyThresholdEcdsaReauthResult;

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

function generateEvmFamilyEcdsaBootstrapRequestId(): string {
  return secureRandomId('tecdsa-keygen', 32, 'EVM family ECDSA bootstrap request IDs');
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
  onAuthSideEffectStarted?: (sideEffect: EvmFamilySigningAuthSideEffect) => void;
  signingOperation?: SigningOperationContext;
  onSigningOperationTransition?: SigningOperationTransitionObserver;
  getThresholdEcdsaRecord: () => ThresholdEcdsaSessionRecord | undefined;
  setThresholdEcdsaRecord: (
    update: EvmFamilyThresholdEcdsaRecordUpdate,
  ) =>
    | Promise<EvmFamilyThresholdEcdsaRecordUpdateResult>
    | EvmFamilyThresholdEcdsaRecordUpdateResult;
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
        if (!record) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact session record material',
          );
        }
        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        if (!rpId) {
          throw new Error('[SigningEngine] missing rpId for passkey ECDSA reconnect');
        }
        const signingKeyContext = buildEcdsaSigningKeyContextFromRecord(record);
        const materialRelayerKeyId = String(record.relayerKeyId || '').trim();
        if (!materialRelayerKeyId) {
          throw new Error('[SigningEngine] missing relayerKeyId for passkey ECDSA reconnect');
        }
        const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
          walletId,
          rpId,
        });
        if (materialRelayerKeyId !== relayerKeyId) {
          throw new Error('[SigningEngine] passkey ECDSA reconnect relayer key mismatch');
        }
        const requestId = generateEvmFamilyEcdsaBootstrapRequestId();
        const remainingUses = postExhaustionStepUpSessionBudgetUses;
        const ecdsaThresholdKeyId = String(signingKeyContext.ecdsaThresholdKeyId).trim();
        if (!ecdsaThresholdKeyId) {
          throw new Error(
            '[SigningEngine] passkey ECDSA reconnect requires threshold key identity',
          );
        }
        const participantIds = signingKeyContext.participantIds.map((participantId) =>
          Number(participantId),
        );
        const { policy } = await buildEcdsaSessionPolicy({
          walletId,
          rpId,
          relayerKeyId,
          chainTarget: lane.chainTarget,
          ecdsaThresholdKeyId,
          ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
          ...(participantIds?.length ? { participantIds } : {}),
          remainingUses,
        });
        const passkeyBootstrapDigest32B64u =
          await computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
            walletId: policy.walletId,
            rpId: policy.rpId,
            ecdsaThresholdKeyId: policy.ecdsaThresholdKeyId,
            signingRootId: signingKeyContext.signingRootId,
            signingRootVersion: signingKeyContext.signingRootVersion || 'default',
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
        if (!record) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact session record material',
          );
        }
        const reconnectPlan = await buildEvmFamilyPasskeyEcdsaProvisionPlan({
          authorization,
          material: { lane, record },
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
        const readyRecord = await runRuntimeCommand(
          SigningOperationCommandKind.ConnectThreshold,
          async () =>
            await ensureEvmFamilyThresholdEcdsaRecordReady({
              deps: args.deps,
              lane,
              chainId: requestChainId,
              record,
              reconnectSessionIdentity,
              reconnectPlan,
              operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
              sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            }),
        );
        const updated = await args.setThresholdEcdsaRecord({
          record: readyRecord,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_admitted',
          accountId: walletId,
          chain: args.request.chain,
          chainId: requestChainId,
          record: {
            walletSigningSessionId: readyRecord.walletSigningSessionId,
            thresholdSessionId: readyRecord.thresholdSessionId,
            hasThresholdSessionAuthToken: Boolean(readyRecord.thresholdSessionAuthToken),
          },
          budgetKind: updated.operation.budgetAdmission ? 'admitted' : 'missing',
        });
        return updated;
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
              const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane });
              if (!record) {
                throw new Error(
                  '[SigningEngine][ecdsa] warm-session reconnect requires exact session record material',
                );
              }
              const reconnectPlan = buildEvmFamilyWarmSessionReconnectPlan({
                authorization,
                material: { lane, record },
                sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
              });
              const readyRecord = await runRuntimeCommand(
                SigningOperationCommandKind.ConnectThreshold,
                async () =>
                  await ensureEvmFamilyThresholdEcdsaRecordReady({
                    deps: args.deps,
                    lane,
                    chainId: requestChainId,
                    record,
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
              const updated = await args.setThresholdEcdsaRecord({
                record: readyRecord,
              });
              return updated;
            },
          },
          onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted,
        }
      : undefined;
  const fallbackThresholdEcdsaRecord = args.getThresholdEcdsaRecord();
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
    ...(fallbackThresholdEcdsaRecord
      ? {
          buildFallbackReadySecp256k1SigningMaterial: async ({
            requestLabel,
          }: {
            requestLabel: unknown;
          }) =>
            await buildReadySecp256k1SigningMaterialFromRecord({
              record: fallbackThresholdEcdsaRecord,
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
