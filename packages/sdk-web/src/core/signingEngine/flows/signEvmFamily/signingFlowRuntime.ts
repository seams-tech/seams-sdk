import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { assertThresholdSigningSessionReady } from '../../session/warmCapabilities/thresholdSigningSessionReadiness';
import { SigningSessionIds } from '../../session/operationState/types';
import { signingLaneAuthMethod } from '../../session/identity/signingLaneAuthBinding';
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
import type { EcdsaSigningMaterialPlan } from './signingFlow';
import { createEvmFamilyWarmSessionServices } from './warmSessionServices';
import { ensureEvmFamilyThresholdEcdsaRecordReady } from './ecdsaReadiness';
import {
  readSelectedEcdsaRecordForLane,
  validateSelectedEcdsaRecordCandidateForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import { requireEvmFamilyEcdsaSigner } from '../../session/identity/exactSigningLaneIdentity';
import { type ThresholdEcdsaSessionRecord } from '../../session/persistence/records';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import {
  buildEcdsaSessionPolicy,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/sessionPolicy';
import {
  buildEcdsaSessionIdentity,
  buildEcdsaSigningKeyContextFromRecord,
  type EcdsaSigningKeyContext,
} from '../../session/warmCapabilities/ecdsaProvisionPlan';
import { resolveThresholdSigningRootBindingFromRecord } from '../../session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyThresholdEcdsaReauthResult } from './thresholdAdmission';
import type { EvmFamilyThresholdEcdsaStepUpRuntime } from './requireEvmFamilyStepUpAuth';
import type { EvmFamilySigningAuthSideEffect } from './freshAuthRetryPolicy';
import { buildReadySecp256k1SigningMaterialFromRecord } from './readySecp256k1Material';
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
  resolveRouterAbEcdsaWalletSessionAuthFromRecord,
} from '../../session/warmCapabilities/routerAbEcdsaWalletSessionAuth';
import {
  classifyRouterAbEcdsaHssPersistedSigningRecord,
  type RouterAbEcdsaHssPersistedSigningRecordState,
} from '../../session/routerAbSigningWalletSession';
import {
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
} from '../../session/budget/policy';
import {
  computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaHssRoleLocalRelayerKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';

type PasskeyEcdsaReconnectMaterial = {
  kind: 'session_record';
  record: ThresholdEcdsaSessionRecord;
};

function signingKeyContextFromPasskeyEcdsaReconnectMaterial(
  material: PasskeyEcdsaReconnectMaterial,
): EcdsaSigningKeyContext {
  return buildEcdsaSigningKeyContextFromRecord(material.record);
}

function relayerKeyIdFromPasskeyEcdsaReconnectMaterial(
  material: PasskeyEcdsaReconnectMaterial,
): string {
  return String(material.record.relayerKeyId || '').trim();
}

function runtimePolicyScopeFromPasskeyEcdsaReconnectMaterial(
  material: PasskeyEcdsaReconnectMaterial,
): ThresholdRuntimePolicyScope | undefined {
  return material.record.runtimePolicyScope;
}

function readPasskeyEcdsaReconnectMaterialForLane(args: {
  deps: EvmFamilySigningDeps;
  lane?: ResolvedEvmFamilyEcdsaSigningLane;
  preparedRecord?: ThresholdEcdsaSessionRecord;
}): PasskeyEcdsaReconnectMaterial | undefined {
  const preparedRecord = validateSelectedEcdsaRecordCandidateForLane({
    lane: args.lane,
    record: args.preparedRecord,
    context: 'passkey ECDSA reconnect',
  });
  if (preparedRecord) return { kind: 'session_record', record: preparedRecord };
  const record = readSelectedEcdsaRecordForLane({ deps: args.deps, lane: args.lane });
  if (record) return { kind: 'session_record', record };
  return undefined;
}

function resolveEvmFamilyStepUpOperationId(
  operation: SigningOperationContext | undefined,
): SigningOperationId {
  return normalizeStepUpOperationId(
    operation?.operationId ||
      SigningSessionIds.signingOperation('evm-family-post-exhaustion-step-up'),
  );
}

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
  signingGrantId: string;
}): {
  thresholdSessionId: string;
  signingGrantId: string;
} {
  return buildEcdsaSessionIdentity({
    thresholdSessionId: args.sessionId,
    signingGrantId: args.signingGrantId,
  });
}

function generateEvmFamilyEcdsaBootstrapRequestId(): string {
  return secureRandomId('tecdsa-keygen', 32, 'EVM family ECDSA bootstrap request IDs');
}

function unavailableEcdsaSigningMaterialPlanForRecordState(
  state: RouterAbEcdsaHssPersistedSigningRecordState,
): EcdsaSigningMaterialPlan {
  switch (state.kind) {
    case 'runtime_validated':
      throw new Error('runtime-validated ECDSA material state is not unavailable');
    case 'invalid':
      return {
        kind: 'unavailable',
        reason: state.reason === 'missing_record' ? 'missing_record' : 'not_runtime_validated',
      };
    case 'restore_available':
    case 'material_hint_unvalidated':
    case 'non_signing':
      return { kind: 'unavailable', reason: 'not_runtime_validated' };
    default: {
      const exhaustive: never = state;
      return exhaustive;
    }
  }
}

// Final ECDSA signing consumes only runtime-validated material. Restore,
// reconnect, and step-up must complete before this plan returns ready material.
async function resolveRuntimeValidatedEcdsaSigningMaterialPlan(args: {
  record: ThresholdEcdsaSessionRecord | undefined;
  requestLabel: unknown;
  walletKeyId: unknown;
}): Promise<EcdsaSigningMaterialPlan> {
  const recordState = classifyRouterAbEcdsaHssPersistedSigningRecord(args.record);
  if (recordState.kind !== 'runtime_validated') {
    return unavailableEcdsaSigningMaterialPlanForRecordState(recordState);
  }
  try {
    const material = await buildReadySecp256k1SigningMaterialFromRecord({
      record: recordState.record,
      requestLabel: args.requestLabel,
      walletKeyId: args.walletKeyId,
    });
    return { kind: 'material_from_runtime_validated_record', material };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('walletKeyId mismatch')) {
      return { kind: 'unavailable', reason: 'rp_id_mismatch' };
    }
    if (message.includes('chain mismatch')) {
      return { kind: 'unavailable', reason: 'chain_mismatch' };
    }
    if (message.includes('fresh Email OTP verification')) {
      return { kind: 'unavailable', reason: 'single_use_email_otp_consumed' };
    }
    throw error;
  }
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
    args.deps.seamsWebConfigs.network.chains,
  );
  const postExhaustionStepUpBudgetPolicy = resolvePostExhaustionStepUpBudgetPolicy({
    operationId: resolveEvmFamilyStepUpOperationId(args.signingOperation),
    requiredSignatureUses: 1,
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
        const material = readPasskeyEcdsaReconnectMaterialForLane({
          deps: args.deps,
          lane,
          preparedRecord: args.getThresholdEcdsaRecord(),
        });
        if (!material) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact session record material',
          );
        }
        const rpId = String(ctx.touchIdPrompt.getRpId() || '').trim();
        if (!rpId) {
          throw new Error('[SigningEngine] missing rpId for passkey ECDSA reconnect');
        }
        const signer = requireEvmFamilyEcdsaSigner(
          lane.identity,
          'passkey ECDSA reconnect runtime',
        );
        const walletKeyId = String(signer.key.walletKeyId || '').trim();
        if (!walletKeyId) {
          throw new Error('[SigningEngine] missing walletKeyId for passkey ECDSA reconnect');
        }
        const signingKeyContext = signingKeyContextFromPasskeyEcdsaReconnectMaterial(material);
        const materialRelayerKeyId = relayerKeyIdFromPasskeyEcdsaReconnectMaterial(material);
        if (!materialRelayerKeyId) {
          throw new Error('[SigningEngine] missing relayerKeyId for passkey ECDSA reconnect');
        }
        const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
          walletId,
          walletKeyId,
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
        const runtimePolicyScope = runtimePolicyScopeFromPasskeyEcdsaReconnectMaterial(material);
        const { policy } = await buildEcdsaSessionPolicy({
          walletId,
          walletKeyId,
          relayerKeyId,
          chainTarget: signer.chainTarget,
          ecdsaThresholdKeyId,
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
          ...(participantIds?.length ? { participantIds } : {}),
          remainingUses,
        });
        const passkeyBootstrapDigest32B64u =
          await (async () => {
            const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
              record: material.record,
            });
            return computeEcdsaHssRoleLocalPasskeyBootstrapAuthDigest32B64u({
              walletId: policy.walletId,
              walletKeyId: policy.walletKeyId,
              rpId,
              ecdsaThresholdKeyId: policy.ecdsaThresholdKeyId,
              signingRootId: String(signingRootBinding.signingRootId),
              signingRootVersion: String(signingRootBinding.signingRootVersion || 'default'),
              keyScope: 'evm-family',
              relayerKeyId,
              requestId,
              sessionId: policy.sessionId,
              signingGrantId: policy.signingGrantId,
              ttlMs: policy.ttlMs,
              remainingUses: policy.remainingUses,
              participantIds: policy.participantIds || participantIds,
            });
          })();
        return {
          webauthnChallenge: {
            kind: 'ecdsa_role_local_bootstrap' as const,
            digest32B64u: passkeyBootstrapDigest32B64u,
            requestId,
            thresholdSessionId: policy.sessionId,
            signingGrantId: policy.signingGrantId,
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
        const material = readPasskeyEcdsaReconnectMaterialForLane({
          deps: args.deps,
          lane,
          preparedRecord: args.getThresholdEcdsaRecord(),
        });
        if (!material) {
          throw new Error(
            '[SigningEngine][ecdsa] passkey ECDSA reconnect requires exact session record material',
          );
        }
        const reconnectPlan = await buildEvmFamilyPasskeyEcdsaProvisionPlan({
          authorization,
          material: { kind: 'session_record', lane, record: material.record },
          sessionBudgetUses: postExhaustionStepUpSessionBudgetUses,
        });
        const selectedRecord = material.record;
        const reconnectSessionIdentity = requirePlannedReconnectSessionIdentity({
          sessionId: reconnectPlan.newSessionIdentity.thresholdSessionId,
          signingGrantId: reconnectPlan.newSessionIdentity.signingGrantId,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_start',
          accountId: walletId,
          chain: args.request.chain,
          chainId: requestChainId,
          lane: {
            authMethod: signingLaneAuthMethod(lane.auth),
            signingGrantId: String(lane.signingGrantId),
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
              record: selectedRecord,
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
        const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(readyRecord);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_admitted',
          accountId: walletId,
          chain: args.request.chain,
          chainId: requestChainId,
          record: {
            signingGrantId: readyRecord.signingGrantId,
            thresholdSessionId: readyRecord.thresholdSessionId,
            hasRouterAbWalletSessionAuth: walletSessionAuth.kind === 'ready',
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
                      signingGrantId: lane.signingGrantId,
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
  const runtimeValidatedThresholdEcdsaRecord = args.getThresholdEcdsaRecord();
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
    ...(runtimeValidatedThresholdEcdsaRecord
      ? {
          resolveEcdsaSigningMaterialPlan: async ({
            requestLabel,
          }: {
            requestLabel: unknown;
          }) =>
            await resolveRuntimeValidatedEcdsaSigningMaterialPlan({
              record: runtimeValidatedThresholdEcdsaRecord,
              requestLabel,
              walletKeyId: args.getResolvedEcdsaSigningLane().key.walletKeyId,
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
