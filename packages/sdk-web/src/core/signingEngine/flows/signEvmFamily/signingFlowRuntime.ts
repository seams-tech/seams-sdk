import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import { secureRandomId } from '@shared/utils/secureRandomId';
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
import { emitEvmFamilySigningEvent, emitEvmFamilySigningOperationTrace } from './events';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { EvmFamilyLifecycleEventCallback, EvmFamilySenderSignatureAlgorithm } from './types';
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
  normalizeStepUpOperationId,
  resolvePostExhaustionStepUpBudgetPolicy,
  resolveSigningBudgetPolicyRemainingUses,
} from '../../session/budget/policy';
import {
  computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u,
  computeEcdsaDerivationRoleLocalRelayerKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';

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

function runtimePolicyScopeForPasskeyEcdsaReconnect(args: {
  material: PasskeyEcdsaReconnectMaterial;
  signingRootBinding: ReturnType<typeof resolveThresholdSigningRootBindingFromRecord>;
}): ThresholdRuntimePolicyScope {
  const runtimePolicyScope = args.material.record.runtimePolicyScope;
  if (!runtimePolicyScope) {
    throw new Error('[SigningEngine] passkey ECDSA reconnect requires runtimePolicyScope');
  }
  const signingRootId = String(args.signingRootBinding.signingRootId || '').trim();
  const separator = signingRootId.lastIndexOf(':');
  if (separator <= 0 || separator >= signingRootId.length - 1) {
    throw new Error('[SigningEngine] passkey ECDSA reconnect requires project:env signingRootId');
  }
  return {
    ...runtimePolicyScope,
    projectId: signingRootId.slice(0, separator),
    envId: signingRootId.slice(separator + 1),
    signingRootVersion: String(args.signingRootBinding.signingRootVersion || 'default'),
  };
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

async function resolveEcdsaSigningMaterialHydrationPlan(args: {
  record: ThresholdEcdsaSessionRecord | undefined;
  requestLabel: unknown;
  evmFamilySigningKeySlotId: unknown;
}): Promise<EcdsaSigningMaterialPlan> {
  if (!args.record) return { kind: 'unavailable', reason: 'missing_record' };
  try {
    const material = await buildReadySecp256k1SigningMaterialFromRecord({
      record: args.record,
      requestLabel: args.requestLabel,
      evmFamilySigningKeySlotId: args.evmFamilySigningKeySlotId,
      hydrationEntryPoint: 'post_page_refresh',
    });
    return { kind: 'material_from_runtime_validated_record', material };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes('evmFamilySigningKeySlotId mismatch')) {
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
        const evmFamilySigningKeySlotId = String(signer.key.evmFamilySigningKeySlotId || '').trim();
        if (!evmFamilySigningKeySlotId) {
          throw new Error('[SigningEngine] missing evmFamilySigningKeySlotId for passkey ECDSA reconnect');
        }
        const signingKeyContext = signingKeyContextFromPasskeyEcdsaReconnectMaterial(material);
        const materialRelayerKeyId = relayerKeyIdFromPasskeyEcdsaReconnectMaterial(material);
        if (!materialRelayerKeyId) {
          throw new Error('[SigningEngine] missing relayerKeyId for passkey ECDSA reconnect');
        }
        const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
          walletId,
          evmFamilySigningKeySlotId,
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
        const signingRootBinding = resolveThresholdSigningRootBindingFromRecord({
          record: material.record,
        });
        const runtimePolicyScope = runtimePolicyScopeForPasskeyEcdsaReconnect({
          material,
          signingRootBinding,
        });
        const { policy } = await buildEcdsaSessionPolicy({
          walletId,
          evmFamilySigningKeySlotId,
          relayerKeyId,
          chainTarget: signer.chainTarget,
          ecdsaThresholdKeyId,
          runtimePolicyScope,
          ...(participantIds?.length ? { participantIds } : {}),
          remainingUses,
        });
        const passkeyBootstrapDigest32B64u =
          await computeEcdsaDerivationRoleLocalPasskeyBootstrapAuthDigest32B64u({
            walletId: policy.walletId,
            evmFamilySigningKeySlotId: policy.evmFamilySigningKeySlotId,
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
          walletId,
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
          walletId,
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
            await resolveEcdsaSigningMaterialHydrationPlan({
              record: runtimeValidatedThresholdEcdsaRecord,
              requestLabel,
              evmFamilySigningKeySlotId: args.getResolvedEcdsaSigningLane().key.evmFamilySigningKeySlotId,
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
