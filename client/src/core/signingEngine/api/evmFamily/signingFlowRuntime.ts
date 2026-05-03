import { SigningEventPhase } from '@/core/types/sdkSentEvents';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import { assertThresholdSigningSessionReady } from '../../orchestration/shared/thresholdSigningSessionReadiness';
import {
  SigningSessionPlanKind,
  type SigningSessionPlan,
} from '../../session/signingSession/types';
import {
  SigningExecutionCommandKind,
  createSigningExecutionCommandTraceEvent,
  type SigningExecutionCommand,
} from '../../session/signingSession/execution';
import {
  createSigningBoundaryTraceEvent,
  emitSigningBoundaryTrace,
  emitSigningSessionFlowTrace,
} from '../../session/signingSession/trace';
import type { EvmFamilySigningDeps } from '../evmSigning';
import { resolveThresholdEcdsaCommitQueueKey } from '../thresholdLifecycle/thresholdEcdsaCommitQueue';
import { emitEvmFamilySigningEvent, emitEvmFamilySigningExecutionTrace } from './events';
import { throwIfEvmFamilySigningCancelled } from './errors';
import type { EvmFamilyLifecycleEventCallback, EvmFamilySenderSignatureAlgorithm } from './types';
import { loadSecp256k1EngineCtor, loadWebAuthnP256EngineCtor } from './signerLoader';
import { createEvmFamilyWarmSessionServices } from './warmSessionServices';
import { ensureSmartAccountDeploymentReady } from './smartAccount';
import { ensureEvmFamilyThresholdEcdsaKeyRefReady } from './ecdsaReadiness';
import {
  readSelectedEcdsaKeyRefForLane,
  readSelectedEcdsaRecordForLane,
  type ResolvedEvmFamilyEcdsaSigningLane,
} from './ecdsaLanes';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { getPrfFirstB64uFromCredential } from '../../signers/webauthn/credentials/credentialExtensions';
import { buildEcdsaSessionPolicy } from '../../threshold/session/sessionPolicy';
import type {
  EvmFamilyThresholdEcdsaOperation,
  EvmFamilyThresholdEcdsaReauthResult,
} from '../../orchestration/shared/thresholdEcdsaTransactionAdmission';

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
  nearAccountId: string;
  thresholdSessionId: string;
  shouldAbort?: () => boolean;
  task: () => Promise<unknown>;
};

type EvmFamilyAuthSideEffect = 'passkey_reauth' | 'threshold_reconnect';

type EvmFamilyRuntimeCommandKind = Extract<
  SigningExecutionCommand['kind'],
  | typeof SigningExecutionCommandKind.RequestOtp
  | typeof SigningExecutionCommandKind.ReconnectThreshold
>;

type EvmFamilyEmailOtpSigningForFlow = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (otpCode: string, challengeId?: string) => Promise<EvmFamilyThresholdEcdsaReauthResult>;
};

function executionCommandTraceForPlan(args: {
  signingSessionPlan?: SigningSessionPlan;
  commandKind: EvmFamilyRuntimeCommandKind;
}) {
  const plan = args.signingSessionPlan;
  if (!plan || plan.kind === SigningSessionPlanKind.NotReady) return null;
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
        commandKind: SigningExecutionCommandKind.RequestOtp,
        execute: emailOtpSigning.prepare,
      }),
    ...(emailOtpSigning.resend
      ? {
          resend: async () =>
            await executeEvmFamilyRuntimeCommand({
              signingSessionPlan: args.signingSessionPlan,
              commandKind: SigningExecutionCommandKind.RequestOtp,
              execute: emailOtpSigning.resend!,
            }),
        }
      : {}),
  };
}

function requirePlannedReconnectSessionIdentity(args: {
  sessionId?: string;
  walletSigningSessionId?: string;
}): {
  thresholdSessionId: string;
  walletSigningSessionId: string;
} {
  const thresholdSessionId = String(args.sessionId || '').trim();
  const walletSigningSessionId = String(args.walletSigningSessionId || '').trim();
  if (!thresholdSessionId || !walletSigningSessionId) {
    throw new Error('[SigningEngine][ecdsa] passkey reconnect requires planned fresh session ids');
  }
  return { thresholdSessionId, walletSigningSessionId };
}

export async function createEvmFamilySigningFlowRuntime(args: {
  deps: EvmFamilySigningDeps;
  nearAccountId: string;
  request: TempoSigningRequest | EvmSigningRequest;
  senderSignatureAlgorithm: EvmFamilySenderSignatureAlgorithm;
  signingSessionPlan?: SigningSessionPlan;
  emailOtpSigningForFlow?: EvmFamilyEmailOtpSigningForFlow;
  confirmationConfigOverride?: unknown;
  shouldAbort?: () => boolean;
  onEvent?: EvmFamilyLifecycleEventCallback;
  getThresholdEcdsaKeyRef: () => ThresholdEcdsaSecp256k1KeyRef | undefined;
  setThresholdEcdsaKeyRef: (
    keyRef: ThresholdEcdsaSecp256k1KeyRef,
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
  const requestChainId = args.request.tx.chainId;
  const emailOtpSigningForFlow = wrapEmailOtpSigningWithRuntimeCommands({
    signingSessionPlan: args.signingSessionPlan,
    emailOtpSigning: args.emailOtpSigningForFlow,
  });
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
        // Exhausted ECDSA passkey sessions must use this planned policy digest as the
        // confirmation challenge. Otherwise confirmation collects one WebAuthn assertion,
        // then generic reconnect collects a second assertion and falls back to default uses.
        const remainingUses = resolveTransactionStepUpSessionUses(usesNeeded);
        const sessionId = String(lane.thresholdSessionId || '').trim();
        const walletSigningSessionId = String(lane.walletSigningSessionId || '').trim();
        if (!sessionId || !walletSigningSessionId) {
          throw new Error('[SigningEngine] passkey ECDSA reconnect requires selected lane identity');
        }
        const { policy, sessionPolicyDigest32 } = await buildEcdsaSessionPolicy({
          userId: args.nearAccountId,
          rpId,
          relayerKeyId,
          sessionId,
          walletSigningSessionId,
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
        credential,
        usesNeeded,
        sessionId,
        walletSigningSessionId,
      }: {
        credential: WebAuthnAuthenticationCredential;
        usesNeeded: number;
        sessionId?: string;
        walletSigningSessionId?: string;
      }) => {
        const clientRootShare32B64u = getPrfFirstB64uFromCredential(credential);
        if (!clientRootShare32B64u) {
          throw new Error('[SigningEngine] missing PRF.first for passkey ECDSA reconnect');
        }
        const lane = args.getResolvedEcdsaSigningLane();
        const reconnectSessionIdentity = requirePlannedReconnectSessionIdentity({
          sessionId,
          walletSigningSessionId,
        });
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_start',
          accountId: args.nearAccountId,
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
        const readyKeyRef = await executeEvmFamilyRuntimeCommand({
          signingSessionPlan: args.signingSessionPlan,
          commandKind: SigningExecutionCommandKind.ReconnectThreshold,
          execute: async () =>
            await ensureEvmFamilyThresholdEcdsaKeyRefReady({
              deps: args.deps,
              lane,
              chainId: requestChainId,
              keyRef: args.getThresholdEcdsaKeyRef(),
              reconnectSessionIdentity,
              clientRootShare32B64u,
              webauthnAuthentication: credential,
              operationUsesNeeded: Math.max(1, Math.floor(Number(usesNeeded) || 1)),
              sessionBudgetUses: resolveTransactionStepUpSessionUses(usesNeeded),
              shouldAbort: args.shouldAbort,
              onEvent: args.onEvent,
            }),
        });
        const operation = await args.setThresholdEcdsaKeyRef(readyKeyRef);
        emitSigningSessionFlowTrace('evm-family', {
          stage: 'ecdsa_runtime.passkey_reconnect_admitted',
          accountId: args.nearAccountId,
          chain: args.request.chain,
          chainId: requestChainId,
          keyRef: {
            walletSigningSessionId: readyKeyRef.walletSigningSessionId,
            thresholdSessionId: readyKeyRef.thresholdSessionId,
            hasThresholdSessionJwt: Boolean(readyKeyRef.thresholdSessionJwt),
          },
          budgetKind: operation.budgetAdmission ? 'admitted' : 'missing',
        });
        return { keyRef: readyKeyRef, operation };
      },
    };
  };
  const emitConfirmedAuthSideEffectStarted = (sideEffect: EvmFamilyAuthSideEffect): void => {
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
          args.deps.seamsPasskeyConfigs.signing.thresholdEcdsa.presignPool,
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
                signingSessionCoordinator: warmSessionServices,
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
    confirmationConfigOverride: args.confirmationConfigOverride,
    ...(args.senderSignatureAlgorithm === 'secp256k1'
      ? {
          onAuthSideEffectStarted: emitConfirmedAuthSideEffectStarted,
          ...(passkeyEcdsaReconnect ? { passkeyEcdsaReconnect } : {}),
          ensureThresholdEcdsaKeyRefReady: async () => {
            const lane = args.getResolvedEcdsaSigningLane();
            const readyKeyRef = await executeEvmFamilyRuntimeCommand({
              signingSessionPlan: args.signingSessionPlan,
              commandKind: SigningExecutionCommandKind.ReconnectThreshold,
              execute: async () =>
                await ensureEvmFamilyThresholdEcdsaKeyRefReady({
                  deps: args.deps,
                  lane,
                  chainId: requestChainId,
                  keyRef: args.getThresholdEcdsaKeyRef(),
                  reconnectSessionIdentity: {
                    thresholdSessionId: String(lane.thresholdSessionId),
                    walletSigningSessionId: String(lane.walletSigningSessionId),
                  },
                  operationUsesNeeded: 1,
                  sessionBudgetUses: resolveTransactionStepUpSessionUses(1),
                  shouldAbort: args.shouldAbort,
                  onEvent: args.onEvent,
                }),
            });
            const operation = await args.setThresholdEcdsaKeyRef(readyKeyRef);
            return { keyRef: readyKeyRef, operation };
          },
        }
      : {}),
  };

  return { flowArgs, warmSessionServices };
}
