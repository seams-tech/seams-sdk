import {
  WorkerRequestType,
  WorkerResponseType,
  type ConfirmationConfig,
  type WorkerSuccessResponse,
} from '@/core/types/signer-worker';
import { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '@/core/config/defaultConfigs';
import { resolveNearNetwork } from '@/core/config/chains';
import type { ThresholdEd25519KeyMaterial } from '@/core/accountData/near/nearAccountData.types';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import type { NearSigningRuntimeDeps } from '../../interfaces/runtime';
import { computeThresholdEd25519Nep413SigningDigestWasm } from '../../chains/near/nearSignerWasm';
import { resolveNearSigningMaterials } from './shared/signingMaterials';
import {
  resolveActiveAuthorizedRouterAbEd25519WalletSessionState,
  type AuthorizedRouterAbEd25519WalletSessionState,
} from '../../session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildNearSigningSessionAuthPlan,
  resolveNearSigningSessionAuthContext,
  SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR,
} from './shared/signingSessionAuthMode';
import { planSigningSession } from '../../session/planning/planner';
import type { SigningSessionCoordinator } from '../../session/SigningSessionCoordinator';
import {
  SigningOperationIntent,
  SigningSessionPlanKind,
  SigningSessionIds,
  type DeferredEd25519MaterialIdentity,
  type SigningSessionPlan,
  type SigningOperationContext,
} from '../../session/operationState/types';
import { thresholdEd25519Nep413OperationFingerprint } from '@shared/threshold/ed25519OperationFingerprint';
import {
  SigningOperationCommandKind,
  runSigningOperationCommand,
  type SigningOperationCommand,
} from '../shared/signingStateMachine';
import {
  buildSigningConfirmationAuthParams,
  confirmationConfigForSigningAuthPlan,
  runSigningConfirmationCommand,
} from '../shared/signingConfirmation';
import {
  requireNearStepUpAuth,
  signingAuthPlanForNearMaterialRequirement,
} from './requireNearStepUpAuth';
import type {
  NearEd25519StepUpAuthorization,
  NearNep413Payload,
} from '../../interfaces/near';
import {
  buildNearEd25519OperationStepUpProof,
  prepareRouterAbEd25519SignatureOnlyOperationStepUp,
  requireNearEd25519OperationStepUpProof,
  requireIssuedNearEd25519OperationStepUpAuthorization,
  tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning,
} from './shared/ed25519YaoNormalSigning';
import { base64Encode, base64UrlDecode } from '@shared/utils/base64';
import { buildNearEd25519StepUpAuthorization } from './stepUpAuthorization';
import { nearEd25519SignerBindingFromBoundaryFields } from '../../session/identity/exactSigningLaneIdentity';
import {
  nearOperationStepUpMaterialFacts,
  prepareNearOperationStepUpMaterial,
  resolveConfirmedNearEd25519YaoCapability,
  resolveNearOperationStepUpMaterial,
  type NearOperationStepUpMaterial,
} from './shared/ed25519YaoCapabilityResolution';
import {
  clearNearOperationStepUpBuilder,
  consumePreparedNearOperationStepUp,
  registerNearOperationStepUpBuilder,
  type PreparedNearOperationStepUp,
} from './shared/operationStepUpPreparation';
import type { NearOperationStepUpPreparationRef } from '../../interfaces/operationStepUpPreparation';

/**
 * Sign a NEP-413 message using the active threshold-controlled NEAR key.
 *
 * @param payload - NEP-413 signing parameters including message, recipient, nonce, and state
 * @returns Promise resolving to signing result with account ID, public key, and signature
 */
type InternalSignNep413MessageResult =
  | {
      success: true;
      accountId: string;
      publicKey: string;
      signature: string;
      state?: string;
      error?: never;
    }
  | {
      success: false;
      error: string;
      accountId?: never;
      publicKey?: never;
      signature?: never;
      state?: never;
    };

function requireNearNep413OperationStepUpPreparation(
  value: NearOperationStepUpPreparationRef | undefined,
): NearOperationStepUpPreparationRef {
  if (!value) {
    throw new Error('[SigningEngine][near] NEP-413 operation step-up preparation is missing');
  }
  return value;
}

function requirePreparedNearNep413OperationStepUp(
  value: PreparedNearOperationStepUp | null,
): Extract<PreparedNearOperationStepUp, { kind: 'near_signature_only' }> {
  if (!value || value.kind !== 'near_signature_only') {
    throw new Error('[SigningEngine][near] NEP-413 operation step-up preparation kind changed');
  }
  return value;
}

function requireNearNep413OperationStepUpMaterial(
  value: NearOperationStepUpMaterial | null,
): NearOperationStepUpMaterial {
  if (!value) {
    throw new Error('[SigningEngine][near] NEP-413 operation step-up material is missing');
  }
  return value;
}

function requireNearNep413SigningDigest(value: string | null): string {
  if (!value) {
    throw new Error('[SigningEngine][near] NEP-413 operation signing digest is missing');
  }
  return value;
}

function requireAuthorizedNearNep413WalletSessionState(
  value: AuthorizedRouterAbEd25519WalletSessionState | null,
): AuthorizedRouterAbEd25519WalletSessionState {
  if (!value) {
    throw new Error('[SigningEngine][near] reusable Wallet Session authorization is unavailable');
  }
  return value;
}

async function resolveNearNep413OperationStepUpCapability(args: {
  material: NearOperationStepUpMaterial;
  prepared: Extract<PreparedNearOperationStepUp, { kind: 'near_signature_only' }>;
  displayDigest: string;
  authorization: Exclude<NearEd25519StepUpAuthorization, { kind: 'warm_session' }>;
  emailOtpProof:
    | Extract<ReturnType<typeof buildNearEd25519OperationStepUpProof>, { kind: 'email_otp' }>
    | null;
}) {
  if (args.authorization.kind === 'passkey') {
    if (
      args.material.kind !== 'passkey_live' &&
      args.material.kind !== 'passkey_sealed'
    ) {
      throw new Error('[SigningEngine][near] passkey NEP-413 material changed factor');
    }
    return await resolveNearOperationStepUpMaterial({
      kind: 'passkey',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
      credential: args.authorization.credential,
    });
  }
  if (
    args.material.kind !== 'email_otp_live' &&
    args.material.kind !== 'email_otp_sealed'
  ) {
    throw new Error('[SigningEngine][near] Email OTP NEP-413 material changed factor');
  }
  if (!args.emailOtpProof) {
    throw new Error('[SigningEngine][near] Email OTP NEP-413 proof is missing');
  }
  if (args.material.kind === 'email_otp_live') {
    return await resolveNearOperationStepUpMaterial({
      kind: 'email_otp_live',
      material: args.material,
      expectedActivation: args.prepared.materialActivation,
    });
  }
  return await resolveNearOperationStepUpMaterial({
    kind: 'email_otp_sealed',
    material: args.material,
    expectedActivation: args.prepared.materialActivation,
    normalSigningRequest: args.prepared.prepare.request,
    displayDigest: args.displayDigest,
    proof: args.emailOtpProof,
  });
}

export async function signNep413Message({
  ctx,
  commandSubject,
  nearAccount,
  signingSessionCoordinator,
  payload,
  forceFreshAuth,
  passkeyEd25519OperationStepUp,
  emailOtpEd25519StepUp,
  yaoSigningPreparation,
  yaoMaterialExecutor,
  selection,
}: NearNep413Payload): Promise<InternalSignNep413MessageResult> {
  const selectionAuth =
    selection.kind === 'authorized' ? selection.selectedLane.auth : selection.candidate.auth;
  const selectedSignerSlot =
    selection.kind === 'authorized'
      ? selection.selectedLane.identity.signer.signerSlot
      : selection.candidate.signerSlot;
  const operationId = payload.operationId;
  const relayerUrl = ctx.relayerUrl;
  const nearAccountId = nearAccount.accountId;
  const touchConfirm = ctx.touchConfirm;
  if (!touchConfirm) {
    throw new Error('UiConfirm bridge not available for NEP-413 signing');
  }
  const requiredSignatureUses = 1;
  let signingAuthPlan: ReturnType<typeof signingAuthPlanForNearMaterialRequirement>;
  let signingSessionPlan: SigningSessionPlan;
  if (selection.kind === 'authorized') {
    const signingSessionAuthContext = resolveNearSigningSessionAuthContext({
      requiredSignatureUses,
      commandSubject,
      forceFreshAuth,
      selectedLane: selection.selectedLane,
      preparation: yaoSigningPreparation,
    });
    const resolvedSigningSession = {
      signingSessionPlan: planSigningSession({
        lane: signingSessionAuthContext.coordinatorInput.lane,
        readiness: signingSessionAuthContext.coordinatorInput.readiness,
        forceFreshAuth: signingSessionAuthContext.coordinatorInput.forceFreshAuth,
      }),
      readiness: signingSessionAuthContext.coordinatorInput.readiness,
      expiresAtMs: signingSessionAuthContext.coordinatorInput.expiresAtMs || 0,
      remainingUses: signingSessionAuthContext.coordinatorInput.remainingUses || 0,
    };
    const nearSigningSessionAuthPlan = buildNearSigningSessionAuthPlan({
      context: signingSessionAuthContext,
      resolvedSigningSession,
    });
    signingAuthPlan = nearSigningSessionAuthPlan.signingAuthPlan;
    signingSessionPlan = resolvedSigningSession.signingSessionPlan;
  } else {
    const candidate = selection.candidate;
    signingAuthPlan = signingAuthPlanForNearMaterialRequirement(selectionAuth);
    const deferredIdentity: DeferredEd25519MaterialIdentity = {
      kind: 'deferred_ed25519_material_identity',
      signer: nearEd25519SignerBindingFromBoundaryFields({
        walletId: candidate.walletId,
        nearAccountId: candidate.nearAccountId,
        nearEd25519SigningKeyId: candidate.nearEd25519SigningKeyId,
        signerSlot: candidate.signerSlot,
      }),
      materialActivation: candidate.materialActivation,
      thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
        candidate.thresholdSessionId,
      ),
    };
    signingSessionPlan = {
      kind: SigningSessionPlanKind.OperationStepUp,
      lane: {
        identity: deferredIdentity,
        auth: candidate.auth,
        curve: 'ed25519',
        keyKind: 'threshold_ed25519',
        chainFamily: 'near',
        sessionOrigin: 'per_operation',
        storageSource: 'sealed_restore',
        retention: 'single_use',
        materialActivation: deferredIdentity.materialActivation,
        thresholdSessionId: deferredIdentity.thresholdSessionId,
      },
    };
  }
  const { thresholdKeyMaterial } = await resolveNearSigningMaterials({
    materialExecutor: yaoMaterialExecutor,
    nearAccount,
    signerSlot: selectedSignerSlot,
    requestedSignerSlot: payload.signerSlot,
    operationLabel: 'NEP-413 signing',
  });
  const signingContext = validateAndPrepareNep413SigningContext({
    nearAccountId,
    relayerUrl,
    thresholdKeyMaterial,
  });
  const signingOperation: SigningOperationContext = {
    operationId,
    operationFingerprint: SigningSessionIds.signingOperationFingerprint(
      await thresholdEd25519Nep413OperationFingerprint({
        nearAccountId,
        nearNetworkId: resolveNearNetwork(
          ctx.chains || PASSKEY_MANAGER_DEFAULT_CONFIGS.network.chains,
        ),
        relayerKeyId: signingContext.threshold.thresholdKeyMaterial.relayerKeyId,
        signerPublicKey: signingContext.threshold.thresholdKeyMaterial.publicKey,
        message: payload.message,
        recipient: payload.recipient,
        nonce: payload.nonce,
        state: payload.state || null,
      }),
    ),
    intent: SigningOperationIntent.TransactionSign,
  };
  const runSharedNearNep413Command = async <T>(args: {
    commandKind: SigningOperationCommand['kind'];
    execute: () => Promise<T>;
  }): Promise<T> =>
    await runSigningOperationCommand({
      signingSessionPlan,
      signingOperation,
      commandKind: args.commandKind,
      execute: args.execute,
    });
  const preparedStepUp = await requireNearStepUpAuth({
    signingAuthPlan,
    signingLaneAuth: selectionAuth,
    requiredSignatureUses,
    passkeyEd25519OperationStepUp,
    emailOtpEd25519StepUp,
  });
  const signatureOnlyIntent = {
    kind: 'nep413_message_v1' as const,
    message: payload.message,
    recipient: payload.recipient,
    nonce: payload.nonce,
    ...(payload.state ? { state: payload.state } : {}),
  };
  let operationStepUpMaterial: NearOperationStepUpMaterial | null = null;
  let operationStepUpSigningDigestB64u: string | null = null;
  if (preparedStepUp.kind !== 'warm_session') {
    operationStepUpMaterial = await prepareNearOperationStepUpMaterial({
      method: preparedStepUp.kind,
      preparation: yaoSigningPreparation,
      executor: yaoMaterialExecutor,
    });
    const material = operationStepUpMaterial;
    const materialFacts = nearOperationStepUpMaterialFacts(material);
    const signingDigest = await computeThresholdEd25519Nep413SigningDigestWasm({
      message: payload.message,
      recipient: payload.recipient,
      nonce: payload.nonce,
      ...(payload.state ? { state: payload.state } : {}),
      workerCtx: ctx,
    });
    operationStepUpSigningDigestB64u = signingDigest.signingDigestB64u;
    registerNearOperationStepUpBuilder({
      requestId: String(operationId),
      build: async (preparation) => {
        if (preparation.kind !== 'near_signature_only') {
          throw new Error(
            '[SigningEngine][near] NEP-413 operation step-up preparation kind changed',
          );
        }
        return await prepareRouterAbEd25519SignatureOnlyOperationStepUp({
          ctx,
          thresholdSessionId: materialFacts.thresholdSessionId,
          materialFacts,
          thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
          walletId: commandSubject.walletSession.walletId,
          nearAccountId,
          materialActivation: material.materialActivation,
          operationId: signingOperation.operationId,
          operationFingerprint: signingOperation.operationFingerprint!,
          displayDigest: preparation.displayDigest,
          signingDigestB64u: signingDigest.signingDigestB64u,
          intent: signatureOnlyIntent,
        });
      },
    });
  }
  let confirmation;
  try {
    confirmation = await runSigningConfirmationCommand({
      signingSessionPlan,
      signingOperation,
      runtime: touchConfirm,
      request: {
        ctx: { touchConfirm },
        sessionId: String(operationId),
        chain: 'near',
        kind: 'nep413',
        ...buildSigningConfirmationAuthParams({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
        }),
        walletId: String(commandSubject.walletSession.walletId),
        nearAccountId,
        nearPublicKeyStr: signingContext.nearPublicKey,
        message: payload.message,
        recipient: payload.recipient,
        title: payload.title,
        body: payload.body,
        confirmationConfigOverride: confirmationConfigForSigningAuthPlan({
          signingAuthPlan: preparedStepUp.confirmationAuthPayload.signingAuthPlan,
          override: payload.confirmationConfigOverride,
        }),
      },
    });
  } finally {
    clearNearOperationStepUpBuilder(String(operationId));
  }
  const stepUpAuthorization = buildNearEd25519StepUpAuthorization({
    prepared: preparedStepUp,
    confirmation,
  });
  const operationStepUpProof =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : buildNearEd25519OperationStepUpProof({
          authorization: stepUpAuthorization,
          preparation: yaoSigningPreparation,
          auth: selectionAuth,
          walletId: commandSubject.walletSession.walletId,
        });
  const preparedOperationStepUp =
    stepUpAuthorization.kind === 'warm_session'
      ? null
      : requirePreparedNearNep413OperationStepUp(
          consumePreparedNearOperationStepUp({
            requestId: String(operationId),
            ref: requireNearNep413OperationStepUpPreparation(
              confirmation.operationStepUpPreparation,
            ),
          }),
        );

  const preparedMaterial = await runSharedNearNep413Command({
    commandKind: SigningOperationCommandKind.PreparePayload,
    execute: async () => {
      return stepUpAuthorization.kind === 'warm_session'
        ? {
            kind: 'warm_session' as const,
            resolved: await resolveConfirmedNearEd25519YaoCapability({
              authorization: stepUpAuthorization,
              preparation: yaoSigningPreparation,
              executor: yaoMaterialExecutor,
            }),
          }
        : {
            kind: 'operation_step_up' as const,
            thresholdSessionId: nearOperationStepUpMaterialFacts(
              requireNearNep413OperationStepUpMaterial(operationStepUpMaterial),
            ).thresholdSessionId,
            resolved: await resolveNearNep413OperationStepUpCapability({
              material: requireNearNep413OperationStepUpMaterial(operationStepUpMaterial),
              prepared: requirePreparedNearNep413OperationStepUp(preparedOperationStepUp),
              displayDigest: confirmation.intentDigest,
              authorization: stepUpAuthorization,
              emailOtpProof:
                operationStepUpProof?.kind === 'email_otp'
                  ? operationStepUpProof
                  : null,
            }),
          };
    },
  });
  const canonicalThresholdSessionId =
    preparedMaterial.kind === 'warm_session'
      ? preparedMaterial.resolved.thresholdSessionId
      : preparedMaterial.thresholdSessionId;

  const executeNep413Request = async () => {
    const signingDigestB64u =
      stepUpAuthorization.kind === 'warm_session'
        ? (
            await computeThresholdEd25519Nep413SigningDigestWasm({
              message: payload.message,
              recipient: payload.recipient,
              nonce: payload.nonce,
              ...(payload.state ? { state: payload.state } : {}),
              workerCtx: ctx,
            })
          ).signingDigestB64u
        : requireNearNep413SigningDigest(operationStepUpSigningDigestB64u);
    const routerAbNormalSigningResult =
      preparedMaterial.kind === 'warm_session'
        ? await tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: preparedMaterial.resolved.material.activeClient,
            walletSessionState: requireAuthorizedNearNep413WalletSessionState(
              await resolveActiveAuthorizedRouterAbEd25519WalletSessionState({
                state: preparedMaterial.resolved.walletSessionState,
                nowMs: Date.now(),
              }),
            ),
            walletId: commandSubject.walletSession.walletId,
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint: signingOperation.operationFingerprint!,
            displayDigest: confirmation.intentDigest,
            signingDigestB64u,
            intent: signatureOnlyIntent,
            authorization: { kind: 'reusable_wallet_session' },
          })
        : await tryFinalizeRouterAbEd25519SignatureOnlyNormalSigning({
            ctx,
            thresholdSessionId: canonicalThresholdSessionId,
            activeClient: preparedMaterial.resolved.material.activeClient,
            materialFacts: preparedMaterial.resolved.material.facts,
            walletId: commandSubject.walletSession.walletId,
            thresholdKeyMaterial: signingContext.threshold.thresholdKeyMaterial,
            nearAccountId,
            operationId: signingOperation.operationId,
            operationFingerprint: signingOperation.operationFingerprint!,
            displayDigest: confirmation.intentDigest,
            signingDigestB64u,
            intent: signatureOnlyIntent,
            authorization: {
              kind: 'operation_step_up',
              prepared: requirePreparedNearNep413OperationStepUp(preparedOperationStepUp),
              proof: requireNearEd25519OperationStepUpProof(operationStepUpProof),
              issuedAuthorization: preparedMaterial.resolved.issuedAuthorization,
            },
          });
    if (routerAbNormalSigningResult) {
      if (
        preparedMaterial.kind === 'operation_step_up' &&
        routerAbNormalSigningResult.authorization === 'operation_step_up'
      ) {
        requireIssuedNearEd25519OperationStepUpAuthorization({
          prepared: requirePreparedNearNep413OperationStepUp(preparedOperationStepUp),
          issuedAuthorization: routerAbNormalSigningResult.issuedAuthorization,
        });
      }
      return {
        type: WorkerResponseType.SignNep413MessageSuccess,
        payload: {
          accountId: nearAccountId,
          publicKey: routerAbNormalSigningResult.signerPublicKey,
          signature: base64Encode(base64UrlDecode(routerAbNormalSigningResult.signatureB64u)),
          state: payload.state || undefined,
        },
      } as WorkerSuccessResponse<typeof WorkerRequestType.SignNep413Message>;
    }
    throw new Error('[SigningEngine][near] Router A/B Ed25519 NEP-413 signing is unavailable');
  };

  const okResponse = await runSharedNearNep413Command({
    commandKind: SigningOperationCommandKind.Sign,
    execute: async () => {
      try {
        return await executeNep413Request();
      } catch (e: unknown) {
        const err = e instanceof Error ? e : new Error(String(e));

        throw err;
      }
    },
  });

  return {
    success: true,
    accountId: okResponse.payload.accountId,
    publicKey: okResponse.payload.publicKey,
    signature: okResponse.payload.signature,
    state: okResponse.payload.state || undefined,
  };
}

type ThresholdNep413SigningContext = {
  nearPublicKey: string;
  threshold: {
    relayerUrl: string;
    thresholdKeyMaterial: ThresholdEd25519KeyMaterial;
  };
};

function validateAndPrepareNep413SigningContext(args: {
  nearAccountId: string;
  relayerUrl: string;
  thresholdKeyMaterial: ThresholdEd25519KeyMaterial | null;
}): ThresholdNep413SigningContext {
  const thresholdKeyMaterial = args.thresholdKeyMaterial;
  if (!thresholdKeyMaterial) {
    throw new Error(`Missing threshold key material for ${args.nearAccountId}`);
  }

  const thresholdPublicKey = String(thresholdKeyMaterial.publicKey || '').trim();
  if (!thresholdPublicKey) {
    throw new Error(`Missing threshold signing public key for ${args.nearAccountId}`);
  }

  const relayerUrl = String(args.relayerUrl || '').trim();
  if (!relayerUrl) {
    throw new Error('Missing relayerUrl (required for threshold-signer)');
  }

  const participantIds = normalizeThresholdEd25519ParticipantIds(
    thresholdKeyMaterial.participants.map((p) => p.id),
  );
  if (!participantIds || participantIds.length < 2) {
    throw new Error(
      `Invalid threshold signing participantIds (expected >=2 participants, got [${(participantIds || []).join(',')}])`,
    );
  }

  return {
    nearPublicKey: thresholdPublicKey,
    threshold: {
      relayerUrl,
      thresholdKeyMaterial,
    },
  };
}
