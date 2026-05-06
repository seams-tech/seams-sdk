import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  SigningSessionPlanKind,
  type SigningSessionPlan,
} from '../../session/signingSession/types';
import {
  SigningExecutionCommandKind,
  buildSigningPostSignExecutionSteps,
  runSigningExecutionSteps,
  type SigningExecutionCommand,
} from '../../session/signingSession/execution';
import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { ThresholdEcdsaSessionRecord } from '../thresholdLifecycle/thresholdSessionStore';
import type { SigningSessionBudgetReservation } from '../../session/signingSession/budget';
import type {
  BudgetAdmittedOperation,
  EvmFamilyEcdsaTransactionLane,
} from '../../session/signingSession/transactionState';
import type { ThresholdEcdsaChainTarget } from '../../session/signingSession/ecdsaChainTarget';
import type {
  EvmFamilyThresholdEcdsaAdmissionBoundary,
  EvmFamilyThresholdEcdsaAuthPlanInput,
} from '../../orchestration/shared/thresholdEcdsaTransactionAdmission';
import {
  evmReserveNonceInputToLane,
  type NonceOperationContext,
} from '../../nonce/NonceCoordinator';
import { mapToRetryableNonceStateError } from './errors';
import {
  emitEvmFamilySigningExecutionTrace,
  type EvmFamilyManagedNonceReservation,
} from './events';
import {
  releaseEvmFamilyNonceReservation,
  type EvmFamilyNonceLifecycleDeps,
} from './nonceLifecycleAdapter';
import {
  resolveNonceNetworkKeyForError,
  type EvmFamilyAccountMetadataDeps,
  type EvmFamilyNonceNetworkDeps,
} from './nonceResolution';
import {
  resolveManagedEvmNonceReservationInput,
  reserveManagedEvmNonceForRequest,
} from './evmNonceLifecycle';
import { toOptionalEvmAddress } from './addresses';
import {
  loadSignEvmWithTouchConfirm,
  loadSignTempoWithTouchConfirm,
} from './signerLoader';
import { reserveManagedTempoNonceForRequest } from './tempoNonceLifecycle';

type EvmFamilyTransactionExecutorDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyNonceLifecycleDeps &
  EvmFamilyNonceNetworkDeps;

type EvmFamilySigningFlowArgs = object;
type EvmFamilyTransactionSigningRequest = EvmSigningRequest | TempoSigningRequest;
type EvmFamilyTransactionSigningResult = EvmSignedResult | TempoSignedResult;
type EvmFamilyTouchConfirmSigner = (args: unknown) => Promise<EvmFamilyTransactionSigningResult>;

type EvmFamilyTransactionSigningExecutorArgs<
  TRequest extends EvmFamilyTransactionSigningRequest,
> = {
  deps: EvmFamilyTransactionExecutorDeps;
  nearAccountId: string;
  request: TRequest;
  flowArgs: EvmFamilySigningFlowArgs;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  signingSessionPlan?: SigningSessionPlan;
  onConfirmationDisplayed: () => void;
  thresholdEcdsaBoundary: EvmFamilyThresholdEcdsaAdmissionBoundary;
  thresholdEcdsaAuthPlan: EvmFamilyThresholdEcdsaAuthPlanInput;
  reserveWalletSigningSessionBudget: (
    operation: BudgetAdmittedOperation<EvmFamilyEcdsaTransactionLane>,
  ) => Promise<SigningSessionBudgetReservation | null>;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  recordFailedWalletSigningSessionSpend: (error: unknown) => void;
  applySuccessfulEcdsaPostSignPolicy: () => Promise<void>;
  deferSuccessfulSigningSessionFinalization?: boolean;
  deferFailedSigningSessionFinalization?: boolean;
  retryWithFreshEmailOtpAuth: (
    error: unknown,
  ) => Promise<TempoSignedResult | EvmSignedResult | null>;
  nonceOperation: NonceOperationContext;
};

type EvmFamilyTransactionSigningConfig<TRequest extends EvmFamilyTransactionSigningRequest> = {
  targetKind: ThresholdEcdsaChainTarget['kind'];
  loadSigner: () => Promise<EvmFamilyTouchConfirmSigner>;
  prepareRequestWithManagedNonce: (args: {
    deps: EvmFamilyTransactionExecutorDeps;
    nearAccountId: string;
    request: TRequest;
    nonceOperation: NonceOperationContext;
    ecdsaSignerAddress?: `0x${string}`;
  }) => Promise<{
    request: TRequest;
    reservation: EvmFamilyManagedNonceReservation;
  }>;
  reconcileNonceLane?: (args: {
    deps: EvmFamilyTransactionExecutorDeps;
    nearAccountId: string;
    request: TRequest;
    ecdsaSignerAddress?: `0x${string}`;
  }) => void;
};

function resolveThresholdEcdsaSignerAddress(args: {
  record?: ThresholdEcdsaSessionRecord;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  keyRef?: ThresholdEcdsaSecp256k1KeyRef;
}): `0x${string}` | undefined {
  return (
    toOptionalEvmAddress(args.keyRef?.ethereumAddress) ||
    toOptionalEvmAddress(args.record?.ethereumAddress) ||
    toOptionalEvmAddress(args.emailOtpReauthRecord?.ethereumAddress)
  );
}

async function runSuccessfulEvmFamilyPostSignCommands(args: {
  signingSessionPlan?: SigningSessionPlan;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  applySuccessfulEcdsaPostSignPolicy: () => Promise<void>;
}): Promise<void> {
  // EVM/Tempo touch-confirm flows return a signed raw transaction, not a broadcast result.
  // Consume wallet-session budget here before the caller can dispatch and poll transaction status.
  if (!args.signingSessionPlan || args.signingSessionPlan.kind === SigningSessionPlanKind.NotReady) {
    await args.recordSuccessfulWalletSigningSessionSpend();
    await args.applySuccessfulEcdsaPostSignPolicy();
    return;
  }

  const result = await runSigningExecutionSteps({
    steps: buildSigningPostSignExecutionSteps(args.signingSessionPlan),
    onTransition: emitEvmFamilySigningExecutionTrace,
    executor: {
      async execute(command: SigningExecutionCommand) {
        if (command.kind === SigningExecutionCommandKind.SpendBudget) {
          await args.recordSuccessfulWalletSigningSessionSpend();
          return;
        }
        if (command.kind === SigningExecutionCommandKind.Cleanup) {
          await args.applySuccessfulEcdsaPostSignPolicy();
          return;
        }
        throw new Error(`[SigningEngine] unexpected post-sign command: ${command.kind}`);
      },
    },
  });
  if (!result.ok) {
    throw result.error;
  }
}

async function executeConfiguredEvmFamilyTransactionSigning<
  TRequest extends EvmFamilyTransactionSigningRequest,
>(
  args: EvmFamilyTransactionSigningExecutorArgs<TRequest>,
  config: EvmFamilyTransactionSigningConfig<TRequest>,
): Promise<EvmFamilyTransactionSigningResult> {
  const signWithTouchConfirm = await config.loadSigner();
  const ecdsaSignerAddress = resolveThresholdEcdsaSignerAddress({
    ...(args.thresholdEcdsaRecord ? { record: args.thresholdEcdsaRecord } : {}),
    ...(args.emailOtpReauthRecord ? { emailOtpReauthRecord: args.emailOtpReauthRecord } : {}),
    ...(args.thresholdEcdsaKeyRef ? { keyRef: args.thresholdEcdsaKeyRef } : {}),
  });
  config.reconcileNonceLane?.({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    ...(ecdsaSignerAddress ? { ecdsaSignerAddress } : {}),
  });

  try {
    const result = await signWithTouchConfirm({
      ...args.flowArgs,
      request: args.request,
      onConfirmationDisplayed: args.onConfirmationDisplayed,
      thresholdEcdsaBoundary: args.thresholdEcdsaBoundary,
      thresholdEcdsaAuthPlan: args.thresholdEcdsaAuthPlan,
      reserveWalletSigningSessionBudget: args.reserveWalletSigningSessionBudget,
      prepareRequestWithManagedNonce: async () =>
        await config.prepareRequestWithManagedNonce({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          request: args.request,
          nonceOperation: args.nonceOperation,
          ...(ecdsaSignerAddress ? { ecdsaSignerAddress } : {}),
        }),
      releaseNonceReservation: async (reservation: EvmFamilyManagedNonceReservation) => {
        await releaseEvmFamilyNonceReservation(args.deps, reservation);
      },
    } as unknown);
    if (!args.deferSuccessfulSigningSessionFinalization) {
      await runSuccessfulEvmFamilyPostSignCommands({
        signingSessionPlan: args.signingSessionPlan,
        recordSuccessfulWalletSigningSessionSpend: args.recordSuccessfulWalletSigningSessionSpend,
        applySuccessfulEcdsaPostSignPolicy: args.applySuccessfulEcdsaPostSignPolicy,
      });
    }
    return result;
  } catch (error: unknown) {
    const retried = await args.retryWithFreshEmailOtpAuth(error);
    if (retried) return retried;
    const finalError = mapToRetryableNonceStateError({
      error,
      chain: config.targetKind,
      networkKey: resolveNonceNetworkKeyForError({
        configs: args.deps.seamsPasskeyConfigs,
        request: args.request,
      }),
      chainId: args.request.tx.chainId,
    });
    if (!args.deferFailedSigningSessionFinalization) {
      args.recordFailedWalletSigningSessionSpend(finalError);
    }
    throw finalError;
  }
}

export async function executeEvmFamilyTransactionSigning(args: {
  deps: EvmFamilyTransactionExecutorDeps;
  nearAccountId: string;
  request: EvmSigningRequest | TempoSigningRequest;
  flowArgs: EvmFamilySigningFlowArgs;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  signingSessionPlan?: SigningSessionPlan;
  onConfirmationDisplayed: () => void;
  thresholdEcdsaBoundary: EvmFamilyThresholdEcdsaAdmissionBoundary;
  thresholdEcdsaAuthPlan: EvmFamilyThresholdEcdsaAuthPlanInput;
  reserveWalletSigningSessionBudget: (
    operation: BudgetAdmittedOperation<EvmFamilyEcdsaTransactionLane>,
  ) => Promise<SigningSessionBudgetReservation | null>;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  recordFailedWalletSigningSessionSpend: (error: unknown) => void;
  applySuccessfulEcdsaPostSignPolicy: () => Promise<void>;
  deferSuccessfulSigningSessionFinalization?: boolean;
  deferFailedSigningSessionFinalization?: boolean;
  retryWithFreshEmailOtpAuth: (error: unknown) => Promise<TempoSignedResult | EvmSignedResult | null>;
  nonceOperation: NonceOperationContext;
}): Promise<TempoSignedResult | EvmSignedResult> {
  if (args.request.chain === 'evm') {
    let reservationInputPromise:
      | ReturnType<typeof resolveManagedEvmNonceReservationInput>
      | null = null;
    const getReservationInput = (nonceArgs: {
      deps: EvmFamilyTransactionExecutorDeps;
      nearAccountId: string;
      request: EvmSigningRequest;
      ecdsaSignerAddress?: `0x${string}`;
    }) => {
      if (!reservationInputPromise) {
        reservationInputPromise = resolveManagedEvmNonceReservationInput({
          deps: nonceArgs.deps,
          nearAccountId: nonceArgs.nearAccountId,
          request: nonceArgs.request,
          ...(nonceArgs.ecdsaSignerAddress ? { senderHint: nonceArgs.ecdsaSignerAddress } : {}),
        });
      }
      return reservationInputPromise;
    };
    return await executeConfiguredEvmFamilyTransactionSigning({
      ...args,
      request: args.request,
    }, {
      targetKind: 'evm',
      loadSigner: loadSignEvmWithTouchConfirm,
      reconcileNonceLane: (nonceArgs) => {
        void getReservationInput(nonceArgs)
          .then((reservationInput) =>
            nonceArgs.deps.nonceCoordinator.reconcile({
              lane: evmReserveNonceInputToLane(reservationInput),
            }),
          )
          .catch(() => null);
      },
      prepareRequestWithManagedNonce: async (nonceArgs) => {
        const reservationInput = await getReservationInput(nonceArgs);
        return await reserveManagedEvmNonceForRequest({
          deps: nonceArgs.deps,
          request: nonceArgs.request,
          reservationInput,
          operation: nonceArgs.nonceOperation,
        });
      },
    });
  }
  return await executeConfiguredEvmFamilyTransactionSigning({
    ...args,
    request: args.request,
  }, {
    targetKind: 'tempo',
    loadSigner: loadSignTempoWithTouchConfirm,
    prepareRequestWithManagedNonce: async (nonceArgs) =>
      await reserveManagedTempoNonceForRequest({
        deps: nonceArgs.deps,
        nearAccountId: nonceArgs.nearAccountId,
        request: nonceArgs.request,
        operation: nonceArgs.nonceOperation,
        ...(nonceArgs.ecdsaSignerAddress ? { senderHint: nonceArgs.ecdsaSignerAddress } : {}),
      }),
  });
}
