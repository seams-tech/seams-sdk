import type { SigningSessionPlan } from '../../session/operationState/types';
import { runSuccessfulEvmFamilyPostSignCommands } from './postSignFinalization';
import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import type { SelectedEcdsaLane } from '../../session/identity/laneIdentity';
import type { SigningSessionBudgetReservation } from '../../session/budget/budget';
import type { BudgetAdmittedOperation } from '../../session/operationState/transactionState';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyThresholdEcdsaStepUp } from './requireEvmFamilyStepUpAuth';
import {
  evmReserveNonceInputToLane,
  type NonceOperationContext,
} from '../../nonce/NonceCoordinator';
import { mapToRetryableNonceStateError } from './errors';
import {
  emitEvmFamilySigningOperationTrace,
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
import { loadSignEvmWithUiConfirm, loadSignTempoWithUiConfirm } from './signerLoader';
import { reserveManagedTempoNonceForRequest } from './tempoNonceLifecycle';

type EvmFamilyTransactionExecutorDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyNonceLifecycleDeps &
  EvmFamilyNonceNetworkDeps;

type EvmFamilySigningFlowArgs = object;
type EvmFamilyTransactionSigningRequest = EvmSigningRequest | TempoSigningRequest;
type EvmFamilyTransactionSigningResult = EvmSignedResult | TempoSignedResult;
type EvmFamilyUiConfirmSigner = (args: unknown) => Promise<EvmFamilyTransactionSigningResult>;

export type EvmFamilyExecutorThresholdEcdsaState =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'prepared';
      lane: SelectedEcdsaLane;
      signingSessionPlan: SigningSessionPlan;
      thresholdOwnerAddress: `0x${string}`;
    };

type EvmFamilyTransactionSigningExecutorArgs<TRequest extends EvmFamilyTransactionSigningRequest> =
  {
    deps: EvmFamilyTransactionExecutorDeps;
    walletId: string;
    request: TRequest;
    chainTarget: ThresholdEcdsaChainTarget;
    flowArgs: EvmFamilySigningFlowArgs;
    thresholdEcdsaState: EvmFamilyExecutorThresholdEcdsaState;
    onConfirmationDisplayed: () => void;
    thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
    reserveWalletSigningSessionBudget: (
      operation: BudgetAdmittedOperation<SelectedEcdsaLane>,
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
  loadSigner: () => Promise<EvmFamilyUiConfirmSigner>;
  prepareRequestWithManagedNonce: (args: {
    deps: EvmFamilyTransactionExecutorDeps;
    walletId: string;
    request: TRequest;
    nonceOperation: NonceOperationContext;
    ecdsaSignerAddress?: `0x${string}`;
  }) => Promise<{
    request: TRequest;
    reservation: EvmFamilyManagedNonceReservation;
  }>;
  reconcileNonceLane?: (args: {
    deps: EvmFamilyTransactionExecutorDeps;
    walletId: string;
    request: TRequest;
    ecdsaSignerAddress?: `0x${string}`;
  }) => void;
};

function resolveThresholdEcdsaSignerAddress(args: {
  state: EvmFamilyExecutorThresholdEcdsaState;
}): `0x${string}` | undefined {
  if (args.state.kind === 'not_required') return undefined;
  return args.state.thresholdOwnerAddress;
}

function requireRawEip1559ThresholdOwnerAddress(args: {
  state: EvmFamilyExecutorThresholdEcdsaState;
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): `0x${string}` | undefined {
  if (args.state.kind === 'not_required') {
    throw new Error(
      `[SigningEngine][evm-family] raw EIP-1559 signing requires prepared threshold ECDSA owner address for ${args.walletId}`,
    );
  }
  return args.state.thresholdOwnerAddress;
}

async function executeConfiguredEvmFamilyTransactionSigning<
  TRequest extends EvmFamilyTransactionSigningRequest,
>(
  args: EvmFamilyTransactionSigningExecutorArgs<TRequest>,
  config: EvmFamilyTransactionSigningConfig<TRequest>,
): Promise<EvmFamilyTransactionSigningResult> {
  const signWithUiConfirm = await config.loadSigner();
  const ecdsaSignerAddress = resolveThresholdEcdsaSignerAddress({
    state: args.thresholdEcdsaState,
  });
  config.reconcileNonceLane?.({
    deps: args.deps,
    walletId: args.walletId,
    request: args.request,
    ...(ecdsaSignerAddress ? { ecdsaSignerAddress } : {}),
  });

  try {
    const result = await signWithUiConfirm({
      ...args.flowArgs,
      request: args.request,
      onConfirmationDisplayed: args.onConfirmationDisplayed,
      thresholdEcdsaStepUp: args.thresholdEcdsaStepUp,
      reserveWalletSigningSessionBudget: args.reserveWalletSigningSessionBudget,
      prepareRequestWithManagedNonce: async () =>
        await config.prepareRequestWithManagedNonce({
          deps: args.deps,
          walletId: args.walletId,
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
        signingSessionPlan:
          args.thresholdEcdsaState.kind === 'prepared'
            ? args.thresholdEcdsaState.signingSessionPlan
            : undefined,
        onTransition: emitEvmFamilySigningOperationTrace,
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
      chainId: args.chainTarget.chainId,
    });
    if (!args.deferFailedSigningSessionFinalization) {
      args.recordFailedWalletSigningSessionSpend(finalError);
    }
    throw finalError;
  }
}

export async function executeEvmFamilyTransactionSigning(args: {
  deps: EvmFamilyTransactionExecutorDeps;
  walletId: string;
  request: EvmSigningRequest | TempoSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  flowArgs: EvmFamilySigningFlowArgs;
  thresholdEcdsaState: EvmFamilyExecutorThresholdEcdsaState;
  onConfirmationDisplayed: () => void;
  thresholdEcdsaStepUp: EvmFamilyThresholdEcdsaStepUp;
  reserveWalletSigningSessionBudget: (
    operation: BudgetAdmittedOperation<SelectedEcdsaLane>,
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
}): Promise<TempoSignedResult | EvmSignedResult> {
  if (args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559') {
    let reservationInputPromise: ReturnType<typeof resolveManagedEvmNonceReservationInput> | null =
      null;
    const rawEip1559OwnerAddress =
      args.request.kind === 'eip1559'
        ? requireRawEip1559ThresholdOwnerAddress({
            state: args.thresholdEcdsaState,
            walletId: args.walletId,
            chainTarget: args.chainTarget,
          })
        : undefined;
    const getReservationInput = (nonceArgs: {
      deps: EvmFamilyTransactionExecutorDeps;
      walletId: string;
      request: EvmSigningRequest;
      ecdsaSignerAddress?: `0x${string}`;
    }) => {
      if (!reservationInputPromise) {
        const senderHint = rawEip1559OwnerAddress || nonceArgs.ecdsaSignerAddress;
        reservationInputPromise = resolveManagedEvmNonceReservationInput({
          deps: nonceArgs.deps,
          walletId: nonceArgs.walletId,
          request: nonceArgs.request,
          ...(senderHint ? { senderHint } : {}),
        });
      }
      return reservationInputPromise;
    };
    const targetKind = args.chainTarget.kind;
    return await executeConfiguredEvmFamilyTransactionSigning(
      {
        ...args,
        request: args.request as EvmSigningRequest,
      },
      {
        targetKind,
        loadSigner: targetKind === 'tempo' ? loadSignTempoWithUiConfirm : loadSignEvmWithUiConfirm,
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
      },
    );
  }
  return await executeConfiguredEvmFamilyTransactionSigning(
    {
      ...args,
      request: args.request as TempoSigningRequest,
    },
    {
      targetKind: 'tempo',
      loadSigner: loadSignTempoWithUiConfirm,
      prepareRequestWithManagedNonce: async (nonceArgs) =>
        await reserveManagedTempoNonceForRequest({
          deps: nonceArgs.deps,
          walletId: nonceArgs.walletId,
          request: nonceArgs.request,
          operation: nonceArgs.nonceOperation,
          ...(nonceArgs.ecdsaSignerAddress ? { senderHint: nonceArgs.ecdsaSignerAddress } : {}),
        }),
    },
  );
}
