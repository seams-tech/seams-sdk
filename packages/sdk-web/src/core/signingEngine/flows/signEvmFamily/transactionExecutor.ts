import type { EvmSignedResult } from '../../chains/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chains/evm/evmSigning.types';
import type { TempoSignedResult } from '../../chains/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chains/tempo/tempoSigning.types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EvmFamilyThresholdEcdsaStepUp } from './requireEvmFamilyStepUpAuth';
import { type PreparedNonceOperationContext } from '../../nonce/NonceCoordinator';
import { mapToRetryableNonceStateError } from './errors';
import {
  type EvmFamilyManagedNonceReservation,
} from './events';
import {
  releaseEvmFamilyNonceReservation,
  type EvmFamilyNonceLifecycleDeps,
} from './nonceLifecycleAdapter';
import {
  resolveWalletChainNonceSenderIdentity,
  thresholdOwnerNonceSenderIdentity,
  resolveNonceNetworkKeyForError,
  type EvmFamilyManagedNonceSenderIdentity,
  type EvmFamilyAccountMetadataDeps,
  type EvmFamilyNonceNetworkDeps,
} from './nonceResolution';
import {
  resolveManagedEvmNonceReservationInput,
  reserveManagedEvmNonceForRequest,
} from './evmNonceLifecycle';
import { loadSignEvmWithUiConfirm, loadSignEvmFamilyWithUiConfirmForTempo } from './signerLoader';
import { reserveManagedTempoNonceForRequest } from './tempoNonceLifecycle';

type EvmFamilyTransactionExecutorDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyNonceLifecycleDeps &
  EvmFamilyNonceNetworkDeps;

type EvmFamilySigningFlowArgs = object & {
  readonly authorization?: {
    readonly kind: 'linked_device';
    readonly confirmationAuthPlan: import('@/core/signingEngine/stepUpConfirmation/types').SigningAuthPlan & {
      readonly kind: 'warmSession';
    };
    readonly sign: (input: {
      readonly requestId: string;
      readonly operationId: string;
      readonly operationDigests: import('@shared/authorization/operationFingerprint').OperationDigestSet;
      readonly signingDigest32: Uint8Array;
    }) => Promise<Uint8Array>;
  };
};
type EvmFamilyTransactionSigningRequest = EvmSigningRequest | TempoSigningRequest;
type EvmFamilyTransactionSigningResult = EvmSignedResult | TempoSignedResult;
type EvmFamilyUiConfirmSigner = (args: unknown) => Promise<EvmFamilyTransactionSigningResult>;

/** What the executor needs from prepared threshold state: the owner address the
 * managed nonce is reserved against. The lane and signing-session plan it used
 * to carry were never read here, and neither exists for auth-neutral material. */
export type EvmFamilyExecutorThresholdEcdsaState =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'prepared';
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
    retryWithFreshEmailOtpAuth: (
      error: unknown,
    ) => Promise<TempoSignedResult | EvmSignedResult | null>;
    nonceOperation: PreparedNonceOperationContext;
  };

type EvmFamilyTransactionSigningConfig<TRequest extends EvmFamilyTransactionSigningRequest> = {
  targetKind: ThresholdEcdsaChainTarget['kind'];
  loadSigner: () => Promise<EvmFamilyUiConfirmSigner>;
  prepareRequestWithManagedNonce: (args: {
    deps: EvmFamilyTransactionExecutorDeps;
    walletId: string;
    request: TRequest;
    nonceOperation: PreparedNonceOperationContext;
  }) => Promise<{
    request: TRequest;
    reservation: EvmFamilyManagedNonceReservation;
  }>;
};

function resolveThresholdOwnerNonceSenderIdentity(args: {
  state: EvmFamilyExecutorThresholdEcdsaState;
}): EvmFamilyManagedNonceSenderIdentity | undefined {
  if (args.state.kind === 'not_required') return undefined;
  return thresholdOwnerNonceSenderIdentity(args.state.thresholdOwnerAddress);
}

function requireRawEip1559ThresholdOwnerNonceSenderIdentity(args: {
  state: EvmFamilyExecutorThresholdEcdsaState;
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): EvmFamilyManagedNonceSenderIdentity {
  if (args.state.kind === 'not_required') {
    throw new Error(
      `[SigningEngine][evm-family] raw EIP-1559 signing requires prepared threshold ECDSA owner address for ${args.walletId}`,
    );
  }
  return thresholdOwnerNonceSenderIdentity(args.state.thresholdOwnerAddress);
}

function resolvePreparedNonceSenderIdentity(args: {
  state: EvmFamilyExecutorThresholdEcdsaState;
}): EvmFamilyManagedNonceSenderIdentity | undefined {
  return resolveThresholdOwnerNonceSenderIdentity(args);
}

function resolveFallbackChainAccountNonceSenderIdentity(args: {
  deps: EvmFamilyTransactionExecutorDeps;
  walletId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): Promise<EvmFamilyManagedNonceSenderIdentity> {
  return resolveWalletChainNonceSenderIdentity({
    deps: args.deps,
    walletId: args.walletId,
    chainTarget: args.chainTarget,
  });
}

async function executeConfiguredEvmFamilyTransactionSigning<
  TRequest extends EvmFamilyTransactionSigningRequest,
>(
  args: EvmFamilyTransactionSigningExecutorArgs<TRequest>,
  config: EvmFamilyTransactionSigningConfig<TRequest>,
): Promise<EvmFamilyTransactionSigningResult> {
  /* Durable-lease recovery only has to finish before the managed-nonce
     reservation, so it runs concurrently with the signer chunk load and is
     awaited inside prepareRequestWithManagedNonce — keeping its IndexedDB
     (and occasional RPC) work off the confirmation modal's critical path. */
  const recoverDurableLeasesTask = args.deps.nonceCoordinator.recoverDurableLeases({
    walletId: args.walletId,
  });
  recoverDurableLeasesTask.catch(() => {});
  const signWithUiConfirm = await config.loadSigner();

  try {
    const result = await signWithUiConfirm({
      ...args.flowArgs,
      authorization: args.flowArgs.authorization ?? { kind: 'owner' },
      request: args.request,
      onConfirmationDisplayed: args.onConfirmationDisplayed,
      thresholdEcdsaStepUp: args.thresholdEcdsaStepUp,
      prepareRequestWithManagedNonce: async () => {
        await recoverDurableLeasesTask;
        return await config.prepareRequestWithManagedNonce({
          deps: args.deps,
          walletId: args.walletId,
          request: args.request,
          nonceOperation: args.nonceOperation,
        });
      },
      releaseNonceReservation: async (reservation: EvmFamilyManagedNonceReservation) => {
        await releaseEvmFamilyNonceReservation(args.deps, reservation);
      },
    } as unknown);
    return result;
  } catch (error: unknown) {
    const retried = await args.retryWithFreshEmailOtpAuth(error);
    if (retried) return retried;
    const finalError = mapToRetryableNonceStateError({
      error,
      chain: config.targetKind,
      networkKey: resolveNonceNetworkKeyForError({
        configs: args.deps.seamsWebConfigs,
        request: args.request,
      }),
      chainId: args.chainTarget.chainId,
    });
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
  retryWithFreshEmailOtpAuth: (
    error: unknown,
  ) => Promise<TempoSignedResult | EvmSignedResult | null>;
  nonceOperation: PreparedNonceOperationContext;
}): Promise<TempoSignedResult | EvmSignedResult> {
  if (args.chainTarget.kind === 'evm' || args.request.kind === 'eip1559') {
    let reservationInputPromise: ReturnType<typeof resolveManagedEvmNonceReservationInput> | null =
      null;
    let fallbackSenderIdentityPromise: Promise<EvmFamilyManagedNonceSenderIdentity> | null = null;
    const rawEip1559SenderIdentity =
      args.request.kind === 'eip1559'
        ? requireRawEip1559ThresholdOwnerNonceSenderIdentity({
            state: args.thresholdEcdsaState,
            walletId: args.walletId,
            chainTarget: args.chainTarget,
          })
        : undefined;
    const preparedSenderIdentity = resolvePreparedNonceSenderIdentity({
      state: args.thresholdEcdsaState,
    });
    const getSenderIdentity = (nonceArgs: {
      deps: EvmFamilyTransactionExecutorDeps;
      walletId: string;
    }): Promise<EvmFamilyManagedNonceSenderIdentity> => {
      const exactSenderIdentity = rawEip1559SenderIdentity || preparedSenderIdentity;
      if (exactSenderIdentity) return Promise.resolve(exactSenderIdentity);
      if (!fallbackSenderIdentityPromise) {
        fallbackSenderIdentityPromise = resolveFallbackChainAccountNonceSenderIdentity({
          deps: nonceArgs.deps,
          walletId: nonceArgs.walletId,
          chainTarget: args.chainTarget,
        });
      }
      return fallbackSenderIdentityPromise;
    };
    const getReservationInput = (nonceArgs: {
      deps: EvmFamilyTransactionExecutorDeps;
      walletId: string;
      request: EvmSigningRequest;
    }) => {
      if (!reservationInputPromise) {
        reservationInputPromise = getSenderIdentity(nonceArgs).then((senderIdentity) =>
          resolveManagedEvmNonceReservationInput({
            deps: nonceArgs.deps,
            walletId: nonceArgs.walletId,
            request: nonceArgs.request,
            senderIdentity,
          }),
        );
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
        loadSigner:
          targetKind === 'tempo'
            ? loadSignEvmFamilyWithUiConfirmForTempo
            : loadSignEvmWithUiConfirm,
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
  let tempoFallbackSenderIdentityPromise: Promise<EvmFamilyManagedNonceSenderIdentity> | null =
    null;
  const tempoPreparedSenderIdentity = resolvePreparedNonceSenderIdentity({
    state: args.thresholdEcdsaState,
  });
  const getTempoSenderIdentity = (nonceArgs: {
    deps: EvmFamilyTransactionExecutorDeps;
    walletId: string;
  }): Promise<EvmFamilyManagedNonceSenderIdentity> => {
    if (tempoPreparedSenderIdentity) return Promise.resolve(tempoPreparedSenderIdentity);
    if (!tempoFallbackSenderIdentityPromise) {
      tempoFallbackSenderIdentityPromise = resolveFallbackChainAccountNonceSenderIdentity({
        deps: nonceArgs.deps,
        walletId: nonceArgs.walletId,
        chainTarget: args.chainTarget,
      });
    }
    return tempoFallbackSenderIdentityPromise;
  };
  return await executeConfiguredEvmFamilyTransactionSigning(
    {
      ...args,
      request: args.request as TempoSigningRequest,
    },
    {
      targetKind: 'tempo',
      loadSigner: loadSignEvmFamilyWithUiConfirmForTempo,
      prepareRequestWithManagedNonce: async (nonceArgs) => {
        const senderIdentity = await getTempoSenderIdentity(nonceArgs);
        return await reserveManagedTempoNonceForRequest({
          deps: nonceArgs.deps,
          walletId: nonceArgs.walletId,
          request: nonceArgs.request,
          operation: nonceArgs.nonceOperation,
          senderIdentity,
        });
      },
    },
  );
}
