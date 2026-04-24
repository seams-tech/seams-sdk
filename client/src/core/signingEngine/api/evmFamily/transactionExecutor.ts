import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import {
  SigningSessionPlanKind,
  type SigningSessionPlan,
} from '../../session/signingSessionTypes';
import {
  SigningExecutionCommandKind,
  buildSigningPostSignExecutionSteps,
  runSigningExecutionSteps,
  type SigningExecutionCommand,
} from '../../session/SigningExecutionMachine';
import type { EvmSignedResult } from '../../chainAdaptors/evm/evmAdapter';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import type { TempoSignedResult } from '../../chainAdaptors/tempo/tempoAdapter';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import type { ThresholdEcdsaSessionRecord } from '../thresholdLifecycle/thresholdSessionStore';
import { mapToRetryableNonceStateError } from './errors';
import {
  emitEvmFamilySigningExecutionTrace,
  type EvmFamilyManagedNonceReservation,
} from './events';
import { releaseEvmFamilyNonceReservation, type EvmFamilyNonceLifecycleDeps } from './nonceLifecycle';
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
import type { EvmFamilyChain } from './types';
import {
  loadSignEvmWithTouchConfirm,
  loadSignTempoWithTouchConfirm,
} from './signerLoader';
import { reserveManagedTempoNonceForRequest } from './tempoNonceLifecycle';

type EvmFamilyTransactionExecutorDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyNonceLifecycleDeps &
  EvmFamilyNonceNetworkDeps;

type EvmFamilySigningFlowArgs = object;

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
  chain: EvmFamilyChain;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  applySuccessfulEcdsaPostSignPolicy: (chain: EvmFamilyChain) => Promise<void>;
}): Promise<void> {
  if (!args.signingSessionPlan || args.signingSessionPlan.kind === SigningSessionPlanKind.NotReady) {
    await args.recordSuccessfulWalletSigningSessionSpend();
    await args.applySuccessfulEcdsaPostSignPolicy(args.chain);
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
          await args.applySuccessfulEcdsaPostSignPolicy(args.chain);
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

async function executeEvmTransactionSigning(args: {
  deps: EvmFamilyTransactionExecutorDeps;
  nearAccountId: string;
  request: EvmSigningRequest;
  flowArgs: EvmFamilySigningFlowArgs;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  signingSessionPlan?: SigningSessionPlan;
  onConfirmationDisplayed: () => void;
  reserveWalletSigningSessionBudget: () => Promise<void>;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  recordFailedWalletSigningSessionSpend: (error: unknown) => void;
  applySuccessfulEcdsaPostSignPolicy: (chain: EvmFamilyChain) => Promise<void>;
  retryWithFreshEmailOtpAuth: (error: unknown) => Promise<TempoSignedResult | EvmSignedResult | null>;
}): Promise<EvmSignedResult | TempoSignedResult> {
  const signEvmWithTouchConfirm = await loadSignEvmWithTouchConfirm();
  const ecdsaSignerAddress = resolveThresholdEcdsaSignerAddress({
    ...(args.thresholdEcdsaRecord ? { record: args.thresholdEcdsaRecord } : {}),
    ...(args.emailOtpReauthRecord ? { emailOtpReauthRecord: args.emailOtpReauthRecord } : {}),
    ...(args.thresholdEcdsaKeyRef ? { keyRef: args.thresholdEcdsaKeyRef } : {}),
  });
  const reservationInputPromise = resolveManagedEvmNonceReservationInput({
    deps: args.deps,
    nearAccountId: args.nearAccountId,
    request: args.request,
    ...(ecdsaSignerAddress ? { senderHint: ecdsaSignerAddress } : {}),
  });
  void reservationInputPromise
    .then((reservationInput) => args.deps.evmNonceManager.reconcileLane(reservationInput))
    .catch(() => null);

  try {
    const result = await signEvmWithTouchConfirm({
      ...args.flowArgs,
      request: args.request,
      onConfirmationDisplayed: args.onConfirmationDisplayed,
      reserveWalletSigningSessionBudget: args.reserveWalletSigningSessionBudget,
      prepareRequestWithManagedNonce: async () =>
        await reserveManagedEvmNonceForRequest({
          deps: args.deps,
          request: args.request,
          reservationInput: await reservationInputPromise,
        }),
      releaseNonceReservation: (reservation: EvmFamilyManagedNonceReservation) => {
        releaseEvmFamilyNonceReservation(args.deps, reservation);
      },
    } as unknown);
    await runSuccessfulEvmFamilyPostSignCommands({
      signingSessionPlan: args.signingSessionPlan,
      chain: 'evm',
      recordSuccessfulWalletSigningSessionSpend: args.recordSuccessfulWalletSigningSessionSpend,
      applySuccessfulEcdsaPostSignPolicy: args.applySuccessfulEcdsaPostSignPolicy,
    });
    return result;
  } catch (error: unknown) {
    const retried = await args.retryWithFreshEmailOtpAuth(error);
    if (retried) return retried;
    const finalError = mapToRetryableNonceStateError({
      error,
      chain: 'evm',
      networkKey: resolveNonceNetworkKeyForError({
        configs: args.deps.tatchiPasskeyConfigs,
        request: args.request,
      }),
      chainId: args.request.tx.chainId,
    });
    args.recordFailedWalletSigningSessionSpend(finalError);
    throw finalError;
  }
}

async function executeTempoTransactionSigning(args: {
  deps: EvmFamilyTransactionExecutorDeps;
  nearAccountId: string;
  request: TempoSigningRequest;
  flowArgs: EvmFamilySigningFlowArgs;
  thresholdEcdsaRecord?: ThresholdEcdsaSessionRecord;
  emailOtpReauthRecord?: ThresholdEcdsaSessionRecord;
  thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
  signingSessionPlan?: SigningSessionPlan;
  onConfirmationDisplayed: () => void;
  reserveWalletSigningSessionBudget: () => Promise<void>;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  recordFailedWalletSigningSessionSpend: (error: unknown) => void;
  applySuccessfulEcdsaPostSignPolicy: (chain: EvmFamilyChain) => Promise<void>;
  retryWithFreshEmailOtpAuth: (error: unknown) => Promise<TempoSignedResult | EvmSignedResult | null>;
}): Promise<EvmSignedResult | TempoSignedResult> {
  const signTempoWithTouchConfirm = await loadSignTempoWithTouchConfirm();
  const ecdsaSignerAddress = resolveThresholdEcdsaSignerAddress({
    ...(args.thresholdEcdsaRecord ? { record: args.thresholdEcdsaRecord } : {}),
    ...(args.emailOtpReauthRecord ? { emailOtpReauthRecord: args.emailOtpReauthRecord } : {}),
    ...(args.thresholdEcdsaKeyRef ? { keyRef: args.thresholdEcdsaKeyRef } : {}),
  });

  try {
    const result = await signTempoWithTouchConfirm({
      ...args.flowArgs,
      request: args.request,
      onConfirmationDisplayed: args.onConfirmationDisplayed,
      reserveWalletSigningSessionBudget: args.reserveWalletSigningSessionBudget,
      prepareRequestWithManagedNonce: async () =>
        await reserveManagedTempoNonceForRequest({
          deps: args.deps,
          nearAccountId: args.nearAccountId,
          request: args.request,
          ...(ecdsaSignerAddress ? { senderHint: ecdsaSignerAddress } : {}),
        }),
      releaseNonceReservation: (reservation: EvmFamilyManagedNonceReservation) => {
        releaseEvmFamilyNonceReservation(args.deps, reservation);
      },
    } as unknown);
    await runSuccessfulEvmFamilyPostSignCommands({
      signingSessionPlan: args.signingSessionPlan,
      chain: 'tempo',
      recordSuccessfulWalletSigningSessionSpend: args.recordSuccessfulWalletSigningSessionSpend,
      applySuccessfulEcdsaPostSignPolicy: args.applySuccessfulEcdsaPostSignPolicy,
    });
    return result;
  } catch (error: unknown) {
    const retried = await args.retryWithFreshEmailOtpAuth(error);
    if (retried) return retried;
    const finalError = mapToRetryableNonceStateError({
      error,
      chain: 'tempo',
      networkKey: resolveNonceNetworkKeyForError({
        configs: args.deps.tatchiPasskeyConfigs,
        request: args.request,
      }),
      chainId: args.request.tx.chainId,
    });
    args.recordFailedWalletSigningSessionSpend(finalError);
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
  reserveWalletSigningSessionBudget: () => Promise<void>;
  recordSuccessfulWalletSigningSessionSpend: () => Promise<void>;
  recordFailedWalletSigningSessionSpend: (error: unknown) => void;
  applySuccessfulEcdsaPostSignPolicy: (chain: EvmFamilyChain) => Promise<void>;
  retryWithFreshEmailOtpAuth: (error: unknown) => Promise<TempoSignedResult | EvmSignedResult | null>;
}): Promise<TempoSignedResult | EvmSignedResult> {
  if (args.request.chain === 'evm') {
    return await executeEvmTransactionSigning({
      ...args,
      request: args.request,
    });
  }
  return await executeTempoTransactionSigning({
    ...args,
    request: args.request,
  });
}
