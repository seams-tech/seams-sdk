import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceBackend';
import {
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  type NonceOperationContext,
} from '../../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import { mapToRetryableNonceStateError } from './errors';
import type { EvmFamilyManagedNonceReservation } from './events';
import type { EvmFamilyNonceLifecycleDeps } from './nonceLifecycleAdapter';
import {
  resolveManagedNonceSender,
  resolveNonceNetworkKey,
  type EvmFamilyAccountMetadataDeps,
  type EvmFamilyNonceNetworkDeps,
} from './nonceResolution';

export async function resolveManagedEvmNonceReservationInput(args: {
  deps: EvmFamilyAccountMetadataDeps & EvmFamilyNonceNetworkDeps;
  nearAccountId: string;
  request: EvmSigningRequest;
  senderHint?: `0x${string}`;
}): Promise<ReserveNonceInput> {
  const sender = await resolveManagedNonceSender(args);
  return {
    chain: 'evm',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.tatchiPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nearAccountId: args.nearAccountId,
  };
}

export async function reserveManagedEvmNonceForRequest(args: {
  deps: EvmFamilyNonceLifecycleDeps;
  request: EvmSigningRequest;
  reservationInput: ReserveNonceInput;
  operation: NonceOperationContext;
}): Promise<{ request: EvmSigningRequest; reservation: EvmFamilyManagedNonceReservation }> {
  const reservationInput = args.reservationInput;
  let reservation: EvmFamilyManagedNonceReservation;
  try {
    const lease = await args.deps.nonceCoordinator.reserve({
      lane: evmReserveNonceInputToLane(reservationInput),
      operation: args.operation,
    });
    reservation = evmNonceLeaseToManagedReservation(lease);
  } catch (error: unknown) {
    throw mapToRetryableNonceStateError({
      error,
      chain: 'evm',
      networkKey: reservationInput.networkKey,
      chainId: reservationInput.chainId,
    });
  }
  return {
    request: {
      ...args.request,
      tx: {
        ...args.request.tx,
        nonce: reservation.nonce,
      },
    },
    reservation,
  };
}
