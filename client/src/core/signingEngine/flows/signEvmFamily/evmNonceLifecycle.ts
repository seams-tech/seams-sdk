import {
  reserveNonceInputFromBoundary,
  type ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceBackend';
import {
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  type NonceOperationContext,
} from '../../nonce/NonceCoordinator';
import type { EvmSigningRequest } from '../../chains/evm/types';
import { mapToRetryableNonceStateError } from './errors';
import type { EvmFamilyManagedNonceReservation } from './events';
import type { EvmFamilyNonceLifecycleDeps } from './nonceLifecycleAdapter';
import {
  resolveManagedNonceSender,
  resolveNonceNetworkKey,
  type EvmFamilyManagedNonceSenderIdentity,
  type EvmFamilyAccountMetadataDeps,
  type EvmFamilyNonceNetworkDeps,
} from './nonceResolution';

export async function resolveManagedEvmNonceReservationInput(args: {
  deps: EvmFamilyAccountMetadataDeps & EvmFamilyNonceNetworkDeps;
  walletId: string;
  request: EvmSigningRequest;
  senderIdentity: EvmFamilyManagedNonceSenderIdentity;
}): Promise<ReserveNonceInput> {
  const sender = await resolveManagedNonceSender({
    senderIdentity: args.senderIdentity,
  });
  return reserveNonceInputFromBoundary({
    chain: 'evm',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.seamsPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    walletId: args.walletId,
  });
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
      networkKey: reservationInput.chainTarget.networkSlug,
      chainId: reservationInput.chainTarget.chainId,
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
