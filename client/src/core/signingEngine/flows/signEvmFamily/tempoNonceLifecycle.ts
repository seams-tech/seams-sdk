import {
  reserveNonceInputFromBoundary,
  type ReserveNonceInput,
} from '@/core/rpcClients/evm/nonceBackend';
import {
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  type PreparedNonceOperationContext,
} from '../../nonce/NonceCoordinator';
import type { TempoSigningRequest } from '../../chains/tempo/types';
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

type TempoManagedNonceDeps = EvmFamilyAccountMetadataDeps &
  EvmFamilyNonceLifecycleDeps &
  EvmFamilyNonceNetworkDeps;

export async function reserveManagedTempoNonceForRequest(args: {
  deps: TempoManagedNonceDeps;
  walletId: string;
  request: TempoSigningRequest;
  operation: PreparedNonceOperationContext;
  senderIdentity: EvmFamilyManagedNonceSenderIdentity;
}): Promise<{ request: TempoSigningRequest; reservation: EvmFamilyManagedNonceReservation }> {
  const sender = await resolveManagedNonceSender({
    senderIdentity: args.senderIdentity,
  });
  const reservationInput: ReserveNonceInput = reserveNonceInputFromBoundary({
    chain: 'tempo',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.seamsWebConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nonceKey: args.request.tx.nonceKey,
    walletId: args.walletId,
  });
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
      chain: 'tempo',
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
