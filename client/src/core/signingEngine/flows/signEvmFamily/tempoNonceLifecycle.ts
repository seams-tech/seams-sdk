import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceBackend';
import {
  evmNonceLeaseToManagedReservation,
  evmReserveNonceInputToLane,
  type NonceOperationContext,
} from '../../nonce/NonceCoordinator';
import type { TempoSigningRequest } from '../../chains/tempo/types';
import { mapToRetryableNonceStateError } from './errors';
import type { EvmFamilyManagedNonceReservation } from './events';
import type { EvmFamilyNonceLifecycleDeps } from './nonceLifecycleAdapter';
import {
  resolveManagedNonceSender,
  resolveNonceNetworkKey,
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
  operation: NonceOperationContext;
  senderHint?: `0x${string}`;
}): Promise<{ request: TempoSigningRequest; reservation: EvmFamilyManagedNonceReservation }> {
  const sender = await resolveManagedNonceSender(args);
  const reservationInput: ReserveNonceInput = {
    chain: 'tempo',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.seamsPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nonceKey: args.request.tx.nonceKey,
    walletId: args.walletId,
  };
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
