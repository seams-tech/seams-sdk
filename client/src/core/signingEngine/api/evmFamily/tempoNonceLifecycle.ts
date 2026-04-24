import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceManager';
import type { TempoSigningRequest } from '../../chainAdaptors/tempo/types';
import { mapToRetryableNonceStateError } from './errors';
import type { EvmFamilyManagedNonceReservation } from './events';
import type { EvmFamilyNonceLifecycleDeps } from './nonceLifecycle';
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
  nearAccountId: string;
  request: TempoSigningRequest;
  senderHint?: `0x${string}`;
}): Promise<{ request: TempoSigningRequest; reservation: EvmFamilyManagedNonceReservation }> {
  const sender = await resolveManagedNonceSender(args);
  const reservationInput: ReserveNonceInput = {
    chain: 'tempo',
    networkKey: resolveNonceNetworkKey({
      configs: args.deps.tatchiPasskeyConfigs,
      request: args.request,
    }),
    chainId: args.request.tx.chainId,
    sender,
    nonceKey: args.request.tx.nonceKey,
    nearAccountId: args.nearAccountId,
  };
  let nonce: bigint;
  try {
    nonce = await args.deps.evmNonceManager.reserveNextNonce(reservationInput);
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
        nonce,
      },
    },
    reservation: {
      ...reservationInput,
      nonce,
    },
  };
}
