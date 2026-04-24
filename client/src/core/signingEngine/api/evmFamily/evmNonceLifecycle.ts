import type { ReserveNonceInput } from '@/core/rpcClients/evm/nonceManager';
import type { EvmSigningRequest } from '../../chainAdaptors/evm/types';
import { mapToRetryableNonceStateError } from './errors';
import type { EvmFamilyManagedNonceReservation } from './events';
import type { EvmFamilyNonceLifecycleDeps } from './nonceLifecycle';
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
}): Promise<{ request: EvmSigningRequest; reservation: EvmFamilyManagedNonceReservation }> {
  const reservationInput = args.reservationInput;
  let nonce: bigint;
  try {
    nonce = await args.deps.evmNonceManager.reserveNextNonce(reservationInput);
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
        nonce,
      },
    },
    reservation: {
      ...reservationInput,
      nonce,
    },
  };
}
