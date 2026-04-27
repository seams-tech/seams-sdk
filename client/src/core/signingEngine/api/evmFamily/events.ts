import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { createSigningFlowEvent } from '@/core/types/sdkSentEvents';
import type { SigningExecutionTransitionEvent } from '../../session/signingSession/execution';
import { emitNonceLifecycleMetric } from './nonceMetrics';
import type {
  EvmFamilyLifecycleEvent,
  EvmFamilyLifecycleEventCallback,
} from './types';

export type EvmFamilyManagedNonceReservation = ManagedNonceReservation;

export function toNonceLifecycleMetricBase(
  reservation: EvmFamilyManagedNonceReservation,
): Omit<Parameters<typeof emitNonceLifecycleMetric>[0], 'metric'> {
  const base = {
    chain: reservation.chain,
    networkKey: reservation.networkKey,
    chainId: reservation.chainId,
    sender: reservation.sender,
    nonce: reservation.nonce.toString(),
    ...(reservation.nearAccountId ? { nearAccountId: reservation.nearAccountId } : {}),
  };
  return reservation.nonceKey != null
    ? { ...base, nonceKey: reservation.nonceKey.toString() }
    : base;
}

export function emitEvmFamilyNonceLifecycleMetric(
  event: Parameters<typeof emitNonceLifecycleMetric>[0],
): void {
  emitNonceLifecycleMetric(event);
}

export function emitEvmFamilyBroadcastEvent(
  onEvent: EvmFamilyLifecycleEventCallback | undefined,
  event: EvmFamilyLifecycleEvent,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: event.flowId ?? createEvmFamilySigningFlowId(event),
      }),
    );
  } catch {}
}

function createEvmFamilySigningFlowId(event: EvmFamilyLifecycleEvent): string {
  const data = event.data || {};
  const chain = String(data.chain || 'evm_family');
  const networkKey = String(data.networkKey || 'unknown_network');
  const nonce = String(data.nonce || '');
  return ['signing', chain, networkKey, nonce || String(event.phase)].join(':');
}

export function emitEvmFamilySigningEvent(
  onEvent: EvmFamilyLifecycleEventCallback | undefined,
  event: EvmFamilyLifecycleEvent,
): void {
  emitEvmFamilyBroadcastEvent(onEvent, event);
}

export function emitEvmFamilySigningExecutionTrace(
  event: SigningExecutionTransitionEvent,
): void {
  if (!isEvmFamilySigningExecutionTraceEnabled()) return;

  try {
    console.debug('[SigningExecutionMachine][evm-family]', event);
  } catch {}
}

function isEvmFamilySigningExecutionTraceEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('tatchi:debug:signing-execution') === '1';
  } catch {
    return false;
  }
}
