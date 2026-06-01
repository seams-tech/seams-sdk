import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { createSigningFlowEvent } from '@/core/types/sdkSentEvents';
import type { SigningOperationTransitionEvent } from '../shared/signingStateMachine';
import { emitNonceLifecycleMetric } from './nonceMetrics';
import type { EvmFamilyLifecycleEvent, EvmFamilyLifecycleEventCallback } from './types';

export type EvmFamilyManagedNonceReservation = ManagedNonceReservation;

export function toNonceLifecycleMetricBase(
  reservation: EvmFamilyManagedNonceReservation,
): Omit<Parameters<typeof emitNonceLifecycleMetric>[0], 'metric'> {
  const base = {
    chainTarget: reservation.chainTarget,
    networkKey: reservation.chainTarget.networkSlug,
    chainId: reservation.chainTarget.chainId,
    sender: reservation.sender,
    nonce: reservation.nonce.toString(),
    walletId: reservation.subjectId,
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

export function emitEvmFamilySigningOperationTrace(event: SigningOperationTransitionEvent): void {
  if (!isEvmFamilySigningOperationTraceEnabled()) return;

  try {
    console.debug('[SigningOperationMachine][evm-family]', event);
  } catch {}
}

function isEvmFamilySigningOperationTraceEnabled(): boolean {
  try {
    const storage = (globalThis as { localStorage?: Storage }).localStorage;
    return storage?.getItem('seams:debug:signing-operation') === '1';
  } catch {
    return false;
  }
}
