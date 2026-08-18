import type { ManagedNonceReservation } from '@/core/rpcClients/evm/nonceBackend';
import { createSigningFlowEvent } from '@/core/types/sdkSentEvents';
import type { SigningOperationTransitionEvent } from '../shared/signingStateMachine';
import type { EvmFamilyLifecycleEvent, EvmFamilyLifecycleEventCallback } from './types';

export type EvmFamilyManagedNonceReservation = ManagedNonceReservation;

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
