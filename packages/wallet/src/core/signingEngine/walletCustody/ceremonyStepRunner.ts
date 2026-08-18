import type { WalletCustodyCeremonyWorkerOperationMap } from '../workerManager/workerTypes';
import type { WalletCustodyCeremonyStepRunner } from './ceremonyDriver';

/**
 * Turns the worker transport into the ceremony driver's step runner.
 *
 * The driver deliberately takes a runner rather than a transport, so it can be
 * exercised without a worker at all. This adapter is the one place that knows
 * both shapes, and it is where the ceremony's channel name is spelled — one
 * spelling, so a run cannot be dispatched to a worker that does not hold its
 * state.
 *
 * The transport is typed structurally rather than by importing the concrete
 * class: this module is on the registration path, and depending on the whole
 * worker manager to send three messages would drag its graph along with it.
 */

export type WalletCustodyCeremonyTransportPort = {
  requestOperation(args: { kind: 'walletCustodyCeremony'; request: unknown }): Promise<unknown>;
};

export function walletCustodyCeremonyStepRunner(
  transport: WalletCustodyCeremonyTransportPort,
): WalletCustodyCeremonyStepRunner {
  return (async <T extends keyof WalletCustodyCeremonyWorkerOperationMap>(
    type: T,
    payload: WalletCustodyCeremonyWorkerOperationMap[T]['payload'],
  ) => {
    /* One worker, keyed by ceremony id, across all three steps: the seed and
       the owner roots live in its wasm state between them, so a step routed
       elsewhere would find no run to continue. */
    return (await transport.requestOperation({
      kind: 'walletCustodyCeremony',
      request: { type, payload },
    })) as WalletCustodyCeremonyWorkerOperationMap[T]['result'];
  }) as WalletCustodyCeremonyStepRunner;
}
