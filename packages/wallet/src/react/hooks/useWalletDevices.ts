import { useMemo } from 'react';
import { useSeams } from '../context';
import type { SeamsContextType } from '../types';

/**
 * The linked-device slice of the wallet context.
 *
 * Pair it with `useDeviceLinking` (the approving-device side) and `ShowQRCode`
 * (the new-device side). A view over the same context, not a second one.
 */
export type UseWalletDevicesResult = Pick<
  SeamsContextType,
  'startDevice2LinkingFlow' | 'cancelDeviceLinking'
> & {
  /** Typed linked-device management: list, revoke. */
  devices: SeamsContextType['seams']['devices'];
};

export function useWalletDevices(): UseWalletDevicesResult {
  const ctx = useSeams();
  return useMemo(
    () => ({
      startDevice2LinkingFlow: ctx.startDevice2LinkingFlow,
      cancelDeviceLinking: ctx.cancelDeviceLinking,
      devices: ctx.seams.devices,
    }),
    [ctx],
  );
}
