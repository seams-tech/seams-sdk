import type { TouchConfirmManagerConfig } from '@/core/types/secure-confirm-worker';
import { createTouchConfirmManager } from '../touchConfirm/TouchConfirmManager';
import type {
  TouchConfirmContext,
  TouchConfirmContextPort,
  TouchConfirmRegistrationPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmSigningPort,
  TouchConfirmWorkerLifecyclePort,
  ThresholdPrfFirstCachePort,
} from '../touchConfirm/types';

export type TouchConfirmBridge =
  & TouchConfirmContextPort
  & TouchConfirmSigningPort
  & TouchConfirmRegistrationPort
  & TouchConfirmSecureConfirmationPort
  & ThresholdPrfFirstCachePort
  & TouchConfirmWorkerLifecyclePort;

export type CreateTouchConfirmBridgeArgs = {
  config: TouchConfirmManagerConfig;
  context: TouchConfirmContext;
};

export function createTouchConfirmBridge(args: CreateTouchConfirmBridgeArgs): TouchConfirmBridge {
  const manager = createTouchConfirmManager(args.config, args.context);
  return manager;
}
