import type {
  TouchConfirmContextPort,
  TouchConfirmManager,
  TouchConfirmRegistrationPort,
  TouchConfirmSecureConfirmationPort,
  TouchConfirmSigningPort,
  TouchConfirmWorkerLifecyclePort,
  ThresholdPrfFirstCachePort,
} from '../touchConfirm';

export type TouchConfirmBridge =
  & TouchConfirmContextPort
  & TouchConfirmSigningPort
  & TouchConfirmRegistrationPort
  & TouchConfirmSecureConfirmationPort
  & ThresholdPrfFirstCachePort
  & TouchConfirmWorkerLifecyclePort;

export function createTouchConfirmBridge(manager: TouchConfirmManager): TouchConfirmBridge {
  return manager;
}
