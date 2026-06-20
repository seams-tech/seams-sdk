import type { HandlerDeps, HandlerMap } from './handlers/walletIframeHandler.types';
import { createAuthWalletIframeHandlers } from './handlers/auth';
import { createDeviceLinkWalletIframeHandlers } from './handlers/deviceLink';
import { createEcdsaTempoWalletIframeHandlers } from './handlers/ecdsaTempo';
import { createEmailOtpWalletIframeHandlers } from './handlers/emailOtp';
import { createExportWalletIframeHandlers } from './handlers/export';
import { createNearWalletIframeHandlers } from './handlers/near';
import { createPreferencesWalletIframeHandlers } from './handlers/preferences';
import { createRecoveryWalletIframeHandlers } from './handlers/recovery';

export type { HandlerDeps, HandlerMap };

export function createWalletIframeHandlers(deps: HandlerDeps): HandlerMap {
  return {
    ...createAuthWalletIframeHandlers(deps),
    ...createNearWalletIframeHandlers(deps),
    ...createEcdsaTempoWalletIframeHandlers(deps),
    ...createEmailOtpWalletIframeHandlers(deps),
    ...createExportWalletIframeHandlers(deps),
    ...createDeviceLinkWalletIframeHandlers(deps),
    ...createRecoveryWalletIframeHandlers(deps),
    ...createPreferencesWalletIframeHandlers(deps),
  };
}
