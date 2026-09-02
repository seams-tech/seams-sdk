import type { SyncAccountHooksOptions } from '@/core/types/sdkSentEvents';
import {
  syncAccount as syncAccountCore,
  type SyncAccountResult,
} from '@/SeamsWeb/operations/recovery/syncAccount';
import type { AccountSyncWebContext } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { walletIdFromString } from '@shared/utils/registrationIntent';

export type AccountSyncDomainDeps = {
  getContext: () => AccountSyncWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

export class AccountSyncDomain {
  private readonly getContext: () => AccountSyncWebContext;
  private readonly walletIframe: Pick<
    WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;

  constructor(deps: AccountSyncDomainDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async syncAccount(args: {
    walletId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult> {
    const walletId = args.walletId ? walletIdFromString(args.walletId) : null;
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args.walletId);
      return await router.syncAccount({
        ...(walletId ? { walletId: String(walletId) } : {}),
        onEvent: args.options?.onEvent,
      });
    }
    return await syncAccountCore(
      this.getContext(),
      walletId ? String(walletId) : null,
      args.options,
    );
  }
}
