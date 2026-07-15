import type { SyncAccountHooksOptions } from '@/core/types/sdkSentEvents';
import type { ActionHooksOptions } from '@/core/types/sdkSentEvents';
import type { ActionResult } from '@/core/types/seams';
import {
  syncAccount as syncAccountCore,
  type SyncAccountResult,
} from '@/SeamsWeb/operations/recovery/syncAccount';
import type { EmailRecoveryWebContext } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { errorMessage } from '@shared/utils/errors';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { prepareRecoveryEmails, getLocalRecoveryEmails } from '@/utils/emailRecovery';

/** SeamsWeb email-recovery entry points. */
export type EmailRecoveryDomainDeps = {
  getContext: () => EmailRecoveryWebContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

function publicRecoveryEmail(entry: { hashHex: string; email?: string }): {
  hashHex: string;
  email: string;
} {
  return {
    hashHex: entry.hashHex,
    email: entry.email || entry.hashHex,
  };
}

export class EmailRecoveryDomain {
  private readonly getContext: () => EmailRecoveryWebContext;
  private readonly walletIframe: Pick<
    WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;

  constructor(deps: EmailRecoveryDomainDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async getRecoveryEmails(
    walletIdInput: string,
  ): Promise<Array<{ hashHex: string; email: string }>> {
    const walletId = walletIdFromString(walletIdInput);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      return await router.getRecoveryEmails(String(walletId));
    }
    const records = await getLocalRecoveryEmails(walletId);
    return records.map(publicRecoveryEmail);
  }

  async setRecoveryEmails(args: {
    walletId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    const walletId = walletIdFromString(args.walletId);
    const recoveryEmails = Array.isArray(args.recoveryEmails) ? args.recoveryEmails : [];
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      return await router.setRecoveryEmails({
        walletId: String(walletId),
        recoveryEmails,
        options: args.options,
      });
    }
    try {
      await prepareRecoveryEmails(walletId, recoveryEmails);
      const result: ActionResult = { success: true };
      await args.options?.afterCall?.(true, result);
      return result;
    } catch (error: unknown) {
      const message = errorMessage(error) || 'Failed to set recovery emails';
      const result: ActionResult = { success: false, error: message };
      await args.options?.onError?.(new Error(message));
      await args.options?.afterCall?.(false);
      return result;
    }
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
