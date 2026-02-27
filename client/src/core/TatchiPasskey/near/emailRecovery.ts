import { toAccountId } from '../../types/accountIds';
import { EmailRecoveryPhase, EmailRecoveryStatus } from '../../types/sdkSentEvents';
import type { SyncAccountHooksOptions } from '../../types/sdkSentEvents';
import type { EmailRecoverySSEEvent } from '../../types/sdkSentEvents';
import type { ActionHooksOptions } from '../../types/sdkSentEvents';
import type { ActionResult } from '../../types/tatchi';
import type { EmailRecoveryFlowOptions, PendingEmailRecovery } from '../../types/emailRecovery';
import { generateEmailRecoveryRequestId } from '../../types/emailRecovery';
import { syncAccount as syncAccountCore, type SyncAccountResult } from '../syncAccount';
import type { PasskeyManagerContext } from '../index';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';
import { normalizeRegistrationCredential } from '../../signingEngine/signers/webauthn/credentials/helpers';
import { redactCredentialExtensionOutputs } from '../../signingEngine/signers/webauthn/credentials';
import { buildThresholdEd25519Participants2pV1 } from '@shared/threshold/participants';
import { IndexedDBManager } from '../../indexedDB';
import { EmailRecoveryPendingStore } from '../../../utils/emailRecovery';
import { errorMessage } from '@shared/utils/errors';
import { isObject } from '@shared/utils/validation';
import { prepareRecoveryEmails, getLocalRecoveryEmails } from '../../../utils/emailRecovery';
import { getLoginSession } from '../login';
import {
  buildThresholdWarmSessionBootstrapPayload,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
} from '../thresholdWarmSessionBootstrap';

/**
 * TatchiPasskey email recovery call graph:
 * - syncAccount -> wallet iframe router sync path OR local syncAccount flow
 * - email recovery start/finalize/cancel -> wallet iframe router OR local recovery domain flow
 */
export type EmailRecoveryDomainDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

export class EmailRecoveryDomain {
  private readonly getContext: () => PasskeyManagerContext;
  private readonly walletIframe: Pick<
    WalletIframeCoordinator,
    'shouldUseWalletIframe' | 'requireRouter'
  >;

  private emailRecoveryOptions?: EmailRecoveryFlowOptions;
  private pendingEmailRecovery: PendingEmailRecovery | null = null;
  private emailRecoveryCancelled = false;

  constructor(deps: EmailRecoveryDomainDeps) {
    this.getContext = deps.getContext;
    this.walletIframe = deps.walletIframe;
  }

  async getRecoveryEmails(accountId: string): Promise<Array<{ hashHex: string; email: string }>> {
    const nearAccountId = toAccountId(accountId);

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(nearAccountId));
      return await router.getRecoveryEmails(String(nearAccountId));
    }

    const records = await getLocalRecoveryEmails(nearAccountId);
    return records.map((entry) => ({
      hashHex: entry.hashHex,
      email: entry.email || entry.hashHex,
    }));
  }

  async setRecoveryEmails(args: {
    accountId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult> {
    const nearAccountId = toAccountId(args.accountId);
    const recoveryEmails = Array.isArray(args.recoveryEmails) ? args.recoveryEmails : [];

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(nearAccountId));
      return await router.setRecoveryEmails({
        nearAccountId: String(nearAccountId),
        recoveryEmails,
        options: args.options,
      });
    }

    try {
      await prepareRecoveryEmails(nearAccountId, recoveryEmails);
      const result: ActionResult = { success: true };
      await args.options?.afterCall?.(true, result);
      return result;
    } catch (error: unknown) {
      const message = errorMessage(error) || 'Failed to set recovery emails';
      const actionResult: ActionResult = { success: false, error: message };
      await args.options?.onError?.(new Error(message));
      await args.options?.afterCall?.(false);
      return actionResult;
    }
  }

  async syncAccount(args: {
    accountId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult> {
    const accountId = args?.accountId ? toAccountId(args.accountId) : null;

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args?.accountId);
      // Router support is wired in the wallet origin; keep app-origin thin.
      return await router.syncAccount({
        ...(accountId ? { accountId: String(accountId) } : {}),
        onEvent: args?.options?.onEvent,
      });
    }

    return await syncAccountCore(this.getContext(), accountId, args?.options);
  }

  async startEmailRecovery(args: {
    accountId: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    const accountId = toAccountId(args.accountId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(accountId));
      return await router.startEmailRecovery({
        accountId: String(accountId),
        onEvent: args.options?.onEvent,
        options: {
          ...(args.options?.confirmerText ? { confirmerText: args.options.confirmerText } : {}),
          ...(args.options?.confirmationConfig
            ? { confirmationConfig: args.options.confirmationConfig }
            : {}),
        },
      });
    }

    this.emailRecoveryOptions = args.options;
    return await this.startEmailRecoveryLocal({ accountId: String(accountId) });
  }

  async finalizeEmailRecovery(args: {
    accountId: string;
    nearPublicKey?: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<void> {
    const accountId = toAccountId(args.accountId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(accountId));
      await router.finalizeEmailRecovery({
        accountId: String(accountId),
        nearPublicKey: args.nearPublicKey,
        onEvent: args.options?.onEvent,
      });
      return;
    }

    this.emailRecoveryOptions = args.options;
    await this.finalizeEmailRecoveryLocal({
      accountId: String(accountId),
      nearPublicKey: args.nearPublicKey,
    });
  }

  async cancelEmailRecovery(args?: { accountId?: string; nearPublicKey?: string }): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args?.accountId);
      await router.stopEmailRecovery({
        ...(args?.accountId ? { accountId: String(args.accountId) } : {}),
        ...(args?.nearPublicKey ? { nearPublicKey: String(args.nearPublicKey) } : {}),
      });
      return;
    }

    await this.cancelEmailRecoveryLocal(args);
  }

  private getPendingEmailRecoveryStore(): EmailRecoveryFlowOptions['pendingStore'] {
    const context = this.getContext();
    return (
      this.emailRecoveryOptions?.pendingStore ||
      new EmailRecoveryPendingStore({
        getPendingTtlMs: () =>
          Number(context.configs?.network?.relayer?.emailRecovery?.pendingTtlMs || 30 * 60_000),
      })
    );
  }

  private emitEmailRecoveryEvent(ev: EmailRecoveryEventPayload): void {
    try {
      this.emailRecoveryOptions?.onEvent?.(ev as EmailRecoverySSEEvent);
    } catch {}
  }

  private async buildEmailRecoveryMailtoUrl(args: {
    accountId: string;
    nearPublicKey?: string;
  }): Promise<string> {
    const accountId = toAccountId(args.accountId);
    const nearPublicKey = String(
      args.nearPublicKey || this.pendingEmailRecovery?.nearPublicKey || '',
    ).trim();
    const requestId = String(this.pendingEmailRecovery?.requestId || '').trim();
    const mailtoAddress = String(
      this.getContext().configs?.network?.relayer?.emailRecovery?.mailtoAddress || '',
    ).trim();
    if (!mailtoAddress) return 'mailto:';
    if (!nearPublicKey || !requestId) return `mailto:${mailtoAddress}`;

    const subject = `recover-${requestId} ${String(accountId)} ${nearPublicKey}`;
    const body = 'tee-encrypted';
    return `mailto:${mailtoAddress}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
  }

  private async startEmailRecoveryLocal(args: {
    accountId: string;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    try {
      const context = this.getContext();
      const nearAccountId = toAccountId(args.accountId);
      const relayerUrl = String(context.configs?.network?.relayer?.url || '').trim();
      if (!relayerUrl) throw new Error('Missing relayer url (configs.network.relayer.url)');

      const rpId = context.signingEngine.getRpId();
      if (!rpId) throw new Error('Missing rpId for email recovery flow');

      this.emailRecoveryCancelled = false;

      this.emitEmailRecoveryEvent({
        step: 1,
        phase: EmailRecoveryPhase.STEP_1_PREPARATION,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Preparing email recovery...',
      });

      const requestId = generateEmailRecoveryRequestId();
      const initialDeviceNumber = 1;

      this.emitEmailRecoveryEvent({
        step: 2,
        phase: EmailRecoveryPhase.STEP_2_TOUCH_ID_REGISTRATION,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Creating passkey for recovery...',
      });

      const registrationSession =
        await context.signingEngine.requestRegistrationCredentialConfirmation({
          nearAccountId: String(nearAccountId),
          deviceNumber: initialDeviceNumber,
          confirmerText: this.emailRecoveryOptions?.confirmerText,
          confirmationConfigOverride: this.emailRecoveryOptions?.confirmationConfig,
        });

      const credential = registrationSession.credential;
      const intentDigest = String(registrationSession.intentDigest || '').trim();
      const deviceNumber = (() => {
        const parts = intentDigest.split(':');
        const last = parts[parts.length - 1];
        const n = Number(last);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : initialDeviceNumber;
      })();

      const derived =
        await context.signingEngine.deriveThresholdEd25519ClientVerifyingShareFromCredential({
          credential,
          nearAccountId,
        });
      if (!derived.success || !derived.clientVerifyingShareB64u) {
        throw new Error(derived.error || 'Failed to derive threshold client verifying share');
      }
      const thresholdWarmPolicyDraft = createThresholdWarmSessionPolicyDraft(context);
      if (!thresholdWarmPolicyDraft) {
        throw new Error('Threshold warm-session defaults are disabled for email recovery');
      }

      const credentialForRelay = redactCredentialExtensionOutputs(
        normalizeRegistrationCredential(credential),
      );
      const prepareResp = await fetch(`${relayerUrl}/email-recovery/prepare`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_id: String(nearAccountId),
          request_id: requestId,
          device_number: deviceNumber,
          threshold_ed25519: buildThresholdWarmSessionBootstrapPayload({
            clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
            nearAccountId: String(nearAccountId),
            rpId,
            policy: thresholdWarmPolicyDraft,
          }),
          rp_id: rpId,
          webauthn_registration: credentialForRelay,
        }),
      });
      const prepareJson: unknown = await prepareResp.json().catch(() => ({}));
      const prepareObj = isObject(prepareJson) ? prepareJson : {};
      const prepareOk = prepareObj.ok === true;
      const prepareMessage = typeof prepareObj.message === 'string' ? prepareObj.message : '';
      const prepareError = typeof prepareObj.error === 'string' ? prepareObj.error : '';
      if (!prepareResp.ok || !prepareOk) {
        throw new Error(
          prepareMessage ||
            prepareError ||
            `email-recovery/prepare failed (HTTP ${prepareResp.status})`,
        );
      }

      const thresholdSection = isObject(prepareObj.thresholdEd25519)
        ? prepareObj.thresholdEd25519
        : {};
      const thresholdPublicKey = String(thresholdSection.publicKey || '').trim();
      const relayerKeyId = String(thresholdSection.relayerKeyId || '').trim();
      const relayerVerifyingShareB64u = String(
        thresholdSection.relayerVerifyingShareB64u || '',
      ).trim();
      if (!thresholdPublicKey || !relayerKeyId || !relayerVerifyingShareB64u) {
        throw new Error('email-recovery/prepare returned incomplete threshold key material');
      }
      const thresholdSession = isObject(thresholdSection.session) ? thresholdSection.session : null;
      if (!thresholdSession) {
        throw new Error('email-recovery/prepare did not return threshold session bootstrap data');
      }

      const credentialId = String(credential.rawId || '').trim();
      const attestationObject = String(credential.response?.attestationObject || '').trim();
      if (!credentialId || !attestationObject) {
        throw new Error('Missing WebAuthn registration attestation in credential');
      }
      const credentialPublicKey =
        await context.signingEngine.extractCosePublicKey(attestationObject);
      const clientParticipantId = Number(thresholdSection.clientParticipantId);
      const relayerParticipantId = Number(thresholdSection.relayerParticipantId);
      await context.signingEngine.storeUserData({
        nearAccountId,
        deviceNumber,
        clientNearPublicKey: thresholdPublicKey,
        lastUpdated: Date.now(),
        passkeyCredential: {
          id: String(credential.id || credentialId),
          rawId: credentialId,
        },
        version: 2,
      });
      await context.signingEngine.storeAuthenticator({
        nearAccountId,
        credentialId,
        credentialPublicKey,
        transports: Array.isArray(credential.response?.transports)
          ? credential.response.transports
          : [],
        name: `Passkey for ${String(nearAccountId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
        deviceNumber,
      });

      await IndexedDBManager.storeNearThresholdKeyMaterial({
        nearAccountId,
        deviceNumber,
        publicKey: thresholdPublicKey,
        relayerKeyId,
        clientShareDerivation: 'prf_first_v1',
        participants: buildThresholdEd25519Participants2pV1({
          clientParticipantId: Number.isFinite(clientParticipantId)
            ? Math.floor(clientParticipantId)
            : null,
          relayerParticipantId: Number.isFinite(relayerParticipantId)
            ? Math.floor(relayerParticipantId)
            : null,
          relayerKeyId,
          relayerUrl,
          clientVerifyingShareB64u: derived.clientVerifyingShareB64u,
          relayerVerifyingShareB64u,
          clientShareDerivation: 'prf_first_v1',
        }),
        timestamp: Date.now(),
      });
      await hydrateThresholdWarmSessionFromRelay({
        context,
        nearAccountId,
        relayerUrl,
        rpId,
        relayerKeyId,
        credential,
        requestedPolicy: thresholdWarmPolicyDraft,
        session: thresholdSession,
        participantIdsHint: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
        setActiveSigningSessionId: true,
      });

      this.pendingEmailRecovery = {
        accountId: nearAccountId,
        deviceNumber,
        requestId,
        nearPublicKey: thresholdPublicKey,
        credential,
        createdAt: Date.now(),
        status: 'awaiting-email',
      };
      if (this.pendingEmailRecovery) {
        await this.getPendingEmailRecoveryStore()?.set?.(this.pendingEmailRecovery);
      }

      this.emitEmailRecoveryEvent({
        step: 3,
        phase: EmailRecoveryPhase.STEP_3_AWAIT_EMAIL,
        status: EmailRecoveryStatus.SUCCESS,
        message: 'Email recovery prepared; send the email to continue',
        requestId,
        nearPublicKey: thresholdPublicKey,
      });

      const mailtoUrl = await this.buildEmailRecoveryMailtoUrl({
        accountId: String(nearAccountId),
        nearPublicKey: thresholdPublicKey,
      });
      return { mailtoUrl, nearPublicKey: thresholdPublicKey };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
      this.emailRecoveryOptions?.onError?.(error);
      this.emitEmailRecoveryEvent({
        step: 0,
        phase: EmailRecoveryPhase.ERROR,
        status: EmailRecoveryStatus.ERROR,
        message: 'Email recovery failed',
        error: error.message,
      });
      throw error;
    }
  }

  private async finalizeEmailRecoveryLocal(args: {
    accountId: string;
    nearPublicKey?: string;
  }): Promise<void> {
    try {
      const context = this.getContext();
      const accountId = toAccountId(args.accountId);
      const nearPublicKey = String(args.nearPublicKey || '').trim();
      const store = this.getPendingEmailRecoveryStore();
      const pending = await store?.get?.(accountId, nearPublicKey || undefined);
      this.pendingEmailRecovery = pending || this.pendingEmailRecovery;
      const targetPk = String(nearPublicKey || pending?.nearPublicKey || '').trim();
      if (!targetPk) {
        throw new Error('Missing nearPublicKey to finalize email recovery');
      }

      this.emitEmailRecoveryEvent({
        step: 4,
        phase: EmailRecoveryPhase.STEP_4_POLLING_ADD_KEY,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Waiting for AddKey on-chain...',
      });

      const pollEveryMs = Number(
        context.configs?.network?.relayer?.emailRecovery?.pollingIntervalMs || 4000,
      );
      const maxMs = Number(
        context.configs?.network?.relayer?.emailRecovery?.maxPollingDurationMs || 30 * 60_000,
      );
      const startedAt = Date.now();
      let found = false;

      while (Date.now() - startedAt < maxMs) {
        if (this.emailRecoveryCancelled) throw new Error('cancelled');
        const list = await context.nearClient.viewAccessKeyList(String(accountId));
        const keys = Array.isArray(list?.keys) ? list.keys : [];
        found = keys.some((key) => {
          if (!isObject(key)) return false;
          return String(key.public_key || '').trim() === targetPk;
        });
        if (found) break;
        await new Promise((resolve) => setTimeout(resolve, Math.max(500, pollEveryMs)));
      }

      if (!found) {
        throw new Error('Timed out waiting for AddKey');
      }

      const deviceNumber = Number.isFinite(Number(pending?.deviceNumber))
        ? Math.floor(Number(pending?.deviceNumber))
        : 1;
      await this.tryAutoLoginAfterRecovery({ accountId, deviceNumber });

      this.emitEmailRecoveryEvent({
        step: 6,
        phase: EmailRecoveryPhase.STEP_6_COMPLETE,
        status: EmailRecoveryStatus.SUCCESS,
        message: 'Email recovery complete',
      });

      if (pending?.nearPublicKey) {
        await store?.clear?.(accountId, pending.nearPublicKey);
      }
      this.pendingEmailRecovery = null;
    } catch (err: unknown) {
      const message = errorMessage(err) || 'Email recovery finalize failed';
      const error = err instanceof Error ? err : new Error(message);
      this.emailRecoveryOptions?.onError?.(error);
      this.emitEmailRecoveryEvent({
        step: 0,
        phase: EmailRecoveryPhase.ERROR,
        status: EmailRecoveryStatus.ERROR,
        message: 'Email recovery finalize failed',
        error: message,
      });
      throw error;
    }
  }

  private async tryAutoLoginAfterRecovery(args: {
    accountId: string;
    deviceNumber: number;
  }): Promise<void> {
    const context = this.getContext();
    try {
      const nearAccountId = toAccountId(String(args.accountId));
      const deviceNumber = Number.isFinite(Number(args.deviceNumber))
        ? Math.max(1, Math.floor(Number(args.deviceNumber)))
        : 1;

      this.emitEmailRecoveryEvent({
        step: 5,
        phase: EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION,
        status: EmailRecoveryStatus.PROGRESS,
        message: 'Restoring local session...',
      });

      await context.signingEngine.setLastUser(nearAccountId, deviceNumber).catch(() => undefined);
      await context.signingEngine.updateLastLogin(nearAccountId).catch(() => undefined);
      await context.signingEngine
        .initializeCurrentUser(nearAccountId, context.nearClient)
        .catch(() => undefined);
      const { login } = await getLoginSession(context, nearAccountId);
      if (!login?.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(nearAccountId)} as logged in`);
      }

      this.emitEmailRecoveryEvent({
        step: 5,
        phase: EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION,
        status: EmailRecoveryStatus.SUCCESS,
        message: `Welcome ${String(nearAccountId)}`,
      });
    } catch (error: unknown) {
      const message = errorMessage(error) || 'Auto-login failed after email recovery';
      this.emitEmailRecoveryEvent({
        step: 5,
        phase: EmailRecoveryPhase.STEP_5_FINALIZING_REGISTRATION,
        status: EmailRecoveryStatus.ERROR,
        message,
        error: message,
      });
    }
  }

  private async cancelEmailRecoveryLocal(args?: {
    accountId?: string;
    nearPublicKey?: string;
  }): Promise<void> {
    this.emailRecoveryCancelled = true;
    this.pendingEmailRecovery = null;
    try {
      const accountId = args?.accountId ? toAccountId(args.accountId) : null;
      if (accountId) {
        await this.getPendingEmailRecoveryStore()?.clear?.(accountId, args?.nearPublicKey);
      }
    } catch {}
  }
}

type EmailRecoveryEventPayload = {
  step: number;
  phase: EmailRecoveryPhase;
  status: EmailRecoveryStatus;
  message: string;
  error?: string;
  data?: Record<string, unknown>;
  logs?: string[];
  [key: string]: unknown;
};
