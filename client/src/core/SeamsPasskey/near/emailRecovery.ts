import { toAccountId } from '../../types/accountIds';
import {
  createEmailRecoveryFlowEvent,
  EmailRecoveryFlowEventPhase,
} from '../../types/sdkSentEvents';
import type {
  CreateEmailRecoveryFlowEventInput,
  EmailRecoveryFlowEvent,
  SyncAccountHooksOptions,
} from '../../types/sdkSentEvents';
import type { ActionHooksOptions } from '../../types/sdkSentEvents';
import type { ActionResult } from '../../types/seams';
import type { EmailRecoveryFlowOptions, PendingEmailRecovery } from '../../types/emailRecovery';
import { generateEmailRecoveryRequestId } from '../../types/emailRecovery';
import { syncAccount as syncAccountCore, type SyncAccountResult } from '../syncAccount';
import type { PasskeyManagerContext } from '../index';
import type { WalletIframeCoordinator } from '../walletIframeCoordinator';
import { normalizeRegistrationCredential } from '../../signingEngine/webauthnAuth/credentials/helpers';
import {
  redactCredentialExtensionOutputs,
} from '../../signingEngine/webauthnAuth/credentials/credentialExtensions';
import { derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential } from '../../signingEngine/session/passkey/ecdsaClientRoot';
import { EmailRecoveryPendingStore } from '../../../utils/emailRecovery';
import { errorMessage } from '@shared/utils/errors';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import { isObject } from '@shared/utils/validation';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { prepareRecoveryEmails, getLocalRecoveryEmails } from '../../../utils/emailRecovery';
import { restoreLocalLoginState } from '../restoreLocalLoginState';
import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519ClientBaseFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from '../thresholdWarmSessionBootstrap';
import { listThresholdEcdsaProvisionTargets } from '../thresholdEcdsaProvisioning';
import { normalizeThresholdRuntimePolicyScope } from '../../signingEngine/threshold/sessionPolicy';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '../../rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

/**
 * SeamsPasskey email recovery call graph:
 * - syncAccount -> wallet iframe router sync path OR local syncAccount flow
 * - email recovery start/finalize/cancel -> wallet iframe router OR local recovery domain flow
 */
export type EmailRecoveryDomainDeps = {
  getContext: () => PasskeyManagerContext;
  walletIframe: Pick<WalletIframeCoordinator, 'shouldUseWalletIframe' | 'requireRouter'>;
};

function coercePositiveInt(value: unknown, fallback: number): number {
  const n = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(n) || n <= 0) return Math.max(1, Math.floor(fallback));
  return Math.floor(n);
}

function requireEmailRecoveryString(value: unknown, field: string): string {
  const text = String(value || '').trim();
  if (!text) throw new Error(`email-recovery ECDSA response missing ${field}`);
  return text;
}

function parseEmailRecoveryEcdsaPrepare(value: unknown): WalletRegistrationEcdsaPrepareContext {
  if (!isObject(value)) {
    throw new Error('email-recovery/prepare returned invalid ECDSA prepare data');
  }
  const participantIds = Array.isArray(value.participantIds)
    ? value.participantIds.map((participantId) => Number(participantId))
    : [];
  if (
    participantIds.length === 0 ||
    participantIds.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0)
  ) {
    throw new Error('email-recovery/prepare returned invalid ECDSA participant ids');
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(value.runtimePolicyScope);
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: requireEmailRecoveryString(value.walletId, 'walletId'),
    rpId: requireEmailRecoveryString(value.rpId, 'rpId'),
    ecdsaThresholdKeyId: requireEmailRecoveryString(value.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
    signingRootId: requireEmailRecoveryString(value.signingRootId, 'signingRootId'),
    signingRootVersion: requireEmailRecoveryString(value.signingRootVersion, 'signingRootVersion'),
    keyScope: 'evm-family',
    relayerKeyId: requireEmailRecoveryString(value.relayerKeyId, 'relayerKeyId'),
    requestId: requireEmailRecoveryString(value.requestId, 'requestId'),
    sessionId: requireEmailRecoveryString(value.sessionId, 'sessionId'),
    walletSigningSessionId: requireEmailRecoveryString(
      value.walletSigningSessionId,
      'walletSigningSessionId',
    ),
    ttlMs: coercePositiveInt(value.ttlMs, 1),
    remainingUses: coercePositiveInt(value.remainingUses, 1),
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
  };
}

function parseEmailRecoveryEcdsaWalletKeys(value: unknown): WalletRegistrationEcdsaWalletKey[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('email-recovery/ecdsa/respond returned no ECDSA wallet keys');
  }
  return value.map((raw) => {
    if (!isObject(raw)) throw new Error('email-recovery/ecdsa/respond returned invalid wallet key');
    const chainTargetRaw = isObject(raw.chainTarget) ? raw.chainTarget : null;
    if (!chainTargetRaw) {
      throw new Error('email-recovery/ecdsa/respond returned wallet key without chain target');
    }
    const chainTarget: ThresholdEcdsaChainTarget =
      thresholdEcdsaChainTargetFromRequest(chainTargetRaw);
    const participantIds = Array.isArray(raw.participantIds)
      ? raw.participantIds.map((participantId) => Number(participantId))
      : [];
    if (
      participantIds.length === 0 ||
      participantIds.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0)
    ) {
      throw new Error('email-recovery/ecdsa/respond returned invalid wallet key participant ids');
    }
    return {
      keyScope: 'evm-family',
      chainTarget,
      walletId: requireEmailRecoveryString(raw.walletId, 'walletId'),
      rpId: requireEmailRecoveryString(raw.rpId, 'rpId'),
      keyHandle: requireEmailRecoveryString(raw.keyHandle, 'keyHandle'),
      ecdsaThresholdKeyId: requireEmailRecoveryString(raw.ecdsaThresholdKeyId, 'ecdsaThresholdKeyId'),
      signingRootId: requireEmailRecoveryString(raw.signingRootId, 'signingRootId'),
      signingRootVersion: requireEmailRecoveryString(raw.signingRootVersion, 'signingRootVersion'),
      thresholdEcdsaPublicKeyB64u: requireEmailRecoveryString(
        raw.thresholdEcdsaPublicKeyB64u,
        'thresholdEcdsaPublicKeyB64u',
      ),
      thresholdOwnerAddress: requireEmailRecoveryString(raw.thresholdOwnerAddress, 'thresholdOwnerAddress'),
      relayerKeyId: requireEmailRecoveryString(raw.relayerKeyId, 'relayerKeyId'),
      relayerVerifyingShareB64u: requireEmailRecoveryString(
        raw.relayerVerifyingShareB64u,
        'relayerVerifyingShareB64u',
      ),
      participantIds,
    };
  });
}

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

  private emailRecoveryFlowId(accountId?: string, requestId?: string): string {
    const accountPart = String(accountId || 'unknown-account').trim() || 'unknown-account';
    const requestPart = String(requestId || 'active').trim() || 'active';
    return `email-recovery:${accountPart}:${requestPart}`;
  }

  private emitEmailRecoveryEvent(input: EmailRecoveryEventPayload): void {
    try {
      this.emailRecoveryOptions?.onEvent?.(
        createEmailRecoveryFlowEvent(input) as EmailRecoveryFlowEvent,
      );
    } catch {}
  }

  private async buildEmailRecoveryMailtoUrl(args: {
    recoveryEmailSubject?: string;
    recoveryEmailBody?: string;
  }): Promise<string> {
    const mailtoAddress = String(
      this.getContext().configs?.network?.relayer?.emailRecovery?.mailtoAddress || '',
    ).trim();
    if (!mailtoAddress) return 'mailto:';
    const subject = String(
      args.recoveryEmailSubject || this.pendingEmailRecovery?.recoveryEmailSubject || '',
    ).trim();
    const body = String(
      args.recoveryEmailBody || this.pendingEmailRecovery?.recoveryEmailBody || '',
    ).trim();
    if (!subject || !body) return `mailto:${mailtoAddress}`;
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

      const requestId = generateEmailRecoveryRequestId();
      const initialSignerSlot = 1;
      const flowId = this.emailRecoveryFlowId(String(nearAccountId), requestId);

      this.emailRecoveryCancelled = false;

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_01_STARTED,
        status: 'started',
      });

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_STARTED,
        status: 'waiting_for_user',
        interaction: { kind: 'passkey_create', overlay: 'show' },
      });

      const registrationSession =
        await context.signingEngine.requestRegistrationCredentialConfirmation({
          nearAccountId: String(nearAccountId),
          signerSlot: initialSignerSlot,
          confirmerText: this.emailRecoveryOptions?.confirmerText,
          confirmationConfigOverride: this.emailRecoveryOptions?.confirmationConfig,
        });

      const credential = registrationSession.credential;

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_SUCCEEDED,
        status: 'succeeded',
        interaction: { kind: 'passkey_create', overlay: 'hide' },
      });

      const intentDigest = String(registrationSession.intentDigest || '').trim();
      const signerSlot = (() => {
        const parts = intentDigest.split(':');
        const last = parts[parts.length - 1];
        const n = Number(last);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : initialSignerSlot;
      })();

      const thresholdWarmPolicy = createThresholdWarmSessionPolicyDraft(context);
      if (!thresholdWarmPolicy) {
        throw new Error('Threshold warm-session defaults are disabled for email recovery');
      }
      const thresholdWarmSessionRequest = buildThresholdWarmSessionRequestEnvelope({
        nearAccountId: String(nearAccountId),
        rpId,
        requestedPolicy: thresholdWarmPolicy,
      });
      const ecdsaProvisionTargets = listThresholdEcdsaProvisionTargets({
        signerOptions: context.configs.signing.thresholdEcdsa.provisioningDefaults,
        chains: context.configs.network.chains,
      });
      if (ecdsaProvisionTargets.length === 0) {
        throw new Error('Email recovery requires at least one configured ECDSA provision target');
      }
      const clientRootShare32B64u =
        await derivePasskeyThresholdEcdsaClientRootShare32B64uFromCredential(credential);
      const credentialForRelay = redactCredentialExtensionOutputs(
        normalizeRegistrationCredential(credential),
      );
      const prepareResp = await fetch(joinNormalizedUrl(relayerUrl, '/email-recovery/prepare'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_id: String(nearAccountId),
          request_id: requestId,
          signer_slot: signerSlot,
          threshold_ed25519: thresholdWarmSessionRequest,
          threshold_ecdsa_prepare: {
            chainTargets: ecdsaProvisionTargets.map((target) => target.chainTarget),
            participantIds: [...THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1.participantIds],
          },
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

      const prepareEcdsaSection = isObject(prepareObj.ecdsa) ? prepareObj.ecdsa : null;
      const ecdsaPrepare = prepareEcdsaSection
        ? parseEmailRecoveryEcdsaPrepare(prepareEcdsaSection.prepare)
        : null;
      if (!ecdsaPrepare) {
        throw new Error('email-recovery/prepare did not return ECDSA prepare data');
      }
      const clientBootstrap: WalletRegistrationEcdsaClientBootstrap =
        await context.signingEngine.prepareWalletRegistrationEcdsaClientBootstrap({
          prepare: ecdsaPrepare,
          clientRootShare32B64u,
        });
      const ecdsaResp = await fetch(joinNormalizedUrl(relayerUrl, '/email-recovery/ecdsa/respond'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          request_id: requestId,
          client_bootstrap: clientBootstrap,
        }),
      });
      const ecdsaJson: unknown = await ecdsaResp.json().catch(() => ({}));
      const ecdsaObj = isObject(ecdsaJson) ? ecdsaJson : {};
      if (!ecdsaResp.ok || ecdsaObj.ok !== true) {
        throw new Error(
          String(ecdsaObj.message || ecdsaObj.error || '') ||
            `email-recovery/ecdsa/respond failed (HTTP ${ecdsaResp.status})`,
        );
      }

      const thresholdSection = isObject(ecdsaObj.thresholdEd25519)
        ? ecdsaObj.thresholdEd25519
        : {};
      const ecdsaResult = isObject(ecdsaObj.ecdsa) ? ecdsaObj.ecdsa : {};
      const ecdsaBootstrap = isObject(ecdsaResult.bootstrap) ? ecdsaResult.bootstrap : {};
      const walletKeys = parseEmailRecoveryEcdsaWalletKeys(ecdsaResult.walletKeys);
      const recoverySessionSection = isObject(ecdsaObj.recoverySession)
        ? ecdsaObj.recoverySession
        : {};
      const recoveryEmailSection = isObject(ecdsaObj.recoveryEmail) ? ecdsaObj.recoveryEmail : {};
      const thresholdPublicKey = String(thresholdSection.publicKey || '').trim();
      const relayerKeyId = String(thresholdSection.relayerKeyId || '').trim();
      const newEvmOwnerAddress = String(
        ecdsaBootstrap.ethereumAddress || walletKeys[0]?.thresholdOwnerAddress || '',
      ).trim();
      const recoverySessionId = String(recoverySessionSection.sessionId || requestId).trim();
      const recoveryDeadlineEpochSeconds = Number(recoveryEmailSection.deadlineEpochSeconds);
      const recoveryEmailPayloadHash = String(recoveryEmailSection.payloadHash || '').trim();
      const recoveryEmailSubject = String(recoveryEmailSection.subject || '').trim();
      const recoveryEmailBody = String(recoveryEmailSection.body || '').trim();
      if (!thresholdPublicKey || !relayerKeyId) {
        throw new Error('email-recovery/prepare returned incomplete threshold key material');
      }
      if (
        !newEvmOwnerAddress ||
        !recoverySessionId ||
        !Number.isFinite(recoveryDeadlineEpochSeconds) ||
        recoveryDeadlineEpochSeconds <= 0 ||
        !recoveryEmailPayloadHash ||
        !recoveryEmailSubject ||
        !recoveryEmailBody
      ) {
        throw new Error(
          'email-recovery/ecdsa/respond returned incomplete canonical recovery email data',
        );
      }
      const thresholdSession = isObject(thresholdSection.session) ? thresholdSection.session : null;
      if (!thresholdSession) {
        throw new Error(
          'email-recovery/ecdsa/respond did not return threshold session bootstrap data',
        );
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
        signerSlot,
        operationalPublicKey: thresholdPublicKey,
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
        signerSlot,
      });

      const { keyVersion: thresholdKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
        thresholdSection,
        'email-recovery bootstrap',
      );
      await storeThresholdEd25519KeyMaterial({
        nearAccountId,
        signerSlot,
        signerId: thresholdPublicKey,
        publicKey: thresholdPublicKey,
        relayerKeyId,
        keyVersion: thresholdKeyVersion,
        clientParticipantId: Number.isFinite(clientParticipantId)
          ? Math.floor(clientParticipantId)
          : null,
        relayerParticipantId: Number.isFinite(relayerParticipantId)
          ? Math.floor(relayerParticipantId)
          : null,
        relayerUrl,
        timestamp: Date.now(),
      });
      await hydrateThresholdWarmSessionFromRelay({
        context,
        nearAccountId,
        relayerUrl,
        rpId,
        relayerKeyId,
        credential,
        requestedPolicy: thresholdWarmPolicy,
        session: thresholdSession,
        participantIdsHint: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
      });
      await reconstructThresholdEd25519ClientBaseFromWarmSession({
        context,
        credential,
        nearAccountId,
        relayerUrl,
        relayerKeyId,
        session: thresholdSession,
        keyVersion: thresholdKeyVersion,
        participantIdsHint: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
      });
      await context.signingEngine.storeWalletEcdsaSignerRecords({
        walletId: walletIdFromString(String(nearAccountId)),
        walletKeys,
      });

      this.pendingEmailRecovery = {
        accountId: nearAccountId,
        signerSlot,
        requestId,
        recoverySessionId,
        nearPublicKey: thresholdPublicKey,
        newEvmOwnerAddress,
        deadlineEpochSeconds: Math.floor(recoveryDeadlineEpochSeconds),
        recoveryEmailPayloadHash,
        recoveryEmailSubject,
        recoveryEmailBody,
        credential,
        createdAt: Date.now(),
        status: 'awaiting-email',
      };
      if (this.pendingEmailRecovery) {
        await this.getPendingEmailRecoveryStore()?.set?.(this.pendingEmailRecovery);
      }

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_SENT,
        status: 'succeeded',
        interaction: { kind: 'email_recovery_link', overlay: 'hide' },
        data: {
          nearPublicKey: thresholdPublicKey,
          recoverySessionId,
          deadlineEpochSeconds: Math.floor(recoveryDeadlineEpochSeconds),
        },
      });

      const mailtoUrl = await this.buildEmailRecoveryMailtoUrl({
        recoveryEmailSubject,
        recoveryEmailBody,
      });

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_WAITING,
        status: 'waiting_for_user',
        interaction: { kind: 'email_recovery_link', overlay: 'hide' },
        data: {
          nearPublicKey: thresholdPublicKey,
          recoverySessionId,
          mailtoUrl,
        },
      });

      return { mailtoUrl, nearPublicKey: thresholdPublicKey };
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err || 'Unknown error'));
      this.emailRecoveryOptions?.onError?.(error);
      this.emitEmailRecoveryEvent({
        flowId: this.emailRecoveryFlowId(args.accountId),
        accountId: String(args.accountId),
        phase: EmailRecoveryFlowEventPhase.FAILED,
        status: 'failed',
        interaction: { kind: 'passkey_create', overlay: 'hide' },
        error: { message: error.message },
      });
      throw error;
    }
  }

  private async finalizeEmailRecoveryLocal(args: {
    accountId: string;
    nearPublicKey?: string;
  }): Promise<void> {
    let failureFlowId = this.emailRecoveryFlowId(args.accountId, args.nearPublicKey);
    let failureRequestId: string | undefined;
    try {
      const context = this.getContext();
      const accountId = toAccountId(args.accountId);
      const nearPublicKey = String(args.nearPublicKey || '').trim();
      const store = this.getPendingEmailRecoveryStore();
      const storedPending = await store?.get?.(accountId, nearPublicKey || undefined);
      const pending = storedPending || this.pendingEmailRecovery;
      this.pendingEmailRecovery = pending || null;
      const targetPk = String(nearPublicKey || pending?.nearPublicKey || '').trim();
      if (!targetPk) {
        throw new Error('Missing nearPublicKey to finalize email recovery');
      }
      const requestId = String(pending?.requestId || '').trim() || undefined;
      const flowId = this.emailRecoveryFlowId(String(accountId), requestId || targetPk);
      failureFlowId = flowId;
      failureRequestId = requestId;

      if (pending) {
        this.emitEmailRecoveryEvent({
          flowId,
          ...(requestId ? { requestId } : {}),
          accountId: String(accountId),
          phase: EmailRecoveryFlowEventPhase.STEP_00_RESUMED_PENDING,
          status: 'running',
          interaction: { kind: 'email_recovery_link', overlay: 'hide' },
          data: {
            nearPublicKey: targetPk,
            recoverySessionId: pending.recoverySessionId,
            pendingStatus: pending.status,
          },
        });
        await this.setPendingEmailRecoveryStatus(store, pending, 'awaiting-add-key');
      }

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(accountId),
        phase: EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_STARTED,
        status: 'running',
        data: { nearPublicKey: targetPk },
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

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(accountId),
        phase: EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_DETECTED,
        status: 'succeeded',
        data: { nearPublicKey: targetPk },
      });

      const signerSlot = coerceSignerSlot(pending?.signerSlot, {
        min: 1,
        fallback: 1,
      });
      if (pending) {
        await this.setPendingEmailRecoveryStatus(store, pending, 'finalizing');
      }
      await this.tryAutoLoginAfterRecovery({ accountId, signerSlot, flowId, requestId });

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(accountId),
        phase: EmailRecoveryFlowEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
      });

      if (pending?.nearPublicKey) {
        await this.setPendingEmailRecoveryStatus(store, pending, 'complete');
        await store?.clear?.(accountId, pending.nearPublicKey);
      }
      this.pendingEmailRecovery = null;
    } catch (err: unknown) {
      const message = errorMessage(err) || 'Email recovery finalize failed';
      const error = err instanceof Error ? err : new Error(message);
      await this.markPendingEmailRecoveryError(args.accountId, args.nearPublicKey).catch(() => {});
      this.emailRecoveryOptions?.onError?.(error);
      this.emitEmailRecoveryEvent({
        flowId: failureFlowId,
        ...(failureRequestId ? { requestId: failureRequestId } : {}),
        accountId: String(args.accountId),
        phase: EmailRecoveryFlowEventPhase.FAILED,
        status: 'failed',
        error: { message },
      });
      throw error;
    }
  }

  private async tryAutoLoginAfterRecovery(args: {
    accountId: string;
    signerSlot: number;
    flowId: string;
    requestId?: string;
  }): Promise<void> {
    const context = this.getContext();
    try {
      const nearAccountId = toAccountId(String(args.accountId));
      const signerSlot = coerceSignerSlot(args.signerSlot, {
        min: 1,
        fallback: 1,
      });

      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_STARTED,
        status: 'running',
      });

      const restored = await restoreLocalLoginState({
        context,
        nearAccountId,
        signerSlot,
      });
      if (!restored.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(nearAccountId)} as logged in`);
      }

      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(nearAccountId),
        phase: EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_SUCCEEDED,
        status: 'succeeded',
      });
    } catch (error: unknown) {
      const message = errorMessage(error) || 'Auto-login failed after email recovery';
      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(args.accountId),
        phase: EmailRecoveryFlowEventPhase.STEP_06_AUTO_UNLOCK_SKIPPED,
        status: 'skipped',
        data: { autoUnlockFailed: true, reason: message },
      });
    }
  }

  private async setPendingEmailRecoveryStatus(
    store: EmailRecoveryFlowOptions['pendingStore'],
    pending: PendingEmailRecovery,
    status: PendingEmailRecovery['status'],
  ): Promise<void> {
    const nextPending = { ...pending, status };
    this.pendingEmailRecovery = nextPending;
    await store?.set?.(nextPending);
  }

  private async markPendingEmailRecoveryError(
    accountIdInput: string,
    nearPublicKeyInput?: string,
  ): Promise<void> {
    const accountId = toAccountId(accountIdInput);
    const nearPublicKey = String(nearPublicKeyInput || '').trim();
    const store = this.getPendingEmailRecoveryStore();
    const pending =
      this.pendingEmailRecovery || (await store?.get?.(accountId, nearPublicKey || undefined));
    if (!pending) return;
    await this.setPendingEmailRecoveryStatus(store, pending, 'error');
  }

  private async cancelEmailRecoveryLocal(args?: {
    accountId?: string;
    nearPublicKey?: string;
  }): Promise<void> {
    this.emailRecoveryCancelled = true;
    this.pendingEmailRecovery = null;
    const accountIdForEvent = args?.accountId ? String(args.accountId) : undefined;
    this.emitEmailRecoveryEvent({
      flowId: this.emailRecoveryFlowId(accountIdForEvent, args?.nearPublicKey),
      ...(accountIdForEvent ? { accountId: accountIdForEvent } : {}),
      phase: EmailRecoveryFlowEventPhase.CANCELLED,
      status: 'cancelled',
      interaction: { kind: 'email_recovery_link', overlay: 'hide' },
    });
    try {
      const accountId = args?.accountId ? toAccountId(args.accountId) : null;
      if (accountId) {
        await this.getPendingEmailRecoveryStore()?.clear?.(accountId, args?.nearPublicKey);
      }
    } catch {}
  }
}

type EmailRecoveryEventPayload = {
  phase: EmailRecoveryFlowEventPhase;
  status: CreateEmailRecoveryFlowEventInput['status'];
  flowId: string;
  message?: string;
  error?: CreateEmailRecoveryFlowEventInput['error'];
  data?: Record<string, unknown>;
} & Omit<CreateEmailRecoveryFlowEventInput, 'phase' | 'status' | 'flowId' | 'message' | 'error' | 'data'>;
