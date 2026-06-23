import { toAccountId, type AccountId } from '@/core/types/accountIds';
import {
  createEmailRecoveryFlowEvent,
  EmailRecoveryFlowEventPhase,
} from '@/core/types/sdkSentEvents';
import type {
  CreateEmailRecoveryFlowEventInput,
  EmailRecoveryFlowEvent,
  SyncAccountHooksOptions,
} from '@/core/types/sdkSentEvents';
import type { ActionHooksOptions } from '@/core/types/sdkSentEvents';
import type { ActionResult } from '@/core/types/seams';
import type { EmailRecoveryFlowOptions, PendingEmailRecovery } from '@/core/types/emailRecovery';
import { generateEmailRecoveryRequestId } from '@/core/types/emailRecovery';
import {
  syncAccount as syncAccountCore,
  type SyncAccountResult,
} from '@/SeamsWeb/operations/recovery/syncAccount';
import type { EmailRecoveryWebContext } from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import { normalizeRegistrationCredential } from '@/core/signingEngine/webauthnAuth/credentials/helpers';
import { redactCredentialExtensionOutputs } from '@/core/signingEngine/webauthnAuth/credentials/credentialExtensions';
import { requirePasskeyPrfFirstB64u } from '@/SeamsWeb/operations/authMethods/passkey/ecdsaBootstrap';
import { EmailRecoveryPendingStore } from '@/utils/emailRecovery';
import { errorMessage } from '@shared/utils/errors';
import { coerceSignerSlot } from '@shared/utils/signerSlot';
import { isObject } from '@shared/utils/validation';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { prepareRecoveryEmails, getLocalRecoveryEmails } from '@/utils/emailRecovery';
import { restoreLocalLoginState } from '@/SeamsWeb/operations/session/restoreLocalLoginState';
import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import {
  ed25519KeyScopeIdFromString,
  walletIdFromString,
  type Ed25519KeyScopeId,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  buildThresholdWarmSessionRequestEnvelope,
  createThresholdWarmSessionPolicyDraft,
  hydrateThresholdWarmSessionFromRelay,
  requireThresholdEd25519WarmSessionKeyVersion,
  reconstructThresholdEd25519SigningMaterialFromWarmSession,
  storeThresholdEd25519KeyMaterial,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { formatEd25519HssKeyVersionForWire } from '@/core/signingEngine/session/keyMaterialBrands';
import { listThresholdEcdsaProvisionTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  assertSameRecoveryResolvedWalletBinding,
  parseRecoveryResolvedWalletBindingFromResponse,
} from './recoveryWalletBinding';

/**
 * SeamsWeb email recovery call graph:
 * - syncAccount -> wallet iframe router sync path OR local syncAccount flow
 * - email recovery start/finalize/cancel -> wallet iframe router OR local recovery domain flow
 */
export type EmailRecoveryDomainDeps = {
  getContext: () => EmailRecoveryWebContext;
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

function requireEmailRecoveryRuntimePolicyScope(value: unknown) {
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(value);
  if (!runtimePolicyScope) {
    throw new Error('email-recovery ECDSA response missing runtimePolicyScope');
  }
  return runtimePolicyScope;
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
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    )
  ) {
    throw new Error('email-recovery/prepare returned invalid ECDSA participant ids');
  }
  const runtimePolicyScope = requireEmailRecoveryRuntimePolicyScope(value.runtimePolicyScope);
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
  return {
    formatVersion: 'ecdsa-hss-role-local',
    walletId: requireEmailRecoveryString(value.walletId, 'walletId'),
    rpId: requireEmailRecoveryString(value.rpId, 'rpId'),
    ecdsaThresholdKeyId: requireEmailRecoveryString(
      value.ecdsaThresholdKeyId,
      'ecdsaThresholdKeyId',
    ),
    signingRootId: signingRootScope.signingRootId,
    signingRootVersion:
      signingRootScope.signingRootVersion || runtimePolicyScope.signingRootVersion,
    keyScope: 'evm-family',
    relayerKeyId: requireEmailRecoveryString(value.relayerKeyId, 'relayerKeyId'),
    requestId: requireEmailRecoveryString(value.requestId, 'requestId'),
    thresholdSessionId: requireEmailRecoveryString(value.thresholdSessionId, 'thresholdSessionId'),
    signingGrantId: requireEmailRecoveryString(value.signingGrantId, 'signingGrantId'),
    ttlMs: coercePositiveInt(value.ttlMs, 1),
    remainingUses: coercePositiveInt(value.remainingUses, 1),
    participantIds,
    runtimePolicyScope,
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
      participantIds.some(
        (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
      )
    ) {
      throw new Error('email-recovery/ecdsa/respond returned invalid wallet key participant ids');
    }
    return {
      keyScope: 'evm-family',
      chainTarget,
      walletId: requireEmailRecoveryString(raw.walletId, 'walletId'),
      rpId: requireEmailRecoveryString(raw.rpId, 'rpId'),
      keyHandle: requireEmailRecoveryString(raw.keyHandle, 'keyHandle'),
      ecdsaThresholdKeyId: requireEmailRecoveryString(
        raw.ecdsaThresholdKeyId,
        'ecdsaThresholdKeyId',
      ),
      signingRootId: requireEmailRecoveryString(raw.signingRootId, 'signingRootId'),
      signingRootVersion: requireEmailRecoveryString(raw.signingRootVersion, 'signingRootVersion'),
      thresholdEcdsaPublicKeyB64u: requireEmailRecoveryString(
        raw.thresholdEcdsaPublicKeyB64u,
        'thresholdEcdsaPublicKeyB64u',
      ),
      thresholdOwnerAddress: requireEmailRecoveryString(
        raw.thresholdOwnerAddress,
        'thresholdOwnerAddress',
      ),
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
  private readonly getContext: () => EmailRecoveryWebContext;
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

  async getRecoveryEmails(walletIdInput: string): Promise<Array<{ hashHex: string; email: string }>> {
    const walletId = walletIdFromString(walletIdInput);

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      return await router.getRecoveryEmails(String(walletId));
    }

    const records = await getLocalRecoveryEmails(walletId);
    return records.map((entry) => ({
      hashHex: entry.hashHex,
      email: entry.email || entry.hashHex,
    }));
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
      const actionResult: ActionResult = { success: false, error: message };
      await args.options?.onError?.(new Error(message));
      await args.options?.afterCall?.(false);
      return actionResult;
    }
  }

  async syncAccount(args: {
    walletId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult> {
    const walletId = args?.walletId ? walletIdFromString(args.walletId) : null;

    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args?.walletId);
      // Router support is wired in the wallet origin; keep app-origin thin.
      return await router.syncAccount({
        ...(walletId ? { walletId: String(walletId) } : {}),
        onEvent: args?.options?.onEvent,
      });
    }

    return await syncAccountCore(this.getContext(), walletId ? String(walletId) : null, args?.options);
  }

  async startEmailRecovery(args: {
    walletId: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    const walletId = walletIdFromString(args.walletId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      return await router.startEmailRecovery({
        walletId: String(walletId),
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
    return await this.startEmailRecoveryLocal({ walletId: String(walletId) });
  }

  async finalizeEmailRecovery(args: {
    walletId: string;
    nearPublicKey?: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<void> {
    const walletId = walletIdFromString(args.walletId);
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(String(walletId));
      await router.finalizeEmailRecovery({
        walletId: String(walletId),
        nearPublicKey: args.nearPublicKey,
        onEvent: args.options?.onEvent,
      });
      return;
    }

    this.emailRecoveryOptions = args.options;
    await this.finalizeEmailRecoveryLocal({
      walletId: String(walletId),
      nearPublicKey: args.nearPublicKey,
    });
  }

  async cancelEmailRecovery(args?: { walletId?: string; nearPublicKey?: string }): Promise<void> {
    if (this.walletIframe.shouldUseWalletIframe()) {
      const router = await this.walletIframe.requireRouter(args?.walletId);
      await router.stopEmailRecovery({
        ...(args?.walletId ? { walletId: String(args.walletId) } : {}),
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
    walletId: string;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }> {
    try {
      const context = this.getContext();
      const walletId = walletIdFromString(args.walletId);
      const relayerUrl = String(context.configs?.network?.relayer?.url || '').trim();
      if (!relayerUrl) throw new Error('Missing relayer url (configs.network.relayer.url)');

      const rpId = context.signingEngine.getRpId();
      if (!rpId) throw new Error('Missing rpId for email recovery flow');

      const requestId = generateEmailRecoveryRequestId();
      const initialSignerSlot = 1;
      const flowId = this.emailRecoveryFlowId(String(walletId), requestId);

      this.emailRecoveryCancelled = false;

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_01_STARTED,
        status: 'started',
      });

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_STARTED,
        status: 'waiting_for_user',
        interaction: { kind: 'passkey_create', overlay: 'show' },
      });

      const registrationSession =
        await context.signingEngine.requestRegistrationCredentialConfirmation({
          walletId: String(walletId),
          signerSlot: initialSignerSlot,
          confirmerText: this.emailRecoveryOptions?.confirmerText,
          confirmationConfigOverride: this.emailRecoveryOptions?.confirmationConfig,
        });

      const credential = registrationSession.credential;

      this.emitEmailRecoveryEvent({
        flowId,
        requestId,
        accountId: String(walletId),
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

      const thresholdWarmPolicy = createThresholdWarmSessionPolicyDraft(context, {
        kind: 'generated_signing_grant',
      });
      if (!thresholdWarmPolicy) {
        throw new Error('Threshold warm-session defaults are disabled for email recovery');
      }
      const thresholdWarmSessionRequest = buildThresholdWarmSessionRequestEnvelope({
        walletId: String(walletId),
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
      const primaryEcdsaProvisionTarget = ecdsaProvisionTargets[0];
      if (!primaryEcdsaProvisionTarget) {
        throw new Error('Email recovery requires an ECDSA provision target');
      }
      const passkeyPrfFirstB64u = requirePasskeyPrfFirstB64u(
        credential,
        'Email recovery ECDSA bootstrap',
      );
      const credentialForRelay = redactCredentialExtensionOutputs(
        normalizeRegistrationCredential(credential),
      );
      const prepareResp = await fetch(joinNormalizedUrl(relayerUrl, '/email-recovery/prepare'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          account_id: String(walletId),
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
      const preparedWalletBinding = parseRecoveryResolvedWalletBindingFromResponse(
        prepareObj as Record<string, unknown>,
        'email-recovery/prepare',
      );
      if (String(preparedWalletBinding.walletId) !== String(walletId)) {
        throw new Error('email-recovery/prepare returned a wallet binding for a different wallet');
      }

      const prepareEcdsaSection = isObject(prepareObj.ecdsa) ? prepareObj.ecdsa : null;
      const ecdsaPrepare = prepareEcdsaSection
        ? parseEmailRecoveryEcdsaPrepare(prepareEcdsaSection.prepare)
        : null;
      if (!ecdsaPrepare) {
        throw new Error('email-recovery/prepare did not return ECDSA prepare data');
      }
      const preparedClientBootstrap = await context.signingEngine.preparePasskeyEcdsaBootstrap({
        prepare: ecdsaPrepare,
        chainTarget: primaryEcdsaProvisionTarget.chainTarget,
        passkeyPrfFirstB64u,
        credentialIdB64u: String(credential.rawId || credential.id || '').trim(),
      });
      const clientBootstrap: WalletRegistrationEcdsaClientBootstrap =
        preparedClientBootstrap.clientBootstrap;
      const ecdsaResp = await fetch(
        joinNormalizedUrl(relayerUrl, '/email-recovery/ecdsa/respond'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            request_id: requestId,
            client_bootstrap: clientBootstrap,
          }),
        },
      );
      const ecdsaJson: unknown = await ecdsaResp.json().catch(() => ({}));
      const ecdsaObj = isObject(ecdsaJson) ? ecdsaJson : {};
      if (!ecdsaResp.ok || ecdsaObj.ok !== true) {
        throw new Error(
          String(ecdsaObj.message || ecdsaObj.error || '') ||
            `email-recovery/ecdsa/respond failed (HTTP ${ecdsaResp.status})`,
        );
      }
      const recoveredWalletBinding = parseRecoveryResolvedWalletBindingFromResponse(
        ecdsaObj as Record<string, unknown>,
        'email-recovery/ecdsa/respond',
      );
      assertSameRecoveryResolvedWalletBinding(
        preparedWalletBinding,
        recoveredWalletBinding,
        'email-recovery/ecdsa/respond',
      );

      const thresholdSection = isObject(ecdsaObj.thresholdEd25519) ? ecdsaObj.thresholdEd25519 : {};
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
        nearAccountId: recoveredWalletBinding.nearAccountId,
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
        nearAccountId: recoveredWalletBinding.nearAccountId,
        credentialId,
        credentialPublicKey,
        transports: Array.isArray(credential.response?.transports)
          ? credential.response.transports
          : [],
        name: `Passkey for ${String(recoveredWalletBinding.walletId)}`,
        registered: new Date().toISOString(),
        syncedAt: new Date().toISOString(),
        signerSlot,
      });

      const { ed25519HssKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
        thresholdSection,
        'email-recovery bootstrap',
      );
      const thresholdKeyVersion = formatEd25519HssKeyVersionForWire(ed25519HssKeyVersion);
      const thresholdKeyMaterialCreatedAtMs = Date.now();
      await storeThresholdEd25519KeyMaterial({
        nearAccountId: recoveredWalletBinding.nearAccountId,
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
        timestamp: thresholdKeyMaterialCreatedAtMs,
      });
      await hydrateThresholdWarmSessionFromRelay({
        context,
        walletId: String(recoveredWalletBinding.walletId),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        ed25519KeyScopeId: String(recoveredWalletBinding.ed25519KeyScopeId),
        relayerUrl,
        rpId,
        relayerKeyId,
        credential,
        signerSlot,
        requestedPolicy: thresholdWarmPolicy,
        session: thresholdSession,
        participantIdsHint: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
      });
      await reconstructThresholdEd25519SigningMaterialFromWarmSession({
        context,
        credential,
        walletId: String(recoveredWalletBinding.walletId),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        ed25519KeyScopeId: recoveredWalletBinding.ed25519KeyScopeId,
        rpId,
        relayerUrl,
        relayerKeyId,
        session: thresholdSession,
        ed25519HssKeyVersion,
        signerSlot,
        materialCreatedAtMs: thresholdKeyMaterialCreatedAtMs,
        participantIdsHint: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
      });
      await context.signingEngine.storeWalletEcdsaSignerRecords({
        walletId: recoveredWalletBinding.walletId,
        walletKeys,
      });

      this.pendingEmailRecovery = {
        accountId: String(recoveredWalletBinding.walletId),
        walletId: String(recoveredWalletBinding.walletId),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        ed25519KeyScopeId: String(recoveredWalletBinding.ed25519KeyScopeId),
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
        accountId: String(recoveredWalletBinding.walletId),
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
        accountId: String(recoveredWalletBinding.walletId),
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
        flowId: this.emailRecoveryFlowId(args.walletId),
        accountId: String(args.walletId),
        phase: EmailRecoveryFlowEventPhase.FAILED,
        status: 'failed',
        interaction: { kind: 'passkey_create', overlay: 'hide' },
        error: { message: error.message },
      });
      throw error;
    }
  }

  private async finalizeEmailRecoveryLocal(args: {
    walletId: string;
    nearPublicKey?: string;
  }): Promise<void> {
    let failureFlowId = this.emailRecoveryFlowId(args.walletId, args.nearPublicKey);
    let failureRequestId: string | undefined;
    try {
      const context = this.getContext();
      const walletId = walletIdFromString(args.walletId);
      const nearPublicKey = String(args.nearPublicKey || '').trim();
      const store = this.getPendingEmailRecoveryStore();
      const storedPending = await store?.get?.(String(walletId), nearPublicKey || undefined);
      const memoryPending =
        this.pendingEmailRecovery?.walletId === String(walletId) ? this.pendingEmailRecovery : null;
      const pending = storedPending || memoryPending;
      this.pendingEmailRecovery = pending || null;
      if (!pending) {
        throw new Error(`Missing pending email recovery for wallet ${String(walletId)}`);
      }
      const nearAccountId = pending.nearAccountId;
      const targetPk = String(nearPublicKey || pending?.nearPublicKey || '').trim();
      if (!targetPk) {
        throw new Error('Missing nearPublicKey to finalize email recovery');
      }
      const requestId = String(pending?.requestId || '').trim() || undefined;
      const flowId = this.emailRecoveryFlowId(String(walletId), requestId || targetPk);
      failureFlowId = flowId;
      failureRequestId = requestId;

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(walletId),
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

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(walletId),
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
        const list = await context.nearClient.viewAccessKeyList(String(nearAccountId));
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
        accountId: String(walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_DETECTED,
        status: 'succeeded',
        data: { nearPublicKey: targetPk },
      });

      const signerSlot = coerceSignerSlot(pending?.signerSlot, {
        min: 1,
        fallback: 1,
      });
      await this.setPendingEmailRecoveryStatus(store, pending, 'finalizing');
      await this.tryAutoLoginAfterRecovery({
        walletId,
        nearAccountId,
        ed25519KeyScopeId: ed25519KeyScopeIdFromString(String(pending.ed25519KeyScopeId)),
        signerSlot,
        flowId,
        requestId,
      });

      this.emitEmailRecoveryEvent({
        flowId,
        ...(requestId ? { requestId } : {}),
        accountId: String(walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_07_COMPLETED,
        status: 'succeeded',
      });

      if (pending?.nearPublicKey) {
        await this.setPendingEmailRecoveryStatus(store, pending, 'complete');
        await store?.clear?.(String(walletId), pending.nearPublicKey);
      }
      this.pendingEmailRecovery = null;
    } catch (err: unknown) {
      const message = errorMessage(err) || 'Email recovery finalize failed';
      const error = err instanceof Error ? err : new Error(message);
      await this.markPendingEmailRecoveryError(args.walletId, args.nearPublicKey).catch(() => {});
      this.emailRecoveryOptions?.onError?.(error);
      this.emitEmailRecoveryEvent({
        flowId: failureFlowId,
        ...(failureRequestId ? { requestId: failureRequestId } : {}),
        accountId: String(args.walletId),
        phase: EmailRecoveryFlowEventPhase.FAILED,
        status: 'failed',
        error: { message },
      });
      throw error;
    }
  }

  private async tryAutoLoginAfterRecovery(args: {
    walletId: WalletId;
    nearAccountId: AccountId;
    ed25519KeyScopeId: Ed25519KeyScopeId;
    signerSlot: number;
    flowId: string;
    requestId?: string;
  }): Promise<void> {
    const context = this.getContext();
    try {
      const signerSlot = coerceSignerSlot(args.signerSlot, {
        min: 1,
        fallback: 1,
      });

      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(args.walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_STARTED,
        status: 'running',
      });

      const restored = await restoreLocalLoginState({
        context,
        walletId: args.walletId,
        nearAccountId: args.nearAccountId,
        ed25519KeyScopeId: args.ed25519KeyScopeId,
        signerSlot,
      });
      if (!restored.isLoggedIn) {
        throw new Error(`Auto-login did not mark ${String(args.nearAccountId)} as logged in`);
      }

      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(args.walletId),
        phase: EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_SUCCEEDED,
        status: 'succeeded',
      });
    } catch (error: unknown) {
      const message = errorMessage(error) || 'Auto-login failed after email recovery';
      this.emitEmailRecoveryEvent({
        flowId: args.flowId,
        ...(args.requestId ? { requestId: args.requestId } : {}),
        accountId: String(args.walletId),
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
    walletIdInput: string,
    nearPublicKeyInput?: string,
  ): Promise<void> {
    const walletId = String(walletIdFromString(walletIdInput));
    const nearPublicKey = String(nearPublicKeyInput || '').trim();
    const store = this.getPendingEmailRecoveryStore();
    const pending =
      this.pendingEmailRecovery || (await store?.get?.(walletId, nearPublicKey || undefined));
    if (!pending) return;
    await this.setPendingEmailRecoveryStatus(store, pending, 'error');
  }

  private async cancelEmailRecoveryLocal(args?: {
    walletId?: string;
    nearPublicKey?: string;
  }): Promise<void> {
    this.emailRecoveryCancelled = true;
    this.pendingEmailRecovery = null;
    const walletIdForEvent = args?.walletId ? String(args.walletId) : undefined;
    this.emitEmailRecoveryEvent({
      flowId: this.emailRecoveryFlowId(walletIdForEvent, args?.nearPublicKey),
      ...(walletIdForEvent ? { accountId: walletIdForEvent } : {}),
      phase: EmailRecoveryFlowEventPhase.CANCELLED,
      status: 'cancelled',
      interaction: { kind: 'email_recovery_link', overlay: 'hide' },
    });
    try {
      const walletId = args?.walletId ? String(walletIdFromString(args.walletId)) : null;
      if (walletId) {
        await this.getPendingEmailRecoveryStore()?.clear?.(walletId, args?.nearPublicKey);
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
} & Omit<
  CreateEmailRecoveryFlowEventInput,
  'phase' | 'status' | 'flowId' | 'message' | 'error' | 'data'
>;
