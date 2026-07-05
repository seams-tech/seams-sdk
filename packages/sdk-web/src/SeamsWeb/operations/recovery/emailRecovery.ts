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
import { base64UrlDecode } from '@shared/utils/base64';
import { coerceSignerSlot, parseSignerSlot } from '@shared/utils/signerSlot';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { isObject } from '@shared/utils/validation';
import { joinNormalizedUrl } from '@shared/utils/normalize';
import { prepareRecoveryEmails, getLocalRecoveryEmails } from '@/utils/emailRecovery';
import { restoreLocalLoginState } from '@/SeamsWeb/operations/session/restoreLocalLoginState';
import { THRESHOLD_SECP256K1_ECDSA_2P_PARTICIPANTS_V1 } from '@shared/threshold/secp256k1';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
  type NearEd25519SigningKeyId,
  type WalletId,
} from '@shared/utils/registrationIntent';
import {
  buildThresholdWarmSessionRequestEnvelope,
  buildThresholdEd25519RegistrationHssClientOwnedArtifact,
  createThresholdWarmSessionPolicyDraft,
  prepareThresholdEd25519RegistrationHssClientMaterialFromCanonicalContext,
  prepareThresholdEd25519RegistrationHssClientRequest,
  persistRegisteredThresholdEd25519Session,
  requireThresholdEd25519WarmSessionKeyVersion,
  type CompletedThresholdEd25519Registration,
  type ThresholdEd25519FinalizedRegistrationHssMaterial,
  type ThresholdEd25519RegistrationHssClientMaterial,
  type ThresholdEd25519RegistrationHssClientMaterialCore,
  type WalletRegistrationThresholdEd25519Response,
} from '@/SeamsWeb/operations/session/thresholdWarmSessionBootstrap';
import { formatEd25519HssKeyVersionForWire } from '@/core/signingEngine/session/keyMaterialBrands';
import { listThresholdEcdsaProvisionTargets } from '@/SeamsWeb/operations/session/thresholdEcdsaProvisioning';
import { normalizeThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type {
  ThresholdEd25519RegistrationWorkerMaterialReport,
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPrepareContext,
  WalletRegistrationEcdsaWalletKey,
} from '@/core/rpcClients/relayer/walletRegistration';
import {
  thresholdEcdsaChainTargetFromRequest,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { retireRecoveredPasskeyThresholdEd25519Sessions } from '@/core/signingEngine/session/persistence/records';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';
import {
  assertSameRecoveryResolvedWalletBinding,
  parseRecoveryResolvedWalletBindingFromResponse,
} from './recoveryWalletBinding';
import type {
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssServerInputDeliveryEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';

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

function requireEmailRecoveryWebAuthnRpId(value: unknown): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

type EmailRecoveryPasskeyCredential = {
  readonly id?: unknown;
  readonly rawId?: unknown;
};

function buildEmailRecoveryPasskeyAuthority(args: {
  walletId: WalletId | string;
  rpId: WebAuthnRpId;
  credential: EmailRecoveryPasskeyCredential;
}) {
  return buildPasskeyWalletAuthAuthority({
    walletId: args.walletId,
    rpId: args.rpId,
    credentialIdB64u: String(args.credential.rawId || args.credential.id || '').trim(),
  });
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
    evmFamilySigningKeySlotId: requireEmailRecoveryString(value.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
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

type EmailRecoveryEcdsaPrepareTarget = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly prepare: WalletRegistrationEcdsaPrepareContext;
};

type EmailRecoveryEd25519HssPrepare = {
  readonly ceremonyHandle: string;
  readonly preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  readonly clientOtOfferMessageB64u: string;
  readonly context: ThresholdEd25519HssCanonicalContext;
};

function parseEmailRecoveryEd25519HssContext(value: unknown): ThresholdEd25519HssCanonicalContext {
  if (!isObject(value)) {
    throw new Error('email-recovery/prepare returned invalid Ed25519 HSS context');
  }
  const applicationBindingDigestB64u = requireEmailRecoveryString(
    value.applicationBindingDigestB64u,
    'thresholdEd25519.hss.context.applicationBindingDigestB64u',
  );
  const participantIds = Array.isArray(value.participantIds)
    ? value.participantIds.map((participantId) => Number(participantId))
    : [];
  if (
    participantIds.length === 0 ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    )
  ) {
    throw new Error('email-recovery/prepare returned invalid Ed25519 HSS participant ids');
  }
  return { applicationBindingDigestB64u, participantIds };
}

function parseEmailRecoveryEd25519HssPreparedSession(
  value: unknown,
): ThresholdEd25519HssPreparedSessionEnvelope {
  if (!isObject(value)) {
    throw new Error('email-recovery/prepare returned invalid Ed25519 HSS prepared session');
  }
  return {
    contextBindingB64u: requireEmailRecoveryString(
      value.contextBindingB64u,
      'thresholdEd25519.hss.preparedSession.contextBindingB64u',
    ),
    evaluatorDriverStateB64u: requireEmailRecoveryString(
      value.evaluatorDriverStateB64u,
      'thresholdEd25519.hss.preparedSession.evaluatorDriverStateB64u',
    ),
  };
}

function parseEmailRecoveryEd25519HssPrepare(value: unknown): EmailRecoveryEd25519HssPrepare {
  if (!isObject(value)) {
    throw new Error('email-recovery/prepare returned no Ed25519 HSS material');
  }
  return {
    ceremonyHandle: requireEmailRecoveryString(
      value.ceremonyHandle,
      'thresholdEd25519.hss.ceremonyHandle',
    ),
    preparedSession: parseEmailRecoveryEd25519HssPreparedSession(value.preparedSession),
    clientOtOfferMessageB64u: requireEmailRecoveryString(
      value.clientOtOfferMessageB64u,
      'thresholdEd25519.hss.clientOtOfferMessageB64u',
    ),
    context: parseEmailRecoveryEd25519HssContext(value.context),
  };
}

function parseEmailRecoveryEd25519HssServerInputDelivery(
  value: unknown,
): ThresholdEd25519HssServerInputDeliveryEnvelope {
  if (!isObject(value)) {
    throw new Error('email-recovery/ed25519/respond returned no Ed25519 HSS server input');
  }
  return {
    contextBindingB64u: requireEmailRecoveryString(
      value.contextBindingB64u,
      'thresholdEd25519.hss.contextBindingB64u',
    ),
    serverInputDeliveryB64u: requireEmailRecoveryString(
      value.serverInputDeliveryB64u,
      'thresholdEd25519.hss.serverInputDeliveryB64u',
    ),
  };
}

function parseEmailRecoveryRegistrationWorkerMaterialReport(
  value: unknown,
): ThresholdEd25519RegistrationWorkerMaterialReport {
  if (!isObject(value)) {
    throw new Error('email-recovery/ed25519/finalize returned no worker material report');
  }
  const report: ThresholdEd25519RegistrationWorkerMaterialReport = {
    kind: 'threshold_ed25519_registration_worker_material_report_v1',
    contextBindingB64u: requireEmailRecoveryString(
      value.contextBindingB64u,
      'thresholdEd25519.registrationWorkerMaterialReport.contextBindingB64u',
    ),
    clientOutputMessageB64u: requireEmailRecoveryString(
      value.clientOutputMessageB64u,
      'thresholdEd25519.registrationWorkerMaterialReport.clientOutputMessageB64u',
    ),
  };
  if (value.kind !== report.kind || value.seedOutputMessageB64u !== undefined) {
    throw new Error('email-recovery/ed25519/finalize returned invalid worker material report');
  }
  return report;
}

function parseEmailRecoveryThresholdEd25519Session(
  value: unknown,
): NonNullable<WalletRegistrationThresholdEd25519Response['session']> {
  if (!isObject(value)) {
    throw new Error('email-recovery/ecdsa/respond did not return threshold session bootstrap data');
  }
  const sessionKind = requireEmailRecoveryString(
    value.sessionKind,
    'thresholdEd25519.session.sessionKind',
  );
  if (sessionKind !== 'jwt' && sessionKind !== 'cookie') {
    throw new Error('email-recovery/ecdsa/respond returned invalid threshold session kind');
  }
  const session: NonNullable<WalletRegistrationThresholdEd25519Response['session']> = {
    sessionKind,
    walletId: requireEmailRecoveryString(value.walletId, 'thresholdEd25519.session.walletId'),
    nearAccountId: requireEmailRecoveryString(
      value.nearAccountId,
      'thresholdEd25519.session.nearAccountId',
    ),
    nearEd25519SigningKeyId: requireEmailRecoveryString(
      value.nearEd25519SigningKeyId,
      'thresholdEd25519.session.nearEd25519SigningKeyId',
    ),
    thresholdSessionId: requireEmailRecoveryString(
      value.thresholdSessionId,
      'thresholdEd25519.session.thresholdSessionId',
    ),
    signingGrantId: requireEmailRecoveryString(
      value.signingGrantId,
      'thresholdEd25519.session.signingGrantId',
    ),
    expiresAtMs: Number(value.expiresAtMs),
  };
  if (!Number.isFinite(session.expiresAtMs) || session.expiresAtMs <= 0) {
    throw new Error('email-recovery/ecdsa/respond returned invalid threshold session expiry');
  }
  if (typeof value.expiresAt === 'string' && value.expiresAt.trim()) {
    session.expiresAt = value.expiresAt.trim();
  }
  if (Array.isArray(value.participantIds)) {
    session.participantIds = value.participantIds.map((participantId) => Number(participantId));
  }
  const remainingUses = Number(value.remainingUses);
  if (Number.isFinite(remainingUses)) {
    session.remainingUses = Math.floor(remainingUses);
  }
  if (Object.prototype.hasOwnProperty.call(value, 'runtimePolicyScope')) {
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(value.runtimePolicyScope);
    if (!runtimePolicyScope) {
      throw new Error('email-recovery/ecdsa/respond returned invalid session runtimePolicyScope');
    }
    session.runtimePolicyScope = runtimePolicyScope;
  }
  if (Object.prototype.hasOwnProperty.call(value, 'routerAbNormalSigning')) {
    const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
      value.routerAbNormalSigning,
    );
    if (!routerAbNormalSigning) {
      throw new Error('email-recovery/ecdsa/respond returned invalid Router A/B signing state');
    }
    session.routerAbNormalSigning = routerAbNormalSigning;
  }
  if (typeof value.jwt === 'string' && value.jwt.trim()) {
    session.jwt = value.jwt.trim();
  }
  return session;
}

function buildEmailRecoveryFinalizedRegistrationHssMaterial(args: {
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  ceremonyHandle: string;
  report: ThresholdEd25519RegistrationWorkerMaterialReport;
}): ThresholdEd25519FinalizedRegistrationHssMaterial {
  const ceremonyHandle = requireEmailRecoveryString(args.ceremonyHandle, 'ed25519 ceremonyHandle');
  if (args.report.contextBindingB64u !== args.preparedSession.contextBindingB64u) {
    throw new Error('email-recovery worker material report context mismatch');
  }
  return {
    preparedSession: args.preparedSession,
    clientOutputMaskRelayerKeyId: `registration:${ceremonyHandle}`,
    workerMaterialReport: args.report,
  };
}

function buildEmailRecoveryRegistrationHssClientMaterial(args: {
  material: ThresholdEd25519RegistrationHssClientMaterialCore;
  runtimePolicyScope: ReturnType<typeof requireEmailRecoveryRuntimePolicyScope>;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
}): ThresholdEd25519RegistrationHssClientMaterial {
  const signingRootScope = signingRootScopeFromRuntimePolicyScope(args.runtimePolicyScope);
  return {
    ...args.material,
    bindingFacts: {
      nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
      signingRootId: parseSdkEcdsaHssSigningRootId(signingRootScope.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(
        signingRootScope.signingRootVersion,
      ),
    },
  };
}

function buildEmailRecoveryCompletedThresholdEd25519Registration(args: {
  thresholdSection: Record<string, unknown>;
  nearAccountId: AccountId;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  session: NonNullable<WalletRegistrationThresholdEd25519Response['session']>;
  report: ThresholdEd25519RegistrationWorkerMaterialReport;
}): CompletedThresholdEd25519Registration {
  const registered: WalletRegistrationThresholdEd25519Response = {
    nearAccountId: args.nearAccountId,
    nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
    publicKey: args.publicKey,
    relayerKeyId: args.relayerKeyId,
    keyVersion: args.keyVersion,
    recoveryExportCapable: true,
    registrationWorkerMaterialReport: args.report,
    session: args.session,
  };
  const clientParticipantId = Number(args.thresholdSection.clientParticipantId);
  if (Number.isFinite(clientParticipantId)) {
    registered.clientParticipantId = Math.floor(clientParticipantId);
  }
  const relayerParticipantId = Number(args.thresholdSection.relayerParticipantId);
  if (Number.isFinite(relayerParticipantId)) {
    registered.relayerParticipantId = Math.floor(relayerParticipantId);
  }
  if (Array.isArray(args.thresholdSection.participantIds)) {
    registered.participantIds = args.thresholdSection.participantIds.map((participantId) =>
      Number(participantId),
    );
  }
  return {
    registered,
    operationalPublicKey: args.publicKey,
  };
}

function parseEmailRecoveryEcdsaPrepareTargets(value: unknown): EmailRecoveryEcdsaPrepareTarget[] {
  if (!isObject(value) || value.kind !== 'evm_family_ecdsa_keygen' || !Array.isArray(value.targets)) {
    throw new Error('email-recovery/prepare returned invalid ECDSA prepare data');
  }
  if (value.targets.length === 0) {
    throw new Error('email-recovery/prepare returned no ECDSA prepare targets');
  }
  return value.targets.map((target) => {
    if (!isObject(target)) {
      throw new Error('email-recovery/prepare returned invalid ECDSA prepare target');
    }
    if (!isObject(target.chainTarget)) {
      throw new Error('email-recovery/prepare returned ECDSA target without chain target');
    }
    return {
      chainTarget: thresholdEcdsaChainTargetFromRequest(target.chainTarget),
      prepare: parseEmailRecoveryEcdsaPrepare(target.prepare),
    };
  });
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
      evmFamilySigningKeySlotId: requireEmailRecoveryString(raw.evmFamilySigningKeySlotId, 'evmFamilySigningKeySlotId'),
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

      const rpIdRaw = context.signingEngine.getRpId();
      if (!rpIdRaw) throw new Error('Missing rpId for email recovery flow');
      const rpId = requireEmailRecoveryWebAuthnRpId(rpIdRaw);

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
        authority: buildEmailRecoveryPasskeyAuthority({
          walletId,
          rpId,
          credential,
        }),
        requestedPolicy: thresholdWarmPolicy,
      });
      const ecdsaProvisionTargets = listThresholdEcdsaProvisionTargets({
        signerOptions: context.configs.signing.thresholdEcdsa.provisioningDefaults,
        chains: context.configs.network.chains,
      });
      if (ecdsaProvisionTargets.length === 0) {
        throw new Error('Email recovery requires at least one configured ECDSA provision target');
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
      const ecdsaPrepareTargets = prepareEcdsaSection
        ? parseEmailRecoveryEcdsaPrepareTargets(prepareEcdsaSection)
        : [];
      if (ecdsaPrepareTargets.length === 0) {
        throw new Error('email-recovery/prepare did not return ECDSA prepare data');
      }

      const prepareThresholdSection = isObject(prepareObj.thresholdEd25519)
        ? prepareObj.thresholdEd25519
        : {};
      const preparedEd25519Hss = parseEmailRecoveryEd25519HssPrepare(
        prepareThresholdSection.hss,
      );
      const ed25519RuntimePolicyScope = requireEmailRecoveryRuntimePolicyScope(
        ecdsaPrepareTargets[0].prepare.runtimePolicyScope,
      );
      const ed25519HssCoreMaterial =
        await prepareThresholdEd25519RegistrationHssClientMaterialFromCanonicalContext({
          context,
          credential,
          hssContext: preparedEd25519Hss.context,
        });
      const ed25519HssMaterial = buildEmailRecoveryRegistrationHssClientMaterial({
        material: ed25519HssCoreMaterial,
        runtimePolicyScope: ed25519RuntimePolicyScope,
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          String(preparedWalletBinding.nearEd25519SigningKeyId),
        ),
      });
      const { clientRequest: ed25519ClientRequest, clientOutputMaskHandle } =
        await prepareThresholdEd25519RegistrationHssClientRequest({
          context,
          material: ed25519HssMaterial,
          preparedSession: preparedEd25519Hss.preparedSession,
          clientOtOfferMessageB64u: preparedEd25519Hss.clientOtOfferMessageB64u,
          ceremonyHandle: preparedEd25519Hss.ceremonyHandle,
        });
      const ed25519RespondResp = await fetch(
        joinNormalizedUrl(relayerUrl, '/email-recovery/ed25519/respond'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            request_id: requestId,
            client_request: {
              clientRequestMessageB64u: ed25519ClientRequest.clientRequestMessageB64u,
            },
          }),
        },
      );
      const ed25519RespondJson: unknown = await ed25519RespondResp.json().catch(() => ({}));
      const ed25519RespondObj = isObject(ed25519RespondJson) ? ed25519RespondJson : {};
      if (!ed25519RespondResp.ok || ed25519RespondObj.ok !== true) {
        throw new Error(
          String(ed25519RespondObj.message || ed25519RespondObj.error || '') ||
            `email-recovery/ed25519/respond failed (HTTP ${ed25519RespondResp.status})`,
        );
      }
      const respondedWalletBinding = parseRecoveryResolvedWalletBindingFromResponse(
        ed25519RespondObj as Record<string, unknown>,
        'email-recovery/ed25519/respond',
      );
      assertSameRecoveryResolvedWalletBinding(
        preparedWalletBinding,
        respondedWalletBinding,
        'email-recovery/ed25519/respond',
      );
      const ed25519RespondThresholdSection = isObject(ed25519RespondObj.thresholdEd25519)
        ? ed25519RespondObj.thresholdEd25519
        : {};
      const ed25519ServerInputDelivery = parseEmailRecoveryEd25519HssServerInputDelivery(
        ed25519RespondThresholdSection.hss,
      );
      const ed25519EvaluationResult =
        await buildThresholdEd25519RegistrationHssClientOwnedArtifact({
          context,
          preparedSession: preparedEd25519Hss.preparedSession,
          clientRequest: ed25519ClientRequest,
          serverInputDelivery: ed25519ServerInputDelivery,
          clientOutputMaskHandle,
        });
      const ed25519FinalizeResp = await fetch(
        joinNormalizedUrl(relayerUrl, '/email-recovery/ed25519/finalize'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            request_id: requestId,
            evaluation_result: ed25519EvaluationResult,
          }),
        },
      );
      const ed25519FinalizeJson: unknown = await ed25519FinalizeResp.json().catch(() => ({}));
      const ed25519FinalizeObj = isObject(ed25519FinalizeJson) ? ed25519FinalizeJson : {};
      if (!ed25519FinalizeResp.ok || ed25519FinalizeObj.ok !== true) {
        throw new Error(
          String(ed25519FinalizeObj.message || ed25519FinalizeObj.error || '') ||
            `email-recovery/ed25519/finalize failed (HTTP ${ed25519FinalizeResp.status})`,
        );
      }
      const finalizedWalletBinding = parseRecoveryResolvedWalletBindingFromResponse(
        ed25519FinalizeObj as Record<string, unknown>,
        'email-recovery/ed25519/finalize',
      );
      assertSameRecoveryResolvedWalletBinding(
        preparedWalletBinding,
        finalizedWalletBinding,
        'email-recovery/ed25519/finalize',
      );
      const finalizedThresholdSection = isObject(ed25519FinalizeObj.thresholdEd25519)
        ? ed25519FinalizeObj.thresholdEd25519
        : {};
      const ed25519RegistrationWorkerMaterialReport =
        parseEmailRecoveryRegistrationWorkerMaterialReport(
          finalizedThresholdSection.registrationWorkerMaterialReport,
        );
      const finalizedRegistrationHssMaterial =
        buildEmailRecoveryFinalizedRegistrationHssMaterial({
          preparedSession: preparedEd25519Hss.preparedSession,
          ceremonyHandle: preparedEd25519Hss.ceremonyHandle,
          report: ed25519RegistrationWorkerMaterialReport,
        });

      const preparedClientBootstraps = await Promise.all(
        ecdsaPrepareTargets.map(async (target) => {
          const preparedClientBootstrap = await context.signingEngine.preparePasskeyEcdsaBootstrap({
            prepare: target.prepare,
            chainTarget: target.chainTarget,
            rpId,
            passkeyPrfFirstB64u,
            credentialIdB64u: String(credential.rawId || credential.id || '').trim(),
          });
          const clientBootstrap: WalletRegistrationEcdsaClientBootstrap =
            preparedClientBootstrap.clientBootstrap;
          return {
            chain_target: target.chainTarget,
            client_bootstrap: clientBootstrap,
          };
        }),
      );
      const ecdsaResp = await fetch(
        joinNormalizedUrl(relayerUrl, '/email-recovery/ecdsa/respond'),
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            request_id: requestId,
            client_bootstraps: preparedClientBootstraps,
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
        finalizedWalletBinding,
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
      const thresholdSession = parseEmailRecoveryThresholdEd25519Session(
        thresholdSection.session,
      );

      const credentialId = String(credential.rawId || '').trim();
      const credentialPublicKeyB64u = String(ecdsaObj.credentialPublicKeyB64u || '').trim();
      if (!credentialId || !credentialPublicKeyB64u) {
        throw new Error('email-recovery/ecdsa/respond returned missing passkey credential data');
      }
      const credentialPublicKey = base64UrlDecode(credentialPublicKeyB64u);
      if (credentialPublicKey.length === 0) {
        throw new Error('email-recovery/ecdsa/respond returned empty credential public key');
      }
      const clientParticipantId = Number(thresholdSection.clientParticipantId);
      const relayerParticipantId = Number(thresholdSection.relayerParticipantId);
      const { ed25519HssKeyVersion } = requireThresholdEd25519WarmSessionKeyVersion(
        thresholdSection,
        'email-recovery bootstrap',
      );
      const thresholdKeyVersion = formatEd25519HssKeyVersionForWire(ed25519HssKeyVersion);
      await context.signingEngine.storeWalletEd25519RecoveryRegistrationData({
        walletId: walletIdFromString(String(recoveredWalletBinding.walletId)),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        nearEd25519SigningKeyId: String(recoveredWalletBinding.nearEd25519SigningKeyId),
        credential,
        credentialPublicKeyB64u,
        signerSlot,
        operationalPublicKey: thresholdPublicKey,
        relayerKeyId,
        keyVersion: thresholdKeyVersion,
        clientParticipantId: Number.isFinite(clientParticipantId)
          ? Math.floor(clientParticipantId)
          : undefined,
        relayerParticipantId: Number.isFinite(relayerParticipantId)
          ? Math.floor(relayerParticipantId)
          : undefined,
        participantIds: Array.isArray(thresholdSection.participantIds)
          ? thresholdSection.participantIds
          : undefined,
      });
      await persistRegisteredThresholdEd25519Session({
        signingEngine: context.signingEngine,
        walletId: String(recoveredWalletBinding.walletId),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          String(recoveredWalletBinding.nearEd25519SigningKeyId),
        ),
        signerSlot,
        auth: {
          kind: 'passkey',
          credential,
        },
        relayerUrl,
        rpId,
        prfFirstB64u: passkeyPrfFirstB64u,
        registrationHssClientMaterial: ed25519HssMaterial,
        finalizedRegistrationHssMaterial,
        registrationSessionPolicy: thresholdWarmSessionRequest.session_policy,
        completedRegistration: buildEmailRecoveryCompletedThresholdEd25519Registration({
          thresholdSection,
          nearAccountId: recoveredWalletBinding.nearAccountId,
          nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
            String(recoveredWalletBinding.nearEd25519SigningKeyId),
          ),
          publicKey: thresholdPublicKey,
          relayerKeyId,
          keyVersion: thresholdKeyVersion,
          session: thresholdSession,
          report: ed25519RegistrationWorkerMaterialReport,
        }),
      });
      const recoveredSignerSlot = parseSignerSlot(signerSlot);
      if (!recoveredSignerSlot) {
        throw new Error('email-recovery recovered signerSlot is invalid');
      }
      retireRecoveredPasskeyThresholdEd25519Sessions({
        walletId: walletIdFromString(String(recoveredWalletBinding.walletId)),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        nearEd25519SigningKeyId: recoveredWalletBinding.nearEd25519SigningKeyId,
        signerSlot: recoveredSignerSlot,
        retainedThresholdSessionId: SigningSessionIds.thresholdEd25519Session(
          thresholdSession.thresholdSessionId,
        ),
      });
      await context.signingEngine.storeWalletEcdsaRecoverySignerRecords({
        walletId: recoveredWalletBinding.walletId,
        walletKeys,
      });

      this.pendingEmailRecovery = {
        accountId: String(recoveredWalletBinding.walletId),
        walletId: String(recoveredWalletBinding.walletId),
        nearAccountId: recoveredWalletBinding.nearAccountId,
        nearEd25519SigningKeyId: String(recoveredWalletBinding.nearEd25519SigningKeyId),
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
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(String(pending.nearEd25519SigningKeyId)),
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
    nearEd25519SigningKeyId: NearEd25519SigningKeyId;
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
        nearEd25519SigningKeyId: args.nearEd25519SigningKeyId,
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
