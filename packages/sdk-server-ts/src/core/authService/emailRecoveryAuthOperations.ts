import { base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  nearEd25519SigningKeyIdFromString,
  walletIdFromString,
} from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { computeSdkEd25519HssApplicationBindingDigestB64u } from '@shared/threshold/ed25519HssBinding';
import {
  parseSdkEcdsaHssSigningRootId,
  parseSdkEcdsaHssSigningRootVersion,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  buildRecoveryEmailBody,
  buildRecoveryEmailPayload,
  buildRecoveryEmailSubject,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';
import {
  computeEcdsaHssRoleLocalRelayerKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { ThresholdSigningService as ThresholdSigningServiceType } from '../ThresholdService';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '../ThresholdService/schemes/schemeIds';
import type { WebAuthnAuthenticatorStore } from '../WebAuthnAuthenticatorStore';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type {
  EmailRecoveryPreparationStore,
  EmailRecoveryResolvedWalletBinding,
} from '../EmailRecoveryPreparationStore';
import type { RecoverySessionStore } from '../RecoverySessionStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
} from '../thresholdEcdsaChainTarget';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from '../recoverySessionRecords';
import type {
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519RegistrationAccountScope,
  ThresholdEd25519HssServerVisibleClientRequestEnvelope,
  ThresholdRuntimePolicyScope,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519AuthorityScope,
} from '../types';
import type {
  ThresholdEd25519RegistrationWorkerMaterialReport,
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaPrepareTarget,
  WalletRegistrationEcdsaWalletKey,
} from '../registrationContracts';
import { parseWalletRegistrationEcdsaClientBootstrap } from '../ThresholdService/validation';
import { randomBase64Url } from './bytes';
import { normalizeThresholdRuntimePolicyScope } from './thresholdRuntimePolicy';
import { normalizeAdjacentFlowEcdsaPrepareSpec } from './walletRegistrationPlanning';
import {
  buildEcdsaWalletKeysFromBootstrap,
  isMatchingEcdsaClientBootstrap,
  parseThresholdEd25519RegistrationInput,
  resolveBoundThresholdRuntimePolicyScope,
  toEcdsaHssClientBootstrapRequest,
  toThresholdEd25519BootstrapSession,
  type ThresholdEd25519BootstrapSession,
} from './registrationThresholdHelpers';
import {
  passkeyThresholdEd25519AuthorityScope,
  requireWebAuthnRpId,
} from './webauthnAuthority';
import {
  decodeBase64UrlOrBase64,
  isHostWithinRpId,
  loadSimpleWebAuthnServer,
  originHostnameOrEmpty,
  parseClientDataJsonBase64url,
} from './webauthnOidcHelpers';
import {
  parseBoundaryWalletId,
  resolvedEd25519WalletBindingFromCredentialBinding,
  resolveExistingThresholdEd25519Binding,
  resolveRecoveryThresholdEd25519SessionPolicyForBinding,
} from './webauthnWalletBinding';
import { isObject } from './record';
import type { WalletId } from '@shared/utils/domainIds';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;
const EMAIL_RECOVERY_ECDSA_THRESHOLD_KEY_ID_VERSION =
  'threshold_ecdsa_hss_email_recovery_key_id_v1';
const EMAIL_RECOVERY_ECDSA_SIGNING_ROOT_VERSION_PREFIX = 'email-recovery';

function emailRecoveryEcdsaSigningRootVersion(input: {
  signingRootVersion: string;
  recoveryRequestId: string;
}): string {
  return [
    EMAIL_RECOVERY_ECDSA_SIGNING_ROOT_VERSION_PREFIX,
    encodeURIComponent(input.signingRootVersion),
    encodeURIComponent(input.recoveryRequestId),
  ].join(':');
}

function emailRecoveryEcdsaRuntimePolicyScope(input: {
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootVersion: string;
}): ThresholdRuntimePolicyScope | undefined {
  if (!input.runtimePolicyScope) return undefined;
  return {
    ...input.runtimePolicyScope,
    signingRootVersion: input.signingRootVersion,
  };
}

async function emailRecoveryEd25519IntentDigestB64u(input: {
  walletId: string;
  requestId: string;
  credentialIdB64u: string;
}): Promise<string> {
  return base64UrlEncode(
    await sha256BytesUtf8(
      alphabetizeStringify({
        version: 'email_recovery_ed25519_hss_scope_v1',
        walletId: input.walletId,
        requestId: input.requestId,
        credentialIdB64u: input.credentialIdB64u,
      }),
    ),
  );
}

function requireRecoveryEd25519RuntimePolicyScope(input: {
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): ThresholdRuntimePolicyScope | { ok: false; code: string; message: string } {
  const scope = input.runtimePolicyScope;
  if (!scope?.orgId || !scope.projectId || !scope.envId || !scope.signingRootVersion) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email Recovery Ed25519 material restore requires runtime policy scope',
    };
  }
  return scope;
}

const ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS = [
  'evaluatorOtStateB64u',
  'yClientB64u',
  'tauClientB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'yRelayerB64u',
  'tauRelayerB64u',
] as const;

const ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS = [
  'serverEvalFinalizeOutputB64u',
  'stagedEvaluatorArtifactHandle',
  'evaluatorOtStateB64u',
  'xClientBaseB64u',
  'xRelayerBaseB64u',
  'yClientB64u',
  'tauClientB64u',
  'yRelayerB64u',
  'tauRelayerB64u',
  'rClientB64u',
  'clientOutputMaskB64u',
  'prfFirstB64u',
  'prfOutputB64u',
  'clientSecretB64u',
  'clientSecret32B64u',
  'seedOutputMessageB64u',
] as const;

function findOwnField(raw: Record<string, unknown>, fields: readonly string[]): string | undefined {
  return fields.find((field) => Object.prototype.hasOwnProperty.call(raw, field));
}

function parseEmailRecoveryEd25519ClientRequest(
  raw: unknown,
):
  | { ok: true; value: ThresholdEd25519HssServerVisibleClientRequestEnvelope }
  | { ok: false; code: 'invalid_body'; message: string } {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'clientRequest is required' };
  }
  const clientRequestMessageB64u = toOptionalTrimmedString(raw.clientRequestMessageB64u);
  if (!clientRequestMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'clientRequest.clientRequestMessageB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_SERVER_VISIBLE_CLIENT_REQUEST_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `clientRequest.${forbiddenField} must stay outside the server-visible request`,
    };
  }
  return { ok: true, value: { clientRequestMessageB64u } };
}

function parseEmailRecoveryEd25519EvaluationResult(
  raw: unknown,
):
  | { ok: true; value: ThresholdEd25519HssClientOwnedStagedEvaluatorArtifactEnvelope }
  | { ok: false; code: 'invalid_body'; message: string } {
  if (!isObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'evaluationResult is required' };
  }
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const stagedEvaluatorArtifactB64u = toOptionalTrimmedString(raw.stagedEvaluatorArtifactB64u);
  const addStageRequestMessageB64u = toOptionalTrimmedString(raw.addStageRequestMessageB64u);
  if (!contextBindingB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.contextBindingB64u is required',
    };
  }
  if (!stagedEvaluatorArtifactB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.stagedEvaluatorArtifactB64u is required',
    };
  }
  if (!addStageRequestMessageB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'evaluationResult.addStageRequestMessageB64u is required',
    };
  }
  const forbiddenField = findOwnField(
    raw,
    ED25519_HSS_CLIENT_OWNED_STAGED_ARTIFACT_FORBIDDEN_FIELDS,
  );
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
    };
  }
  return {
    ok: true,
    value: { contextBindingB64u, stagedEvaluatorArtifactB64u, addStageRequestMessageB64u },
  };
}

async function buildEmailRecoveryEd25519HssContext(input: {
  registrationAccountScope: ThresholdEd25519RegistrationAccountScope;
}): Promise<ThresholdEd25519HssCanonicalContext> {
  return {
    applicationBindingDigestB64u: await computeSdkEd25519HssApplicationBindingDigestB64u({
      nearEd25519SigningKeyId: input.registrationAccountScope.nearEd25519SigningKeyId,
      signingRootId: parseSdkEcdsaHssSigningRootId(input.registrationAccountScope.signingRootId),
      signingRootVersion: parseSdkEcdsaHssSigningRootVersion(
        input.registrationAccountScope.signingRootVersion,
      ),
    }),
    participantIds: [...input.registrationAccountScope.participantIds],
  };
}

async function buildEmailRecoveryEd25519RegistrationAccountScope(input: {
  walletBinding: EmailRecoveryResolvedWalletBinding;
  requestId: string;
  credentialIdB64u: string;
  signingRootId: string;
  signingRootVersion: string;
  keyVersion: string;
  participantIds: number[];
}): Promise<ThresholdEd25519RegistrationAccountScope> {
  return {
    kind: 'known_account_registration_scope',
    walletId: input.walletBinding.walletId,
    intentDigestB64u: await emailRecoveryEd25519IntentDigestB64u({
      walletId: input.walletBinding.walletId,
      requestId: input.requestId,
      credentialIdB64u: input.credentialIdB64u,
    }),
    signingRootId: input.signingRootId,
    signingRootVersion: input.signingRootVersion,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
      input.walletBinding.nearEd25519SigningKeyId,
    ),
    signerSlot: input.walletBinding.signerSlot,
    keyPurpose: 'email_recovery',
    keyVersion: input.keyVersion,
    derivationVersion: 1,
    participantIds: [...input.participantIds],
    nearAccountId: input.walletBinding.nearAccountId,
  };
}

async function computeEmailRecoveryEcdsaHssRoleLocalThresholdKeyId(input: {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  signingRootId: string;
  signingRootVersion: string;
  recoveryRequestId: string;
}): Promise<string> {
  const digest32 = await sha256BytesUtf8(
    alphabetizeStringify({
      version: EMAIL_RECOVERY_ECDSA_THRESHOLD_KEY_ID_VERSION,
      walletId: input.walletId,
      evmFamilySigningKeySlotId: input.evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
      recoveryRequestId: input.recoveryRequestId,
    }),
  );
  return `ehss-recovery-${base64UrlEncode(digest32)}`;
}

function readOptionalRequestRecord(value: unknown): Record<string, unknown> | null {
  return isObject(value) ? value : null;
}

function readNestedRequestRecord(
  value: Record<string, unknown>,
  key: string,
): Record<string, unknown> | null {
  return readOptionalRequestRecord(value[key]);
}

export type EmailRecoveryAuthOperationsPorts = {
  ensureSignerAndRelayerAccount: () => Promise<void>;
  getThresholdSigningService: () => ThresholdSigningServiceType | null;
  getDefaultRuntimePolicyScope?: () => ThresholdRuntimePolicyScope | undefined;
  webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore;
  webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore;
  emailRecoveryPreparationStore: EmailRecoveryPreparationStore;
  recoverySessionStore: RecoverySessionStore;
};

type EmailRecoveryEcdsaClientBootstrapEntry = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
};

type EmailRecoveryEcdsaServerBootstrapEntry = {
  readonly chainTarget: ThresholdEcdsaChainTarget;
  readonly bootstrap: EcdsaHssServerBootstrapResponse;
};

type EmailRecoveryEcdsaClientBootstrapParseResult =
  | {
      readonly ok: true;
      readonly entries: EmailRecoveryEcdsaClientBootstrapEntry[];
    }
  | {
      readonly ok: false;
      readonly code: 'invalid_body';
      readonly message: string;
    };

function parseEmailRecoveryEcdsaClientBootstraps(
  raw: unknown,
): EmailRecoveryEcdsaClientBootstrapParseResult {
  if (!Array.isArray(raw) || raw.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email Recovery ECDSA clientBootstraps are required',
    };
  }
  const entries: EmailRecoveryEcdsaClientBootstrapEntry[] = [];
  const seenTargets = new Set<string>();
  for (const item of raw) {
    const record = readOptionalRequestRecord(item);
    const chainTarget = thresholdEcdsaChainTargetFromValue(record?.chainTarget);
    const clientBootstrap = parseWalletRegistrationEcdsaClientBootstrap(record?.clientBootstrap);
    if (!record || !chainTarget || !clientBootstrap) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid Email Recovery ECDSA client bootstrap',
      };
    }
    const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
    if (seenTargets.has(targetKey)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email Recovery ECDSA clientBootstraps contain duplicate chain targets',
      };
    }
    seenTargets.add(targetKey);
    entries.push({ chainTarget, clientBootstrap });
  }
  return { ok: true, entries };
}

function findEmailRecoveryEcdsaClientBootstrapEntry(input: {
  readonly entries: readonly EmailRecoveryEcdsaClientBootstrapEntry[];
  readonly targetKey: string;
}): EmailRecoveryEcdsaClientBootstrapEntry | null {
  let matched: EmailRecoveryEcdsaClientBootstrapEntry | null = null;
  for (const entry of input.entries) {
    if (thresholdEcdsaChainTargetKey(entry.chainTarget) !== input.targetKey) continue;
    if (matched) return null;
    matched = entry;
  }
  return matched;
}

function resolveEmailRecoveryEcdsaClientBootstraps(input: {
  readonly expectedTargets: readonly WalletRegistrationEcdsaPrepareTarget[];
  readonly actualEntries: readonly EmailRecoveryEcdsaClientBootstrapEntry[];
}): EmailRecoveryEcdsaClientBootstrapParseResult {
  if (input.expectedTargets.length !== input.actualEntries.length) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'Email Recovery ECDSA bootstrap target count mismatch',
    };
  }
  const entries: EmailRecoveryEcdsaClientBootstrapEntry[] = [];
  for (const expectedTarget of input.expectedTargets) {
    const targetKey = thresholdEcdsaChainTargetKey(expectedTarget.chainTarget);
    const entry = findEmailRecoveryEcdsaClientBootstrapEntry({
      entries: input.actualEntries,
      targetKey,
    });
    if (!entry) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Email Recovery ECDSA bootstrap missing target ${targetKey}`,
      };
    }
    if (
      !isMatchingEcdsaClientBootstrap(expectedTarget.prepare, entry.clientBootstrap)
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email Recovery ECDSA bootstrap identity mismatch',
      };
    }
    entries.push(entry);
  }
  return { ok: true, entries };
}

function buildEmailRecoveryEcdsaWalletKeys(input: {
  readonly bootstraps: readonly EmailRecoveryEcdsaServerBootstrapEntry[];
}):
  | {
      readonly ok: true;
      readonly walletKeys: WalletRegistrationEcdsaWalletKey[];
    }
  | {
      readonly ok: false;
      readonly code: 'incomplete_ecdsa_wallet_key';
      readonly message: string;
    } {
  const walletKeys: WalletRegistrationEcdsaWalletKey[] = [];
  for (const entry of input.bootstraps) {
    const result = buildEcdsaWalletKeysFromBootstrap({
      bootstrap: entry.bootstrap,
      chainTargets: [entry.chainTarget],
      errorContext: 'Email Recovery ECDSA bootstrap',
    });
    if (!result.ok) return result;
    walletKeys.push(...result.walletKeys);
  }
  return { ok: true, walletKeys };
}

export class EmailRecoveryAuthOperations {
  constructor(private readonly ports: EmailRecoveryAuthOperationsPorts) {}

  private async prepareEmailRecoveryEcdsaStartPayload(input: {
    registrationCeremonyId: string;
    recoveryRequestId: string;
    walletId: WalletId;
    signingRootId: string;
    signingRootVersion: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    participantIds: readonly number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<WalletRegistrationEcdsaPreparePayload> {
    const targets: WalletRegistrationEcdsaPrepareTarget[] = [];
    for (const chainTarget of input.chainTargets) {
      const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
      const signingRootVersion = emailRecoveryEcdsaSigningRootVersion({
        signingRootVersion: input.signingRootVersion,
        recoveryRequestId: input.recoveryRequestId,
      });
      const runtimePolicyScope = emailRecoveryEcdsaRuntimePolicyScope({
        runtimePolicyScope: input.runtimePolicyScope,
        signingRootVersion,
      });
      const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
        walletId: input.walletId,
        signingRootId: input.signingRootId,
        signingRootVersion,
        chainTargetKey,
      });
      const ecdsaThresholdKeyId = await computeEmailRecoveryEcdsaHssRoleLocalThresholdKeyId({
        walletId: input.walletId,
        evmFamilySigningKeySlotId,
        signingRootId: input.signingRootId,
        signingRootVersion,
        recoveryRequestId: input.recoveryRequestId,
      });
      const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
        walletId: input.walletId,
        evmFamilySigningKeySlotId,
      });
      targets.push({
        chainTarget,
        prepare: {
          formatVersion: 'ecdsa-hss-role-local',
          walletId: input.walletId,
          evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId,
          signingRootId: input.signingRootId,
          signingRootVersion,
          keyScope: 'evm-family',
          relayerKeyId,
          requestId: `${input.registrationCeremonyId}:ecdsa:${encodeURIComponent(chainTargetKey)}`,
          thresholdSessionId: `tehss_${randomBase64Url(24)}`,
          signingGrantId: `wss_${randomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: [...input.participantIds],
          ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
        },
      });
    }
    return {
      kind: 'evm_family_ecdsa_keygen',
      targets,
    };
  }

  async prepareEmailRecovery(request: {
    account_id?: unknown;
    accountId?: unknown;
    request_id?: unknown;
    requestId?: unknown;
    signer_slot?: unknown;
    signerSlot?: unknown;
    threshold_ed25519?: unknown;
    threshold_ecdsa?: unknown;
    threshold_ecdsa_prepare?: unknown;
    rp_id?: unknown;
    webauthn_registration?: unknown;
    expected_origin?: string;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        walletId: string;
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        walletBinding: EmailRecoveryResolvedWalletBinding;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          authorityScope: ThresholdEd25519AuthorityScope;
          publicKey: string;
          keyVersion?: string;
          recoveryExportCapable?: boolean;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: ThresholdEd25519BootstrapSession;
          hss?: {
            ceremonyHandle: string;
            preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
            clientOtOfferMessageB64u: string;
            context: ThresholdEd25519HssCanonicalContext;
          };
        };
        ecdsa: WalletRegistrationEcdsaPreparePayload;
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const requestRecord = readOptionalRequestRecord(request);
      if (!requestRecord) {
        return { ok: false, code: 'invalid_body', message: 'JSON body required' };
      }
      if (requestRecord.threshold_ecdsa != null) {
        return {
          ok: false,
          code: 'invalid_body',
          message:
            'threshold_ecdsa email-recovery bootstrap has been removed; use role-local ECDSA HSS bootstrap',
        };
      }
      await this.ports.ensureSignerAndRelayerAccount();

      const accountIdRaw = toOptionalTrimmedString(request?.account_id ?? request?.accountId);
      const accountId = accountIdRaw ? parseBoundaryWalletId(accountIdRaw) : null;
      if (!accountId) {
        return { ok: false, code: 'invalid_body', message: 'Invalid wallet accountId' };
      }

      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }

      const rpId = String(request?.rp_id || '').trim();
      if (!rpId) return { ok: false, code: 'invalid_body', message: 'Missing rp_id' };

      const signerSlot = (() => {
        const raw = request?.signer_slot ?? request?.signerSlot ?? 1;
        const n = typeof raw === 'number' ? raw : Number(raw);
        return Number.isFinite(n) && n >= 1 ? Math.floor(n) : 1;
      })();

      const thresholdEd25519Raw = requestRecord.threshold_ed25519;
      const thresholdEd25519Record = readOptionalRequestRecord(thresholdEd25519Raw);
      const thresholdEd25519Bootstrap =
        parseThresholdEd25519RegistrationInput(thresholdEd25519Raw);
      const thresholdEd25519SessionPolicy = thresholdEd25519Bootstrap.sessionPolicy;
      if (thresholdEd25519Record?.session_policy != null && !thresholdEd25519SessionPolicy) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy must be an object',
        };
      }
      const thresholdEd25519SessionKind = thresholdEd25519Bootstrap.sessionKind;
      if (thresholdEd25519SessionKind && thresholdEd25519SessionKind !== 'jwt') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_kind must be jwt',
        };
      }
      if (!thresholdEd25519SessionPolicy && thresholdEd25519SessionKind) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ed25519.session_policy is required when session_kind is provided',
        };
      }
      const ecdsaPrepareSpec = normalizeAdjacentFlowEcdsaPrepareSpec(
        requestRecord.threshold_ecdsa_prepare,
      );
      if (!ecdsaPrepareSpec.ok) return ecdsaPrepareSpec;
      if (!ecdsaPrepareSpec.value) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'threshold_ecdsa_prepare is required for email recovery',
        };
      }

      const cred = readOptionalRequestRecord(request.webauthn_registration);
      if (!cred)
        return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };
      const credResponse = readNestedRequestRecord(cred, 'response');
      const clientDataJSON =
        typeof credResponse?.clientDataJSON === 'string' ? credResponse.clientDataJSON : '';

      // Reuse the canonical deterministic registration challenge schema.
      // Email recovery authorization happens out-of-band (DKIM/TEE), so we don't
      // need to bind the WebAuthn registration challenge to the email `requestId`.
      const expectedIntent = `register:${accountId}:${signerSlot}`;
      const expectedChallenge = base64UrlEncode(await sha256BytesUtf8(expectedIntent));

      const clientData = parseClientDataJsonBase64url(clientDataJSON);
      if (clientData.type !== 'webauthn.create') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
        };
      }
      if (clientData.challenge !== expectedChallenge) {
        return {
          ok: false,
          code: 'challenge_mismatch',
          message: 'Registration challenge mismatch',
        };
      }
      const originHost = originHostnameOrEmpty(clientData.origin);
      const webAuthnRpId = requireWebAuthnRpId(rpId, 'email recovery registration rpId');
      if (!isHostWithinRpId(originHost, webAuthnRpId)) {
        return { ok: false, code: 'invalid_origin', message: 'WebAuthn origin is not within rpId' };
      }

      const mod = await loadSimpleWebAuthnServer();
      const verifyRegistrationResponse = mod.verifyRegistrationResponse;
      if (typeof verifyRegistrationResponse !== 'function') {
        return {
          ok: false,
          code: 'unsupported',
          message: 'WebAuthn registration verifier is unavailable in this runtime',
        };
      }

      const expectedOriginStrict = toOptionalTrimmedString(request.expected_origin);
      if (!expectedOriginStrict) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const registration = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge,
        expectedOrigin: expectedOriginStrict,
        expectedRPID: webAuthnRpId,
        requireUserVerification: false,
      });
      if (!registration?.verified) {
        return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
      }

      const threshold = this.ports.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bindingStore = this.ports.webAuthnCredentialBindingStore;
      const existingRuntimePolicyScope = await resolveBoundThresholdRuntimePolicyScope({
        bindingStore,
        userId: accountId,
        rpId,
      });
      const defaultRuntimePolicyScope = this.ports.getDefaultRuntimePolicyScope?.();
      const existingThresholdEd25519Binding = await resolveExistingThresholdEd25519Binding({
        bindingStore,
        userId: accountId,
        rpId,
      });
      if (!existingThresholdEd25519Binding) {
        return {
          ok: false,
          code: 'not_found',
          message: 'No existing threshold-ed25519 key binding found for account',
        };
      }
      const keygen = {
        relayerKeyId: String(existingThresholdEd25519Binding.relayerKeyId || '').trim(),
        publicKey: existingThresholdEd25519Binding.publicKey,
        keyVersion: String(existingThresholdEd25519Binding.keyVersion || '').trim(),
        recoveryExportCapable:
          existingThresholdEd25519Binding.recoveryExportCapable === true ? true : undefined,
        clientParticipantId: existingThresholdEd25519Binding.clientParticipantId,
        relayerParticipantId: existingThresholdEd25519Binding.relayerParticipantId,
        participantIds: existingThresholdEd25519Binding.participantIds,
      };
      if (
        !keygen.relayerKeyId ||
        !keygen.publicKey ||
        !keygen.keyVersion ||
        keygen.recoveryExportCapable !== true
      ) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Existing threshold-ed25519 binding is incomplete',
        };
      }
      const walletBinding = resolvedEd25519WalletBindingFromCredentialBinding({
        binding: existingThresholdEd25519Binding,
        signerSlot,
      });
      const walletBindingAuthorityScope = passkeyThresholdEd25519AuthorityScope(
        requireWebAuthnRpId(walletBinding.rpId, 'email recovery registration rpId'),
      );
      const requestedEd25519RuntimePolicyScope = thresholdEd25519SessionPolicy
        ? normalizeThresholdRuntimePolicyScope(thresholdEd25519SessionPolicy.runtimePolicyScope)
        : undefined;
      const initialEcdsaRuntimePolicyScope =
        ecdsaPrepareSpec.value.runtimePolicyScope ||
        existingRuntimePolicyScope ||
        requestedEd25519RuntimePolicyScope ||
        defaultRuntimePolicyScope;
      const ed25519RuntimeScope = requireRecoveryEd25519RuntimePolicyScope({
        runtimePolicyScope:
          existingRuntimePolicyScope ||
          requestedEd25519RuntimePolicyScope ||
          initialEcdsaRuntimePolicyScope ||
          defaultRuntimePolicyScope,
      });
      if ('ok' in ed25519RuntimeScope) return ed25519RuntimeScope;
      const ecdsaRuntimePolicyScope = initialEcdsaRuntimePolicyScope || ed25519RuntimeScope;
      const signingRootId =
        ecdsaPrepareSpec.value.signingRootId ||
        (ecdsaRuntimePolicyScope ? deriveSigningRootId(ecdsaRuntimePolicyScope) : undefined);
      const signingRootVersion =
        ecdsaPrepareSpec.value.signingRootVersion ||
        ecdsaRuntimePolicyScope?.signingRootVersion ||
        'default';
      const ed25519SigningRootId = deriveSigningRootId(ed25519RuntimeScope);
      const ed25519SigningRootVersion = ed25519RuntimeScope.signingRootVersion;
      const ed25519ParticipantIds = keygen.participantIds;
      if (
        !signingRootId ||
        !signingRootVersion ||
        !ed25519SigningRootId ||
        !ed25519SigningRootVersion ||
        !Array.isArray(ed25519ParticipantIds) ||
        ed25519ParticipantIds.length < 2
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'email recovery requires Ed25519 and ECDSA signing-root metadata',
        };
      }
      const ecdsaPrepare = await this.prepareEmailRecoveryEcdsaStartPayload({
        registrationCeremonyId: `email_recovery_${randomBase64Url(16)}`,
        recoveryRequestId: requestId,
        walletId: walletIdFromString(walletBinding.walletId),
        signingRootId,
        signingRootVersion,
        chainTargets: ecdsaPrepareSpec.value.chainTargets,
        participantIds: ecdsaPrepareSpec.value.participantIds,
        ...(ecdsaRuntimePolicyScope ? { runtimePolicyScope: ecdsaRuntimePolicyScope } : {}),
      });

      const credentialIdB64u = String(registration?.registrationInfo?.credential?.id || '').trim();
      const credentialPublicKey = registration?.registrationInfo?.credential?.publicKey as
        | Uint8Array
        | undefined;
      const counter = registration?.registrationInfo?.credential?.counter as number | undefined;

      if (!credentialIdB64u || !credentialPublicKey) {
        return {
          ok: false,
          code: 'internal',
          message: 'Registration verification did not return credential public key material',
        };
      }
      const registrationAccountScope = await buildEmailRecoveryEd25519RegistrationAccountScope({
        walletBinding,
        requestId,
        credentialIdB64u,
        signingRootId: ed25519SigningRootId,
        signingRootVersion: ed25519SigningRootVersion,
        keyVersion: keygen.keyVersion,
        participantIds: ed25519ParticipantIds,
      });
      const ed25519HssContext = await buildEmailRecoveryEd25519HssContext({
        registrationAccountScope,
      });
      const preparedEd25519 = await threshold.ed25519Hss.prepareForRegistration({
        orgId: ed25519RuntimeScope.orgId,
        signingRootId: ed25519SigningRootId,
        signingRootVersion: ed25519SigningRootVersion,
        request: {
          registrationAccountScope,
          wallet_key_id: registrationAccountScope.nearEd25519SigningKeyId,
          context: ed25519HssContext,
        },
      });
      if (!preparedEd25519.ok) {
        return {
          ok: false,
          code: preparedEd25519.code || 'hss_prepare_failed',
          message: preparedEd25519.message || 'Email Recovery Ed25519 HSS prepare failed',
        };
      }

      const now = Date.now();
      await this.ports.emailRecoveryPreparationStore.put({
        version: 'email_recovery_preparation_v1',
        requestId,
        accountId: walletBinding.walletId,
        walletBinding,
        rpId: walletBinding.rpId,
        signerSlot: walletBinding.signerSlot,
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(credentialPublicKey),
        counter: Number.isFinite(counter) && counter! >= 0 ? Math.floor(counter!) : 0,
        createdAtMs: now,
        expiresAtMs: now + DEFAULT_RECOVERY_SESSION_TTL_MS,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          authorityScope: walletBindingAuthorityScope,
          publicKey: keygen.publicKey,
          keyVersion: keygen.keyVersion,
          recoveryExportCapable: true,
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
        },
        thresholdEd25519Hss: {
          orgId: ed25519RuntimeScope.orgId,
          registrationAccountScope,
          context: ed25519HssContext,
          ceremonyHandle: preparedEd25519.ceremonyHandle,
          preparedSession: preparedEd25519.preparedSession,
          clientOtOfferMessageB64u: preparedEd25519.clientOtOfferMessageB64u,
          serverState: preparedEd25519.serverState,
          ...(thresholdEd25519SessionPolicy
            ? { requestedSessionPolicy: thresholdEd25519SessionPolicy }
            : {}),
        },
        ecdsa: ecdsaPrepare,
        existingRuntimePolicyScope: existingRuntimePolicyScope || ed25519RuntimeScope,
      });

      return {
        ok: true,
        accountId: walletBinding.walletId,
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        walletBinding,
        requestId,
        signerSlot: walletBinding.signerSlot,
        credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: keygen.relayerKeyId,
          authorityScope: walletBindingAuthorityScope,
          publicKey: keygen.publicKey,
          ...(keygen.keyVersion ? { keyVersion: keygen.keyVersion } : {}),
          ...(typeof keygen.recoveryExportCapable === 'boolean'
            ? { recoveryExportCapable: keygen.recoveryExportCapable }
            : {}),
          clientParticipantId: keygen.clientParticipantId,
          relayerParticipantId: keygen.relayerParticipantId,
          participantIds: keygen.participantIds,
          hss: {
            ceremonyHandle: preparedEd25519.ceremonyHandle,
            preparedSession: preparedEd25519.preparedSession,
            clientOtOfferMessageB64u: preparedEd25519.clientOtOfferMessageB64u,
            context: ed25519HssContext,
          },
        },
        ecdsa: ecdsaPrepare,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email recovery preparation failed',
      };
    }
  }

  async respondEmailRecoveryEd25519(request: {
    request_id?: unknown;
    requestId?: unknown;
    clientRequest?: unknown;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        walletId: string;
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        walletBinding: EmailRecoveryResolvedWalletBinding;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          authorityScope: ThresholdEd25519AuthorityScope;
          participantIds?: number[];
          hss: {
            contextBindingB64u: string;
            serverInputDeliveryB64u: string;
          };
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }
      const clientRequest = parseEmailRecoveryEd25519ClientRequest(request.clientRequest);
      if (!clientRequest.ok) return clientRequest;

      const preparationStore = this.ports.emailRecoveryPreparationStore;
      const preparation = await preparationStore.get(requestId);
      if (!preparation) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired email recovery preparation',
        };
      }
      const threshold = this.ports.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }

      const hss = preparation.thresholdEd25519Hss;
      const responded = await threshold.ed25519Hss.respondForRegistration({
        orgId: hss.orgId,
        request: {
          registrationAccountScope: hss.registrationAccountScope,
          wallet_key_id: hss.registrationAccountScope.nearEd25519SigningKeyId,
          ceremonyHandle: hss.ceremonyHandle,
          preparedSession: hss.preparedSession,
          serverState: hss.serverState,
          clientRequest: clientRequest.value,
        },
      });
      if (!responded.ok) {
        return {
          ok: false,
          code: responded.code || 'hss_respond_failed',
          message: responded.message || 'Email Recovery Ed25519 HSS respond failed',
        };
      }

      await preparationStore.put({
        ...preparation,
        thresholdEd25519HssResponded: {
          orgId: hss.orgId,
          registrationAccountScope: hss.registrationAccountScope,
          context: hss.context,
          ceremonyHandle: hss.ceremonyHandle,
          preparedSession: hss.preparedSession,
          serverState: responded.serverState,
        },
      });

      return {
        ok: true,
        accountId: preparation.walletBinding.walletId,
        walletId: preparation.walletBinding.walletId,
        nearAccountId: preparation.walletBinding.nearAccountId,
        nearEd25519SigningKeyId: preparation.walletBinding.nearEd25519SigningKeyId,
        walletBinding: preparation.walletBinding,
        requestId,
        signerSlot: preparation.walletBinding.signerSlot,
        credentialIdB64u: preparation.credentialIdB64u,
        thresholdEd25519: {
          relayerKeyId: preparation.thresholdEd25519.relayerKeyId,
          authorityScope: preparation.thresholdEd25519.authorityScope,
          ...(preparation.thresholdEd25519.participantIds
            ? { participantIds: preparation.thresholdEd25519.participantIds }
            : {}),
          hss: {
            contextBindingB64u: responded.contextBindingB64u,
            serverInputDeliveryB64u: responded.serverInputDeliveryB64u,
          },
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email Recovery Ed25519 response failed',
      };
    }
  }

  async finalizeEmailRecoveryEd25519(request: {
    request_id?: unknown;
    requestId?: unknown;
    evaluationResult?: unknown;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        walletId: string;
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        walletBinding: EmailRecoveryResolvedWalletBinding;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          authorityScope: ThresholdEd25519AuthorityScope;
          publicKey: string;
          keyVersion: string;
          recoveryExportCapable: true;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: ThresholdEd25519BootstrapSession;
          registrationWorkerMaterialReport: ThresholdEd25519RegistrationWorkerMaterialReport;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }
      const evaluationResult = parseEmailRecoveryEd25519EvaluationResult(request.evaluationResult);
      if (!evaluationResult.ok) return evaluationResult;

      const preparationStore = this.ports.emailRecoveryPreparationStore;
      const preparation = await preparationStore.get(requestId);
      if (!preparation) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired email recovery preparation',
        };
      }
      const respondedHss = preparation.thresholdEd25519HssResponded;
      if (!respondedHss) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Email Recovery Ed25519 HSS respond must complete before finalize',
        };
      }
      const threshold = this.ports.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }

      const walletBinding = preparation.walletBinding;
      const authority = buildPasskeyWalletAuthAuthority({
        walletId: walletBinding.walletId,
        rpId: requireWebAuthnRpId(walletBinding.rpId, 'email recovery registration rpId'),
        credentialIdB64u: preparation.credentialIdB64u,
      });
      const finalized = await threshold.ed25519Hss.finalizeForRegistration({
        orgId: respondedHss.orgId,
        request: {
          registrationAccountScope: respondedHss.registrationAccountScope,
          wallet_key_id: respondedHss.registrationAccountScope.nearEd25519SigningKeyId,
          authority,
          ceremonyHandle: respondedHss.ceremonyHandle,
          preparedSession: respondedHss.preparedSession,
          serverState: respondedHss.serverState,
          serverEvalSource: { kind: 'serialized_replay' },
          evaluationResult: evaluationResult.value,
          accountResolution: {
            kind: 'known_account',
            nearAccountId: walletBinding.nearAccountId,
          },
        },
      });
      if (!finalized.ok) {
        return {
          ok: false,
          code: finalized.code || 'hss_finalize_failed',
          message: finalized.message || 'Email Recovery Ed25519 HSS finalize failed',
        };
      }

      const scheme = threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
      if (!scheme || scheme.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
        return {
          ok: false,
          code: 'not_configured',
          message: `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled`,
        };
      }
      const keygen = await scheme.registration.keygenFromRegistrationMaterial({
        walletId: walletBinding.walletId,
        nearAccountId: finalized.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        authority,
        keyVersion: respondedHss.registrationAccountScope.keyVersion,
        recoveryExportCapable: true,
        publicKey: finalized.publicKey,
        relayerKeyId: finalized.relayerKeyId,
      });
      if (!keygen.ok) {
        return {
          ok: false,
          code: keygen.code || 'keygen_failed',
          message: keygen.message || 'Email Recovery Ed25519 keygen failed',
        };
      }

      const requestedSessionPolicy = preparation.thresholdEd25519Hss.requestedSessionPolicy;
      if (!requestedSessionPolicy) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Email Recovery Ed25519 session policy is missing',
        };
      }
      const resolvedSessionPolicy = resolveRecoveryThresholdEd25519SessionPolicyForBinding({
        requestedSessionPolicy,
        binding: walletBinding,
        relayerKeyId: keygen.relayerKeyId,
        persistedRuntimePolicyScope: preparation.existingRuntimePolicyScope,
      });
      const session = await threshold.mintEd25519SessionFromRegistration({
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        authority: resolvedSessionPolicy.sessionPolicy.authority,
        relayerKeyId: keygen.relayerKeyId,
        sessionPolicy: resolvedSessionPolicy.sessionPolicy,
      });
      if (
        !session.ok ||
        !session.thresholdSessionId ||
        !Number.isFinite(Number(session.expiresAtMs))
      ) {
        return {
          ok: false,
          code: session.code || 'internal',
          message: session.message || 'threshold-ed25519 email-recovery bootstrap failed',
        };
      }
      const thresholdEd25519Session = toThresholdEd25519BootstrapSession(session);
      if (!thresholdEd25519Session) {
        return {
          ok: false,
          code: 'internal',
          message: 'threshold-ed25519 email-recovery bootstrap failed',
        };
      }

      const thresholdEd25519 = {
        relayerKeyId: keygen.relayerKeyId,
        authorityScope: passkeyThresholdEd25519AuthorityScope(
          requireWebAuthnRpId(walletBinding.rpId, 'email recovery registration rpId'),
        ),
        publicKey: keygen.publicKey,
        keyVersion: keygen.keyVersion,
        recoveryExportCapable: true as const,
        clientParticipantId: keygen.clientParticipantId,
        relayerParticipantId: keygen.relayerParticipantId,
        participantIds: keygen.participantIds,
        session: thresholdEd25519Session,
        registrationWorkerMaterialReport: {
          kind: 'threshold_ed25519_registration_worker_material_report_v1',
          contextBindingB64u: finalized.finalizedReport.contextBindingB64u,
          clientOutputMessageB64u: finalized.finalizedReport.clientOutputMessageB64u,
        } satisfies ThresholdEd25519RegistrationWorkerMaterialReport,
      };
      await preparationStore.put({
        ...preparation,
        thresholdEd25519,
      });

      return {
        ok: true,
        accountId: walletBinding.walletId,
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        walletBinding,
        requestId,
        signerSlot: walletBinding.signerSlot,
        credentialIdB64u: preparation.credentialIdB64u,
        thresholdEd25519,
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email Recovery Ed25519 finalize failed',
      };
    }
  }

  async respondEmailRecoveryEcdsa(request: {
    request_id?: unknown;
    requestId?: unknown;
    clientBootstraps?: unknown;
  }): Promise<
    | {
        ok: true;
        accountId: string;
        walletId: string;
        nearAccountId: string;
        nearEd25519SigningKeyId: string;
        walletBinding: EmailRecoveryResolvedWalletBinding;
        requestId: string;
        signerSlot: number;
        credentialIdB64u: string;
        credentialPublicKeyB64u: string;
        thresholdEd25519: {
          relayerKeyId: string;
          authorityScope: ThresholdEd25519AuthorityScope;
          publicKey: string;
          keyVersion: string;
          recoveryExportCapable: true;
          clientParticipantId?: number;
          relayerParticipantId?: number;
          participantIds?: number[];
          session?: ThresholdEd25519BootstrapSession;
        };
        ecdsa: {
          bootstraps: EmailRecoveryEcdsaServerBootstrapEntry[];
          walletKeys: WalletRegistrationEcdsaWalletKey[];
        };
        recoverySession: {
          sessionId: string;
          status: 'prepared';
          expiresAtMs: number;
          deadlineEpochSeconds: number;
          payloadHash: string;
        };
        recoveryEmail: {
          subject: string;
          body: string;
          payload: RecoveryEmailPayload;
          payloadHash: string;
          deadlineEpochSeconds: number;
        };
      }
    | { ok: false; code: string; message: string }
  > {
    try {
      const requestId = String(request?.request_id ?? request?.requestId ?? '').trim();
      if (!requestId || !/^[A-Za-z0-9_-]{3,64}$/.test(requestId)) {
        return { ok: false, code: 'invalid_body', message: 'Invalid requestId' };
      }
      const parsed = parseEmailRecoveryEcdsaClientBootstraps(request.clientBootstraps);
      if (!parsed.ok) return parsed;

      const preparationStore = this.ports.emailRecoveryPreparationStore;
      const preparation = await preparationStore.get(requestId);
      if (!preparation) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired email recovery preparation',
        };
      }
      if (!preparation.thresholdEd25519.session) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Email Recovery Ed25519 material must be finalized before ECDSA respond',
        };
      }
      const resolved = resolveEmailRecoveryEcdsaClientBootstraps({
        expectedTargets: preparation.ecdsa.targets,
        actualEntries: parsed.entries,
      });
      if (!resolved.ok) return resolved;
      const threshold = this.ports.getThresholdSigningService();
      if (!threshold) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bootstraps: EmailRecoveryEcdsaServerBootstrapEntry[] = [];
      for (const entry of resolved.entries) {
        const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(
          toEcdsaHssClientBootstrapRequest(entry.clientBootstrap),
        );
        if (!bootstrap.ok) {
          return {
            ok: false,
            code: bootstrap.code || 'hss_respond_failed',
            message: bootstrap.message || 'Email Recovery ECDSA HSS bootstrap failed',
          };
        }
        bootstraps.push({
          chainTarget: entry.chainTarget,
          bootstrap: bootstrap.value,
        });
      }
      const walletKeys = buildEmailRecoveryEcdsaWalletKeys({ bootstraps });
      if (!walletKeys.ok) return walletKeys;

      const primaryBootstrap = bootstraps[0]?.bootstrap;
      const newEvmOwnerAddress = toOptionalTrimmedString(primaryBootstrap?.ethereumAddress);
      if (!newEvmOwnerAddress) {
        return {
          ok: false,
          code: 'internal',
          message: 'Email Recovery ECDSA bootstrap returned no owner address',
        };
      }

      const now = Date.now();
      const walletBinding = preparation.walletBinding;
      const recoveryDeadlineEpochSeconds = Math.floor(preparation.expiresAtMs / 1000);
      const recoveryEmailPayload = buildRecoveryEmailPayload({
        nearAccountId: walletBinding.nearAccountId,
        recoverySessionId: requestId,
        newNearPublicKey: preparation.thresholdEd25519.publicKey,
        newEvmOwnerAddress,
        deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        scope: 'all-linked-evm-accounts',
      });
      const recoveryEmailPayloadHash = await hashRecoveryEmailPayload(recoveryEmailPayload);
      const recoveryEmailSubject = buildRecoveryEmailSubject(recoveryEmailPayload);
      const recoveryEmailBody = buildRecoveryEmailBody(recoveryEmailPayload);

      const authStore = this.ports.webAuthnAuthenticatorStore;
      await authStore.put(walletBinding.walletId, {
        version: 'webauthn_authenticator_v1',
        credentialIdB64u: preparation.credentialIdB64u,
        credentialPublicKeyB64u: preparation.credentialPublicKeyB64u,
        counter: preparation.counter,
        createdAtMs: now,
        updatedAtMs: now,
      });

      const bindingStore = this.ports.webAuthnCredentialBindingStore;
      await bindingStore.put({
        version: 'webauthn_credential_binding_v1',
        rpId: preparation.rpId,
        credentialIdB64u: preparation.credentialIdB64u,
        userId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        signerSlot: walletBinding.signerSlot,
        publicKey: preparation.thresholdEd25519.publicKey,
        relayerKeyId: preparation.thresholdEd25519.relayerKeyId,
        keyVersion: preparation.thresholdEd25519.keyVersion,
        recoveryExportCapable: true,
        clientParticipantId: preparation.thresholdEd25519.clientParticipantId,
        relayerParticipantId: preparation.thresholdEd25519.relayerParticipantId,
        participantIds: preparation.thresholdEd25519.participantIds,
        ...(preparation.thresholdEd25519.session?.runtimePolicyScope ||
        preparation.existingRuntimePolicyScope
          ? {
              runtimePolicyScope:
                preparation.thresholdEd25519.session?.runtimePolicyScope ||
                preparation.existingRuntimePolicyScope,
            }
          : {}),
        createdAtMs: now,
        updatedAtMs: now,
      });

      const recoverySessionRecord = buildPreparedRecoverySessionRecord({
        sessionId: requestId,
        userId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        signerSlot: walletBinding.signerSlot,
        newNearPublicKey: preparation.thresholdEd25519.publicKey,
        newEvmOwnerAddress,
        recoveryDeadlineEpochSeconds,
        recoveryEmailPayloadHash,
        scope: 'all-linked-evm-accounts',
        expiresAtMs: preparation.expiresAtMs,
        metadata: {
          rpId: preparation.rpId,
          credentialIdB64u: preparation.credentialIdB64u,
          recoveryEmail: {
            subject: recoveryEmailSubject,
            body: recoveryEmailBody,
          },
          thresholdEd25519: {
            relayerKeyId: preparation.thresholdEd25519.relayerKeyId,
            ...(preparation.thresholdEd25519.session
              ? { sessionId: preparation.thresholdEd25519.session.thresholdSessionId }
              : {}),
          },
          thresholdEcdsa: {
            relayerKeyId: primaryBootstrap.relayerKeyId,
            ethereumAddress: newEvmOwnerAddress,
            sessionId: primaryBootstrap.thresholdSessionId,
          },
        },
      });
      if (!recoverySessionRecord) {
        return {
          ok: false,
          code: 'internal',
          message: 'Failed to build recovery session record',
        };
      }
      await this.ports.recoverySessionStore.put(recoverySessionRecord);
      await preparationStore.del(requestId);

      return {
        ok: true,
        accountId: walletBinding.walletId,
        walletId: walletBinding.walletId,
        nearAccountId: walletBinding.nearAccountId,
        nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
        walletBinding,
        requestId,
        signerSlot: walletBinding.signerSlot,
        credentialIdB64u: preparation.credentialIdB64u,
        credentialPublicKeyB64u: preparation.credentialPublicKeyB64u,
        thresholdEd25519: preparation.thresholdEd25519,
        ecdsa: {
          bootstraps,
          walletKeys: walletKeys.walletKeys,
        },
        recoverySession: {
          sessionId: recoverySessionRecord.sessionId,
          status: 'prepared',
          expiresAtMs: recoverySessionRecord.expiresAtMs,
          deadlineEpochSeconds: recoverySessionRecord.recoveryDeadlineEpochSeconds,
          payloadHash: recoverySessionRecord.recoveryEmailPayloadHash,
        },
        recoveryEmail: {
          subject: recoveryEmailSubject,
          body: recoveryEmailBody,
          payload: recoveryEmailPayload,
          payloadHash: recoveryEmailPayloadHash,
          deadlineEpochSeconds: recoveryDeadlineEpochSeconds,
        },
      };
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(e) || 'Email Recovery ECDSA response failed',
      };
    }
  }
}
