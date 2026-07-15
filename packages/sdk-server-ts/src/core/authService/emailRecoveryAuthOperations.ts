import { base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
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
import type { RouterAbEcdsaBootstrapExportRuntime } from '../routerAbSigning/RouterAbEcdsaBootstrapExportRuntime';
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
  ThresholdRuntimePolicyScope,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519AuthorityScope,
} from '../types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaPrepareTarget,
  WalletRegistrationEcdsaWalletKey,
} from '../registrationContracts';
import { parseWalletRegistrationEcdsaClientBootstrap } from '../ThresholdService/validation';
import { randomBase64Url } from './bytes';
import { normalizeAdjacentFlowEcdsaPrepareSpec } from './walletRegistrationPlanning';
import {
  buildEcdsaWalletKeysFromBootstrap,
  isMatchingEcdsaClientBootstrap,
  resolveBoundThresholdRuntimePolicyScope,
  toEcdsaHssClientBootstrapRequest,
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
  getRouterAbEcdsaBootstrapExportRuntime: () => RouterAbEcdsaBootstrapExportRuntime | null;
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
    for (const chainTarget of input.chainTargets) {
      const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
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
      const ecdsaRuntimePolicyScope =
        ecdsaPrepareSpec.value.runtimePolicyScope ||
        existingRuntimePolicyScope ||
        defaultRuntimePolicyScope;
      const signingRootId =
        ecdsaPrepareSpec.value.signingRootId ||
        (ecdsaRuntimePolicyScope ? deriveSigningRootId(ecdsaRuntimePolicyScope) : undefined);
      const signingRootVersion =
        ecdsaPrepareSpec.value.signingRootVersion ||
        ecdsaRuntimePolicyScope?.signingRootVersion ||
        'default';
      if (!signingRootId || !signingRootVersion) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'email recovery requires ECDSA signing-root metadata',
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
        ecdsa: ecdsaPrepare,
        ...(existingRuntimePolicyScope
          ? { existingRuntimePolicyScope }
          : {}),
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
      const resolved = resolveEmailRecoveryEcdsaClientBootstraps({
        expectedTargets: preparation.ecdsa.targets,
        actualEntries: parsed.entries,
      });
      if (!resolved.ok) return resolved;
      const runtime = this.ports.getRouterAbEcdsaBootstrapExportRuntime();
      if (!runtime) {
        return {
          ok: false,
          code: 'not_configured',
          message: 'Threshold signing is not configured on this server',
        };
      }
      const bootstraps: EmailRecoveryEcdsaServerBootstrapEntry[] = [];
      for (const entry of resolved.entries) {
        const bootstrap = await runtime.ecdsaHssRoleLocalBootstrap(
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
