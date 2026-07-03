import { base64UrlEncode } from '@shared/utils/encoders';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { walletIdFromString, type RegistrationSignerPlan } from '@shared/utils/registrationIntent';
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
  computeEcdsaHssRoleLocalThresholdKeyId,
} from '@shared/threshold/ecdsaHssRoleLocalBootstrap';
import type { ThresholdSigningService as ThresholdSigningServiceType } from '../ThresholdService';
import type { WebAuthnAuthenticatorStore } from '../WebAuthnAuthenticatorStore';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type {
  EmailRecoveryPreparationStore,
  EmailRecoveryResolvedWalletBinding,
} from '../EmailRecoveryPreparationStore';
import type { RecoverySessionStore } from '../RecoverySessionStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from '../recoverySessionRecords';
import type {
  EcdsaHssServerBootstrapResponse,
  ThresholdRuntimePolicyScope,
  WalletRegistrationEcdsaPreparePayload,
  WalletRegistrationEcdsaWalletKey,
  WebAuthnAuthenticationCredential,
  ThresholdEd25519AuthorityScope,
} from '../types';
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
  validateThresholdEd25519SessionPolicyBindings,
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
  resolveThresholdEd25519SessionPolicyForBinding,
} from './webauthnWalletBinding';
import { isObject } from './record';
import type { WalletId } from '@shared/utils/domainIds';

const REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES = 3;

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
  webAuthnAuthenticatorStore: WebAuthnAuthenticatorStore;
  webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore;
  emailRecoveryPreparationStore: EmailRecoveryPreparationStore;
  recoverySessionStore: RecoverySessionStore;
};

export class EmailRecoveryAuthOperations {
  constructor(private readonly ports: EmailRecoveryAuthOperationsPorts) {}

  private async prepareEmailRecoveryEcdsaStartPayload(input: {
    registrationCeremonyId: string;
    walletId: WalletId;
    signingRootId: string;
    signingRootVersion: string;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
    participantIds: readonly number[];
    runtimePolicyScope?: ThresholdRuntimePolicyScope;
  }): Promise<WalletRegistrationEcdsaPreparePayload> {
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: input.walletId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    });
    const ecdsaThresholdKeyId = await computeEcdsaHssRoleLocalThresholdKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion: input.signingRootVersion,
    });
    const relayerKeyId = await computeEcdsaHssRoleLocalRelayerKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
    });
    return {
      kind: 'evm_family_ecdsa_keygen',
      chainTargets: [...input.chainTargets],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: input.walletId,
        evmFamilySigningKeySlotId,
        ecdsaThresholdKeyId,
        signingRootId: input.signingRootId,
        signingRootVersion: input.signingRootVersion,
        keyScope: 'evm-family',
        relayerKeyId,
        requestId: `${input.registrationCeremonyId}:ecdsa`,
        thresholdSessionId: `tehss_${randomBase64Url(24)}`,
        signingGrantId: `wss_${randomBase64Url(24)}`,
        ttlMs: 10 * 60_000,
        remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
        participantIds: [...input.participantIds],
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
      },
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
        ecdsaPrepareSpec.value.runtimePolicyScope || existingRuntimePolicyScope;
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
          message: 'threshold_ecdsa_prepare requires a signing root',
        };
      }
      const ecdsaPrepare = await this.prepareEmailRecoveryEcdsaStartPayload({
        registrationCeremonyId: `email_recovery_${randomBase64Url(16)}`,
        walletId: walletIdFromString(walletBinding.walletId),
        signingRootId,
        signingRootVersion,
        chainTargets: ecdsaPrepareSpec.value.chainTargets,
        participantIds: ecdsaPrepareSpec.value.participantIds,
        ...(ecdsaRuntimePolicyScope ? { runtimePolicyScope: ecdsaRuntimePolicyScope } : {}),
      });
      let thresholdEd25519Session: ThresholdEd25519BootstrapSession | undefined;
      if (thresholdEd25519SessionPolicy) {
        const requestedSessionPolicy = thresholdEd25519SessionPolicy;
        const resolvedSessionPolicy = resolveThresholdEd25519SessionPolicyForBinding({
          requestedSessionPolicy,
          binding: walletBinding,
          relayerKeyId: keygen.relayerKeyId,
          persistedRuntimePolicyScope: existingRuntimePolicyScope,
        });
        const policyBindingError = validateThresholdEd25519SessionPolicyBindings({
          requestedSessionPolicy: resolvedSessionPolicy.sessionPolicy,
          expectedWalletId: walletBinding.walletId,
          expectedRelayerKeyId: keygen.relayerKeyId,
          expectedNearAccountId: walletBinding.nearAccountId,
          expectedNearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
          expectedAuthorityScope: walletBindingAuthorityScope,
        });
        if (policyBindingError) {
          return {
            ok: false,
            code: 'invalid_body',
            message: policyBindingError,
          };
        }

        const session = await threshold.mintEd25519SessionFromRegistration({
          walletId: walletBinding.walletId,
          nearAccountId: walletBinding.nearAccountId,
          nearEd25519SigningKeyId: walletBinding.nearEd25519SigningKeyId,
          authorityScope: walletBindingAuthorityScope,
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
        const normalizedSession = toThresholdEd25519BootstrapSession(session);
        if (!normalizedSession) {
          return {
            ok: false,
            code: 'internal',
            message: 'threshold-ed25519 email-recovery bootstrap failed',
          };
        }
        thresholdEd25519Session = normalizedSession;
      }

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
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
        },
        ecdsa: ecdsaPrepare,
        ...(existingRuntimePolicyScope ? { existingRuntimePolicyScope } : {}),
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
          ...(thresholdEd25519Session ? { session: thresholdEd25519Session } : {}),
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
    client_bootstrap?: unknown;
    clientBootstrap?: unknown;
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
          bootstrap: EcdsaHssServerBootstrapResponse;
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
      const parsed = parseWalletRegistrationEcdsaClientBootstrap(
        request?.client_bootstrap ?? request?.clientBootstrap,
      );
      if (!parsed) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Invalid Email Recovery ECDSA client bootstrap',
        };
      }

      const preparationStore = this.ports.emailRecoveryPreparationStore;
      const preparation = await preparationStore.get(requestId);
      if (!preparation) {
        return {
          ok: false,
          code: 'not_found',
          message: 'Unknown or expired email recovery preparation',
        };
      }
      if (!isMatchingEcdsaClientBootstrap(preparation.ecdsa.prepare, parsed)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email Recovery ECDSA bootstrap identity mismatch',
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
      const bootstrap = await threshold.ecdsaHssRoleLocalBootstrap(
        toEcdsaHssClientBootstrapRequest(parsed),
      );
      if (!bootstrap.ok) {
        return {
          ok: false,
          code: bootstrap.code || 'hss_respond_failed',
          message: bootstrap.message || 'Email Recovery ECDSA HSS bootstrap failed',
        };
      }
      const walletKeys = buildEcdsaWalletKeysFromBootstrap({
        bootstrap: bootstrap.value,
        chainTargets: preparation.ecdsa.chainTargets,
        errorContext: 'Email Recovery ECDSA bootstrap',
      });
      if (!walletKeys.ok) return walletKeys;

      const newEvmOwnerAddress = toOptionalTrimmedString(bootstrap.value.ethereumAddress);
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
            relayerKeyId: bootstrap.value.relayerKeyId,
            ethereumAddress: newEvmOwnerAddress,
            sessionId: bootstrap.value.thresholdSessionId,
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
          bootstrap: bootstrap.value,
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
