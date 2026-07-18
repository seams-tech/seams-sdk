import { base64UrlEncode } from '@shared/utils/encoders';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { errorMessage } from '@shared/utils/errors';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { deriveSigningRootId } from '@shared/threshold/signingRootScope';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  computeEcdsaDerivationRoleLocalRelayerKeyId,
  parseSdkEcdsaDerivationThresholdKeyId,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import type { WebAuthnCredentialBindingStore } from '../WebAuthnCredentialBindingStore';
import type {
  EmailRecoveryPreparationStore,
  EmailRecoveryEcdsaPreparePayload,
  EmailRecoveryEcdsaPrepareTarget,
  EmailRecoveryResolvedWalletBinding,
} from '../EmailRecoveryPreparationStore';
import type { ThresholdEcdsaChainTarget } from '../thresholdEcdsaChainTarget';
import { thresholdEcdsaChainTargetKey } from '../thresholdEcdsaChainTarget';
import { DEFAULT_RECOVERY_SESSION_TTL_MS } from '../recoverySessionRecords';
import type {
  ThresholdRuntimePolicyScope,
  ThresholdEd25519AuthorityScope,
} from '../types';
import { registrationPreparationIdFromString } from '../registrationContracts';
import { randomBase64Url } from './bytes';
import { normalizeAdjacentFlowEcdsaPrepareSpec } from './walletRegistrationPlanning';
import {
  resolveBoundThresholdRuntimePolicyScope,
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
  'threshold_ecdsa_derivation_email_recovery_key_id_v1';
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
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootVersion: string;
}): ThresholdRuntimePolicyScope {
  return {
    ...input.runtimePolicyScope,
    signingRootVersion: input.signingRootVersion,
  };
}


async function computeEmailRecoveryEcdsaDerivationRoleLocalThresholdKeyId(input: {
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
  return `ederivation-recovery-${base64UrlEncode(digest32)}`;
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
  getDefaultRuntimePolicyScope?: () => ThresholdRuntimePolicyScope | undefined;
  webAuthnCredentialBindingStore: WebAuthnCredentialBindingStore;
  emailRecoveryPreparationStore: EmailRecoveryPreparationStore;
};

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
    runtimePolicyScope: ThresholdRuntimePolicyScope;
  }): Promise<EmailRecoveryEcdsaPreparePayload> {
    if (
      input.chainTargets.length === 0 ||
      input.participantIds.length !== 2 ||
      input.participantIds[0] !== 1 ||
      input.participantIds[1] !== 2
    ) {
      throw new Error('Email Recovery ECDSA requires one family and participant pair [1, 2]');
    }
    const targets: EmailRecoveryEcdsaPrepareTarget[] = [];
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
    const ecdsaThresholdKeyId = await computeEmailRecoveryEcdsaDerivationRoleLocalThresholdKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
      signingRootId: input.signingRootId,
      signingRootVersion,
      recoveryRequestId: input.recoveryRequestId,
    });
    const relayerKeyId = await computeEcdsaDerivationRoleLocalRelayerKeyId({
      walletId: input.walletId,
      evmFamilySigningKeySlotId,
    });
    for (const chainTarget of input.chainTargets) {
      const chainTargetKey = thresholdEcdsaChainTargetKey(chainTarget);
      targets.push({
        chainTarget,
        prepare: {
          formatVersion: 'ecdsa-derivation-role-local',
          walletId: input.walletId,
          evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: parseSdkEcdsaDerivationThresholdKeyId(
            ecdsaThresholdKeyId,
          ),
          signingRootId: input.signingRootId,
          signingRootVersion,
          keyScope: 'evm-family',
          relayerKeyId,
          registrationPreparationId: registrationPreparationIdFromString(
            `regprep_${randomBase64Url(24)}`,
          ),
          requestId: `${input.registrationCeremonyId}:ecdsa:${encodeURIComponent(chainTargetKey)}`,
          thresholdSessionId: `tederivation_${randomBase64Url(24)}`,
          signingGrantId: `wss_${randomBase64Url(24)}`,
          ttlMs: 10 * 60_000,
          remainingUses: REGISTRATION_WALLET_SIGNING_SESSION_REMAINING_USES,
          participantIds: [1, 2],
          runtimePolicyScope,
        },
      });
    }
    const firstTarget = targets[0];
    if (!firstTarget) {
      throw new Error('Email Recovery ECDSA requires at least one chain target');
    }
    return {
      kind: 'evm_family_ecdsa_recovery',
      targets: [firstTarget, ...targets.slice(1)],
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
        ecdsa: EmailRecoveryEcdsaPreparePayload;
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
      if (!ecdsaRuntimePolicyScope || !signingRootId || !signingRootVersion) {
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
        runtimePolicyScope: ecdsaRuntimePolicyScope,
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

}
