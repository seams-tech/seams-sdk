import {
  parseAppSessionVersion,
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseOrgId,
  parseProviderSubject,
} from '@shared/utils/domainIds';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { base64UrlEncode } from '@shared/utils/encoders';
import {
  addAuthMethodIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  normalizeEmailOtpRegistrationProof,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type RegistrationAuthority,
  type RegistrationIntentV1,
  type WalletId,
} from '@shared/utils/registrationIntent';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveWebAuthnAuthenticatorDeviceInfo,
  type WebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import {
  buildEmailOtpWalletAuthAuthority,
  type EmailOtpProvider,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { WalletAuthMethodStore } from '../../core/d1WalletAuthMethodStore';
import type {
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletAddSignerStartRequest,
  EmailOtpWalletRegistrationAuthorityInput,
  PasskeyWalletRegistrationAuthorityInput,
  WalletRegistrationAuthorityInput,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
} from '../../core/registrationContracts';
import { CloudflareD1EmailOtpChallengeVerifier } from './d1EmailOtpChallengeVerifier';
import {
  CloudflareD1RegistrationCeremonyIntentStore,
  missingRegistrationCeremonyDoStore,
} from './d1RegistrationCeremonyStore';
import { parseWalletIdForIntent } from './d1RegistrationCeremonyRecords';
import type { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from './d1GoogleEmailOtpRegistrationAttemptStore';
import {
  expiredGoogleEmailOtpRegistrationAttemptRecord,
  pendingGoogleEmailOtpRegistrationAttemptWithSelectedCandidate,
  runtimePolicyScopeKey,
} from './d1GoogleEmailOtpRegistrationRecords';
import { toRecordValue } from './d1RouterApiAuthBoundary';
import {
  activeWalletAuthMethodRecord,
  authorizeD1WalletAuthMethodRevoke,
  d1HostIsWithinWebAuthnRpId,
  d1WebAuthnOriginHostnameOrEmpty,
  findD1WalletAuthMethodRecordForRevokeTarget,
  parseD1RevokeWalletAuthMethodInput,
  parseD1WebAuthnClientDataJsonBase64url,
  resolveD1AddAuthMethodExistingAuth,
  resolveD1AddSignerExistingAuth,
  revokedD1WalletAuthMethodRecord,
  validateD1RevokeWalletAuthMethodPolicy,
  walletAuthAuthorityFromRegistrationAuthority,
  walletAuthMethodRecordFromRegistrationAuthority,
  type D1AddAuthMethodExistingAuthResolution,
  type D1AddSignerExistingAuthResolution,
} from './d1WalletAuthMethodBoundary';
import type { CloudflareD1WebAuthnStore } from './d1WebAuthnStore';

type StartWalletAddAuthMethodInput = WalletAddAuthMethodStartRequest;
type StartWalletAddAuthMethodResult = WalletAddAuthMethodStartResponse;
type FinalizeWalletAddAuthMethodInput = WalletAddAuthMethodFinalizeRequest;
type FinalizeWalletAddAuthMethodResult = WalletAddAuthMethodFinalizeResponse;
type RevokeWalletAuthMethodInput = WalletRevokeAuthMethodRequest;
type RevokeWalletAuthMethodResult = WalletRevokeAuthMethodResponse;
type WalletAuthMethodError = {
  readonly ok: false;
  readonly code: string;
  readonly message: string;
};
type WalletAuthMethodAuthorityResult =
  | {
      readonly ok: true;
      readonly authority: RegistrationAuthority;
    }
  | WalletAuthMethodError;

type SimpleWebAuthnVerifier = (args: unknown) => Promise<unknown>;
type SimpleWebAuthnServerModule = {
  readonly verifyRegistrationResponse?: SimpleWebAuthnVerifier;
};

type Sha256Bytes = (input: Uint8Array) => Promise<Uint8Array>;
type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore | null;
type WalletAuthMethodStoreProvider = () => WalletAuthMethodStore;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return hex;
}

function runtimePolicyScopeKeyForRegistrationIntent(input: unknown): string {
  try {
    return runtimePolicyScopeKey(normalizeRuntimePolicyScope(input));
  } catch {
    return '';
  }
}

function unreachableRegistrationStartAuthority(value: never): never {
  throw new Error(`Unhandled registration start authority kind: ${String(value)}`);
}

function unreachableAddAuthMethodAuthority(value: never): never {
  throw new Error(`Unhandled add-auth-method authority kind: ${String(value)}`);
}

async function loadSimpleWebAuthnServer(): Promise<SimpleWebAuthnServerModule> {
  try {
    return (await import('@simplewebauthn/server')) as SimpleWebAuthnServerModule;
  } catch (error: unknown) {
    throw new Error(
      `Server WebAuthn route selected but '@simplewebauthn/server' dependency is not available: ${
        errorMessage(error) || 'import failed'
      }`,
    );
  }
}

export class CloudflareD1WalletAuthMethodService {
  private readonly emailOtpChallengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getWalletAuthMethodStore: WalletAuthMethodStoreProvider;
  private readonly googleEmailOtpRegistrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
  private readonly sha256Bytes: Sha256Bytes;
  private readonly webAuthnStore: CloudflareD1WebAuthnStore;

  constructor(input: {
    readonly emailOtpChallengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getWalletAuthMethodStore: WalletAuthMethodStoreProvider;
    readonly googleEmailOtpRegistrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
    readonly sha256Bytes: Sha256Bytes;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
  }) {
    this.emailOtpChallengeVerifier = input.emailOtpChallengeVerifier;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getWalletAuthMethodStore = input.getWalletAuthMethodStore;
    this.googleEmailOtpRegistrationAttempts = input.googleEmailOtpRegistrationAttempts;
    this.sha256Bytes = input.sha256Bytes;
    this.webAuthnStore = input.webAuthnStore;
  }

  async startWalletAddAuthMethod(
    request: StartWalletAddAuthMethodInput,
    context?: { readonly userAgent?: string },
  ): Promise<StartWalletAddAuthMethodResult> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const walletId = parseWalletIdForIntent(request.walletId);
      if (!walletId) {
        return { ok: false, code: 'invalid_body', message: 'walletId is required' };
      }
      const grant = addAuthMethodIntentGrantFromString(
        toOptionalTrimmedString(request.addAuthMethodIntentGrant) || '',
      );
      if (!grant) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant is required',
        };
      }
      const intentPreview = await store.getAddAuthMethodIntent(grant);
      if (!intentPreview) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      if (request.intent.walletId !== walletId) {
        return { ok: false, code: 'invalid_body', message: 'add-auth-method walletId mismatch' };
      }
      const digestB64u = toOptionalTrimmedString(request.addAuthMethodIntentDigestB64u);
      const requestDigest = await computeAddAuthMethodIntentDigestB64u(request.intent);
      if (!digestB64u || digestB64u !== requestDigest || digestB64u !== intentPreview.digestB64u) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method intent digest mismatch',
        };
      }

      const storedAuth = await this.resolveAddAuthMethodExistingAuth({
        auth: request.auth,
        walletId,
        intent: intentPreview.intent,
        nowMs: Date.now(),
      });
      if (!storedAuth.ok) return storedAuth;

      const storedIntent = await store.takeAddAuthMethodIntent(grant);
      if (!storedIntent) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin);
      if (request.authority.kind === 'passkey' && !storedExpectedOrigin) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'expected_origin is required for WebAuthn registration verification',
        };
      }
      const authority = await this.verifyAddAuthMethodAuthority({
        orgId: storedIntent.orgId,
        authority: request.authority,
        expectedDigestB64u: storedIntent.digestB64u,
        expectedOrigin: storedExpectedOrigin || '',
        intent: storedIntent.intent,
        userAgent: context?.userAgent,
      });
      if (!authority.ok) return authority;

      const addAuthMethodCeremonyId = `wauthc_${secureRandomBase64Url(24)}`;
      await store.putAddAuthMethodCeremony({
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
        digestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
        expiresAtMs: Date.now() + 10 * 60_000,
        auth: storedAuth.auth,
        authority: authority.authority,
      });
      return {
        ok: true,
        addAuthMethodCeremonyId,
        intent: storedIntent.intent,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-auth-method ceremony',
      };
    }
  }

  async finalizeWalletAddAuthMethod(
    request: FinalizeWalletAddAuthMethodInput,
  ): Promise<FinalizeWalletAddAuthMethodResult> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      if (!store) return missingRegistrationCeremonyDoStore();
      const ceremony = await store.getAddAuthMethodCeremony(request.addAuthMethodCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
      }
      const duplicate = await this.findDuplicateAuthority(ceremony.authority);
      if (duplicate) return duplicate;
      const consumed = await store.takeAddAuthMethodCeremony(ceremony.addAuthMethodCeremonyId);
      if (!consumed) {
        return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
      }
      await this.persistAuthority({
        authority: consumed.authority,
        now: Date.now(),
      });
      const authority = walletAuthAuthorityFromRegistrationAuthority(consumed.authority);
      return {
        ok: true,
        walletId: consumed.intent.walletId,
        authority,
        ...(consumed.authority.kind === 'passkey' ? { rpId: consumed.authority.rpId } : {}),
        authMethod: {
          kind: consumed.authority.kind,
          status: 'active',
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-auth-method ceremony',
      };
    }
  }

  async resolveAddSignerExistingAuth(input: {
    readonly auth: WalletAddSignerStartRequest['auth'];
    readonly walletId: WalletId;
    readonly intent: AddSignerIntentV1;
    readonly nowMs: number;
  }): Promise<D1AddSignerExistingAuthResolution> {
    return await resolveD1AddSignerExistingAuth({
      auth: input.auth,
      walletId: input.walletId,
      intent: input.intent,
      walletAuthMethodStore: this.getWalletAuthMethodStore(),
      nowMs: input.nowMs,
    });
  }

  async resolveAddAuthMethodExistingAuth(input: {
    readonly auth: WalletAddAuthMethodStartRequest['auth'];
    readonly walletId: WalletId;
    readonly intent: AddAuthMethodIntentV1;
    readonly nowMs: number;
  }): Promise<D1AddAuthMethodExistingAuthResolution> {
    const walletAuthMethodStore = this.getWalletAuthMethodStore();
    const walletMethods = await walletAuthMethodStore.listForWallet({
      walletId: input.walletId,
    });
    const activeWalletMethods = walletMethods.filter(activeWalletAuthMethodRecord);
    if (activeWalletMethods.length === 0) {
      return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
    }
    return await resolveD1AddAuthMethodExistingAuth({
      auth: input.auth,
      walletId: input.walletId,
      intent: input.intent,
      walletAuthMethodStore,
      nowMs: input.nowMs,
    });
  }

  async verifyRegistrationAuthorityForIntent(input: {
    readonly orgId: string;
    readonly authority: WalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: RegistrationIntentV1;
    readonly userAgent?: string;
  }): Promise<WalletAuthMethodAuthorityResult> {
    const authority = input.authority;
    switch (authority.kind) {
      case 'passkey':
        return await this.verifyRegistrationPasskeyAuthority({
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          expectedOrigin: input.expectedOrigin,
          intent: input.intent,
          userAgent: input.userAgent,
        });
      case 'email_otp':
        return await this.verifyRegistrationEmailOtpAuthority({
          orgId: input.orgId,
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          intent: input.intent,
        });
    }
    return unreachableRegistrationStartAuthority(authority);
  }

  async verifyActivePasskeyAuthority(
    authority: PasskeyWalletAuthAuthority,
  ): Promise<{ readonly ok: true } | WalletAuthMethodError> {
    const record = await this.getWalletAuthMethodStore().getPasskey({
      rpId: authority.verifier.rpId,
      credentialIdB64u: authority.factor.credentialIdB64u,
    });
    if (
      !record ||
      record.kind !== 'passkey' ||
      record.status !== 'active' ||
      record.walletId !== authority.walletId ||
      record.rpId !== authority.verifier.rpId ||
      record.credentialIdB64u !== authority.factor.credentialIdB64u
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Passkey authority is not active for this wallet',
      };
    }
    return { ok: true };
  }

  async verifyActiveEmailOtpAuthority(
    authority: EmailOtpWalletAuthAuthority,
  ): Promise<{ readonly ok: true } | WalletAuthMethodError> {
    const record = await this.getWalletAuthMethodStore().getEmailOtp({
      walletId: authority.walletId,
      emailHashHex: authority.verifier.emailHashHex,
    });
    if (
      !record ||
      record.kind !== 'email_otp' ||
      record.status !== 'active' ||
      record.walletId !== authority.walletId ||
      record.emailHashHex !== authority.verifier.emailHashHex
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Email OTP authority is not active for this wallet',
      };
    }
    return { ok: true };
  }

  async resolveActiveEmailOtpAuthorityForVerifiedSubject(input: {
    readonly walletId: string;
    readonly providerUserId: string;
  }): Promise<
    { readonly ok: true; readonly authority: EmailOtpWalletAuthAuthority } | WalletAuthMethodError
  > {
    const walletId = toOptionalTrimmedString(input.walletId);
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    if (!walletId || !providerUserId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Verified Email OTP authority identity is required',
      };
    }
    const records = [];
    for (const record of await this.getWalletAuthMethodStore().listForWallet({ walletId })) {
      if (record.kind === 'email_otp' && record.status === 'active') {
        records.push(record);
      }
    }
    if (records.length !== 1) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Wallet requires one exact active Email OTP authority',
      };
    }
    const record = records[0];
    if (!record || record.kind !== 'email_otp') {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Wallet Email OTP authority is unavailable',
      };
    }
    const provider: EmailOtpProvider = providerUserId.startsWith('google:') ? 'google' : 'email';
    try {
      return {
        ok: true,
        authority: buildEmailOtpWalletAuthAuthority({
          walletId,
          provider,
          providerUserId,
          emailHashHex: record.emailHashHex,
        }),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'invalid_state',
        message: errorMessage(error) || 'Stored Email OTP authority is invalid',
      };
    }
  }

  async verifyAddAuthMethodAuthority(input: {
    readonly orgId: string;
    readonly authority: StartWalletAddAuthMethodInput['authority'];
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly userAgent?: string;
  }): Promise<WalletAuthMethodAuthorityResult> {
    const authority = input.authority;
    switch (authority.kind) {
      case 'passkey':
        return await this.verifyAddAuthMethodPasskeyAuthority({
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          expectedOrigin: input.expectedOrigin,
          intent: input.intent,
          userAgent: input.userAgent,
        });
      case 'email_otp':
        return await this.verifyAddAuthMethodEmailOtpAuthority({
          orgId: input.orgId,
          authority,
          expectedDigestB64u: input.expectedDigestB64u,
          intent: input.intent,
        });
    }
    return unreachableAddAuthMethodAuthority(authority);
  }

  async findDuplicateAuthority(
    authority: RegistrationAuthority,
  ): Promise<WalletAuthMethodError | null> {
    if (authority.kind === 'passkey') {
      const duplicateCredential = await this.getWalletAuthMethodStore().getPasskey({
        rpId: authority.rpId,
        credentialIdB64u: authority.credentialIdB64u,
      });
      return duplicateCredential
        ? {
            ok: false,
            code: 'duplicate_auth_method',
            message: 'Passkey credential is already registered',
          }
        : null;
    }
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
      walletId: authority.walletId,
      emailHashHex: authority.emailHashHex,
    });
    return duplicateEmailOtp && duplicateEmailOtp.status === 'active'
      ? {
          ok: false,
          code: 'duplicate_auth_method',
          message: 'Email OTP auth method is already registered',
        }
      : null;
  }

  async persistAuthority(input: {
    readonly authority: RegistrationAuthority;
    readonly now: number;
  }): Promise<void> {
    if (input.authority.kind === 'passkey') {
      await this.webAuthnStore.writeAuthenticator({
        userId: input.authority.walletId,
        record: {
          credentialIdB64u: input.authority.credentialIdB64u,
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
          deviceInfo: input.authority.device,
        },
      });
    }
    await this.getWalletAuthMethodStore().put(
      walletAuthMethodRecordFromRegistrationAuthority({
        authority: input.authority,
        now: input.now,
      }),
    );
  }

  async revokeWalletAuthMethod(
    input: RevokeWalletAuthMethodInput,
  ): Promise<RevokeWalletAuthMethodResult> {
    try {
      const parsed = parseD1RevokeWalletAuthMethodInput(input);
      if (!parsed.ok) return parsed.result;
      const policyError = validateD1RevokeWalletAuthMethodPolicy({
        auth: parsed.auth,
        walletId: parsed.walletId,
        target: parsed.target,
        nowMs: Date.now(),
      });
      if (policyError) return policyError;

      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const walletMethods = await walletAuthMethodStore.listForWallet({
        walletId: parsed.walletId,
      });
      const activeWalletMethods = walletMethods.filter(activeWalletAuthMethodRecord);
      if (activeWalletMethods.length === 0) {
        return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
      }
      const authorizationError = await authorizeD1WalletAuthMethodRevoke({
        walletAuthMethodStore,
        walletId: parsed.walletId,
        auth: parsed.auth,
      });
      if (authorizationError) return authorizationError;

      const targetRecord = await findD1WalletAuthMethodRecordForRevokeTarget({
        walletAuthMethodStore,
        walletId: parsed.walletId,
        target: parsed.target,
        emailHash: this.emailHashHex.bind(this),
      });
      if (!targetRecord) {
        return { ok: false, code: 'not_found', message: 'wallet auth method not found' };
      }
      if (targetRecord.status !== 'active') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet auth method is already revoked',
        };
      }
      if (activeWalletMethods.length <= 1) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet must retain at least one active auth method',
        };
      }
      await walletAuthMethodStore.put(
        revokedD1WalletAuthMethodRecord({
          record: targetRecord,
          updatedAtMs: Date.now(),
        }),
      );
      if (targetRecord.kind === 'passkey') {
        return {
          ok: true,
          walletId: parsed.walletId,
          authMethod: {
            kind: 'passkey',
            status: 'revoked',
          },
          rpId: targetRecord.rpId,
        };
      }
      return {
        ok: true,
        walletId: parsed.walletId,
        authMethod: {
          kind: 'email_otp',
          status: 'revoked',
        },
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to revoke wallet auth method',
      };
    }
  }

  private async verifyRegistrationCredentialForIntent(input: {
    readonly webauthnRegistration: unknown;
    readonly expectedChallenge: string;
    readonly expectedOrigin: string;
    readonly rpId: string;
    readonly userAgent?: string;
  }): Promise<
    | {
        readonly ok: true;
        readonly credential: {
          readonly credentialIdB64u: string;
          readonly credentialPublicKeyB64u: string;
          readonly counter: number;
          readonly device: WebAuthnAuthenticatorDeviceInfo;
        };
      }
    | WalletAuthMethodError
  > {
    const credential = toRecordValue(input.webauthnRegistration);
    if (!credential) {
      return { ok: false, code: 'invalid_body', message: 'Missing webauthn_registration' };
    }
    const response = toRecordValue(credential.response);
    const clientDataJSON = toOptionalTrimmedString(response?.clientDataJSON);
    const clientData = parseD1WebAuthnClientDataJsonBase64url(clientDataJSON);
    if (clientData.type !== 'webauthn.create') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid webauthn_registration.clientDataJSON.type (expected webauthn.create)',
      };
    }
    if (clientData.challenge !== input.expectedChallenge) {
      return { ok: false, code: 'challenge_mismatch', message: 'Registration challenge mismatch' };
    }
    const expectedOrigin = toOptionalTrimmedString(input.expectedOrigin);
    if (!expectedOrigin) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'expected_origin is required for WebAuthn registration verification',
      };
    }
    if (
      !d1HostIsWithinWebAuthnRpId(d1WebAuthnOriginHostnameOrEmpty(clientData.origin), input.rpId)
    ) {
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
    const registration = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge: input.expectedChallenge,
      expectedOrigin,
      expectedRPID: input.rpId,
      requireUserVerification: false,
    });
    const registrationRecord = toRecordValue(registration);
    if (registrationRecord?.verified !== true) {
      return { ok: false, code: 'not_verified', message: 'Registration verification failed' };
    }
    const registrationInfo = toRecordValue(registrationRecord.registrationInfo);
    const credentialInfo = toRecordValue(registrationInfo?.credential);
    const credentialIdB64u = toOptionalTrimmedString(credentialInfo?.id);
    const publicKey = credentialInfo?.publicKey;
    if (!credentialInfo || !credentialIdB64u || !(publicKey instanceof Uint8Array)) {
      return {
        ok: false,
        code: 'internal',
        message: 'Registration verification did not return credential public key material',
      };
    }
    const counter = Number(credentialInfo.counter);
    /* device facts: UA from the registering request, AAGUID + backup flag from
       the verified attestation, transports from the credential response */
    const transports = Array.isArray(credentialInfo.transports)
      ? credentialInfo.transports.filter((t): t is string => typeof t === 'string')
      : Array.isArray(response?.transports)
        ? (response.transports as unknown[]).filter((t): t is string => typeof t === 'string')
        : [];
    const device = deriveWebAuthnAuthenticatorDeviceInfo({
      userAgent: input.userAgent,
      aaguid: toOptionalTrimmedString(registrationInfo?.aaguid) || '',
      backedUp: registrationInfo?.credentialBackedUp === true,
      transports,
    });
    return {
      ok: true,
      credential: {
        credentialIdB64u,
        credentialPublicKeyB64u: base64UrlEncode(publicKey),
        counter: Number.isFinite(counter) && counter >= 0 ? Math.floor(counter) : 0,
        device,
      },
    };
  }

  private async verifyRegistrationPasskeyAuthority(input: {
    readonly authority: PasskeyWalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: RegistrationIntentV1;
    readonly userAgent?: string;
  }): Promise<WalletAuthMethodAuthorityResult> {
    if (input.intent.authMethod.kind !== 'passkey') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Passkey registration authority requires a passkey intent',
      };
    }
    const verified = await this.verifyRegistrationCredentialForIntent({
      webauthnRegistration: input.authority.webauthnRegistration,
      expectedChallenge: input.expectedDigestB64u,
      expectedOrigin: input.expectedOrigin,
      rpId: input.intent.authMethod.rpId,
      userAgent: input.userAgent,
    });
    if (!verified.ok) return verified;
    const duplicateCredential = await this.getWalletAuthMethodStore().getPasskey({
      rpId: input.intent.authMethod.rpId,
      credentialIdB64u: verified.credential.credentialIdB64u,
    });
    if (duplicateCredential) {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Passkey credential is already registered',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'passkey',
        walletId: input.intent.walletId,
        rpId: input.intent.authMethod.rpId,
        credentialIdB64u: verified.credential.credentialIdB64u,
        credentialPublicKeyB64u: verified.credential.credentialPublicKeyB64u,
        counter: verified.credential.counter,
        device: verified.credential.device,
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async verifyRegistrationEmailOtpAuthority(input: {
    readonly orgId: string;
    readonly authority: EmailOtpWalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly intent: RegistrationIntentV1;
  }): Promise<WalletAuthMethodAuthorityResult> {
    const proof = normalizeEmailOtpRegistrationProof(input.authority.emailOtpRegistrationProof);
    if (!proof) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpRegistrationProof is required for Email OTP registration',
      };
    }
    if (proof.registrationIntentDigestB64u !== input.expectedDigestB64u) {
      return {
        ok: false,
        code: 'registration_intent_digest_mismatch',
        message: 'Email OTP registration proof is not bound to this registration intent',
      };
    }
    if (input.intent.authMethod.kind !== 'email_otp') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration authority requires an Email OTP intent',
      };
    }
    if (proof.proofKind === 'google_sso_registration') {
      if (input.intent.authMethod.proofKind !== 'google_sso_registration') {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Google SSO registration proof requires a Google SSO registration intent',
        };
      }
      if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
        return {
          ok: false,
          code: 'email_mismatch',
          message: 'Email OTP registration proof email does not match the intent',
        };
      }
      if (
        proof.googleEmailOtpRegistrationAttemptId !==
        input.intent.authMethod.googleEmailOtpRegistrationAttemptId
      ) {
        return {
          ok: false,
          code: 'registration_attempt_mismatch',
          message: 'Google SSO registration proof does not match the registration attempt',
        };
      }
      if (
        proof.googleEmailOtpRegistrationOfferId !==
          input.intent.authMethod.googleEmailOtpRegistrationOfferId ||
        proof.googleEmailOtpRegistrationCandidateId !==
          input.intent.authMethod.googleEmailOtpRegistrationCandidateId
      ) {
        return {
          ok: false,
          code: 'registration_offer_mismatch',
          message: 'Google SSO registration proof does not match the selected offer candidate',
        };
      }
      const attempt = await this.googleEmailOtpRegistrationAttempts.read(
        proof.googleEmailOtpRegistrationAttemptId,
      );
      if (!attempt) {
        return {
          ok: false,
          code: 'registration_attempt_missing',
          message: 'Google Email OTP registration attempt expired or was not found',
        };
      }
      if (attempt.state !== 'started' && attempt.state !== 'key_finalized') {
        return {
          ok: false,
          code: 'registration_attempt_not_started',
          message: 'Google Email OTP registration attempt is not active',
        };
      }
      if (attempt.expiresAtMs <= Date.now()) {
        await this.googleEmailOtpRegistrationAttempts.put(
          expiredGoogleEmailOtpRegistrationAttemptRecord({
            record: attempt,
            updatedAtMs: Date.now(),
          }),
        );
        return {
          ok: false,
          code: 'registration_attempt_expired',
          message: 'Google Email OTP registration attempt expired',
        };
      }
      if (attempt.providerSubject !== proof.providerSubject) {
        return {
          ok: false,
          code: 'challenge_subject_mismatch',
          message: 'Email OTP registration attempt does not match the provider subject',
        };
      }
      if (attempt.email.toLowerCase() !== proof.email) {
        return {
          ok: false,
          code: 'email_mismatch',
          message: 'Google Email OTP registration attempt email does not match the proof',
        };
      }
      if (attempt.appSessionVersion !== proof.appSessionVersion) {
        return {
          ok: false,
          code: 'app_session_version_mismatch',
          message: 'Google Email OTP registration attempt does not match the app session',
        };
      }
      if (attempt.offerId !== proof.googleEmailOtpRegistrationOfferId) {
        return {
          ok: false,
          code: 'registration_offer_mismatch',
          message: 'Google Email OTP registration attempt does not match the selected offer',
        };
      }
      const selectedOfferCandidate = attempt.offerCandidates.find(
        (candidate) => candidate.candidateId === proof.googleEmailOtpRegistrationCandidateId,
      );
      if (!selectedOfferCandidate || selectedOfferCandidate.walletId !== input.intent.walletId) {
        return {
          ok: false,
          code: 'registration_candidate_mismatch',
          message: 'Google Email OTP registration candidate does not match walletId',
        };
      }
      if (
        attempt.walletId !== selectedOfferCandidate.walletId ||
        attempt.selectedCandidateId !== selectedOfferCandidate.candidateId ||
        attempt.collisionCounter !== selectedOfferCandidate.collisionCounter
      ) {
        await this.googleEmailOtpRegistrationAttempts.put(
          pendingGoogleEmailOtpRegistrationAttemptWithSelectedCandidate({
            record: attempt,
            candidate: selectedOfferCandidate,
            updatedAtMs: Date.now(),
          }),
        );
      }
      if (
        runtimePolicyScopeKey(attempt.runtimePolicyScope) !==
        runtimePolicyScopeKeyForRegistrationIntent(input.intent.runtimePolicyScope)
      ) {
        return {
          ok: false,
          code: 'runtime_policy_scope_mismatch',
          message: 'Google Email OTP registration attempt does not match runtime policy scope',
        };
      }
      const providerSubject = parseProviderSubject(proof.providerSubject);
      const finalWalletId = parseWalletIdForIntent(input.intent.walletId);
      const orgId = parseOrgId(input.orgId);
      const appSessionVersion = parseAppSessionVersion(proof.appSessionVersion);
      if (!providerSubject.ok || !finalWalletId || !orgId.ok || !appSessionVersion.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Google SSO registration proof contains invalid domain fields',
        };
      }
      const email = attempt.email.toLowerCase();
      const emailHashHex = await this.emailHashHex(email);
      const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
        walletId: finalWalletId,
        emailHashHex,
      });
      if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
        return {
          ok: false,
          code: 'duplicate_auth_method',
          message: 'Email OTP auth method is already registered',
        };
      }
      return {
        ok: true,
        authority: {
          kind: 'email_otp',
          proofKind: 'google_sso_registration',
          walletId: finalWalletId,
          providerSubject: providerSubject.value,
          email,
          emailHashHex,
          googleEmailOtpRegistrationAttemptId: attempt.attemptId,
          googleEmailOtpRegistrationOfferId: attempt.offerId,
          googleEmailOtpRegistrationCandidateId: selectedOfferCandidate.candidateId,
          registrationAuthorityId: attempt.attemptId,
          finalWalletId,
          orgId: orgId.value,
          appSessionVersion: appSessionVersion.value,
          registrationIntentDigestB64u: input.expectedDigestB64u,
        },
      };
    }
    if (input.intent.authMethod.proofKind !== 'otp_challenge') {
      return {
        ok: false,
        code: 'unsupported',
        message:
          'Cloudflare D1 registration start currently supports direct Email OTP challenge intent',
      };
    }
    if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Email OTP registration proof email does not match the intent',
      };
    }
    const verified = await this.emailOtpChallengeVerifier.verifyRegistration({
      providerSubject: proof.providerSubject,
      proofEmail: proof.email,
      walletId: input.intent.walletId,
      orgId: input.orgId,
      challengeId: proof.challengeId,
      otpCode: proof.otpCode,
      otpChannel: proof.otpChannel,
      sessionHash: input.expectedDigestB64u,
      appSessionVersion: proof.appSessionVersion,
    });
    if (!verified.ok) return verified;
    const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
    if (verifiedEmail !== proof.email) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Verified Email OTP address does not match the registration proof',
      };
    }
    const emailHashHex = await this.emailHashHex(proof.email);
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
      walletId: input.intent.walletId,
      emailHashHex,
    });
    if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Email OTP auth method is already registered',
      };
    }
    const providerSubject = parseProviderSubject(proof.providerSubject);
    const challengeSubjectId = parseChallengeSubjectId(proof.providerSubject);
    const challengeId = parseEmailOtpChallengeId(proof.challengeId);
    const orgId = parseOrgId(input.orgId);
    const appSessionVersion = parseAppSessionVersion(proof.appSessionVersion);
    if (
      !providerSubject.ok ||
      !challengeSubjectId.ok ||
      !challengeId.ok ||
      !orgId.ok ||
      !appSessionVersion.ok
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration proof contains invalid domain fields',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        walletId: input.intent.walletId,
        providerSubject: providerSubject.value,
        challengeSubjectId: challengeSubjectId.value,
        email: proof.email,
        emailHashHex,
        challengeId: challengeId.value,
        registrationAuthorityId: challengeId.value,
        originalWalletId: input.intent.walletId,
        finalWalletId: input.intent.walletId,
        orgId: orgId.value,
        appSessionVersion: appSessionVersion.value,
        challengePurpose: 'registration',
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async verifyAddAuthMethodPasskeyAuthority(input: {
    readonly authority: PasskeyWalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly expectedOrigin: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly userAgent?: string;
  }): Promise<WalletAuthMethodAuthorityResult> {
    if (input.intent.authMethod.kind !== 'passkey') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Passkey add-auth-method authority requires a passkey intent',
      };
    }
    const verified = await this.verifyRegistrationCredentialForIntent({
      webauthnRegistration: input.authority.webauthnRegistration,
      expectedChallenge: input.expectedDigestB64u,
      expectedOrigin: input.expectedOrigin,
      rpId: input.intent.authMethod.rpId,
      userAgent: input.userAgent,
    });
    if (!verified.ok) return verified;
    const duplicateCredential = await this.getWalletAuthMethodStore().getPasskey({
      rpId: input.intent.authMethod.rpId,
      credentialIdB64u: verified.credential.credentialIdB64u,
    });
    if (duplicateCredential) {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Passkey credential is already registered',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'passkey',
        walletId: input.intent.walletId,
        rpId: input.intent.authMethod.rpId,
        credentialIdB64u: verified.credential.credentialIdB64u,
        credentialPublicKeyB64u: verified.credential.credentialPublicKeyB64u,
        counter: verified.credential.counter,
        device: verified.credential.device,
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async verifyAddAuthMethodEmailOtpAuthority(input: {
    readonly orgId: string;
    readonly authority: EmailOtpWalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly intent: AddAuthMethodIntentV1;
  }): Promise<WalletAuthMethodAuthorityResult> {
    const proof = input.authority.emailOtpRegistrationProof;
    if (proof.proofKind !== 'otp_challenge') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP add-auth-method requires an OTP challenge proof',
      };
    }
    if (proof.registrationIntentDigestB64u !== input.expectedDigestB64u) {
      return {
        ok: false,
        code: 'registration_intent_digest_mismatch',
        message: 'Email OTP registration proof is not bound to this add-auth-method intent',
      };
    }
    if (input.intent.authMethod.kind !== 'email_otp') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP add-auth-method authority requires an Email OTP intent',
      };
    }
    if (proof.email !== input.intent.authMethod.email.toLowerCase()) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Email OTP registration proof email does not match the intent',
      };
    }
    const verified = await this.emailOtpChallengeVerifier.verifyRegistration({
      providerSubject: proof.providerSubject,
      proofEmail: proof.email,
      walletId: input.intent.walletId,
      orgId: input.orgId,
      challengeId: proof.challengeId,
      otpCode: proof.otpCode,
      otpChannel: proof.otpChannel,
      sessionHash: input.expectedDigestB64u,
      appSessionVersion: proof.appSessionVersion,
    });
    if (!verified.ok) return verified;
    const verifiedEmail = toOptionalTrimmedString(verified.email)?.toLowerCase();
    if (verifiedEmail !== proof.email) {
      return {
        ok: false,
        code: 'email_mismatch',
        message: 'Verified Email OTP address does not match the registration proof',
      };
    }
    const emailHashHex = await this.emailHashHex(proof.email);
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtp({
      walletId: input.intent.walletId,
      emailHashHex,
    });
    if (duplicateEmailOtp && duplicateEmailOtp.status === 'active') {
      return {
        ok: false,
        code: 'duplicate_auth_method',
        message: 'Email OTP auth method is already registered',
      };
    }
    const providerSubject = parseProviderSubject(proof.providerSubject);
    const challengeSubjectId = parseChallengeSubjectId(proof.providerSubject);
    const challengeId = parseEmailOtpChallengeId(proof.challengeId);
    const orgId = parseOrgId(input.orgId);
    const appSessionVersion = parseAppSessionVersion(proof.appSessionVersion);
    if (
      !providerSubject.ok ||
      !challengeSubjectId.ok ||
      !challengeId.ok ||
      !orgId.ok ||
      !appSessionVersion.ok
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Email OTP registration proof contains invalid domain fields',
      };
    }
    return {
      ok: true,
      authority: {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        walletId: input.intent.walletId,
        providerSubject: providerSubject.value,
        challengeSubjectId: challengeSubjectId.value,
        email: proof.email,
        emailHashHex,
        challengeId: challengeId.value,
        registrationAuthorityId: challengeId.value,
        originalWalletId: input.intent.walletId,
        finalWalletId: input.intent.walletId,
        orgId: orgId.value,
        appSessionVersion: appSessionVersion.value,
        challengePurpose: 'registration',
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async emailHashHex(email: string): Promise<string> {
    return bytesToHex(await this.sha256Bytes(new TextEncoder().encode(email)));
  }
}
