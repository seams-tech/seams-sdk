import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWalletAddAuthMethodRegistrationOptions } from '@shared/utils/addAuthMethodRegistration';
import {
  parseChallengeSubjectId,
  parseEmailOtpChallengeId,
  parseWalletAuthMethodId,
  parseOrgId,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  PASSKEY_PRF_FIRST_SALT_V1,
  PASSKEY_PRF_SECOND_SALT_V1,
} from '@shared/utils/signingSessionSeal';
import {
  addAuthMethodIntentGrantFromString,
  buildWalletAuthMethodRecordV2,
  computeWalletAuthMethodRevokeOperationFingerprintV1,
  computeAddAuthMethodIntentDigestB64u,
  normalizeEmailOtpRegistrationProof,
  type AddAuthMethodIntentV1,
  type AddSignerIntentV1,
  type RegistrationAuthority,
  type RegistrationIntentV1,
  type WalletId,
  type WalletAuthMethodRevocationProof,
  type WalletAuthMethodRecordV2,
} from '@shared/utils/registrationIntent';
import { admitAddWalletAuthMethod } from '@shared/utils/addWalletAuthMethod';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  deriveWebAuthnAuthenticatorDeviceInfo,
  type WebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import {
  buildEmailOtpWalletAuthAuthority,
  walletAuthAuthorityRef,
  type EmailOtpProvider,
  type EmailOtpWalletAuthAuthority,
  type PasskeyWalletAuthAuthority,
  type WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import type { D1WalletAuthMethodStore } from '../../../../core/d1WalletAuthMethodStore';
import type { StoredWalletAddAuthMethodCeremony } from '../../../../core/RegistrationCeremonyStore';
import type {
  WalletAddAuthMethodFinalizeResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletAddAuthMethodRegistrationOptions,
  WalletAddSignerStartRequest,
  EmailOtpWalletRegistrationAuthorityInput,
  PasskeyWalletRegistrationAuthorityInput,
  WalletRegistrationAuthorityInput,
  WalletRevokeAuthMethodResponse,
} from '../../../../core/registrationContracts';
import {
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
} from '@shared/passkey-custody';
import { CloudflareD1EmailOtpChallengeVerifier } from '../emailOtp/d1EmailOtpChallengeVerifier';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../registration/d1RegistrationCeremonyStore';
import { parseWalletIdForIntent } from '../registration/d1RegistrationCeremonyRecords';
import type { CloudflareD1GoogleEmailOtpRegistrationAttemptStore } from '../emailOtp/d1GoogleEmailOtpRegistrationAttemptStore';
import {
  expiredGoogleEmailOtpRegistrationAttemptRecord,
  pendingGoogleEmailOtpRegistrationAttemptWithSelectedCandidate,
  runtimePolicyScopeKey,
} from '../emailOtp/d1GoogleEmailOtpRegistrationRecords';
import { toRecordValue } from '../auth/d1RouterApiAuthBoundary';
import {
  d1HostIsWithinWebAuthnRpId,
  resolveD1AddAuthMethodExistingAuth,
  resolveD1AddSignerExistingAuth,
  verifyD1LinkedDeviceFreshRevokeProofV1,
  walletAuthAuthorityFromRegistrationAuthority,
  type D1FreshRevokeWebAuthnVerifierV1,
  type D1AddAuthMethodExistingAuthResolution,
  type D1AddSignerExistingAuthResolution,
} from './d1WalletAuthMethodBoundary';
import {
  parseWebAuthnClientDataJsonBase64url,
  webAuthnOriginHostnameOrEmpty,
} from '../../../auth/webAuthnCredentialCodecs';
import type { CloudflareD1WebAuthnStore } from '../webauthn/d1WebAuthnStore';
import type { WebAuthnCredentialBindingRecord } from '../../../../core/WebAuthnCredentialBindingStore';
import type { CloudflareD1PasskeyCustodyEnvelopeStore } from '../passkeyCustody/d1PasskeyCustodyEnvelopeStore';
import type { D1WalletAuthorityStore } from './d1WalletAuthorityStore';
import {
  buildDelegatedWalletAuthorityV1,
  buildFullOwnerPermissionsV1,
  sameDelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import {
  resolveWalletAuthMethodIdForAuthority,
  type WalletExecutionLaneAuthSource,
} from '../../../../core/signingLanes/WalletExecutionLaneProjection';
import type {
  ActiveWalletSessionAuthorityResolution,
  FinalizeWalletAddAuthMethodCommand,
  RevokeWalletAuthMethodCommand,
  StartWalletAddAuthMethodCommand,
  WalletAuthMethodRevokeProofVerificationResult,
  WalletUnlockEmailOtpAuthorityResolution,
  WalletUnlockPasskeyAuthorityResolution,
} from '../../../framework/authServicePort';

type StartWalletAddAuthMethodInput = StartWalletAddAuthMethodCommand;
type StartWalletAddAuthMethodResult = WalletAddAuthMethodStartResponse;
/** Long enough for a device to retry across a reload, short of ceremony scale. */
const ADD_AUTH_METHOD_FINALIZE_REPLAY_TTL_MS = 24 * 60 * 60 * 1000;

type FinalizeWalletAddAuthMethodInput = FinalizeWalletAddAuthMethodCommand;
type FinalizeWalletAddAuthMethodResult = WalletAddAuthMethodFinalizeResponse;
type RevokeWalletAuthMethodInput = RevokeWalletAuthMethodCommand;
type RevokeWalletAuthMethodResult = WalletRevokeAuthMethodResponse;
type OwnerWalletSessionRevocationStatementsV1 = (input: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly requestedAtMs: number;
}) => readonly D1PreparedStatementLike[];
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
type RegistrationCeremonyStoreProvider = () => CloudflareD1RegistrationCeremonyIntentStore;
type WalletAuthMethodStoreProvider = () => D1WalletAuthMethodStore;

type PasskeyAddAuthMethodIntent = AddAuthMethodIntentV1 & {
  readonly authMethod: Extract<AddAuthMethodIntentV1['authMethod'], { kind: 'passkey' }>;
};
type EmailOtpAddAuthMethodIntent = AddAuthMethodIntentV1 & {
  readonly authMethod: Extract<AddAuthMethodIntentV1['authMethod'], { kind: 'email_otp' }>;
};

function isPasskeyAddAuthMethodIntent(
  intent: AddAuthMethodIntentV1,
): intent is PasskeyAddAuthMethodIntent {
  return intent.authMethod.kind === 'passkey';
}

function isEmailOtpAddAuthMethodIntent(
  intent: AddAuthMethodIntentV1,
): intent is EmailOtpAddAuthMethodIntent {
  return intent.authMethod.kind === 'email_otp';
}

function isActiveWalletAuthMethodRecordV2(
  record: WalletAuthMethodRecordV2,
): record is Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }> {
  return record.status === 'active';
}

function requireStoredRpId(raw: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(raw);
  if (!parsed.ok) throw new Error('Stored passkey RP ID is invalid');
  return parsed.value;
}

function requireStoredCredentialId(raw: string): WebAuthnCredentialIdB64u {
  const parsed = parseWebAuthnCredentialIdB64u(raw);
  if (!parsed.ok) throw new Error('Stored passkey credential ID is invalid');
  return parsed.value;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error || '');
}

function allocateWalletAuthMethodId(): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(`wallet-auth-method:${secureRandomBase64Url(32)}`);
  if (!parsed.ok)
    throw new Error(`Generated wallet auth-method ID is invalid: ${parsed.error.message}`);
  return parsed.value;
}

type ActiveWalletAuthMethodRecordV2 = Extract<
  WalletAuthMethodRecordV2,
  { readonly status: 'active' }
>;

async function resolveActiveAddAuthMethodSource(input: {
  readonly walletAuthMethodStore: Pick<D1WalletAuthMethodStore, 'readByIdV2' | 'getPasskeyV2'>;
  readonly walletId: WalletId;
  readonly auth: StoredWalletAddAuthMethodCeremony['auth'];
}): Promise<ActiveWalletAuthMethodRecordV2 | null> {
  const record =
    input.auth.kind === 'email_otp'
      ? input.auth.authorityRef.walletId !== input.walletId
        ? null
        : await input.walletAuthMethodStore.readByIdV2({
            walletAuthMethodId: input.auth.authorityRef.walletAuthMethodId,
          })
      : await input.walletAuthMethodStore.getPasskeyV2({
          rpId: input.auth.rpId,
          credentialIdB64u: input.auth.credentialIdB64u,
        });
  if (!record || record.status !== 'active' || record.walletId !== input.walletId) return null;
  if (input.auth.kind === 'email_otp') return record.kind === 'email_otp' ? record : null;
  return record.kind === 'passkey' ? record : null;
}

function buildActiveAddedWalletAuthMethodV2(input: {
  readonly authority: RegistrationAuthority;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthMethodRecordV2['walletAuthorityId'];
  readonly now: number;
}): ActiveWalletAuthMethodRecordV2 {
  const record =
    input.authority.kind === 'passkey'
      ? buildWalletAuthMethodRecordV2({
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: input.walletAuthMethodId,
          walletId: input.authority.walletId,
          walletAuthorityId: input.walletAuthorityId,
          kind: 'passkey',
          status: 'active',
          rpId: input.authority.rpId,
          credentialIdB64u: requireStoredCredentialId(input.authority.credentialIdB64u),
          credentialPublicKeyB64u: input.authority.credentialPublicKeyB64u,
          counter: input.authority.counter,
          createdAtMs: input.now,
          updatedAtMs: input.now,
          activatedAtMs: input.now,
        })
      : buildWalletAuthMethodRecordV2({
          version: 'wallet_auth_method_v2',
          walletAuthMethodId: input.walletAuthMethodId,
          walletId: input.authority.walletId,
          walletAuthorityId: input.walletAuthorityId,
          kind: 'email_otp',
          status: 'active',
          emailHashHex: input.authority.emailHashHex,
          registrationAuthorityId: input.authority.registrationAuthorityId,
          createdAtMs: input.now,
          updatedAtMs: input.now,
          activatedAtMs: input.now,
        });
  if (record.status !== 'active') throw new Error('Added wallet auth method must be active');
  return record;
}

function bindEmailOtpAuthorityToMethod(
  authority: EmailOtpWalletAuthAuthority,
  walletAuthMethodId: WalletAuthMethodId,
): EmailOtpWalletAuthAuthority {
  return {
    walletId: authority.walletId,
    factor: authority.factor,
    verifier: authority.verifier,
    bindingId: walletAuthMethodId,
  };
}

function isFullOwnerAuthorityV1(authority: ActiveWalletAuthorityV1): boolean {
  return sameDelegatedWalletAuthorityV1(
    buildDelegatedWalletAuthorityV1({ permissions: authority.permissions }),
    buildDelegatedWalletAuthorityV1({ permissions: buildFullOwnerPermissionsV1() }),
  );
}

function walletAuthMethodRevokedResponse(
  walletId: WalletId,
  record: Extract<WalletAuthMethodRecordV2, { readonly status: 'revoked' }>,
): WalletRevokeAuthMethodResponse {
  return record.kind === 'passkey'
    ? {
        ok: true,
        walletId,
        authMethod: { kind: 'passkey', status: 'revoked' },
        rpId: record.rpId,
      }
    : {
        ok: true,
        walletId,
        authMethod: { kind: 'email_otp', status: 'revoked' },
      };
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

function custodyFactorFromAddAuthMethodAuth(auth: StoredWalletAddAuthMethodCeremony['auth']) {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'passkey' as const,
        rpId: requireStoredRpId(auth.rpId),
        credentialIdB64u: requireStoredCredentialId(auth.credentialIdB64u),
      };
    case 'wallet_session':
      /* R103 zero-prompt handoff: the custody factor is the passkey that
         minted the authorizing owner Wallet Session, carried on the resolved
         session binding rather than a fresh assertion. */
      return {
        kind: 'passkey' as const,
        rpId: requireStoredRpId(auth.rpId),
        credentialIdB64u: requireStoredCredentialId(auth.credentialIdB64u),
      };
    case 'email_otp':
      return {
        kind: 'email_otp' as const,
        enrollmentId: auth.enrollmentId,
        enrollmentSealKeyVersion: auth.enrollmentSealKeyVersion,
      };
    default:
      return unreachableRegistrationStartAuthority(auth);
  }
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

async function buildAddedPasskeyCredentialBinding(input: {
  readonly webAuthnStore: CloudflareD1WebAuthnStore;
  readonly ceremony: Extract<StoredWalletAddAuthMethodCeremony, { readonly kind: 'passkey' }>;
  readonly walletId: WalletId;
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: string;
  readonly now: number;
}): Promise<WebAuthnCredentialBindingRecord> {
  if (input.ceremony.auth.kind === 'email_otp') {
    return {
      version: 'webauthn_credential_binding_v1',
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
      userId: String(input.walletId),
      createdAtMs: input.now,
      updatedAtMs: input.now,
    };
  }
  const source = await input.webAuthnStore.readBindingByCredential({
    rpId: input.ceremony.auth.rpId,
    credentialIdB64u: input.ceremony.auth.credentialIdB64u,
  });
  if (
    !source ||
    source.userId !== input.walletId ||
    !source.nearAccountId ||
    !source.nearEd25519SigningKeyId ||
    source.signerSlot === undefined ||
    !source.publicKey
  ) {
    throw new Error('Authorizing passkey binding is missing wallet identity fields');
  }
  const binding: WebAuthnCredentialBindingRecord = {
    version: 'webauthn_credential_binding_v1',
    rpId: input.rpId,
    credentialIdB64u: input.credentialIdB64u,
    userId: String(input.walletId),
    nearAccountId: source.nearAccountId,
    nearEd25519SigningKeyId: source.nearEd25519SigningKeyId,
    signerSlot: source.signerSlot,
    publicKey: source.publicKey,
    createdAtMs: input.now,
    updatedAtMs: input.now,
  };
  if (source.relayerKeyId) binding.relayerKeyId = source.relayerKeyId;
  if (source.keyVersion) binding.keyVersion = source.keyVersion;
  if (typeof source.recoveryExportCapable === 'boolean') {
    binding.recoveryExportCapable = source.recoveryExportCapable;
  }
  if (source.clientParticipantId !== undefined) {
    binding.clientParticipantId = source.clientParticipantId;
  }
  if (source.relayerParticipantId !== undefined) {
    binding.relayerParticipantId = source.relayerParticipantId;
  }
  if (source.participantIds) binding.participantIds = source.participantIds.slice();
  if (source.runtimePolicyScope) binding.runtimePolicyScope = source.runtimePolicyScope;
  return binding;
}

export class CloudflareD1WalletAuthMethodService {
  private readonly emailOtpChallengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
  private readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
  private readonly getWalletAuthMethodStore: WalletAuthMethodStoreProvider;
  private readonly googleEmailOtpRegistrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
  private readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
  private readonly sha256Bytes: Sha256Bytes;
  private readonly webAuthnStore: CloudflareD1WebAuthnStore;
  private readonly walletAuthorityStore: D1WalletAuthorityStore;
  private readonly orgId: string;
  private readonly verifyWebAuthnAuthenticationLite: D1FreshRevokeWebAuthnVerifierV1;

  private readonly prepareOwnerWalletSessionRevocation: OwnerWalletSessionRevocationStatementsV1;

  constructor(input: {
    readonly emailOtpChallengeVerifier: CloudflareD1EmailOtpChallengeVerifier;
    readonly getRegistrationCeremonyIntentStore: RegistrationCeremonyStoreProvider;
    readonly getWalletAuthMethodStore: WalletAuthMethodStoreProvider;
    readonly googleEmailOtpRegistrationAttempts: CloudflareD1GoogleEmailOtpRegistrationAttemptStore;
    readonly passkeyCustodyEnvelopes: CloudflareD1PasskeyCustodyEnvelopeStore;
    readonly sha256Bytes: Sha256Bytes;
    readonly webAuthnStore: CloudflareD1WebAuthnStore;
    readonly walletAuthorityStore: D1WalletAuthorityStore;
    readonly orgId: string;
    readonly verifyWebAuthnAuthenticationLite: D1FreshRevokeWebAuthnVerifierV1;
    readonly prepareOwnerWalletSessionRevocation: OwnerWalletSessionRevocationStatementsV1;
  }) {
    this.emailOtpChallengeVerifier = input.emailOtpChallengeVerifier;
    this.getRegistrationCeremonyIntentStore = input.getRegistrationCeremonyIntentStore;
    this.getWalletAuthMethodStore = input.getWalletAuthMethodStore;
    this.googleEmailOtpRegistrationAttempts = input.googleEmailOtpRegistrationAttempts;
    this.passkeyCustodyEnvelopes = input.passkeyCustodyEnvelopes;
    this.sha256Bytes = input.sha256Bytes;
    this.webAuthnStore = input.webAuthnStore;
    this.walletAuthorityStore = input.walletAuthorityStore;
    this.orgId = input.orgId;
    this.verifyWebAuthnAuthenticationLite = input.verifyWebAuthnAuthenticationLite;
    this.prepareOwnerWalletSessionRevocation = input.prepareOwnerWalletSessionRevocation;
  }

  async startWalletAddAuthMethod(
    request: StartWalletAddAuthMethodInput,
    _context?: { readonly userAgent?: string },
  ): Promise<StartWalletAddAuthMethodResult> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      const walletId = parseWalletIdForIntent(request.subject.walletId);
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
        orgId: intentPreview.orgId,
        intent: intentPreview.intent,
        nowMs: Date.now(),
      });
      if (!storedAuth.ok) return storedAuth;
      const sourceMethod = await resolveActiveAddAuthMethodSource({
        walletAuthMethodStore: this.getWalletAuthMethodStore(),
        walletId,
        auth: storedAuth.auth,
      });
      if (!sourceMethod) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Add-auth-method source is not an active V2 wallet auth method',
        };
      }
      const sourceAuthority = await this.walletAuthorityStore.readById(
        sourceMethod.walletAuthorityId,
      );
      if (
        !sourceAuthority ||
        sourceAuthority.state !== 'active' ||
        sourceAuthority.walletId !== walletId ||
        !isFullOwnerAuthorityV1(sourceAuthority)
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Add-auth-method source authority is not an active full owner',
        };
      }

      /* R109C admission, and deliberately before the intent is consumed: a
         family the authority already holds is a state the caller asked for and
         already has, so it answers `already_configured` without verifying a
         target factor, minting a ceremony, or letting the browser write
         anything. The activation transaction repeats the check as a
         conditional insert; this one exists so the ordinary case never gets
         that far. */
      const admission = admitAddWalletAuthMethod({
        sourceMethod,
        targetFamily: request.authority.kind,
        activeMethodsOnAuthority: (
          await this.getWalletAuthMethodStore().listForWalletV2({ walletId })
        )
          .filter(isActiveWalletAuthMethodRecordV2)
          .filter((method) => method.walletAuthorityId === sourceMethod.walletAuthorityId),
      });
      if (admission.kind === 'already_configured') {
        return {
          ok: false,
          code: 'already_configured',
          message: `Wallet authority already has an active ${admission.family} auth method`,
        };
      }

      const storedIntent = await store.takeAddAuthMethodIntent(grant);
      if (!storedIntent) {
        return {
          ok: false,
          code: 'invalid_grant',
          message: 'add-auth-method intent grant expired',
        };
      }
      const storedExpectedOrigin = toOptionalTrimmedString(storedIntent.expectedOrigin);
      const addAuthMethodCeremonyId = `wauthc_${secureRandomBase64Url(24)}`;
      const targetWalletAuthMethodId = allocateWalletAuthMethodId();
      const expiresAtMs = Date.now() + 10 * 60_000;
      if (request.authority.kind === 'passkey') {
        const passkeyIntent = storedIntent.intent;
        if (!isPasskeyAddAuthMethodIntent(passkeyIntent)) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Passkey authority requires a passkey add-auth-method intent',
          };
        }
        if (!storedExpectedOrigin) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'expected_origin is required for WebAuthn registration verification',
          };
        }
        if (storedAuth.auth.kind === 'email_otp') {
          /* By the exact method the caller named, not by 'the wallet's only
             active Email method'. Linking gives one wallet several active
             Email methods sharing its verified address, so the wallet-wide
             resolver cannot survive it — the same shape as the three escaped
             defects R103E repaired. */
          const authority = await this.resolveActiveEmailOtpAuthorityForVerifiedMethod({
            walletId: String(walletId),
            walletAuthMethodId: String(storedAuth.auth.authorityRef.walletAuthMethodId),
            providerUserId: storedAuth.auth.providerUserId,
          });
          if (!authority.ok) return authority;
          const expectedAuthorityRef = await walletAuthAuthorityRef({
            authority: authority.authority,
          });
          if (
            expectedAuthorityRef.walletId !== storedAuth.auth.authorityRef.walletId ||
            expectedAuthorityRef.authorityDigest !== storedAuth.auth.authorityRef.authorityDigest ||
            expectedAuthorityRef.walletAuthMethodId !==
              storedAuth.auth.authorityRef.walletAuthMethodId
          ) {
            return {
              ok: false,
              code: 'unauthorized',
              message: 'Email OTP authority does not match this wallet',
            };
          }
          const enrollment = await this.emailOtpChallengeVerifier.readActiveEnrollmentForWallet({
            walletId: String(walletId),
            orgId: storedIntent.orgId,
            providerUserId: storedAuth.auth.providerUserId,
          });
          if (!enrollment.ok) return enrollment;
          if (
            enrollment.enrollment.enrollmentId !== storedAuth.auth.enrollmentId ||
            enrollment.enrollment.enrollmentSealKeyVersion !==
              storedAuth.auth.enrollmentSealKeyVersion
          ) {
            return {
              ok: false,
              code: 'conflict',
              message: 'Email OTP enrollment changed; retry passkey linking',
            };
          }
        }
        const custodyFactor = custodyFactorFromAddAuthMethodAuth(storedAuth.auth);
        const envelopeLookup = await this.passkeyCustodyEnvelopes.lookupEnvelopeForFactor({
          walletId,
          factor: custodyFactor,
        });
        if (envelopeLookup.kind !== 'active') {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Authenticated passkey custody envelope is unavailable',
          };
        }
        const registration = this.createPasskeyRegistrationOptions({
          walletId,
          rpId: passkeyIntent.authMethod.rpId,
          walletMethods: await this.getWalletAuthMethodStore().listForWalletV2({ walletId }),
        });
        await store.putAddAuthMethodCeremony({
          kind: 'passkey',
          addAuthMethodCeremonyId,
          intent: passkeyIntent,
          digestB64u: storedIntent.digestB64u,
          orgId: storedIntent.orgId,
          sourceWalletAuthMethodId: sourceMethod.walletAuthMethodId,
          sourceWalletAuthorityId: sourceMethod.walletAuthorityId,
          sourceAuthorityDigestB64u: sourceAuthority.authorityDigestB64u,
          sourceAuthorityRevocationEpoch: sourceAuthority.revocationEpoch,
          targetWalletAuthMethodId,
          ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
          expiresAtMs,
          auth: storedAuth.auth,
          passkeyRegistration: {
            rpId: passkeyIntent.authMethod.rpId,
            challengeB64u: registration.challengeB64u,
            options: registration,
          },
          custodyEnvelope: envelopeLookup.envelope,
        });
        return {
          ok: true,
          addAuthMethodCeremonyId,
          intent: passkeyIntent,
          custodyEnvelope: envelopeLookup.envelope,
          registration,
          addAuthMethodCeremonyExpiresAtMs: expiresAtMs,
        };
      }

      const emailOtpIntent = storedIntent.intent;
      if (!isEmailOtpAddAuthMethodIntent(emailOtpIntent)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP authority requires an Email OTP add-auth-method intent',
        };
      }
      const authority = await this.verifyAddAuthMethodEmailOtpAuthority({
        orgId: storedIntent.orgId,
        authority: request.authority,
        expectedDigestB64u: storedIntent.digestB64u,
        intent: emailOtpIntent,
        sourceWalletAuthorityId: sourceMethod.walletAuthorityId,
      });
      if (!authority.ok) return authority;
      /* R109C: the browser reseals the wallet's existing custody seed under the
         verified Email OTP factor, so this branch carries the source method's
         envelope exactly as the Passkey branch above does. The lookup is by the
         source factor, which is what makes an addition impossible on a wallet
         whose source method has no live custody. */
      const emailOtpSourceEnvelope = await this.passkeyCustodyEnvelopes.lookupEnvelopeForFactor({
        walletId,
        factor: custodyFactorFromAddAuthMethodAuth(storedAuth.auth),
      });
      if (emailOtpSourceEnvelope.kind !== 'active') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'Add-auth-method source has no active wallet custody envelope',
        };
      }
      await store.putAddAuthMethodCeremony({
        kind: 'email_otp',
        addAuthMethodCeremonyId,
        intent: emailOtpIntent,
        digestB64u: storedIntent.digestB64u,
        orgId: storedIntent.orgId,
        sourceWalletAuthMethodId: sourceMethod.walletAuthMethodId,
        sourceWalletAuthorityId: sourceMethod.walletAuthorityId,
        sourceAuthorityDigestB64u: sourceAuthority.authorityDigestB64u,
        sourceAuthorityRevocationEpoch: sourceAuthority.revocationEpoch,
        targetWalletAuthMethodId,
        ...(storedIntent.expectedOrigin ? { expectedOrigin: storedIntent.expectedOrigin } : {}),
        expiresAtMs,
        auth: storedAuth.auth,
        authority: authority.authority,
        custodyEnvelope: emailOtpSourceEnvelope.envelope,
      });
      return {
        ok: true,
        addAuthMethodCeremonyId,
        intent: emailOtpIntent,
        custodyEnvelope: emailOtpSourceEnvelope.envelope,
        addAuthMethodCeremonyExpiresAtMs: expiresAtMs,
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to start wallet add-auth-method ceremony',
      };
    }
  }

  /**
   * What an exact retry has to match: the ceremony, the request as sent, and
   * the authorization branch with any linked admission.
   *
   * Substituting a credential, an envelope, or any admitted identity — wallet,
   * device, enrollment, key manifest — changes this digest, so one comparison
   * separates a retry from a different finalize wearing the same ceremony id.
   */
  private async finalizeReplayDigestB64u(
    request: FinalizeWalletAddAuthMethodInput,
  ): Promise<string> {
    return base64UrlEncode(
      await this.sha256Bytes(
        new TextEncoder().encode(
          alphabetizeStringify({
            addAuthMethodCeremonyId: request.addAuthMethodCeremonyId,
            webauthnRegistration: request.webauthnRegistration ?? null,
            custodyEnvelope: request.custodyEnvelope ?? null,
            authorization: request.authorization,
          }),
        ),
      ),
    );
  }

  /**
   * `atomicCompanionStatements` ride in the same batch as the credential, the
   * custody envelope, and the owner binding.
   *
   * Device 2's linked finalize is the reason this exists. Its link session has
   * to advance exactly when the credential commits, and a caller cannot get
   * that by making two calls: finalize is irreversible, so a cancel or an expiry
   * winning in between would leave a terminal session holding a live owner
   * credential. Statements passed here either commit with it or the whole
   * finalize fails, which is the only pair of outcomes that keeps those two
   * facts in agreement.
   *
   * They are a separate argument rather than part of the command because the
   * command is the wire contract every caller shares, and no wire request may
   * describe database writes.
   */
  async finalizeWalletAddAuthMethod(
    request: FinalizeWalletAddAuthMethodInput,
    atomicCompanionStatements: readonly D1PreparedStatementLike[] = [],
  ): Promise<FinalizeWalletAddAuthMethodResult> {
    try {
      const store = this.getRegistrationCeremonyIntentStore();
      // Before the ceremony lookup: finalize consumes its ceremony, so a retry
      // arrives after it is gone and would otherwise read as not_found.
      const replayDigestB64u = await this.finalizeReplayDigestB64u(request);
      const priorFinalize = await store.getAddAuthMethodFinalizeReplay(
        request.addAuthMethodCeremonyId,
      );
      if (priorFinalize) {
        return priorFinalize.requestDigestB64u === replayDigestB64u
          ? priorFinalize.response
          : {
              ok: false,
              code: 'conflict',
              message: 'add-auth-method ceremony was already finalized with a different request',
            };
      }
      const ceremony = await store.getAddAuthMethodCeremony(request.addAuthMethodCeremonyId);
      if (!ceremony) {
        return { ok: false, code: 'not_found', message: 'add-auth-method ceremony not found' };
      }
      const walletId = parseWalletIdForIntent(request.subject.walletId);
      if (!walletId || ceremony.intent.walletId !== walletId) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-auth-method ceremony subject mismatch',
        };
      }
      const sourceRevalidation = await this.revalidateAddAuthMethodSource({
        ceremony,
        walletId,
      });
      if (sourceRevalidation) return sourceRevalidation;
      if (ceremony.kind === 'passkey') {
        const hasWebAuthnRegistration = request.webauthnRegistration !== undefined;
        const hasCustodyEnvelope = request.custodyEnvelope !== undefined;
        if (!hasWebAuthnRegistration || !hasCustodyEnvelope) {
          return {
            ok: false,
            code: 'invalid_body',
            message: 'Passkey add-auth-method finalize requires registration and custody envelope',
          };
        }
        const expectedOrigin = toOptionalTrimmedString(ceremony.expectedOrigin);
        if (!expectedOrigin) {
          return {
            ok: false,
            code: 'invalid_state',
            message: 'Passkey add-auth-method ceremony has no expected origin',
          };
        }
        const verified = await this.verifyRegistrationCredentialForIntent({
          webauthnRegistration: request.webauthnRegistration,
          expectedChallenge: ceremony.passkeyRegistration.challengeB64u,
          expectedOrigin,
          rpId: ceremony.passkeyRegistration.rpId,
        });
        if (!verified.ok) return verified;
        const credential = verified.credential;
        const duplicate = await this.getWalletAuthMethodStore().getPasskeyV2({
          rpId: ceremony.passkeyRegistration.rpId,
          credentialIdB64u: credential.credentialIdB64u,
        });
        const duplicateAuthenticator = await this.webAuthnStore.readAuthenticator({
          userId: String(walletId),
          credentialIdB64u: credential.credentialIdB64u,
        });
        const duplicateBinding = await this.webAuthnStore.readBindingByCredential({
          rpId: ceremony.passkeyRegistration.rpId,
          credentialIdB64u: credential.credentialIdB64u,
        });
        if (duplicate || duplicateAuthenticator || duplicateBinding) {
          return {
            ok: false,
            code: 'duplicate_auth_method',
            message: 'Passkey credential is already registered',
          };
        }

        let replacementEnvelope: PasskeyCustodyEnvelopeRecord | null = null;
        if (hasCustodyEnvelope) {
          try {
            replacementEnvelope = parsePasskeyCustodyEnvelopeRecord(request.custodyEnvelope);
          } catch {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'custodyEnvelope is invalid',
            };
          }
          const expectedCiphertextDigestB64u = base64UrlEncode(
            await this.sha256Bytes(base64UrlDecode(replacementEnvelope.sealedCustodySecretB64u)),
          );
          if (
            replacementEnvelope.walletId !== walletId ||
            replacementEnvelope.factor.kind !== 'passkey' ||
            replacementEnvelope.factor.rpId !== ceremony.passkeyRegistration.rpId ||
            replacementEnvelope.factor.credentialIdB64u !== credential.credentialIdB64u ||
            replacementEnvelope.envelopeRevision !== 1 ||
            replacementEnvelope.lifecycle.state !== 'active' ||
            replacementEnvelope.envelopeId === ceremony.custodyEnvelope.envelopeId ||
            replacementEnvelope.ciphertextDigestB64u !== expectedCiphertextDigestB64u
          ) {
            return {
              ok: false,
              code: 'invalid_body',
              message: 'custodyEnvelope is not bound to the verified passkey',
            };
          }
          const currentEnvelope = await this.passkeyCustodyEnvelopes.lookupEnvelopeForFactor({
            walletId,
            factor: custodyFactorFromAddAuthMethodAuth(ceremony.auth),
          });
          if (
            currentEnvelope.kind !== 'active' ||
            currentEnvelope.envelope.envelopeId !== ceremony.custodyEnvelope.envelopeId
          ) {
            return {
              ok: false,
              code: 'conflict',
              message: 'Existing passkey custody changed; retry add-auth-method linking',
            };
          }
        }
        const authority: RegistrationAuthority = {
          kind: 'passkey',
          walletId,
          rpId: requireStoredRpId(ceremony.passkeyRegistration.rpId),
          credentialIdB64u: credential.credentialIdB64u,
          credentialPublicKeyB64u: credential.credentialPublicKeyB64u,
          counter: credential.counter,
          device: credential.device,
          registrationIntentDigestB64u: ceremony.digestB64u,
        };
        const now = Date.now();
        const authMethod = buildActiveAddedWalletAuthMethodV2({
          authority,
          walletAuthMethodId: ceremony.targetWalletAuthMethodId,
          walletAuthorityId: ceremony.sourceWalletAuthorityId,
          now,
        });
        const binding = await buildAddedPasskeyCredentialBinding({
          webAuthnStore: this.webAuthnStore,
          ceremony,
          walletId,
          rpId: requireStoredRpId(ceremony.passkeyRegistration.rpId),
          credentialIdB64u: credential.credentialIdB64u,
          now,
        });
        const response: Extract<WalletAddAuthMethodFinalizeResponse, { ok: true }> = {
          ok: true,
          walletId,
          authority: walletAuthAuthorityFromRegistrationAuthority({
            authority,
            walletAuthMethodId: ceremony.targetWalletAuthMethodId,
          }),
          rpId: requireStoredRpId(ceremony.passkeyRegistration.rpId),
          authMethod: {
            kind: 'passkey',
            status: 'active',
            credentialIdB64u: credential.credentialIdB64u,
            credentialPublicKeyB64u: credential.credentialPublicKeyB64u,
            counter: credential.counter,
            device: credential.device,
          },
        };
        const replayStatements = await store.buildAddAuthMethodFinalizeReplayStatements({
          kind: 'wallet_add_auth_method_finalize_replay_v1',
          addAuthMethodCeremonyId: ceremony.addAuthMethodCeremonyId,
          requestDigestB64u: replayDigestB64u,
          response,
          createdAtMs: now,
          expiresAtMs: now + ADD_AUTH_METHOD_FINALIZE_REPLAY_TTL_MS,
        });
        const additionalStatements = [
          ...this.prepareAddAuthMethodSourceGuard({ ceremony, walletId }),
          this.webAuthnStore.prepareAuthenticatorInsertStatement({
            userId: String(walletId),
            record: {
              credentialIdB64u: credential.credentialIdB64u,
              credentialPublicKeyB64u: credential.credentialPublicKeyB64u,
              counter: credential.counter,
              createdAtMs: now,
              updatedAtMs: now,
              deviceInfo: credential.device,
            },
          }),
          this.webAuthnStore.prepareCredentialBindingInsertStatement(binding),
          ...this.getWalletAuthMethodStore().prepareV2InsertStatements(authMethod),
          ...replayStatements,
          // Last, so the session CAS guard sees `changes()` from its own
          // update rather than from a statement that follows it.
          ...atomicCompanionStatements,
        ];
        const link =
          replacementEnvelope === null
            ? await this.passkeyCustodyEnvelopes.commitPasskeyFactorWithoutCustodyAtomically({
                additionalStatements,
              })
            : await this.passkeyCustodyEnvelopes.linkWalletCustodyFactorAtomically({
                envelope: replacementEnvelope,
                additionalStatements,
              });
        if (link.kind === 'version_mismatch' || link.kind === 'conflict') {
          return {
            ok: false,
            code: 'conflict',
            message: 'Passkey credential or custody envelope already exists',
          };
        }
        await store.takeAddAuthMethodCeremony(ceremony.addAuthMethodCeremonyId);
        return response;
      }

      /* Authority-scoped, not wallet-wide. `findDuplicateAuthority` asks
         whether the WALLET already has an active Email OTP method for this
         address, which is the right question at registration and the wrong one
         here: R103E gives every linked device its own Email OTP method sharing
         the wallet's verified address, so the wallet-wide answer would reject
         R109C's addition on any wallet that has ever linked a device. What
         must be unique is one active Email OTP method per authority, and this
         repeats at activation the admission the start already made. */
      const authorityEmailOtpMethods = (
        await this.getWalletAuthMethodStore().listForWalletV2({ walletId })
      )
        .filter(isActiveWalletAuthMethodRecordV2)
        .filter(
          (method) =>
            method.kind === 'email_otp' &&
            method.walletAuthorityId === ceremony.sourceWalletAuthorityId,
        );
      if (authorityEmailOtpMethods.length > 0) {
        return {
          ok: false,
          code: 'already_configured',
          message: 'Wallet authority already has an active email_otp auth method',
        };
      }
      if (request.webauthnRegistration !== undefined) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP add-auth-method finalize carries no WebAuthn registration',
        };
      }
      if (request.custodyEnvelope === undefined) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Email OTP add-auth-method finalize requires the resealed custody envelope',
        };
      }
      /* R109C: the browser opened the source envelope this ceremony carried and
         resealed the same seed under the verified Email OTP factor. The
         enrollment is read here rather than trusted from the request, so the
         envelope has to name the exact enrollment this wallet just verified. */
      const targetEnrollment = await this.emailOtpChallengeVerifier.readActiveEnrollmentForWallet({
        walletId: String(walletId),
        orgId: ceremony.orgId,
        providerUserId: String(ceremony.authority.providerSubject),
      });
      if (!targetEnrollment.ok) return targetEnrollment;
      let resealedEnvelope: PasskeyCustodyEnvelopeRecord;
      try {
        resealedEnvelope = parsePasskeyCustodyEnvelopeRecord(request.custodyEnvelope);
      } catch {
        return { ok: false, code: 'invalid_body', message: 'custodyEnvelope is invalid' };
      }
      const expectedResealedCiphertextDigestB64u = base64UrlEncode(
        await this.sha256Bytes(base64UrlDecode(resealedEnvelope.sealedCustodySecretB64u)),
      );
      if (
        resealedEnvelope.walletId !== walletId ||
        resealedEnvelope.factor.kind !== 'email_otp' ||
        resealedEnvelope.factor.enrollmentId !== targetEnrollment.enrollment.enrollmentId ||
        resealedEnvelope.factor.enrollmentSealKeyVersion !==
          targetEnrollment.enrollment.enrollmentSealKeyVersion ||
        resealedEnvelope.envelopeRevision !== 1 ||
        resealedEnvelope.lifecycle.state !== 'active' ||
        resealedEnvelope.envelopeId === ceremony.custodyEnvelope.envelopeId ||
        resealedEnvelope.ciphertextDigestB64u !== expectedResealedCiphertextDigestB64u
      ) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'custodyEnvelope is not bound to the verified Email OTP factor',
        };
      }
      /* The source envelope must still be the one the ceremony resealed from,
         so a custody change between start and finalize cannot commit a seed
         sealed against superseded material. */
      const currentSourceEnvelope = await this.passkeyCustodyEnvelopes.lookupEnvelopeForFactor({
        walletId,
        factor: custodyFactorFromAddAuthMethodAuth(ceremony.auth),
      });
      if (
        currentSourceEnvelope.kind !== 'active' ||
        currentSourceEnvelope.envelope.envelopeId !== ceremony.custodyEnvelope.envelopeId
      ) {
        return {
          ok: false,
          code: 'conflict',
          message: 'Existing wallet custody changed; retry add-auth-method linking',
        };
      }
      const now = Date.now();
      const authMethod = buildActiveAddedWalletAuthMethodV2({
        authority: ceremony.authority,
        walletAuthMethodId: ceremony.targetWalletAuthMethodId,
        walletAuthorityId: ceremony.sourceWalletAuthorityId,
        now,
      });
      const authority = walletAuthAuthorityFromRegistrationAuthority({
        authority: ceremony.authority,
        walletAuthMethodId: ceremony.targetWalletAuthMethodId,
      });
      const emailOtpResponse: Extract<WalletAddAuthMethodFinalizeResponse, { ok: true }> = {
        ok: true,
        walletId: ceremony.intent.walletId,
        authority,
        authMethod: { kind: 'email_otp', status: 'active' },
      };
      /* The Passkey branch has always written a replay record; this one did
         not, so an exact retry after a lost response found neither ceremony nor
         replay and answered not_found. R109C requires a retry to return the
         same active method. */
      const emailOtpReplayStatements = await store.buildAddAuthMethodFinalizeReplayStatements({
        kind: 'wallet_add_auth_method_finalize_replay_v1',
        addAuthMethodCeremonyId: ceremony.addAuthMethodCeremonyId,
        requestDigestB64u: replayDigestB64u,
        response: emailOtpResponse,
        createdAtMs: now,
        expiresAtMs: now + ADD_AUTH_METHOD_FINALIZE_REPLAY_TTL_MS,
      });
      const linked = await this.passkeyCustodyEnvelopes.linkWalletCustodyFactorAtomically({
        envelope: resealedEnvelope,
        additionalStatements: [
          ...this.prepareAddAuthMethodSourceGuard({ ceremony, walletId }),
          /* The transactional half of the missing-family rule. The admission
             at start is a read and cannot close a race; this aborts the batch
             if a concurrent ceremony activated an Email method on the same
             authority first. Applied to the Email branch only: R109C permits
             several active Passkeys on one authority, and Passkey uniqueness
             is credential-scoped and already enforced by its own index. */
          ...this.getWalletAuthMethodStore().prepareActiveV2TargetFamilyAbsentGuardStatements({
            walletId,
            walletAuthorityId: ceremony.sourceWalletAuthorityId,
            kind: 'email_otp',
          }),
          ...this.getWalletAuthMethodStore().prepareV2InsertStatements(authMethod),
          ...emailOtpReplayStatements,
          ...atomicCompanionStatements,
        ],
      });
      if (linked.kind === 'version_mismatch' || linked.kind === 'conflict') {
        return {
          ok: false,
          code: 'conflict',
          message: 'Add-auth-method source changed or target method already exists',
        };
      }
      await store.takeAddAuthMethodCeremony(ceremony.addAuthMethodCeremonyId);
      return emailOtpResponse;
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message: errorMessage(error) || 'Failed to finalize wallet add-auth-method ceremony',
      };
    }
  }

  private async revalidateAddAuthMethodSource(input: {
    readonly ceremony: StoredWalletAddAuthMethodCeremony;
    readonly walletId: WalletId;
  }): Promise<WalletAuthMethodError | null> {
    const sourceMethod = await this.getWalletAuthMethodStore().readByIdV2({
      walletAuthMethodId: input.ceremony.sourceWalletAuthMethodId,
    });
    if (
      !sourceMethod ||
      sourceMethod.status !== 'active' ||
      sourceMethod.walletId !== input.walletId ||
      sourceMethod.walletAuthorityId !== input.ceremony.sourceWalletAuthorityId
    ) {
      return {
        ok: false,
        code: 'conflict',
        message: 'Add-auth-method source method changed; restart the operation',
      };
    }
    const sourceAuthority = await this.walletAuthorityStore.readById(
      input.ceremony.sourceWalletAuthorityId,
    );
    if (
      !sourceAuthority ||
      sourceAuthority.state !== 'active' ||
      sourceAuthority.walletId !== input.walletId ||
      sourceAuthority.authorityDigestB64u !== input.ceremony.sourceAuthorityDigestB64u ||
      sourceAuthority.revocationEpoch !== input.ceremony.sourceAuthorityRevocationEpoch ||
      !isFullOwnerAuthorityV1(sourceAuthority)
    ) {
      return {
        ok: false,
        code: 'conflict',
        message: 'Add-auth-method source authority changed; restart the operation',
      };
    }
    return null;
  }

  private prepareAddAuthMethodSourceGuard(input: {
    readonly ceremony: StoredWalletAddAuthMethodCeremony;
    readonly walletId: WalletId;
  }): readonly D1PreparedStatementLike[] {
    return this.getWalletAuthMethodStore().prepareActiveV2SourceGuardStatements({
      walletId: input.walletId,
      walletAuthMethodId: input.ceremony.sourceWalletAuthMethodId,
      walletAuthorityId: input.ceremony.sourceWalletAuthorityId,
      authorityDigestB64u: input.ceremony.sourceAuthorityDigestB64u,
      authorityRevocationEpoch: input.ceremony.sourceAuthorityRevocationEpoch,
    });
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
    readonly orgId: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly nowMs: number;
  }): Promise<D1AddAuthMethodExistingAuthResolution> {
    const walletAuthMethodStore = this.getWalletAuthMethodStore();
    const walletMethods = await walletAuthMethodStore.listForWalletV2({
      walletId: input.walletId,
    });
    const activeWalletMethods = walletMethods.filter(isActiveWalletAuthMethodRecordV2);
    if (activeWalletMethods.length === 0) {
      return { ok: false, code: 'not_found', message: 'wallet has no active auth methods' };
    }
    if (input.auth.kind === 'email_otp') {
      /* Exact method, for the same reason as the start branch above: a wallet
         with a linked device has more than one active Email method. */
      const authority = await this.resolveActiveEmailOtpAuthorityForVerifiedMethod({
        walletId: String(input.walletId),
        walletAuthMethodId: String(input.auth.authorityRef.walletAuthMethodId),
        providerUserId: input.auth.providerUserId,
      });
      if (!authority.ok) return authority;
      const expectedAuthorityRef = await walletAuthAuthorityRef({
        authority: authority.authority,
      });
      if (
        expectedAuthorityRef.walletId !== input.auth.authorityRef.walletId ||
        expectedAuthorityRef.authorityDigest !== input.auth.authorityRef.authorityDigest ||
        expectedAuthorityRef.walletAuthMethodId !== input.auth.authorityRef.walletAuthMethodId
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Email OTP authority reference does not match this wallet',
        };
      }
      const enrollment = await this.emailOtpChallengeVerifier.readActiveEnrollmentForWallet({
        walletId: String(input.walletId),
        orgId: input.orgId,
        providerUserId: input.auth.providerUserId,
      });
      if (!enrollment.ok) return enrollment;
      if (
        enrollment.enrollment.enrollmentId !== input.auth.enrollmentId ||
        enrollment.enrollment.enrollmentSealKeyVersion !== input.auth.enrollmentSealKeyVersion
      ) {
        return {
          ok: false,
          code: 'conflict',
          message: 'Email OTP enrollment changed; retry passkey linking',
        };
      }
      return {
        ok: true,
        auth: {
          kind: 'email_otp',
          providerUserId: input.auth.providerUserId,
          enrollmentId: input.auth.enrollmentId,
          enrollmentSealKeyVersion: input.auth.enrollmentSealKeyVersion,
          authorityRef: input.auth.authorityRef,
        },
      };
    }
    if (input.auth.kind === 'wallet_session') {
      /* R103 zero-prompt handoff: the route already verified the bearer
         session and resolved its minting passkey. This re-checks that the
         passkey is still an active auth method of this exact wallet, so a
         revoked credential cannot keep authorizing ceremonies through a
         session it minted earlier. */
      const sessionFactorIsActive = activeWalletMethods.some(
        (method) =>
          method.kind === 'passkey' &&
          input.auth.kind === 'wallet_session' &&
          String(method.rpId || '') === String(input.auth.rpId) &&
          String(method.credentialIdB64u || '') === String(input.auth.credentialIdB64u),
      );
      if (!sessionFactorIsActive) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Owner Wallet Session passkey is not an active auth method of this wallet',
        };
      }
      return {
        ok: true,
        auth: {
          kind: 'wallet_session',
          walletSessionId: input.auth.walletSessionId,
          authorizationId: input.auth.authorizationId,
          rpId: String(input.auth.rpId),
          credentialIdB64u: input.auth.credentialIdB64u,
        },
      };
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
    readonly verificationOperationId: string;
    readonly verificationReceiptExpiresAtMs: number;
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
          verificationOperationId: input.verificationOperationId,
          verificationReceiptExpiresAtMs: input.verificationReceiptExpiresAtMs,
        });
    }
    return unreachableRegistrationStartAuthority(authority);
  }

  async verifyActivePasskeyAuthority(authority: PasskeyWalletAuthAuthority): Promise<
    | {
        readonly ok: true;
        readonly authority: ActiveWalletAuthorityV1;
        readonly authMethod: Extract<
          WalletAuthMethodRecordV2,
          { readonly kind: 'passkey'; readonly status: 'active' }
        >;
      }
    | WalletAuthMethodError
  > {
    const record = await this.getWalletAuthMethodStore().getPasskeyV2({
      rpId: authority.verifier.rpId,
      credentialIdB64u: authority.factor.credentialIdB64u,
    });
    if (
      !record ||
      record.kind !== 'passkey' ||
      record.status !== 'active' ||
      record.walletId !== authority.walletId ||
      record.walletAuthMethodId !== authority.bindingId ||
      record.rpId !== authority.verifier.rpId ||
      record.credentialIdB64u !== authority.factor.credentialIdB64u
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Passkey authority is not active for this wallet',
      };
    }
    const walletAuthority = await this.walletAuthorityStore.readById(record.walletAuthorityId);
    if (
      !walletAuthority ||
      walletAuthority.state !== 'active' ||
      walletAuthority.walletId !== record.walletId ||
      walletAuthority.authorityId !== record.walletAuthorityId
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Passkey wallet authority is not active for this wallet',
      };
    }
    return { ok: true, authority: walletAuthority, authMethod: record };
  }

  async resolveActiveWalletSessionAuthority(input: {
    readonly walletId: WalletId;
    readonly authorityRef: WalletAuthAuthorityRef;
    readonly authSource: WalletExecutionLaneAuthSource;
  }): Promise<ActiveWalletSessionAuthorityResolution> {
    const authMethods = await this.getWalletAuthMethodStore().listForWalletV2({
      walletId: input.walletId,
    });
    const walletAuthMethodId = await resolveWalletAuthMethodIdForAuthority({
      walletId: input.walletId,
      authorityRef: input.authorityRef,
      authSource: input.authSource,
      authMethods,
    });
    if (!walletAuthMethodId) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Wallet Session proof does not identify one active wallet auth method',
      };
    }
    const authMethod = authMethods.find(
      (candidate) => candidate.walletAuthMethodId === walletAuthMethodId,
    );
    if (!authMethod || authMethod.status !== 'active') {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Wallet Session auth method is not active',
      };
    }
    const authority = await this.walletAuthorityStore.readById(authMethod.walletAuthorityId);
    if (
      !authority ||
      authority.state !== 'active' ||
      authority.walletId !== input.walletId ||
      authority.authorityId !== authMethod.walletAuthorityId
    ) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Wallet Session authority is not active',
      };
    }
    return { kind: 'active_authority', authority, authMethod };
  }

  async resolveActivePasskeyAuthorityForVerifiedCredential(input: {
    readonly walletId: WalletId;
    readonly rpId: WebAuthnRpId;
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  }): Promise<
    | {
        readonly ok: true;
        readonly authority: PasskeyWalletAuthAuthority;
        readonly walletAuthority: ActiveWalletAuthorityV1;
        readonly authMethod: Extract<
          WalletAuthMethodRecordV2,
          { readonly kind: 'passkey'; readonly status: 'active' }
        >;
      }
    | WalletAuthMethodError
  > {
    const record = await this.getWalletAuthMethodStore().getPasskeyV2({
      rpId: input.rpId,
      credentialIdB64u: input.credentialIdB64u,
    });
    if (
      !record ||
      record.kind !== 'passkey' ||
      record.status !== 'active' ||
      record.walletId !== input.walletId
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Passkey credential is not active for this wallet',
      };
    }
    const authority: PasskeyWalletAuthAuthority = {
      walletId: record.walletId,
      factor: { kind: 'passkey', credentialIdB64u: record.credentialIdB64u },
      verifier: { kind: 'webauthn', rpId: record.rpId },
      bindingId: record.walletAuthMethodId,
    };
    const active = await this.verifyActivePasskeyAuthority(authority);
    return active.ok
      ? {
          ok: true,
          authority,
          walletAuthority: active.authority,
          authMethod: active.authMethod,
        }
      : active;
  }

  async resolveActivePasskeyAuthorityForUnlock(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly walletAuthorityId: WalletAuthorityId;
    readonly rpId: WebAuthnRpId;
    readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  }): Promise<WalletUnlockPasskeyAuthorityResolution> {
    const record = await this.getWalletAuthMethodStore().readByIdV2({
      walletAuthMethodId: input.walletAuthMethodId,
    });
    if (
      !record ||
      record.kind !== 'passkey' ||
      record.status !== 'active' ||
      record.walletId !== input.walletId ||
      record.walletAuthorityId !== input.walletAuthorityId ||
      record.rpId !== input.rpId ||
      record.credentialIdB64u !== input.credentialIdB64u
    ) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Verified passkey does not identify an active wallet auth method',
      };
    }

    const authority = await this.walletAuthorityStore.readById(record.walletAuthorityId);
    if (
      !authority ||
      authority.state !== 'active' ||
      authority.walletId !== record.walletId ||
      authority.authorityId !== record.walletAuthorityId
    ) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Verified passkey authority is not active for this wallet',
      };
    }
    return { kind: 'active_authority', authority, authMethod: record };
  }

  async resolveActiveEmailOtpAuthorityForUnlock(input: {
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly providerUserId: string;
    readonly emailHashHex: string;
  }): Promise<WalletUnlockEmailOtpAuthorityResolution> {
    const record = await this.getWalletAuthMethodStore().readByIdV2({
      walletAuthMethodId: input.walletAuthMethodId,
    });
    if (
      !record ||
      record.kind !== 'email_otp' ||
      record.status !== 'active' ||
      record.walletId !== input.walletId ||
      record.emailHashHex !== input.emailHashHex
    ) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Verified Email OTP does not identify an active wallet auth method',
      };
    }

    const authority = await this.walletAuthorityStore.readById(record.walletAuthorityId);
    if (
      !authority ||
      authority.state !== 'active' ||
      authority.walletId !== record.walletId ||
      authority.authorityId !== record.walletAuthorityId
    ) {
      return {
        kind: 'rejected',
        code: 'unauthorized',
        message: 'Verified Email OTP authority is not active for this wallet',
      };
    }

    const provider: EmailOtpProvider = input.providerUserId.startsWith('google:')
      ? 'google'
      : 'email';
    let boundAuthority: EmailOtpWalletAuthAuthority;
    try {
      boundAuthority = bindEmailOtpAuthorityToMethod(
        buildEmailOtpWalletAuthAuthority({
          walletId: String(record.walletId),
          provider,
          providerUserId: input.providerUserId,
          emailHashHex: record.emailHashHex,
        }),
        record.walletAuthMethodId,
      );
    } catch (error: unknown) {
      return {
        kind: 'rejected',
        code: 'invalid_state',
        message: errorMessage(error) || 'Stored Email OTP authority is invalid',
      };
    }

    return {
      kind: 'active_authority',
      authority,
      walletAuthAuthority: boundAuthority,
      authMethod: record,
    };
  }

  async verifyActiveEmailOtpAuthority(
    authority: EmailOtpWalletAuthAuthority,
  ): Promise<{ readonly ok: true } | WalletAuthMethodError> {
    const record = await this.getWalletAuthMethodStore().getEmailOtpV2({
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
    const records: WalletAuthMethodRecordV2[] = [];
    for (const record of await this.getWalletAuthMethodStore().listForWalletV2({ walletId })) {
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
      const authority = buildEmailOtpWalletAuthAuthority({
        walletId,
        provider,
        providerUserId,
        emailHashHex: record.emailHashHex,
      });
      return {
        ok: true,
        authority: bindEmailOtpAuthorityToMethod(authority, record.walletAuthMethodId),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'invalid_state',
        message: errorMessage(error) || 'Stored Email OTP authority is invalid',
      };
    }
  }

  /**
   * The exact active Email OTP authority a caller names. Several methods can
   * share one wallet's verified email once a device is linked, so an operation
   * that knows its method must resolve by that identity instead of asking for
   * the wallet's only one.
   */
  async resolveActiveEmailOtpAuthorityForVerifiedMethod(input: {
    readonly walletId: string;
    readonly walletAuthMethodId: string;
    readonly providerUserId: string;
  }): Promise<
    { readonly ok: true; readonly authority: EmailOtpWalletAuthAuthority } | WalletAuthMethodError
  > {
    const walletId = toOptionalTrimmedString(input.walletId);
    const providerUserId = toOptionalTrimmedString(input.providerUserId);
    const parsedMethodId = parseWalletAuthMethodId(input.walletAuthMethodId);
    if (!walletId || !providerUserId || !parsedMethodId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Verified Email OTP authority identity is required',
      };
    }
    const record = await this.getWalletAuthMethodStore().readByIdV2({
      walletAuthMethodId: parsedMethodId.value,
    });
    if (
      !record ||
      record.kind !== 'email_otp' ||
      record.status !== 'active' ||
      String(record.walletId) !== walletId
    ) {
      return {
        ok: false,
        code: 'unauthorized',
        message: 'Named Email OTP method is not active for this wallet',
      };
    }
    const provider: EmailOtpProvider = providerUserId.startsWith('google:') ? 'google' : 'email';
    try {
      return {
        ok: true,
        authority: bindEmailOtpAuthorityToMethod(
          buildEmailOtpWalletAuthAuthority({
            walletId,
            provider,
            providerUserId,
            emailHashHex: record.emailHashHex,
          }),
          record.walletAuthMethodId,
        ),
      };
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'invalid_state',
        message: errorMessage(error) || 'Stored Email OTP authority is invalid',
      };
    }
  }

  async findDuplicateAuthority(
    authority: RegistrationAuthority,
  ): Promise<WalletAuthMethodError | null> {
    if (authority.kind === 'passkey') {
      const duplicateCredential = await this.getWalletAuthMethodStore().getPasskeyV2({
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
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtpV2({
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

  /**
   * Mixed registration finalization runs in two requests. The ECDSA leg
   * persists the founding authority and auth method before the deferred
   * Ed25519 leg arrives, so that leg must address the same rows.
   */
  async readActiveRegistrationIdentity(authority: RegistrationAuthority): Promise<{
    readonly walletAuthorityId: WalletAuthMethodRecordV2['walletAuthorityId'];
    readonly walletAuthMethodId: WalletAuthMethodRecordV2['walletAuthMethodId'];
    readonly authority: ActiveWalletAuthorityV1;
    readonly authMethod: Extract<WalletAuthMethodRecordV2, { readonly status: 'active' }>;
  } | null> {
    const record =
      authority.kind === 'passkey'
        ? await this.getWalletAuthMethodStore().getPasskeyV2({
            rpId: authority.rpId,
            credentialIdB64u: authority.credentialIdB64u,
          })
        : await this.getWalletAuthMethodStore().getEmailOtpV2({
            walletId: String(authority.walletId),
            emailHashHex: authority.emailHashHex,
          });
    if (!record || record.status !== 'active' || record.walletId !== authority.walletId) {
      return null;
    }
    if (authority.kind === 'passkey') {
      if (
        record.kind !== 'passkey' ||
        record.rpId !== authority.rpId ||
        record.credentialIdB64u !== authority.credentialIdB64u ||
        record.credentialPublicKeyB64u !== authority.credentialPublicKeyB64u
      ) {
        return null;
      }
    } else if (
      record.kind !== 'email_otp' ||
      record.emailHashHex !== authority.emailHashHex ||
      record.registrationAuthorityId !== authority.registrationAuthorityId
    ) {
      return null;
    }
    const walletAuthority = await this.walletAuthorityStore.readById(record.walletAuthorityId);
    if (
      !walletAuthority ||
      walletAuthority.state !== 'active' ||
      walletAuthority.walletId !== record.walletId
    ) {
      return null;
    }
    return {
      walletAuthorityId: record.walletAuthorityId,
      walletAuthMethodId: record.walletAuthMethodId,
      authority: walletAuthority,
      authMethod: record,
    };
  }

  async readActiveRegistrationAuthority(authority: RegistrationAuthority): Promise<{
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  } | null> {
    const identity = await this.readActiveRegistrationIdentity(authority);
    if (!identity) return null;
    const walletAuthority = await this.walletAuthorityStore.readById(identity.walletAuthorityId);
    if (
      !walletAuthority ||
      walletAuthority.state !== 'active' ||
      walletAuthority.walletId !== authority.walletId ||
      walletAuthority.authorityId !== identity.walletAuthorityId
    ) {
      return null;
    }
    return {
      authority: walletAuthority,
      walletAuthMethodId: identity.walletAuthMethodId,
    };
  }

  async verifyWalletAuthMethodRevokeProof(input: {
    readonly walletId: WalletId;
    readonly targetWalletAuthMethodId: WalletAuthMethodId;
    readonly requestedAtMs: number;
    readonly sourceProof: WalletAuthMethodRevocationProof;
    readonly expectedOrigin: string;
  }): Promise<WalletAuthMethodRevokeProofVerificationResult> {
    try {
      const operationFingerprintDigest = await computeWalletAuthMethodRevokeOperationFingerprintV1({
        walletId: input.walletId,
        targetWalletAuthMethodId: input.targetWalletAuthMethodId,
        requestedAtMs: input.requestedAtMs,
      });
      const verified = await verifyD1LinkedDeviceFreshRevokeProofV1({
        walletId: input.walletId,
        orgId: this.orgId,
        targetWalletAuthMethodId: input.targetWalletAuthMethodId,
        proof: input.sourceProof,
        expectedOrigin: input.expectedOrigin,
        verifiedAtMs: input.requestedAtMs,
        operationFingerprintDigest,
        walletAuthMethodStore: this.getWalletAuthMethodStore(),
        verifyWebAuthnAuthenticationLite: this.verifyWebAuthnAuthenticationLite,
        verifyEmailOtpExisting: this.emailOtpChallengeVerifier.verifyExisting.bind(
          this.emailOtpChallengeVerifier,
        ),
        readEmailOtpEnrollment: this.emailOtpChallengeVerifier.readEnrollmentForWallet.bind(
          this.emailOtpChallengeVerifier,
        ),
      });
      if (verified.kind === 'denied') return verified;
      const sourceMethod = await this.getWalletAuthMethodStore().readByIdV2({
        walletAuthMethodId: verified.walletAuthMethodId,
      });
      if (
        !sourceMethod ||
        sourceMethod.status !== 'active' ||
        sourceMethod.walletId !== input.walletId ||
        sourceMethod.walletAuthMethodId === input.targetWalletAuthMethodId
      ) {
        return {
          kind: 'denied',
          code: 'unauthorized',
          message: 'Fresh revocation proof is not from a different active wallet method',
        };
      }
      const sourceAuthority = await this.walletAuthorityStore.readById(
        sourceMethod.walletAuthorityId,
      );
      if (
        !sourceAuthority ||
        sourceAuthority.state !== 'active' ||
        sourceAuthority.walletId !== input.walletId ||
        !isFullOwnerAuthorityV1(sourceAuthority)
      ) {
        return {
          kind: 'denied',
          code: 'unauthorized',
          message: 'Fresh revocation proof requires a full-owner authority',
        };
      }
      return verified;
    } catch (error: unknown) {
      return {
        kind: 'denied',
        code: 'invalid',
        message: errorMessage(error) || 'Fresh revocation proof is invalid',
      };
    }
  }

  private createPasskeyRegistrationOptions(input: {
    readonly walletId: WalletId;
    readonly rpId: string;
    readonly walletMethods: readonly WalletAuthMethodRecordV2[];
  }): WalletAddAuthMethodRegistrationOptions {
    const challengeId = secureRandomBase64Url(16, 'add-auth-method registration challenge id');
    const challengeB64u = secureRandomBase64Url(32, 'add-auth-method registration challenge');
    // Minted through the canonical parser so the options this ceremony hands
    // out are the same shape every reader — including a linked Device 2 —
    // validates them back into.
    return parseWalletAddAuthMethodRegistrationOptions({
      kind: 'webauthn_add_auth_method_registration_v1',
      challengeId,
      challengeB64u,
      rpId: input.rpId,
      user: {
        idB64u: base64UrlEncode(new TextEncoder().encode(String(input.walletId))),
        name: String(input.walletId),
        displayName: String(input.walletId),
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
      timeoutMs: 60_000,
      attestation: 'none',
      extensions: {
        prf: {
          eval: {
            firstB64u: base64UrlEncode(PASSKEY_PRF_FIRST_SALT_V1),
            secondB64u: base64UrlEncode(PASSKEY_PRF_SECOND_SALT_V1),
          },
        },
      },
      excludeCredentials: input.walletMethods
        .filter(
          (method): method is Extract<WalletAuthMethodRecordV2, { kind: 'passkey' }> =>
            method.kind === 'passkey' && method.rpId === input.rpId,
        )
        .map((method) => ({ type: 'public-key' as const, id: method.credentialIdB64u })),
    });
  }

  async revokeWalletAuthMethod(
    input: RevokeWalletAuthMethodInput,
  ): Promise<RevokeWalletAuthMethodResult> {
    try {
      const walletId = input.subject.walletId;
      const sourceWalletAuthMethodId = input.verifiedSource.walletAuthMethodId;
      if (sourceWalletAuthMethodId === input.walletAuthMethodId) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Revocation requires a different active source auth method',
        };
      }
      const walletAuthMethodStore = this.getWalletAuthMethodStore();
      const sourceMethod = await walletAuthMethodStore.readByIdV2({
        walletAuthMethodId: sourceWalletAuthMethodId,
      });
      const sourceAuthority = sourceMethod
        ? await this.walletAuthorityStore.readById(sourceMethod.walletAuthorityId)
        : null;
      if (
        !sourceMethod ||
        sourceMethod.status !== 'active' ||
        sourceMethod.walletId !== walletId ||
        !sourceAuthority ||
        sourceAuthority.state !== 'active' ||
        sourceAuthority.walletId !== walletId ||
        !isFullOwnerAuthorityV1(sourceAuthority)
      ) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Fresh revocation proof requires a different active full-owner method',
        };
      }
      const targetMethod = await walletAuthMethodStore.readByIdV2({
        walletAuthMethodId: input.walletAuthMethodId,
      });
      if (!targetMethod || targetMethod.walletId !== walletId) {
        return { ok: false, code: 'not_found', message: 'wallet auth method not found' };
      }
      if (targetMethod.status === 'revoked') {
        return walletAuthMethodRevokedResponse(walletId, targetMethod);
      }
      if (targetMethod.status !== 'active') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet auth method is not active',
        };
      }
      const targetAuthority = await this.walletAuthorityStore.readById(
        targetMethod.walletAuthorityId,
      );
      if (
        !targetAuthority ||
        targetAuthority.walletId !== walletId ||
        targetAuthority.state !== 'active'
      ) {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet auth method authority is not active',
        };
      }
      const revoked = await this.walletAuthorityStore.revokeWalletAuthMethod({
        walletId,
        authorityId: targetAuthority.authorityId,
        walletAuthMethodId: input.walletAuthMethodId,
        expectedAuthorityRevocationEpoch: targetAuthority.revocationEpoch,
        requestedAtMs: input.requestedAtMs,
        sessionRevocationStatements: this.prepareOwnerWalletSessionRevocation({
          walletId,
          walletAuthMethodId: input.walletAuthMethodId,
          requestedAtMs: input.requestedAtMs,
        }),
      });
      if (revoked.kind === 'would_remove_last_wallet_auth_method') {
        return {
          ok: false,
          code: 'invalid_state',
          message: 'wallet must retain at least one active auth method',
        };
      }
      if (revoked.kind === 'conflict') {
        return {
          ok: false,
          code: 'conflict',
          message: 'wallet auth method changed; retry revocation',
        };
      }
      return walletAuthMethodRevokedResponse(walletId, revoked.authMethod);
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
    const clientData = parseWebAuthnClientDataJsonBase64url(clientDataJSON);
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
    if (!d1HostIsWithinWebAuthnRpId(webAuthnOriginHostnameOrEmpty(clientData.origin), input.rpId)) {
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
    const duplicateCredential = await this.getWalletAuthMethodStore().getPasskeyV2({
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
    readonly verificationOperationId: string;
    readonly verificationReceiptExpiresAtMs: number;
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
      if (attempt.email.toLowerCase() !== proof.email) {
        return {
          ok: false,
          code: 'email_mismatch',
          message: 'Google Email OTP registration attempt email does not match the proof',
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
      const providerSubject = parseProviderSubject(attempt.providerSubject);
      const finalWalletId = parseWalletIdForIntent(input.intent.walletId);
      const orgId = parseOrgId(input.orgId);
      if (!providerSubject.ok || !finalWalletId || !orgId.ok) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'Google SSO registration proof contains invalid domain fields',
        };
      }
      const email = attempt.email.toLowerCase();
      const emailHashHex = await this.emailHashHex(email);
      const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtpV2({
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
          ownerProofBindingDigest: input.expectedDigestB64u,
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
    const verified = await this.emailOtpChallengeVerifier.verifyRegistrationResumable({
      providerSubject: proof.providerSubject,
      proofEmail: proof.email,
      walletId: input.intent.walletId,
      orgId: input.orgId,
      challengeId: proof.challengeId,
      otpCode: proof.otpCode,
      otpChannel: proof.otpChannel,
      ownerProofBindingDigest: input.expectedDigestB64u,
      operationId: input.verificationOperationId,
      receiptExpiresAtMs: input.verificationReceiptExpiresAtMs,
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
    const duplicateEmailOtp = await this.getWalletAuthMethodStore().getEmailOtpV2({
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
    if (!providerSubject.ok || !challengeSubjectId.ok || !challengeId.ok || !orgId.ok) {
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
        ownerProofBindingDigest: input.expectedDigestB64u,
        challengePurpose: 'registration',
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async verifyAddAuthMethodEmailOtpAuthority(input: {
    readonly orgId: string;
    readonly authority: EmailOtpWalletRegistrationAuthorityInput;
    readonly expectedDigestB64u: string;
    readonly intent: AddAuthMethodIntentV1;
    readonly sourceWalletAuthorityId: WalletAuthMethodRecordV2['walletAuthorityId'];
  }): Promise<
    | {
        readonly ok: true;
        readonly authority: Extract<RegistrationAuthority, { kind: 'email_otp' }>;
      }
    | WalletAuthMethodError
  > {
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
      ownerProofBindingDigest: input.expectedDigestB64u,
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
    /* Authority-scoped. `getEmailOtpV2` answers a wallet-wide question and
       returns the earliest matching row regardless of status, so it both
       blocked this addition because a SIBLING authority held an Email method
       — every wallet that has linked a device — and could miss a later active
       row behind an earlier revoked one. The invariant R109C states is one
       active Email OTP method per authority, so that is what is checked. The
       registration path above keeps the wallet-wide question, which is the
       right one for a wallet that has no authority yet. */
    const authorityEmailOtpMethods = (
      await this.getWalletAuthMethodStore().listForWalletV2({ walletId: input.intent.walletId })
    )
      .filter(isActiveWalletAuthMethodRecordV2)
      .filter(
        (method) =>
          method.kind === 'email_otp' &&
          method.walletAuthorityId === input.sourceWalletAuthorityId,
      );
    if (authorityEmailOtpMethods.length > 0) {
      return {
        ok: false,
        code: 'already_configured',
        message: 'Wallet authority already has an active email_otp auth method',
      };
    }
    const providerSubject = parseProviderSubject(proof.providerSubject);
    const challengeSubjectId = parseChallengeSubjectId(proof.providerSubject);
    const challengeId = parseEmailOtpChallengeId(proof.challengeId);
    const orgId = parseOrgId(input.orgId);
    if (!providerSubject.ok || !challengeSubjectId.ok || !challengeId.ok || !orgId.ok) {
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
        ownerProofBindingDigest: input.expectedDigestB64u,
        challengePurpose: 'registration',
        registrationIntentDigestB64u: input.expectedDigestB64u,
      },
    };
  }

  private async emailHashHex(email: string): Promise<string> {
    return bytesToHex(await this.sha256Bytes(new TextEncoder().encode(email)));
  }
}
