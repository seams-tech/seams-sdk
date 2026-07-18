import type { RouterApiWalletRegistrationRouteService } from './authServicePort';
import type {
  EcdsaKeyFactsInventoryPolicy,
  WebAuthnAuthenticationCredential,
  EcdsaDerivationServerBootstrapResponse,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdEd25519AuthorityScope,
  WalletKeyFactsInventoryAuth,
} from '../core/types';
import type {
  CancelRegistrationIntentRequest,
  CancelRegistrationIntentResponse,
  CreateAddAuthMethodIntentRequest,
  CreateAddSignerIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerEcdsaActivationRequest,
  WalletAddSignerEcdsaActivationResponse,
  WalletAddSignerEcdsaDerivationRespondRequest,
  WalletAddSignerEcdsaDerivationRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationEcdsaActivationRequest,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaFinalize,
  WalletRegistrationEd25519YaoActivationReference,
  WalletRegistrationFinalizeSignerWork,
  WalletRegistrationFinalizeRouteResponse,
  WalletRegistrationFinalizeRouteSuccess,
  WalletRegistrationFinalizeSuccess,
  WalletRegistrationFinalizeAuthMethod,
  WalletRegistrationEcdsaDerivationRespondRequest,
  WalletRegistrationEcdsaDerivationRespondResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
} from '../core/registrationContracts';
import { registrationPreparationIdFromString } from '../core/registrationContracts';
import type { ThresholdEcdsaChainTarget } from '../core/thresholdEcdsaChainTarget';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
} from '../core/thresholdEcdsaChainTarget';
import {
  parseAppSessionClaims,
  parseWalletRegistrationEcdsaClientBootstrap,
} from '../core/ThresholdService/validation';
import { findUnexpectedRouteKey } from './routeRequestValidation';
import {
  buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap,
  resolveActiveRuntimePolicyScopeForEnvironment,
  signRouterAbEcdsaDerivationWalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from './commonRouterUtils';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveRegistrationBootstrapApiCredentialAuth } from './routerApiCredentialAuth';
import type {
  RouterApiBootstrapTokenVerifier,
  RouterApiKeyAuthAdapter,
  RouterApiProjectEnvironmentResolver,
  SessionAdapter,
} from './routerApi';
import type { HeaderRecord, RouteResponse, RouteServices } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';
import { isPlainObject } from '@shared/utils/validation';
import {
  parseRouterAbEcdsaRegistrationActivationRequestV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import { normalizeCorsOrigin } from '../core/SessionService';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import {
  deriveImplicitNearAccountIdFromEd25519PublicKey,
  parseImplicitNearAccountId,
} from '@shared/utils/near';
import {
  addAuthMethodIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  normalizeAddAuthMethodInput,
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  normalizeEmailOtpRegistrationProof,
  normalizeRegistrationAuthMethodInput,
  normalizeRegistrationSignerPlan,
  normalizeWalletAuthMethodTarget,
  registrationIntentGrantFromString,
  registrationSignerSetSelectionFromPlan,
  walletIdFromString,
  type AddSignerIntentV1,
  type AddAuthMethodIntentV1,
  type AddSignerSelection,
  type RegistrationIntentV1,
  type RegistrationSignerPlan,
  type RegistrationSignerSetSelection,
  type RegisterWalletInput,
} from '@shared/utils/registrationIntent';
import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { isEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

type RouterApiWalletRegistrationServices = {
  walletRegistration: RouterApiWalletRegistrationRouteService;
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  bootstrapTokenVerifier?: RouterApiBootstrapTokenVerifier | null;
  orgProjectEnv?: RouterApiProjectEnvironmentResolver | null;
  routerAbPublicKeyset?: RouterAbPublicKeysetV2 | null;
  session?: SessionAdapter | null;
};

type ParsedRegistrationSignerSet = {
  readonly selection: RegistrationSignerSetSelection;
  readonly plan: RegistrationSignerPlan;
};

type RouterApiWalletRegistrationInput = {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  pathParams?: Record<string, string | undefined>;
  route: RouteDefinition;
  services: RouterApiWalletRegistrationServices;
  sourceIp?: string;
};

type ParseResult<T> = { ok: true; value: T } | { ok: false; code: 'invalid_body'; message: string };

/** User-Agent of the registering request; feeds authenticator device labels. */
function registrationUserAgentFromHeaders(headers: HeaderRecord): string | undefined {
  const raw = headers['user-agent'] ?? headers['User-Agent'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = String(value || '').trim();
  return trimmed ? trimmed : undefined;
}

type PasskeyWalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeSuccess,
  { authMethod: { kind: 'passkey' } }
>;

type EmailOtpWalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeSuccess,
  { authMethod: { kind: 'email_otp' } }
>;

function assertNeverWalletRegistrationFinalizeKind(value: never): never {
  throw new Error(`Unsupported wallet registration finalize kind: ${String(value)}`);
}

function isPasskeyWalletRegistrationFinalizeSuccess(
  result: WalletRegistrationFinalizeSuccess,
): result is PasskeyWalletRegistrationFinalizeSuccess {
  return result.authMethod.kind === 'passkey';
}

function isEmailOtpWalletRegistrationFinalizeSuccess(
  result: WalletRegistrationFinalizeSuccess,
): result is EmailOtpWalletRegistrationFinalizeSuccess {
  return result.authMethod.kind === 'email_otp';
}

function buildPasskeyWalletRegistrationFinalizeRouteSuccess(
  result: PasskeyWalletRegistrationFinalizeSuccess,
): WalletRegistrationFinalizeRouteSuccess {
  switch (result.kind) {
    case 'near_ed25519':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        rpId: result.rpId,
        authMethod: result.authMethod,
        kind: result.kind,
        authorityScope: result.authorityScope,
        accountProvisioning: result.accountProvisioning,
        resolvedAccount: result.resolvedAccount,
        ed25519: result.ed25519,
      };
    case 'evm_family_ecdsa':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        rpId: result.rpId,
        authMethod: result.authMethod,
        kind: result.kind,
        ecdsa: result.ecdsa,
      };
    case 'near_ed25519_and_evm_family_ecdsa':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        rpId: result.rpId,
        authMethod: result.authMethod,
        kind: result.kind,
        authorityScope: result.authorityScope,
        accountProvisioning: result.accountProvisioning,
        resolvedAccount: result.resolvedAccount,
        ed25519: result.ed25519,
        ecdsa: result.ecdsa,
      };
    default:
      return assertNeverWalletRegistrationFinalizeKind(result);
  }
}

function buildEmailOtpWalletRegistrationFinalizeRouteSuccess(
  result: EmailOtpWalletRegistrationFinalizeSuccess,
  appSessionJwt: string,
): WalletRegistrationFinalizeRouteSuccess {
  switch (result.kind) {
    case 'near_ed25519':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        authMethod: result.authMethod,
        kind: result.kind,
        authorityScope: result.authorityScope,
        accountProvisioning: result.accountProvisioning,
        resolvedAccount: result.resolvedAccount,
        ed25519: result.ed25519,
        appSessionJwt,
      };
    case 'evm_family_ecdsa':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        authMethod: result.authMethod,
        kind: result.kind,
        ecdsa: result.ecdsa,
        appSessionJwt,
      };
    case 'near_ed25519_and_evm_family_ecdsa':
      return {
        ok: true,
        walletId: result.walletId,
        authority: result.authority,
        registrationDiagnostics: result.registrationDiagnostics,
        authMethod: result.authMethod,
        kind: result.kind,
        authorityScope: result.authorityScope,
        accountProvisioning: result.accountProvisioning,
        resolvedAccount: result.resolvedAccount,
        ed25519: result.ed25519,
        ecdsa: result.ecdsa,
        appSessionJwt,
      };
    default:
      return assertNeverWalletRegistrationFinalizeKind(result);
  }
}

function walletRegistrationRoutePolicyServices(
  input: RouterApiWalletRegistrationInput,
): RouteServices {
  const service = input.services.walletRegistration;
  return {
    walletRegistration: service,
    walletAuthMethods: service,
    thresholdRuntime: service,
    sessionVersions: service,
    webAuthn: service,
    nearFunding: service,
  };
}

function parseFundImplicitNearAccountBody(
  body: unknown,
  walletId: string,
): ParseResult<FundImplicitNearAccountRequest> {
  if (!isPlainObject(body)) {
    return { ok: false, code: 'invalid_body', message: 'JSON body required' };
  }
  const nearAccountId = String((body as { nearAccountId?: unknown }).nearAccountId || '').trim();
  const nearPublicKeyStr = String(
    (body as { nearPublicKeyStr?: unknown }).nearPublicKeyStr || '',
  ).trim();
  if (!walletId) return { ok: false, code: 'invalid_body', message: 'walletId is required' };
  if (!nearAccountId) {
    return { ok: false, code: 'invalid_body', message: 'nearAccountId is required' };
  }
  if (!nearPublicKeyStr) {
    return { ok: false, code: 'invalid_body', message: 'nearPublicKeyStr is required' };
  }
  const parsedNearAccountId = parseImplicitNearAccountId(nearAccountId);
  if (!parsedNearAccountId.ok) {
    return { ok: false, code: 'invalid_body', message: parsedNearAccountId.message };
  }
  try {
    const derivedNearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(nearPublicKeyStr);
    if (derivedNearAccountId !== parsedNearAccountId.value) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'nearAccountId does not match nearPublicKeyStr implicit account ID',
      };
    }
  } catch (error: unknown) {
    const message =
      error && typeof error === 'object' && 'message' in error
        ? String((error as { message?: unknown }).message || 'Invalid nearPublicKeyStr')
        : 'Invalid nearPublicKeyStr';
    return { ok: false, code: 'invalid_body', message };
  }
  return {
    ok: true,
    value: {
      walletId,
      nearAccountId: parsedNearAccountId.value,
      nearPublicKeyStr,
    },
  };
}

function exposesRegistrationRouteDiagnostics(input: RouterApiWalletRegistrationInput): boolean {
  const raw =
    input.headers['x-seams-benchmark-diagnostics'] ??
    input.headers['X-Seams-Benchmark-Diagnostics'];
  return String(raw || '').trim() === 'registration-flow';
}

function stripRegistrationRouteDiagnostics<T>(response: T): T {
  if (
    !isPlainObject(response) ||
    !Object.prototype.hasOwnProperty.call(response, 'registrationDiagnostics')
  ) {
    return response;
  }
  const copy = { ...response };
  delete copy.registrationDiagnostics;
  return copy as T;
}

function requireWebAuthnExpectedOrigin(
  input: RouterApiWalletRegistrationInput,
): { ok: true; expectedOrigin: string } | { ok: false; response: RouteResponse<RouteErrorBody> } {
  const expectedOrigin = normalizeCorsOrigin(input.origin);
  if (expectedOrigin) return { ok: true, expectedOrigin };
  return {
    ok: false,
    response: routeError(
      403,
      'forbidden',
      'Origin header is required and must be a valid exact origin',
    ),
  };
}

function requireWebAuthnRpId(
  raw: unknown,
): { ok: true; rpId: WebAuthnRpId } | { ok: false; response: RouteResponse<RouteErrorBody> } {
  const parsed = parseWebAuthnRpId(raw);
  if (parsed.ok) return { ok: true, rpId: parsed.value };
  return {
    ok: false,
    response: routeError(400, 'invalid_body', parsed.error.message),
  };
}

const EMAIL_OTP_BACKUP_ACK_ALLOWED_FIELDS = [
  'kind',
  'offerId',
  'candidateId',
  'recoveryCodesIssuedAtMs',
  'backupActionKind',
  'acknowledgedAtMs',
  'idempotencyKey',
] as const;

const EMAIL_OTP_BACKUP_ACK_FORBIDDEN_FIELDS = [
  'recoveryKeys',
  'recoveryCodes',
  'appSessionJwt',
  'otpCode',
  'challengeId',
  'walletId',
  'webauthn',
  'passkey',
  'bootstrap',
  'bootstrapMaterial',
  'clientSecret32',
] as const;

const WALLET_REGISTRATION_FINALIZE_FORBIDDEN_FIELDS = [
  'delivery',
  'challengeId',
  'otpCode',
  'resend',
  'walletId',
  'webauthn',
  'webauthnRegistration',
  'webauthn_registration',
  'authenticatorOptions',
  'publicKey',
  'passkey',
  'passkeyPrfFirstB64u',
] as const;

const WALLET_REGISTRATION_FINALIZE_ALLOWED_FIELDS = [
  'registrationCeremonyId',
  'idempotencyKey',
  'kind',
  'ed25519',
  'ecdsa',
  'emailOtpEnrollment',
  'emailOtpBackupAck',
  'signerWork',
] as const;

const EMAIL_OTP_ENROLLMENT_ALLOWED_FIELDS = [
  'recoveryWrappedEnrollmentEscrows',
  'enrollmentSealKeyVersion',
  'clientUnlockPublicKeyB64u',
  'unlockKeyVersion',
  'thresholdEcdsaClientVerifyingShareB64u',
] as const;

const EMAIL_OTP_ENROLLMENT_FORBIDDEN_FIELDS = [
  ...WALLET_REGISTRATION_FINALIZE_FORBIDDEN_FIELDS,
  'recoveryKeys',
  'recoveryCodes',
  'appSessionJwt',
  'bootstrap',
  'bootstrapMaterial',
  'clientSecret32',
  'registrationAuthorityId',
] as const;

const ECDSA_REGISTRATION_ECDSA_DERIVATION_RESPOND_FORBIDDEN_FIELDS = [
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'sessionKind',
] as const;

const WALLET_REGISTRATION_FINALIZE_SIGNER_WORK_FIELDS = ['kind', 'ed25519', 'ecdsa'] as const;
const WALLET_REGISTRATION_ED25519_FINALIZE_FIELDS = ['activationReference'] as const;
const WALLET_REGISTRATION_YAO_ACTIVATION_REFERENCE_FIELDS = [
  'kind',
  'lifecycle_id',
  'session_id',
] as const;
const WALLET_REGISTRATION_ECDSA_FINALIZE_FIELDS = ['expectedKeyHandles'] as const;

function trimRequiredString(
  raw: Record<string, unknown>,
  field: string,
  message: string,
): ParseResult<string> {
  const value = typeof raw[field] === 'string' ? raw[field].trim() : '';
  if (!value) return { ok: false, code: 'invalid_body', message };
  return { ok: true, value };
}

function findOwnField(raw: Record<string, unknown>, fields: readonly string[]): string | undefined {
  return fields.find((field) => Object.prototype.hasOwnProperty.call(raw, field));
}

function findUnknownField(
  raw: Record<string, unknown>,
  allowed: readonly string[],
): string | undefined {
  return Object.keys(raw).find((field) => !allowed.includes(field));
}

function hasBranch(
  body: Record<string, unknown>,
  field: 'ed25519' | 'ecdsa' | 'emailOtpEnrollment',
): boolean {
  return Object.prototype.hasOwnProperty.call(body, field);
}

function parseChainTargets(raw: unknown): ParseResult<ThresholdEcdsaChainTarget[]> {
  if (!Array.isArray(raw) || raw.length === 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth.policy.chainTargets must contain at least one chain target',
    };
  }
  const targets: ThresholdEcdsaChainTarget[] = [];
  for (const value of raw) {
    const target = thresholdEcdsaChainTargetFromValue(value);
    if (!target) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.policy.chainTargets contains an invalid chain target',
      };
    }
    targets.push(target);
  }
  return { ok: true, value: targets };
}

function parseParticipantIds(raw: unknown, field: string): ParseResult<number[]> {
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, code: 'invalid_body', message: `${field} must contain participant ids` };
  }
  const participantIds = raw.map((value) => Math.floor(Number(value)));
  if (participantIds.some((value) => !Number.isFinite(value) || value < 1)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `${field} contains an invalid participant id`,
    };
  }
  return { ok: true, value: Array.from(new Set(participantIds)).sort((a, b) => a - b) };
}

async function attachEcdsaWalletSessionJwt(
  input: RouterApiWalletRegistrationInput,
  bootstrap: EcdsaDerivationServerBootstrapResponse | undefined,
  runtimePolicyScope?: RuntimePolicyScope,
): Promise<RouteResponse<RouteErrorBody> | null> {
  if (!bootstrap) return null;
  const normalSigningRuntime = input.services.walletRegistration.getRouterAbNormalSigningRuntime();
  if (!normalSigningRuntime) {
    return routeError(500, 'internal', 'Router A/B normal signing is not configured');
  }
  const signingWorkerId = normalSigningRuntime.getSigningWorkerId();
  const routerAbEcdsaDerivationNormalSigning = buildRouterAbEcdsaDerivationNormalSigningStateForBootstrap({
    bootstrap,
    routerAbPublicKeyset: input.services.routerAbPublicKeyset,
    signingWorkerId,
  });
  if (!routerAbEcdsaDerivationNormalSigning.ok) {
    return routeError(500, 'internal', routerAbEcdsaDerivationNormalSigning.message);
  }
  const signed = await signRouterAbEcdsaDerivationWalletSessionJwt({
    session: input.services.session,
    userId: bootstrap.walletId,
    evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
    relayerKeyId: bootstrap.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      thresholdSessionId: bootstrap.thresholdSessionId,
      signingGrantId: bootstrap.signingGrantId,
      expiresAtMs: bootstrap.expiresAtMs,
      participantIds: bootstrap.participantIds,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      keyHandle: bootstrap.keyHandle,
      stableKeyContext: {
        walletId: bootstrap.walletId,
        evmFamilySigningKeySlotId: bootstrap.evmFamilySigningKeySlotId,
        keyScope: 'evm-family',
        ecdsaThresholdKeyId: bootstrap.ecdsaThresholdKeyId,
        signingRootId: bootstrap.signingRootId,
        signingRootVersion: bootstrap.signingRootVersion,
        applicationBindingDigestB64u: bootstrap.applicationBindingDigestB64u,
        contextBinding32B64u: bootstrap.contextBinding32B64u,
      },
      publicIdentity: bootstrap.publicIdentity,
      activationEpoch: bootstrap.thresholdSessionId,
      signingWorkerId,
      routerAbEcdsaDerivationNormalSigning: routerAbEcdsaDerivationNormalSigning.state,
    },
    fallbackParticipantIds: bootstrap.participantIds,
    requireJwtErrorMessage: 'Router A/B ECDSA derivation Wallet Session must use jwt sessionKind',
    invalidPayloadErrorMessage: 'invalid Router A/B ECDSA derivation Wallet Session payload for jwt signing',
  });
  if (!signed.ok) {
    const code = signed.code === 'sessions_disabled' ? 'internal' : signed.code;
    return routeError(signed.status, code, signed.message);
  }
  bootstrap.jwt = signed.jwt;
  return null;
}

function parseAddSignerSelection(raw: unknown): ParseResult<AddSignerSelection> {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'add-signer signerSelection is required' };
  }
  if (raw.mode === 'ecdsa') {
    const ecdsa = isPlainObject(raw.ecdsa) ? raw.ecdsa : null;
    if (!ecdsa) {
      return { ok: false, code: 'invalid_body', message: 'add-signer ECDSA spec is required' };
    }
    const chainTargets = parseChainTargets(ecdsa.chainTargets);
    if (!chainTargets.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-signer ECDSA chainTargets are invalid',
      };
    }
    const participantIds = parseParticipantIds(
      ecdsa.participantIds,
      'add-signer ECDSA participantIds',
    );
    if (!participantIds.ok) return participantIds;
    return {
      ok: true,
      value: {
        mode: 'ecdsa',
        ecdsa: {
          chainTargets: chainTargets.value,
          participantIds: participantIds.value,
        },
      },
    };
  }
  if (raw.mode === 'ed25519') {
    const ed25519 = isPlainObject(raw.ed25519) ? raw.ed25519 : null;
    if (!ed25519) {
      return { ok: false, code: 'invalid_body', message: 'add-signer Ed25519 spec is required' };
    }
    const mode = typeof ed25519.mode === 'string' ? ed25519.mode.trim() : '';
    const signerSlot = Math.floor(Number(ed25519.signerSlot));
    const keyPurpose = typeof ed25519.keyPurpose === 'string' ? ed25519.keyPurpose.trim() : '';
    const keyVersion = typeof ed25519.keyVersion === 'string' ? ed25519.keyVersion.trim() : '';
    const derivationVersion = Math.floor(Number(ed25519.derivationVersion));
    const participantIds = parseParticipantIds(
      ed25519.participantIds,
      'add-signer Ed25519 participantIds',
    );
    if (!participantIds.ok) return participantIds;
    if (
      !Number.isFinite(signerSlot) ||
      signerSlot < 1 ||
      !keyPurpose ||
      !keyVersion ||
      !Number.isFinite(derivationVersion) ||
      derivationVersion < 1
    ) {
      return { ok: false, code: 'invalid_body', message: 'add-signer Ed25519 spec is invalid' };
    }
    if (mode === 'create_implicit_near_account') {
      return {
        ok: true,
        value: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_implicit_near_account',
            signerSlot,
            participantIds: participantIds.value,
            keyPurpose,
            keyVersion,
            derivationVersion,
          },
        },
      };
    }
  }
  return {
    ok: false,
    code: 'invalid_body',
    message: 'add-signer signerSelection mode is unsupported',
  };
}

function parseRegistrationSignerSet(raw: unknown): ParseResult<ParsedRegistrationSignerSet> {
  const signerPlan = normalizeRegistrationSignerPlan(raw);
  if (!signerPlan.ok) {
    return { ok: false, code: 'invalid_body', message: signerPlan.message };
  }
  const signerSelection = registrationSignerSetSelectionFromPlan(signerPlan.value, {
    normalizeEcdsaChainTarget: thresholdEcdsaChainTargetFromValue,
  });
  if (!signerSelection.ok) {
    return { ok: false, code: 'invalid_body', message: signerSelection.message };
  }
  return {
    ok: true,
    value: {
      selection: signerSelection.value,
      plan: signerPlan.value,
    },
  };
}

function parseRegisterWalletInput(raw: unknown): ParseResult<RegisterWalletInput> {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'wallet is required' };
  }
  const kind = typeof raw.kind === 'string' ? raw.kind.trim() : '';
  if (kind === 'server_allocated') {
    if (Object.prototype.hasOwnProperty.call(raw, 'walletId')) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'server-allocated wallet input must not include walletId',
      };
    }
    return { ok: true, value: { kind: 'server_allocated' } };
  }
  if (kind === 'provided') {
    const walletId = walletIdFromString(String(raw.walletId || '').trim());
    if (!walletId) {
      return { ok: false, code: 'invalid_body', message: 'wallet.walletId is required' };
    }
    return {
      ok: true,
      value: {
        kind: 'provided',
        walletId,
      },
    };
  }
  return { ok: false, code: 'invalid_body', message: 'wallet.kind is invalid' };
}

function parseCreateRegistrationIntentRequest(
  body: Record<string, unknown>,
): ParseResult<CreateRegistrationIntentRequest> {
  const wallet = parseRegisterWalletInput(body.wallet);
  if (!wallet.ok) return wallet;
  const authMethod = normalizeRegistrationAuthMethodInput(body.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'authMethod is invalid' };
  }
  const signerSelection = parseRegistrationSignerSet(body.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  return {
    ok: true,
    value: {
      wallet: wallet.value,
      authMethod,
      signerSelection: signerSelection.value.selection,
    },
  };
}

function parseCancelRegistrationIntentRequest(
  body: Record<string, unknown>,
): ParseResult<CancelRegistrationIntentRequest> {
  const registrationIntentGrant = String(body.registrationIntentGrant || '').trim();
  const registrationIntentDigestB64u = String(body.registrationIntentDigestB64u || '').trim();
  if (!registrationIntentGrant || !registrationIntentDigestB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration intent grant and digest are required',
    };
  }
  return {
    ok: true,
    value: {
      registrationIntentGrant: registrationIntentGrantFromString(registrationIntentGrant),
      registrationIntentDigestB64u,
    },
  };
}

function parseCreateAddSignerIntentRequest(
  body: Record<string, unknown>,
  walletId: string,
): ParseResult<CreateAddSignerIntentRequest> {
  const signerSelection = parseAddSignerSelection(body.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      signerSelection: signerSelection.value,
    },
  };
}

function parseCreateAddAuthMethodIntentRequest(
  body: Record<string, unknown>,
  walletId: string,
): ParseResult<CreateAddAuthMethodIntentRequest> {
  const authMethod = normalizeAddAuthMethodInput(body.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'authMethod is invalid' };
  }
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      authMethod,
    },
  };
}

function keyTargetsCoveredByPolicy(
  keyTargets: readonly unknown[],
  policyTargets: readonly ThresholdEcdsaChainTarget[],
): boolean {
  const allowed = new Set(policyTargets.map((target) => thresholdEcdsaChainTargetKey(target)));
  for (const rawTarget of keyTargets) {
    if (!isPlainObject(rawTarget)) return false;
    const chainTarget = thresholdEcdsaChainTargetFromValue(rawTarget.chainTarget);
    if (!chainTarget || !allowed.has(thresholdEcdsaChainTargetKey(chainTarget))) return false;
  }
  return true;
}

function parseInventoryKeyTargets(raw: unknown): ParseResult<
  {
    keyHandle: string;
    chainTarget: ThresholdEcdsaChainTarget;
  }[]
> {
  if (!Array.isArray(raw) || raw.length === 0) {
    return { ok: false, code: 'invalid_body', message: 'keyTargets is required' };
  }
  const targets: { keyHandle: string; chainTarget: ThresholdEcdsaChainTarget }[] = [];
  for (const rawTarget of raw) {
    if (!isPlainObject(rawTarget)) {
      return { ok: false, code: 'invalid_body', message: 'keyTargets contains an invalid target' };
    }
    const keyHandle = typeof rawTarget.keyHandle === 'string' ? rawTarget.keyHandle.trim() : '';
    const chainTarget = thresholdEcdsaChainTargetFromValue(rawTarget.chainTarget);
    if (!keyHandle || !chainTarget) {
      return { ok: false, code: 'invalid_body', message: 'keyTargets contains an invalid target' };
    }
    targets.push({ keyHandle, chainTarget });
  }
  return { ok: true, value: targets };
}

function parseWebAuthnAuthenticationCredential(
  raw: unknown,
): ParseResult<WebAuthnAuthenticationCredential> {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'auth.credential is required' };
  }
  const response = isPlainObject(raw.response) ? raw.response : null;
  if (
    typeof raw.id !== 'string' ||
    typeof raw.rawId !== 'string' ||
    typeof raw.type !== 'string' ||
    !response ||
    typeof response.clientDataJSON !== 'string' ||
    typeof response.authenticatorData !== 'string' ||
    typeof response.signature !== 'string'
  ) {
    return { ok: false, code: 'invalid_body', message: 'auth.credential is invalid' };
  }
  return {
    ok: true,
    value: {
      id: raw.id,
      rawId: raw.rawId,
      type: raw.type,
      authenticatorAttachment:
        typeof raw.authenticatorAttachment === 'string' ? raw.authenticatorAttachment : null,
      response: {
        clientDataJSON: response.clientDataJSON,
        authenticatorData: response.authenticatorData,
        signature: response.signature,
        userHandle: typeof response.userHandle === 'string' ? response.userHandle : null,
      },
      clientExtensionResults: isPlainObject(raw.clientExtensionResults)
        ? raw.clientExtensionResults
        : null,
    },
  };
}

function parseOptionalRuntimePolicyScope(
  raw: unknown,
): ParseResult<RuntimePolicyScope | undefined> {
  if (raw === undefined) return { ok: true, value: undefined };
  try {
    return { ok: true, value: normalizeRuntimePolicyScope(raw) };
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth.runtimePolicyScope is invalid',
    };
  }
}

async function parseWalletEcdsaInventoryBody(
  body: Record<string, unknown>,
  walletId: string,
): Promise<
  ParseResult<{
    rpId: string;
    auth: WalletKeyFactsInventoryAuth;
    keyTargets: {
      keyHandle: string;
      chainTarget: ThresholdEcdsaChainTarget;
    }[];
  }>
> {
  const rpId = trimRequiredString(body, 'rpId', 'rpId is required');
  if (!rpId.ok) return rpId;
  const keyTargets = parseInventoryKeyTargets(body.keyTargets);
  if (!keyTargets.ok) return keyTargets;
  const auth = isPlainObject(body.auth) ? body.auth : null;
  if (!auth) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth is required',
    };
  }
  if (auth.kind === 'webauthn_assertion') {
    const credential = parseWebAuthnAuthenticationCredential(auth.credential);
    if (!credential.ok) return credential;
    const expectedChallengeDigestB64u =
      typeof auth.expectedChallengeDigestB64u === 'string'
        ? auth.expectedChallengeDigestB64u.trim()
        : '';
    const serverNonceB64u =
      typeof auth.serverNonceB64u === 'string' ? auth.serverNonceB64u.trim() : '';
    if (!expectedChallengeDigestB64u || !serverNonceB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u and auth.serverNonceB64u are required',
      };
    }
    const runtimePolicyScope = parseOptionalRuntimePolicyScope(auth.runtimePolicyScope);
    if (!runtimePolicyScope.ok) return runtimePolicyScope;
    const computedDigest = await computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u({
      walletId,
      rpId: rpId.value,
      keyTargets: keyTargets.value,
      ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
      serverNonceB64u,
    });
    if (expectedChallengeDigestB64u !== computedDigest) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u mismatch',
      };
    }
    return {
      ok: true,
      value: {
        rpId: rpId.value,
        auth: {
          kind: 'webauthn_assertion',
          credential: credential.value,
          expectedChallengeDigestB64u,
          serverNonceB64u,
          ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
        },
        keyTargets: keyTargets.value,
      },
    };
  }
  if (auth.kind !== 'app_session') {
    return { ok: false, code: 'invalid_body', message: 'auth.kind is unsupported' };
  }
  const policy = isPlainObject(auth.policy) ? auth.policy : null;
  if (!policy) {
    return { ok: false, code: 'invalid_body', message: 'auth.policy is required' };
  }
  if (policy.permission !== 'ecdsa_key_facts_inventory') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth.policy.permission must be ecdsa_key_facts_inventory',
    };
  }
  if (String(policy.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'invalid_body', message: 'auth.policy.walletId mismatch' };
  }
  const expiresAtMs = Number(policy.expiresAtMs);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    return { ok: false, code: 'invalid_body', message: 'auth.policy is expired' };
  }
  const policyTargets = parseChainTargets(policy.chainTargets);
  if (!policyTargets.ok) return policyTargets;
  if (!keyTargetsCoveredByPolicy(keyTargets.value, policyTargets.value)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'keyTargets must be covered by auth.policy.chainTargets',
    };
  }
  const normalizedPolicy: EcdsaKeyFactsInventoryPolicy = {
    permission: 'ecdsa_key_facts_inventory',
    walletId: walletIdFromString(walletId),
    chainTargets: policyTargets.value,
    expiresAtMs,
  };
  return {
    ok: true,
    value: {
      rpId: rpId.value,
      auth: { kind: 'app_session', policy: normalizedPolicy },
      keyTargets: keyTargets.value,
    },
  };
}

function sameCanonicalValue(left: unknown, right: unknown): boolean {
  return alphabetizeStringify(left) === alphabetizeStringify(right);
}

async function parseWalletAddSignerStartBody(
  body: Record<string, unknown>,
  walletId: string,
): Promise<ParseResult<WalletAddSignerStartRequest>> {
  const intent = isPlainObject(body.intent) ? body.intent : null;
  if (!intent || intent.version !== 'add_signer_intent_v1') {
    return { ok: false, code: 'invalid_body', message: 'add-signer intent is required' };
  }
  const rawAddSignerIntentGrant =
    typeof body.addSignerIntentGrant === 'string' ? body.addSignerIntentGrant.trim() : '';
  if (!rawAddSignerIntentGrant) {
    return { ok: false, code: 'invalid_body', message: 'add-signer intent grant is required' };
  }
  const addSignerIntentGrant = addSignerIntentGrantFromString(rawAddSignerIntentGrant);
  if (String(intent.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'invalid_body', message: 'add-signer walletId mismatch' };
  }
  const signerSelection = parseAddSignerSelection(intent.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'add-signer intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: AddSignerIntentV1 = {
    version: 'add_signer_intent_v1',
    walletId: walletIdFromString(walletId),
    signerSelection: signerSelection.value,
    ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
    nonceB64u,
  };
  const expectedDigest =
    typeof body.addSignerIntentDigestB64u === 'string' ? body.addSignerIntentDigestB64u.trim() : '';
  const computedDigest = await computeAddSignerIntentDigestB64u(normalizedIntent);
  if (!expectedDigest || expectedDigest !== computedDigest) {
    return { ok: false, code: 'invalid_body', message: 'add-signer intent digest mismatch' };
  }

  const auth = isPlainObject(body.auth) ? body.auth : null;
  if (!auth) {
    return { ok: false, code: 'invalid_body', message: 'add-signer auth is required' };
  }
  if (auth.kind === 'webauthn_assertion') {
    const authRpId = parseWebAuthnRpId(auth.rpId);
    if (!authRpId.ok) {
      return { ok: false, code: 'invalid_body', message: authRpId.error.message };
    }
    const credential = parseWebAuthnAuthenticationCredential(auth.credential);
    if (!credential.ok) return credential;
    const expectedChallengeDigestB64u =
      typeof auth.expectedChallengeDigestB64u === 'string'
        ? auth.expectedChallengeDigestB64u.trim()
        : '';
    if (expectedChallengeDigestB64u !== expectedDigest) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u must match add-signer intent digest',
      };
    }
    return {
      ok: true,
      value: {
        walletId: walletIdFromString(walletId),
        addSignerIntentGrant,
        addSignerIntentDigestB64u: expectedDigest,
        intent: normalizedIntent,
        auth: {
          kind: 'webauthn_assertion',
          rpId: authRpId.value,
          credential: credential.value,
          expectedChallengeDigestB64u,
        },
      },
    };
  }
  if (auth.kind !== 'app_session') {
    return { ok: false, code: 'invalid_body', message: 'add-signer auth.kind is unsupported' };
  }
  const policy = isPlainObject(auth.policy) ? auth.policy : null;
  if (!policy) {
    return { ok: false, code: 'invalid_body', message: 'add-signer auth.policy is required' };
  }
  if (policy.permission !== 'wallet_signer_provision') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-signer auth.policy.permission must be wallet_signer_provision',
    };
  }
  if (String(policy.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'invalid_body', message: 'add-signer auth.policy wallet mismatch' };
  }
  if (!sameCanonicalValue(policy.signerSelection, normalizedIntent.signerSelection)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-signer auth.policy signerSelection mismatch',
    };
  }
  const expiresAtMs = Number(policy.expiresAtMs);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
    return { ok: false, code: 'invalid_body', message: 'add-signer auth.policy is expired' };
  }
  const policyRuntimeScope = parseOptionalRuntimePolicyScope(policy.runtimePolicyScope);
  if (!policyRuntimeScope.ok) return policyRuntimeScope;
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      addSignerIntentGrant,
      addSignerIntentDigestB64u: expectedDigest,
      intent: normalizedIntent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId: walletIdFromString(walletId),
          signerSelection: normalizedIntent.signerSelection,
          ...(policyRuntimeScope.value ? { runtimePolicyScope: policyRuntimeScope.value } : {}),
          expiresAtMs,
        },
      },
    },
  };
}

async function parseWalletRegistrationStartBody(
  body: Record<string, unknown>,
): Promise<ParseResult<WalletRegistrationStartRequest>> {
  const intent = isPlainObject(body.intent) ? body.intent : null;
  if (!intent || intent.version !== 'registration_intent_v1') {
    return { ok: false, code: 'invalid_body', message: 'registration intent is required' };
  }
  const rawRegistrationIntentGrant =
    typeof body.registrationIntentGrant === 'string' ? body.registrationIntentGrant.trim() : '';
  if (!rawRegistrationIntentGrant) {
    return { ok: false, code: 'invalid_body', message: 'registration intent grant is required' };
  }
  const walletId = String(intent.walletId || '').trim();
  if (!walletId) {
    return { ok: false, code: 'invalid_body', message: 'registration walletId is required' };
  }
  const authMethod = normalizeRegistrationAuthMethodInput(intent.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'registration authMethod is invalid' };
  }
  const signerSelection = parseRegistrationSignerSet(intent.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'registration intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: RegistrationIntentV1 = {
    version: 'registration_intent_v1',
    walletId: walletIdFromString(walletId),
    authMethod,
    signerSelection: signerSelection.value.selection,
    ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
    nonceB64u,
  };
  const expectedDigest =
    typeof body.registrationIntentDigestB64u === 'string'
      ? body.registrationIntentDigestB64u.trim()
      : '';
  const computedDigest = await computeRegistrationIntentDigestB64u(normalizedIntent);
  if (!expectedDigest || expectedDigest !== computedDigest) {
    return { ok: false, code: 'invalid_body', message: 'registration intent digest mismatch' };
  }
  if (
    Object.prototype.hasOwnProperty.call(body, 'threshold_ed25519') ||
    Object.prototype.hasOwnProperty.call(body, 'threshold_ecdsa_prepare') ||
    Object.prototype.hasOwnProperty.call(body, 'auth')
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'fresh wallet registration does not accept session or legacy auth branches',
    };
  }
  const registrationPreparationId =
    typeof body.registrationPreparationId === 'string' ? body.registrationPreparationId.trim() : '';
  if (registrationPreparationId) {
    if (
      Object.prototype.hasOwnProperty.call(body, 'webauthn_registration') ||
      Object.prototype.hasOwnProperty.call(body, 'emailOtpRegistrationProof')
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'prepared wallet registration start does not accept authority proof fields',
      };
    }
    return {
      ok: true,
      value: {
        registrationIntentGrant: registrationIntentGrantFromString(rawRegistrationIntentGrant),
        registrationIntentDigestB64u: expectedDigest,
        intent: normalizedIntent,
        registrationPreparationId: registrationPreparationIdFromString(registrationPreparationId),
      },
    };
  }
  if (Object.prototype.hasOwnProperty.call(body, 'webauthn_registration')) {
    if (authMethod.kind !== 'passkey') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'webauthn_registration requires a passkey registration intent',
      };
    }
    return {
      ok: true,
      value: {
        registrationIntentGrant: registrationIntentGrantFromString(rawRegistrationIntentGrant),
        registrationIntentDigestB64u: expectedDigest,
        intent: normalizedIntent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: body.webauthn_registration,
        },
      },
    };
  }
  if (Object.prototype.hasOwnProperty.call(body, 'emailOtpRegistrationProof')) {
    if (authMethod.kind !== 'email_otp') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpRegistrationProof requires an Email OTP registration intent',
      };
    }
    const proof = normalizeEmailOtpRegistrationProof(body.emailOtpRegistrationProof);
    if (!proof) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpRegistrationProof is invalid',
      };
    }
    return {
      ok: true,
      value: {
        registrationIntentGrant: registrationIntentGrantFromString(rawRegistrationIntentGrant),
        registrationIntentDigestB64u: expectedDigest,
        intent: normalizedIntent,
        authority: {
          kind: 'email_otp',
          emailOtpRegistrationProof: proof,
        },
      },
    };
  }
  return {
    ok: false,
    code: 'invalid_body',
    message: 'fresh wallet registration authority is required',
  };
}

async function parseWalletAddAuthMethodStartBody(
  body: Record<string, unknown>,
  walletId: string,
): Promise<ParseResult<WalletAddAuthMethodStartRequest>> {
  const intent = isPlainObject(body.intent) ? body.intent : null;
  if (!intent || intent.version !== 'add_auth_method_intent_v1') {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method intent is required' };
  }
  const rawGrant =
    typeof body.addAuthMethodIntentGrant === 'string' ? body.addAuthMethodIntentGrant.trim() : '';
  if (!rawGrant) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method intent grant is required',
    };
  }
  if (String(intent.walletId || '').trim() !== walletId) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method walletId mismatch' };
  }
  const authMethod = normalizeAddAuthMethodInput(intent.authMethod);
  if (!authMethod) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method authMethod is invalid',
    };
  }
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: AddAuthMethodIntentV1 = {
    version: 'add_auth_method_intent_v1',
    walletId: walletIdFromString(walletId),
    authMethod,
    ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
    nonceB64u,
  };
  const expectedDigest =
    typeof body.addAuthMethodIntentDigestB64u === 'string'
      ? body.addAuthMethodIntentDigestB64u.trim()
      : '';
  const computedDigest = await computeAddAuthMethodIntentDigestB64u(normalizedIntent);
  if (!expectedDigest || expectedDigest !== computedDigest) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method intent digest mismatch' };
  }
  const auth = isPlainObject(body.auth) ? body.auth : null;
  if (!auth) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method auth is required' };
  }
  let existingAuth: WalletAddAuthMethodStartRequest['auth'];
  if (auth.kind === 'webauthn_assertion') {
    const authRpId = parseWebAuthnRpId(auth.rpId);
    if (!authRpId.ok) {
      return { ok: false, code: 'invalid_body', message: authRpId.error.message };
    }
    const credential = parseWebAuthnAuthenticationCredential(auth.credential);
    if (!credential.ok) return credential;
    const expectedChallengeDigestB64u =
      typeof auth.expectedChallengeDigestB64u === 'string'
        ? auth.expectedChallengeDigestB64u.trim()
        : '';
    if (expectedChallengeDigestB64u !== expectedDigest) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u must match add-auth-method intent digest',
      };
    }
    existingAuth = {
      kind: 'webauthn_assertion',
      rpId: authRpId.value,
      credential: credential.value,
      expectedChallengeDigestB64u,
    };
  } else if (auth.kind === 'app_session') {
    const policy = isPlainObject(auth.policy) ? auth.policy : null;
    if (!policy) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy is required',
      };
    }
    if (policy.permission !== 'wallet_auth_method_provision') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy.permission must be wallet_auth_method_provision',
      };
    }
    if (String(policy.walletId || '').trim() !== walletId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy wallet mismatch',
      };
    }
    if (!sameCanonicalValue(policy.authMethod, normalizedIntent.authMethod)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy authMethod mismatch',
      };
    }
    const expiresAtMs = Number(policy.expiresAtMs);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'add-auth-method auth.policy is expired',
      };
    }
    const policyRuntimeScope = parseOptionalRuntimePolicyScope(policy.runtimePolicyScope);
    if (!policyRuntimeScope.ok) return policyRuntimeScope;
    existingAuth = {
      kind: 'app_session',
      policy: {
        permission: 'wallet_auth_method_provision',
        walletId: walletIdFromString(walletId),
        authMethod: normalizedIntent.authMethod,
        ...(policyRuntimeScope.value ? { runtimePolicyScope: policyRuntimeScope.value } : {}),
        expiresAtMs,
      },
    };
  } else {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method auth.kind is unsupported',
    };
  }

  let authority: WalletAddAuthMethodStartRequest['authority'];
  if (Object.prototype.hasOwnProperty.call(body, 'webauthnRegistration')) {
    authority = {
      kind: 'passkey',
      webauthnRegistration: body.webauthnRegistration,
    };
  } else if (Object.prototype.hasOwnProperty.call(body, 'emailOtpRegistrationProof')) {
    const proof = normalizeEmailOtpRegistrationProof(body.emailOtpRegistrationProof);
    if (!proof) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpRegistrationProof is invalid',
      };
    }
    authority = {
      kind: 'email_otp',
      emailOtpRegistrationProof: proof,
    };
  } else {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'new auth-method authority is required',
    };
  }
  if (authority.kind !== normalizedIntent.authMethod.kind) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'new auth-method authority kind must match the requested auth-method kind',
    };
  }

  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      addAuthMethodIntentGrant: addAuthMethodIntentGrantFromString(rawGrant),
      addAuthMethodIntentDigestB64u: expectedDigest,
      intent: normalizedIntent,
      auth: existingAuth,
      authority,
    },
  };
}

function parseWalletRegistrationEcdsaDerivationRespondRequest(
  body: Record<string, unknown>,
): ParseResult<WalletRegistrationEcdsaDerivationRespondRequest> {
  const registrationCeremonyId = trimRequiredString(
    body,
    'registrationCeremonyId',
    'registrationCeremonyId is required',
  );
  if (!registrationCeremonyId.ok) return registrationCeremonyId;
  const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
  if (!ecdsa || ecdsa.kind !== 'router_ab_ecdsa_registration_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA registration response is required',
    };
  }
  let strictRegistration: WalletRegistrationEcdsaDerivationRespondRequest['ecdsa']['strictRegistration'];
  try {
    strictRegistration = parseRouterAbEcdsaRegistrationRequestV1(ecdsa.strictRegistration);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA registration request is invalid',
    };
  }
  return {
    ok: true,
    value: {
      registrationCeremonyId: registrationCeremonyId.value,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration,
      },
    },
  };
}

function parseWalletRegistrationEcdsaActivationRequest(
  body: Record<string, unknown>,
): ParseResult<WalletRegistrationEcdsaActivationRequest> {
  try {
    return {
      ok: true,
      value: parseRouterAbEcdsaRegistrationActivationRequestV1(body),
    };
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA activation request is invalid',
    };
  }
}

function parseEmailOtpBackupAck(
  value: unknown,
): ParseResult<NonNullable<WalletRegistrationFinalizeRequest['emailOtpBackupAck']>> {
  const ack = isPlainObject(value) ? value : null;
  if (!ack) {
    return { ok: false, code: 'invalid_body', message: 'emailOtpBackupAck must be an object' };
  }
  const forbiddenField = findOwnField(ack, EMAIL_OTP_BACKUP_ACK_FORBIDDEN_FIELDS);
  if (forbiddenField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `emailOtpBackupAck.${forbiddenField} must not be included`,
    };
  }
  const unknownField = findUnknownField(ack, EMAIL_OTP_BACKUP_ACK_ALLOWED_FIELDS);
  if (unknownField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `emailOtpBackupAck.${unknownField} is not supported`,
    };
  }
  if (ack.kind !== 'email_otp_recovery_code_backup_ack_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.kind must be email_otp_recovery_code_backup_ack_v1',
    };
  }
  const recoveryCodesIssuedAtMs = Number(ack.recoveryCodesIssuedAtMs);
  if (!Number.isSafeInteger(recoveryCodesIssuedAtMs) || recoveryCodesIssuedAtMs <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.recoveryCodesIssuedAtMs must be a positive integer timestamp',
    };
  }
  const backupActionKind =
    typeof ack.backupActionKind === 'string' ? ack.backupActionKind.trim() : '';
  if (
    backupActionKind !== 'download' &&
    backupActionKind !== 'copy' &&
    backupActionKind !== 'print' &&
    backupActionKind !== 'manual'
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.backupActionKind is invalid',
    };
  }
  const acknowledgedAtMs = Number(ack.acknowledgedAtMs);
  if (!Number.isSafeInteger(acknowledgedAtMs) || acknowledgedAtMs <= 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.acknowledgedAtMs must be a positive integer timestamp',
    };
  }
  const idempotencyKey = typeof ack.idempotencyKey === 'string' ? ack.idempotencyKey.trim() : '';
  if (!idempotencyKey) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpBackupAck.idempotencyKey is required',
    };
  }
  const offerId = typeof ack.offerId === 'string' ? ack.offerId.trim() : '';
  const candidateId = typeof ack.candidateId === 'string' ? ack.candidateId.trim() : '';
  return {
    ok: true,
    value: {
      kind: 'email_otp_recovery_code_backup_ack_v1',
      ...(offerId ? { offerId } : {}),
      ...(candidateId ? { candidateId } : {}),
      recoveryCodesIssuedAtMs,
      backupActionKind,
      acknowledgedAtMs,
      idempotencyKey,
    },
  };
}

function parseYaoSessionId(value: unknown): ParseResult<readonly number[]> {
  if (!Array.isArray(value) || value.length !== 32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ed25519.activationReference.session_id must contain 32 bytes',
    };
  }
  const sessionId: number[] = [];
  let nonzero = false;
  for (const valueByte of value) {
    if (
      typeof valueByte !== 'number' ||
      !Number.isInteger(valueByte) ||
      valueByte < 0 ||
      valueByte > 255
    ) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ed25519.activationReference.session_id contains an invalid byte',
      };
    }
    if (valueByte !== 0) nonzero = true;
    sessionId.push(valueByte);
  }
  if (!nonzero) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ed25519.activationReference.session_id must be nonzero',
    };
  }
  return { ok: true, value: sessionId };
}

function parseYaoVisibleIdentifier(value: unknown, field: string): ParseResult<string> {
  if (typeof value !== 'string' || value.length === 0) {
    return { ok: false, code: 'invalid_body', message: `${field} is required` };
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code > 0x7e) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `${field} must contain visible ASCII bytes`,
      };
    }
  }
  return { ok: true, value };
}

function parseWalletRegistrationEd25519YaoActivationReference(
  raw: unknown,
): ParseResult<WalletRegistrationEd25519YaoActivationReference> {
  const activationReference = isPlainObject(raw) ? raw : null;
  if (!activationReference) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ed25519.activationReference is required',
    };
  }
  const unknownField = findUnknownField(
    activationReference,
    WALLET_REGISTRATION_YAO_ACTIVATION_REFERENCE_FIELDS,
  );
  if (unknownField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `ed25519.activationReference.${unknownField} is not supported`,
    };
  }
  if (activationReference.kind !== 'router_ab_ed25519_yao_activation_reference_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message:
        'ed25519.activationReference.kind must be router_ab_ed25519_yao_activation_reference_v1',
    };
  }
  const lifecycleId = parseYaoVisibleIdentifier(
    activationReference.lifecycle_id,
    'ed25519.activationReference.lifecycle_id',
  );
  if (!lifecycleId.ok) return lifecycleId;
  const sessionId = parseYaoSessionId(activationReference.session_id);
  if (!sessionId.ok) return sessionId;
  return {
    ok: true,
    value: {
      kind: 'router_ab_ed25519_yao_activation_reference_v1',
      lifecycle_id: lifecycleId.value,
      session_id: sessionId.value,
    },
  };
}

function parseWalletRegistrationEd25519Finalize(
  raw: unknown,
): ParseResult<Extract<WalletRegistrationFinalizeSignerWork, { kind: 'near_ed25519' }>['ed25519']> {
  const ed25519 = isPlainObject(raw) ? raw : null;
  if (!ed25519) {
    return { ok: false, code: 'invalid_body', message: 'ed25519 is required' };
  }
  const unknownField = findUnknownField(ed25519, WALLET_REGISTRATION_ED25519_FINALIZE_FIELDS);
  if (unknownField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `ed25519.${unknownField} is not supported`,
    };
  }
  const activationReference = parseWalletRegistrationEd25519YaoActivationReference(
    ed25519.activationReference,
  );
  if (!activationReference.ok) return activationReference;
  return { ok: true, value: { activationReference: activationReference.value } };
}

function parseWalletRegistrationEcdsaFinalize(
  raw: unknown,
): ParseResult<WalletRegistrationEcdsaFinalize> {
  const ecdsa = isPlainObject(raw) ? raw : null;
  if (!ecdsa) {
    return { ok: false, code: 'invalid_body', message: 'ecdsa is required' };
  }
  const unknownField = findUnknownField(ecdsa, WALLET_REGISTRATION_ECDSA_FINALIZE_FIELDS);
  if (unknownField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `ecdsa.${unknownField} is not supported`,
    };
  }
  if (!Array.isArray(ecdsa.expectedKeyHandles) || ecdsa.expectedKeyHandles.length !== 1) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ecdsa.expectedKeyHandles must contain one family key handle',
    };
  }
  const expectedKeyHandle =
    typeof ecdsa.expectedKeyHandles[0] === 'string'
      ? ecdsa.expectedKeyHandles[0].trim()
      : '';
  if (!expectedKeyHandle) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ecdsa.expectedKeyHandles contains an invalid family key handle',
    };
  }
  return { ok: true, value: { expectedKeyHandles: [expectedKeyHandle] } };
}

function parseWalletRegistrationFinalizeSignerWork(
  raw: unknown,
): ParseResult<WalletRegistrationFinalizeSignerWork> {
  const signerWork = isPlainObject(raw) ? raw : null;
  if (!signerWork) {
    return { ok: false, code: 'invalid_body', message: 'signerWork is required' };
  }
  const unknownField = findUnknownField(
    signerWork,
    WALLET_REGISTRATION_FINALIZE_SIGNER_WORK_FIELDS,
  );
  if (unknownField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `${unknownField} is not supported for wallet registration finalize kind`,
    };
  }
  switch (signerWork.kind) {
    case 'near_ed25519': {
      if (Object.hasOwn(signerWork, 'ecdsa')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'near_ed25519 finalize cannot include ecdsa',
        };
      }
      const ed25519 = parseWalletRegistrationEd25519Finalize(signerWork.ed25519);
      if (!ed25519.ok) return ed25519;
      return { ok: true, value: { kind: 'near_ed25519', ed25519: ed25519.value } };
    }
    case 'evm_family_ecdsa': {
      if (Object.hasOwn(signerWork, 'ed25519')) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'evm_family_ecdsa finalize cannot include ed25519',
        };
      }
      const ecdsa = parseWalletRegistrationEcdsaFinalize(signerWork.ecdsa);
      if (!ecdsa.ok) return ecdsa;
      return { ok: true, value: { kind: 'evm_family_ecdsa', ecdsa: ecdsa.value } };
    }
    case 'near_ed25519_and_evm_family_ecdsa': {
      const ed25519 = parseWalletRegistrationEd25519Finalize(signerWork.ed25519);
      if (!ed25519.ok) return ed25519;
      const ecdsa = parseWalletRegistrationEcdsaFinalize(signerWork.ecdsa);
      if (!ecdsa.ok) return ecdsa;
      return {
        ok: true,
        value: {
          kind: 'near_ed25519_and_evm_family_ecdsa',
          ed25519: ed25519.value,
          ecdsa: ecdsa.value,
        },
      };
    }
    default:
      return {
        ok: false,
        code: 'invalid_body',
        message: 'wallet registration finalize kind is invalid',
      };
  }
}

export function parseWalletRegistrationFinalizeRequest(
  body: Record<string, unknown>,
): ParseResult<WalletRegistrationFinalizeRequest> {
  const registrationCeremonyId = trimRequiredString(
    body,
    'registrationCeremonyId',
    'registrationCeremonyId is required',
  );
  if (!registrationCeremonyId.ok) return registrationCeremonyId;
  const forbiddenTopLevelField = findOwnField(body, WALLET_REGISTRATION_FINALIZE_FORBIDDEN_FIELDS);
  if (forbiddenTopLevelField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `${forbiddenTopLevelField} must not be included in wallet registration finalize`,
    };
  }
  const unknownTopLevelField = findUnknownField(body, WALLET_REGISTRATION_FINALIZE_ALLOWED_FIELDS);
  if (unknownTopLevelField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `${unknownTopLevelField} is not supported in wallet registration finalize`,
    };
  }
  if (Object.hasOwn(body, 'signerWork')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'wallet registration finalize signer inputs use the top-level kind discriminator',
    };
  }
  const signerWork = parseWalletRegistrationFinalizeSignerWork({
    kind: body.kind,
    ...(Object.hasOwn(body, 'ed25519') ? { ed25519: body.ed25519 } : {}),
    ...(Object.hasOwn(body, 'ecdsa') ? { ecdsa: body.ecdsa } : {}),
  });
  if (!signerWork.ok) return signerWork;
  const value: WalletRegistrationFinalizeRequest = {
    registrationCeremonyId: registrationCeremonyId.value,
    ...signerWork.value,
  };
  if (Object.prototype.hasOwnProperty.call(body, 'idempotencyKey')) {
    const idempotencyKey =
      typeof body.idempotencyKey === 'string' ? body.idempotencyKey.trim() : '';
    if (!idempotencyKey) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'idempotencyKey must be a non-empty string',
      };
    }
    value.idempotencyKey = idempotencyKey;
  }
  if (hasBranch(body, 'emailOtpEnrollment')) {
    const enrollment = isPlainObject(body.emailOtpEnrollment) ? body.emailOtpEnrollment : null;
    if (!enrollment) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpEnrollment finalize input is invalid',
      };
    }
    const forbiddenEnrollmentField = findOwnField(
      enrollment,
      EMAIL_OTP_ENROLLMENT_FORBIDDEN_FIELDS,
    );
    if (forbiddenEnrollmentField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `emailOtpEnrollment.${forbiddenEnrollmentField} must not be included`,
      };
    }
    const unknownEnrollmentField = findUnknownField(
      enrollment,
      EMAIL_OTP_ENROLLMENT_ALLOWED_FIELDS,
    );
    if (unknownEnrollmentField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `emailOtpEnrollment.${unknownEnrollmentField} is not supported`,
      };
    }
    if (!Array.isArray(enrollment.recoveryWrappedEnrollmentEscrows)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpEnrollment.recoveryWrappedEnrollmentEscrows must be an array',
      };
    }
    const enrollmentSealKeyVersion = trimRequiredString(
      enrollment,
      'enrollmentSealKeyVersion',
      'emailOtpEnrollment.enrollmentSealKeyVersion is required',
    );
    if (!enrollmentSealKeyVersion.ok) return enrollmentSealKeyVersion;
    const clientUnlockPublicKeyB64u = trimRequiredString(
      enrollment,
      'clientUnlockPublicKeyB64u',
      'emailOtpEnrollment.clientUnlockPublicKeyB64u is required',
    );
    if (!clientUnlockPublicKeyB64u.ok) return clientUnlockPublicKeyB64u;
    const unlockKeyVersion = trimRequiredString(
      enrollment,
      'unlockKeyVersion',
      'emailOtpEnrollment.unlockKeyVersion is required',
    );
    if (!unlockKeyVersion.ok) return unlockKeyVersion;
    const thresholdEcdsaClientVerifyingShareB64u = trimRequiredString(
      enrollment,
      'thresholdEcdsaClientVerifyingShareB64u',
      'emailOtpEnrollment.thresholdEcdsaClientVerifyingShareB64u is required',
    );
    if (!thresholdEcdsaClientVerifyingShareB64u.ok) {
      return thresholdEcdsaClientVerifyingShareB64u;
    }
    value.emailOtpEnrollment = {
      recoveryWrappedEnrollmentEscrows: enrollment.recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion: enrollmentSealKeyVersion.value,
      clientUnlockPublicKeyB64u: clientUnlockPublicKeyB64u.value,
      unlockKeyVersion: unlockKeyVersion.value,
      thresholdEcdsaClientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u.value,
    };
  }
  if (Object.prototype.hasOwnProperty.call(body, 'emailOtpBackupAck')) {
    const ack = parseEmailOtpBackupAck(body.emailOtpBackupAck);
    if (!ack.ok) return ack;
    value.emailOtpBackupAck = ack.value;
  }
  return {
    ok: true,
    value,
  };
}

function parseWalletAddSignerEcdsaDerivationRespondRequest(
  body: Record<string, unknown>,
): ParseResult<WalletAddSignerEcdsaDerivationRespondRequest> {
  const unknownBodyField = findUnknownField(body, ['addSignerCeremonyId', 'ecdsa']);
  if (unknownBodyField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `add-signer ECDSA request field ${unknownBodyField} is unsupported`,
    };
  }
  const addSignerCeremonyId = trimRequiredString(
    body,
    'addSignerCeremonyId',
    'addSignerCeremonyId is required',
  );
  if (!addSignerCeremonyId.ok) return addSignerCeremonyId;
  const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
  if (!ecdsa || ecdsa.kind !== 'router_ab_ecdsa_registration_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA add-signer request is required',
    };
  }
  const unknownEcdsaField = findUnknownField(ecdsa, ['kind', 'strictRegistration']);
  if (unknownEcdsaField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `add-signer ECDSA field ${unknownEcdsaField} is unsupported`,
    };
  }
  let strictRegistration: WalletAddSignerEcdsaDerivationRespondRequest['ecdsa']['strictRegistration'];
  try {
    strictRegistration = parseRouterAbEcdsaRegistrationRequestV1(ecdsa.strictRegistration);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA add-signer request is invalid',
    };
  }
  return {
    ok: true,
    value: {
      addSignerCeremonyId: addSignerCeremonyId.value,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration,
      },
    },
  };
}

function parseWalletAddSignerEcdsaActivationRequest(
  body: Record<string, unknown>,
): ParseResult<WalletAddSignerEcdsaActivationRequest> {
  const unknownBodyField = findUnknownField(body, ['addSignerCeremonyId', 'ecdsa']);
  if (unknownBodyField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `add-signer ECDSA activation field ${unknownBodyField} is unsupported`,
    };
  }
  const addSignerCeremonyId = trimRequiredString(
    body,
    'addSignerCeremonyId',
    'addSignerCeremonyId is required',
  );
  if (!addSignerCeremonyId.ok) return addSignerCeremonyId;
  const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
  if (!ecdsa || ecdsa.kind !== 'router_ab_ecdsa_registration_activation_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA add-signer activation is required',
    };
  }
  const unknownEcdsaField = findUnknownField(ecdsa, ['kind', 'publicFacts']);
  if (unknownEcdsaField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `add-signer ECDSA activation field ${unknownEcdsaField} is unsupported`,
    };
  }
  try {
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_v1',
          publicFacts: parseRouterAbEcdsaVerifiedClientActivationFactsV1(
            ecdsa.publicFacts,
          ),
        },
      },
    };
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA add-signer activation facts are invalid',
    };
  }
}

function parseWalletAddSignerFinalizeRequest(
  body: Record<string, unknown>,
): ParseResult<WalletAddSignerFinalizeRequest> {
  const addSignerCeremonyId = trimRequiredString(
    body,
    'addSignerCeremonyId',
    'addSignerCeremonyId is required',
  );
  if (!addSignerCeremonyId.ok) return addSignerCeremonyId;
  const idempotencyKey = trimRequiredString(body, 'idempotencyKey', 'idempotencyKey is required');
  if (!idempotencyKey.ok) return idempotencyKey;
  if (body.kind === 'near_ed25519') {
    if (Object.prototype.hasOwnProperty.call(body, 'ecdsa')) {
      return { ok: false, code: 'invalid_body', message: 'Ed25519 finalize cannot carry ECDSA' };
    }
    const ed25519 = parseWalletRegistrationEd25519Finalize(body.ed25519);
    if (!ed25519.ok) return ed25519;
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        idempotencyKey: idempotencyKey.value,
        kind: 'near_ed25519',
        ed25519: ed25519.value,
      },
    };
  }
  if (body.kind === 'evm_family_ecdsa') {
    if (Object.prototype.hasOwnProperty.call(body, 'ed25519')) {
      return { ok: false, code: 'invalid_body', message: 'ECDSA finalize cannot carry Ed25519' };
    }
    const ecdsa = parseWalletRegistrationEcdsaFinalize(body.ecdsa);
    if (!ecdsa.ok) return ecdsa;
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        idempotencyKey: idempotencyKey.value,
        kind: 'evm_family_ecdsa',
        ecdsa: ecdsa.value,
      },
    };
  }
  return { ok: false, code: 'invalid_body', message: 'add-signer finalize kind is invalid' };
}

function parseWalletAddAuthMethodFinalizeRequest(
  body: Record<string, unknown>,
): ParseResult<WalletAddAuthMethodFinalizeRequest> {
  const addAuthMethodCeremonyId = trimRequiredString(
    body,
    'addAuthMethodCeremonyId',
    'addAuthMethodCeremonyId is required',
  );
  if (!addAuthMethodCeremonyId.ok) return addAuthMethodCeremonyId;
  return {
    ok: true,
    value: {
      addAuthMethodCeremonyId: addAuthMethodCeremonyId.value,
    },
  };
}

async function parseWalletRevokeAuthMethodRequest(
  body: Record<string, unknown>,
  walletId: string,
): Promise<ParseResult<WalletRevokeAuthMethodRequest>> {
  if (Object.prototype.hasOwnProperty.call(body, 'rpId')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'rpId belongs on passkey target or WebAuthn auth',
    };
  }
  const target = normalizeWalletAuthMethodTarget(body.target);
  if (!target) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke target is invalid',
    };
  }
  const auth = isPlainObject(body.auth) ? body.auth : null;
  if (!auth) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke auth is required',
    };
  }
  let existingAuth: WalletRevokeAuthMethodRequest['auth'];
  if (auth.kind === 'webauthn_assertion') {
    const rpId = parseWebAuthnRpId(auth.rpId);
    if (!rpId.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: rpId.error.message,
      };
    }
    const credential = parseWebAuthnAuthenticationCredential(auth.credential);
    if (!credential.ok) return credential;
    const expectedChallengeDigestB64u =
      typeof auth.expectedChallengeDigestB64u === 'string'
        ? auth.expectedChallengeDigestB64u.trim()
        : '';
    if (!expectedChallengeDigestB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u is required',
      };
    }
    existingAuth = {
      kind: 'webauthn_assertion',
      rpId: rpId.value,
      credential: credential.value,
      expectedChallengeDigestB64u,
    };
  } else if (auth.kind === 'app_session') {
    const policy = isPlainObject(auth.policy) ? auth.policy : null;
    if (!policy) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth-method revoke auth.policy is required',
      };
    }
    if (policy.permission !== 'wallet_auth_method_revoke') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth-method revoke auth.policy.permission must be wallet_auth_method_revoke',
      };
    }
    if (String(policy.walletId || '').trim() !== walletId) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth-method revoke auth.policy wallet mismatch',
      };
    }
    if (!sameCanonicalValue(policy.target, target)) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth-method revoke auth.policy target mismatch',
      };
    }
    const expiresAtMs = Number(policy.expiresAtMs);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= Date.now()) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth-method revoke auth.policy is expired',
      };
    }
    const policyRuntimeScope = parseOptionalRuntimePolicyScope(policy.runtimePolicyScope);
    if (!policyRuntimeScope.ok) return policyRuntimeScope;
    existingAuth = {
      kind: 'app_session',
      policy: {
        permission: 'wallet_auth_method_revoke',
        walletId: walletIdFromString(walletId),
        target,
        ...(policyRuntimeScope.value ? { runtimePolicyScope: policyRuntimeScope.value } : {}),
        expiresAtMs,
      },
    };
  } else {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke auth.kind is unsupported',
    };
  }

  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      auth: existingAuth,
      target,
    },
  };
}

export async function handleRouterApiWalletRegistrationIntent(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<CreateRegistrationIntentResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseCreateRegistrationIntentRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const origin = normalizeCorsOrigin(input.origin);
  if (!origin) {
    return routeError(
      403,
      'forbidden',
      'Origin header is required and must be a valid exact origin',
    );
  }
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: walletRegistrationRoutePolicyServices(input),
    sourceIp: input.sourceIp,
    resolvers: {
      apiCredentials: async () =>
        await resolveRegistrationBootstrapApiCredentialAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          body: input.body as Record<string, unknown>,
          bootstrapTokenVerifier: input.services.bootstrapTokenVerifier,
          headers: input.headers,
          origin,
          route: input.route,
          sourceIp: input.sourceIp,
        }),
    },
  });
  if (!resolved.ok) return routeJson(resolved.status, resolved.body);
  if (resolved.context.principal.kind !== 'api_credentials') {
    return routeError(500, 'internal', 'wallet registration intent requires API credentials');
  }
  const principal = resolved.context.principal.principal;
  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: principal.orgId,
    environmentId: principal.environmentId,
    projectId: principal.projectId,
    envId: principal.envId,
  });
  const result = await input.services.walletRegistration.createRegistrationIntent({
    request: request.value,
    orgId: principal.orgId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(runtimePolicyScope
      ? {
          signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        }
      : {}),
    expectedOrigin: origin,
  });
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletRegistrationIntentCancel(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<CancelRegistrationIntentResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseCancelRegistrationIntentRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.cancelRegistrationIntent({
    request: request.value,
  });
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletAddSignerIntent(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<CreateAddSignerIntentResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId path parameter is required');
  }
  const request = parseCreateAddSignerIntentRequest(input.body, walletId);
  if (!request.ok) return routeError(400, request.code, request.message);
  const origin = normalizeCorsOrigin(input.origin);
  if (!origin) {
    return routeError(
      403,
      'forbidden',
      'Origin header is required and must be a valid exact origin',
    );
  }
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: walletRegistrationRoutePolicyServices(input),
    sourceIp: input.sourceIp,
    resolvers: {
      apiCredentials: async () =>
        await resolveRegistrationBootstrapApiCredentialAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          body: input.body as Record<string, unknown>,
          bootstrapTokenVerifier: input.services.bootstrapTokenVerifier,
          headers: input.headers,
          origin,
          route: input.route,
          sourceIp: input.sourceIp,
        }),
    },
  });
  if (!resolved.ok) return routeJson(resolved.status, resolved.body);
  if (resolved.context.principal.kind !== 'api_credentials') {
    return routeError(500, 'internal', 'wallet add-signer intent requires API credentials');
  }
  const principal = resolved.context.principal.principal;
  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: principal.orgId,
    environmentId: principal.environmentId,
    projectId: principal.projectId,
    envId: principal.envId,
  });
  const result = await input.services.walletRegistration.createAddSignerIntent({
    request: request.value,
    orgId: principal.orgId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(runtimePolicyScope
      ? {
          signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        }
      : {}),
    expectedOrigin: origin,
  });
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletRegistrationStart(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationStartResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = await parseWalletRegistrationStartBody(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.startWalletRegistration(request.value, {
    userAgent: registrationUserAgentFromHeaders(input.headers),
  });
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRouterApiWalletRegistrationEcdsaDerivationRespond(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationEcdsaDerivationRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationEcdsaDerivationRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.respondWalletRegistrationEcdsaDerivation(
    request.value,
  );
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRouterApiWalletRegistrationEcdsaActivation(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationEcdsaActivationResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationEcdsaActivationRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.activateWalletRegistrationEcdsa(
    request.value,
  );
  if (!result.ok) return routeJson(400, result);
  const runtimePolicyScope =
    await input.services.walletRegistration.getWalletRegistrationRuntimePolicyScope(
      request.value.registrationCeremonyId,
    );
  const signingError = await attachEcdsaWalletSessionJwt(
    input,
    result.ecdsa.bootstrap,
    runtimePolicyScope,
  );
  if (signingError) return signingError;
  return routeJson(200, result);
}

export async function handleRouterApiWalletRegistrationFinalize(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationFinalizeRouteResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const finalizeStartedAtMs = Date.now();
  const result = await input.services.walletRegistration.finalizeWalletRegistration(request.value);
  input.logger.info('[wallet-registration][finalize-route] auth service completed', {
    ok: Boolean(result.ok),
    code: result.ok ? undefined : result.code || 'internal',
    walletId: result.ok ? result.walletId : undefined,
    durationMs: Date.now() - finalizeStartedAtMs,
  });
  let routeResult: WalletRegistrationFinalizeRouteResponse;
  if (!result.ok) {
    routeResult = result;
  } else if (isPasskeyWalletRegistrationFinalizeSuccess(result)) {
    routeResult = buildPasskeyWalletRegistrationFinalizeRouteSuccess(result);
  } else if (isEmailOtpWalletRegistrationFinalizeSuccess(result)) {
    if (!isEmailOtpWalletAuthAuthority(result.authority)) {
      return routeError(500, 'internal', 'Email OTP registration returned a different authority');
    }
    const session = input.services.session;
    if (!session) {
      return routeError(500, 'internal', 'Email OTP registration requires session signing');
    }
    const appSessionVersion = await input.services.walletRegistration.getOrCreateAppSessionVersion({
      userId: result.authority.factor.providerUserId,
    });
    if (!appSessionVersion.ok) {
      return routeError(500, 'internal', appSessionVersion.message);
    }
    const runtimePolicyScope =
      result.kind === 'evm_family_ecdsa' ? undefined : result.ed25519.session.runtimePolicyScope;
    const appSessionJwt = await session.signJwt(result.authority.factor.providerUserId, {
      kind: 'app_session_v1',
      appSessionVersion: appSessionVersion.appSessionVersion,
      provider: result.authority.factor.provider,
      providerSubject: result.authority.factor.providerUserId,
      walletId: result.walletId,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    });
    routeResult = buildEmailOtpWalletRegistrationFinalizeRouteSuccess(result, appSessionJwt);
  } else {
    result satisfies never;
    return routeError(500, 'internal', 'Registration returned an unsupported auth method');
  }
  const response = exposesRegistrationRouteDiagnostics(input)
    ? routeResult
    : stripRegistrationRouteDiagnostics(routeResult);
  input.logger.info('[wallet-registration][finalize-route] returning response', {
    ok: Boolean(routeResult.ok),
    status: routeResult.ok ? 200 : 400,
    walletId: routeResult.ok ? routeResult.walletId : undefined,
    durationMs: Date.now() - finalizeStartedAtMs,
  });
  return routeJson(routeResult.ok ? 200 : 400, response, {
    usage: routeResult.ok ? { walletId: routeResult.walletId } : undefined,
  });
}

export async function handleRouterApiWalletAddSignerStart(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerStartResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const parsedBody = await parseWalletAddSignerStartBody(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const parsedRpId = requireWebAuthnRpId(parsedBody.value.auth.rpId);
    if (!parsedRpId.ok) return parsedRpId.response;
    const verified = await input.services.walletRegistration.verifyWebAuthnAuthenticationLite({
      userId: walletId,
      rpId: parsedRpId.rpId,
      expectedChallenge: parsedBody.value.auth.expectedChallengeDigestB64u,
      expected_origin: origin.expectedOrigin,
      webauthn_authentication: parsedBody.value.auth.credential,
    });
    if (!verified.success || !verified.verified) {
      return routeError(
        401,
        'unauthorized',
        verified.message || 'Invalid add-signer WebAuthn authorization',
      );
    }
  } else {
    const session = input.services.session;
    if (!session) {
      return routeError(401, 'unauthorized', 'App session auth is required');
    }
    const parsedSession = await session.parse(input.headers || {});
    if (!parsedSession.ok) {
      return routeError(401, 'unauthorized', 'Missing or invalid app session');
    }
    const appSessionClaims = parseAppSessionClaims(parsedSession.claims);
    if (!appSessionClaims) {
      return routeError(401, 'unauthorized', 'Add-signer requires app-session auth');
    }
    if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
      return routeError(401, 'unauthorized', 'App session is expired');
    }
    const sessionVersion = await input.services.walletRegistration.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const result = await input.services.walletRegistration.startWalletAddSigner(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletAddSignerEcdsaDerivationRespond(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerEcdsaDerivationRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerEcdsaDerivationRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.respondWalletAddSignerEcdsaDerivation(request.value);
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletAddSignerEcdsaActivation(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerEcdsaActivationResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerEcdsaActivationRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.activateWalletAddSignerEcdsa(
    request.value,
  );
  if (!result.ok) return routeJson(400, result);
  const runtimePolicyScope =
    await input.services.walletRegistration.getWalletAddSignerRuntimePolicyScope(
      request.value.addSignerCeremonyId,
    );
  const signingError = await attachEcdsaWalletSessionJwt(
    input,
    result.ecdsa.bootstrap,
    runtimePolicyScope || undefined,
  );
  if (signingError) return signingError;
  return routeJson(200, result);
}

export async function handleRouterApiWalletAddSignerFinalize(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerFinalizeResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.finalizeWalletAddSigner(request.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRouterApiWalletAddAuthMethodIntent(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<CreateAddAuthMethodIntentResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId path parameter is required');
  }
  const request = parseCreateAddAuthMethodIntentRequest(input.body, walletId);
  if (!request.ok) return routeError(400, request.code, request.message);
  const origin = normalizeCorsOrigin(input.origin);
  if (!origin) {
    return routeError(
      403,
      'forbidden',
      'Origin header is required and must be a valid exact origin',
    );
  }
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: walletRegistrationRoutePolicyServices(input),
    sourceIp: input.sourceIp,
    resolvers: {
      apiCredentials: async () =>
        await resolveRegistrationBootstrapApiCredentialAuth({
          apiKeyAuth: input.services.apiKeyAuth,
          body: input.body as Record<string, unknown>,
          bootstrapTokenVerifier: input.services.bootstrapTokenVerifier,
          headers: input.headers,
          origin,
          route: input.route,
          sourceIp: input.sourceIp,
        }),
    },
  });
  if (!resolved.ok) return routeJson(resolved.status, resolved.body);
  if (resolved.context.principal.kind !== 'api_credentials') {
    return routeError(500, 'internal', 'wallet add-auth-method intent requires API credentials');
  }
  const principal = resolved.context.principal.principal;
  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: principal.orgId,
    environmentId: principal.environmentId,
    projectId: principal.projectId,
    envId: principal.envId,
  });
  const result = await input.services.walletRegistration.createAddAuthMethodIntent({
    request: request.value,
    orgId: principal.orgId,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(runtimePolicyScope
      ? {
          signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        }
      : {}),
    expectedOrigin: origin,
  });
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletAddAuthMethodStart(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddAuthMethodStartResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const parsedBody = await parseWalletAddAuthMethodStartBody(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const parsedRpId = requireWebAuthnRpId(parsedBody.value.auth.rpId);
    if (!parsedRpId.ok) return parsedRpId.response;
    const verified = await input.services.walletRegistration.verifyWebAuthnAuthenticationLite({
      userId: walletId,
      rpId: parsedRpId.rpId,
      expectedChallenge: parsedBody.value.auth.expectedChallengeDigestB64u,
      expected_origin: origin.expectedOrigin,
      webauthn_authentication: parsedBody.value.auth.credential,
    });
    if (!verified.success || !verified.verified) {
      return routeError(
        401,
        'unauthorized',
        verified.message || 'Invalid add-auth-method WebAuthn authorization',
      );
    }
  } else {
    const session = input.services.session;
    if (!session) {
      return routeError(401, 'unauthorized', 'App session auth is required');
    }
    const parsedSession = await session.parse(input.headers || {});
    if (!parsedSession.ok) {
      return routeError(401, 'unauthorized', 'Missing or invalid app session');
    }
    const appSessionClaims = parseAppSessionClaims(parsedSession.claims);
    if (!appSessionClaims) {
      return routeError(401, 'unauthorized', 'Add-auth-method requires app-session auth');
    }
    if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
      return routeError(401, 'unauthorized', 'App session is expired');
    }
    const sessionVersion = await input.services.walletRegistration.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const result = await input.services.walletRegistration.startWalletAddAuthMethod(
    parsedBody.value,
    { userAgent: registrationUserAgentFromHeaders(input.headers) },
  );
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRouterApiWalletAddAuthMethodFinalize(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddAuthMethodFinalizeResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddAuthMethodFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.finalizeWalletAddAuthMethod(request.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRouterApiWalletRevokeAuthMethod(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRevokeAuthMethodResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const parsedBody = await parseWalletRevokeAuthMethodRequest(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const verified = await input.services.walletRegistration.verifyWebAuthnAuthenticationLite({
      userId: walletId,
      rpId: parsedBody.value.auth.rpId,
      expectedChallenge: parsedBody.value.auth.expectedChallengeDigestB64u,
      expected_origin: origin.expectedOrigin,
      webauthn_authentication: parsedBody.value.auth.credential,
    });
    if (!verified.success || !verified.verified) {
      return routeError(
        401,
        'unauthorized',
        verified.message || 'Invalid auth-method revoke WebAuthn authorization',
      );
    }
  } else {
    const session = input.services.session;
    if (!session) {
      return routeError(401, 'unauthorized', 'App session auth is required');
    }
    const parsedSession = await session.parse(input.headers || {});
    if (!parsedSession.ok) {
      return routeError(401, 'unauthorized', 'Missing or invalid app session');
    }
    const appSessionClaims = parseAppSessionClaims(parsedSession.claims);
    if (!appSessionClaims) {
      return routeError(401, 'unauthorized', 'Auth-method revoke requires app-session auth');
    }
    if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
      return routeError(401, 'unauthorized', 'App session is expired');
    }
    const sessionVersion = await input.services.walletRegistration.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const result = await input.services.walletRegistration.revokeWalletAuthMethod(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRouterApiWalletEcdsaKeyFactsInventory(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<RouteErrorBody | Record<string, unknown>>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const parsedBody = await parseWalletEcdsaInventoryBody(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const parsedRpId = requireWebAuthnRpId(parsedBody.value.rpId);
    if (!parsedRpId.ok) return parsedRpId.response;
    const verified = await input.services.walletRegistration.verifyWebAuthnAuthenticationLite({
      userId: walletId,
      rpId: parsedRpId.rpId,
      expectedChallenge: parsedBody.value.auth.expectedChallengeDigestB64u,
      expected_origin: origin.expectedOrigin,
      webauthn_authentication: parsedBody.value.auth.credential,
    });
    if (!verified.success || !verified.verified) {
      return routeError(
        401,
        'unauthorized',
        verified.message || 'Invalid ECDSA key-facts inventory WebAuthn authorization',
      );
    }
  } else {
    const session = input.services.session;
    if (!session) {
      return routeError(401, 'unauthorized', 'App session auth is required');
    }
    const parsedSession = await session.parse(input.headers || {});
    if (!parsedSession.ok) {
      return routeError(401, 'unauthorized', 'Missing or invalid app session');
    }
    const appSessionClaims = parseAppSessionClaims(parsedSession.claims);
    if (!appSessionClaims) {
      return routeError(401, 'unauthorized', 'ECDSA key-facts inventory requires app-session auth');
    }
    if (appSessionClaims.exp !== undefined && appSessionClaims.exp * 1000 <= Date.now()) {
      return routeError(401, 'unauthorized', 'App session is expired');
    }
    const sessionVersion = await input.services.walletRegistration.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const keyInventory = await input.services.walletRegistration.listWalletEcdsaKeyFactsInventory({
    walletId,
    rpId: parsedBody.value.rpId,
    keyTargets: parsedBody.value.keyTargets,
  });
  input.logger.info('[wallet][ecdsa-key-facts-inventory][diagnostic]', {
    walletId,
    ...keyInventory.diagnostics,
  });
  return routeJson(200, {
    ok: true,
    ecdsaKeyIdentityTargets: keyInventory.records,
    diagnostics: keyInventory.diagnostics,
  });
}

export async function handleRouterApiWalletNearImplicitAccountFund(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<RouteErrorBody | FundImplicitNearAccountResult>> {
  const walletId = String(input.pathParams?.walletId || '').trim();
  const parsedBody = parseFundImplicitNearAccountBody(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);

  const sessionInputs = await validateRouterAbEd25519WalletSessionTokenInputs({
    body: input.body,
    headers: input.headers || {},
    session: input.services.session,
  });
  if (!sessionInputs.ok) {
    return routeError(401, 'unauthorized', sessionInputs.message);
  }
  if (sessionInputs.claims.walletId !== parsedBody.value.walletId) {
    return routeError(403, 'forbidden', 'Wallet session does not match walletId');
  }
  if (sessionInputs.claims.nearAccountId !== parsedBody.value.nearAccountId) {
    return routeError(403, 'forbidden', 'Wallet session does not match nearAccountId');
  }

  const result = await input.services.walletRegistration.fundImplicitNearAccount(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}
