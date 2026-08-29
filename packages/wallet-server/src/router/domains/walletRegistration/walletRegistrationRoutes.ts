import type {
  WalletRegistrationNearProvisioningResponseV2,
  WalletRegistrationActivateRouteResponseV2,
  WalletRegistrationActivateResponseV2,
  WalletRegistrationRespondResponseV2,
  WalletRegistrationSetupResponseV2,
} from '../../../core/threeRouteRegistrationContracts';
import type { RouterAbEcdsaRegistrationRequestV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { parseWalletSessionClientCapabilityV1 } from '@shared/authorization/capabilityKinds';
import type { WalletRegistrationAuthorityInput } from '../../../core/registrationContracts';
import { resolvePublishableKeyApiCredentialAuth } from '../../auth/routerApiCredentialAuth';
import { extractRouterApiEnvironmentId } from '../../auth/routerApiKeyAuth';
import type { RouterApiPublishableKeyAuthAdapter } from '../../framework/routerApi';
import type {
  RouterApiAuthorizationSessionService,
  RouterApiWalletRegistrationRouteService,
} from '../../framework/authServicePort';
import type {
  WebAuthnAuthenticationCredential,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdEd25519AuthorityScope,
  WalletKeyFactsInventoryAuth,
} from '../../../core/types';
import type {
  CreateAddAuthMethodIntentRequest,
  CreateAddSignerIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerEcdsaActivationRequest,
  WalletAddSignerEcdsaActivationResponse,
  WalletAddSignerEcdsaDerivationRespondRequest,
  WalletAddSignerEcdsaDerivationRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletAddAuthMethodEmailOtpTargetV1,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletRegistrationEcdsaActivationRequest,
  WalletRegistrationEcdsaActivationResponse,
  WalletRegistrationEcdsaFinalize,
  WalletRegistrationEd25519YaoActivationReference,
  WalletRegistrationFinalizeSignerWork,
  WalletRegistrationFinalizeRouteResponse,
  WalletRegistrationFinalizeRouteSuccess,
  WalletRegistrationFinalizeSuccess,
  PasskeyWalletRegistrationFinalizeAuthMethod,
  EmailOtpWalletRegistrationFinalizeAuthMethod,
  WalletRegistrationEcdsaDerivationRespondRequest,
  WalletRegistrationEcdsaDerivationRespondResponse,
} from '../../../core/registrationContracts';
import type { ThresholdEcdsaChainTarget } from '../../../core/thresholdEcdsaChainTarget';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
} from '../../../core/thresholdEcdsaChainTarget';
import { findUnexpectedRouteKey } from '../../framework/routeRequestValidation';
import {
  resolveActiveRuntimePolicyScopeForEnvironment,
  resolveOpaqueOwnerWalletSessionAdmission,
  resolveWalletSessionOperationCredentialAdmission,
  resolveWalletSessionOperationCredentialAdmissionFromContext,
  type WalletSessionOperationCredentialAdmission,
} from '../../auth/commonRouterUtils';
import { extractBearerCredential } from '../../auth/routerApiKeyAuth';
import { enforceRoutePolicy } from '../../framework/enforceRoutePolicy';
import type { NormalizedRouterLogger } from '../../framework/logger';
import type {
  RouterApiKeyAuthAdapter,
  RouterApiProjectEnvironmentResolver,
  SessionAdapter,
  RouterApiWalletProjectionAdapter,
} from '../../framework/routerApi';
import type {
  HeaderRecord,
  RouteResponse,
  RouteServices,
} from '../../framework/routeExecutionContext';
import type { RouteDefinition } from '../../framework/routeDefinitions';
import type { RouteErrorBody } from '../../framework/routeResponses';
import { routeError, routeJson } from '../../framework/routeResponses';
import { isPlainObject } from '@shared/utils/validation';
import { base58Encode, base64UrlDecode } from '@shared/utils/encoders';
import {
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { parsePasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parseRouterAbEcdsaRegistrationActivationRequestV1,
  parseRouterAbEcdsaRegistrationRequestV1,
  parseRouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { RouterAbPublicKeysetV2 } from '@shared/utils/routerAbPublicKeyset';
import type { WalletRegistrationActivateInput } from './walletRegistrationInputs';
import { verifyWalletRegistrationSetupClaims } from './walletRegistrationSetupPayload';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { ecdsaClientRootPublicKey33B64uFromString } from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
import { normalizeCorsOrigin } from '../../../core/SessionService';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import {
  deriveImplicitNearAccountIdFromEd25519PublicKey,
  parseImplicitNearAccountId,
} from '@shared/utils/near';
import {
  addAuthMethodIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  normalizeAddAuthMethodInput,
  normalizeAddAuthMethodIntentCaller,
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  findRegistrationSignerPlanEvmFamilyEcdsaBranch,
  findRegistrationSignerPlanNearEd25519Branch,
  normalizeEmailOtpRegistrationProof,
  normalizeRegistrationSignerPlan,
  registrationSignerSetSelectionFromPlan,
  walletIdFromString,
  type AddSignerIntentV1,
  type AddAuthMethodIntentV1,
  type AddSignerSelection,
  type RegistrationSignerPlan,
  type RegistrationSignerSetSelection,
} from '@shared/utils/registrationIntent';
import {
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnRpId,
  type WebAuthnRpId,
} from '@shared/utils/domainIds';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';
import { isEmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  parseRouterAbTraceContextV1,
  ROUTER_AB_TRACE_ID_HEADER_V1,
  type RouterAbTraceContextV1,
} from '@shared/utils/routerAbTraceContext';
import type { RouterAbEd25519YaoGatewaySpanV1 } from '../ed25519Yao/registration/routerAbEd25519YaoHttpRegistrationBackend';
import {
  parseHostedWalletSessionOperationCredentialToken,
  parsePrimaryWalletSessionOperationCredentialToken,
  parseSessionOrigin,
  type SessionOrigin,
} from '../../../authorization/domain';

type RouterApiWalletRegistrationServices = {
  walletRegistration: RouterApiWalletRegistrationRouteService;
  authorizationSessions: RouterApiAuthorizationSessionService;
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  orgProjectEnv?: RouterApiProjectEnvironmentResolver | null;
  routerAbPublicKeyset?: RouterAbPublicKeysetV2 | null;
  session?: SessionAdapter | null;
  publishableKeyAuth?: RouterApiPublishableKeyAuthAdapter | null;
  walletProjection?: RouterApiWalletProjectionAdapter | null;
};

type ParsedRegistrationSignerSet = {
  readonly selection: RegistrationSignerSetSelection;
  readonly plan: RegistrationSignerPlan;
};

type RouterApiWalletRegistrationInput = {
  body: unknown;
  headers: HeaderRecord;
  hostedWalletOrigins: readonly (string | undefined)[];
  logger: NormalizedRouterLogger;
  origin?: string;
  pathParams?: Record<string, string | undefined>;
  route: RouteDefinition;
  services: RouterApiWalletRegistrationServices;
  sourceIp?: string;
};

type ParseResult<T> = { ok: true; value: T } | { ok: false; code: 'invalid_body'; message: string };

type ParsedWalletAddAuthMethodStartRequest = Omit<WalletAddAuthMethodStartRequest, 'auth'> & {
  readonly auth:
    | Extract<WalletAddAuthMethodStartRequest['auth'], { readonly kind: 'webauthn_assertion' }>
    | { readonly kind: 'wallet_session' }
    /* Parsed, not yet resolved: the route verifies the code and turns this
       into the service's `email_otp` auth, whose identity fields come from the
       verified challenge rather than the body. */
    | {
        readonly kind: 'email_otp_source_proof';
        readonly challengeId: string;
        readonly otpCode: string;
        readonly expectedChallengeDigestB64u: string;
      };
};

type RegistrationTraceContextParseResult =
  | { readonly ok: true; readonly value: RouterAbTraceContextV1 | null }
  | { readonly ok: false; readonly message: string };

function parseRegistrationTraceContext(headers: HeaderRecord): RegistrationTraceContextParseResult {
  const rawTraceId = headers[ROUTER_AB_TRACE_ID_HEADER_V1] ?? headers['X-Seams-Trace-Id'];
  const parsed = parseRouterAbTraceContextV1(rawTraceId);
  if (parsed.ok) return { ok: true, value: parsed.value };
  if (parsed.reason === 'missing') return { ok: true, value: null };
  return { ok: false, message: parsed.message };
}

function emitGatewayD1CommitSpan(input: {
  logger: NormalizedRouterLogger;
  traceId: string | null;
  startedAt: number;
  outcome: RouterAbEd25519YaoGatewaySpanV1['outcome'];
}): void {
  if (input.traceId === null) return;
  const span: RouterAbEd25519YaoGatewaySpanV1 = {
    event: 'router_ab_yao_gateway_span_v1',
    span: 'gateway.d1_commit',
    operation: 'registration',
    outcome: input.outcome,
    duration_ms: Math.max(0, Math.round(performance.now() - input.startedAt)),
    trace_id: input.traceId,
  };
  try {
    input.logger.info(JSON.stringify(span));
  } catch {
    // Observability must never change the registration response.
  }
}

/** User-Agent of the registering request; feeds authenticator device labels. */
function registrationUserAgentFromHeaders(headers: HeaderRecord): string | undefined {
  const raw = headers['user-agent'] ?? headers['User-Agent'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  const trimmed = String(value || '').trim();
  return trimmed ? trimmed : undefined;
}

type PasskeyWalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeSuccess,
  { authMethod: PasskeyWalletRegistrationFinalizeAuthMethod }
>;

type EmailOtpWalletRegistrationFinalizeSuccess = Extract<
  WalletRegistrationFinalizeSuccess,
  { authMethod: EmailOtpWalletRegistrationFinalizeAuthMethod }
>;

type WalletRegistrationActivateSuccessV2 = Extract<
  WalletRegistrationActivateResponseV2,
  { ok: true }
>;

type EmailOtpWalletRegistrationActivateSuccessV2 = Extract<
  WalletRegistrationActivateSuccessV2,
  { authMethod: EmailOtpWalletRegistrationFinalizeAuthMethod }
>;

type PasskeyWalletRegistrationActivateSuccessV2 = Extract<
  WalletRegistrationActivateSuccessV2,
  { authMethod: PasskeyWalletRegistrationFinalizeAuthMethod }
>;

function assertNeverWalletRegistrationFinalizeKind(value: never): never {
  throw new Error(`Unsupported wallet registration finalize kind: ${String(value)}`);
}

function assertNeverWalletEcdsaInventoryAuth(value: never): never {
  throw new Error(`Unsupported wallet ECDSA inventory auth: ${String(value)}`);
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

function isEmailOtpWalletRegistrationActivateSuccessV2(
  result: WalletRegistrationActivateSuccessV2,
): result is EmailOtpWalletRegistrationActivateSuccessV2 {
  return result.authMethod.kind === 'email_otp';
}

function isPasskeyWalletRegistrationActivateSuccessV2(
  result: WalletRegistrationActivateSuccessV2,
): result is PasskeyWalletRegistrationActivateSuccessV2 {
  return result.authMethod.kind === 'passkey';
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
        foundingAuthority: result.foundingAuthority,
        foundingAuthMethod: result.foundingAuthMethod,
        registrationDiagnostics: result.registrationDiagnostics,
        rpId: result.rpId,
        authMethod: result.authMethod,
        ...(result.walletCustody ? { walletCustody: result.walletCustody } : {}),
        custodyKeyManifestDigestB64u: result.custodyKeyManifestDigestB64u,
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
        foundingAuthority: result.foundingAuthority,
        foundingAuthMethod: result.foundingAuthMethod,
        registrationDiagnostics: result.registrationDiagnostics,
        rpId: result.rpId,
        authMethod: result.authMethod,
        ...(result.walletCustody ? { walletCustody: result.walletCustody } : {}),
        custodyKeyManifestDigestB64u: result.custodyKeyManifestDigestB64u,
        kind: result.kind,
        ecdsa: result.ecdsa,
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

const ECDSA_REGISTRATION_ECDSA_DERIVATION_RESPOND_FORBIDDEN_FIELDS = [
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'sessionKind',
] as const;

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
  /* Required, and parsed here once. The branch decides what the source must
     present at `start`, and it is folded into the digest the source proof
     signs, so a proof taken for a same-device addition cannot start a
     linked-device ceremony. */
  const caller = normalizeAddAuthMethodIntentCaller(body);
  if (!caller) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method caller is invalid' };
  }
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      authMethod,
      caller,
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
  if (auth.kind === 'opaque_wallet_session' && auth.curve === 'ecdsa_secp256k1') {
    return {
      ok: true,
      value: {
        rpId: rpId.value,
        auth: { kind: 'opaque_wallet_session', curve: 'ecdsa_secp256k1' },
        keyTargets: keyTargets.value,
      },
    };
  }
  return { ok: false, code: 'invalid_body', message: 'auth.kind is unsupported' };
}

async function resolveRouteOpaqueOwnerWalletSession(
  input: RouterApiWalletRegistrationInput,
  curve: 'ecdsa' | 'ed25519',
) {
  const token = extractBearerCredential(input.headers);
  if (!token) return null;
  try {
    return await resolveOpaqueOwnerWalletSessionAdmission({
      authorizationSessions: input.services.authorizationSessions,
      token,
      curve,
      nowMs: Date.now(),
    });
  } catch {
    return null;
  }
}

type EcdsaInventorySessionAdmission = Extract<
  WalletSessionOperationCredentialAdmission,
  { readonly curve: 'ecdsa' }
>;

type EcdsaInventorySessionResolution =
  | { readonly kind: 'admitted'; readonly admission: EcdsaInventorySessionAdmission }
  | { readonly kind: 'hosted_origin_rejected' }
  | { readonly kind: 'unavailable' };

const ECDSA_INVENTORY_SESSION_OPERATION = {
  keyFamily: 'ecdsa_secp256k1',
  operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction,
} as const;

function hostedInventoryRequestOrigin(
  input: RouterApiWalletRegistrationInput,
): SessionOrigin | null {
  let requestOrigin: SessionOrigin;
  try {
    requestOrigin = parseSessionOrigin(input.origin);
  } catch {
    return null;
  }
  for (const candidate of input.hostedWalletOrigins) {
    try {
      if (parseSessionOrigin(candidate) === requestOrigin) return requestOrigin;
    } catch {
      continue;
    }
  }
  return null;
}

function admittedEcdsaInventorySession(
  resolution: ReturnType<typeof resolveWalletSessionOperationCredentialAdmissionFromContext>,
): EcdsaInventorySessionAdmission | null {
  if (resolution.kind !== 'admitted' || resolution.admission.curve !== 'ecdsa') return null;
  return resolution.admission;
}

async function resolveRouteEcdsaInventorySession(
  input: RouterApiWalletRegistrationInput,
): Promise<EcdsaInventorySessionResolution> {
  const token = extractBearerCredential(input.headers);
  if (!token) return { kind: 'unavailable' };
  const nowMs = Date.now();
  if (token.startsWith('wst_')) {
    let primaryToken: ReturnType<typeof parsePrimaryWalletSessionOperationCredentialToken>;
    try {
      primaryToken = parsePrimaryWalletSessionOperationCredentialToken(token);
    } catch {
      return { kind: 'unavailable' };
    }
    const resolution = await resolveWalletSessionOperationCredentialAdmission({
      authorizationSessions: input.services.authorizationSessions,
      token: primaryToken,
      nowMs,
      operation: ECDSA_INVENTORY_SESSION_OPERATION,
    });
    if (resolution.kind !== 'admitted' || resolution.admission.curve !== 'ecdsa') {
      return { kind: 'unavailable' };
    }
    return { kind: 'admitted', admission: resolution.admission };
  }
  if (!token.startsWith('wsh_')) return { kind: 'unavailable' };
  let hostedToken: ReturnType<typeof parseHostedWalletSessionOperationCredentialToken>;
  try {
    hostedToken = parseHostedWalletSessionOperationCredentialToken(token);
  } catch {
    return { kind: 'unavailable' };
  }
  const requestOrigin = hostedInventoryRequestOrigin(input);
  if (!requestOrigin) return { kind: 'hosted_origin_rejected' };
  const context =
    await input.services.authorizationSessions.readHostedWalletSessionOperationCredentialV2({
      tenantId: input.services.authorizationSessions.tenantId,
      token: hostedToken,
      requestOrigin,
      nowMs,
    });
  if (!context) return { kind: 'unavailable' };
  const admission = admittedEcdsaInventorySession(
    resolveWalletSessionOperationCredentialAdmissionFromContext({
      context,
      nowMs,
      operation: ECDSA_INVENTORY_SESSION_OPERATION,
    }),
  );
  if (admission) {
    return { kind: 'admitted', admission };
  }
  return { kind: 'unavailable' };
}

type NearFundingWalletSessionAdmission = {
  readonly kind: 'owner';
  readonly walletId: string;
  readonly nearAccountId: string;
};

async function resolveRouteNearFundingWalletSession(
  input: RouterApiWalletRegistrationInput,
): Promise<NearFundingWalletSessionAdmission | null> {
  const token = extractBearerCredential(input.headers);
  if (!token) return null;
  const v2 = await resolveWalletSessionOperationCredentialAdmission({
    authorizationSessions: input.services.authorizationSessions,
    token,
    nowMs: Date.now(),
    operation: {
      keyFamily: 'ed25519',
      operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction,
    },
  });
  if (v2.kind === 'admitted' && v2.admission.curve === 'ed25519') {
    const signer = v2.admission.admission.signer;
    const nearAccountId = deriveImplicitNearAccountIdFromEd25519PublicKey(
      `ed25519:${base58Encode(base64UrlDecode(signer.registeredPublicKeyB64u))}`,
    );
    return {
      kind: 'owner',
      walletId: String(v2.admission.context.authorization.session.walletId),
      nearAccountId,
    };
  }
  return null;
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
  return { ok: false, code: 'invalid_body', message: 'add-signer auth.kind is unsupported' };
}

async function parseWalletAddAuthMethodStartBody(
  body: Record<string, unknown>,
  walletId: string,
): Promise<ParseResult<ParsedWalletAddAuthMethodStartRequest>> {
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
  const targetWalletAuthMethodId = parseWalletAuthMethodId(intent.targetWalletAuthMethodId);
  if (!targetWalletAuthMethodId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method intent target method id is invalid',
    };
  }
  const intentCaller = normalizeAddAuthMethodIntentCaller(intent);
  if (!intentCaller) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method caller is invalid' };
  }
  const intentCommon = {
    version: 'add_auth_method_intent_v1',
    walletId: walletIdFromString(walletId),
    authMethod,
    targetWalletAuthMethodId: targetWalletAuthMethodId.value,
    ...(runtimePolicyScope.value ? { runtimePolicyScope: runtimePolicyScope.value } : {}),
    nonceB64u,
  } as const;
  const normalizedIntent: AddAuthMethodIntentV1 =
    intentCaller.caller === 'same_device_addition'
      ? { ...intentCommon, caller: 'same_device_addition', source: intentCaller.source }
      : { ...intentCommon, caller: 'linked_device_ceremony' };
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
  let existingAuth: ParsedWalletAddAuthMethodStartRequest['auth'];
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
  } else if (auth.kind === 'email_otp') {
    /* R109C `email_otp_to_passkey`: the source is the wallet's Email OTP
       method. The body carries only the one-time code and the digest it was
       taken over; every identity fact — provider subject, enrollment, authority
       — is resolved from the verified challenge in the route handler, so a
       caller cannot name whose method authorized the addition. */
    const emailChallengeId = typeof auth.challengeId === 'string' ? auth.challengeId.trim() : '';
    const emailOtpCode = typeof auth.otpCode === 'string' ? auth.otpCode.trim() : '';
    const emailExpectedDigest =
      typeof auth.expectedChallengeDigestB64u === 'string'
        ? auth.expectedChallengeDigestB64u.trim()
        : '';
    if (!emailChallengeId || !emailOtpCode) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'email_otp auth requires a challenge and a one-time code',
      };
    }
    if (emailExpectedDigest !== expectedDigest) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'auth.expectedChallengeDigestB64u must match add-auth-method intent digest',
      };
    }
    existingAuth = {
      kind: 'email_otp_source_proof',
      challengeId: emailChallengeId,
      otpCode: emailOtpCode,
      expectedChallengeDigestB64u: emailExpectedDigest,
    };
  } else if (auth.kind === 'wallet_session') {
    /* R103 zero-prompt handoff: the body names only the auth kind. Every
       identity fact is resolved from the verified bearer admission in the
       route handler before a service request is built. */
    if (Object.keys(auth).length !== 1) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'wallet_session auth carries no body facts',
      };
    }
    existingAuth = {
      kind: 'wallet_session',
    };
  } else {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method auth.kind is unsupported',
    };
  }

  let authority: WalletAddAuthMethodStartRequest['authority'];
  if (normalizedIntent.authMethod.kind === 'passkey') {
    if (Object.prototype.hasOwnProperty.call(body, 'webauthnRegistration')) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'webauthnRegistration belongs on add-auth-method finalize',
      };
    }
    authority = { kind: 'passkey' };
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

function parseActivationRequestDigest(value: unknown): RouterAbPublicDigest32V1Wire | null {
  if (!isPlainObject(value) || !Array.isArray(value.bytes) || value.bytes.length !== 32)
    return null;
  const bytes: number[] = [];
  for (const entry of value.bytes) {
    if (!Number.isInteger(entry) || Number(entry) < 0 || Number(entry) > 255) return null;
    bytes.push(Number(entry));
  }
  return { bytes };
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
    typeof ecdsa.expectedKeyHandles[0] === 'string' ? ecdsa.expectedKeyHandles[0].trim() : '';
  if (!expectedKeyHandle) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ecdsa.expectedKeyHandles contains an invalid family key handle',
    };
  }
  return { ok: true, value: { expectedKeyHandles: [expectedKeyHandle] } };
}

type WalletAddSignerNearCustodyKeySet = Extract<
  WalletAddSignerFinalizeRequest,
  { kind: 'near_ed25519' }
>['custodyKeySet'];
type WalletAddSignerEcdsaCustodyKeySet = Extract<
  WalletAddSignerFinalizeRequest,
  { kind: 'evm_family_ecdsa' }
>['custodyKeySet'];

function parseWalletAddSignerCustodyKeySet(
  raw: unknown,
  kind: 'near_ed25519',
): ParseResult<WalletAddSignerNearCustodyKeySet>;
function parseWalletAddSignerCustodyKeySet(
  raw: unknown,
  kind: 'evm_family_ecdsa',
): ParseResult<WalletAddSignerEcdsaCustodyKeySet>;
function parseWalletAddSignerCustodyKeySet(
  raw: unknown,
  kind: 'near_ed25519' | 'evm_family_ecdsa',
): ParseResult<WalletAddSignerNearCustodyKeySet | WalletAddSignerEcdsaCustodyKeySet> {
  const custodyKeySet = isPlainObject(raw) ? raw : null;
  if (!custodyKeySet) {
    return { ok: false, code: 'invalid_body', message: 'custodyKeySet is required' };
  }
  const expectedKind = kind === 'near_ed25519' ? 'near_ed25519_v1' : 'evm_family_ecdsa_v1';
  if (custodyKeySet.kind !== expectedKind) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `custodyKeySet.kind must be ${expectedKind}`,
    };
  }
  let keyManifestDigestB64u: string;
  try {
    keyManifestDigestB64u = parseDigestB64u(custodyKeySet.keyManifestDigestB64u);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'custodyKeySet.keyManifestDigestB64u is invalid',
    };
  }
  if (kind === 'near_ed25519') {
    const registeredPublicKeyB64u = trimRequiredString(
      custodyKeySet,
      'registeredPublicKeyB64u',
      'custodyKeySet.registeredPublicKeyB64u is required',
    );
    if (!registeredPublicKeyB64u.ok) return registeredPublicKeyB64u;
    return {
      ok: true,
      value: {
        kind: 'near_ed25519_v1',
        keyManifestDigestB64u,
        registeredPublicKeyB64u: registeredPublicKeyB64u.value,
      },
    };
  }
  const clientRootPublicKeyRaw = trimRequiredString(
    custodyKeySet,
    'clientRootPublicKey33B64u',
    'custodyKeySet.clientRootPublicKey33B64u is required',
  );
  if (!clientRootPublicKeyRaw.ok) return clientRootPublicKeyRaw;
  try {
    return {
      ok: true,
      value: {
        kind: 'evm_family_ecdsa_v1',
        keyManifestDigestB64u,
        clientRootPublicKey33B64u: ecdsaClientRootPublicKey33B64uFromString(
          clientRootPublicKeyRaw.value,
        ),
      },
    };
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'custodyKeySet.clientRootPublicKey33B64u is invalid',
    };
  }
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
  const unknownEcdsaField = findUnknownField(ecdsa, [
    'kind',
    'strictRegistration',
    'requestDigestB64u',
  ]);
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
  const requestDigestB64u = parseRegistrationRequestDigestB64u(ecdsa.requestDigestB64u);
  if (!requestDigestB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA add-signer requestDigestB64u must contain 32 base64url bytes',
    };
  }
  return {
    ok: true,
    value: {
      addSignerCeremonyId: addSignerCeremonyId.value,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration,
        requestDigestB64u,
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
  const unknownEcdsaField = findUnknownField(ecdsa, [
    'kind',
    'activationCorrelationId',
    'publicFacts',
    'expectedActivationRequestDigest',
  ]);
  if (unknownEcdsaField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `add-signer ECDSA activation field ${unknownEcdsaField} is unsupported`,
    };
  }
  try {
    const parsed = parseRouterAbEcdsaRegistrationActivationRequestV1({
      registrationCeremonyId: addSignerCeremonyId.value,
      ecdsa: {
        kind: ecdsa.kind,
        activationCorrelationId: ecdsa.activationCorrelationId,
        publicFacts: ecdsa.publicFacts,
      },
    });
    const expectedActivationRequestDigest = parseActivationRequestDigest(
      ecdsa.expectedActivationRequestDigest,
    );
    if (!expectedActivationRequestDigest) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ECDSA activation request digest is invalid',
      };
    }
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_v1',
          activationCorrelationId: parsed.ecdsa.activationCorrelationId,
          publicFacts: parsed.ecdsa.publicFacts,
          expectedActivationRequestDigest,
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
    const custodyKeySet = parseWalletAddSignerCustodyKeySet(body.custodyKeySet, 'near_ed25519');
    if (!custodyKeySet.ok) return custodyKeySet;
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        idempotencyKey: idempotencyKey.value,
        kind: 'near_ed25519',
        ed25519: ed25519.value,
        custodyKeySet: custodyKeySet.value,
      },
    };
  }
  if (body.kind === 'evm_family_ecdsa') {
    if (Object.prototype.hasOwnProperty.call(body, 'ed25519')) {
      return { ok: false, code: 'invalid_body', message: 'ECDSA finalize cannot carry Ed25519' };
    }
    const ecdsa = parseWalletRegistrationEcdsaFinalize(body.ecdsa);
    if (!ecdsa.ok) return ecdsa;
    const custodyKeySet = parseWalletAddSignerCustodyKeySet(body.custodyKeySet, 'evm_family_ecdsa');
    if (!custodyKeySet.ok) return custodyKeySet;
    return {
      ok: true,
      value: {
        addSignerCeremonyId: addSignerCeremonyId.value,
        idempotencyKey: idempotencyKey.value,
        kind: 'evm_family_ecdsa',
        ecdsa: ecdsa.value,
        custodyKeySet: custodyKeySet.value,
      },
    };
  }
  return { ok: false, code: 'invalid_body', message: 'add-signer finalize kind is invalid' };
}

/**
 * The caller's statement about the wallet's shared Email OTP enrollment.
 *
 * Required on this branch rather than optional. The two cases carry different
 * material and land on different persistence, and a body that simply omitted
 * the field would read as "reuse whatever is there" — which on a wallet with no
 * enrollment is not a reusable state, and on a wallet with one is a claim the
 * caller never made.
 */
function parseWalletAddAuthMethodEmailOtpTarget(
  raw: unknown,
):
  | { readonly ok: true; readonly value: WalletAddAuthMethodEmailOtpTargetV1 }
  | { readonly ok: false; readonly code: 'invalid_body'; readonly message: string } {
  if (!isPlainObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpTarget is required for an Email OTP add-auth-method finalize',
    };
  }
  if (raw.kind === 'existing_enrollment') {
    if (raw.enrollment !== undefined) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'emailOtpTarget.enrollment belongs to the new_enrollment branch',
      };
    }
    return { ok: true, value: { kind: 'existing_enrollment' } };
  }
  if (raw.kind !== 'new_enrollment') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpTarget.kind must be existing_enrollment or new_enrollment',
    };
  }
  const enrollment = raw.enrollment;
  if (!isPlainObject(enrollment)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'emailOtpTarget.enrollment is required to create an enrollment',
    };
  }
  const material = {
    enrollmentSealKeyVersion: '',
    clientUnlockPublicKeyB64u: '',
    unlockKeyVersion: '',
    serverSealedFactorCiphertextB64u: '',
  };
  for (const field of Object.keys(material) as (keyof typeof material)[]) {
    const value = enrollment[field];
    if (typeof value !== 'string' || !value.trim()) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `emailOtpTarget.enrollment.${field} is required`,
      };
    }
    material[field] = value.trim();
  }
  return { ok: true, value: { kind: 'new_enrollment', enrollment: material } };
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
  const hasRegistration = Object.prototype.hasOwnProperty.call(body, 'webauthnRegistration');
  const hasEnvelope = Object.prototype.hasOwnProperty.call(body, 'custodyEnvelope');
  if (hasRegistration && !hasEnvelope) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'a WebAuthn registration must be finalized with its custody envelope',
    };
  }
  if (!hasRegistration && hasEnvelope) {
    /* R109C's Email OTP target: the factor was verified by its one-use grant
       rather than by a created credential, so the body carries the resealed
       envelope alone. Requiring the pair here would refuse the exact request
       the finalize service now demands for this branch. */
    const emailOtpTarget = parseWalletAddAuthMethodEmailOtpTarget(body.emailOtpTarget);
    if (!emailOtpTarget.ok) return emailOtpTarget;
    try {
      return {
        ok: true,
        value: {
          addAuthMethodCeremonyId: addAuthMethodCeremonyId.value,
          custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(body.custodyEnvelope),
          emailOtpTarget: emailOtpTarget.value,
        },
      };
    } catch {
      return { ok: false, code: 'invalid_body', message: 'custodyEnvelope is invalid' };
    }
  }
  if (hasRegistration) {
    try {
      return {
        ok: true,
        value: {
          addAuthMethodCeremonyId: addAuthMethodCeremonyId.value,
          webauthnRegistration: body.webauthnRegistration,
          custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(body.custodyEnvelope),
        },
      };
    } catch {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'custodyEnvelope is invalid',
      };
    }
  }
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
  const keys = Object.keys(body).sort();
  if (
    keys.length !== 4 ||
    keys[0] !== 'requestedAtMs' ||
    keys[1] !== 'sourceProof' ||
    keys[2] !== 'walletAuthMethodId' ||
    keys[3] !== 'walletId'
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'auth-method revoke body fields are invalid',
    };
  }
  const requestedAtMs = Number(body.requestedAtMs);
  if (!Number.isSafeInteger(requestedAtMs) || requestedAtMs < 0) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'requestedAtMs is invalid',
    };
  }
  const bodyWalletId = typeof body.walletId === 'string' ? body.walletId.trim() : '';
  if (!bodyWalletId || bodyWalletId !== walletId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'walletId path and body values must agree',
    };
  }
  const walletAuthMethodId = parseWalletAuthMethodId(body.walletAuthMethodId);
  if (!walletAuthMethodId.ok) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'walletAuthMethodId is invalid',
    };
  }
  const sourceProof = parseWalletRevokeAuthMethodSourceProof(body.sourceProof);
  if (!sourceProof.ok) return sourceProof;
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      walletAuthMethodId: walletAuthMethodId.value,
      requestedAtMs,
      sourceProof: sourceProof.value,
    },
  };
}

function parseWalletRevokeAuthMethodSourceProof(
  raw: unknown,
): ParseResult<WalletRevokeAuthMethodRequest['sourceProof']> {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'sourceProof is required' };
  }
  if (raw.kind === 'webauthn_assertion') {
    const rpId = parseWebAuthnRpId(raw.rpId);
    if (!rpId.ok) return { ok: false, code: 'invalid_body', message: rpId.error.message };
    const credential = parseWebAuthnAuthenticationCredential(raw.credential);
    if (!credential.ok) return credential;
    const expectedChallengeDigestB64u =
      typeof raw.expectedChallengeDigestB64u === 'string'
        ? raw.expectedChallengeDigestB64u.trim()
        : '';
    if (!expectedChallengeDigestB64u) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'sourceProof.expectedChallengeDigestB64u is required',
      };
    }
    if (!hasExactObjectKeys(raw, ['credential', 'expectedChallengeDigestB64u', 'kind', 'rpId'])) {
      return { ok: false, code: 'invalid_body', message: 'sourceProof fields are invalid' };
    }
    return {
      ok: true,
      value: {
        kind: 'webauthn_assertion',
        rpId: rpId.value,
        credential: credential.value,
        expectedChallengeDigestB64u,
      },
    };
  }
  if (raw.kind === 'email_otp') {
    if (
      !hasExactObjectKeys(raw, ['challengeId', 'kind', 'otpCode', 'ownerProofBindingDigest']) ||
      typeof raw.challengeId !== 'string' ||
      typeof raw.otpCode !== 'string' ||
      typeof raw.ownerProofBindingDigest !== 'string' ||
      !raw.challengeId.trim() ||
      !raw.otpCode.trim() ||
      !raw.ownerProofBindingDigest.trim()
    ) {
      return { ok: false, code: 'invalid_body', message: 'sourceProof fields are invalid' };
    }
    return {
      ok: true,
      value: {
        kind: 'email_otp',
        challengeId: raw.challengeId.trim(),
        otpCode: raw.otpCode.trim(),
        ownerProofBindingDigest: raw.ownerProofBindingDigest.trim(),
      },
    };
  }
  return { ok: false, code: 'invalid_body', message: 'sourceProof.kind is unsupported' };
}

function hasExactObjectKeys(input: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(input).sort();
  const keys = [...expected].sort();
  return actual.length === keys.length && actual.every((key, index) => key === keys[index]);
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
  const publishableKeyAuth = input.services.publishableKeyAuth;
  if (!publishableKeyAuth) {
    return routeError(
      500,
      'route_auth_not_configured',
      'wallet add-signer intent requires publishable key auth on this server',
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
        await resolvePublishableKeyApiCredentialAuth({
          environmentId: extractRouterApiEnvironmentId(input.headers) || undefined,
          headers: input.headers,
          missingEnvironmentMessage: 'Environment header is required for add-signer intent',
          missingOriginMessage: 'Origin header is required and must be a valid exact origin',
          missingPublishableKeyMessage: 'Missing publishable key',
          origin,
          publishableKeyAuth,
          route: input.route,
          routeAuthNotConfiguredMessage: 'Add-signer intent requires API credential auth policy',
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
    command: {
      subject: { kind: 'wallet_signer_management', walletId: request.value.walletId },
      signerSelection: request.value.signerSelection,
    },
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

/**
 * Refactor 94C. `POST /wallets/register/setup` — the single admitted entry
 * point that replaces the bootstrap grant, the intent, and start.
 *
 * Authentication is the same API-credential plane the intent route used, so
 * origin and environment binding are unchanged; what is gone is the stored
 * grant that used to sit between the check and its only reader.
 */
export async function handleRouterApiWalletRegistrationSetup(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationSetupResponseV2 | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const origin = normalizeCorsOrigin(input.origin);
  if (!origin) {
    return routeError(
      403,
      'forbidden',
      'Origin header is required and must be a valid exact origin',
    );
  }
  const publishableKeyAuth = input.services.publishableKeyAuth;
  if (!publishableKeyAuth) {
    return routeError(
      500,
      'route_auth_not_configured',
      'wallet registration setup requires publishable key auth on this server',
    );
  }
  /* Publishable key only. The client authenticates directly, so there is no
     bootstrap token to mint, store, and read back — and deliberately no
     secret-key or bootstrap-token fallback, which would reintroduce the
     credential the grant existed to carry. */
  const resolved = await enforceRoutePolicy({
    headers: input.headers,
    logger: input.logger,
    request: { body: input.body, headers: input.headers },
    route: input.route,
    services: walletRegistrationRoutePolicyServices(input),
    sourceIp: input.sourceIp,
    resolvers: {
      apiCredentials: async () =>
        await resolvePublishableKeyApiCredentialAuth({
          environmentId: extractRouterApiEnvironmentId(input.headers) || undefined,
          headers: input.headers,
          missingEnvironmentMessage: 'Environment header is required for wallet registration setup',
          missingOriginMessage: 'Origin header is required and must be a valid exact origin',
          missingPublishableKeyMessage: 'Missing publishable key',
          origin,
          publishableKeyAuth,
          route: input.route,
          routeAuthNotConfiguredMessage:
            'Wallet registration setup requires API credential auth policy',
        }),
    },
  });
  if (!resolved.ok) return routeJson(resolved.status, resolved.body);
  if (resolved.context.principal.kind !== 'api_credentials') {
    return routeError(500, 'internal', 'wallet registration setup requires API credentials');
  }
  const principal = resolved.context.principal.principal;
  const runtimePolicyScope = await resolveActiveRuntimePolicyScopeForEnvironment({
    orgProjectEnv: input.services.orgProjectEnv || null,
    orgId: principal.orgId,
    environmentId: principal.environmentId,
    projectId: principal.projectId,
    envId: principal.envId,
  });
  const session = input.services.session;
  if (!session) {
    return routeError(500, 'internal', 'wallet registration setup requires session signing');
  }
  const body = input.body as Record<string, unknown>;
  const result = await input.services.walletRegistration.setupWalletRegistration({
    request: {
      ...(isPlainObject(body.wallet) ? { wallet: body.wallet as never } : {}),
      signerSelection: body.signerSelection as never,
      authMethod: body.authMethod as never,
    },
    orgId: principal.orgId,
    expectedOrigin: origin,
    signer: session,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(runtimePolicyScope
      ? {
          signingRootId: `${runtimePolicyScope.projectId}:${runtimePolicyScope.envId}`,
          signingRootVersion: runtimePolicyScope.signingRootVersion,
        }
      : {}),
  });
  return routeJson(result.ok ? 200 : 400, result);
}

/**
 * Refactor 94C. `POST /wallets/register/respond` — the authenticated leg.
 *
 * Bearing the proof, so it is a public-plane route authorized by the signed
 * setup payload plus the WebAuthn or Email OTP proof, exactly as the
 * derivation respond leg it replaces was.
 */
export async function handleRouterApiWalletRegistrationRespond(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationRespondResponseV2 | RouteErrorBody>> {
  const traceContext = parseRegistrationTraceContext(input.headers);
  if (!traceContext.ok) return routeError(400, 'invalid_trace_id', traceContext.message);
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const session = input.services.session;
  if (!session) {
    return routeError(500, 'internal', 'wallet registration respond requires session signing');
  }
  const parsed = parseWalletRegistrationRespondRequest(input.body);
  if (!parsed.ok) return routeError(400, parsed.code, parsed.message);
  const result = await input.services.walletRegistration.respondWalletRegistration(
    {
      ...parsed.value,
      verifier: session,
      ...(registrationUserAgentFromHeaders(input.headers)
        ? { userAgent: registrationUserAgentFromHeaders(input.headers) }
        : {}),
    },
    traceContext.value ?? undefined,
  );
  return routeJson(result.ok ? 200 : 400, result);
}

/**
 * Parses respond's public body. `signedSetup` stays an opaque string here —
 * the service verifies it; parsing its contents at the boundary would invite
 * trusting them before verification.
 */
function parseWalletRegistrationRespondRequest(body: unknown): ParseResult<{
  registrationCeremonyId: string;
  signedSetup: string;
  authority: WalletRegistrationAuthorityInput;
  planKind: 'evm_family_ecdsa' | 'near_ed25519_and_evm_family_ecdsa' | 'near_ed25519';
  ecdsa?: {
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
    requestDigestB64u: string;
  };
}> {
  if (!isPlainObject(body)) {
    return { ok: false, code: 'invalid_body', message: 'JSON body required' };
  }
  const registrationCeremonyId = String(body.registrationCeremonyId || '').trim();
  if (!registrationCeremonyId) {
    return { ok: false, code: 'invalid_body', message: 'registrationCeremonyId is required' };
  }
  const signedSetup = String(body.signedSetup || '').trim();
  if (!signedSetup) {
    return { ok: false, code: 'invalid_body', message: 'signedSetup is required' };
  }
  /* The signer-plan discriminant. The service checks it against the plan the
     ceremony actually recorded, so a caller cannot drive an Ed25519-only
     ceremony down the ECDSA arm or the reverse. */
  const planKind = String(body.kind || '').trim();
  if (
    planKind !== 'evm_family_ecdsa' &&
    planKind !== 'near_ed25519_and_evm_family_ecdsa' &&
    planKind !== 'near_ed25519'
  ) {
    return { ok: false, code: 'invalid_body', message: 'kind must name the signer plan' };
  }
  if (planKind === 'near_ed25519' && body.ecdsa !== undefined) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'an Ed25519-only respond carries no ECDSA registration',
    };
  }
  /* Exactly one proof branch; the auth method the ceremony recorded decides
     which one is admissible, and the service rejects a mismatch. */
  const hasWebAuthn = Object.prototype.hasOwnProperty.call(body, 'webauthn_registration');
  const hasEmailOtp = Object.prototype.hasOwnProperty.call(body, 'emailOtpRegistrationProof');
  if (hasWebAuthn === hasEmailOtp) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'exactly one registration authority proof is required',
    };
  }
  let authority: WalletRegistrationAuthorityInput;
  if (hasWebAuthn) {
    authority = { kind: 'passkey', webauthnRegistration: body.webauthn_registration };
  } else {
    const proof = normalizeEmailOtpRegistrationProof(body.emailOtpRegistrationProof);
    if (!proof) {
      return { ok: false, code: 'invalid_body', message: 'emailOtpRegistrationProof is invalid' };
    }
    authority = { kind: 'email_otp', emailOtpRegistrationProof: proof };
  }
  if (planKind === 'near_ed25519') {
    return {
      ok: true,
      value: { registrationCeremonyId, signedSetup, authority, planKind },
    };
  }
  const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
  if (!ecdsa || ecdsa.kind !== 'router_ab_ecdsa_registration_v1') {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA registration request is required',
    };
  }
  let strictRegistration: RouterAbEcdsaRegistrationRequestV1;
  try {
    strictRegistration = parseRouterAbEcdsaRegistrationRequestV1(ecdsa.strictRegistration);
  } catch {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'strict Router A/B ECDSA registration request is invalid',
    };
  }
  const requestDigestB64u = parseRegistrationRequestDigestB64u(ecdsa.requestDigestB64u);
  if (!requestDigestB64u) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'ECDSA registration requestDigestB64u must contain 32 base64url bytes',
    };
  }
  return {
    ok: true,
    value: {
      registrationCeremonyId,
      signedSetup,
      authority,
      planKind,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration,
        requestDigestB64u,
      },
    },
  };
}

function parseRegistrationRequestDigestB64u(raw: unknown): string | null {
  const value = typeof raw === 'string' ? raw.trim() : '';
  if (!value || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    return base64UrlDecode(value).byteLength === 32 ? value : null;
  } catch {
    return null;
  }
}

async function projectActivatedWallet(input: {
  readonly registrationCeremonyId: string;
  readonly services: RouterApiWalletRegistrationServices;
  readonly signedSetup: unknown;
}): Promise<string | null> {
  const walletProjection = input.services.walletProjection || null;
  if (!walletProjection) return null;
  const verifier = input.services.session;
  if (!verifier) return 'wallet projection requires setup verification';
  const verified = await verifyWalletRegistrationSetupClaims(verifier, input.signedSetup, {
    registrationCeremonyId: input.registrationCeremonyId,
    nowMs: Date.now(),
  });
  if (!verified.ok) return verified.message;
  if (verified.claims.policy.kind !== 'runtime_policy_scope') {
    return 'wallet projection requires an exact runtime policy scope';
  }
  if (verified.claims.policy.scope.orgId !== verified.claims.orgId) {
    return 'wallet projection scope does not match its organization';
  }
  try {
    await walletProjection.recordCreatedWallet({
      orgId: verified.claims.orgId,
      runtimePolicyScope: verified.claims.policy.scope,
      walletId: verified.claims.walletId,
      occurredAt: new Date().toISOString(),
    });
    return null;
  } catch (error: unknown) {
    return error instanceof Error ? error.message : String(error);
  }
}

/**
 * Refactor 94C. `POST /wallets/register/activate` — activation and
 * finalization behind one Gateway operation row.
 */
export async function handleRouterApiWalletRegistrationActivate(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationActivateRouteResponseV2 | RouteErrorBody>> {
  const traceContext = parseRegistrationTraceContext(input.headers);
  if (!traceContext.ok) return routeError(400, 'invalid_trace_id', traceContext.message);
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const session = input.services.session;
  if (!session) {
    return routeError(500, 'internal', 'wallet registration activate requires setup verification');
  }
  const body = input.body as Record<string, unknown>;
  const registrationCeremonyId = String(body.registrationCeremonyId || '').trim();
  if (!registrationCeremonyId) {
    return routeError(400, 'invalid_body', 'registrationCeremonyId is required');
  }
  const signedSetup = String(body.signedSetup || '').trim();
  if (!signedSetup) return routeError(400, 'invalid_body', 'signedSetup is required');
  const idempotencyKey = String(body.idempotencyKey || '').trim();
  if (!idempotencyKey) return routeError(400, 'invalid_body', 'idempotencyKey is required');
  const parsedWalletSessionClientCapability = parseWalletSessionClientCapabilityV1(
    body.walletSessionClientCapability,
  );
  if (!parsedWalletSessionClientCapability.ok) {
    return routeError(
      400,
      'invalid_body',
      parsedWalletSessionClientCapability.error.message,
    );
  }
  const planKind = String(body.kind || '').trim();
  if (
    planKind !== 'evm_family_ecdsa' &&
    planKind !== 'near_ed25519_and_evm_family_ecdsa' &&
    planKind !== 'near_ed25519'
  ) {
    return routeError(400, 'invalid_body', 'kind must name the signer plan');
  }
  const ed25519Only = planKind === 'near_ed25519';
  if (ed25519Only && body.ecdsa !== undefined) {
    return routeError(400, 'invalid_body', 'an Ed25519-only activate carries no ECDSA activation');
  }
  const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
  const unknownEcdsaField = ecdsa
    ? findUnknownField(ecdsa, [
        'activationCorrelationId',
        'activationRequestDigestB64u',
        'clientActivation',
      ])
    : null;
  if (unknownEcdsaField) {
    return routeError(
      400,
      'invalid_body',
      `wallet registration ECDSA activation field ${unknownEcdsaField} is unsupported`,
    );
  }
  if (
    !ed25519Only &&
    (!ecdsa ||
      typeof ecdsa.activationCorrelationId !== 'string' ||
      typeof ecdsa.activationRequestDigestB64u !== 'string' ||
      !isPlainObject(ecdsa.clientActivation))
  ) {
    return routeError(400, 'invalid_body', 'browser-verified clientActivation is required');
  }
  let parsedActivation: WalletRegistrationActivateInput['ecdsa'];
  if (ecdsa) {
    try {
      const parsed = parseRouterAbEcdsaRegistrationActivationRequestV1({
        registrationCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_activation_v1',
          activationCorrelationId: ecdsa.activationCorrelationId,
          publicFacts: ecdsa.clientActivation,
        },
      });
      parsedActivation = {
        activationCorrelationId: parsed.ecdsa.activationCorrelationId,
        activationRequestDigestB64u: parseDigestB64u(ecdsa.activationRequestDigestB64u),
        clientActivation: parsed.ecdsa.publicFacts,
      };
    } catch {
      return routeError(400, 'invalid_body', 'ECDSA activation facts are invalid');
    }
  }
  const result = await input.services.walletRegistration.activateWalletRegistration(
    {
      registrationCeremonyId,
      signedSetup,
      idempotencyKey,
      walletSessionClientCapability: parsedWalletSessionClientCapability.value,
      planKind,
      ...(parsedActivation ? { ecdsa: parsedActivation } : {}),
      ...(body.emailOtpEnrollment ? { emailOtpEnrollment: body.emailOtpEnrollment } : {}),
      /* Passed through untouched. Rejecting a malformed custody payload at the
         route would fail an activation the wallet's registration survives, and
         the client would learn nothing about its seed. */
      ...(body.walletCustodyCommit !== undefined
        ? { walletCustodyCommit: body.walletCustodyCommit }
        : {}),
      verifier: session,
    },
    traceContext.value ?? undefined,
  );
  if (!result.ok) return routeJson(400, result);
  if (
    !isEmailOtpWalletRegistrationActivateSuccessV2(result) &&
    !isPasskeyWalletRegistrationActivateSuccessV2(result)
  ) {
    return routeError(
      500,
      'internal',
      'Wallet registration activation returned an invalid authority',
    );
  }
  const projectionError = await projectActivatedWallet({
    registrationCeremonyId,
    services: input.services,
    signedSetup,
  });
  if (projectionError) {
    return routeError(
      500,
      'internal',
      `Wallet was created but its Console projection failed: ${projectionError}`,
    );
  }
  return routeJson(200, result);
}

/**
 * Refactor 94C. `POST /wallets/register/near-provisioning` — the non-blocking
 * completion the client calls after activate, once its already-running Yao
 * computation produces an activation.
 */
export async function handleRouterApiWalletRegistrationNearProvisioning(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationNearProvisioningResponseV2 | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const session = input.services.session;
  if (!session) {
    return routeError(500, 'internal', 'NEAR provisioning requires setup verification');
  }
  const body = input.body as Record<string, unknown>;
  const registrationCeremonyId = String(body.registrationCeremonyId || '').trim();
  const signedSetup = String(body.signedSetup || '').trim();
  const idempotencyKey = String(body.idempotencyKey || '').trim();
  if (!registrationCeremonyId || !signedSetup || !idempotencyKey) {
    return routeError(
      400,
      'invalid_body',
      'registrationCeremonyId, signedSetup and idempotencyKey are required',
    );
  }
  const parsedWalletSessionClientCapability = parseWalletSessionClientCapabilityV1(
    body.walletSessionClientCapability,
  );
  if (!parsedWalletSessionClientCapability.ok) {
    return routeError(
      400,
      'invalid_body',
      parsedWalletSessionClientCapability.error.message,
    );
  }
  const ed25519 = isPlainObject(body.ed25519) ? body.ed25519 : null;
  if (!ed25519) {
    return routeError(400, 'invalid_body', 'ed25519 activation reference is required');
  }
  const result = await input.services.walletRegistration.completeWalletRegistrationNearProvisioning(
    {
      registrationCeremonyId,
      signedSetup,
      idempotencyKey,
      walletSessionClientCapability: parsedWalletSessionClientCapability.value,
      ed25519,
      emailOtpEnrollment: body.emailOtpEnrollment,
      ...(body.walletCustodyCommit !== undefined
        ? { walletCustodyCommit: body.walletCustodyCommit }
        : {}),
      verifier: session,
    },
  );
  if (!result.ok) return routeJson(400, result);
  return routeJson(200, result);
}

/**
 * Formats Gateway boundary timings as a `Server-Timing` header value and
 * removes them from the response body. The wire body must stay byte-identical
 * to the uninstrumented response; only the header carries timing. Fixed metric
 * names and numeric durations only.
 */
function takeEcdsaGatewayServerTiming<
  T extends { ok: boolean; gatewayServerTiming?: readonly (readonly [string, number])[] },
>(result: T): { body: T; headers?: Record<string, string> } {
  if (!result.ok || !result.gatewayServerTiming?.length) {
    const { gatewayServerTiming: _dropped, ...body } = result;
    return { body: body as T };
  }
  const header = result.gatewayServerTiming
    .map(([name, durationMs]) => `${name};dur=${Math.max(0, durationMs).toFixed(1)}`)
    .join(', ');
  const { gatewayServerTiming: _stripped, ...body } = result;
  return { body: body as T, headers: { 'Server-Timing': header } };
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
    const admission = await resolveRouteOpaqueOwnerWalletSession(input, 'ecdsa');
    if (!admission || admission.curve !== 'ecdsa') {
      return routeError(401, 'unauthorized', 'Opaque ECDSA Wallet Session is unavailable');
    }
    if (admission.binding.walletId !== walletId) {
      return routeError(403, 'forbidden', 'Wallet session does not match walletId');
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
  const result = await input.services.walletRegistration.respondWalletAddSignerEcdsaDerivation(
    request.value,
  );
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
  const publishableKeyAuth = input.services.publishableKeyAuth;
  if (!publishableKeyAuth) {
    return routeError(
      500,
      'route_auth_not_configured',
      'wallet add-auth-method intent requires publishable key auth on this server',
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
        await resolvePublishableKeyApiCredentialAuth({
          environmentId: extractRouterApiEnvironmentId(input.headers) || undefined,
          headers: input.headers,
          missingEnvironmentMessage: 'Environment header is required for add-auth-method intent',
          missingOriginMessage: 'Origin header is required and must be a valid exact origin',
          missingPublishableKeyMessage: 'Missing publishable key',
          origin,
          publishableKeyAuth,
          route: input.route,
          routeAuthNotConfiguredMessage:
            'Add-auth-method intent requires API credential auth policy',
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
    command: {
      subject: { kind: 'wallet_auth_method_management', walletId: request.value.walletId },
      authMethod: request.value.authMethod,
      caller: request.value.caller,
    },
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

/**
 * Sends the enrollment code for an Email OTP addition.
 *
 * The intent grant is the whole gate. The address is read from the intent the
 * grant names rather than taken from the body: a caller able to name the
 * recipient could send any wallet's enrollment code anywhere, and the grant is
 * the only evidence this addition was authorized at all.
 */
export async function handleRouterApiWalletAddAuthMethodEmailOtpChallenge(
  input: RouterApiWalletRegistrationInput,
): Promise<
  RouteResponse<
    | {
        readonly ok: true;
        readonly challengeId: string;
        readonly expiresAtMs: number;
        readonly emailHint: string;
      }
    /* Looser than `RouteErrorBody` on purpose: the OTP issuer's codes —
       rate_limited, locked_out — are its vocabulary, and collapsing them into
       the route's would tell a caller "bad request" when the answer is "wait". */
    | { readonly ok: false; readonly code: string; readonly message: string }
  >
> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const rawWalletId = String(input.pathParams?.walletId || '').trim();
  const walletId = parseWalletId(rawWalletId);
  if (!walletId.ok) return routeError(400, 'invalid_body', 'walletId is required');
  const grant = addAuthMethodIntentGrantFromString(
    String(input.body.addAuthMethodIntentGrant || '').trim(),
  );
  const digestB64u = String(input.body.addAuthMethodIntentDigestB64u || '').trim();
  if (!grant || !digestB64u) {
    return routeError(
      400,
      'invalid_body',
      'addAuthMethodIntentGrant and addAuthMethodIntentDigestB64u are required',
    );
  }
  const result = await input.services.walletRegistration.createAddAuthMethodEmailOtpChallenge({
    walletId: walletId.value,
    addAuthMethodIntentGrant: grant,
    addAuthMethodIntentDigestB64u: digestB64u,
  });
  /* Only the grant and the intent identity are gates here, so everything the
     issuer refuses for — an expired grant, a rate limit — is a bad request
     rather than a refusal to authorize. The issuer's own code is kept in the
     body so a caller can still tell a lockout from a typo. */
  if (!result.ok) {
    if (result.code === 'unauthorized') {
      return routeError(401, 'unauthorized', result.message);
    }
    if (result.code === 'internal') {
      return routeError(500, 'internal', result.message);
    }
    return routeJson(400, { ok: false, code: result.code, message: result.message });
  }
  return routeJson(200, result);
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
  const parsedRequest = parsedBody.value;
  let request: WalletAddAuthMethodStartRequest;
  if (parsedRequest.auth.kind === 'webauthn_assertion') {
    /* The mirror of the refusal below: a fresh assertion is what a same-device
       addition presents, and the linked-device ceremony start has no local
       source factor to produce one. */
    if (parsedRequest.intent.caller !== 'same_device_addition') {
      return routeError(
        401,
        'unauthorized',
        'Linked-device add-auth-method start requires the owner Wallet Session handoff',
      );
    }
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const parsedRpId = requireWebAuthnRpId(parsedRequest.auth.rpId);
    if (!parsedRpId.ok) return parsedRpId.response;
    const verified = await input.services.walletRegistration.verifyWebAuthnAuthenticationLite({
      userId: walletId,
      rpId: parsedRpId.rpId,
      expectedChallenge: parsedRequest.auth.expectedChallengeDigestB64u,
      expected_origin: origin.expectedOrigin,
      webauthn_authentication: parsedRequest.auth.credential,
    });
    if (!verified.success || !verified.verified) {
      return routeError(
        401,
        'unauthorized',
        verified.message || 'Invalid add-auth-method WebAuthn authorization',
      );
    }
    const auth = parsedRequest.auth;
    request = {
      ...parsedRequest,
      auth: {
        kind: auth.kind,
        rpId: auth.rpId,
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      },
    };
  } else if (parsedRequest.auth.kind === 'email_otp_source_proof') {
    /* R109C `email_otp_to_passkey`. The same rule as the assertion branch: a
       same-device addition proves its source freshly, so the linked-device
       ceremony cannot borrow this path. */
    if (parsedRequest.intent.caller !== 'same_device_addition') {
      return routeError(
        401,
        'unauthorized',
        'Linked-device add-auth-method start requires the owner Wallet Session handoff',
      );
    }
    const sourceProof = parsedRequest.auth;
    const verified = await input.services.walletRegistration.verifyAddAuthMethodEmailOtpSourceProof(
      {
        walletId: walletIdFromString(walletId),
        walletAuthMethodId: parsedRequest.intent.source.walletAuthMethodId,
        challengeId: sourceProof.challengeId,
        otpCode: sourceProof.otpCode,
        expectedDigestB64u: sourceProof.expectedChallengeDigestB64u,
      },
    );
    if (!verified.ok) {
      return routeError(
        verified.code === 'invalid_state' ? 400 : 401,
        verified.code === 'invalid_state' ? 'invalid_body' : 'unauthorized',
        verified.message,
      );
    }
    request = { ...parsedRequest, auth: verified.auth };
  } else if (parsedRequest.auth.kind === 'wallet_session') {
    /* Only the linked-device ceremony may authorize with a reusable bearer
       credential. A same-device addition names itself in its own intent and
       must present a fresh operation-specific proof, so accepting a session
       here would let a bearer token stand in for the assertion R109C
       requires. */
    if (parsedRequest.intent.caller !== 'linked_device_ceremony') {
      return routeError(
        401,
        'unauthorized',
        'Same-device add-auth-method requires a fresh source proof, not a Wallet Session',
      );
    }
    /* R103 zero-prompt handoff: owner authority for the linked-device
       ceremony start is the active owner Wallet Session presented as the
       bearer credential. The session's own minting authority names the
       passkey whose custody envelope the ceremony binds — the body supplied
       none of these facts. */
    const admission = await resolveRouteOpaqueOwnerWalletSession(input, 'ed25519');
    if (!admission || admission.curve !== 'ed25519') {
      return routeError(
        401,
        'unauthorized',
        'Add-auth-method requires an active owner Wallet Session',
      );
    }
    const binding = admission.binding;
    if (String(binding.walletId) !== walletId) {
      return routeError(401, 'unauthorized', 'Owner Wallet Session names another wallet');
    }
    const authority = binding.authority;
    if (authority.factor?.kind !== 'passkey' || authority.verifier?.kind !== 'webauthn') {
      return routeError(
        401,
        'unauthorized',
        'Add-auth-method requires a passkey-owned owner Wallet Session',
      );
    }
    request = {
      ...parsedRequest,
      auth: {
        kind: 'wallet_session',
        walletSessionId: String(binding.walletSessionId),
        authorizationId: String(binding.authorizationId),
        rpId: authority.verifier.rpId,
        credentialIdB64u: String(authority.factor.credentialIdB64u),
      },
    };
  } else {
    return routeError(400, 'invalid_body', 'add-auth-method auth.kind is unsupported');
  }
  const result = await input.services.walletRegistration.startWalletAddAuthMethod(
    {
      ...request,
      subject: { kind: 'wallet_auth_method_management', walletId: walletIdFromString(walletId) },
    },
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
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) return routeError(400, 'invalid_body', 'walletId is required');
  const result = await input.services.walletRegistration.finalizeWalletAddAuthMethod({
    ...request.value,
    subject: { kind: 'wallet_auth_method_management', walletId: walletIdFromString(walletId) },
    // This route is owner-authenticated and has no link session, so it can only
    // ever finalize an ordinary owner factor.
    authorization: { kind: 'owner' },
  });
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
  const pathWalletAuthMethodId = String(input.pathParams?.walletAuthMethodId || '').trim();
  const parsedPathWalletAuthMethodId = parseWalletAuthMethodId(pathWalletAuthMethodId);
  if (!parsedPathWalletAuthMethodId.ok) {
    return routeError(400, 'invalid_body', 'walletAuthMethodId path parameter is invalid');
  }
  const parsedBody = await parseWalletRevokeAuthMethodRequest(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedPathWalletAuthMethodId.value !== parsedBody.value.walletAuthMethodId) {
    return routeError(400, 'invalid_body', 'walletAuthMethodId path and body values must agree');
  }
  const origin = requireWebAuthnExpectedOrigin(input);
  if (!origin.ok) return origin.response;
  const verified = await input.services.walletRegistration.verifyWalletAuthMethodRevokeProof({
    walletId: parsedBody.value.walletId,
    targetWalletAuthMethodId: parsedBody.value.walletAuthMethodId,
    requestedAtMs: parsedBody.value.requestedAtMs,
    sourceProof: parsedBody.value.sourceProof,
    expectedOrigin: origin.expectedOrigin,
  });
  if (verified.kind === 'denied') {
    return routeError(401, 'unauthorized', verified.message);
  }
  const result = await input.services.walletRegistration.revokeWalletAuthMethod({
    ...parsedBody.value,
    subject: { kind: 'wallet_auth_method_management', walletId: walletIdFromString(walletId) },
    verifiedSource: {
      walletAuthMethodId: verified.walletAuthMethodId,
      verifiedAtMs: verified.verifiedAtMs,
    },
  });
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
  let inventoryWalletId = walletId;
  switch (parsedBody.value.auth.kind) {
    case 'webauthn_assertion': {
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
      break;
    }
    case 'opaque_wallet_session': {
      let resolution: EcdsaInventorySessionResolution;
      try {
        resolution = await resolveRouteEcdsaInventorySession(input);
      } catch {
        return routeError(503, 'internal', 'ECDSA Wallet Session is unavailable');
      }
      if (resolution.kind === 'hosted_origin_rejected') {
        return routeError(403, 'forbidden', 'Hosted Wallet Session origin is unavailable');
      }
      if (resolution.kind !== 'admitted') {
        return routeError(401, 'unauthorized', 'ECDSA Wallet Session is unavailable');
      }
      const admittedWalletId = resolution.admission.context.authorization.session.walletId;
      if (admittedWalletId !== walletId) {
        return routeError(403, 'forbidden', 'Wallet session does not match walletId');
      }
      inventoryWalletId = admittedWalletId;
      break;
    }
    default:
      return assertNeverWalletEcdsaInventoryAuth(parsedBody.value.auth);
  }
  const keyInventory = await input.services.walletRegistration.listWalletEcdsaKeyFactsInventory({
    walletId: inventoryWalletId,
    rpId: parsedBody.value.rpId,
    keyTargets: parsedBody.value.keyTargets,
  });
  input.logger.info('[wallet][ecdsa-key-facts-inventory][diagnostic]', {
    walletId: inventoryWalletId,
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

  const admission = await resolveRouteNearFundingWalletSession(input);
  if (!admission) {
    return routeError(401, 'unauthorized', 'Ed25519 Wallet Session is unavailable');
  }
  if (admission.walletId !== parsedBody.value.walletId) {
    return routeError(403, 'forbidden', 'Wallet session does not match walletId');
  }
  if (admission.nearAccountId !== parsedBody.value.nearAccountId) {
    return routeError(403, 'forbidden', 'Wallet session does not match nearAccountId');
  }

  const result = await input.services.walletRegistration.fundImplicitNearAccount(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}
