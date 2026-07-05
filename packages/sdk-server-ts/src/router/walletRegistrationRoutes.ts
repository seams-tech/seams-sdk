import type { RouterApiWalletRegistrationRouteService } from './authServicePort';
import type {
  EcdsaKeyFactsInventoryPolicy,
  Ed25519SessionPolicy,
  WebAuthnAuthenticationCredential,
  EcdsaHssServerBootstrapResponse,
  FundImplicitNearAccountRequest,
  FundImplicitNearAccountResult,
  ThresholdEd25519AuthorityScope,
  ThresholdEd25519BootstrapSession,
  WalletKeyFactsInventoryAuth
} from '../core/types';
import type {
  CreateAddAuthMethodIntentRequest,
  CreateAddSignerIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  WalletAddSignerFinalizeRequest,
  WalletAddSignerFinalizeResponse,
  WalletAddSignerHssRespondRequest,
  WalletAddSignerHssRespondResponse,
  WalletAddSignerStartRequest,
  WalletAddSignerStartResponse,
  WalletAddAuthMethodFinalizeRequest,
  WalletAddAuthMethodFinalizeResponse,
  WalletRevokeAuthMethodRequest,
  WalletRevokeAuthMethodResponse,
  WalletAddAuthMethodStartRequest,
  WalletAddAuthMethodStartResponse,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationPrepareRequest,
  WalletRegistrationPrepareGateContext,
  WalletRegistrationPrepareResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse
} from '../core/registrationContracts';
import {
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  registrationPreparationIdFromString
} from '../core/registrationContracts';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
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
  buildRouterAbEcdsaHssNormalSigningStateForBootstrap,
  resolveActiveRuntimePolicyScopeForEnvironment,
  signRouterAbEcdsaHssWalletSessionJwt,
  signRouterAbEd25519WalletSessionJwt,
  validateRouterAbEd25519WalletSessionTokenInputs,
} from './commonRouterUtils';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveRegistrationBootstrapApiCredentialAuth } from './routerApiCredentialAuth';
import type { RouterApiKeyAuthAdapter, SessionAdapter } from './routerApi';
import type { HeaderRecord, RouteResponse, RouteServices } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';
import { isPlainObject } from '@shared/utils/validation';
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
  normalizeNearAccountOwnershipProofV1,
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

type RouterApiWalletRegistrationServices = {
  walletRegistration: RouterApiWalletRegistrationRouteService;
  apiKeyAuth?: RouterApiKeyAuthAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
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

type RouterApiWalletRegistrationPrepareInput = Omit<
  RouterApiWalletRegistrationInput,
  'services'
> & {
  services: RouterApiWalletRegistrationServices;
};

type ParseResult<T> = { ok: true; value: T } | { ok: false; code: 'invalid_body'; message: string };

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

type Ed25519SessionCarrier = {
  ok: true;
  walletId: string;
  authority: WalletAuthAuthority;
  rpId?: string;
  ed25519?: {
    nearAccountId: string;
    relayerKeyId: string;
    participantIds?: number[];
    session?: ThresholdEd25519BootstrapSession;
  };
};

type MaybeEd25519SessionCarrier =
  | Extract<WalletRegistrationFinalizeResponse, { ok: true }>
  | Extract<WalletAddSignerFinalizeResponse, { ok: true }>;

function hasAttachableEd25519Session(
  result: MaybeEd25519SessionCarrier,
): result is MaybeEd25519SessionCarrier & Ed25519SessionCarrier {
  if (!result.ed25519?.session) return false;
  const record = result as { authority?: unknown };
  const authority = parseWalletAuthAuthority(record.authority);
  return Boolean(authority && authority.walletId === result.walletId);
}

const ED25519_HSS_RESPOND_FORBIDDEN_FIELDS = [
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

const ED25519_HSS_FINALIZE_FORBIDDEN_FIELDS = [
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

const ED25519_HSS_FINALIZE_ALLOWED_FIELDS = [
  'contextBindingB64u',
  'stagedEvaluatorArtifactB64u',
  'addStageRequestMessageB64u',
] as const;

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

const ECDSA_REGISTRATION_HSS_RESPOND_FORBIDDEN_FIELDS = [
  'clientRootProof',
  'passkeyBootstrapAuthorization',
  'sessionKind',
] as const;

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

async function attachEd25519WalletSessionJwt(
  input: RouterApiWalletRegistrationInput,
  result: Ed25519SessionCarrier,
): Promise<RouteResponse<RouteErrorBody> | null> {
  const ed25519 = result.ed25519;
  const session = ed25519?.session;
  if (!session) return null;
  if (session.sessionKind !== 'jwt') {
    return routeError(400, 'invalid_body', 'Ed25519 Wallet Session must use jwt sessionKind');
  }
  const signed = await signRouterAbEd25519WalletSessionJwt({
    session: input.services.session,
    userId: String(result.walletId),
    authority: result.authority,
    relayerKeyId: ed25519.relayerKeyId,
    sessionInfo: {
      ...session,
      sessionKind: 'jwt',
      thresholdSessionId: session.thresholdSessionId,
      walletId: session.walletId,
      nearAccountId: session.nearAccountId,
      nearEd25519SigningKeyId: session.nearEd25519SigningKeyId,
      runtimePolicyScope: session.runtimePolicyScope,
      routerAbNormalSigning: session.routerAbNormalSigning,
    },
    fallbackParticipantIds: ed25519.participantIds,
    requireJwtErrorMessage: 'Ed25519 Wallet Session must use jwt sessionKind',
    invalidPayloadErrorMessage: 'invalid Ed25519 Wallet Session payload for jwt signing',
  });
  if (!signed.ok) {
    const code = signed.code === 'sessions_disabled' ? 'internal' : signed.code;
    return routeError(signed.status, code, signed.message);
  }
  session.jwt = signed.jwt;
  return null;
}

async function attachEcdsaWalletSessionJwt(
  input: RouterApiWalletRegistrationInput,
  bootstrap: EcdsaHssServerBootstrapResponse | undefined,
  runtimePolicyScope?: RuntimePolicyScope,
): Promise<RouteResponse<RouteErrorBody> | null> {
  if (!bootstrap) return null;
  const threshold = input.services.walletRegistration.getThresholdSigningService();
  if (!threshold) {
    return routeError(500, 'internal', 'Threshold signing is not configured on this server');
  }
  const routerAbEcdsaHssNormalSigning = buildRouterAbEcdsaHssNormalSigningStateForBootstrap({
    bootstrap,
    routerAbPublicKeyset: input.services.routerAbPublicKeyset,
    signingWorkerId: threshold.getRouterAbNormalSigningWorkerId(),
  });
  if (!routerAbEcdsaHssNormalSigning.ok) {
    return routeError(500, 'internal', routerAbEcdsaHssNormalSigning.message);
  }
  const signed = await signRouterAbEcdsaHssWalletSessionJwt({
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
      signingWorkerId: threshold.getRouterAbNormalSigningWorkerId(),
      routerAbEcdsaHssNormalSigning: routerAbEcdsaHssNormalSigning.state,
    },
    fallbackParticipantIds: bootstrap.participantIds,
    requireJwtErrorMessage: 'ECDSA-HSS Wallet Session must use jwt sessionKind',
    invalidPayloadErrorMessage: 'invalid ECDSA-HSS Wallet Session payload for jwt signing',
  });
  if (!signed.ok) {
    const code = signed.code === 'sessions_disabled' ? 'internal' : signed.code;
    return routeError(signed.status, code, signed.message);
  }
  bootstrap.jwt = signed.jwt;
  return null;
}

function registrationClientBootstrapRuntimePolicyScope(input: {
  readonly request: WalletRegistrationHssRespondRequest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): RuntimePolicyScope | undefined {
  const targetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  for (const entry of input.request.ecdsa?.clientBootstraps || []) {
    if (thresholdEcdsaChainTargetKey(entry.chainTarget) !== targetKey) continue;
    return entry.clientBootstrap.runtimePolicyScope;
  }
  return undefined;
}

function addSignerClientBootstrapRuntimePolicyScope(input: {
  readonly request: WalletAddSignerHssRespondRequest;
  readonly chainTarget: ThresholdEcdsaChainTarget;
}): RuntimePolicyScope | undefined {
  const targetKey = thresholdEcdsaChainTargetKey(input.chainTarget);
  for (const entry of input.request.ecdsa?.clientBootstraps || []) {
    if (thresholdEcdsaChainTargetKey(entry.chainTarget) !== targetKey) continue;
    return entry.clientBootstrap.runtimePolicyScope;
  }
  return undefined;
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
    const nearAccountId =
      typeof ed25519.nearAccountId === 'string' ? ed25519.nearAccountId.trim() : '';
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
      !nearAccountId ||
      !Number.isFinite(signerSlot) ||
      signerSlot < 1 ||
      !keyPurpose ||
      !keyVersion ||
      !Number.isFinite(derivationVersion) ||
      derivationVersion < 1
    ) {
      return { ok: false, code: 'invalid_body', message: 'add-signer Ed25519 spec is invalid' };
    }
    if (mode === 'create_near_account') {
      return {
        ok: true,
        value: {
          mode: 'ed25519',
          ed25519: {
            mode: 'create_near_account',
            nearAccountId,
            signerSlot,
            participantIds: participantIds.value,
            keyPurpose,
            keyVersion,
            derivationVersion,
          },
        },
      };
    }
    if (mode === 'link_existing_near_account') {
      const accountOwnershipProof = normalizeNearAccountOwnershipProofV1(
        ed25519.accountOwnershipProof,
      );
      if (!accountOwnershipProof) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'add-signer Ed25519 account ownership proof is required',
        };
      }
      return {
        ok: true,
        value: {
          mode: 'ed25519',
          ed25519: {
            mode: 'link_existing_near_account',
            nearAccountId,
            signerSlot,
            participantIds: participantIds.value,
            keyPurpose,
            keyVersion,
            derivationVersion,
            accountOwnershipProof,
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

async function parseWalletRegistrationPrepareBody(
  body: Record<string, unknown>,
): Promise<ParseResult<Omit<WalletRegistrationPrepareRequest, 'prepareGate'>>> {
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
  const authMethod = normalizeRegistrationAuthMethodInput(intent.authMethod);
  const signerSelection = parseRegistrationSignerSet(intent.signerSelection);
  if (!walletId) {
    return { ok: false, code: 'invalid_body', message: 'registration walletId is required' };
  }
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'registration authMethod is invalid' };
  }
  if (!signerSelection.ok) return signerSelection;
  const nearEd25519Branch = findRegistrationSignerPlanNearEd25519Branch(signerSelection.value.plan);
  if (!nearEd25519Branch) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration prepare requires an Ed25519 signer selection',
    };
  }
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
    Object.prototype.hasOwnProperty.call(body, 'auth') ||
    Object.prototype.hasOwnProperty.call(body, 'prepareGate')
  ) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration prepare does not accept HSS, legacy auth, or gate payload fields',
    };
  }
  let authority: WalletRegistrationPrepareRequest['authority'];
  if (Object.prototype.hasOwnProperty.call(body, 'webauthn_registration')) {
    if (authMethod.kind !== 'passkey') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'webauthn_registration requires a passkey registration intent',
      };
    }
    authority = {
      kind: 'passkey',
      webauthnRegistration: body.webauthn_registration,
    };
  } else if (Object.prototype.hasOwnProperty.call(body, 'emailOtpRegistrationProof')) {
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
    authority = {
      kind: 'email_otp',
      emailOtpRegistrationProof: proof,
    };
  } else {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration prepare authority is required',
    };
  }
  const work = isPlainObject(body.work) ? body.work : null;
  const ecdsaBranch = findRegistrationSignerPlanEvmFamilyEcdsaBranch(signerSelection.value.plan);
  const expectedKind = ecdsaBranch ? 'ed25519_hss_and_ecdsa' : 'ed25519_hss';
  if (!work || work.kind !== expectedKind) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `registration prepare work must be ${expectedKind}`,
    };
  }
  return {
    ok: true,
    value: {
      registrationIntentGrant: registrationIntentGrantFromString(rawRegistrationIntentGrant),
      registrationIntentDigestB64u: expectedDigest,
      intent: normalizedIntent,
      authority,
      work: { kind: expectedKind },
    },
  };
}

function registrationPrepareGateContextFromRoute(
  input: RouterApiWalletRegistrationInput,
): WalletRegistrationPrepareGateContext {
  const sourceIp = String(input.sourceIp || '').trim();
  if (sourceIp) return { kind: 'source_ip', sourceIp };
  return { kind: 'source_unavailable', reason: 'source_ip_unavailable' };
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

function parseWalletRegistrationHssRespondRequest(
  body: Record<string, unknown>,
): ParseResult<WalletRegistrationHssRespondRequest> {
  const registrationCeremonyId = trimRequiredString(
    body,
    'registrationCeremonyId',
    'registrationCeremonyId is required',
  );
  if (!registrationCeremonyId.ok) return registrationCeremonyId;
  if (!hasBranch(body, 'ed25519') && !hasBranch(body, 'ecdsa')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration HSS response is required',
    };
  }
  const value: WalletRegistrationHssRespondRequest = {
    registrationCeremonyId: registrationCeremonyId.value,
  };
  if (hasBranch(body, 'ed25519')) {
    const ed25519 = isPlainObject(body.ed25519) ? body.ed25519 : null;
    if (!ed25519) {
      return { ok: false, code: 'invalid_body', message: 'ed25519 response is invalid' };
    }
    const clientRequest = isPlainObject(ed25519.clientRequest) ? ed25519.clientRequest : null;
    if (!clientRequest) {
      return { ok: false, code: 'invalid_body', message: 'ed25519.clientRequest is required' };
    }
    const clientRequestMessageB64u = trimRequiredString(
      clientRequest,
      'clientRequestMessageB64u',
      'ed25519.clientRequest.clientRequestMessageB64u is required',
    );
    if (!clientRequestMessageB64u.ok) return clientRequestMessageB64u;
    const forbiddenField = findOwnField(clientRequest, ED25519_HSS_RESPOND_FORBIDDEN_FIELDS);
    if (forbiddenField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `ed25519.clientRequest.${forbiddenField} must stay outside the server-visible request`,
      };
    }
    value.ed25519 = {
      clientRequest: {
        clientRequestMessageB64u: clientRequestMessageB64u.value,
      },
    };
  }
  if (hasBranch(body, 'ecdsa')) {
    const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
    if (!ecdsa) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa response is invalid' };
    }
    const clientBootstraps = Array.isArray(ecdsa.clientBootstraps)
      ? ecdsa.clientBootstraps
      : null;
    if (!clientBootstraps || clientBootstraps.length === 0) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ecdsa.clientBootstraps is required',
      };
    }
    const parsedEntries: NonNullable<WalletRegistrationHssRespondRequest['ecdsa']>['clientBootstraps'] =
      [];
    const seenTargets = new Set<string>();
    for (const entry of clientBootstraps) {
      const entryRecord = isPlainObject(entry) ? entry : null;
      const clientBootstrap = isPlainObject(entryRecord?.clientBootstrap)
        ? entryRecord.clientBootstrap
        : null;
      const chainTarget = thresholdEcdsaChainTargetFromValue(entryRecord?.chainTarget);
      if (!entryRecord || !clientBootstrap || !chainTarget) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ecdsa.clientBootstraps entry is invalid',
        };
      }
      const targetKey = thresholdEcdsaChainTargetKey(chainTarget);
      if (seenTargets.has(targetKey)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ecdsa.clientBootstraps contains duplicate chain targets',
        };
      }
      seenTargets.add(targetKey);
      const forbiddenField = findOwnField(
        clientBootstrap,
        ECDSA_REGISTRATION_HSS_RESPOND_FORBIDDEN_FIELDS,
      );
      if (forbiddenField) {
        return {
          ok: false,
          code: 'invalid_body',
          message: `ecdsa.clientBootstraps.clientBootstrap.${forbiddenField} must stay outside the registration ceremony request`,
        };
      }
      const parsed = parseWalletRegistrationEcdsaClientBootstrap(clientBootstrap);
      if (!parsed) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ecdsa.clientBootstraps clientBootstrap is invalid',
        };
      }
      parsedEntries.push({
        chainTarget,
        clientBootstrap: {
          formatVersion: parsed.formatVersion,
          walletId: parsed.walletId,
          evmFamilySigningKeySlotId: parsed.evmFamilySigningKeySlotId,
          ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
          signingRootId: parsed.signingRootId,
          signingRootVersion: parsed.signingRootVersion,
          keyScope: parsed.keyScope,
          relayerKeyId: parsed.relayerKeyId,
          ...(parsed.registrationPreparationId
            ? { registrationPreparationId: parsed.registrationPreparationId }
            : {}),
          hssClientSharePublicKey33B64u: parsed.hssClientSharePublicKey33B64u,
          clientShareRetryCounter: parsed.clientShareRetryCounter,
          contextBinding32B64u: parsed.contextBinding32B64u,
          requestId: parsed.requestId,
          thresholdSessionId: parsed.thresholdSessionId,
          signingGrantId: parsed.signingGrantId,
          ttlMs: parsed.ttlMs,
          remainingUses: parsed.remainingUses,
          participantIds: parsed.participantIds,
          ...(parsed.runtimePolicyScope ? { runtimePolicyScope: parsed.runtimePolicyScope } : {}),
        },
      });
    }
    value.ecdsa = { clientBootstraps: parsedEntries };
  }
  return { ok: true, value };
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

function parseWalletRegistrationFinalizeRequest(
  body: Record<string, unknown>,
): ParseResult<WalletRegistrationFinalizeRequest> {
  const registrationCeremonyId = trimRequiredString(
    body,
    'registrationCeremonyId',
    'registrationCeremonyId is required',
  );
  if (!registrationCeremonyId.ok) return registrationCeremonyId;
  if (!hasBranch(body, 'ed25519') && !hasBranch(body, 'ecdsa')) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration finalize input is required',
    };
  }
  const forbiddenTopLevelField = findOwnField(body, WALLET_REGISTRATION_FINALIZE_FORBIDDEN_FIELDS);
  if (forbiddenTopLevelField) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `${forbiddenTopLevelField} must not be included in wallet registration finalize`,
    };
  }
  const value: WalletRegistrationFinalizeRequest = {
    registrationCeremonyId: registrationCeremonyId.value,
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
  if (hasBranch(body, 'ed25519')) {
    const ed25519 = isPlainObject(body.ed25519) ? body.ed25519 : null;
    if (!ed25519) {
      return { ok: false, code: 'invalid_body', message: 'ed25519 finalize input is invalid' };
    }
    const evaluationResult = isPlainObject(ed25519.evaluationResult)
      ? ed25519.evaluationResult
      : null;
    if (!evaluationResult) {
      return { ok: false, code: 'invalid_body', message: 'ed25519.evaluationResult is required' };
    }
    const contextBindingB64u = trimRequiredString(
      evaluationResult,
      'contextBindingB64u',
      'ed25519.evaluationResult.contextBindingB64u is required',
    );
    if (!contextBindingB64u.ok) return contextBindingB64u;
    const stagedEvaluatorArtifactB64u = trimRequiredString(
      evaluationResult,
      'stagedEvaluatorArtifactB64u',
      'ed25519.evaluationResult.stagedEvaluatorArtifactB64u is required',
    );
    if (!stagedEvaluatorArtifactB64u.ok) return stagedEvaluatorArtifactB64u;
    const addStageRequestMessageB64u = trimRequiredString(
      evaluationResult,
      'addStageRequestMessageB64u',
      'ed25519.evaluationResult.addStageRequestMessageB64u is required',
    );
    if (!addStageRequestMessageB64u.ok) return addStageRequestMessageB64u;
    const forbiddenField = findOwnField(evaluationResult, ED25519_HSS_FINALIZE_FORBIDDEN_FIELDS);
    if (forbiddenField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `ed25519.evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
      };
    }
    const unsupportedField = findUnexpectedRouteKey(
      evaluationResult,
      ED25519_HSS_FINALIZE_ALLOWED_FIELDS,
    );
    if (unsupportedField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Unsupported ed25519.evaluationResult field: ${unsupportedField}`,
      };
    }
    const sessionKindRaw =
      typeof ed25519.sessionKind === 'string' ? ed25519.sessionKind.trim() : '';
    if (sessionKindRaw && sessionKindRaw !== 'jwt') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'ed25519.sessionKind must be jwt',
      };
    }
    const sessionKind = sessionKindRaw === 'jwt' ? 'jwt' : undefined;
    const sessionPolicy = isPlainObject(ed25519.sessionPolicy)
      ? (ed25519.sessionPolicy as Ed25519SessionPolicy)
      : undefined;
    value.ed25519 = {
      evaluationResult: {
        contextBindingB64u: contextBindingB64u.value,
        stagedEvaluatorArtifactB64u: stagedEvaluatorArtifactB64u.value,
        addStageRequestMessageB64u: addStageRequestMessageB64u.value,
      },
      ...(sessionKind ? { sessionKind } : {}),
      ...(sessionPolicy ? { sessionPolicy } : {}),
    };
  }
  if (hasBranch(body, 'ecdsa')) {
    const ecdsa = isPlainObject(body.ecdsa) ? body.ecdsa : null;
    if (!ecdsa) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa finalize input is invalid' };
    }
    if (ecdsa.expectedKeyHandles !== undefined) {
      if (!Array.isArray(ecdsa.expectedKeyHandles)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ecdsa.expectedKeyHandles must be an array',
        };
      }
      const expectedKeyHandles = ecdsa.expectedKeyHandles.map((keyHandle) =>
        typeof keyHandle === 'string' ? keyHandle.trim() : '',
      );
      if (expectedKeyHandles.some((keyHandle) => !keyHandle)) {
        return {
          ok: false,
          code: 'invalid_body',
          message: 'ecdsa.expectedKeyHandles contains an invalid key handle',
        };
      }
      value.ecdsa = { expectedKeyHandles };
    } else {
      value.ecdsa = {};
    }
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

function parseWalletAddSignerHssRespondRequest(
  body: Record<string, unknown>,
): ParseResult<WalletAddSignerHssRespondRequest> {
  const addSignerCeremonyId = trimRequiredString(
    body,
    'addSignerCeremonyId',
    'addSignerCeremonyId is required',
  );
  if (!addSignerCeremonyId.ok) return addSignerCeremonyId;
  const registrationLike = parseWalletRegistrationHssRespondRequest({
    ...body,
    registrationCeremonyId: addSignerCeremonyId.value,
  });
  if (!registrationLike.ok) return registrationLike;
  return {
    ok: true,
    value: {
      addSignerCeremonyId: addSignerCeremonyId.value,
      ...(registrationLike.value.ed25519 ? { ed25519: registrationLike.value.ed25519 } : {}),
      ...(registrationLike.value.ecdsa ? { ecdsa: registrationLike.value.ecdsa } : {}),
    },
  };
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
  const registrationLike = parseWalletRegistrationFinalizeRequest({
    ...body,
    registrationCeremonyId: addSignerCeremonyId.value,
  });
  if (!registrationLike.ok) return registrationLike;
  return {
    ok: true,
    value: {
      addSignerCeremonyId: addSignerCeremonyId.value,
      ...(registrationLike.value.ed25519 ? { ed25519: registrationLike.value.ed25519 } : {}),
      ...(registrationLike.value.ecdsa ? { ecdsa: registrationLike.value.ecdsa } : {}),
    },
  };
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
          bootstrapTokenStore: input.services.bootstrapTokenStore,
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
          bootstrapTokenStore: input.services.bootstrapTokenStore,
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
  const result = await input.services.walletRegistration.startWalletRegistration(request.value);
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRouterApiWalletRegistrationPrepare(
  input: RouterApiWalletRegistrationPrepareInput,
): Promise<RouteResponse<WalletRegistrationPrepareResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = await parseWalletRegistrationPrepareBody(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.prepareWalletRegistration({
    ...request.value,
    prepareGate: registrationPrepareGateContextFromRoute(input),
  });
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRouterApiWalletRegistrationHssRespond(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationHssRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationHssRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.respondWalletRegistrationHss(
    request.value,
  );
  if (result.ok && result.ecdsa) {
    for (const entry of result.ecdsa.bootstraps) {
      const signingError = await attachEcdsaWalletSessionJwt(
        input,
        entry.bootstrap,
        registrationClientBootstrapRuntimePolicyScope({
          request: request.value,
          chainTarget: entry.chainTarget,
        }),
      );
      if (signingError) return signingError;
    }
  }
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRouterApiWalletRegistrationFinalize(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationFinalizeResponse | RouteErrorBody>> {
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
    hasEd25519Session: Boolean(result.ok && result.ed25519?.session),
    durationMs: Date.now() - finalizeStartedAtMs,
  });
  if (result.ok) {
    const jwtStartedAtMs = Date.now();
    input.logger.info(
      '[wallet-registration][finalize-route] attaching Ed25519 wallet session jwt',
      {
        walletId: result.walletId,
        hasEd25519Session: Boolean(result.ed25519?.session),
      },
    );
    if (result.ed25519?.session) {
      if (!hasAttachableEd25519Session(result)) {
        return routeError(500, 'internal', 'Ed25519 Wallet Session is missing wallet authority');
      }
      const signingError = await attachEd25519WalletSessionJwt(input, result);
      input.logger.info(
        '[wallet-registration][finalize-route] Ed25519 wallet session jwt attached',
        {
          ok: !signingError,
          durationMs: Date.now() - jwtStartedAtMs,
        },
      );
      if (signingError) return signingError;
    }
  }
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  input.logger.info('[wallet-registration][finalize-route] returning response', {
    ok: Boolean(result.ok),
    status: result.ok ? 200 : 400,
    walletId: result.ok ? result.walletId : undefined,
    durationMs: Date.now() - finalizeStartedAtMs,
  });
  return routeJson(result.ok ? 200 : 400, response, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
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

export async function handleRouterApiWalletAddSignerHssRespond(
  input: RouterApiWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerHssRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerHssRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.walletRegistration.respondWalletAddSignerHss(request.value);
  if (result.ok && result.ecdsa) {
    for (const entry of result.ecdsa.bootstraps) {
      const signingError = await attachEcdsaWalletSessionJwt(
        input,
        entry.bootstrap,
        addSignerClientBootstrapRuntimePolicyScope({
          request: request.value,
          chainTarget: entry.chainTarget,
        }),
      );
      if (signingError) return signingError;
    }
  }
  return routeJson(result.ok ? 200 : 400, result);
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
  if (result.ok && result.ed25519?.session) {
    if (!hasAttachableEd25519Session(result)) {
      return routeError(500, 'internal', 'Ed25519 Wallet Session is missing wallet authority');
    }
    const signingError = await attachEd25519WalletSessionJwt(input, result);
    if (signingError) return signingError;
  }
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
          bootstrapTokenStore: input.services.bootstrapTokenStore,
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
  const result = await input.services.walletRegistration.startWalletAddAuthMethod(parsedBody.value);
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
