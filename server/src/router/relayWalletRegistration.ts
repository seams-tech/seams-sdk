import type { AuthService } from '../core/AuthService';
import type {
  CreateAddAuthMethodIntentRequest,
  CreateAddSignerIntentRequest,
  CreateAddAuthMethodIntentResponse,
  CreateAddSignerIntentResponse,
  CreateRegistrationIntentRequest,
  CreateRegistrationIntentResponse,
  EcdsaKeyFactsInventoryPolicy,
  Ed25519SessionPolicy,
  WebAuthnAuthenticationCredential,
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
  EcdsaHssServerBootstrapResponse,
  ThresholdEd25519BootstrapSession,
  WalletKeyFactsInventoryAuth,
  WalletRegistrationFinalizeRequest,
  WalletRegistrationFinalizeResponse,
  WalletRegistrationHssRespondRequest,
  WalletRegistrationHssRespondResponse,
  WalletRegistrationStartRequest,
  WalletRegistrationStartResponse,
} from '../core/types';
import type { ConsoleBootstrapTokenService } from '../console/bootstrapTokens';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import type { ThresholdEcdsaChainTarget } from '../core/thresholdEcdsaChainTarget';
import {
  thresholdEcdsaChainTargetFromValue,
  thresholdEcdsaChainTargetKey,
} from '../core/thresholdEcdsaChainTarget';
import {
  parseAppSessionClaims,
  parseEcdsaHssClientBootstrapRequest,
} from '../core/ThresholdService/validation';
import {
  resolveActiveRuntimePolicyScopeForEnvironment,
  signThresholdSessionAuthToken,
} from './commonRouterUtils';
import { enforceRoutePolicy } from './enforceRoutePolicy';
import type { NormalizedRouterLogger } from './logger';
import { resolveRegistrationBootstrapApiCredentialAuth } from './relayApiCredentialAuth';
import type { RelayApiKeyAuthAdapter, SessionAdapter } from './relay';
import type { HeaderRecord, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';
import type { RouteErrorBody } from './routeResponses';
import { routeError, routeJson } from './routeResponses';
import { isPlainObject } from '@shared/utils/validation';
import { normalizeCorsOrigin } from '../core/SessionService';
import { computeWalletEcdsaKeyFactsInventoryChallengeDigestB64u } from '@shared/utils/ecdsaKeyFactsInventory';
import {
  addAuthMethodIntentGrantFromString,
  computeAddAuthMethodIntentDigestB64u,
  normalizeAddAuthMethodInput,
  addSignerIntentGrantFromString,
  computeAddSignerIntentDigestB64u,
  computeRegistrationIntentDigestB64u,
  normalizeEmailOtpRegistrationProof,
  normalizeNearAccountOwnershipProofV1,
  normalizeRegistrationAuthMethodInput,
  normalizeWalletAuthMethodTarget,
  registrationIntentGrantFromString,
  walletIdFromString,
  type AddSignerIntentV1,
  type AddAuthMethodIntentV1,
  type AddSignerSelection,
  type RegistrationIntentV1,
  type RegistrationSignerSelection,
  type RegisterWalletInput,
} from '@shared/utils/registrationIntent';
import { alphabetizeStringify } from '@shared/utils/digests';
import {
  normalizeRuntimePolicyScope,
  type RuntimePolicyScope,
} from '@shared/threshold/signingRootScope';

type RelayWalletRegistrationServices = {
  authService: AuthService;
  apiKeyAuth?: RelayApiKeyAuthAdapter | null;
  bootstrapTokenStore?: ConsoleBootstrapTokenService | null;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
  session?: SessionAdapter | null;
};

type RelayWalletRegistrationInput = {
  body: unknown;
  headers: HeaderRecord;
  logger: NormalizedRouterLogger;
  origin?: string;
  pathParams?: Record<string, string | undefined>;
  route: RouteDefinition;
  services: RelayWalletRegistrationServices;
  sourceIp?: string;
};

type ParseResult<T> = { ok: true; value: T } | { ok: false; code: 'invalid_body'; message: string };

function exposesRegistrationRouteDiagnostics(input: RelayWalletRegistrationInput): boolean {
  const raw =
    input.headers['x-seams-benchmark-diagnostics'] ??
    input.headers['X-Seams-Benchmark-Diagnostics'];
  return String(raw || '').trim() === 'registration-flow';
}

function stripRegistrationRouteDiagnostics<T>(response: T): T {
  if (!isPlainObject(response) || !Object.prototype.hasOwnProperty.call(response, 'registrationDiagnostics')) {
    return response;
  }
  const copy = { ...response };
  delete copy.registrationDiagnostics;
  return copy as T;
}

function requireWebAuthnExpectedOrigin(
  input: RelayWalletRegistrationInput,
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

type Ed25519SessionCarrier = {
  ok: true;
  rpId: string;
  ed25519?: {
    nearAccountId: string;
    relayerKeyId: string;
    participantIds?: number[];
    session?: ThresholdEd25519BootstrapSession;
  };
};

type WalletAddSignerServiceMethods = {
  startWalletAddSigner?: (
    request: WalletAddSignerStartRequest,
  ) => Promise<WalletAddSignerStartResponse>;
  respondWalletAddSignerHss?: (
    request: WalletAddSignerHssRespondRequest,
  ) => Promise<WalletAddSignerHssRespondResponse>;
  finalizeWalletAddSigner?: (
    request: WalletAddSignerFinalizeRequest,
  ) => Promise<WalletAddSignerFinalizeResponse>;
};

type WalletAddAuthMethodServiceMethods = {
  createAddAuthMethodIntent?: (input: {
    request: CreateAddAuthMethodIntentRequest;
    orgId: string;
    runtimePolicyScope?: RuntimePolicyScope;
    signingRootId?: string;
    signingRootVersion?: string;
    expectedOrigin: string;
  }) => Promise<CreateAddAuthMethodIntentResponse>;
  startWalletAddAuthMethod?: (
    request: WalletAddAuthMethodStartRequest,
  ) => Promise<WalletAddAuthMethodStartResponse>;
  finalizeWalletAddAuthMethod?: (
    request: WalletAddAuthMethodFinalizeRequest,
  ) => Promise<WalletAddAuthMethodFinalizeResponse>;
  revokeWalletAuthMethod?: (
    request: WalletRevokeAuthMethodRequest,
  ) => Promise<WalletRevokeAuthMethodResponse>;
};

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

function findUnknownField(raw: Record<string, unknown>, allowed: readonly string[]): string | undefined {
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

async function attachEd25519ThresholdSessionJwt(
  input: RelayWalletRegistrationInput,
  result: Ed25519SessionCarrier,
): Promise<RouteResponse<RouteErrorBody> | null> {
  const ed25519 = result.ed25519;
  const session = ed25519?.session;
  if (!session) return null;
  const signed = await signThresholdSessionAuthToken({
    session: input.services.session,
    kind: 'threshold_ed25519_session_v1',
    userId: ed25519.nearAccountId,
    rpId: result.rpId,
    relayerKeyId: ed25519.relayerKeyId,
    sessionInfo: session,
    fallbackParticipantIds: ed25519.participantIds,
    requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
  });
  if (!signed.ok) {
    const code = signed.code === 'sessions_disabled' ? 'internal' : signed.code;
    return routeError(signed.status, code, signed.message);
  }
  session.jwt = signed.jwt;
  return null;
}

async function attachEcdsaThresholdSessionJwt(
  input: RelayWalletRegistrationInput,
  bootstrap: EcdsaHssServerBootstrapResponse | undefined,
  runtimePolicyScope?: RuntimePolicyScope,
): Promise<RouteResponse<RouteErrorBody> | null> {
  if (!bootstrap) return null;
  const signed = await signThresholdSessionAuthToken({
    session: input.services.session,
    kind: 'threshold_ecdsa_session_v2',
    userId: bootstrap.walletId,
    rpId: bootstrap.rpId,
    relayerKeyId: bootstrap.relayerKeyId,
    sessionInfo: {
      sessionKind: 'jwt',
      sessionId: bootstrap.sessionId,
      walletSigningSessionId: bootstrap.walletSigningSessionId,
      expiresAtMs: bootstrap.expiresAtMs,
      participantIds: bootstrap.participantIds,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      keyHandle: bootstrap.keyHandle,
    },
    fallbackParticipantIds: bootstrap.participantIds,
    requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
    invalidPayloadErrorMessage: 'invalid thresholdEcdsa HSS bootstrap session payload for jwt signing',
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

function parseRegistrationSignerSelection(
  raw: unknown,
): ParseResult<RegistrationSignerSelection> {
  if (!isPlainObject(raw)) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration signerSelection is required',
    };
  }
  type RegistrationEd25519Spec = Extract<
    RegistrationSignerSelection,
    { mode: 'ed25519_only' }
  >['ed25519'];
  const parseEd25519 = (): ParseResult<RegistrationEd25519Spec> => {
    const ed25519 = isPlainObject(raw.ed25519) ? raw.ed25519 : null;
    if (!ed25519) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registration Ed25519 spec is required',
      };
    }
    const nearAccountId =
      typeof ed25519.nearAccountId === 'string' ? ed25519.nearAccountId.trim() : '';
    const signerSlot = Math.floor(Number(ed25519.signerSlot));
    const keyPurpose = typeof ed25519.keyPurpose === 'string' ? ed25519.keyPurpose.trim() : '';
    const keyVersion = typeof ed25519.keyVersion === 'string' ? ed25519.keyVersion.trim() : '';
    const derivationVersion = Math.floor(Number(ed25519.derivationVersion));
    const createNearAccount = Boolean(ed25519.createNearAccount);
    const participantIds = parseParticipantIds(
      ed25519.participantIds,
      'registration Ed25519 participantIds',
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
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registration Ed25519 spec is invalid',
      };
    }
    return {
      ok: true,
      value: {
        nearAccountId,
        signerSlot,
        participantIds: participantIds.value,
        keyPurpose,
        keyVersion,
        derivationVersion,
        createNearAccount,
      },
    };
  };

  if (raw.mode === 'ed25519_only') {
    const ed25519 = parseEd25519();
    if (!ed25519.ok) return ed25519;
    return {
      ok: true,
      value: {
        mode: 'ed25519_only',
        ed25519: ed25519.value,
      },
    };
  }
  if (raw.mode === 'ecdsa_only') {
    const ecdsa = isPlainObject(raw.ecdsa) ? raw.ecdsa : null;
    if (!ecdsa) {
      return { ok: false, code: 'invalid_body', message: 'registration ECDSA spec is required' };
    }
    const chainTargets = parseChainTargets(ecdsa.chainTargets);
    if (!chainTargets.ok) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registration ECDSA chainTargets are invalid',
      };
    }
    const participantIds = parseParticipantIds(
      ecdsa.participantIds,
      'registration ECDSA participantIds',
    );
    if (!participantIds.ok) return participantIds;
    return {
      ok: true,
      value: {
        mode: 'ecdsa_only',
        ecdsa: {
          chainTargets: chainTargets.value,
          participantIds: participantIds.value,
        },
      },
    };
  }
  if (raw.mode === 'ed25519_and_ecdsa') {
    const ed25519 = parseEd25519();
    if (!ed25519.ok) return ed25519;
    const ecdsaSelection = parseRegistrationSignerSelection({
      mode: 'ecdsa_only',
      ecdsa: raw.ecdsa,
    });
    if (!ecdsaSelection.ok) return ecdsaSelection;
    if (ecdsaSelection.value.mode !== 'ecdsa_only') {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'registration ECDSA selection is invalid',
      };
    }
    return {
      ok: true,
      value: {
        mode: 'ed25519_and_ecdsa',
        ed25519: ed25519.value,
        ecdsa: ecdsaSelection.value.ecdsa,
      },
    };
  }
  return {
    ok: false,
    code: 'invalid_body',
    message: 'registration signerSelection mode is unsupported',
  };
}

function parseRegisterWalletInput(raw: unknown): ParseResult<RegisterWalletInput> {
  if (!isPlainObject(raw)) {
    return { ok: false, code: 'invalid_body', message: 'wallet is required' };
  }
  const kind = typeof raw.kind === 'string' ? raw.kind.trim() : '';
  if (kind === 'server_generated') {
    if (Object.prototype.hasOwnProperty.call(raw, 'walletId')) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'server-generated wallet input must not include walletId',
      };
    }
    return { ok: true, value: { kind: 'server_generated' } };
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
  const rpId = trimRequiredString(body, 'rpId', 'rpId is required');
  if (!rpId.ok) return rpId;
  const authMethod = normalizeRegistrationAuthMethodInput(body.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'authMethod is invalid' };
  }
  const signerSelection = parseRegistrationSignerSelection(body.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  return {
    ok: true,
    value: {
      wallet: wallet.value,
      rpId: rpId.value,
      authMethod,
      signerSelection: signerSelection.value,
    },
  };
}

function parseCreateAddSignerIntentRequest(
  body: Record<string, unknown>,
  walletId: string,
): ParseResult<CreateAddSignerIntentRequest> {
  const rpId = trimRequiredString(body, 'rpId', 'rpId is required');
  if (!rpId.ok) return rpId;
  const signerSelection = parseAddSignerSelection(body.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      rpId: rpId.value,
      signerSelection: signerSelection.value,
    },
  };
}

function parseCreateAddAuthMethodIntentRequest(
  body: Record<string, unknown>,
  walletId: string,
): ParseResult<CreateAddAuthMethodIntentRequest> {
  const rpId = trimRequiredString(body, 'rpId', 'rpId is required');
  if (!rpId.ok) return rpId;
  const authMethod = normalizeAddAuthMethodInput(body.authMethod);
  if (!authMethod) {
    return { ok: false, code: 'invalid_body', message: 'authMethod is invalid' };
  }
  return {
    ok: true,
    value: {
      walletId: walletIdFromString(walletId),
      rpId: rpId.value,
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
  const rpId = typeof intent.rpId === 'string' ? intent.rpId.trim() : '';
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!rpId || !nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'add-signer intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: AddSignerIntentV1 = {
    version: 'add_signer_intent_v1',
    walletId: walletIdFromString(walletId),
    rpId,
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
  const signerSelection = parseRegistrationSignerSelection(intent.signerSelection);
  if (!signerSelection.ok) return signerSelection;
  const rpId = typeof intent.rpId === 'string' ? intent.rpId.trim() : '';
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!rpId || !nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'registration intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: RegistrationIntentV1 = {
    version: 'registration_intent_v1',
    walletId: walletIdFromString(walletId),
    rpId,
    authMethod,
    signerSelection: signerSelection.value,
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
  const rpId = typeof intent.rpId === 'string' ? intent.rpId.trim() : '';
  const nonceB64u = typeof intent.nonceB64u === 'string' ? intent.nonceB64u.trim() : '';
  if (!rpId || !nonceB64u) {
    return { ok: false, code: 'invalid_body', message: 'add-auth-method intent is incomplete' };
  }
  const runtimePolicyScope = parseOptionalRuntimePolicyScope(intent.runtimePolicyScope);
  if (!runtimePolicyScope.ok) return runtimePolicyScope;
  const normalizedIntent: AddAuthMethodIntentV1 = {
    version: 'add_auth_method_intent_v1',
    walletId: walletIdFromString(walletId),
    rpId,
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
    const clientBootstrap = isPlainObject(ecdsa.clientBootstrap) ? ecdsa.clientBootstrap : null;
    if (!clientBootstrap) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa.clientBootstrap is required' };
    }
    const forbiddenField = findOwnField(
      clientBootstrap,
      ECDSA_REGISTRATION_HSS_RESPOND_FORBIDDEN_FIELDS,
    );
    if (forbiddenField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `ecdsa.clientBootstrap.${forbiddenField} must stay outside the registration ceremony request`,
      };
    }
    const parsed = parseEcdsaHssClientBootstrapRequest(clientBootstrap);
    if (!parsed) {
      return { ok: false, code: 'invalid_body', message: 'ecdsa.clientBootstrap is invalid' };
    }
    value.ecdsa = {
      clientBootstrap: {
        formatVersion: parsed.formatVersion,
        walletId: parsed.walletId,
        rpId: parsed.rpId,
        ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
        signingRootId: parsed.signingRootId,
        signingRootVersion: parsed.signingRootVersion,
        keyScope: parsed.keyScope,
        relayerKeyId: parsed.relayerKeyId,
        hssClientSharePublicKey33B64u: parsed.hssClientSharePublicKey33B64u,
        clientShareRetryCounter: parsed.clientShareRetryCounter,
        contextBinding32B64u: parsed.contextBinding32B64u,
        requestId: parsed.requestId,
        sessionId: parsed.sessionId,
        walletSigningSessionId: parsed.walletSigningSessionId,
        ttlMs: parsed.ttlMs,
        remainingUses: parsed.remainingUses,
        participantIds: parsed.participantIds,
        ...(parsed.runtimePolicyScope ? { runtimePolicyScope: parsed.runtimePolicyScope } : {}),
      },
    };
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
    const forbiddenField = findOwnField(evaluationResult, ED25519_HSS_FINALIZE_FORBIDDEN_FIELDS);
    if (forbiddenField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `ed25519.evaluationResult.${forbiddenField} must stay outside the client-owned staged artifact`,
      };
    }
    const sessionKindRaw =
      typeof ed25519.sessionKind === 'string' ? ed25519.sessionKind.trim() : '';
    const sessionKind =
      sessionKindRaw === 'jwt' || sessionKindRaw === 'cookie' ? sessionKindRaw : undefined;
    const sessionPolicy = isPlainObject(ed25519.sessionPolicy)
      ? (ed25519.sessionPolicy as Ed25519SessionPolicy)
      : undefined;
    value.ed25519 = {
      evaluationResult: {
        contextBindingB64u: contextBindingB64u.value,
        stagedEvaluatorArtifactB64u: stagedEvaluatorArtifactB64u.value,
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
    const forbiddenEnrollmentField = findOwnField(enrollment, EMAIL_OTP_ENROLLMENT_FORBIDDEN_FIELDS);
    if (forbiddenEnrollmentField) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `emailOtpEnrollment.${forbiddenEnrollmentField} must not be included`,
      };
    }
    const unknownEnrollmentField = findUnknownField(enrollment, EMAIL_OTP_ENROLLMENT_ALLOWED_FIELDS);
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
  const rpId = trimRequiredString(body, 'rpId', 'rpId is required');
  if (!rpId.ok) return rpId;
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
      rpId: rpId.value,
      auth: existingAuth,
      target,
    },
  };
}

export async function handleRelayWalletRegistrationIntent(
  input: RelayWalletRegistrationInput,
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
    services: { authService: input.services.authService },
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
  const result = await input.services.authService.createRegistrationIntent({
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

export async function handleRelayWalletAddSignerIntent(
  input: RelayWalletRegistrationInput,
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
    services: { authService: input.services.authService },
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
  const result = await input.services.authService.createAddSignerIntent({
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

export async function handleRelayWalletRegistrationStart(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationStartResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = await parseWalletRegistrationStartBody(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.authService.startWalletRegistration(request.value);
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response);
}

export async function handleRelayWalletRegistrationHssRespond(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationHssRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationHssRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.authService.respondWalletRegistrationHss(request.value);
  if (result.ok) {
    const signingError = await attachEcdsaThresholdSessionJwt(
      input,
      result.ecdsa?.bootstrap,
      request.value.ecdsa?.clientBootstrap.runtimePolicyScope,
    );
    if (signingError) return signingError;
  }
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRelayWalletRegistrationFinalize(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletRegistrationFinalizeResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletRegistrationFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await input.services.authService.finalizeWalletRegistration(request.value);
  if (result.ok) {
    const signingError = await attachEd25519ThresholdSessionJwt(input, result);
    if (signingError) return signingError;
  }
  const response = exposesRegistrationRouteDiagnostics(input)
    ? result
    : stripRegistrationRouteDiagnostics(result);
  return routeJson(result.ok ? 200 : 400, response, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRelayWalletAddSignerStart(
  input: RelayWalletRegistrationInput,
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
    const verified = await input.services.authService.verifyWebAuthnAuthenticationLite({
      nearAccountId: walletId,
      rpId: parsedBody.value.intent.rpId,
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
    const sessionVersion = await input.services.authService.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const service = input.services.authService as AuthService & WalletAddSignerServiceMethods;
  if (!service.startWalletAddSigner) {
    return routeError(501, 'internal', 'wallet add-signer start is not implemented');
  }
  const result = await service.startWalletAddSigner(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRelayWalletAddSignerHssRespond(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerHssRespondResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerHssRespondRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const service = input.services.authService as AuthService & WalletAddSignerServiceMethods;
  if (!service.respondWalletAddSignerHss) {
    return routeError(501, 'internal', 'wallet add-signer HSS respond is not implemented');
  }
  const result = await service.respondWalletAddSignerHss(request.value);
  if (result.ok) {
    const signingError = await attachEcdsaThresholdSessionJwt(
      input,
      result.ecdsa?.bootstrap,
      request.value.ecdsa?.clientBootstrap.runtimePolicyScope,
    );
    if (signingError) return signingError;
  }
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRelayWalletAddSignerFinalize(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletAddSignerFinalizeResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const request = parseWalletAddSignerFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const service = input.services.authService as AuthService & WalletAddSignerServiceMethods;
  if (!service.finalizeWalletAddSigner) {
    return routeError(501, 'internal', 'wallet add-signer finalize is not implemented');
  }
  const result = await service.finalizeWalletAddSigner(request.value);
  if (result.ok) {
    const signingError = await attachEd25519ThresholdSessionJwt(input, result);
    if (signingError) return signingError;
  }
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRelayWalletAddAuthMethodIntent(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<CreateAddAuthMethodIntentResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId path parameter is required');
  }
  const service = input.services.authService as AuthService & WalletAddAuthMethodServiceMethods;
  if (!service.createAddAuthMethodIntent) {
    return routeError(501, 'internal', 'wallet add-auth-method intent is not implemented');
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
    services: { authService: input.services.authService },
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
  const result = await service.createAddAuthMethodIntent({
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

export async function handleRelayWalletAddAuthMethodStart(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletAddAuthMethodStartResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const service = input.services.authService as AuthService & WalletAddAuthMethodServiceMethods;
  if (!service.startWalletAddAuthMethod) {
    return routeError(501, 'internal', 'wallet add-auth-method start is not implemented');
  }
  const parsedBody = await parseWalletAddAuthMethodStartBody(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const verified = await input.services.authService.verifyWebAuthnAuthenticationLite({
      nearAccountId: walletId,
      rpId: parsedBody.value.intent.rpId,
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
    const sessionVersion = await input.services.authService.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const result = await service.startWalletAddAuthMethod(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result);
}

export async function handleRelayWalletAddAuthMethodFinalize(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletAddAuthMethodFinalizeResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const service = input.services.authService as AuthService & WalletAddAuthMethodServiceMethods;
  if (!service.finalizeWalletAddAuthMethod) {
    return routeError(501, 'internal', 'wallet add-auth-method finalize is not implemented');
  }
  const request = parseWalletAddAuthMethodFinalizeRequest(input.body);
  if (!request.ok) return routeError(400, request.code, request.message);
  const result = await service.finalizeWalletAddAuthMethod(request.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRelayWalletRevokeAuthMethod(
  input: RelayWalletRegistrationInput,
): Promise<RouteResponse<WalletRevokeAuthMethodResponse | RouteErrorBody>> {
  if (!isPlainObject(input.body)) {
    return routeError(400, 'invalid_body', 'JSON body required');
  }
  const walletId = String(input.pathParams?.walletId || '').trim();
  if (!walletId) {
    return routeError(400, 'invalid_body', 'walletId is required');
  }
  const service = input.services.authService as AuthService & WalletAddAuthMethodServiceMethods;
  if (!service.revokeWalletAuthMethod) {
    return routeError(501, 'internal', 'wallet auth-method revoke is not implemented');
  }
  const parsedBody = await parseWalletRevokeAuthMethodRequest(input.body, walletId);
  if (!parsedBody.ok) return routeError(400, parsedBody.code, parsedBody.message);
  if (parsedBody.value.auth.kind === 'webauthn_assertion') {
    const origin = requireWebAuthnExpectedOrigin(input);
    if (!origin.ok) return origin.response;
    const verified = await input.services.authService.verifyWebAuthnAuthenticationLite({
      nearAccountId: walletId,
      rpId: parsedBody.value.rpId,
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
    const sessionVersion = await input.services.authService.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const result = await service.revokeWalletAuthMethod(parsedBody.value);
  return routeJson(result.ok ? 200 : 400, result, {
    usage: result.ok ? { walletId: result.walletId } : undefined,
  });
}

export async function handleRelayWalletEcdsaKeyFactsInventory(
  input: RelayWalletRegistrationInput,
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
    const verified = await input.services.authService.verifyWebAuthnAuthenticationLite({
      nearAccountId: walletId,
      rpId: parsedBody.value.rpId,
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
    const sessionVersion = await input.services.authService.validateAppSessionVersion({
      userId: appSessionClaims.sub,
      appSessionVersion: appSessionClaims.appSessionVersion,
    });
    if (!sessionVersion.ok) {
      return routeError(401, 'unauthorized', sessionVersion.message);
    }
  }
  const keyInventory = await input.services.authService.listWalletEcdsaKeyFactsInventory({
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
