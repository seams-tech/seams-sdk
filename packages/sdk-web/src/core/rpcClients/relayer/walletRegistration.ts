import type {
  AddAuthMethodInput,
  AddAuthMethodIntentGrant,
  AddAuthMethodIntentV1,
  AddSignerIntentV1,
  AddSignerIntentGrant,
  EmailOtpRegistrationProof,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationNearAccountProvisioning,
  ResolvedRegistrationNearAccount,
  WalletAuthMethodTarget,
  WalletId,
  WebAuthnRpId,
} from '@shared/utils/registrationIntent';
import { parseNearEd25519SigningKeyId, walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parsePasskeyCustodyEnvelopeRecord,
  parseWalletCustodyRegistrationOutcome,
  type PasskeyCustodyEnvelopeRecord,
  type WalletCustodyCeremonyCommitPayload,
  type WalletCustodyRegistrationOutcome,
} from '@shared/passkey-custody';
import { parseImplicitNearAccountId, parseNamedNearAccountId } from '@shared/utils/near';
import { alphabetizeStringify } from '@shared/utils/digests';
import type { CorrelationId } from '@shared/utils/canonicalPrimitives';
import type {
  RegistrationEstablishedEcdsaSession,
  RegistrationEstablishedEd25519Session,
  RegistrationEstablishedSession,
} from '@shared/utils/registrationEstablishedSession';
import {
  parseCanonicalEcdsaServerActivationRequest,
  type CanonicalEcdsaServerActivationRequest,
} from '@shared/utils/ecdsaCapabilityActivation';
import {
  parseWebAuthnRpId,
  parseThresholdEcdsaSessionId,
  parseThresholdEd25519SessionId,
  parseWalletId,
  type RootShareEpoch,
  type ThresholdEd25519SessionId,
} from '@shared/utils/domainIds';
import type { WebAuthnAuthenticatorDeviceInfo } from '@shared/utils/webauthnDeviceInfo';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import {
  type RouterAbEd25519YaoActivationAdmissionReceiptV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  isPasskeyWalletAuthAuthority,
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  requireRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  parseRouterAbEcdsaDerivationActivationCommitQueryResultV1,
  parseRouterAbEcdsaDerivationActivationPrepareResultV1,
  parseRouterAbEcdsaRegistrationPublicActivationReceiptV1,
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
  parseRouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaRegistrationPublicActivationReceiptV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
  type RouterAbEcdsaDerivationActivationCommitQueryResultV1,
  type RouterAbEcdsaDerivationActivationPrepareResultV1,
  type RouterAbPublicDigest32V1Wire,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { AccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import {
  parseThresholdEcdsaKeyIdentityTargets,
  type ThresholdEcdsaKeyIdentityInventoryEntry,
} from '@/core/signingEngine/session/passkey/ecdsaKeyFactsInventory';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import {
  normalizeThresholdRuntimePolicyScope,
  type Ed25519AuthorityScope,
  type ThresholdRuntimePolicyScope,
} from '@/core/signingEngine/threshold/sessionPolicy';
import type {
  EcdsaDerivationRoleLocalPublicIdentity,
  ThresholdEcdsaDerivationRoleLocalBootstrapValue,
} from './thresholdEcdsa';
import { parseThresholdEcdsaDerivationRoleLocalBootstrapValue } from './thresholdEcdsa';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import { requireOpaqueWalletSessionToken } from '@shared/utils/sessionTokens';
import { parseThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  registrationSignerSetRequestSelection,
  type RegistrationSignerSetRequest,
} from './registrationSignerSetRequest';

const REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL = '[Registration] wallet route payload summary';
const ROUTE_PAYLOAD_BREAKDOWN_MAX_DEPTH = 2;
const ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS = 64;
const WALLET_REGISTRATION_SETUP_PATH = '/wallets/register/setup';
const WALLET_REGISTRATION_RESPOND_PATH = '/wallets/register/respond';
const WALLET_REGISTRATION_ACTIVATE_PATH = '/wallets/register/activate';
const WALLET_REGISTRATION_NEAR_PROVISIONING_PATH = '/wallets/register/near-provisioning';
/** Managed environment id header for Router API `api_credentials` auth. */
const ROUTER_API_ENVIRONMENT_ID_HEADER = 'X-Seams-Environment-Id';
const WALLET_REGISTRATION_PREPARE_PATH = '/wallets/register/prepare';
const WALLET_REGISTRATION_FINALIZE_PATH = '/wallets/register/finalize';
const WRANGLER_WORKER_RESTARTED_MID_REQUEST = 'Your worker restarted mid-request';

function utf8Bytes(value: string): number {
  try {
    return new TextEncoder().encode(String(value || '')).length;
  } catch {
    return String(value || '').length;
  }
}

function registrationBenchmarkDiagnosticsEnabled(): boolean {
  try {
    return (
      (globalThis as { __SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS?: unknown })
        .__SEAMS_REGISTRATION_BENCHMARK_DIAGNOSTICS === true
    );
  } catch {
    return false;
  }
}

function collectPayloadSizeBreakdown(input: {
  value: unknown;
  out: Record<string, number>;
  path: string;
  depth: number;
}): void {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return;
  if (Object.keys(input.out).length >= ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS) return;
  for (const [key, entry] of Object.entries(input.value as Record<string, unknown>)) {
    if (Object.keys(input.out).length >= ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS) return;
    const fieldPath = input.path ? `${input.path}.${key}` : key;
    if (typeof entry === 'string') {
      input.out[`${fieldPath}Bytes`] = utf8Bytes(entry);
    } else if (Array.isArray(entry)) {
      input.out[`${fieldPath}Count`] = entry.length;
    } else if (input.depth > 0 && entry && typeof entry === 'object') {
      collectPayloadSizeBreakdown({
        value: entry,
        out: input.out,
        path: fieldPath,
        depth: input.depth - 1,
      });
    }
  }
}

function payloadSizeBreakdown(value: unknown): Record<string, number> {
  const out: Record<string, number> = {};
  collectPayloadSizeBreakdown({
    value,
    out,
    path: '',
    depth: ROUTE_PAYLOAD_BREAKDOWN_MAX_DEPTH,
  });
  return out;
}

function parseJsonText(text: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(text || '{}');
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

async function readResponseText(response: Response): Promise<string> {
  try {
    return await response.text();
  } catch {
    return '{}';
  }
}

function walletRegistrationPostMaxAttempts(path: string): number {
  return path === WALLET_REGISTRATION_PREPARE_PATH ? 2 : 1;
}

function isWranglerWorkerRestartedMidRequestResponse(input: {
  path: string;
  status: number;
  responseText: string;
  attempt: number;
}): boolean {
  return (
    input.path === WALLET_REGISTRATION_PREPARE_PATH &&
    input.attempt === 0 &&
    input.status === 503 &&
    input.responseText.includes(WRANGLER_WORKER_RESTARTED_MID_REQUEST)
  );
}

async function postJson<TResponse>(args: {
  relayerUrl: string;
  path: string;
  body: unknown;
  headers?: Record<string, string>;
  /**
   * Receives the raw `Server-Timing` response header when the Gateway sends
   * one. Diagnostics only: never awaited, never allowed to throw into the
   * request, and null whenever the header is absent or unexposed by CORS.
   */
  onServerTiming?: (header: string | null) => void;
}): Promise<TResponse> {
  const startedAt = Date.now();
  const requestBody = JSON.stringify(args.body);
  const maxAttempts = walletRegistrationPostMaxAttempts(args.path);
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const response = await fetch(
      `${normalizeRelayerBaseUrl(args.relayerUrl, { trim: false })}${args.path}`,
      buildRelayerJsonPostRequestInit({
        headers: args.headers,
        body: args.body,
        bodyJson: requestBody,
      }),
    );
    if (args.onServerTiming) {
      try {
        args.onServerTiming(response.headers.get('Server-Timing'));
      } catch {
        // Diagnostics must never change registration behavior.
      }
    }
    const responseText = await readResponseText(response);
    const data = parseJsonText(responseText);
    if (registrationBenchmarkDiagnosticsEnabled()) {
      console.info(REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL, {
        path: args.path,
        status: response.status,
        attempt,
        requestBytes: utf8Bytes(requestBody),
        requestSizeBreakdown: payloadSizeBreakdown(args.body),
        responseBytes: utf8Bytes(responseText),
        responseSizeBreakdown: payloadSizeBreakdown(data),
        totalMs: Date.now() - startedAt,
      });
    }
    if (
      isWranglerWorkerRestartedMidRequestResponse({
        path: args.path,
        status: response.status,
        responseText,
        attempt,
      })
    ) {
      continue;
    }
    if (!response.ok || data.ok === false) {
      throw new Error(String(data.message || data.error || data.code || `HTTP ${response.status}`));
    }
    return data as TResponse;
  }
  throw new Error('wallet registration request exhausted retry attempts');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function requireResponseString(args: {
  responseName: string;
  field: string;
  value: unknown;
}): string {
  const value = String(args.value || '').trim();
  if (!value) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return value;
}

function requireResponseRecord(args: {
  responseName: string;
  field: string;
  value: unknown;
}): Record<string, unknown> {
  if (!isRecord(args.value)) {
    throw new Error(`${args.responseName} response missing ${args.field}`);
  }
  return args.value;
}

export type CreateRegistrationIntentRequest = {
  wallet: RegisterWalletInput;
  authMethod: RegistrationAuthMethodInput;
  signerSelection: RegistrationSignerSetRequest;
};

export type CreateRegistrationIntentResponse = {
  ok: true;
  intent: RegistrationIntentV1;
  registrationIntentDigestB64u: string;
  registrationIntentGrant: RegistrationIntentGrant;
  expiresAtMs: number;
};

export type CancelRegistrationIntentResponse = {
  ok: true;
  cancelled: boolean;
  releasedServerAllocatedWalletId: boolean;
};

export type FundImplicitNearAccountForTestingResponse =
  | {
      ok: true;
      walletId: string;
      nearAccountId: string;
      fundedAmountYocto: string;
      transactionHash?: string;
      message?: string;
    }
  | {
      ok: false;
      code: string;
      message: string;
    };

export async function fundImplicitNearAccountForTesting(args: {
  relayerUrl: string;
  walletId: WalletId | string;
  nearAccountId: string;
  nearPublicKeyStr: string;
  walletSessionToken: string;
}): Promise<FundImplicitNearAccountForTestingResponse> {
  const walletId = String(args.walletId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const nearPublicKeyStr = String(args.nearPublicKeyStr || '').trim();
  const walletSessionToken = String(args.walletSessionToken || '').trim();
  if (!walletId) throw new Error('walletId is required for implicit NEAR account funding');
  if (!nearAccountId) {
    throw new Error('nearAccountId is required for implicit NEAR account funding');
  }
  if (!nearPublicKeyStr) {
    throw new Error('nearPublicKeyStr is required for implicit NEAR account funding');
  }
  if (!walletSessionToken) {
    throw new Error('walletSessionToken is required for implicit NEAR account funding');
  }
  return await postJson<FundImplicitNearAccountForTestingResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/near/implicit-account/fund`,
    headers: buildBearerAuthorizationHeader({
      token: walletSessionToken,
      missingMessage: 'walletSessionToken is required for implicit NEAR account funding',
    }),
    body: {
      nearAccountId,
      nearPublicKeyStr,
    },
  });
}

export type RegistrationPreparationId = string & { readonly __brand: 'RegistrationPreparationId' };

export function registrationPreparationIdFromString(value: string): RegistrationPreparationId {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new Error('Registration preparation id is required');
  }
  return normalized as RegistrationPreparationId;
}

export type WalletRegistrationRouteTimingName =
  | 'registrationIntentLoadMs'
  | 'registrationIntentDigestMs'
  | 'registrationIntentConsumeMs'
  | 'registrationAttemptGateMs'
  | 'registrationPreparationPersistMs'
  | 'registrationPreparationLoadMs'
  | 'registrationPreparationConsumeMs'
  | 'registrationPreparationScopeCheckMs'
  | 'registrationAuthorityVerifyMs'
  | 'registrationEcdsaPrepareMs'
  | 'registrationCeremonyPersistMs'
  | 'registerPrepareTotalMs'
  | 'registerStartTotalMs'
  | 'registrationEcdsaRespondMs'
  | 'registrationFinalizeReplayLoadMs'
  | 'registrationCeremonyLoadMs'
  | 'registrationEcdsaBootstrapVerifyMs'
  | 'sponsoredNearAccountCreateMs'
  | 'registrationKeygenMs'
  | 'registrationEmailOtpEnrollmentPlanMs'
  | 'relaySessionMintMs'
  | 'relayGoogleEmailOtpActivationPlanMs'
  | 'relayPersistenceMs'
  | 'registrationFinalizeReplayCacheMs'
  | 'registerFinalizeTotalMs';

export type WalletRegistrationRouteDiagnostics = {
  kind: 'wallet_registration_route_diagnostics_v1';
  route:
    | 'wallets_register_start'
    | 'wallets_register_ecdsa_derivation_respond'
    | 'wallets_register_finalize';
  entries: {
    name: WalletRegistrationRouteTimingName;
    durationMs: number;
  }[];
};

export type WalletRegistrationEd25519YaoStart = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
  admissionReceipt: RouterAbEd25519YaoActivationAdmissionReceiptV1<'registration'>;
};

export type WalletRegistrationEcdsaPreparePayload = {
  kind: 'evm_family_ecdsa_keygen';
  chainTargets: readonly [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  prepare: WalletRegistrationEcdsaPrepareContext;
  strictRegistration: RouterAbEcdsaRegistrationRequestFactsV1;
};

type WalletRegistrationStartResponseBase = {
  ok: true;
  registrationCeremonyId: string;
  intent: RegistrationIntentV1;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
};

export type WalletRegistrationStartResponse = WalletRegistrationStartResponseBase &
  (
    | {
        kind: 'near_ed25519';
        ed25519: WalletRegistrationEd25519YaoStart;
        ecdsa?: never;
      }
    | {
        kind: 'evm_family_ecdsa';
        ecdsa: WalletRegistrationEcdsaPreparePayload;
        ed25519?: never;
      }
    | {
        kind: 'near_ed25519_and_evm_family_ecdsa';
        ed25519: WalletRegistrationEd25519YaoStart;
        ecdsa: WalletRegistrationEcdsaPreparePayload;
      }
  );

/**
 * Refactor 94C. The `/wallets/register/setup` response.
 *
 * `signedSetup` is opaque to the client: it is carried to routes 2 and 3 and
 * echoed verbatim, never parsed. `registrationIntentDigestB64u` is the
 * challenge the WebAuthn create must sign.
 *
 * ECDSA only, for both authentication methods. The Ed25519 branch of a mixed
 * plan is admitted by respond, once the verified proof determines its
 * authority scope; the client then starts that work asynchronously and never
 * awaits it for wallet readiness.
 */
export type WalletRegistrationSetupResponseV2 =
  | {
      ok: true;
      registrationCeremonyId: string;
      walletId: string;
      registrationIntentDigestB64u: string;
      intent: RegistrationIntentV1;
      signedSetup: string;
      ecdsa: WalletRegistrationEcdsaPreparePayload;
    }
  | { ok: false; code: string; message: string; retryAfterMs?: number };

function requireExactResponseKeys(
  record: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(record).filter((key) => !allowedSet.has(key));
  if (unknown.length > 0) {
    throw new Error(`${label} contains unknown fields: ${unknown.join(', ')}`);
  }
}

function parseWalletAddSignerEcdsaRespondResponse(
  value: unknown,
): WalletAddSignerEcdsaRespondResponse {
  const responseName = 'Wallet add-signer ECDSA derivation';
  const response = requireResponseRecord({
    responseName,
    field: 'response',
    value,
  });
  requireExactResponseKeys(
    response,
    ['ok', 'addSignerCeremonyId', 'ecdsa'],
    `${responseName} response`,
  );
  if (response.ok !== true) {
    throw new Error(`${responseName} response is not successful`);
  }
  const ecdsa = requireResponseRecord({
    responseName,
    field: 'ecdsa',
    value: response.ecdsa,
  });
  requireExactResponseKeys(ecdsa, ['kind', 'strictResult'], `${responseName} response ecdsa`);
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_forwarded_v1') {
    throw new Error(`${responseName} response kind is invalid`);
  }
  return {
    ok: true,
    addSignerCeremonyId: requireResponseString({
      responseName,
      field: 'addSignerCeremonyId',
      value: response.addSignerCeremonyId,
    }),
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_forwarded_v1',
      strictResult: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(ecdsa.strictResult),
    },
  };
}

function parseWalletAddSignerEcdsaActivationResponse(
  value: unknown,
): WalletAddSignerEcdsaActivationResponse {
  const responseName = 'Wallet add-signer ECDSA activation';
  const response = requireResponseRecord({
    responseName,
    field: 'response',
    value,
  });
  requireExactResponseKeys(
    response,
    ['ok', 'addSignerCeremonyId', 'ecdsa'],
    `${responseName} response`,
  );
  if (response.ok !== true) {
    throw new Error(`${responseName} response is not successful`);
  }
  const ecdsa = requireResponseRecord({
    responseName,
    field: 'ecdsa',
    value: response.ecdsa,
  });
  requireExactResponseKeys(
    ecdsa,
    ['kind', 'activation', 'bootstrap'],
    `${responseName} response ecdsa`,
  );
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_activated_v1') {
    throw new Error(`${responseName} response kind is invalid`);
  }
  return {
    ok: true,
    addSignerCeremonyId: requireResponseString({
      responseName,
      field: 'addSignerCeremonyId',
      value: response.addSignerCeremonyId,
    }),
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_activated_v1',
      activation: parseRouterAbEcdsaRegistrationPublicActivationReceiptV1(ecdsa.activation),
      bootstrap: parseThresholdEcdsaDerivationRoleLocalBootstrapValue(ecdsa.bootstrap),
    },
  };
}

export type WalletRegistrationFinalizeAuthMethod =
  | {
      kind: 'passkey';
      credentialIdB64u: string;
      credentialPublicKeyB64u: string;
    }
  | {
      kind: 'email_otp';
      registrationAuthorityId: string;
    };

export type WalletRegistrationEd25519YaoActivationReference = {
  kind: 'router_ab_ed25519_yao_activation_reference_v1';
  lifecycle_id: string;
  session_id: RouterAbEd25519YaoBytes32V1;
};

export type WalletRegistrationEd25519YaoBootstrapSession = {
  sessionKind: 'opaque';
  walletSessionToken: string;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: Ed25519AuthorityScope;
  thresholdSessionId: string;
  authorizationId: WalletSessionAuthorizationId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  expiresAtMs: number;
  participantIds: readonly [number, number];
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type WalletEd25519YaoSignerPublicResult = {
  signerSlot: number;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  participantIds: readonly [number, number];
};

export type WalletRegistrationEd25519YaoPublicResult = WalletEd25519YaoSignerPublicResult & {
  thresholdSessionId: ThresholdEd25519SessionId;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

type WalletRegistrationFinalizeResponseBase = {
  ok: true;
  walletId: WalletId;
  authority: WalletAuthAuthority;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
  /**
   * What became of the custody run that rode this leg, when one did. Absent
   * means no custody payload was sent — never that a sent one succeeded.
   *
   * A caller must act on anything other than `committed`: the registration
   * itself succeeded either way, so this is the only signal that the wallet's
   * seed is not yet recoverable.
   */
  walletCustody?: WalletCustodyRegistrationOutcome;
};

export type WalletRegistrationFinalizeResponseAuthority =
  | {
      rpId: string;
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'passkey' }>;
    }
  | {
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'email_otp' }>;
      rpId?: never;
    };

type WalletRegistrationFinalizeSignerResult =
  | {
      kind: 'near_ed25519';
      authorityScope: Ed25519AuthorityScope;
      accountProvisioning: RegistrationNearAccountProvisioning;
      resolvedAccount: ResolvedRegistrationNearAccount;
      ed25519: WalletRegistrationEd25519YaoPublicResult;
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: { walletKeys: WalletRegistrationEcdsaWalletKey[] };
      authorityScope?: never;
      accountProvisioning?: never;
      resolvedAccount?: never;
      ed25519?: never;
    };

export type EmailOtpWalletRegistrationFinalizeResponse = WalletRegistrationFinalizeResponseBase &
  Extract<WalletRegistrationFinalizeResponseAuthority, { authMethod: { kind: 'email_otp' } }> &
  WalletRegistrationFinalizeSignerResult;

export type WalletRegistrationFinalizeResponse =
  | (WalletRegistrationFinalizeResponseBase &
      Extract<WalletRegistrationFinalizeResponseAuthority, { authMethod: { kind: 'passkey' } }> &
      WalletRegistrationFinalizeSignerResult)
  | EmailOtpWalletRegistrationFinalizeResponse;

export function isEmailOtpWalletRegistrationFinalizeResponse(
  response: WalletRegistrationFinalizeResponse,
): response is EmailOtpWalletRegistrationFinalizeResponse {
  return response.authMethod.kind === 'email_otp';
}

export type WalletRegistrationEmailOtpEnrollmentMaterial = {
  enrollmentSealKeyVersion: string;
  serverSealedFactorCiphertextB64u: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
};

export type CreateAddAuthMethodIntentRequest = {
  walletId: WalletId;
  rpId: string;
  authMethod: AddAuthMethodInput;
};

export type CreateAddAuthMethodIntentResponse = {
  ok: true;
  intent: AddAuthMethodIntentV1;
  addAuthMethodIntentDigestB64u: string;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  expiresAtMs: number;
};

export type CreateAddSignerIntentRequest = {
  walletId: WalletId;
  rpId: string;
  signerSelection: AddSignerIntentV1['signerSelection'];
};

export type CreateAddSignerIntentResponse = {
  ok: true;
  intent: AddSignerIntentV1;
  addSignerIntentDigestB64u: string;
  addSignerIntentGrant: AddSignerIntentGrant;
  expiresAtMs: number;
};

export type AddSignerAuth = {
  kind: 'webauthn_assertion';
  rpId: string;
  credential: WebAuthnAuthenticationCredential;
  expectedChallengeDigestB64u: string;
};

export type AddAuthMethodAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'email_otp';
    };

export type WalletAddAuthMethodAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration?: never;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

/**
 * Declared once in the shared package. The server mints these options, this
 * client hands them to `navigator.credentials.create`, and the linked-device
 * target preparation carries them to Device 2 — one declaration, so none of
 * the three can drift from the ceremony.
 */
import {
  parseWalletAddAuthMethodRegistrationOptions,
  type WalletAddAuthMethodRegistrationOptions,
} from '@shared/utils/addAuthMethodRegistration';
export type { WalletAddAuthMethodRegistrationOptions };

export type WalletAddAuthMethodStartResponse =
  | {
      ok: true;
      addAuthMethodCeremonyId: string;
      intent: AddAuthMethodIntentV1;
      custodyEnvelope: PasskeyCustodyEnvelopeRecord;
      registration: WalletAddAuthMethodRegistrationOptions;
      /** When the ceremony itself stops being finalizable. */
      addAuthMethodCeremonyExpiresAtMs: number;
    }
  | {
      ok: true;
      addAuthMethodCeremonyId: string;
      intent: AddAuthMethodIntentV1;
      custodyEnvelope?: never;
      registration?: never;
      addAuthMethodCeremonyExpiresAtMs?: never;
    };

export type WalletAddAuthMethodFinalizeResponse =
  | {
      ok: true;
      walletId: WalletId;
      rpId: string;
      authMethod: {
        kind: 'passkey';
        status: 'active';
        credentialIdB64u: string;
        credentialPublicKeyB64u: string;
        counter: number;
        device: WebAuthnAuthenticatorDeviceInfo;
      };
    }
  | {
      ok: true;
      walletId: WalletId;
      rpId?: never;
      authMethod: {
        kind: 'email_otp';
        status: 'active';
      };
    };

export type RevokeAuthMethodAuth = {
  kind: 'webauthn_assertion';
  rpId: WebAuthnRpId;
  credential: WebAuthnAuthenticationCredential;
  expectedChallengeDigestB64u: string;
};

export type WalletRevokeAuthMethodResponse =
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'passkey';
        status: 'revoked';
      };
      rpId: string;
    }
  | {
      ok: true;
      walletId: WalletId;
      authMethod: {
        kind: 'email_otp';
        status: 'revoked';
      };
      rpId?: never;
    };

export function parseWalletAddAuthMethodStartResponse(args: {
  readonly value: unknown;
  readonly expectedIntent: AddAuthMethodIntentV1;
}): WalletAddAuthMethodStartResponse {
  const responseName = 'Wallet add-auth-method start';
  const record = requireResponseRecord({ responseName, field: 'body', value: args.value });
  if (record.ok !== true) throw new Error(`${responseName} response is not successful`);
  const addAuthMethodCeremonyId = requireResponseString({
    responseName,
    field: 'addAuthMethodCeremonyId',
    value: record.addAuthMethodCeremonyId,
  });
  const intent = requireExactAddAuthMethodIntent(record.intent, args.expectedIntent);
  if (args.expectedIntent.authMethod.kind === 'email_otp') {
    assertExactResponseKeys(record, ['ok', 'addAuthMethodCeremonyId', 'intent'], responseName);
    return { ok: true, addAuthMethodCeremonyId, intent };
  }
  assertExactResponseKeys(
    record,
    [
      'ok',
      'addAuthMethodCeremonyId',
      'intent',
      'custodyEnvelope',
      'registration',
      'addAuthMethodCeremonyExpiresAtMs',
    ],
    responseName,
  );
  return {
    ok: true,
    addAuthMethodCeremonyId,
    intent,
    custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(record.custodyEnvelope),
    registration: parseWalletAddAuthMethodRegistrationOptions(record.registration),
    addAuthMethodCeremonyExpiresAtMs: requireResponseSafeInteger({
      responseName,
      field: 'addAuthMethodCeremonyExpiresAtMs',
      value: record.addAuthMethodCeremonyExpiresAtMs,
      minimum: 1,
    }),
  };
}

type WalletAddSignerStartResponseBase = {
  ok: true;
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
};

export type WalletAddSignerStartResponse =
  | (WalletAddSignerStartResponseBase & {
      readonly authorizationKind: 'webauthn_assertion';
      kind: 'near_ed25519';
      ed25519: {
        admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
        custodyEnvelope: PasskeyCustodyEnvelopeRecord;
      };
      ecdsa?: never;
    })
  | (WalletAddSignerStartResponseBase & {
      readonly authorizationKind: 'webauthn_assertion';
      kind: 'evm_family_ecdsa';
      ecdsa: WalletRegistrationEcdsaPreparePayload & {
        readonly custodyEnvelope: PasskeyCustodyEnvelopeRecord;
      };
      ed25519?: never;
    });

export type WalletAddSignerEcdsaRespondResponse = {
  ok: true;
  addSignerCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_forwarded_v1';
    strictResult: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
  };
};

export type WalletAddSignerEcdsaActivationResponse = {
  ok: true;
  addSignerCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activated_v1';
    activation: RouterAbEcdsaRegistrationPublicActivationReceiptV1;
    bootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
  };
};

export type WalletAddSignerFinalizeResponse = {
  ok: true;
  walletId: WalletId;
} & (
  | {
      kind: 'near_ed25519';
      rpId: string;
      credentialIdB64u: string;
      ed25519: WalletEd25519YaoSignerPublicResult;
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      rpId: string;
      ecdsa: { walletKeys: WalletRegistrationEcdsaWalletKey[] };
      ed25519?: never;
    }
);

function assertExactResponseKeys(
  record: Record<string, unknown>,
  allowedKeys: readonly string[],
  responseName: string,
): void {
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) {
      throw new Error(`${responseName} response contains unexpected ${key}`);
    }
  }
}

function requireResponseSafeInteger(args: {
  responseName: string;
  field: string;
  value: unknown;
  minimum: number;
}): number {
  const value = Number(args.value);
  if (!Number.isSafeInteger(value) || value < args.minimum) {
    throw new Error(`${args.responseName} response has invalid ${args.field}`);
  }
  return value;
}

function requireResponseParticipantPair(
  value: unknown,
  responseName: string,
): readonly [number, number] {
  if (!Array.isArray(value) || value.length !== 2) {
    throw new Error(`${responseName} response has invalid participantIds`);
  }
  const first = requireResponseSafeInteger({
    responseName,
    field: 'participantIds[0]',
    value: value[0],
    minimum: 1,
  });
  const second = requireResponseSafeInteger({
    responseName,
    field: 'participantIds[1]',
    value: value[1],
    minimum: 1,
  });
  if (first === second) {
    throw new Error(`${responseName} response has duplicate participantIds`);
  }
  if (first !== 1 || second !== 2) {
    throw new Error(`${responseName} response has unsupported participantIds`);
  }
  return [first, second];
}

function requireExactAddSignerIntent(
  value: unknown,
  expected: AddSignerIntentV1,
): AddSignerIntentV1 {
  if (alphabetizeStringify(value) !== alphabetizeStringify(expected)) {
    throw new Error('Wallet add-signer start response changed the admitted intent');
  }
  return expected;
}

function requireExactAddAuthMethodIntent(
  value: unknown,
  expected: AddAuthMethodIntentV1,
): AddAuthMethodIntentV1 {
  if (alphabetizeStringify(value) !== alphabetizeStringify(expected)) {
    throw new Error('Wallet add-auth-method start response changed the admitted intent');
  }
  return expected;
}

function parseWalletAddSignerEcdsaPrepareContext(
  value: unknown,
  responseName: string,
): WalletRegistrationEcdsaPrepareContext {
  const prepare = requireResponseRecord({
    responseName,
    field: 'ecdsa.prepare',
    value,
  });
  assertExactResponseKeys(
    prepare,
    [
      'formatVersion',
      'walletId',
      'evmFamilySigningKeySlotId',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'keyScope',
      'relayerKeyId',
      'registrationPreparationId',
      'requestId',
      'thresholdSessionId',
      'ttlMs',
      'remainingUses',
      'participantIds',
      'runtimePolicyScope',
    ],
    responseName,
  );
  if (
    prepare.formatVersion !== 'ecdsa-derivation-role-local' ||
    prepare.keyScope !== 'evm-family'
  ) {
    throw new Error(`${responseName} response has invalid prepare discriminator`);
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(prepare.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${responseName} response has invalid runtimePolicyScope`);
  }
  const result: WalletRegistrationEcdsaPrepareContext = {
    formatVersion: 'ecdsa-derivation-role-local',
    walletId: requireResponseString({
      responseName,
      field: 'prepare.walletId',
      value: prepare.walletId,
    }),
    evmFamilySigningKeySlotId: requireResponseString({
      responseName,
      field: 'prepare.evmFamilySigningKeySlotId',
      value: prepare.evmFamilySigningKeySlotId,
    }),
    ecdsaThresholdKeyId: requireResponseString({
      responseName,
      field: 'prepare.ecdsaThresholdKeyId',
      value: prepare.ecdsaThresholdKeyId,
    }),
    signingRootId: requireResponseString({
      responseName,
      field: 'prepare.signingRootId',
      value: prepare.signingRootId,
    }),
    signingRootVersion: requireResponseString({
      responseName,
      field: 'prepare.signingRootVersion',
      value: prepare.signingRootVersion,
    }),
    keyScope: 'evm-family',
    relayerKeyId: requireResponseString({
      responseName,
      field: 'prepare.relayerKeyId',
      value: prepare.relayerKeyId,
    }),
    registrationPreparationId: registrationPreparationIdFromString(
      requireResponseString({
        responseName,
        field: 'prepare.registrationPreparationId',
        value: prepare.registrationPreparationId,
      }),
    ),
    requestId: requireResponseString({
      responseName,
      field: 'prepare.requestId',
      value: prepare.requestId,
    }),
    thresholdSessionId: requireResponseString({
      responseName,
      field: 'prepare.thresholdSessionId',
      value: prepare.thresholdSessionId,
    }),
    ttlMs: requireResponseSafeInteger({
      responseName,
      field: 'prepare.ttlMs',
      value: prepare.ttlMs,
      minimum: 1,
    }),
    remainingUses: requireResponseSafeInteger({
      responseName,
      field: 'prepare.remainingUses',
      value: prepare.remainingUses,
      minimum: 0,
    }),
    participantIds: [...requireResponseParticipantPair(prepare.participantIds, responseName)],
    runtimePolicyScope,
  };
  return result;
}

function parseWalletAddSignerEcdsaPrepare(
  value: unknown,
  expectedIntent: AddSignerIntentV1,
): WalletRegistrationEcdsaPreparePayload {
  const responseName = 'Wallet add-signer ECDSA start';
  const record = requireResponseRecord({ responseName, field: 'ecdsa', value });
  assertExactResponseKeys(
    record,
    ['kind', 'chainTargets', 'prepare', 'strictRegistration', 'custodyEnvelope'],
    responseName,
  );
  if (record.kind !== 'evm_family_ecdsa_keygen' || !Array.isArray(record.chainTargets)) {
    throw new Error(`${responseName} response has invalid payload`);
  }
  if (expectedIntent.signerSelection.mode !== 'ecdsa') {
    throw new Error(`${responseName} response substituted signer branch`);
  }
  const expectedTargets = expectedIntent.signerSelection.ecdsa.chainTargets;
  if (record.chainTargets.length !== expectedTargets.length) {
    throw new Error(`${responseName} response changed target count`);
  }
  const chainTargets: ThresholdEcdsaChainTarget[] = [];
  for (let index = 0; index < record.chainTargets.length; index += 1) {
    const target = record.chainTargets[index];
    const actual = parseWalletAddSignerChainTarget(target, responseName);
    const expectedValue = expectedTargets[index];
    if (!expectedValue) {
      throw new Error(`${responseName} response changed chainTarget`);
    }
    const expected = parseWalletAddSignerChainTarget(expectedValue, responseName);
    if (alphabetizeStringify(actual) !== alphabetizeStringify(expected)) {
      throw new Error(`${responseName} response changed chainTarget`);
    }
    chainTargets.push(actual);
  }
  const [firstTarget, ...remainingTargets] = chainTargets;
  if (!firstTarget) {
    throw new Error(`${responseName} response requires an EVM-family target`);
  }
  const prepare = parseWalletAddSignerEcdsaPrepareContext(record.prepare, responseName);
  const strictRegistration = parseRouterAbEcdsaRegistrationRequestFactsV1(
    record.strictRegistration,
  );
  if (strictRegistration.registration_purpose !== 'wallet_add_signer') {
    throw new Error(`${responseName} response has invalid registration purpose`);
  }
  return {
    kind: 'evm_family_ecdsa_keygen',
    chainTargets: [firstTarget, ...remainingTargets],
    prepare,
    strictRegistration,
  };
}

export function parseWalletAddSignerStartResponse(args: {
  value: unknown;
  expectedIntent: AddSignerIntentV1;
}): WalletAddSignerStartResponse {
  const responseName = 'Wallet add-signer start';
  const record = requireResponseRecord({ responseName, field: 'body', value: args.value });
  assertExactResponseKeys(
    record,
    ['ok', 'addSignerCeremonyId', 'intent', 'authorizationKind', 'kind', 'ed25519', 'ecdsa'],
    responseName,
  );
  if (record.ok !== true) throw new Error(`${responseName} response is not successful`);
  const addSignerCeremonyId = requireResponseString({
    responseName,
    field: 'addSignerCeremonyId',
    value: record.addSignerCeremonyId,
  });
  const intent = requireExactAddSignerIntent(record.intent, args.expectedIntent);
  if (record.authorizationKind !== 'webauthn_assertion') {
    throw new Error(`${responseName} response has invalid authorization kind`);
  }
  switch (record.kind) {
    case 'near_ed25519': {
      if (
        record.authorizationKind !== 'webauthn_assertion' ||
        intent.signerSelection.mode !== 'ed25519' ||
        record.ecdsa !== undefined
      ) {
        throw new Error(`${responseName} response substituted signer branch`);
      }
      const ed25519 = requireResponseRecord({
        responseName,
        field: 'ed25519',
        value: record.ed25519,
      });
      assertExactResponseKeys(ed25519, ['admissionRequest', 'custodyEnvelope'], responseName);
      const admission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
        ed25519.admissionRequest,
      );
      if (!admission.ok) throw new Error(admission.message);
      return {
        ok: true,
        addSignerCeremonyId,
        intent,
        authorizationKind: 'webauthn_assertion',
        kind: 'near_ed25519',
        ed25519: {
          admissionRequest: admission.value,
          custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(ed25519.custodyEnvelope),
        },
      };
    }
    case 'evm_family_ecdsa': {
      if (intent.signerSelection.mode !== 'ecdsa' || record.ed25519 !== undefined) {
        throw new Error(`${responseName} response substituted signer branch`);
      }
      const ecdsa = parseWalletAddSignerEcdsaPrepare(record.ecdsa, intent);
      const ecdsaRecord = requireResponseRecord({
        responseName,
        field: 'ecdsa',
        value: record.ecdsa,
      });
      return {
        ok: true,
        addSignerCeremonyId,
        intent,
        authorizationKind: 'webauthn_assertion',
        kind: 'evm_family_ecdsa',
        ecdsa: {
          ...ecdsa,
          custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(ecdsaRecord.custodyEnvelope),
        },
      };
    }
    default:
      throw new Error(`${responseName} response has invalid kind`);
  }
}

function requireResponseRpId(value: unknown, responseName: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(`${responseName} response has invalid rpId`);
  return parsed.value;
}

function parseWalletRegistrationEd25519AuthorityScope(
  value: unknown,
  responseName: string,
): Ed25519AuthorityScope {
  const authorityScope = requireResponseRecord({
    responseName,
    field: 'authorityScope',
    value,
  });
  switch (authorityScope.kind) {
    case 'passkey_rp':
      assertExactResponseKeys(authorityScope, ['kind', 'rpId'], responseName);
      return {
        kind: 'passkey_rp',
        rpId: requireResponseRpId(authorityScope.rpId, responseName),
      };
    case 'email_otp': {
      assertExactResponseKeys(authorityScope, ['kind', 'provider', 'providerUserId'], responseName);
      if (authorityScope.provider !== 'google' && authorityScope.provider !== 'email') {
        throw new Error(`${responseName} response has invalid authorityScope provider`);
      }
      return {
        kind: 'email_otp',
        provider: authorityScope.provider,
        providerUserId: requireResponseString({
          responseName,
          field: 'authorityScope.providerUserId',
          value: authorityScope.providerUserId,
        }),
      };
    }
    default:
      throw new Error(`${responseName} response has invalid authorityScope`);
  }
}

function parseWalletEd25519YaoSignerPublicResult(
  value: unknown,
  responseName: string,
): WalletEd25519YaoSignerPublicResult {
  const ed25519 = requireResponseRecord({ responseName, field: 'ed25519', value });
  assertExactResponseKeys(
    ed25519,
    [
      'signerSlot',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'publicKey',
      'relayerKeyId',
      'keyVersion',
      'recoveryExportCapable',
      'participantIds',
    ],
    responseName,
  );
  if (ed25519.recoveryExportCapable !== true) {
    throw new Error(`${responseName} response is not recovery/export capable`);
  }
  return {
    signerSlot: requireResponseSafeInteger({
      responseName,
      field: 'ed25519.signerSlot',
      value: ed25519.signerSlot,
      minimum: 1,
    }),
    nearAccountId: requireResponseString({
      responseName,
      field: 'ed25519.nearAccountId',
      value: ed25519.nearAccountId,
    }),
    nearEd25519SigningKeyId: requireResponseString({
      responseName,
      field: 'ed25519.nearEd25519SigningKeyId',
      value: ed25519.nearEd25519SigningKeyId,
    }),
    publicKey: requireResponseString({
      responseName,
      field: 'ed25519.publicKey',
      value: ed25519.publicKey,
    }),
    relayerKeyId: requireResponseString({
      responseName,
      field: 'ed25519.relayerKeyId',
      value: ed25519.relayerKeyId,
    }),
    keyVersion: requireResponseString({
      responseName,
      field: 'ed25519.keyVersion',
      value: ed25519.keyVersion,
    }),
    recoveryExportCapable: true,
    participantIds: requireResponseParticipantPair(ed25519.participantIds, responseName),
  };
}

function parseWalletRegistrationEd25519Result(
  value: unknown,
  responseName: string,
): WalletRegistrationEd25519YaoPublicResult {
  const ed25519 = requireResponseRecord({ responseName, field: 'ed25519', value });
  assertExactResponseKeys(
    ed25519,
    [
      'signerSlot',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'publicKey',
      'relayerKeyId',
      'keyVersion',
      'recoveryExportCapable',
      'participantIds',
      'thresholdSessionId',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ],
    responseName,
  );
  const publicResult = parseWalletEd25519YaoSignerPublicResult(
    {
      signerSlot: ed25519.signerSlot,
      nearAccountId: ed25519.nearAccountId,
      nearEd25519SigningKeyId: ed25519.nearEd25519SigningKeyId,
      publicKey: ed25519.publicKey,
      relayerKeyId: ed25519.relayerKeyId,
      keyVersion: ed25519.keyVersion,
      recoveryExportCapable: ed25519.recoveryExportCapable,
      participantIds: ed25519.participantIds,
    },
    responseName,
  );
  const thresholdSessionId = parseThresholdEd25519SessionId(ed25519.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error(`${responseName} response has invalid ed25519.thresholdSessionId`);
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(ed25519.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${responseName} response has invalid ed25519.runtimePolicyScope`);
  }
  return {
    ...publicResult,
    thresholdSessionId: thresholdSessionId.value,
    runtimePolicyScope,
    routerAbNormalSigning: requireRouterAbEd25519NormalSigningState(ed25519.routerAbNormalSigning),
  };
}

function parseWalletAddSignerChainTarget(
  value: unknown,
  responseName: string,
): ThresholdEcdsaChainTarget {
  const target = requireResponseRecord({ responseName, field: 'chainTarget', value });
  switch (target.kind) {
    case 'evm':
      assertExactResponseKeys(
        target,
        ['kind', 'namespace', 'chainId', 'networkSlug'],
        responseName,
      );
      return thresholdEcdsaChainTargetFromRequest(target);
    case 'tempo':
      assertExactResponseKeys(target, ['kind', 'chainId', 'networkSlug'], responseName);
      return thresholdEcdsaChainTargetFromRequest(target);
    default:
      throw new Error(`${responseName} response has invalid chainTarget kind`);
  }
}

function parseWalletAddSignerEcdsaWalletKey(
  value: unknown,
  responseName: string,
): WalletRegistrationEcdsaWalletKey {
  const key = requireResponseRecord({ responseName, field: 'ecdsa.walletKeys[]', value });
  assertExactResponseKeys(
    key,
    [
      'keyScope',
      'chainTarget',
      'walletId',
      'evmFamilySigningKeySlotId',
      'keyHandle',
      'ecdsaThresholdKeyId',
      'signingRootId',
      'signingRootVersion',
      'thresholdEcdsaPublicKeyB64u',
      'thresholdOwnerAddress',
      'relayerKeyId',
      'relayerVerifyingShareB64u',
      'contextBinding32B64u',
      'derivationClientSharePublicKey33B64u',
      'clientShareRetryCounter',
      'relayerShareRetryCounter',
      'participantIds',
      'publicCapability',
    ],
    responseName,
  );
  if (key.keyScope !== 'evm-family') {
    throw new Error(`${responseName} response has invalid keyScope`);
  }
  return {
    keyScope: 'evm-family',
    chainTarget: parseWalletAddSignerChainTarget(key.chainTarget, responseName),
    walletId: requireResponseString({ responseName, field: 'walletId', value: key.walletId }),
    evmFamilySigningKeySlotId: requireResponseString({
      responseName,
      field: 'evmFamilySigningKeySlotId',
      value: key.evmFamilySigningKeySlotId,
    }),
    keyHandle: requireResponseString({ responseName, field: 'keyHandle', value: key.keyHandle }),
    ecdsaThresholdKeyId: requireResponseString({
      responseName,
      field: 'ecdsaThresholdKeyId',
      value: key.ecdsaThresholdKeyId,
    }),
    signingRootId: requireResponseString({
      responseName,
      field: 'signingRootId',
      value: key.signingRootId,
    }),
    signingRootVersion: requireResponseString({
      responseName,
      field: 'signingRootVersion',
      value: key.signingRootVersion,
    }),
    thresholdEcdsaPublicKeyB64u: requireResponseString({
      responseName,
      field: 'thresholdEcdsaPublicKeyB64u',
      value: key.thresholdEcdsaPublicKeyB64u,
    }),
    thresholdOwnerAddress: requireResponseString({
      responseName,
      field: 'thresholdOwnerAddress',
      value: key.thresholdOwnerAddress,
    }),
    relayerKeyId: requireResponseString({
      responseName,
      field: 'relayerKeyId',
      value: key.relayerKeyId,
    }),
    relayerVerifyingShareB64u: requireResponseString({
      responseName,
      field: 'relayerVerifyingShareB64u',
      value: key.relayerVerifyingShareB64u,
    }),
    contextBinding32B64u: requireResponseString({
      responseName,
      field: 'contextBinding32B64u',
      value: key.contextBinding32B64u,
    }),
    derivationClientSharePublicKey33B64u: requireResponseString({
      responseName,
      field: 'derivationClientSharePublicKey33B64u',
      value: key.derivationClientSharePublicKey33B64u,
    }),
    clientShareRetryCounter: requireResponseSafeInteger({
      responseName,
      field: 'clientShareRetryCounter',
      value: key.clientShareRetryCounter,
      minimum: 0,
    }),
    relayerShareRetryCounter: requireResponseSafeInteger({
      responseName,
      field: 'relayerShareRetryCounter',
      value: key.relayerShareRetryCounter,
      minimum: 0,
    }),
    participantIds: requireResponseParticipantPair(key.participantIds, responseName),
    publicCapability: parseRouterAbEcdsaDerivationPublicCapabilityV1(key.publicCapability),
  };
}

export function parseWalletAddSignerFinalizeResponse(args: {
  value: unknown;
  expectedKind: FinalizeWalletAddSignerArgs['kind'];
}): WalletAddSignerFinalizeResponse {
  const responseName = 'Wallet add-signer finalize';
  const record = requireResponseRecord({ responseName, field: 'body', value: args.value });
  assertExactResponseKeys(
    record,
    ['ok', 'walletId', 'kind', 'rpId', 'credentialIdB64u', 'ed25519', 'ecdsa'],
    responseName,
  );
  if (record.ok !== true || record.kind !== args.expectedKind) {
    throw new Error(`${responseName} response substituted signer branch`);
  }
  const walletId = walletIdFromString(
    requireResponseString({ responseName, field: 'walletId', value: record.walletId }),
  );
  const rpId = requireResponseRpId(record.rpId, responseName);
  switch (record.kind) {
    case 'near_ed25519': {
      if (record.ecdsa !== undefined) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const ed25519 = parseWalletEd25519YaoSignerPublicResult(
        record.ed25519,
        'Wallet add-signer Ed25519 finalize',
      );
      return {
        ok: true,
        walletId,
        kind: 'near_ed25519',
        rpId,
        credentialIdB64u: requireResponseString({
          responseName,
          field: 'credentialIdB64u',
          value: record.credentialIdB64u,
        }),
        ed25519,
      };
    }
    case 'evm_family_ecdsa': {
      if (record.ed25519 !== undefined || record.credentialIdB64u !== undefined) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const ecdsa = requireResponseRecord({ responseName, field: 'ecdsa', value: record.ecdsa });
      assertExactResponseKeys(ecdsa, ['walletKeys'], responseName);
      if (!Array.isArray(ecdsa.walletKeys) || ecdsa.walletKeys.length === 0) {
        throw new Error(`${responseName} response has invalid walletKeys`);
      }
      return {
        ok: true,
        walletId,
        kind: 'evm_family_ecdsa',
        rpId,
        ecdsa: {
          walletKeys: ecdsa.walletKeys.map((value) =>
            parseWalletAddSignerEcdsaWalletKey(value, 'Wallet add-signer ECDSA finalize'),
          ),
        },
      };
    }
    default:
      throw new Error(`${responseName} response has invalid kind`);
  }
}

export type WalletRegistrationEcdsaPrepareContext = {
  formatVersion: 'ecdsa-derivation-role-local';
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  keyScope: 'evm-family';
  relayerKeyId: string;
  registrationPreparationId: RegistrationPreparationId;
  requestId: string;
  thresholdSessionId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: readonly [number, number];
  runtimePolicyScope: ThresholdRuntimePolicyScope;
};

export type WalletRegistrationEcdsaClientBootstrap = WalletRegistrationEcdsaPrepareContext & {
  derivationClientSharePublicKey33B64u: string;
  clientShareRetryCounter: number;
  contextBinding32B64u: string;
  clientRootProof?: never;
  passkeyBootstrapAuthorization?: never;
};

export type WalletRegistrationEcdsaWalletKey = {
  keyScope: 'evm-family';
  chainTarget: ThresholdEcdsaChainTarget;
  walletId: string;
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  ecdsaThresholdKeyId: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  thresholdOwnerAddress: string;
  relayerKeyId: string;
  relayerVerifyingShareB64u: string;
  contextBinding32B64u: string;
  derivationClientSharePublicKey33B64u: string;
  clientShareRetryCounter: number;
  relayerShareRetryCounter: number;
  participantIds: readonly [number, number];
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
};

export type WalletRegistrationEcdsaCompletedBootstrap = {
  bootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
  relayerShareRetryCounter: number;
};

type WalletRegistrationStartAuthority =
  | {
      kind: 'passkey';
      webauthnRegistration: unknown;
      emailOtpRegistrationProof?: never;
    }
  | {
      kind: 'email_otp';
      emailOtpRegistrationProof: EmailOtpRegistrationProof;
      webauthnRegistration?: never;
    };

export type WalletRegistrationEcdsaDerivationRespondBootstrap = {
  walletId: string;
  evmFamilySigningKeySlotId: string;
  ecdsaThresholdKeyId: string;
  relayerKeyId: string;
  applicationBindingDigestB64u: string;
  contextBinding32B64u: string;
  publicIdentity: EcdsaDerivationRoleLocalPublicIdentity;
  relayerShareRetryCounter: number;
  keyHandle: string;
  signingRootId: string;
  signingRootVersion: string;
  thresholdEcdsaPublicKeyB64u: string;
  ethereumAddress: string;
  relayerVerifyingShareB64u: string;
  participantIds: number[];
  routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
};

function requireMatchingString(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): string {
  const expected = String(args.expected || '').trim();
  const actual = String(args.actual || '').trim();
  if (!expected || !actual) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

function requireMatchingParticipantIds(args: {
  expected: readonly unknown[];
  actual: readonly unknown[];
}): number[] {
  const expected = args.expected.map((participantId) => Math.floor(Number(participantId)));
  const actual = args.actual.map((participantId) => Math.floor(Number(participantId)));
  const invalid =
    expected.length === 0 ||
    actual.length === 0 ||
    expected.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0) ||
    actual.some((participantId) => !Number.isSafeInteger(participantId) || participantId <= 0);
  if (invalid) {
    throw new Error('ECDSA registration bootstrap returned incomplete participantIds');
  }
  if (expected.length !== actual.length || expected.some((id, index) => id !== actual[index])) {
    throw new Error('ECDSA registration bootstrap participantIds mismatch');
  }
  return actual;
}

export function parseWalletRegistrationEcdsaDerivationRespond(args: {
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  serverBootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
  activationEpoch: RootShareEpoch;
}): WalletRegistrationEcdsaDerivationRespondBootstrap {
  const clientBootstrap = args.clientBootstrap;
  const serverBootstrap = args.serverBootstrap;
  requireMatchingString({
    field: 'derivationClientSharePublicKey33B64u',
    expected: clientBootstrap.derivationClientSharePublicKey33B64u,
    actual: serverBootstrap.publicIdentity.derivationClientSharePublicKey33B64u,
  });
  const contextBinding32B64u = requireMatchingString({
    field: 'contextBinding32B64u',
    expected: clientBootstrap.contextBinding32B64u,
    actual: serverBootstrap.contextBinding32B64u,
  });
  const walletId = requireMatchingString({
    field: 'walletId',
    expected: clientBootstrap.walletId,
    actual: serverBootstrap.walletId,
  });
  const evmFamilySigningKeySlotId = requireMatchingString({
    field: 'evmFamilySigningKeySlotId',
    expected: clientBootstrap.evmFamilySigningKeySlotId,
    actual: serverBootstrap.evmFamilySigningKeySlotId,
  });
  requireMatchingString({
    field: 'activationEpoch',
    expected: args.activationEpoch,
    actual: serverBootstrap.activationEpoch,
  });
  const participantIds = requireMatchingParticipantIds({
    expected: clientBootstrap.participantIds,
    actual: serverBootstrap.participantIds,
  });

  const routerAbEcdsaDerivationNormalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1(
    serverBootstrap.routerAbEcdsaDerivationNormalSigning,
  );
  const ecdsaThresholdKeyId = String(serverBootstrap.ecdsaThresholdKeyId || '').trim();
  const keyHandle = String(serverBootstrap.keyHandle || '').trim();
  const signingRootId = String(serverBootstrap.signingRootId || '').trim();
  const signingRootVersion = String(serverBootstrap.signingRootVersion || '').trim();
  const applicationBindingDigestB64u = String(
    serverBootstrap.applicationBindingDigestB64u || '',
  ).trim();
  const thresholdEcdsaPublicKeyB64u = String(
    serverBootstrap.thresholdEcdsaPublicKeyB64u || '',
  ).trim();
  const ethereumAddress = String(serverBootstrap.ethereumAddress || '').trim();
  const relayerKeyId = String(serverBootstrap.relayerKeyId || '').trim();
  const relayerVerifyingShareB64u = String(serverBootstrap.relayerVerifyingShareB64u || '').trim();
  const relayerShareRetryCounter = Math.floor(Number(serverBootstrap.relayerShareRetryCounter));
  if (
    !walletId ||
    !evmFamilySigningKeySlotId ||
    !keyHandle ||
    !ecdsaThresholdKeyId ||
    !signingRootId ||
    !signingRootVersion ||
    !applicationBindingDigestB64u ||
    !thresholdEcdsaPublicKeyB64u ||
    !ethereumAddress ||
    !relayerKeyId ||
    !relayerVerifyingShareB64u ||
    !Number.isSafeInteger(relayerShareRetryCounter) ||
    relayerShareRetryCounter < 0 ||
    !participantIds.length ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    )
  ) {
    throw new Error('ECDSA registration bootstrap returned incomplete session material');
  }
  return {
    walletId,
    evmFamilySigningKeySlotId,
    ecdsaThresholdKeyId,
    relayerKeyId,
    applicationBindingDigestB64u,
    contextBinding32B64u,
    publicIdentity: serverBootstrap.publicIdentity,
    relayerShareRetryCounter,
    keyHandle,
    signingRootId,
    signingRootVersion,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    participantIds,
    routerAbEcdsaDerivationNormalSigning,
  };
}

export type WalletEcdsaKeyFactsInventoryTarget = {
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type WalletEcdsaKeyFactsInventoryResponse = {
  ok: true;
  records: ThresholdEcdsaKeyIdentityInventoryEntry[];
  diagnostics: unknown;
};

/**
 * Refactor 94C. `POST /wallets/register/setup` — the single admitted entry
 * point replacing the grant, intent, and start calls below.
 *
 * It is called *before* the WebAuthn create prompt, because its response
 * carries the challenge that create must sign. The server-side preparation
 * therefore overlaps the user's authenticator interaction.
 */
export async function setupWalletRegistration(args: {
  relayerUrl: string;
  request: {
    wallet?: RegisterWalletInput;
    signerSelection: CreateRegistrationIntentRequest['signerSelection'];
    authMethod: CreateRegistrationIntentRequest['authMethod'];
  };
  /**
   * The route's auth plane is `api_credentials` with `publishable_key` only —
   * no bootstrap token to mint first, and no secret-key fallback on a route
   * the browser calls directly. The key travels as a Bearer token and the
   * environment id as `X-Seams-Environment-Id`; the browser adds Origin.
   */
  auth: { publishableKey: string; environmentId: string };
  headers?: Record<string, string>;
  onServerTiming?: (header: string | null) => void;
}): Promise<WalletRegistrationSetupResponseV2> {
  const publishableKey = String(args.auth?.publishableKey || '').trim();
  const environmentId = String(args.auth?.environmentId || '').trim();
  if (!publishableKey || !environmentId) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'registration setup requires a publishable key and environment id',
    };
  }
  return await postJson<WalletRegistrationSetupResponseV2>({
    relayerUrl: args.relayerUrl,
    path: WALLET_REGISTRATION_SETUP_PATH,
    headers: {
      ...args.headers,
      Authorization: `Bearer ${publishableKey}`,
      [ROUTER_API_ENVIRONMENT_ID_HEADER]: environmentId,
    },
    body: {
      ...(args.request.wallet ? { wallet: args.request.wallet } : {}),
      signerSelection: args.request.signerSelection,
      authMethod: args.request.authMethod,
    },
    ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
  });
}

export async function createWalletAddSignerIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddSignerIntentRequest;
  auth: { publishableKey: string; environmentId: string };
}): Promise<CreateAddSignerIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer intent');
  const publishableKey = String(args.auth.publishableKey || '').trim();
  const environmentId = String(args.auth.environmentId || '').trim();
  if (!publishableKey || !environmentId) {
    throw new Error('add-signer intent requires a publishable key and environment id');
  }
  return await postJson<CreateAddSignerIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/intent`,
    headers: {
      Authorization: `Bearer ${publishableKey}`,
      [ROUTER_API_ENVIRONMENT_ID_HEADER]: environmentId,
    },
    body: args.request,
  });
}

export async function createWalletAddAuthMethodIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddAuthMethodIntentRequest;
  auth: { publishableKey: string; environmentId: string };
}): Promise<CreateAddAuthMethodIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method intent');
  const publishableKey = String(args.auth.publishableKey || '').trim();
  const environmentId = String(args.auth.environmentId || '').trim();
  if (!publishableKey || !environmentId) {
    throw new Error('add-auth-method intent requires a publishable key and environment id');
  }
  return await postJson<CreateAddAuthMethodIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/intent`,
    headers: {
      Authorization: `Bearer ${publishableKey}`,
      [ROUTER_API_ENVIRONMENT_ID_HEADER]: environmentId,
    },
    body: args.request,
  });
}

/**
 * Refactor 94C route 2. Authenticated respond: the proof the client just
 * collected against setup's challenge travels with the ECDSA registration
 * request, so one round trip both establishes the verified authority and runs
 * the Router leg.
 *
 * The result is a discriminated signer plan, not a bundle with an optional
 * Ed25519 member. A mixed plan always carries deferred NEAR work; an
 * ECDSA-only plan has no arm to omit. The NEAR work is `deferred` by
 * construction — the caller starts it and must never await it to decide the
 * wallet is usable.
 */
export type WalletRegistrationRespondEd25519DeferredWork = {
  status: 'deferred';
} & WalletRegistrationEd25519YaoStart;

type WalletRegistrationRespondEcdsaBundles = {
  kind: 'router_ab_ecdsa_registration_forwarded_v1';
  strictResult: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
};

export type WalletRegistrationRespondResponseV2 =
  | {
      ok: true;
      registrationCeremonyId: string;
      kind: 'evm_family_ecdsa';
      ecdsa: WalletRegistrationRespondEcdsaBundles;
      ed25519?: never;
    }
  | {
      ok: true;
      registrationCeremonyId: string;
      kind: 'near_ed25519_and_evm_family_ecdsa';
      ecdsa: WalletRegistrationRespondEcdsaBundles;
      ed25519: WalletRegistrationRespondEd25519DeferredWork;
    }
  | {
      /* Ed25519-only: no ECDSA leg ran, so there are no proof bundles to
         verify. The deferred work is still deferred — being the wallet's sole
         signer is not a reason to block on it. */
      ok: true;
      registrationCeremonyId: string;
      kind: 'near_ed25519';
      ecdsa?: never;
      ed25519: WalletRegistrationRespondEd25519DeferredWork;
    };

/**
 * Strict boundary parser for route 2.
 *
 * `kind` selects which fields are legal, so the allowed-key set is computed
 * from it: a mixed response missing its Ed25519 arm, or an ECDSA-only response
 * carrying one, is rejected rather than silently narrowed. That is the point
 * of the discriminated union — a wallet whose NEAR branch was requested but
 * whose deferred work never arrived must fail loudly here, not register as
 * ECDSA-only.
 */
function parseWalletRegistrationRespondResponseV2(
  value: unknown,
): WalletRegistrationRespondResponseV2 {
  const responseName = 'Wallet registration respond';
  const response = requireResponseRecord({ responseName, field: 'body', value });
  if (response.ok !== true) {
    throw new Error(`${responseName} response is not successful`);
  }
  const registrationCeremonyId = requireResponseString({
    responseName,
    field: 'registrationCeremonyId',
    value: response.registrationCeremonyId,
  });
  /* Discriminate and check shape before parsing any nested payload. A wrong
     plan shape should say so, not surface as a confusing failure from deep
     inside the ECDSA bundle parser. */
  const kind = response.kind;
  if (
    kind !== 'evm_family_ecdsa' &&
    kind !== 'near_ed25519_and_evm_family_ecdsa' &&
    kind !== 'near_ed25519'
  ) {
    throw new Error(`${responseName} response kind is invalid`);
  }
  const carriesEcdsa = kind !== 'near_ed25519';
  const carriesEd25519 = kind !== 'evm_family_ecdsa';
  requireExactResponseKeys(
    response,
    [
      'ok',
      'registrationCeremonyId',
      'kind',
      ...(carriesEcdsa ? ['ecdsa'] : []),
      ...(carriesEd25519 ? ['ed25519'] : []),
    ],
    responseName,
  );
  if (carriesEd25519 && response.ed25519 === undefined) {
    throw new Error(`${responseName} signer plan is missing its ed25519 deferred work`);
  }
  if (!carriesEcdsa) {
    /* No ECDSA leg ran, so there is nothing to verify in the browser. */
    return {
      ok: true,
      registrationCeremonyId,
      kind: 'near_ed25519',
      ed25519: parseWalletRegistrationRespondEd25519DeferredWork(response.ed25519),
    };
  }
  const ecdsaRecord = requireResponseRecord({
    responseName,
    field: 'ecdsa',
    value: response.ecdsa,
  });
  requireExactResponseKeys(ecdsaRecord, ['kind', 'strictResult'], `${responseName} ecdsa`);
  if (ecdsaRecord.kind !== 'router_ab_ecdsa_registration_forwarded_v1') {
    throw new Error(`${responseName} ecdsa kind is invalid`);
  }
  const ed25519 = carriesEd25519
    ? parseWalletRegistrationRespondEd25519DeferredWork(response.ed25519)
    : null;
  const ecdsa: WalletRegistrationRespondEcdsaBundles = {
    kind: 'router_ab_ecdsa_registration_forwarded_v1',
    strictResult: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(ecdsaRecord.strictResult),
  };
  return ed25519
    ? {
        ok: true,
        registrationCeremonyId,
        kind: 'near_ed25519_and_evm_family_ecdsa',
        ecdsa,
        ed25519,
      }
    : { ok: true, registrationCeremonyId, kind: 'evm_family_ecdsa', ecdsa };
}

function parseWalletRegistrationRespondEd25519DeferredWork(
  value: unknown,
): WalletRegistrationRespondEd25519DeferredWork {
  const responseName = 'Wallet registration respond ed25519';
  const record = requireResponseRecord({ responseName, field: 'ed25519', value });
  requireExactResponseKeys(
    record,
    ['status', 'admissionRequest', 'admissionReceipt'],
    responseName,
  );
  /* `deferred` is the only legal status. Anything else would mean the server
     believes this work is already running or complete, which no client is
     entitled to assume about NEAR provisioning. */
  if (record.status !== 'deferred') {
    throw new Error(`${responseName} status is invalid`);
  }
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
    record.admissionRequest,
  );
  if (!admissionRequest.ok) {
    throw new Error(`${responseName} admissionRequest is invalid`);
  }
  const admissionReceipt = parseRouterAbEd25519YaoRegistrationActivationAdmissionReceiptV1(
    record.admissionReceipt,
  );
  if (!admissionReceipt.ok) {
    throw new Error(`${responseName} admissionReceipt is invalid`);
  }
  return {
    status: 'deferred',
    admissionRequest: admissionRequest.value,
    admissionReceipt: admissionReceipt.value,
  };
}

type WalletRegistrationSignerPlanKind = WalletRegistrationRespondResponseV2['kind'];

type RespondWalletRegistrationArgsBase = {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  /** Opaque; echoed exactly as setup returned it. */
  signedSetup: string;
  onServerTiming?: (header: string | null) => void;
} & WalletRegistrationStartAuthority;

type WalletRegistrationRespondEcdsaRequest = {
  kind: 'router_ab_ecdsa_registration_v1';
  strictRegistration: RouterAbEcdsaRegistrationRequestV1;
  requestDigestB64u: string;
};

type RespondWalletRegistrationArgs =
  | (RespondWalletRegistrationArgsBase & {
      signerPlanKind: 'near_ed25519';
      ecdsa?: never;
    })
  | (RespondWalletRegistrationArgsBase & {
      signerPlanKind: Exclude<WalletRegistrationSignerPlanKind, 'near_ed25519'>;
      ecdsa: WalletRegistrationRespondEcdsaRequest;
    });

function walletRegistrationRespondBody(
  args: RespondWalletRegistrationArgs,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    registrationCeremonyId: args.registrationCeremonyId,
    signedSetup: args.signedSetup,
    kind: args.signerPlanKind,
  };
  switch (args.kind) {
    case 'passkey':
      body.webauthn_registration = args.webauthnRegistration;
      break;
    case 'email_otp':
      body.emailOtpRegistrationProof = args.emailOtpRegistrationProof;
      break;
  }
  if (args.ecdsa) body.ecdsa = args.ecdsa;
  return body;
}

export async function respondWalletRegistration(
  args: RespondWalletRegistrationArgs,
): Promise<WalletRegistrationRespondResponseV2> {
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: WALLET_REGISTRATION_RESPOND_PATH,
    headers: args.headers,
    body: walletRegistrationRespondBody(args),
    onServerTiming: args.onServerTiming,
  });
  return parseWalletRegistrationRespondResponseV2(response);
}

/**
 * Refactor 94C route 3. Activate absorbs finalize: one call carries the
 * browser-verified activation facts and the Email OTP enrollment material that
 * used to ride a separate finalize request, and returns the terminal wallet.
 *
 * `nearProvisioning` is a snapshot only. It never carries NEAR identifiers
 * before readiness — those appear once deferred provisioning reaches
 * `near_ready`, never from this response.
 */
/**
 * Activate absorbed two routes, so its response is the union of what both
 * returned: the finalize terminal wallet *and* the activation payload the old
 * `derivation/activate` returned.
 *
 * Both halves are load-bearing on the client. `activation` feeds
 * `finalizeRouterAbEcdsaRegistrationActivation`, and `bootstrap` feeds the
 * session bootstrap; without them the wallet registers server-side and cannot
 * sign locally, which is the opposite of what this route exists to deliver.
 *
 * Both live inside `ecdsa` alongside the wallet keys, matching the server
 * contract: one payload carrying everything the terminal leg produced. The
 * strict parser rejects a response missing them, so a server that folded the
 * legs without merging the payloads fails at the boundary rather than
 * silently producing a wallet that cannot sign.
 */
type ActivateTerminalEcdsaPayload = Extract<
  WalletRegistrationFinalizeResponse,
  { ok: true; kind: 'evm_family_ecdsa' }
>['ecdsa'] & {
  activation: RouterAbEcdsaRegistrationPublicActivationReceiptV1;
  bootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
};

/**
 * Ed25519-only activate returns a wallet that cannot sign yet: its sole signer
 * arrives with the deferred Yao computation. `nearProvisioning` is required on
 * this arm — a pending wallet with no provisioning state would be
 * indistinguishable from one that never needed NEAR.
 */
type DistributiveOmit<T, K extends keyof any> = T extends unknown ? Omit<T, K> : never;

export type WalletRegistrationActivateEd25519PendingV2 = DistributiveOmit<
  Extract<WalletRegistrationFinalizeResponse, { ok: true; kind: 'near_ed25519' }>,
  'ed25519' | 'resolvedAccount' | 'accountProvisioning' | 'authorityScope'
> & {
  /* Required, not optional: a pending Ed25519-only wallet with no provisioning
     state would be indistinguishable from one that never needed NEAR. */
  nearProvisioning: { status: 'near_pending' };
  ed25519?: never;
  resolvedAccount?: never;
  accountProvisioning?: never;
  authorityScope?: never;
  ecdsa?: never;
};

export type WalletRegistrationActivateResponseV2 =
  | (Omit<
      Extract<WalletRegistrationFinalizeResponse, { ok: true; kind: 'evm_family_ecdsa' }>,
      never
    > & {
      ecdsa: ActivateTerminalEcdsaPayload;
      registrationEstablishedSession: RegistrationEstablishedSession;
      nearProvisioning?: { status: 'pending' };
    })
  | WalletRegistrationActivateEd25519PendingV2;

function parseRegistrationEstablishedSession(
  value: unknown,
  expectedWalletId: WalletId,
): RegistrationEstablishedSession {
  const responseName = 'Wallet registration established session';
  const record = requireResponseRecord({
    responseName,
    field: 'registrationEstablishedSession',
    value,
  });
  assertExactResponseKeys(
    record,
    [
      'kind',
      'walletId',
      'authorizationId',
      'walletSessionId',
      'quotaId',
      'expiresAtMs',
      'remainingUses',
      'tokens',
    ],
    responseName,
  );
  if (record.kind !== 'registration_established_wallet_session_v1') {
    throw new Error(`${responseName} kind is invalid`);
  }
  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok || walletId.value !== expectedWalletId) {
    throw new Error(`${responseName} wallet identity is invalid`);
  }
  const authorizationId = parseWalletSessionAuthorizationId(record.authorizationId);
  const walletSessionId = parseWalletSessionId(record.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(record.quotaId);
  if (!authorizationId.ok || !walletSessionId.ok || !quotaId.ok) {
    throw new Error(`${responseName} identity is invalid`);
  }
  const expiresAtMs = requireResponseSafeInteger({
    responseName,
    field: 'expiresAtMs',
    value: record.expiresAtMs,
    minimum: 1,
  });
  const remainingUses = requireResponseSafeInteger({
    responseName,
    field: 'remainingUses',
    value: record.remainingUses,
    minimum: 1,
  });
  const tokens = requireResponseRecord({ responseName, field: 'tokens', value: record.tokens });
  if (tokens.kind === 'evm_family_ecdsa') {
    const ecdsa = parseRegistrationEstablishedEcdsaSession(tokens.ecdsa, {
      responseName,
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
    });
    assertExactResponseKeys(tokens, ['kind', 'ecdsa'], `${responseName} tokens`);
    return {
      kind: 'registration_established_wallet_session_v1',
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses,
      tokens: { kind: 'evm_family_ecdsa', ecdsa },
    };
  }
  if (tokens.kind === 'near_ed25519') {
    const ed25519 = parseRegistrationEstablishedEd25519Session(tokens.ed25519, {
      responseName,
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
    });
    assertExactResponseKeys(tokens, ['kind', 'ed25519'], `${responseName} tokens`);
    return {
      kind: 'registration_established_wallet_session_v1',
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses,
      tokens: { kind: 'near_ed25519', ed25519 },
    };
  }
  if (tokens.kind === 'near_ed25519_and_evm_family_ecdsa') {
    const ecdsa = parseRegistrationEstablishedEcdsaSession(tokens.ecdsa, {
      responseName,
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
    });
    const ed25519 = parseRegistrationEstablishedEd25519Session(tokens.ed25519, {
      responseName,
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
    });
    assertExactResponseKeys(tokens, ['kind', 'ecdsa', 'ed25519'], `${responseName} tokens`);
    return {
      kind: 'registration_established_wallet_session_v1',
      walletId: walletId.value,
      authorizationId: authorizationId.value,
      walletSessionId: walletSessionId.value,
      quotaId: quotaId.value,
      expiresAtMs,
      remainingUses,
      tokens: { kind: 'near_ed25519_and_evm_family_ecdsa', ecdsa, ed25519 },
    };
  }
  throw new Error(`${responseName} token kind is invalid`);
}

function parseRegistrationEstablishedEcdsaSession(
  value: unknown,
  identity: {
    responseName: string;
    walletId: WalletId;
    authorizationId: WalletSessionAuthorizationId;
    walletSessionId: WalletSessionId;
    quotaId: MpcWalletSigningQuotaId;
    expiresAtMs: number;
  },
): RegistrationEstablishedEcdsaSession {
  const record = requireResponseRecord({
    responseName: identity.responseName,
    field: 'tokens.ecdsa',
    value,
  });
  assertExactResponseKeys(
    record,
    [
      'sessionKind',
      'walletSessionToken',
      'thresholdSessionId',
      'keyHandle',
      'runtimePolicyScope',
      'routerAbEcdsaDerivationNormalSigning',
    ],
    `${identity.responseName} ECDSA token`,
  );
  if (record.sessionKind !== 'opaque') {
    throw new Error(`${identity.responseName} ECDSA token session kind is invalid`);
  }
  const walletSessionToken = requireOpaqueWalletSessionToken(
    requireResponseString({
      responseName: identity.responseName,
      field: 'tokens.ecdsa.walletSessionToken',
      value: record.walletSessionToken,
    }),
    'tokens.ecdsa.walletSessionToken',
  );
  const thresholdSessionId = parseThresholdEcdsaSessionId(record.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error(`${identity.responseName} ECDSA threshold session is invalid`);
  }
  const keyHandle = parseThresholdEcdsaKeyHandle(
    requireResponseString({
      responseName: identity.responseName,
      field: 'tokens.ecdsa.keyHandle',
      value: record.keyHandle,
    }),
  );
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(record.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${identity.responseName} ECDSA runtime policy is invalid`);
  }
  const normalSigning = requireRouterAbEcdsaDerivationNormalSigningStateV1(
    record.routerAbEcdsaDerivationNormalSigning,
  );
  return {
    sessionKind: 'opaque',
    walletSessionToken,
    thresholdSessionId: thresholdSessionId.value,
    keyHandle,
    runtimePolicyScope,
    routerAbEcdsaDerivationNormalSigning: normalSigning,
  };
}

function parseRegistrationEstablishedEd25519Session(
  value: unknown,
  identity: {
    responseName: string;
    walletId: WalletId;
    authorizationId: WalletSessionAuthorizationId;
    walletSessionId: WalletSessionId;
    quotaId: MpcWalletSigningQuotaId;
    expiresAtMs: number;
  },
): RegistrationEstablishedEd25519Session {
  const record = requireResponseRecord({
    responseName: identity.responseName,
    field: 'tokens.ed25519',
    value,
  });
  assertExactResponseKeys(
    record,
    [
      'sessionKind',
      'walletSessionToken',
      'thresholdSessionId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ],
    `${identity.responseName} Ed25519 token`,
  );
  if (record.sessionKind !== 'opaque') {
    throw new Error(`${identity.responseName} Ed25519 token session kind is invalid`);
  }
  const walletSessionToken = requireOpaqueWalletSessionToken(
    requireResponseString({
      responseName: identity.responseName,
      field: 'tokens.ed25519.walletSessionToken',
      value: record.walletSessionToken,
    }),
    'tokens.ed25519.walletSessionToken',
  );
  const thresholdSessionId = parseThresholdEd25519SessionId(record.thresholdSessionId);
  if (!thresholdSessionId.ok) {
    throw new Error(`${identity.responseName} Ed25519 threshold session is invalid`);
  }
  const nearAccountId = requireResponseString({
    responseName: identity.responseName,
    field: 'tokens.ed25519.nearAccountId',
    value: record.nearAccountId,
  });
  if (!parseImplicitNearAccountId(nearAccountId).ok && !parseNamedNearAccountId(nearAccountId).ok) {
    throw new Error(`${identity.responseName} Ed25519 NEAR account is invalid`);
  }
  const nearEd25519SigningKeyId = parseNearEd25519SigningKeyId(
    requireResponseString({
      responseName: identity.responseName,
      field: 'tokens.ed25519.nearEd25519SigningKeyId',
      value: record.nearEd25519SigningKeyId,
    }),
  );
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(record.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${identity.responseName} Ed25519 runtime policy is invalid`);
  }
  const normalSigning = requireRouterAbEd25519NormalSigningState(record.routerAbNormalSigning);
  let parsedNearAccountId;
  const parsedImplicitNearAccountId = parseImplicitNearAccountId(nearAccountId);
  if (parsedImplicitNearAccountId.ok) {
    parsedNearAccountId = parsedImplicitNearAccountId.value;
  } else {
    const parsedNamedNearAccountId = parseNamedNearAccountId(nearAccountId);
    if (!parsedNamedNearAccountId.ok) {
      throw new Error(`${identity.responseName} Ed25519 NEAR account is invalid`);
    }
    parsedNearAccountId = parsedNamedNearAccountId.value;
  }
  return {
    sessionKind: 'opaque',
    walletSessionToken,
    thresholdSessionId: thresholdSessionId.value,
    nearAccountId: parsedNearAccountId,
    nearEd25519SigningKeyId,
    runtimePolicyScope,
    routerAbNormalSigning: normalSigning,
  };
}

/**
 * Strict boundary parser for route 3.
 *
 * The terminal wallet body is exactly the finalize success this route
 * absorbed, so it is parsed by the existing finalize parser rather than a
 * second copy that could drift from it. Only `nearProvisioning` is new.
 *
 * That field is a status and nothing else: NEAR identifiers before readiness
 * are precisely what the deferred lifecycle exists to prevent, so a payload
 * carrying them here is rejected instead of passed through.
 */
function parseWalletRegistrationActivateResponseV2(
  value: unknown,
): WalletRegistrationActivateResponseV2 {
  const responseName = 'Wallet registration activate';
  const record = requireResponseRecord({ responseName, field: 'body', value });
  const {
    nearProvisioning,
    registrationEstablishedSession: rawEstablishedSession,
    ...terminal
  } = record;
  if (record.kind === 'near_ed25519') {
    /* Ed25519-only: no ECDSA leg ran, so there is no activation payload and no
       local session to build. The wallet exists but cannot sign until the
       deferred completion installs its sole signer, which is why the pending
       provisioning status is required rather than optional here. */
    const provisioning = requireResponseRecord({
      responseName,
      field: 'nearProvisioning',
      value: nearProvisioning,
    });
    requireExactResponseKeys(provisioning, ['status'], `${responseName} nearProvisioning`);
    if (provisioning.status !== 'near_pending') {
      throw new Error(`${responseName} Ed25519-only wallet must be pending NEAR provisioning`);
    }
    if (rawEstablishedSession !== undefined) {
      throw new Error(`${responseName} pending Ed25519 wallet cannot carry an established session`);
    }
    assertExactResponseKeys(
      record,
      [
        'ok',
        'walletId',
        'authority',
        'registrationDiagnostics',
        'rpId',
        'authMethod',
        'walletCustody',
        'kind',
        'nearProvisioning',
      ],
      responseName,
    );
    if (record.ok !== true) {
      throw new Error(`${responseName} did not return a pending Ed25519 wallet`);
    }
    const walletId = walletIdFromString(
      requireResponseString({
        responseName,
        field: 'walletId',
        value: terminal.walletId,
      }),
    );
    const authority = parseWalletRegistrationFinalizeAuthority(terminal.authority);
    const authMethod = requireResponseRecord({
      responseName,
      field: 'authMethod',
      value: terminal.authMethod,
    });
    const authorityBranch = parseWalletRegistrationFinalizeAuthorityBranch({
      response: terminal,
      walletId,
      authority,
    });
    const registrationDiagnostics =
      terminal.registrationDiagnostics === undefined
        ? undefined
        : parseWalletRegistrationFinalizeDiagnostics(terminal.registrationDiagnostics);
    if (authorityBranch.kind === 'passkey') {
      return {
        ok: true,
        kind: 'near_ed25519',
        walletId,
        authority,
        ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
        rpId: authorityBranch.rpId,
        authMethod: authorityBranch.authMethod,
        nearProvisioning: { status: 'near_pending' },
      };
    }
    return {
      ok: true,
      kind: 'near_ed25519',
      walletId,
      authority,
      ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
      authMethod: authorityBranch.authMethod,
      /* An Ed25519-only wallet has no key set yet, so no custody run can have
         ridden this call — but the field is carried rather than dropped, so a
         Gateway that reports one is never silently ignored. */
      ...(record.walletCustody === undefined
        ? {}
        : {
            walletCustody: parseWalletCustodyRegistrationOutcome(
              record.walletCustody,
              responseName,
            ),
          }),
      nearProvisioning: { status: 'near_pending' },
    };
  }
  const ecdsaRecord = requireResponseRecord({
    responseName,
    field: 'ecdsa',
    value: record.ecdsa,
  });
  const { activation, bootstrap, ...terminalEcdsa } = ecdsaRecord;
  /* Validate the snapshot before the terminal body, so a leaked NEAR
     identifier is reported as such rather than buried behind whatever the
     finalize parser objects to first. */
  if (nearProvisioning !== undefined) {
    const provisioning = requireResponseRecord({
      responseName,
      field: 'nearProvisioning',
      value: nearProvisioning,
    });
    requireExactResponseKeys(provisioning, ['status'], `${responseName} nearProvisioning`);
    if (provisioning.status !== 'pending') {
      throw new Error(`${responseName} nearProvisioning status is invalid`);
    }
  }
  /* Without these the wallet cannot sign locally, so their absence is a
     failure of the route rather than an optional extra. */
  if (activation === undefined || bootstrap === undefined) {
    throw new Error(
      `${responseName} is missing the activation payload the client needs to build its ECDSA session`,
    );
  }
  const authMethod = requireResponseRecord({
    responseName,
    field: 'authMethod',
    value: terminal.authMethod,
  });
  const finalizeTerminal = { ...terminal, ecdsa: terminalEcdsa };
  const finalized = parseWalletRegistrationFinalizeResponse({
    value: finalizeTerminal,
    expectedKind: 'evm_family_ecdsa',
  });
  if (!finalized.ok || finalized.kind !== 'evm_family_ecdsa') {
    throw new Error(`${responseName} did not return an activated ECDSA wallet`);
  }
  const registrationEstablishedSession = parseRegistrationEstablishedSession(
    rawEstablishedSession,
    finalized.walletId,
  );
  return {
    ...finalized,
    ecdsa: {
      ...finalized.ecdsa,
      activation: parseRouterAbEcdsaRegistrationPublicActivationReceiptV1(activation),
      bootstrap: parseThresholdEcdsaDerivationRoleLocalBootstrapValue(bootstrap),
    },
    registrationEstablishedSession,
    ...(nearProvisioning === undefined ? {} : { nearProvisioning: { status: 'pending' as const } }),
  };
}

type ActivateWalletRegistrationArgsBase = {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  signedSetup: string;
  idempotencyKey: string;
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;
  /** The custody ceremony's sealed output for the key set this call activates. */
  walletCustodyCommit?: WalletCustodyCeremonyCommitPayload;
  onServerTiming?: (header: string | null) => void;
};

type WalletRegistrationActivateEcdsaRequest = {
  activationCorrelationId: CorrelationId;
  activationRequestDigestB64u: string;
  clientActivation: RouterAbEcdsaVerifiedClientActivationFactsV1;
  expectedKeyHandles?: string[];
};

type ActivateWalletRegistrationArgs =
  | (ActivateWalletRegistrationArgsBase & {
      signerPlanKind: 'near_ed25519';
      ecdsa?: never;
    })
  | (ActivateWalletRegistrationArgsBase & {
      signerPlanKind: Exclude<WalletRegistrationSignerPlanKind, 'near_ed25519'>;
      ecdsa: WalletRegistrationActivateEcdsaRequest;
    });

function walletRegistrationActivateBody(
  args: ActivateWalletRegistrationArgs,
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    registrationCeremonyId: args.registrationCeremonyId,
    kind: args.signerPlanKind,
    signedSetup: args.signedSetup,
    idempotencyKey: args.idempotencyKey,
  };
  if (args.ecdsa) body.ecdsa = args.ecdsa;
  if (args.emailOtpEnrollment) body.emailOtpEnrollment = args.emailOtpEnrollment;
  if (args.walletCustodyCommit) body.walletCustodyCommit = args.walletCustodyCommit;
  return body;
}

export async function activateWalletRegistration(
  args: ActivateWalletRegistrationArgs,
): Promise<WalletRegistrationActivateResponseV2> {
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: WALLET_REGISTRATION_ACTIVATE_PATH,
    headers: args.headers,
    body: walletRegistrationActivateBody(args),
    onServerTiming: args.onServerTiming,
  });
  return parseWalletRegistrationActivateResponseV2(response);
}

/**
 * Refactor 94C route 4. The deferred NEAR completion, called once the Yao
 * computation the client started after respond has finished.
 *
 * One completion path serves both plans: an Ed25519-only wallet installs its
 * sole signer here, and a mixed wallet's NEAR arm lands here too. It carries
 * its own idempotency key because it is a separate effect from activate's —
 * sharing one would let a retry of this call replay activate's commit.
 *
 * A retryable failure leaves the pending wallet intact and the call
 * repeatable, so the caller reports provisioning state rather than unwinding
 * a wallet that already exists.
 */
export type WalletRegistrationNearProvisioningResponseV2 =
  | (Extract<WalletRegistrationFinalizeResponse, { ok: true; kind: 'near_ed25519' }> & {
      registrationEstablishedSession: RegistrationEstablishedSession;
      nearProvisioning: { status: 'near_ready' };
    })
  | {
      ok: false;
      code: string;
      message: string;
      nearProvisioning?: { status: 'near_failed_retryable' };
    };

function parseWalletRegistrationNearProvisioningResponseV2(
  value: unknown,
): WalletRegistrationNearProvisioningResponseV2 {
  const responseName = 'Wallet registration NEAR provisioning';
  const record = requireResponseRecord({ responseName, field: 'body', value });
  if (record.ok !== true) {
    const allowed = ['ok', 'code', 'message', 'nearProvisioning'] as const;
    assertExactResponseKeys(record, allowed, responseName);
    if (typeof record.code !== 'string' || typeof record.message !== 'string') {
      throw new Error(`${responseName} failure is invalid`);
    }
    if (record.nearProvisioning !== undefined) {
      const status = requireResponseRecord({
        responseName,
        field: 'nearProvisioning',
        value: record.nearProvisioning,
      });
      assertExactResponseKeys(status, ['status'], `${responseName} nearProvisioning`);
      if (status.status !== 'near_failed_retryable') {
        throw new Error(`${responseName} failure status is invalid`);
      }
      return {
        ok: false,
        code: record.code,
        message: record.message,
        nearProvisioning: { status: 'near_failed_retryable' },
      };
    }
    return { ok: false, code: record.code, message: record.message };
  }
  assertExactResponseKeys(
    record,
    [
      'ok',
      'walletId',
      'authority',
      'registrationDiagnostics',
      'rpId',
      'authMethod',
      'walletCustody',
      'custodyKeyManifestDigestB64u',
      'kind',
      'accountProvisioning',
      'resolvedAccount',
      'ed25519',
      'authorityScope',
      'nearProvisioning',
      'registrationEstablishedSession',
    ],
    responseName,
  );
  const provisioning = requireResponseRecord({
    responseName,
    field: 'nearProvisioning',
    value: record.nearProvisioning,
  });
  assertExactResponseKeys(provisioning, ['status'], `${responseName} nearProvisioning`);
  if (provisioning.status !== 'near_ready') {
    throw new Error(`${responseName} success status is invalid`);
  }
  const {
    nearProvisioning: _nearProvisioning,
    registrationEstablishedSession,
    ...terminal
  } = record;
  const finalized = parseWalletRegistrationFinalizeResponse({
    value: terminal,
    expectedKind: 'near_ed25519',
  });
  if (!finalized.ok || finalized.kind !== 'near_ed25519') {
    throw new Error(`${responseName} did not return a finalized Ed25519 wallet`);
  }
  return {
    ...finalized,
    nearProvisioning: { status: 'near_ready' },
    registrationEstablishedSession: parseRegistrationEstablishedSession(
      registrationEstablishedSession,
      finalized.walletId,
    ),
  };
}

export async function completeWalletRegistrationNearProvisioning(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  signedSetup: string;
  /** Distinct from activate's: a separate effect needs a separate key. */
  idempotencyKey: string;
  ed25519: { activationReference: WalletRegistrationEd25519YaoActivationReference };
  auth:
    | { kind: 'passkey' }
    | {
        kind: 'email_otp';
        enrollment: WalletRegistrationEmailOtpEnrollmentMaterial;
      };
  /**
   * The custody ceremony's sealed output. For an Ed25519-only wallet this is
   * the call that establishes custody: activate had no key set to seal against.
   */
  walletCustodyCommit?: WalletCustodyCeremonyCommitPayload;
  onServerTiming?: (header: string | null) => void;
}): Promise<WalletRegistrationNearProvisioningResponseV2> {
  const body: Record<string, unknown> = {
    registrationCeremonyId: args.registrationCeremonyId,
    signedSetup: args.signedSetup,
    idempotencyKey: args.idempotencyKey,
    ed25519: args.ed25519,
  };

  if (args.auth.kind === 'email_otp') {
    body.emailOtpEnrollment = args.auth.enrollment;
  }
  if (args.walletCustodyCommit) body.walletCustodyCommit = args.walletCustodyCommit;
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: WALLET_REGISTRATION_NEAR_PROVISIONING_PATH,
    headers: args.headers,
    body,
    ...(args.onServerTiming ? { onServerTiming: args.onServerTiming } : {}),
  });
  return parseWalletRegistrationNearProvisioningResponseV2(response);
}

type FinalizeWalletRegistrationBaseArgs = {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  idempotencyKey: string;
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;
};

export type FinalizeWalletRegistrationArgs = FinalizeWalletRegistrationBaseArgs &
  (
    | {
        kind: 'near_ed25519';
        ed25519: { activationReference: WalletRegistrationEd25519YaoActivationReference };
        ecdsa?: never;
      }
    | {
        kind: 'evm_family_ecdsa';
        ecdsa: { expectedKeyHandles?: string[] };
        ed25519?: never;
      }
  );

function parseWalletRegistrationRouteTimingName(value: unknown): WalletRegistrationRouteTimingName {
  switch (value) {
    case 'registrationIntentLoadMs':
    case 'registrationIntentDigestMs':
    case 'registrationIntentConsumeMs':
    case 'registrationAttemptGateMs':
    case 'registrationPreparationPersistMs':
    case 'registrationPreparationLoadMs':
    case 'registrationPreparationConsumeMs':
    case 'registrationPreparationScopeCheckMs':
    case 'registrationAuthorityVerifyMs':
    case 'registrationEcdsaPrepareMs':
    case 'registrationCeremonyPersistMs':
    case 'registerPrepareTotalMs':
    case 'registerStartTotalMs':
    case 'registrationEcdsaRespondMs':
    case 'registrationFinalizeReplayLoadMs':
    case 'registrationCeremonyLoadMs':
    case 'registrationEcdsaBootstrapVerifyMs':
    case 'sponsoredNearAccountCreateMs':
    case 'registrationKeygenMs':
    case 'registrationEmailOtpEnrollmentPlanMs':
    case 'relaySessionMintMs':
    case 'relayGoogleEmailOtpActivationPlanMs':
    case 'relayPersistenceMs':
    case 'registrationFinalizeReplayCacheMs':
    case 'registerFinalizeTotalMs':
      return value;
    default:
      throw new Error('Wallet registration finalize response has invalid diagnostics timing name');
  }
}

function parseWalletRegistrationFinalizeDiagnostics(
  value: unknown,
): WalletRegistrationRouteDiagnostics {
  const responseName = 'Wallet registration finalize';
  const diagnostics = requireResponseRecord({
    responseName,
    field: 'registrationDiagnostics',
    value,
  });
  assertExactResponseKeys(diagnostics, ['kind', 'route', 'entries'], responseName);
  if (
    diagnostics.kind !== 'wallet_registration_route_diagnostics_v1' ||
    diagnostics.route !== 'wallets_register_finalize' ||
    !Array.isArray(diagnostics.entries)
  ) {
    throw new Error(`${responseName} response has invalid registrationDiagnostics`);
  }
  return {
    kind: 'wallet_registration_route_diagnostics_v1',
    route: 'wallets_register_finalize',
    entries: diagnostics.entries.map((entryValue) => {
      const entry = requireResponseRecord({
        responseName,
        field: 'registrationDiagnostics.entries[]',
        value: entryValue,
      });
      assertExactResponseKeys(entry, ['name', 'durationMs'], responseName);
      if (
        typeof entry.durationMs !== 'number' ||
        !Number.isFinite(entry.durationMs) ||
        entry.durationMs < 0
      ) {
        throw new Error(`${responseName} response has invalid diagnostics durationMs`);
      }
      return {
        name: parseWalletRegistrationRouteTimingName(entry.name),
        durationMs: entry.durationMs,
      };
    }),
  };
}

function parseWalletRegistrationFinalizeAuthority(value: unknown): WalletAuthAuthority {
  const responseName = 'Wallet registration finalize';
  const authority = requireResponseRecord({ responseName, field: 'authority', value });
  assertExactResponseKeys(authority, ['walletId', 'factor', 'verifier', 'bindingId'], responseName);
  const factor = requireResponseRecord({
    responseName,
    field: 'authority.factor',
    value: authority.factor,
  });
  const verifier = requireResponseRecord({
    responseName,
    field: 'authority.verifier',
    value: authority.verifier,
  });
  switch (factor.kind) {
    case 'passkey':
      assertExactResponseKeys(factor, ['kind', 'credentialIdB64u'], responseName);
      assertExactResponseKeys(verifier, ['kind', 'rpId'], responseName);
      break;
    case 'email_otp':
      assertExactResponseKeys(factor, ['kind', 'provider', 'providerUserId'], responseName);
      assertExactResponseKeys(verifier, ['kind', 'emailHashHex'], responseName);
      break;
    default:
      throw new Error(`${responseName} response has invalid authority factor`);
  }
  const parsed = parseWalletAuthAuthority(authority);
  if (!parsed) {
    throw new Error(`${responseName} response has invalid authority`);
  }
  return parsed;
}

type ParsedWalletRegistrationFinalizeAuthorityBranch =
  | {
      kind: 'passkey';
      rpId: string;
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'passkey' }>;
    }
  | {
      kind: 'email_otp';
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'email_otp' }>;
      rpId?: never;
    };

function parseWalletRegistrationFinalizeAuthorityBranch(args: {
  response: Record<string, unknown>;
  walletId: WalletId;
  authority: WalletAuthAuthority;
}): ParsedWalletRegistrationFinalizeAuthorityBranch {
  const responseName = 'Wallet registration finalize';
  const authMethod = requireResponseRecord({
    responseName,
    field: 'authMethod',
    value: args.response.authMethod,
  });
  if (String(args.authority.walletId) !== String(args.walletId)) {
    throw new Error(`${responseName} response authority wallet mismatch`);
  }
  switch (authMethod.kind) {
    case 'passkey': {
      assertExactResponseKeys(
        authMethod,
        ['kind', 'credentialIdB64u', 'credentialPublicKeyB64u'],
        responseName,
      );
      if (!isPasskeyWalletAuthAuthority(args.authority)) {
        throw new Error(`${responseName} response has inconsistent passkey authority`);
      }
      const rpId = requireResponseRpId(args.response.rpId, responseName);
      const credentialIdB64u = requireResponseString({
        responseName,
        field: 'authMethod.credentialIdB64u',
        value: authMethod.credentialIdB64u,
      });
      if (
        String(args.authority.factor.credentialIdB64u) !== credentialIdB64u ||
        String(args.authority.verifier.rpId) !== String(rpId)
      ) {
        throw new Error(`${responseName} response passkey authority binding mismatch`);
      }
      return {
        kind: 'passkey',
        rpId,
        authMethod: {
          kind: 'passkey',
          credentialIdB64u,
          credentialPublicKeyB64u: requireResponseString({
            responseName,
            field: 'authMethod.credentialPublicKeyB64u',
            value: authMethod.credentialPublicKeyB64u,
          }),
        },
      };
    }
    case 'email_otp':
      assertExactResponseKeys(authMethod, ['kind', 'registrationAuthorityId'], responseName);
      if (isPasskeyWalletAuthAuthority(args.authority) || args.response.rpId !== undefined) {
        throw new Error(`${responseName} response has inconsistent email OTP authority`);
      }
      return {
        kind: 'email_otp',
        authMethod: {
          kind: 'email_otp',
          registrationAuthorityId: requireResponseString({
            responseName,
            field: 'authMethod.registrationAuthorityId',
            value: authMethod.registrationAuthorityId,
          }),
        },
      };
    default:
      throw new Error(`${responseName} response has invalid authMethod`);
  }
}

function parseWalletRegistrationNearAccountProvisioning(
  value: unknown,
): RegistrationNearAccountProvisioning {
  const responseName = 'Wallet registration finalize';
  const provisioning = requireResponseRecord({
    responseName,
    field: 'accountProvisioning',
    value,
  });
  switch (provisioning.kind) {
    case 'implicit_account':
      assertExactResponseKeys(provisioning, ['kind', 'accountIdSource'], responseName);
      if (provisioning.accountIdSource !== 'ed25519_public_key') {
        throw new Error(`${responseName} response has invalid implicit account provisioning`);
      }
      return {
        kind: 'implicit_account',
        accountIdSource: 'ed25519_public_key',
      };
    case 'sponsored_named_account': {
      assertExactResponseKeys(
        provisioning,
        ['kind', 'requestedAccountId', 'sponsor'],
        responseName,
      );
      const requestedAccountId = parseNamedNearAccountId(provisioning.requestedAccountId);
      if (!requestedAccountId.ok || provisioning.sponsor !== 'relayer') {
        throw new Error(`${responseName} response has invalid named account provisioning`);
      }
      return {
        kind: 'sponsored_named_account',
        requestedAccountId: requestedAccountId.value,
        sponsor: 'relayer',
      };
    }
    default:
      throw new Error(`${responseName} response has invalid accountProvisioning kind`);
  }
}

function parseWalletRegistrationResolvedNearAccount(
  value: unknown,
): ResolvedRegistrationNearAccount {
  const responseName = 'Wallet registration finalize';
  const resolved = requireResponseRecord({
    responseName,
    field: 'resolvedAccount',
    value,
  });
  switch (resolved.kind) {
    case 'implicit_account': {
      assertExactResponseKeys(
        resolved,
        ['kind', 'nearAccountId', 'nearEd25519SigningKeyId'],
        responseName,
      );
      const nearAccountId = parseImplicitNearAccountId(resolved.nearAccountId);
      if (!nearAccountId.ok) {
        throw new Error(`${responseName} response has invalid implicit nearAccountId`);
      }
      return {
        kind: 'implicit_account',
        nearAccountId: nearAccountId.value,
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(resolved.nearEd25519SigningKeyId),
      };
    }
    case 'sponsored_named_account': {
      assertExactResponseKeys(
        resolved,
        ['kind', 'nearAccountId', 'nearEd25519SigningKeyId', 'transactionHash'],
        responseName,
      );
      const nearAccountId = parseNamedNearAccountId(resolved.nearAccountId);
      if (!nearAccountId.ok) {
        throw new Error(`${responseName} response has invalid named nearAccountId`);
      }
      return {
        kind: 'sponsored_named_account',
        nearAccountId: nearAccountId.value,
        nearEd25519SigningKeyId: parseNearEd25519SigningKeyId(resolved.nearEd25519SigningKeyId),
        transactionHash: requireResponseString({
          responseName,
          field: 'resolvedAccount.transactionHash',
          value: resolved.transactionHash,
        }),
      };
    }
    default:
      throw new Error(`${responseName} response has invalid resolvedAccount kind`);
  }
}

function parseWalletRegistrationFinalizeEcdsaResult(args: { value: unknown; walletId: WalletId }): {
  walletKeys: WalletRegistrationEcdsaWalletKey[];
} {
  const responseName = 'Wallet registration finalize';
  const ecdsa = requireResponseRecord({ responseName, field: 'ecdsa', value: args.value });
  assertExactResponseKeys(ecdsa, ['walletKeys'], responseName);
  if (!Array.isArray(ecdsa.walletKeys) || ecdsa.walletKeys.length === 0) {
    throw new Error(`${responseName} response has invalid walletKeys`);
  }
  const targetKeys = new Set<string>();
  const walletKeys = ecdsa.walletKeys.map((value) => {
    const walletKey = parseWalletAddSignerEcdsaWalletKey(value, responseName);
    if (walletKey.walletId !== String(args.walletId)) {
      throw new Error(`${responseName} response ECDSA walletId mismatch`);
    }
    if (
      String(walletKey.publicCapability.client_id) !== String(args.walletId) ||
      walletKey.publicCapability.public_identity.context_binding_b64u !==
        walletKey.contextBinding32B64u ||
      walletKey.publicCapability.public_identity.derivation_client_share_public_key33_b64u !==
        walletKey.derivationClientSharePublicKey33B64u ||
      walletKey.publicCapability.public_identity.threshold_public_key33_b64u !==
        walletKey.thresholdEcdsaPublicKeyB64u ||
      walletKey.publicCapability.public_identity.client_share_retry_counter !==
        walletKey.clientShareRetryCounter ||
      walletKey.publicCapability.public_identity.server_share_retry_counter !==
        walletKey.relayerShareRetryCounter
    ) {
      throw new Error(`${responseName} response ECDSA public capability mismatch`);
    }
    const targetKey = thresholdEcdsaChainTargetKey(walletKey.chainTarget);
    if (targetKeys.has(targetKey)) {
      throw new Error(`${responseName} response has duplicate ECDSA target ${targetKey}`);
    }
    targetKeys.add(targetKey);
    return walletKey;
  });
  return { walletKeys };
}

function parseWalletRegistrationFinalizeNearResult(args: {
  response: Record<string, unknown>;
  walletId: WalletId;
  authority: WalletAuthAuthority;
}): {
  authorityScope: Ed25519AuthorityScope;
  accountProvisioning: RegistrationNearAccountProvisioning;
  resolvedAccount: ResolvedRegistrationNearAccount;
  ed25519: WalletRegistrationEd25519YaoPublicResult;
} {
  const responseName = 'Wallet registration finalize';
  const authorityScope = parseWalletRegistrationEd25519AuthorityScope(
    args.response.authorityScope,
    responseName,
  );
  const accountProvisioning = parseWalletRegistrationNearAccountProvisioning(
    args.response.accountProvisioning,
  );
  const resolvedAccount = parseWalletRegistrationResolvedNearAccount(args.response.resolvedAccount);
  const ed25519 = parseWalletRegistrationEd25519Result(args.response.ed25519, responseName);
  if (
    accountProvisioning.kind !== resolvedAccount.kind ||
    resolvedAccount.nearAccountId !== ed25519.nearAccountId ||
    resolvedAccount.nearEd25519SigningKeyId !== ed25519.nearEd25519SigningKeyId
  ) {
    throw new Error(`${responseName} response has inconsistent Ed25519 identity`);
  }
  if (
    (authorityScope.kind === 'passkey_rp' &&
      (!isPasskeyWalletAuthAuthority(args.authority) ||
        String(args.authority.verifier.rpId) !== String(authorityScope.rpId))) ||
    (authorityScope.kind === 'email_otp' &&
      (isPasskeyWalletAuthAuthority(args.authority) ||
        args.authority.factor.provider !== authorityScope.provider ||
        String(args.authority.factor.providerUserId) !== authorityScope.providerUserId))
  ) {
    throw new Error(`${responseName} response authorityScope mismatch`);
  }
  return {
    authorityScope,
    accountProvisioning,
    resolvedAccount,
    ed25519,
  };
}

export function parseWalletRegistrationFinalizeResponse(args: {
  value: unknown;
  expectedKind: FinalizeWalletRegistrationArgs['kind'];
}): WalletRegistrationFinalizeResponse {
  const responseName = 'Wallet registration finalize';
  const response = requireResponseRecord({
    responseName,
    field: 'body',
    value: args.value,
  });
  assertExactResponseKeys(
    response,
    [
      'ok',
      'walletId',
      'authority',
      'registrationDiagnostics',
      'rpId',
      'authMethod',
      'walletCustody',
      'kind',
      'authorityScope',
      'accountProvisioning',
      'resolvedAccount',
      'ed25519',
      'ecdsa',
    ],
    responseName,
  );
  if (response.ok !== true || response.kind !== args.expectedKind) {
    throw new Error(`${responseName} response substituted signer branch`);
  }
  const walletId = walletIdFromString(
    requireResponseString({
      responseName,
      field: 'walletId',
      value: response.walletId,
    }),
  );
  const authority = parseWalletRegistrationFinalizeAuthority(response.authority);
  const authorityBranch = parseWalletRegistrationFinalizeAuthorityBranch({
    response,
    walletId,
    authority,
  });
  const registrationDiagnostics =
    response.registrationDiagnostics === undefined
      ? undefined
      : parseWalletRegistrationFinalizeDiagnostics(response.registrationDiagnostics);
  /* Absent is a real state — no custody payload rode this leg — and distinct
     from every reported outcome. It must not be conflated with `committed`. */
  const walletCustody =
    response.walletCustody === undefined
      ? {}
      : {
          walletCustody: parseWalletCustodyRegistrationOutcome(
            response.walletCustody,
            responseName,
          ),
        };

  switch (response.kind) {
    case 'near_ed25519': {
      if (response.ecdsa !== undefined) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const near = parseWalletRegistrationFinalizeNearResult({
        response,
        walletId,
        authority,
      });
      if (authorityBranch.kind === 'passkey') {
        return {
          ok: true,
          walletId,
          authority,
          ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
          ...walletCustody,
          rpId: authorityBranch.rpId,
          authMethod: authorityBranch.authMethod,
          kind: 'near_ed25519',
          authorityScope: near.authorityScope,
          accountProvisioning: near.accountProvisioning,
          resolvedAccount: near.resolvedAccount,
          ed25519: near.ed25519,
        };
      }
      return {
        ok: true,
        walletId,
        authority,
        ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
        ...walletCustody,
        authMethod: authorityBranch.authMethod,
        kind: 'near_ed25519',
        authorityScope: near.authorityScope,
        accountProvisioning: near.accountProvisioning,
        resolvedAccount: near.resolvedAccount,
        ed25519: near.ed25519,
      };
    }
    case 'evm_family_ecdsa': {
      if (
        response.authorityScope !== undefined ||
        response.accountProvisioning !== undefined ||
        response.resolvedAccount !== undefined ||
        response.ed25519 !== undefined
      ) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
      const ecdsa = parseWalletRegistrationFinalizeEcdsaResult({
        value: response.ecdsa,
        walletId,
      });
      if (authorityBranch.kind === 'passkey') {
        return {
          ok: true,
          walletId,
          authority,
          ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
          ...walletCustody,
          rpId: authorityBranch.rpId,
          authMethod: authorityBranch.authMethod,
          kind: 'evm_family_ecdsa',
          ecdsa,
        };
      }
      return {
        ok: true,
        walletId,
        authority,
        ...(registrationDiagnostics ? { registrationDiagnostics } : {}),
        ...walletCustody,
        authMethod: authorityBranch.authMethod,
        kind: 'evm_family_ecdsa',
        ecdsa,
      };
    }
    default:
      throw new Error(`${responseName} response has invalid kind`);
  }
}

function addSignerAuthBody(auth: AddSignerAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        rpId: auth.rpId,
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
  }
}

function addAuthMethodAuthBody(auth: AddAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        rpId: auth.rpId,
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
    case 'email_otp':
      return { kind: 'email_otp' };
  }
}

function addAuthMethodAuthorityBody(
  authority: WalletAddAuthMethodAuthority,
): Record<string, unknown> {
  switch (authority.kind) {
    case 'passkey':
      return {};
    case 'email_otp':
      return { emailOtpRegistrationProof: authority.emailOtpRegistrationProof };
  }
}

function revokeAuthMethodAuthBody(auth: RevokeAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        rpId: auth.rpId,
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
  }
}

export async function startWalletAddSigner(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerIntentGrant: AddSignerIntentGrant;
  addSignerIntentDigestB64u: string;
  intent: AddSignerIntentV1;
  auth: AddSignerAuth;
}): Promise<WalletAddSignerStartResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer start');
  const value = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/start`,
    body: {
      addSignerIntentGrant: args.addSignerIntentGrant,
      addSignerIntentDigestB64u: args.addSignerIntentDigestB64u,
      intent: args.intent,
      auth: addSignerAuthBody(args.auth),
    },
  });
  return parseWalletAddSignerStartResponse({ value, expectedIntent: args.intent });
}

export async function startWalletAddAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  addAuthMethodIntentGrant: AddAuthMethodIntentGrant;
  addAuthMethodIntentDigestB64u: string;
  intent: AddAuthMethodIntentV1;
  auth: AddAuthMethodAuth;
  authority: WalletAddAuthMethodAuthority;
}): Promise<WalletAddAuthMethodStartResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method start');
  const value = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/start`,
    body: {
      addAuthMethodIntentGrant: args.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: args.addAuthMethodIntentDigestB64u,
      intent: args.intent,
      auth: addAuthMethodAuthBody(args.auth),
      ...addAuthMethodAuthorityBody(args.authority),
    },
  });
  return parseWalletAddAuthMethodStartResponse({ value, expectedIntent: args.intent });
}

export async function respondWalletAddSignerEcdsa(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
    requestDigestB64u: string;
  };
}): Promise<WalletAddSignerEcdsaRespondResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer ECDSA respond');
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/derivation/respond`,
    body: {
      addSignerCeremonyId: args.addSignerCeremonyId,
      ecdsa: args.ecdsa,
    },
  });
  return parseWalletAddSignerEcdsaRespondResponse(response);
}

export async function activateWalletAddSignerEcdsa(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  activationCorrelationId: CorrelationId;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
  expectedActivationRequestDigest: RouterAbPublicDigest32V1Wire;
}): Promise<WalletAddSignerEcdsaActivationResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer ECDSA activation');
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/derivation/activate`,
    body: {
      addSignerCeremonyId: args.addSignerCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1',
        activationCorrelationId: args.activationCorrelationId,
        publicFacts: args.publicFacts,
        expectedActivationRequestDigest: args.expectedActivationRequestDigest,
      },
    },
  });
  return parseWalletAddSignerEcdsaActivationResponse(response);
}

export type FinalizeWalletAddSignerArgs = {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  idempotencyKey: string;
} & (
  | {
      kind: 'near_ed25519';
      ed25519: {
        activationReference: WalletRegistrationEd25519YaoActivationReference;
      };
      custodyKeySet: {
        readonly kind: 'near_ed25519_v1';
        readonly keyManifestDigestB64u: string;
        readonly registeredPublicKeyB64u: string;
      };
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: {
        expectedKeyHandles?: string[];
      };
      custodyKeySet: {
        readonly kind: 'evm_family_ecdsa_v1';
        readonly keyManifestDigestB64u: string;
        readonly clientRootPublicKey33B64u: string;
      };
      ed25519?: never;
    }
);

function addSignerFinalizeBody(args: FinalizeWalletAddSignerArgs): unknown {
  switch (args.kind) {
    case 'near_ed25519':
      return {
        addSignerCeremonyId: args.addSignerCeremonyId,
        idempotencyKey: args.idempotencyKey,
        kind: args.kind,
        ed25519: args.ed25519,
        custodyKeySet: args.custodyKeySet,
      };
    case 'evm_family_ecdsa':
      return {
        addSignerCeremonyId: args.addSignerCeremonyId,
        idempotencyKey: args.idempotencyKey,
        kind: args.kind,
        ecdsa: args.ecdsa,
        custodyKeySet: args.custodyKeySet,
      };
  }
}

export async function finalizeWalletAddSigner(
  args: FinalizeWalletAddSignerArgs,
): Promise<WalletAddSignerFinalizeResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer finalize');
  const value = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/finalize`,
    body: addSignerFinalizeBody(args),
  });
  return parseWalletAddSignerFinalizeResponse({ value, expectedKind: args.kind });
}

export async function finalizeWalletAddAuthMethod(
  args:
    | {
        relayerUrl: string;
        walletId: WalletId;
        addAuthMethodCeremonyId: string;
        webauthnRegistration: unknown;
        custodyEnvelope: PasskeyCustodyEnvelopeRecord;
      }
    | {
        relayerUrl: string;
        walletId: WalletId;
        addAuthMethodCeremonyId: string;
        webauthnRegistration?: never;
        custodyEnvelope?: never;
      },
): Promise<WalletAddAuthMethodFinalizeResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method finalize');
  const body =
    args.webauthnRegistration !== undefined && args.custodyEnvelope !== undefined
      ? {
          addAuthMethodCeremonyId: args.addAuthMethodCeremonyId,
          webauthnRegistration: args.webauthnRegistration,
          custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(args.custodyEnvelope),
        }
      : { addAuthMethodCeremonyId: args.addAuthMethodCeremonyId };
  return await postJson<WalletAddAuthMethodFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/finalize`,
    body,
  });
}

export async function revokeWalletAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  auth: RevokeAuthMethodAuth;
  target: WalletAuthMethodTarget;
}): Promise<WalletRevokeAuthMethodResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for auth-method revoke');
  return await postJson<WalletRevokeAuthMethodResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/revoke`,
    body: {
      auth: revokeAuthMethodAuthBody(args.auth),
      target: args.target,
    },
  });
}

export async function fetchWalletEcdsaKeyFactsInventoryWithOpaqueWalletSession(args: {
  relayerUrl: string;
  walletId: WalletId;
  rpId: string;
  curve: 'ecdsa_secp256k1';
  walletSessionToken: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const walletId = String(args.walletId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const walletSessionToken = String(args.walletSessionToken || '').trim();
  if (!walletId) {
    throw new Error('walletId is required for ECDSA key-facts inventory');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts inventory');
  }
  if (!walletSessionToken) {
    throw new Error('walletSessionToken is required for ECDSA key-facts inventory');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    headers: buildBearerAuthorizationHeader({
      token: walletSessionToken,
      missingMessage: 'walletSessionToken is required for ECDSA key-facts inventory',
    }),
    body: {
      rpId,
      keyTargets: args.keyTargets,
      auth: {
        kind: 'opaque_wallet_session',
        curve: args.curve,
      },
    },
  });
  const records = Array.isArray(data.ecdsaKeyIdentityTargets) ? data.ecdsaKeyIdentityTargets : [];
  return {
    ok: true,
    records: parseThresholdEcdsaKeyIdentityTargets({
      walletId: args.walletId,
      rpId,
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}

export async function fetchWalletEcdsaKeyFactsInventoryWithWebAuthn(args: {
  relayerUrl: string;
  walletId: WalletId;
  rpId: string;
  credential: WebAuthnAuthenticationCredential;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  serverNonceB64u: string;
  expectedChallengeDigestB64u: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const walletId = String(args.walletId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const serverNonceB64u = String(args.serverNonceB64u || '').trim();
  const expectedChallengeDigestB64u = String(args.expectedChallengeDigestB64u || '').trim();
  if (!walletId) {
    throw new Error('walletId is required for ECDSA key-facts inventory');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts inventory');
  }
  if (!serverNonceB64u || !expectedChallengeDigestB64u) {
    throw new Error('WebAuthn ECDSA key-facts inventory requires challenge binding');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    body: {
      rpId,
      keyTargets: args.keyTargets,
      auth: {
        kind: 'webauthn_assertion',
        credential: args.credential,
        serverNonceB64u,
        expectedChallengeDigestB64u,
        ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
      },
    },
  });
  const records = Array.isArray(data.ecdsaKeyIdentityTargets) ? data.ecdsaKeyIdentityTargets : [];
  return {
    ok: true,
    records: parseThresholdEcdsaKeyIdentityTargets({
      walletId: args.walletId,
      rpId,
      records,
    }),
    diagnostics: Object.prototype.hasOwnProperty.call(data, 'diagnostics')
      ? data.diagnostics
      : null,
  };
}
