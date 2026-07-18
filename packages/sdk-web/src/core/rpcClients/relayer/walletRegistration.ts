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
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { alphabetizeStringify } from '@shared/utils/digests';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';
import {
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
  type RouterAbEd25519YaoBytes32V1,
  type RouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '@shared/utils/routerAbEd25519Yao';
import {
  parseWalletAuthAuthority,
  type WalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import {
  requireRouterAbEd25519NormalSigningState,
  type RouterAbEd25519NormalSigningState,
} from '@shared/utils/signingSessionSeal';
import {
  parseRouterAbEcdsaRegistrationPublicActivationReceiptV1,
  parseRouterAbEcdsaRegistrationRequestFactsV1,
  parseRouterAbEcdsaStrictForwardedRegistrationResponseV1,
  parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1,
  type RouterAbEcdsaRegistrationRequestFactsV1,
  type RouterAbEcdsaRegistrationRequestV1,
  type RouterAbEcdsaRegistrationPublicActivationReceiptV1,
  type RouterAbEcdsaVerifiedClientActivationFactsV1,
  type RouterAbEcdsaStrictForwardedRegistrationResponseV1,
  type RouterAbEcdsaDerivationPublicCapabilityV1,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  computeSdkEcdsaDerivationApplicationBindingDigestB64u,
  parseSdkEcdsaDerivationSigningRootId,
  parseSdkEcdsaDerivationSigningRootVersion,
} from '@shared/threshold/ecdsaDerivationRoleLocalBootstrap';
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
import type { ThresholdEcdsaSessionBootstrapResult } from '@/core/signingEngine/threshold/ecdsa/activation';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import type {
  ThresholdEcdsaRoleLocalWorkerShareHandle,
  ThresholdEcdsaSecp256k1KeyRef,
} from '@/core/signingEngine/interfaces/signing';
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
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPasskeyAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '@/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';
import type {
  EcdsaRoleLocalPublicFacts,
  EcdsaRoleLocalReadyStateBlob,
} from '@/core/platform';
import {
  buildBearerAuthorizationHeader,
  buildRelayerJsonPostRequestInit,
  normalizeRelayerBaseUrl,
} from './relayerHttp';
import {
  registrationSignerSetRequestSelection,
  type RegistrationSignerSetRequest,
} from './registrationSignerSetRequest';

const REGISTRATION_ROUTE_PAYLOAD_DIAGNOSTICS_LABEL = '[Registration] wallet route payload summary';
const ROUTE_PAYLOAD_BREAKDOWN_MAX_DEPTH = 2;
const ROUTE_PAYLOAD_BREAKDOWN_MAX_FIELDS = 64;
const WALLET_REGISTRATION_INTENT_CANCEL_PATH = '/wallets/register/intent/cancel';
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

function logWalletRegistrationRouteProgress(
  stage: string,
  details?: Record<string, unknown>,
): void {
  console.info('[wallet-registration][route] progress', {
    stage,
    ...(details || {}),
  });
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
}): Promise<TResponse> {
  const startedAt = Date.now();
  const requestBody = JSON.stringify(args.body);
  const maxAttempts = walletRegistrationPostMaxAttempts(args.path);
  if (args.path === WALLET_REGISTRATION_FINALIZE_PATH) {
    logWalletRegistrationRouteProgress('finalize_fetch_started', {
      requestBytes: utf8Bytes(requestBody),
    });
  }
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    const response = await fetch(
      `${normalizeRelayerBaseUrl(args.relayerUrl, { trim: false })}${args.path}`,
      buildRelayerJsonPostRequestInit({
        headers: args.headers,
        body: args.body,
        bodyJson: requestBody,
      }),
    );
    if (args.path === WALLET_REGISTRATION_FINALIZE_PATH) {
      logWalletRegistrationRouteProgress('finalize_fetch_headers_received', {
        status: response.status,
        ok: response.ok,
        durationMs: Date.now() - startedAt,
      });
    }
    const responseText = await readResponseText(response);
    if (args.path === WALLET_REGISTRATION_FINALIZE_PATH) {
      logWalletRegistrationRouteProgress('finalize_fetch_body_read', {
        responseBytes: utf8Bytes(responseText),
        durationMs: Date.now() - startedAt,
      });
    }
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
      logWalletRegistrationRouteProgress('prepare_worker_restart_retry', {
        status: response.status,
        responseBytes: utf8Bytes(responseText),
        durationMs: Date.now() - startedAt,
      });
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

function createRegistrationIntentWireRequest(
  request: CreateRegistrationIntentRequest,
): CreateRegistrationIntentRequest {
  return {
    wallet: request.wallet,
    authMethod: request.authMethod,
    signerSelection: registrationSignerSetRequestSelection(request.signerSelection),
  };
}

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
  walletSessionJwt: string;
}): Promise<FundImplicitNearAccountForTestingResponse> {
  const walletId = String(args.walletId || '').trim();
  const nearAccountId = String(args.nearAccountId || '').trim();
  const nearPublicKeyStr = String(args.nearPublicKeyStr || '').trim();
  const walletSessionJwt = String(args.walletSessionJwt || '').trim();
  if (!walletId) throw new Error('walletId is required for implicit NEAR account funding');
  if (!nearAccountId) {
    throw new Error('nearAccountId is required for implicit NEAR account funding');
  }
  if (!nearPublicKeyStr) {
    throw new Error('nearPublicKeyStr is required for implicit NEAR account funding');
  }
  if (!walletSessionJwt) {
    throw new Error('walletSessionJwt is required for implicit NEAR account funding');
  }
  return await postJson<FundImplicitNearAccountForTestingResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/near/implicit-account/fund`,
    headers: buildBearerAuthorizationHeader({
      token: walletSessionJwt,
      missingMessage: 'walletSessionJwt is required for implicit NEAR account funding',
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
  route: 'wallets_register_start' | 'wallets_register_ecdsa_derivation_respond' | 'wallets_register_finalize';
  entries: {
    name: WalletRegistrationRouteTimingName;
    durationMs: number;
  }[];
};

export type WalletRegistrationEd25519YaoStart = {
  admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1;
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

export type WalletRegistrationEcdsaRespondResponse = {
  ok: true;
  registrationCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_forwarded_v1';
    strictResult: RouterAbEcdsaStrictForwardedRegistrationResponseV1;
  };
};

export type WalletRegistrationEcdsaActivationResponse = {
  ok: true;
  registrationCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_activated_v1';
    activation: RouterAbEcdsaRegistrationPublicActivationReceiptV1;
    bootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
  };
};

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

function parseWalletRegistrationEcdsaRespondResponse(
  value: unknown,
): WalletRegistrationEcdsaRespondResponse {
  const response = requireResponseRecord({
    responseName: 'ECDSA registration derivation',
    field: 'response',
    value,
  });
  requireExactResponseKeys(
    response,
    ['ok', 'registrationCeremonyId', 'registrationDiagnostics', 'ecdsa'],
    'ECDSA registration derivation response',
  );
  if (response.ok !== true) {
    throw new Error('ECDSA registration derivation response is not successful');
  }
  const ecdsa = requireResponseRecord({
    responseName: 'ECDSA registration derivation',
    field: 'ecdsa',
    value: response.ecdsa,
  });
  requireExactResponseKeys(
    ecdsa,
    ['kind', 'strictResult'],
    'ECDSA registration derivation response ecdsa',
  );
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_forwarded_v1') {
    throw new Error('ECDSA registration derivation response kind is invalid');
  }
  return {
    ok: true,
    registrationCeremonyId: requireResponseString({
      responseName: 'ECDSA registration derivation',
      field: 'registrationCeremonyId',
      value: response.registrationCeremonyId,
    }),
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_forwarded_v1',
      strictResult: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(
        ecdsa.strictResult,
      ),
    },
  };
}

function parseWalletRegistrationEcdsaActivationResponse(
  value: unknown,
): WalletRegistrationEcdsaActivationResponse {
  const response = requireResponseRecord({
    responseName: 'ECDSA registration activation',
    field: 'response',
    value,
  });
  requireExactResponseKeys(
    response,
    ['ok', 'registrationCeremonyId', 'ecdsa'],
    'ECDSA registration activation response',
  );
  if (response.ok !== true) {
    throw new Error('ECDSA registration activation response is not successful');
  }
  const ecdsa = requireResponseRecord({
    responseName: 'ECDSA registration activation',
    field: 'ecdsa',
    value: response.ecdsa,
  });
  requireExactResponseKeys(
    ecdsa,
    ['kind', 'activation', 'bootstrap'],
    'ECDSA registration activation response ecdsa',
  );
  if (ecdsa.kind !== 'router_ab_ecdsa_registration_activated_v1') {
    throw new Error('ECDSA registration activation response kind is invalid');
  }
  return {
    ok: true,
    registrationCeremonyId: requireResponseString({
      responseName: 'ECDSA registration activation',
      field: 'registrationCeremonyId',
      value: response.registrationCeremonyId,
    }),
    ecdsa: {
      kind: 'router_ab_ecdsa_registration_activated_v1',
      activation: parseRouterAbEcdsaRegistrationPublicActivationReceiptV1(
        ecdsa.activation,
      ),
      bootstrap: parseThresholdEcdsaDerivationRoleLocalBootstrapValue(ecdsa.bootstrap),
    },
  };
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
  requireExactResponseKeys(
    ecdsa,
    ['kind', 'strictResult'],
    `${responseName} response ecdsa`,
  );
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
      strictResult: parseRouterAbEcdsaStrictForwardedRegistrationResponseV1(
        ecdsa.strictResult,
      ),
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
      activation: parseRouterAbEcdsaRegistrationPublicActivationReceiptV1(
        ecdsa.activation,
      ),
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
  sessionKind: 'jwt';
  walletSessionJwt: string;
  walletId: WalletId;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  authorityScope: Ed25519AuthorityScope;
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  participantIds: readonly [number, number];
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
};

export type WalletRegistrationEd25519YaoPublicResult = {
  signerSlot: number;
  nearAccountId: string;
  nearEd25519SigningKeyId: string;
  publicKey: string;
  relayerKeyId: string;
  keyVersion: string;
  recoveryExportCapable: true;
  participantIds: readonly [number, number];
  session: WalletRegistrationEd25519YaoBootstrapSession;
};

type WalletRegistrationFinalizeResponseBase = {
  ok: true;
  walletId: WalletId;
  authority: WalletAuthAuthority;
  registrationDiagnostics?: WalletRegistrationRouteDiagnostics;
};

export type WalletRegistrationFinalizeResponseAuthority =
  | {
      rpId: string;
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'passkey' }>;
      appSessionJwt?: never;
    }
  | {
      authMethod: Extract<WalletRegistrationFinalizeAuthMethod, { kind: 'email_otp' }>;
      appSessionJwt: string;
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
      }
    | {
        kind: 'near_ed25519_and_evm_family_ecdsa';
        authorityScope: Ed25519AuthorityScope;
        accountProvisioning: RegistrationNearAccountProvisioning;
        resolvedAccount: ResolvedRegistrationNearAccount;
        ed25519: WalletRegistrationEd25519YaoPublicResult;
        ecdsa: { walletKeys: WalletRegistrationEcdsaWalletKey[] };
      };

export type EmailOtpWalletRegistrationFinalizeResponse =
  WalletRegistrationFinalizeResponseBase &
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
  recoveryWrappedEnrollmentEscrows: unknown[];
  enrollmentSealKeyVersion: string;
  clientUnlockPublicKeyB64u: string;
  unlockKeyVersion: string;
  thresholdEcdsaClientVerifyingShareB64u: string;
};

export type WalletRegistrationEmailOtpBackupAck = {
  kind: 'email_otp_recovery_code_backup_ack_v1';
  offerId?: string;
  candidateId?: string;
  recoveryCodesIssuedAtMs: number;
  backupActionKind: 'download' | 'copy' | 'print' | 'manual';
  acknowledgedAtMs: number;
  idempotencyKey: string;
};

export type AddSignerAppSessionPolicy = {
  permission: 'wallet_signer_provision';
  walletId: WalletId;
  signerSelection: AddSignerIntentV1['signerSelection'];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
};

export type AddAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_provision';
  walletId: WalletId;
  authMethod: AddAuthMethodInput;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
};

export type RevokeAuthMethodAppSessionPolicy = {
  permission: 'wallet_auth_method_revoke';
  walletId: WalletId;
  target: WalletAuthMethodTarget;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  expiresAtMs: number;
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

export type AddSignerAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: string;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: AddSignerAppSessionPolicy;
    };

export type AddAuthMethodAuth =
  | {
      kind: 'webauthn_assertion';
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: AddAuthMethodAppSessionPolicy;
    };

export type WalletAddAuthMethodAuthority =
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

export type WalletAddAuthMethodStartResponse = {
  ok: true;
  addAuthMethodCeremonyId: string;
  intent: AddAuthMethodIntentV1;
};

export type WalletAddAuthMethodFinalizeResponse = {
  ok: true;
  walletId: WalletId;
  rpId: string;
  authMethod: {
    kind: 'passkey' | 'email_otp';
    status: 'active' | 'revoked';
  };
};

export type RevokeAuthMethodAuth =
  | {
      kind: 'webauthn_assertion';
      rpId: WebAuthnRpId;
      credential: WebAuthnAuthenticationCredential;
      expectedChallengeDigestB64u: string;
    }
  | {
      kind: 'app_session';
      appSessionJwt: string;
      policy: RevokeAuthMethodAppSessionPolicy;
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

export type WalletAddSignerStartResponse = {
  ok: true;
  addSignerCeremonyId: string;
  intent: AddSignerIntentV1;
} & (
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
);

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
      ed25519: WalletRegistrationEd25519YaoPublicResult;
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
      'signingGrantId',
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
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(
    prepare.runtimePolicyScope,
  );
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
    signingGrantId: requireResponseString({
      responseName,
      field: 'prepare.signingGrantId',
      value: prepare.signingGrantId,
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
    participantIds: [
      ...requireResponseParticipantPair(prepare.participantIds, responseName),
    ],
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
    ['kind', 'chainTargets', 'prepare', 'strictRegistration'],
    responseName,
  );
  if (
    record.kind !== 'evm_family_ecdsa_keygen' ||
    !Array.isArray(record.chainTargets)
  ) {
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
  const prepare = parseWalletAddSignerEcdsaPrepareContext(
    record.prepare,
    responseName,
  );
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
    ['ok', 'addSignerCeremonyId', 'intent', 'kind', 'ed25519', 'ecdsa'],
    responseName,
  );
  if (record.ok !== true) throw new Error(`${responseName} response is not successful`);
  const addSignerCeremonyId = requireResponseString({
    responseName,
    field: 'addSignerCeremonyId',
    value: record.addSignerCeremonyId,
  });
  const intent = requireExactAddSignerIntent(record.intent, args.expectedIntent);
  switch (record.kind) {
    case 'near_ed25519': {
      if (intent.signerSelection.mode !== 'ed25519' || record.ecdsa !== undefined) {
        throw new Error(`${responseName} response substituted signer branch`);
      }
      const ed25519 = requireResponseRecord({
        responseName,
        field: 'ed25519',
        value: record.ed25519,
      });
      assertExactResponseKeys(ed25519, ['admissionRequest'], responseName);
      const admission = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1(
        ed25519.admissionRequest,
      );
      if (!admission.ok) throw new Error(admission.message);
      return {
        ok: true,
        addSignerCeremonyId,
        intent,
        kind: 'near_ed25519',
        ed25519: { admissionRequest: admission.value },
      };
    }
    case 'evm_family_ecdsa':
      if (intent.signerSelection.mode !== 'ecdsa' || record.ed25519 !== undefined) {
        throw new Error(`${responseName} response substituted signer branch`);
      }
      return {
        ok: true,
        addSignerCeremonyId,
        intent,
        kind: 'evm_family_ecdsa',
        ecdsa: parseWalletAddSignerEcdsaPrepare(record.ecdsa, intent),
      };
    default:
      throw new Error(`${responseName} response has invalid kind`);
  }
}

function requireResponseRpId(value: unknown, responseName: string): WebAuthnRpId {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(`${responseName} response has invalid rpId`);
  return parsed.value;
}

function parseWalletAddSignerEd25519Session(
  value: unknown,
): WalletRegistrationEd25519YaoBootstrapSession {
  const responseName = 'Wallet add-signer Ed25519 finalize';
  const session = requireResponseRecord({ responseName, field: 'ed25519.session', value });
  assertExactResponseKeys(
    session,
    [
      'sessionKind',
      'walletSessionJwt',
      'walletId',
      'nearAccountId',
      'nearEd25519SigningKeyId',
      'authorityScope',
      'thresholdSessionId',
      'signingGrantId',
      'expiresAtMs',
      'participantIds',
      'remainingUses',
      'signingRootId',
      'signingRootVersion',
      'runtimePolicyScope',
      'routerAbNormalSigning',
    ],
    responseName,
  );
  if (session.sessionKind !== 'jwt') {
    throw new Error(`${responseName} response has invalid sessionKind`);
  }
  const authorityScope = requireResponseRecord({
    responseName,
    field: 'ed25519.session.authorityScope',
    value: session.authorityScope,
  });
  assertExactResponseKeys(authorityScope, ['kind', 'rpId'], responseName);
  if (authorityScope.kind !== 'passkey_rp') {
    throw new Error(`${responseName} response has invalid authorityScope`);
  }
  const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(session.runtimePolicyScope);
  if (!runtimePolicyScope) {
    throw new Error(`${responseName} response has invalid runtimePolicyScope`);
  }
  return {
    sessionKind: 'jwt',
    walletSessionJwt: requireResponseString({
      responseName,
      field: 'ed25519.session.walletSessionJwt',
      value: session.walletSessionJwt,
    }),
    walletId: walletIdFromString(
      requireResponseString({
        responseName,
        field: 'ed25519.session.walletId',
        value: session.walletId,
      }),
    ),
    nearAccountId: requireResponseString({
      responseName,
      field: 'ed25519.session.nearAccountId',
      value: session.nearAccountId,
    }),
    nearEd25519SigningKeyId: requireResponseString({
      responseName,
      field: 'ed25519.session.nearEd25519SigningKeyId',
      value: session.nearEd25519SigningKeyId,
    }),
    authorityScope: {
      kind: 'passkey_rp',
      rpId: requireResponseRpId(authorityScope.rpId, responseName),
    },
    thresholdSessionId: requireResponseString({
      responseName,
      field: 'ed25519.session.thresholdSessionId',
      value: session.thresholdSessionId,
    }),
    signingGrantId: requireResponseString({
      responseName,
      field: 'ed25519.session.signingGrantId',
      value: session.signingGrantId,
    }),
    expiresAtMs: requireResponseSafeInteger({
      responseName,
      field: 'ed25519.session.expiresAtMs',
      value: session.expiresAtMs,
      minimum: 1,
    }),
    participantIds: requireResponseParticipantPair(session.participantIds, responseName),
    remainingUses: requireResponseSafeInteger({
      responseName,
      field: 'ed25519.session.remainingUses',
      value: session.remainingUses,
      minimum: 0,
    }),
    signingRootId: requireResponseString({
      responseName,
      field: 'ed25519.session.signingRootId',
      value: session.signingRootId,
    }),
    signingRootVersion: requireResponseString({
      responseName,
      field: 'ed25519.session.signingRootVersion',
      value: session.signingRootVersion,
    }),
    runtimePolicyScope,
    routerAbNormalSigning: requireRouterAbEd25519NormalSigningState(session.routerAbNormalSigning),
  };
}

function parseWalletAddSignerEd25519Result(
  value: unknown,
): WalletRegistrationEd25519YaoPublicResult {
  const responseName = 'Wallet add-signer Ed25519 finalize';
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
      'session',
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
    session: parseWalletAddSignerEd25519Session(ed25519.session),
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

function parseWalletAddSignerEcdsaWalletKey(value: unknown): WalletRegistrationEcdsaWalletKey {
  const responseName = 'Wallet add-signer ECDSA finalize';
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
      'participantIds',
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
    participantIds: [...requireResponseParticipantPair(key.participantIds, responseName)],
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
    case 'near_ed25519':
      if (record.ecdsa !== undefined) {
        throw new Error(`${responseName} response mixed signer branches`);
      }
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
        ed25519: parseWalletAddSignerEd25519Result(record.ed25519),
      };
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
        ecdsa: { walletKeys: ecdsa.walletKeys.map(parseWalletAddSignerEcdsaWalletKey) },
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
  signingGrantId: string;
  ttlMs: number;
  remainingUses: number;
  participantIds: number[];
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
  participantIds: number[];
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
  thresholdSessionId: string;
  signingGrantId: string;
  expiresAtMs: number;
  remainingUses: number;
  walletSessionJwt: string;
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

function requireMatchingPositiveSafeInteger(args: {
  field: string;
  expected: unknown;
  actual: unknown;
}): number {
  const expected = Math.floor(Number(args.expected));
  const actual = Math.floor(Number(args.actual));
  if (
    !Number.isSafeInteger(expected) ||
    expected <= 0 ||
    !Number.isSafeInteger(actual) ||
    actual <= 0
  ) {
    throw new Error(`ECDSA registration bootstrap returned incomplete ${args.field}`);
  }
  if (expected !== actual) {
    throw new Error(`ECDSA registration bootstrap ${args.field} mismatch`);
  }
  return actual;
}

export function parseWalletRegistrationEcdsaDerivationRespond(args: {
  clientBootstrap: WalletRegistrationEcdsaClientBootstrap;
  serverBootstrap: ThresholdEcdsaDerivationRoleLocalBootstrapValue;
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
  const thresholdSessionId = requireMatchingString({
    field: 'thresholdSessionId',
    expected: clientBootstrap.thresholdSessionId,
    actual: serverBootstrap.thresholdSessionId,
  });
  const signingGrantId = requireMatchingString({
    field: 'signingGrantId',
    expected: clientBootstrap.signingGrantId,
    actual: serverBootstrap.signingGrantId,
  });
  const remainingUses = requireMatchingPositiveSafeInteger({
    field: 'remainingUses',
    expected: clientBootstrap.remainingUses,
    actual: serverBootstrap.remainingUses,
  });
  const participantIds = requireMatchingParticipantIds({
    expected: clientBootstrap.participantIds,
    actual: serverBootstrap.participantIds,
  });

  const walletSessionJwt = String(serverBootstrap.jwt || '').trim();
  const routerAbEcdsaDerivationNormalSigning =
    parseRouterAbEcdsaDerivationNormalSigningFromWalletRegistrationJwtV1({
      walletSessionJwt,
      expected: {
        walletId: String(serverBootstrap.walletId || '').trim(),
        evmFamilySigningKeySlotId: String(serverBootstrap.evmFamilySigningKeySlotId || '').trim(),
        keyHandle: String(serverBootstrap.keyHandle || '').trim(),
        relayerKeyId: String(serverBootstrap.relayerKeyId || '').trim(),
        ecdsaThresholdKeyId: String(serverBootstrap.ecdsaThresholdKeyId || '').trim(),
        signingRootId: String(serverBootstrap.signingRootId || '').trim(),
        signingRootVersion: String(serverBootstrap.signingRootVersion || '').trim(),
        thresholdSessionId: String(serverBootstrap.thresholdSessionId || '').trim(),
        signingGrantId: String(serverBootstrap.signingGrantId || '').trim(),
        expiresAtMs: Number(serverBootstrap.expiresAtMs),
        participantIds: serverBootstrap.participantIds.map((participantId) =>
          Math.floor(Number(participantId)),
        ),
        applicationBindingDigestB64u: String(
          serverBootstrap.applicationBindingDigestB64u || '',
        ).trim(),
        contextBinding32B64u: String(serverBootstrap.contextBinding32B64u || '').trim(),
        clientPublicKey33B64u: String(
          serverBootstrap.publicIdentity.derivationClientSharePublicKey33B64u || '',
        ).trim(),
        serverPublicKey33B64u: String(
          serverBootstrap.publicIdentity.relayerPublicKey33B64u || '',
        ).trim(),
        thresholdPublicKey33B64u: String(
          serverBootstrap.publicIdentity.groupPublicKey33B64u || '',
        ).trim(),
        ethereumAddress: String(serverBootstrap.ethereumAddress || '').trim(),
        clientShareRetryCounter: Math.floor(Number(serverBootstrap.clientShareRetryCounter)),
        serverShareRetryCounter: Math.floor(Number(serverBootstrap.relayerShareRetryCounter)),
      },
    });
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
  const relayerShareRetryCounter = Math.floor(
    Number(serverBootstrap.relayerShareRetryCounter),
  );
  const expiresAtMs = Math.max(0, Math.floor(Number(serverBootstrap.expiresAtMs)));
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
    !thresholdSessionId ||
    !signingGrantId ||
    !walletSessionJwt ||
    !participantIds.length ||
    participantIds.some(
      (participantId) => !Number.isSafeInteger(participantId) || participantId <= 0,
    ) ||
    !Number.isFinite(remainingUses) ||
    !Number.isFinite(expiresAtMs)
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
    thresholdSessionId,
    signingGrantId,
    expiresAtMs,
    remainingUses,
    walletSessionJwt,
    routerAbEcdsaDerivationNormalSigning,
  };
}

export async function buildWalletRegistrationEcdsaSessionBootstrap(args: {
  walletId: string;
  relayerUrl: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keygenSessionId: string;
  clientVerifyingShareB64u: string;
  serverBootstrap: WalletRegistrationEcdsaDerivationRespondBootstrap;
  walletKey: WalletRegistrationEcdsaWalletKey;
  publicCapability: RouterAbEcdsaDerivationPublicCapabilityV1;
  authMethod:
    | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
    | { kind: 'email_otp'; providerUserId: string };
  material:
    | {
        kind: 'worker_handle';
        handle: ThresholdEcdsaRoleLocalWorkerShareHandle;
        publicFacts: EcdsaRoleLocalPublicFacts;
      }
    | {
        kind: 'ready_state_blob';
        stateBlob: EcdsaRoleLocalReadyStateBlob;
  };
}): Promise<ThresholdEcdsaSessionBootstrapResult> {
  const serverBootstrap = args.serverBootstrap;
  requireMatchingString({
    field: 'walletId',
    expected: args.walletId,
    actual: serverBootstrap.walletId,
  });
  requireMatchingString({
    field: 'walletKey.walletId',
    expected: args.walletId,
    actual: args.walletKey.walletId,
  });
  const evmFamilySigningKeySlotId = requireMatchingString({
    field: 'evmFamilySigningKeySlotId',
    expected: args.walletKey.evmFamilySigningKeySlotId,
    actual: serverBootstrap.evmFamilySigningKeySlotId,
  });
  const keyHandle = requireMatchingString({
    field: 'keyHandle',
    expected: args.walletKey.keyHandle,
    actual: serverBootstrap.keyHandle,
  });
  const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId(
    requireMatchingString({
      field: 'ecdsaThresholdKeyId',
      expected: args.walletKey.ecdsaThresholdKeyId,
      actual: serverBootstrap.ecdsaThresholdKeyId,
    }),
  );
  const signingRootId = requireMatchingString({
    field: 'signingRootId',
    expected: args.walletKey.signingRootId,
    actual: serverBootstrap.signingRootId,
  });
  const signingRootVersion = requireMatchingString({
    field: 'signingRootVersion',
    expected: args.walletKey.signingRootVersion,
    actual: serverBootstrap.signingRootVersion,
  });
  const thresholdEcdsaPublicKeyB64u = requireMatchingString({
    field: 'thresholdEcdsaPublicKeyB64u',
    expected: args.walletKey.thresholdEcdsaPublicKeyB64u,
    actual: serverBootstrap.thresholdEcdsaPublicKeyB64u,
  });
  const ethereumAddress = requireMatchingString({
    field: 'ethereumAddress',
    expected: args.walletKey.thresholdOwnerAddress,
    actual: serverBootstrap.ethereumAddress,
  });
  const relayerKeyId = requireMatchingString({
    field: 'relayerKeyId',
    expected: args.walletKey.relayerKeyId,
    actual: serverBootstrap.relayerKeyId,
  });
  const relayerVerifyingShareB64u = requireMatchingString({
    field: 'relayerVerifyingShareB64u',
    expected: args.walletKey.relayerVerifyingShareB64u,
    actual: serverBootstrap.relayerVerifyingShareB64u,
  });
  requireMatchingString({
    field: 'chainTarget',
    expected: thresholdEcdsaChainTargetKey(args.chainTarget),
    actual: thresholdEcdsaChainTargetKey(args.walletKey.chainTarget),
  });

  const participantIds = requireMatchingParticipantIds({
    expected: args.walletKey.participantIds,
    actual: serverBootstrap.participantIds,
  });
  const walletSessionJwt = serverBootstrap.walletSessionJwt;
  const routerAbEcdsaDerivationNormalSigning = serverBootstrap.routerAbEcdsaDerivationNormalSigning;
  const thresholdSessionId = serverBootstrap.thresholdSessionId;
  const signingGrantId = serverBootstrap.signingGrantId;
  const remainingUses = serverBootstrap.remainingUses;
  const expiresAtMs = serverBootstrap.expiresAtMs;
  const expectedApplicationBindingDigestB64u = await computeSdkEcdsaDerivationApplicationBindingDigestB64u(
    {
      walletId: toWalletId(args.walletId),
      ecdsaThresholdKeyId,
      signingRootId: parseSdkEcdsaDerivationSigningRootId(signingRootId),
      signingRootVersion: parseSdkEcdsaDerivationSigningRootVersion(signingRootVersion),
    },
  );
  const applicationBindingDigestB64u = requireMatchingString({
    field: 'applicationBindingDigestB64u',
    expected: expectedApplicationBindingDigestB64u,
    actual: serverBootstrap.applicationBindingDigestB64u,
  });
  const publicFacts = buildEcdsaRoleLocalPublicFacts({
    walletId: args.walletId,
    evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId,
    signingRootVersion,
    applicationBindingDigestB64u,
    participantIds,
    clientParticipantId: 1,
    relayerParticipantId: 2,
    contextBinding32B64u: serverBootstrap.contextBinding32B64u,
    derivationClientSharePublicKey33B64u: args.clientVerifyingShareB64u,
    relayerPublicKey33B64u: serverBootstrap.publicIdentity.relayerPublicKey33B64u,
    groupPublicKey33B64u: serverBootstrap.publicIdentity.groupPublicKey33B64u,
    ethereumAddress,
    publicCapability: args.publicCapability,
  });
  const authMethod = buildWalletRegistrationEcdsaRoleLocalAuthMethod(
    args.authMethod,
  );
  const backendBinding = buildWalletRegistrationEcdsaBackendBinding({
    material: args.material,
    relayerKeyId,
    clientVerifyingShareB64u: args.clientVerifyingShareB64u,
    publicFacts,
    authMethod,
  });

  const keyRef: ThresholdEcdsaSecp256k1KeyRef = {
    type: 'threshold-ecdsa-secp256k1',
    userId: args.walletId,
    evmFamilySigningKeySlotId,
    chainTarget: args.chainTarget,
    relayerUrl: args.relayerUrl,
    keyHandle,
    ecdsaThresholdKeyId,
    backendBinding,
    participantIds,
    thresholdEcdsaPublicKeyB64u,
    ethereumAddress,
    relayerVerifyingShareB64u,
    routerAbEcdsaDerivationNormalSigning,
    thresholdSessionKind: 'jwt',
    walletSessionJwt,
    thresholdSessionId,
    signingGrantId,
  };
  return {
    thresholdEcdsaKeyRef: keyRef,
    ...(args.authMethod.kind === 'passkey'
      ? { passkeyCredentialIdB64u: args.authMethod.credentialIdB64u }
      : {}),
    keygen: {
      ok: true,
      keygenSessionId: args.keygenSessionId,
      evmFamilySigningKeySlotId,
      keyHandle,
      ecdsaThresholdKeyId,
      clientVerifyingShareB64u: args.clientVerifyingShareB64u,
      thresholdEcdsaPublicKeyB64u,
      ethereumAddress,
      relayerKeyId,
      relayerVerifyingShareB64u,
      participantIds,
      chainId: args.chainTarget.chainId,
    },
    session: {
      ok: true,
      thresholdSessionId,
      signingGrantId,
      expiresAtMs,
      remainingUses,
      jwt: walletSessionJwt,
    },
  };
}

function buildWalletRegistrationEcdsaRoleLocalAuthMethod(
  authMethod:
    | { kind: 'passkey'; credentialIdB64u: string; rpId: string }
    | { kind: 'email_otp'; providerUserId: string },
): ReturnType<
  | typeof buildEcdsaRoleLocalEmailOtpAuthMethod
  | typeof buildEcdsaRoleLocalPasskeyAuthMethod
> {
  switch (authMethod.kind) {
    case 'passkey':
      return buildEcdsaRoleLocalPasskeyAuthMethod({
        credentialIdB64u: authMethod.credentialIdB64u,
        rpId: authMethod.rpId,
      });
    case 'email_otp':
      return buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: authMethod.providerUserId,
      });
  }
}

function buildWalletRegistrationEcdsaBackendBinding(args: {
  material:
    | {
        kind: 'worker_handle';
        handle: ThresholdEcdsaRoleLocalWorkerShareHandle;
        publicFacts: EcdsaRoleLocalPublicFacts;
      }
    | {
        kind: 'ready_state_blob';
        stateBlob: EcdsaRoleLocalReadyStateBlob;
      };
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  publicFacts: EcdsaRoleLocalPublicFacts;
  authMethod: ReturnType<
    | typeof buildEcdsaRoleLocalEmailOtpAuthMethod
    | typeof buildEcdsaRoleLocalPasskeyAuthMethod
  >;
}): NonNullable<ThresholdEcdsaSecp256k1KeyRef['backendBinding']> {
  switch (args.material.kind) {
    case 'worker_handle':
      return {
        materialKind: 'role_local_worker_handle',
        relayerKeyId: args.relayerKeyId,
        clientVerifyingShareB64u: args.clientVerifyingShareB64u,
        roleLocalMaterialHandle: args.material.handle,
        publicFacts: args.material.publicFacts,
        authMethod: args.authMethod,
      };
    case 'ready_state_blob':
      return {
        materialKind: 'role_local_ready_state_blob',
        relayerKeyId: args.relayerKeyId,
        clientVerifyingShareB64u: args.clientVerifyingShareB64u,
        stateBlob: args.material.stateBlob,
        ecdsaRoleLocalReadyRecord: buildEcdsaRoleLocalReadyRecord({
          stateBlob: args.material.stateBlob,
          publicFacts: args.publicFacts,
          authMethod: args.authMethod,
        }),
      };
  }
}

export type WalletEcdsaKeyFactsInventoryTarget = {
  keyHandle: string;
  ecdsaThresholdKeyId?: never;
  chainTarget: ThresholdEcdsaChainTarget;
};

export type WalletEcdsaKeyFactsInventoryAppSessionPolicy = {
  permission: 'ecdsa_key_facts_inventory';
  walletId: WalletId;
  chainTargets: readonly ThresholdEcdsaChainTarget[];
  expiresAtMs: number;
};

export type WalletEcdsaKeyFactsInventoryResponse = {
  ok: true;
  records: ThresholdEcdsaKeyIdentityInventoryEntry[];
  diagnostics: unknown;
};

export async function createWalletRegistrationIntent(args: {
  relayerUrl: string;
  request: CreateRegistrationIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateRegistrationIntentResponse> {
  return await postJson<CreateRegistrationIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/intent',
    body: createRegistrationIntentWireRequest(args.request),
    headers: args.headers,
  });
}

export async function cancelWalletRegistrationIntent(args: {
  relayerUrl: string;
  registrationIntentGrant: RegistrationIntentGrant;
  registrationIntentDigestB64u: string;
  headers?: Record<string, string>;
}): Promise<CancelRegistrationIntentResponse> {
  return await postJson<CancelRegistrationIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: WALLET_REGISTRATION_INTENT_CANCEL_PATH,
    body: {
      registrationIntentGrant: args.registrationIntentGrant,
      registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    },
    headers: args.headers,
  });
}

export async function createWalletAddSignerIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddSignerIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateAddSignerIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-signer intent');
  return await postJson<CreateAddSignerIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/intent`,
    headers: args.headers,
    body: args.request,
  });
}

export async function createWalletAddAuthMethodIntent(args: {
  relayerUrl: string;
  walletId: WalletId;
  request: CreateAddAuthMethodIntentRequest;
  headers?: Record<string, string>;
}): Promise<CreateAddAuthMethodIntentResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method intent');
  return await postJson<CreateAddAuthMethodIntentResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/intent`,
    headers: args.headers,
    body: args.request,
  });
}

function walletRegistrationStartAuthorityBody(
  authority: WalletRegistrationStartAuthority,
): Record<string, unknown> {
  switch (authority.kind) {
    case 'passkey':
      return { webauthn_registration: authority.webauthnRegistration };
    case 'email_otp':
      return { emailOtpRegistrationProof: authority.emailOtpRegistrationProof };
  }
}

export async function startWalletRegistration(
  args: {
    relayerUrl: string;
    headers?: Record<string, string>;
    registrationIntentGrant: RegistrationIntentGrant;
    registrationIntentDigestB64u: string;
    intent: RegistrationIntentV1;
  } & WalletRegistrationStartAuthority,
): Promise<WalletRegistrationStartResponse> {
  const body = {
    registrationIntentGrant: args.registrationIntentGrant,
    registrationIntentDigestB64u: args.registrationIntentDigestB64u,
    intent: args.intent,
    ...walletRegistrationStartAuthorityBody(args),
  };
  return await postJson<WalletRegistrationStartResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/start',
    headers: args.headers,
    body,
  });
}

export async function respondWalletRegistrationEcdsa(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
  };
}): Promise<WalletRegistrationEcdsaRespondResponse> {
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/derivation/respond',
    headers: args.headers,
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ecdsa: args.ecdsa,
    },
  });
  return parseWalletRegistrationEcdsaRespondResponse(response);
}

export async function activateWalletRegistrationEcdsa(args: {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
}): Promise<WalletRegistrationEcdsaActivationResponse> {
  const response = await postJson<unknown>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/derivation/activate',
    headers: args.headers,
    body: {
      registrationCeremonyId: args.registrationCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1',
        publicFacts: args.publicFacts,
      },
    },
  });
  return parseWalletRegistrationEcdsaActivationResponse(response);
}

type FinalizeWalletRegistrationBaseArgs = {
  relayerUrl: string;
  headers?: Record<string, string>;
  registrationCeremonyId: string;
  idempotencyKey?: string;
  emailOtpEnrollment?: WalletRegistrationEmailOtpEnrollmentMaterial;
  emailOtpBackupAck?: WalletRegistrationEmailOtpBackupAck;
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
    | {
        kind: 'near_ed25519_and_evm_family_ecdsa';
        ed25519: { activationReference: WalletRegistrationEd25519YaoActivationReference };
        ecdsa: { expectedKeyHandles?: string[] };
      }
  );

export function buildWalletRegistrationFinalizeBody(args: FinalizeWalletRegistrationArgs): unknown {
  const base = {
    registrationCeremonyId: args.registrationCeremonyId,
    ...(args.idempotencyKey ? { idempotencyKey: args.idempotencyKey } : {}),
    ...(args.emailOtpEnrollment ? { emailOtpEnrollment: args.emailOtpEnrollment } : {}),
    ...(args.emailOtpBackupAck ? { emailOtpBackupAck: args.emailOtpBackupAck } : {}),
  };
  switch (args.kind) {
    case 'near_ed25519':
      return { ...base, kind: args.kind, ed25519: args.ed25519 };
    case 'evm_family_ecdsa':
      return { ...base, kind: args.kind, ecdsa: args.ecdsa };
    case 'near_ed25519_and_evm_family_ecdsa':
      return { ...base, kind: args.kind, ed25519: args.ed25519, ecdsa: args.ecdsa };
    default:
      return assertNeverFinalizeWalletRegistrationArgs(args);
  }
}

function assertNeverFinalizeWalletRegistrationArgs(value: never): never {
  throw new Error(`Unsupported wallet registration finalize kind: ${String(value)}`);
}

export async function finalizeWalletRegistration(
  args: FinalizeWalletRegistrationArgs,
): Promise<WalletRegistrationFinalizeResponse> {
  return await postJson<WalletRegistrationFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: '/wallets/register/finalize',
    headers: args.headers,
    body: buildWalletRegistrationFinalizeBody(args),
  });
}

function addSignerAuthHeaders(auth: AddSignerAuth): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session add-signer auth',
  });
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
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
      };
  }
}

function addAuthMethodAuthHeaders(auth: AddAuthMethodAuth): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session add-auth-method auth',
  });
}

function addAuthMethodAuthBody(auth: AddAuthMethodAuth): unknown {
  switch (auth.kind) {
    case 'webauthn_assertion':
      return {
        kind: 'webauthn_assertion',
        credential: auth.credential,
        expectedChallengeDigestB64u: auth.expectedChallengeDigestB64u,
      };
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
      };
  }
}

function addAuthMethodAuthorityBody(
  authority: WalletAddAuthMethodAuthority,
): Record<string, unknown> {
  switch (authority.kind) {
    case 'passkey':
      return { webauthnRegistration: authority.webauthnRegistration };
    case 'email_otp':
      return { emailOtpRegistrationProof: authority.emailOtpRegistrationProof };
  }
}

function revokeAuthMethodAuthHeaders(
  auth: RevokeAuthMethodAuth,
): Record<string, string> | undefined {
  if (auth.kind !== 'app_session') return undefined;
  return buildBearerAuthorizationHeader({
    token: auth.appSessionJwt,
    missingMessage: 'appSessionJwt is required for app-session auth-method revoke',
  });
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
    case 'app_session':
      return {
        kind: 'app_session',
        policy: auth.policy,
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
    headers: addSignerAuthHeaders(args.auth),
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
  return await postJson<WalletAddAuthMethodStartResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/start`,
    headers: addAuthMethodAuthHeaders(args.auth),
    body: {
      addAuthMethodIntentGrant: args.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: args.addAuthMethodIntentDigestB64u,
      intent: args.intent,
      auth: addAuthMethodAuthBody(args.auth),
      ...addAuthMethodAuthorityBody(args.authority),
    },
  });
}

export async function respondWalletAddSignerEcdsa(args: {
  relayerUrl: string;
  walletId: WalletId;
  addSignerCeremonyId: string;
  ecdsa: {
    kind: 'router_ab_ecdsa_registration_v1';
    strictRegistration: RouterAbEcdsaRegistrationRequestV1;
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
  publicFacts: RouterAbEcdsaVerifiedClientActivationFactsV1;
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
        publicFacts: args.publicFacts,
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
      ecdsa?: never;
    }
  | {
      kind: 'evm_family_ecdsa';
      ecdsa: {
        expectedKeyHandles?: string[];
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
      };
    case 'evm_family_ecdsa':
      return {
        addSignerCeremonyId: args.addSignerCeremonyId,
        idempotencyKey: args.idempotencyKey,
        kind: args.kind,
        ecdsa: args.ecdsa,
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

export async function finalizeWalletAddAuthMethod(args: {
  relayerUrl: string;
  walletId: WalletId;
  addAuthMethodCeremonyId: string;
}): Promise<WalletAddAuthMethodFinalizeResponse> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('walletId is required for add-auth-method finalize');
  return await postJson<WalletAddAuthMethodFinalizeResponse>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/auth-methods/finalize`,
    body: {
      addAuthMethodCeremonyId: args.addAuthMethodCeremonyId,
    },
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
    headers: revokeAuthMethodAuthHeaders(args.auth),
    body: {
      auth: revokeAuthMethodAuthBody(args.auth),
      target: args.target,
    },
  });
}

export async function fetchWalletEcdsaKeyFactsInventoryWithAppSession(args: {
  relayerUrl: string;
  walletId: WalletId;
  rpId: string;
  appSessionJwt: string;
  keyTargets: readonly WalletEcdsaKeyFactsInventoryTarget[];
  policy: WalletEcdsaKeyFactsInventoryAppSessionPolicy;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
}): Promise<WalletEcdsaKeyFactsInventoryResponse> {
  const walletId = String(args.walletId || '').trim();
  const rpId = String(args.rpId || '').trim();
  const appSessionJwt = String(args.appSessionJwt || '').trim();
  if (!walletId) {
    throw new Error('walletId is required for ECDSA key-facts inventory');
  }
  if (!rpId) {
    throw new Error('rpId is required for ECDSA key-facts inventory');
  }
  if (!appSessionJwt) {
    throw new Error('appSessionJwt is required for ECDSA key-facts inventory');
  }
  if (String(args.policy.walletId || '').trim() !== walletId) {
    throw new Error('policy.walletId must match walletId for ECDSA key-facts inventory');
  }

  const data = await postJson<Record<string, unknown>>({
    relayerUrl: args.relayerUrl,
    path: `/wallets/${encodeURIComponent(walletId)}/signers/ecdsa/key-facts/inventory`,
    headers: buildBearerAuthorizationHeader({
      token: appSessionJwt,
      missingMessage: 'appSessionJwt is required for ECDSA key-facts inventory',
    }),
    body: {
      rpId,
      keyTargets: args.keyTargets,
      auth: {
        kind: 'app_session',
        policy: args.policy,
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
